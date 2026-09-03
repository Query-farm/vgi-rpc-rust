//! Blocking HTTP transport for the vgi-rpc client.
//!
//! HTTP is *not* a [`crate::Transport`] (it is request/response, not a byte
//! stream). Streaming is **stateless on the wire**: the server seals its
//! `StreamState` into an opaque token carried in the `vgi_rpc.stream_state#b64`
//! batch metadata; the client echoes that token back verbatim on each
//! continuation request and never decodes it.
//!
//! Endpoints (relative to the configured `prefix`, default empty):
//! `POST {prefix}/{method}` unary, `POST {prefix}/{method}/init` stream init,
//! `POST {prefix}/{method}/exchange` exchange / producer continuation / cancel,
//! `DELETE {prefix}/__session__` sticky teardown,
//! `POST {prefix}/__upload_url__/init` request-externalization upload URLs.
//!
//! Production features: configurable request timeout + retry (connection-level,
//! never on exchange), zstd request compression with 415 codec fallback, 413
//! request externalization via server-vended upload URLs, transparent
//! external-location response resolution, and sticky sessions.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::Duration;

use arrow_array::RecordBatch;
use arrow_schema::Schema;
use reqwest::blocking::Client as ReqwestClient;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::{Method, StatusCode};

use vgi_rpc::errors::{Result, RpcError};
use vgi_rpc::external::{
    any_url_validator, validate_external_url, Compression, ExternalLocationConfig, ExternalStorage,
    FetchedPayload, Fetcher, UploadResult, UrlValidator,
};
use vgi_rpc::introspect::DESCRIBE_METHOD_NAME;
use vgi_rpc::metadata::{CALL_STATE_KEY, CANCEL_KEY, LOCATION_KEY, REQUEST_ID_KEY, STATE_KEY};
use vgi_rpc::retry::RetryConfig;
use vgi_rpc::wire::{empty_batch, write_one_batch, Metadata, StreamReader};

use crate::client::OnLog;
use crate::envelope::{classify, BatchKind};
use crate::introspect::{empty_schema, parse_describe_batch, ServiceDescription};
use crate::request::{build_request_metadata, generate_request_id};

/// Apache Arrow IPC stream content type (matches `vgi_rpc::http::ARROW_CONTENT_TYPE`).
pub const ARROW_CONTENT_TYPE: &str = "application/vnd.apache.arrow.stream";

// Sticky-session + capability + codec header names (mirror Python `_common.py`).
const SESSION_HEADER: &str = "VGI-Session";
const SESSION_ACCEPT_HEADER: &str = "VGI-Session-Accept";
const SESSION_CLOSE_HEADER: &str = "VGI-Session-Close";
const STICKY_ENABLED_HEADER: &str = "VGI-Sticky-Enabled";
const STICKY_DEFAULT_TTL_HEADER: &str = "VGI-Sticky-Default-TTL";
const STICKY_ECHO_HEADERS_HEADER: &str = "VGI-Sticky-Echo-Headers";
const ECHO_HEADER_PREFIX: &str = "VGI-Echo-";
const SUPPORTED_ENCODINGS_HEADER: &str = "VGI-Supported-Encodings";
const MAX_REQUEST_BYTES_HEADER: &str = "VGI-Max-Request-Bytes";
const MAX_RESPONSE_BYTES_HEADER: &str = "VGI-Max-Response-Bytes";
const ACCEPT_MAX_RESPONSE_BYTES_HEADER: &str = "VGI-Accept-Max-Response-Bytes";
const ACCEPT_MAX_RESPONSE_BYTES_SUPPORT_HEADER: &str = "VGI-Accept-Max-Response-Bytes-Support";
const MAX_EXTERNALIZED_RESPONSE_BYTES_HEADER: &str = "VGI-Max-Externalized-Response-Bytes";
const EXTERNALIZATION_ENABLED_HEADER: &str = "VGI-Externalization-Enabled";
const MAX_UPLOAD_BYTES_HEADER: &str = "VGI-Max-Upload-Bytes";
const UPLOAD_URL_HEADER: &str = "VGI-Upload-URL-Support";
const SESSION_ENDPOINT: &str = "__session__";
// The upload-URL method name is a shared public wire contract, not a
// client-local literal.
use vgi_rpc::external::{upload_url_params_schema, UPLOAD_URL_METHOD};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_COMPRESSION_LEVEL: i32 = 3;
const DEFAULT_MAX_ENCODED_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_DECODED_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_ACCEPTED_MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const MIN_ACCEPTED_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_SAFE_RESPONSE_BYTES: u64 = (1u64 << 53) - 1;
/// The only coding this client can produce for request bodies. Also the
/// assumed server capability when `VGI-Supported-Encodings` is absent.
const DEFAULT_REQUEST_ENCODING: &str = "zstd";

enum HttpBackend {
    Reqwest(ReqwestClient),
    #[cfg(feature = "iroh")]
    Iroh(crate::httpi::HttpiExecutor),
}

struct BackendResponse {
    status: StatusCode,
    headers: HeaderMap,
    content_length: Option<u64>,
    body: Box<dyn Read>,
}

impl BackendResponse {
    fn status(&self) -> StatusCode {
        self.status
    }

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

struct BackendRequestError {
    error: RpcError,
    retry_safe: bool,
}

impl HttpBackend {
    fn execute(
        &self,
        method: Method,
        target: String,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> std::result::Result<BackendResponse, BackendRequestError> {
        match self {
            Self::Reqwest(client) => client
                .request(method, target)
                .headers(headers)
                .body(body)
                .send()
                .map(|response| BackendResponse {
                    status: response.status(),
                    headers: response.headers().clone(),
                    content_length: response.content_length(),
                    body: Box::new(response),
                })
                .map_err(|error| BackendRequestError {
                    // Preserve the existing reqwest retry behavior. Native
                    // Iroh is stricter below because it carries explicit
                    // dispatch certainty.
                    error: RpcError::new("TransportError", error.to_string()),
                    retry_safe: true,
                }),
            #[cfg(feature = "iroh")]
            Self::Iroh(client) => {
                let raw_headers = headers
                    .iter()
                    .map(|(name, value)| {
                        (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec())
                    })
                    .collect();
                client
                    .execute(method.as_str(), &target, raw_headers, body)
                    .map_err(|error| {
                        let retry_safe =
                            error.dispatch == vgi_iroh_transport::DispatchCertainty::NotSent;
                        BackendRequestError {
                            error: crate::httpi::transport_rpc_error(error),
                            retry_safe,
                        }
                    })
                    .and_then(|response| {
                        let status = StatusCode::from_u16(response.status).map_err(|error| {
                            BackendRequestError {
                                error: RpcError::new(
                                    "ProtocolError",
                                    format!("invalid Iroh HTTP response status: {error}"),
                                ),
                                retry_safe: false,
                            }
                        })?;
                        let mut headers = HeaderMap::new();
                        for (name, value) in response.headers {
                            let name = HeaderName::from_bytes(&name).map_err(|error| {
                                BackendRequestError {
                                    error: RpcError::new(
                                        "ProtocolError",
                                        format!("invalid Iroh HTTP response header name: {error}"),
                                    ),
                                    retry_safe: false,
                                }
                            })?;
                            let value = HeaderValue::from_bytes(&value).map_err(|error| {
                                BackendRequestError {
                                    error: RpcError::new(
                                        "ProtocolError",
                                        format!("invalid Iroh HTTP response header value: {error}"),
                                    ),
                                    retry_safe: false,
                                }
                            })?;
                            headers.append(name, value);
                        }
                        let content_length = parse_content_length(&headers).map_err(|error| {
                            BackendRequestError {
                                error,
                                retry_safe: false,
                            }
                        })?;
                        Ok(BackendResponse {
                            status,
                            headers,
                            content_length,
                            body: Box::new(response.body),
                        })
                    })
            }
        }
    }

    fn target(&self, base_url: &str, prefix: &str, path: &str) -> String {
        match self {
            Self::Reqwest(_) => format!("{}{}/{}", base_url, prefix, path),
            #[cfg(feature = "iroh")]
            Self::Iroh(_) => format!("{prefix}/{path}"),
        }
    }

    #[cfg(feature = "iroh")]
    fn iroh_endpoint_id(&self) -> Option<String> {
        match self {
            Self::Reqwest(_) => None,
            Self::Iroh(client) => Some(client.endpoint_id()),
        }
    }
}

fn zstd_window_log_for_limit(max_size: usize) -> u32 {
    // A level-1 streaming encoder advertises a 512 KiB history window even
    // for tiny frames whose content size was unknown to the encoder.
    const INTEROPERABLE_WINDOW_LOG_FLOOR: u32 = 19;
    let bounded = max_size.max(1 << INTEROPERABLE_WINDOW_LOG_FLOOR);
    let ceil_log = usize::BITS - bounded.saturating_sub(1).leading_zeros();
    ceil_log.clamp(INTEROPERABLE_WINDOW_LOG_FLOOR, 31)
}

/// Server capabilities advertised on `OPTIONS {prefix}/health`.
#[derive(Debug, Clone)]
pub struct HttpServerCapabilities {
    pub sticky_enabled: bool,
    pub sticky_default_ttl: Option<u64>,
    pub sticky_echo_headers: Vec<String>,
    pub upload_url_support: bool,
    pub max_request_bytes: Option<u64>,
    pub max_response_bytes: Option<u64>,
    pub accept_max_response_bytes_support: bool,
    pub max_externalized_response_bytes: Option<u64>,
    pub externalization_enabled: bool,
    pub max_upload_bytes: Option<u64>,
    /// Content codings the server can decompress on request bodies (and
    /// re-encode on responses), from `VGI-Supported-Encodings`.
    ///
    /// Three distinct server answers collapse into this one field, so read
    /// it as a set, not as "did the header parse":
    ///
    /// - header **absent** ⇒ `["zstd"]`. A server predating the
    ///   advertisement; every such server accepted zstd, so assuming it
    ///   keeps request compression working against old deployments.
    /// - header **present but empty** ⇒ `[]`. The server positively states
    ///   it speaks no compression. Sending it a compressed body would earn
    ///   a 415, so [`HttpClient`] stops compressing on seeing this.
    /// - header **present and non-empty** ⇒ the parsed list.
    ///
    /// Mirrors Python's `HttpServerCapabilities.supported_encodings`,
    /// including the `(zstd,)` default — hence the hand-written [`Default`].
    pub supported_encodings: Vec<String>,
}

impl Default for HttpServerCapabilities {
    /// All-negative defaults except `supported_encodings`, which defaults to
    /// the absent-header reading (`zstd`) rather than the empty set — an
    /// undiscovered server is a legacy server, not one that refuses
    /// compression.
    fn default() -> Self {
        Self {
            sticky_enabled: false,
            sticky_default_ttl: None,
            sticky_echo_headers: Vec::new(),
            upload_url_support: false,
            max_request_bytes: None,
            max_response_bytes: None,
            accept_max_response_bytes_support: false,
            max_externalized_response_bytes: None,
            externalization_enabled: false,
            max_upload_bytes: None,
            supported_encodings: vec![DEFAULT_REQUEST_ENCODING.to_string()],
        }
    }
}

/// A pre-signed upload-URL pair returned by `request_upload_urls`.
#[derive(Debug, Clone)]
pub struct UploadUrl {
    pub upload_url: String,
    pub download_url: String,
    pub expires_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// Client-side HTTPS fetcher for external-location resolution
// ---------------------------------------------------------------------------

/// Reqwest-blocking `Fetcher` that returns the still-encoded body under a hard
/// cap. The shared external-location resolver performs bounded decoding.
struct ClientHttpFetcher {
    client: ReqwestClient,
}

fn redact_external_url(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return "<invalid external URL>".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

impl Fetcher for ClientHttpFetcher {
    fn fetch(&self, url: &str, _compression: Compression, max_bytes: usize) -> Result<Vec<u8>> {
        let mut resp = self.client.get(url).send().map_err(|_| {
            RpcError::runtime_error(format!(
                "external GET failed for {}",
                redact_external_url(url)
            ))
        })?;
        if !resp.status().is_success() {
            return Err(RpcError::runtime_error(format!(
                "external GET returned {} for {}",
                resp.status(),
                redact_external_url(url)
            )));
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = resp
                .read(&mut buf)
                .map_err(|_| RpcError::runtime_error("external GET body read failed"))?;
            if n == 0 {
                break;
            }
            if out.len() + n > max_bytes {
                return Err(RpcError::runtime_error(format!(
                    "external payload exceeds max_bytes={max_bytes}"
                )));
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(out)
    }

    fn fetch_with_policy(
        &self,
        url: &str,
        _compression: Compression,
        max_bytes: usize,
        validator: &UrlValidator,
        max_redirects: usize,
    ) -> Result<FetchedPayload> {
        use reqwest::header::{CONTENT_ENCODING, LOCATION};

        validate_external_url(validator, url)?;
        let mut current = reqwest::Url::parse(url)
            .map_err(|_| RpcError::value_error("URL rejected: invalid external URL"))?;
        let mut redirects = 0usize;
        loop {
            let mut resp = self.client.get(current.clone()).send().map_err(|_| {
                RpcError::runtime_error(format!(
                    "external GET failed for {}",
                    redact_external_url(current.as_str())
                ))
            })?;
            if resp.status().is_redirection() {
                if redirects >= max_redirects {
                    return Err(RpcError::runtime_error(format!(
                        "external fetch redirect limit ({max_redirects}) exceeded"
                    )));
                }
                let location = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| RpcError::runtime_error("external redirect missing Location"))?;
                let next = current.join(location).map_err(|_| {
                    RpcError::runtime_error("external redirect has invalid Location")
                })?;
                validate_external_url(validator, next.as_str())?;
                current = next;
                redirects += 1;
                continue;
            }
            if !resp.status().is_success() {
                return Err(RpcError::runtime_error(format!(
                    "external GET returned {} for {}",
                    resp.status(),
                    redact_external_url(current.as_str())
                )));
            }
            if let Some(len) = resp.content_length() {
                if len > max_bytes as u64 {
                    return Err(RpcError::runtime_error(format!(
                        "external payload Content-Length {len} exceeds max_fetch_bytes={max_bytes}"
                    )));
                }
            }
            let compression = resp
                .headers()
                .get(CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.eq_ignore_ascii_case("zstd"))
                .map_or(Compression::None, |_| Compression::Zstd(0));
            let mut out = Vec::new();
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = resp
                    .read(&mut buf)
                    .map_err(|_| RpcError::runtime_error("external GET body read failed"))?;
                if n == 0 {
                    break;
                }
                if out.len() + n > max_bytes {
                    return Err(RpcError::runtime_error(format!(
                        "external payload exceeds max_fetch_bytes={max_bytes}"
                    )));
                }
                out.extend_from_slice(&buf[..n]);
            }
            return Ok(FetchedPayload {
                bytes: out,
                compression,
            });
        }
    }
}

/// Storage backend that refuses uploads — the client resolves pointers but
/// never uploads through the `ExternalStorage` path (request externalization
/// uses the upload-URL flow instead).
struct NoopStorage;
impl ExternalStorage for NoopStorage {
    fn upload(&self, _ipc_bytes: &[u8], _compression: Compression) -> Result<UploadResult> {
        Err(RpcError::runtime_error(
            "client does not upload via ExternalStorage",
        ))
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for an [`HttpClient`].
pub struct HttpClientBuilder {
    base_url: String,
    prefix: String,
    headers: HeaderMap,
    on_log: Option<OnLog>,
    relax_nullability: bool,
    protocol_version: Option<String>,
    inner: Option<ReqwestClient>,
    timeout: Option<Duration>,
    retry: RetryConfig,
    compression_level: Option<i32>,
    external_validator: Option<UrlValidator>,
    max_encoded_response_bytes: usize,
    max_encoded_response_bytes_explicit: bool,
    max_decoded_response_bytes: usize,
    max_decoded_response_bytes_explicit: bool,
    accepted_max_response_bytes: usize,
}

impl HttpClientBuilder {
    /// Mount endpoints under a URL prefix (default empty).
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Add a default header sent on every request (e.g. `Authorization`).
    pub fn header(mut self, name: &str, value: &str) -> Result<Self> {
        let n = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| RpcError::value_error(format!("bad header name: {e}")))?;
        let v = HeaderValue::from_str(value)
            .map_err(|e| RpcError::value_error(format!("bad header value: {e}")))?;
        self.headers.insert(n, v);
        Ok(self)
    }

    /// Supply a preconfigured reqwest client (e.g. with custom TLS / auth).
    pub fn client(mut self, client: ReqwestClient) -> Self {
        self.inner = Some(client);
        self
    }

    pub fn on_log(mut self, f: OnLog) -> Self {
        self.on_log = Some(f);
        self
    }

    pub fn relax_nullability(mut self, yes: bool) -> Self {
        self.relax_nullability = yes;
        self
    }

    pub fn protocol_version(mut self, v: impl Into<String>) -> Self {
        self.protocol_version = Some(v.into());
        self
    }

    /// Per-request timeout (default 30s). `None` disables it.
    pub fn timeout(mut self, t: Option<Duration>) -> Self {
        self.timeout = t;
        self
    }

    /// Opt into replaying eligible requests after connection-level failures.
    /// Retries are disabled by default because unary and init handlers may
    /// have side effects. Exchange requests are never retried.
    pub fn retry(mut self, cfg: RetryConfig) -> Self {
        self.retry = cfg;
        self
    }

    /// zstd request-body compression level (default `Some(3)`). `None`
    /// disables request compression (identity bodies).
    pub fn compression_level(mut self, level: Option<i32>) -> Self {
        self.compression_level = level;
        self
    }

    /// Hard ceiling on response bytes read from the network, before content
    /// decoding. Applies with or without `Content-Length` (default 256 MiB).
    pub fn max_encoded_response_bytes(mut self, n: usize) -> Self {
        assert!(
            n >= MIN_ACCEPTED_MAX_RESPONSE_BYTES && (n as u64) <= MAX_SAFE_RESPONSE_BYTES,
            "max_encoded_response_bytes must be in 65536..=2^53-1"
        );
        self.max_encoded_response_bytes = n;
        self.max_encoded_response_bytes_explicit = true;
        self
    }

    /// Hard ceiling on a response after content decoding (default 256 MiB).
    /// This is independent from the encoded-byte ceiling, so a small zstd
    /// response cannot expand without bound.
    pub fn max_decoded_response_bytes(mut self, n: usize) -> Self {
        assert!(
            n >= MIN_ACCEPTED_MAX_RESPONSE_BYTES && (n as u64) <= MAX_SAFE_RESPONSE_BYTES,
            "max_decoded_response_bytes must be in 65536..=2^53-1"
        );
        self.max_decoded_response_bytes = n;
        self.max_decoded_response_bytes_explicit = true;
        self
    }

    /// Maximum decoded response this client is willing to accept. Sent on
    /// every request as `VGI-Accept-Max-Response-Bytes` and also enforced
    /// locally. Native clients default to 256 MiB.
    pub fn accepted_max_response_bytes(mut self, n: usize) -> Self {
        assert!(
            n >= MIN_ACCEPTED_MAX_RESPONSE_BYTES && (n as u64) <= MAX_SAFE_RESPONSE_BYTES,
            "accepted_max_response_bytes must be in 65536..=2^53-1"
        );
        self.accepted_max_response_bytes = n;
        if !self.max_encoded_response_bytes_explicit {
            self.max_encoded_response_bytes = n;
        }
        if !self.max_decoded_response_bytes_explicit {
            self.max_decoded_response_bytes = n;
        }
        self
    }

    /// Enable transparent external-location response resolution, validating
    /// fetched URLs with `validator` (use [`any_url_validator`] for trusted /
    /// test storage, [`safe_https_validator`](vgi_rpc::external::safe_https_validator)
    /// for production).
    pub fn external_resolution(mut self, validator: UrlValidator) -> Self {
        self.external_validator = Some(validator);
        self
    }

    /// Enable external resolution accepting any URL (trusted/test storage).
    pub fn external_resolution_any(self) -> Self {
        self.external_resolution(any_url_validator())
    }

    pub fn build(self) -> Result<HttpClient> {
        let inner = match self.inner {
            Some(ref c) => c.clone(),
            None => {
                let mut b = ReqwestClient::builder();
                if let Some(t) = self.timeout {
                    b = b.timeout(t);
                }
                b.build().map_err(|e| {
                    RpcError::new("TransportError", format!("build http client: {e}"))
                })?
            }
        };
        self.build_with_backend(HttpBackend::Reqwest(inner.clone()), inner)
    }

    #[cfg(feature = "iroh")]
    pub(crate) fn build_httpi(self, executor: crate::httpi::HttpiExecutor) -> Result<HttpClient> {
        let external_client = match self.inner.as_ref() {
            Some(client) => client.clone(),
            None => {
                let mut builder = ReqwestClient::builder();
                if let Some(timeout) = self.timeout {
                    builder = builder.timeout(timeout);
                }
                builder.build().map_err(|error| {
                    RpcError::new(
                        "TransportError",
                        format!("build external HTTP client: {error}"),
                    )
                })?
            }
        };
        self.build_with_backend(HttpBackend::Iroh(executor), external_client)
    }

    fn build_with_backend(
        self,
        backend: HttpBackend,
        external_client: ReqwestClient,
    ) -> Result<HttpClient> {
        // The fetcher uses its own redirect-free, timed client (SSRF-safer).
        let fetch_client = ReqwestClient::builder()
            .timeout(self.timeout.unwrap_or(DEFAULT_TIMEOUT))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| RpcError::new("TransportError", format!("build fetch client: {e}")))?;
        let external = self.external_validator.map(|validator| {
            let mut cfg = ExternalLocationConfig::new(
                Arc::new(NoopStorage),
                Arc::new(ClientHttpFetcher {
                    client: fetch_client,
                }),
            );
            cfg.url_validator = validator;
            cfg
        });
        Ok(HttpClient {
            base_url: self.base_url.trim_end_matches('/').to_string(),
            prefix: self.prefix,
            headers: self.headers,
            backend,
            external_client,
            on_log: self.on_log,
            relax_nullability: self.relax_nullability,
            protocol_version: self.protocol_version,
            retry: self.retry,
            compression_level: self.compression_level,
            max_encoded_response_bytes: self.max_encoded_response_bytes,
            max_decoded_response_bytes: self.max_decoded_response_bytes,
            accepted_max_response_bytes: self
                .accepted_max_response_bytes
                .min(self.max_decoded_response_bytes)
                .min(self.max_encoded_response_bytes),
            external,
            caps: RefCell::new(None),
            send_compressed: RefCell::new(self.compression_level.is_some()),
            session: None,
            session_stack: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Sticky-session state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SessionState {
    token: Option<String>,
    echo: BTreeMap<String, String>,
    detached: bool,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A blocking HTTP client for a vgi-rpc server.
pub struct HttpClient {
    base_url: String,
    prefix: String,
    headers: HeaderMap,
    backend: HttpBackend,
    /// Ordinary HTTP(S) remains authoritative for external upload URLs even
    /// when VGI requests themselves use `httpi://`.
    external_client: ReqwestClient,
    on_log: Option<OnLog>,
    relax_nullability: bool,
    protocol_version: Option<String>,
    retry: RetryConfig,
    compression_level: Option<i32>,
    max_encoded_response_bytes: usize,
    max_decoded_response_bytes: usize,
    accepted_max_response_bytes: usize,
    external: Option<ExternalLocationConfig>,
    caps: RefCell<Option<HttpServerCapabilities>>,
    /// Whether to zstd-compress request bodies (disabled after a 415).
    send_compressed: RefCell<bool>,
    /// The active sticky session (innermost), if any.
    session: Option<SessionState>,
    /// Outer sessions suspended by a nested `begin_session` (restored on
    /// `end_session`), so concurrent sessions on one client don't clobber.
    session_stack: Vec<SessionState>,
}

impl HttpClient {
    /// Start building a client for `base_url` (e.g. `http://127.0.0.1:8080`).
    pub fn connect(base_url: impl Into<String>) -> HttpClientBuilder {
        HttpClientBuilder {
            base_url: base_url.into(),
            prefix: String::new(),
            headers: HeaderMap::new(),
            on_log: None,
            relax_nullability: false,
            protocol_version: None,
            inner: None,
            timeout: Some(DEFAULT_TIMEOUT),
            retry: RetryConfig::default(),
            compression_level: Some(DEFAULT_COMPRESSION_LEVEL),
            external_validator: None,
            max_encoded_response_bytes: DEFAULT_MAX_ENCODED_RESPONSE_BYTES,
            max_encoded_response_bytes_explicit: false,
            max_decoded_response_bytes: DEFAULT_MAX_DECODED_RESPONSE_BYTES,
            max_decoded_response_bytes_explicit: false,
            accepted_max_response_bytes: DEFAULT_ACCEPTED_MAX_RESPONSE_BYTES,
        }
    }

    /// Start building a native blocking client for a canonical
    /// `httpi://<endpoint-id>[/base-path]` target.
    #[cfg(feature = "iroh")]
    pub fn connect_httpi(target: &str) -> Result<crate::httpi::HttpiClientBuilder> {
        crate::httpi::HttpiClientBuilder::connect(target)
    }

    /// Cryptographic identity presented by this native HTTPi client. Ordinary
    /// HTTP clients return `None`.
    #[cfg(feature = "iroh")]
    pub fn iroh_endpoint_id(&self) -> Option<String> {
        self.backend.iroh_endpoint_id()
    }

    fn target(&self, path: &str) -> String {
        self.backend.target(&self.base_url, &self.prefix, path)
    }

    /// Build per-request headers: content type, codec advertisement, and
    /// (when a session is active) sticky session headers.
    fn build_headers(&self, content_encoding: Option<&str>) -> HeaderMap {
        let mut h = self.headers.clone();
        h.insert(CONTENT_TYPE, HeaderValue::from_static(ARROW_CONTENT_TYPE));
        h.insert(
            ACCEPT_MAX_RESPONSE_BYTES_HEADER,
            HeaderValue::from_str(&self.accepted_max_response_bytes.to_string())
                .expect("validated response budget is a valid header"),
        );
        if let Some(enc) = content_encoding {
            if let Ok(v) = HeaderValue::from_str(enc) {
                h.insert(reqwest::header::CONTENT_ENCODING, v);
            }
            // Advertise the codecs we can decode on responses.
            h.insert(
                reqwest::header::ACCEPT_ENCODING,
                HeaderValue::from_static("zstd, gzip, identity"),
            );
        }
        if let Some(s) = self.session.as_ref() {
            h.insert(SESSION_ACCEPT_HEADER, HeaderValue::from_static("true"));
            if let Some(tok) = s.token.as_ref() {
                if let Ok(v) = HeaderValue::from_str(tok) {
                    h.insert(SESSION_HEADER, v);
                }
            }
            for (name, value) in &s.echo {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    h.insert(n, v);
                }
            }
        }
        h
    }

    /// Update sticky-session state from a response's headers.
    fn process_session_headers(&mut self, headers: &HeaderMap) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if let Some(tok) = headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok()) {
            session.token = Some(tok.to_string());
        }
        for (name, value) in headers.iter() {
            let n = name.as_str();
            if let Some(stripped) = n
                .strip_prefix(&ECHO_HEADER_PREFIX.to_ascii_lowercase())
                .or_else(|| n.strip_prefix(ECHO_HEADER_PREFIX))
            {
                if let Ok(v) = value.to_str() {
                    session.echo.insert(stripped.to_string(), v.to_string());
                }
            }
        }
        let closed = headers
            .get(SESSION_CLOSE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if closed {
            session.token = None;
        }
    }

    /// POST an Arrow body, with codec negotiation (415), request
    /// externalization (413), explicitly configured connection replay, and
    /// sticky-session header capture. Returns the response body bytes.
    fn post(&mut self, path: &str, body: Vec<u8>, retryable: bool) -> Result<Vec<u8>> {
        // The advertised/default receive budget is meaningful only after the
        // server has positively acknowledged the contract. This auth-exempt
        // probe is cached for the client lifetime.
        self.capabilities()?;
        // Proactive externalization when caps are known and the body is large.
        let body = self.maybe_externalize_request(body)?;
        let (mut resp_headers, mut bytes, mut status) = self.send(path, &body, retryable)?;
        // The server stamps `VGI-Supported-Encodings` on every response, so
        // the first reply already tells us whether it speaks compression —
        // no OPTIONS probe, and no wasted 415 round-trip against a server
        // that advertises none.
        self.refresh_supported_encodings(&resp_headers);

        // 415: server can't decode our request encoding — disable compression
        // and retry once with an identity body.
        if status == StatusCode::UNSUPPORTED_MEDIA_TYPE && *self.send_compressed.borrow() {
            self.refresh_supported_encodings(&resp_headers);
            *self.send_compressed.borrow_mut() = false;
            let (h, b, s) = self.send(path, &body, retryable)?;
            resp_headers = h;
            bytes = b;
            status = s;
        }

        // 413: request too large — externalize via upload URL and retry once.
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            let pointer = self.externalize_request_body(&body)?;
            let (h, b, s) = self.send(path, &pointer, retryable)?;
            resp_headers = h;
            bytes = b;
            status = s;
        }

        if status == StatusCode::UNAUTHORIZED {
            let txt = String::from_utf8_lossy(&bytes).to_string();
            return Err(RpcError::new("AuthenticationError", txt));
        }
        self.process_session_headers(&resp_headers);
        Ok(bytes)
    }

    /// One send attempt (with connection retry for `retryable` ops),
    /// returning `(response headers, decoded body, status)`. Decodes bounded
    /// zstd and gzip responses transparently.
    fn send(
        &self,
        path: &str,
        body: &[u8],
        retryable: bool,
    ) -> Result<(HeaderMap, Vec<u8>, StatusCode)> {
        let compress = *self.send_compressed.borrow();
        let (payload, content_encoding) = if compress {
            let level = self.compression_level.unwrap_or(DEFAULT_COMPRESSION_LEVEL);
            // Embed the content-size in the frame header — Python's one-shot
            // `zstandard` decompressor requires it, mirroring vgi-rpc's own
            // external compression.
            let mut enc = zstd::bulk::Compressor::new(level)
                .map_err(|e| RpcError::new("TransportError", format!("zstd init: {e}")))?;
            enc.set_parameter(zstd::stream::raw::CParameter::ContentSizeFlag(true))
                .map_err(|e| RpcError::new("TransportError", format!("zstd param: {e}")))?;
            let z = enc
                .compress(body)
                .map_err(|e| RpcError::new("TransportError", format!("zstd encode: {e}")))?;
            (z, Some("zstd"))
        } else {
            (body.to_vec(), None)
        };
        let headers = self.build_headers(content_encoding);
        let target = self.target(path);

        let attempts = if retryable {
            self.retry.max_attempts.max(1)
        } else {
            1
        };
        let mut last_err = None;
        for attempt in 0..attempts {
            if attempt > 0 {
                std::thread::sleep(self.retry.delay_before(attempt));
            }
            let res = self.backend.execute(
                Method::POST,
                target.clone(),
                headers.clone(),
                payload.clone(),
            );
            match res {
                Ok(resp) => {
                    let status = resp.status();
                    let resp_headers = resp.headers().clone();
                    if !has_single_response_budget_support(&resp_headers) {
                        return Err(RpcError::new(
                            "ProtocolError",
                            "server response does not advertise VGI-Accept-Max-Response-Bytes-Support: true",
                        ));
                    }
                    let response_encoding = resp_headers
                        .get(reqwest::header::CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_ascii_lowercase);
                    let discovered_server_limit = self
                        .caps
                        .borrow()
                        .as_ref()
                        .and_then(|caps| caps.max_response_bytes);
                    let response_server_limit = parse_max_response_bytes(&resp_headers)?;
                    let decoded_limit = [
                        Some(self.max_decoded_response_bytes as u64),
                        Some(self.accepted_max_response_bytes as u64),
                        discovered_server_limit,
                        response_server_limit,
                    ]
                    .into_iter()
                    .flatten()
                    .min()
                    .expect("local decoded response limits are always configured")
                        as usize;
                    // Encoded and decoded limits are independent for compressed
                    // representations. Identity bytes are already decoded, so
                    // bound them during the socket read instead of allocating up
                    // to the larger encoded safety ceiling first.
                    let identity_response = response_encoding
                        .as_deref()
                        .is_none_or(|encoding| encoding == "identity");
                    let decoded_budget_is_tighter =
                        decoded_limit <= self.max_encoded_response_bytes;
                    let encoded_limit = if identity_response {
                        self.max_encoded_response_bytes.min(decoded_limit)
                    } else {
                        self.max_encoded_response_bytes
                    };
                    let encoded_error_type = if identity_response && decoded_budget_is_tighter {
                        "ResponseTooLargeError"
                    } else {
                        "TransportError"
                    };
                    let encoded_description = if identity_response && decoded_budget_is_tighter {
                        "decoded HTTP identity response"
                    } else {
                        "encoded HTTP response (max_encoded_response_bytes)"
                    };
                    let raw = read_bounded_response(
                        resp,
                        encoded_limit,
                        encoded_description,
                        encoded_error_type,
                    )?;
                    let decoded = match response_encoding.as_deref() {
                        Some("zstd") => {
                            let mut decoder = zstd::Decoder::new(Cursor::new(raw.as_slice()))
                                .map_err(|e| {
                                    RpcError::new(
                                        "TransportError",
                                        format!("zstd decode response: {e}"),
                                    )
                                })?;
                            decoder
                                .window_log_max(zstd_window_log_for_limit(decoded_limit))
                                .map_err(|e| {
                                    RpcError::new(
                                        "TransportError",
                                        format!("zstd response window limit: {e}"),
                                    )
                                })?;
                            read_bounded(
                                decoder,
                                decoded_limit,
                                "decoded HTTP response (max_decoded_response_bytes)",
                                "ResponseTooLargeError",
                            )?
                        }
                        Some("gzip") => read_bounded(
                            flate2::read::GzDecoder::new(raw.as_slice()),
                            decoded_limit,
                            "decoded HTTP response (max_decoded_response_bytes)",
                            "ResponseTooLargeError",
                        )?,
                        _ => {
                            if raw.len() > decoded_limit {
                                return Err(RpcError::new(
                                    "ResponseTooLargeError",
                                    format!(
                                        "decoded HTTP response exceeds max_response_bytes ({} > {})",
                                        raw.len(), decoded_limit
                                    ),
                                ));
                            }
                            raw
                        }
                    };
                    return Ok((resp_headers, decoded, status));
                }
                Err(error) => {
                    last_err = Some(RpcError::new(
                        error.error.error_type,
                        format!("http post {path}: {}", error.error.message),
                    ));
                    if !error.retry_safe {
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| RpcError::new("TransportError", "http post failed")))
    }

    fn req_md(&self, method: &str, extra: Option<&Metadata>) -> (String, Metadata) {
        let id = generate_request_id();
        let md = build_request_metadata(method, &id, self.protocol_version.as_deref(), extra);
        (id, md)
    }

    /// Make a unary call.
    pub fn call_unary(
        &mut self,
        method: &str,
        params: &RecordBatch,
        metadata: Option<&Metadata>,
    ) -> Result<(RecordBatch, Metadata)> {
        let (_id, md) = self.req_md(method, metadata);
        let body = write_one_batch(params, Some(&md))?;
        let resp = self.post(method, body, true)?;
        let relax = self.relax_nullability;
        let external = self.external.clone();
        read_unary(&resp, &mut self.on_log, relax, external.as_ref())
    }

    /// Fetch the service description via `__describe__`.
    pub fn describe(&mut self) -> Result<ServiceDescription> {
        let params = empty_batch(empty_schema().as_ref())?;
        let (batch, md) = self.call_unary(DESCRIBE_METHOD_NAME, &params, None)?;
        parse_describe_batch(&batch, &md)
    }

    /// Open a producer stream over HTTP.
    pub fn open_producer(
        &mut self,
        method: &str,
        params: &RecordBatch,
        metadata: Option<&Metadata>,
        has_header: bool,
    ) -> Result<HttpStreamSession<'_>> {
        self.open_stream(method, params, metadata, has_header, false)
    }

    /// Open an exchange stream over HTTP.
    pub fn open_exchange(
        &mut self,
        method: &str,
        params: &RecordBatch,
        metadata: Option<&Metadata>,
        has_header: bool,
    ) -> Result<HttpStreamSession<'_>> {
        self.open_stream(method, params, metadata, has_header, true)
    }

    fn open_stream(
        &mut self,
        method: &str,
        params: &RecordBatch,
        metadata: Option<&Metadata>,
        has_header: bool,
        is_exchange: bool,
    ) -> Result<HttpStreamSession<'_>> {
        let (_id, md) = self.req_md(method, metadata);
        let body = write_one_batch(params, Some(&md))?;
        let resp = self.post(&format!("{method}/init"), body, true)?;

        let relax = self.relax_nullability;
        let external = self.external.clone();
        let mut cursor = Cursor::new(resp);
        let header = if has_header {
            read_substream(&mut cursor, &mut self.on_log, relax, external.as_ref())?
        } else {
            None
        };
        let parsed = parse_response(
            &mut cursor,
            &mut self.on_log,
            relax,
            is_exchange,
            external.as_ref(),
        )?;

        Ok(HttpStreamSession {
            client: self,
            method: method.to_string(),
            header,
            pending: parsed.batches.into(),
            finished: parsed.finished,
            token: parsed.token,
            call_token: parsed.call_token,
            cancelled: false,
        })
    }

    /// Resume a producer stream from a continuation `token` without re-binding.
    ///
    /// A continuation request (`POST {prefix}/{method}/exchange` carrying only
    /// the state token) is fully self-describing: the server recovers the
    /// producer state, schemas, and function identity from the signed token
    /// alone, so no bind/`init` round-trip is needed. This is the cheap path
    /// for a stateless relay that holds a per-batch token (see
    /// [`HttpStreamSession::next_with_token`]) and resumes on any
    /// connection/node — unlike `open_producer`, which would produce and
    /// discard a fresh first turn before seeking.
    ///
    /// The returned session is positioned at `token`; the first
    /// [`next_with_token`](HttpStreamSession::next_with_token) (or
    /// [`tick`](HttpStreamSession::tick)) issues the continuation.
    ///
    /// `token` is the opaque blob from
    /// [`next_with_token`](HttpStreamSession::next_with_token), which packs
    /// both the cursor and the call token — the resuming node may never have
    /// seen this stream's `/init`, so it needs both.
    ///
    /// Mirrors Python `_HttpProxy.resume_stream`.
    pub fn resume_stream(
        &mut self,
        method: &str,
        token: impl Into<String>,
    ) -> HttpStreamSession<'_> {
        let (cursor, call_token) = unpack_resume_token(&token.into());
        HttpStreamSession {
            client: self,
            method: method.to_string(),
            header: None,
            pending: VecDeque::new(),
            token: Some(cursor),
            call_token,
            finished: false,
            cancelled: false,
        }
    }

    /// Query server capabilities via `OPTIONS {prefix}/health` (cached).
    pub fn capabilities(&self) -> Result<HttpServerCapabilities> {
        if let Some(c) = self.caps.borrow().as_ref() {
            return Ok(c.clone());
        }
        let caps = self.fetch_capabilities()?;
        self.apply_supported_encodings(&caps.supported_encodings);
        *self.caps.borrow_mut() = Some(caps.clone());
        Ok(caps)
    }

    fn fetch_capabilities(&self) -> Result<HttpServerCapabilities> {
        let mut headers = self.headers.clone();
        headers.insert(
            ACCEPT_MAX_RESPONSE_BYTES_HEADER,
            HeaderValue::from_str(&self.accepted_max_response_bytes.to_string())
                .expect("validated response budget is a valid header"),
        );
        let resp = self
            .backend
            .execute(Method::OPTIONS, self.target("health"), headers, Vec::new())
            .map_err(|error| {
                RpcError::new(
                    error.error.error_type,
                    format!("options health: {}", error.error.message),
                )
            })?;
        require_response_budget_discovery(resp.status(), resp.headers())?;
        let max_response_bytes = parse_max_response_bytes(resp.headers())?;
        let mut caps = parse_caps(resp.headers());
        caps.max_response_bytes = max_response_bytes;
        Ok(caps)
    }

    /// Harvest `VGI-Supported-Encodings` from a response and cache it.
    ///
    /// An **absent** header is left alone — it says nothing new, and
    /// overwriting the cache with a guess would lose a real advertisement
    /// seen earlier. A **present but empty** header is recorded as the empty
    /// set, which is the whole reason this is not a plain `split()`: it is
    /// the server saying "no compression", and it must switch request
    /// compression off rather than read as "nothing to update".
    fn refresh_supported_encodings(&self, headers: &HeaderMap) {
        let Some(encs) = parse_supported_encodings(headers) else {
            return;
        };
        self.apply_supported_encodings(&encs);
        // Refine an already-discovered capability set, but never seed one:
        // a stub holding only this field would be served from cache by
        // `capabilities()` in place of the real `OPTIONS /health` probe,
        // silently reporting every other capability as absent.
        if let Some(caps) = self.caps.borrow_mut().as_mut() {
            caps.supported_encodings = encs;
        }
    }

    /// Stop compressing request bodies when the server's advertised set has
    /// no coding this client can produce — an empty set, or one listing only
    /// codings we cannot emit (this client produces zstd only).
    ///
    /// One-way on purpose: nothing here re-enables compression. The other
    /// path that clears the flag is the 415 fallback, and a server that has
    /// already rejected our coding should not be retried with it because a
    /// later response happened to advertise it.
    fn apply_supported_encodings(&self, encodings: &[String]) {
        if !encodings
            .iter()
            .any(|e| e.eq_ignore_ascii_case(DEFAULT_REQUEST_ENCODING))
        {
            *self.send_compressed.borrow_mut() = false;
        }
    }

    /// Request `count` pre-signed upload URLs from `__upload_url__/init`.
    pub fn request_upload_urls(&mut self, count: usize) -> Result<Vec<UploadUrl>> {
        use arrow_array::{Int64Array, RecordBatch as RB};
        let schema = upload_url_params_schema();
        let batch = RB::try_new(schema, vec![Arc::new(Int64Array::from(vec![count as i64]))])?;
        let (_id, md) = self.req_md(UPLOAD_URL_METHOD, None);
        let body = write_one_batch(&batch, Some(&md))?;
        let resp = self.post(&format!("{UPLOAD_URL_METHOD}/init"), body, true)?;
        parse_upload_urls(&resp, &mut self.on_log)
    }

    // --- sticky sessions --------------------------------------------------

    /// Begin a sticky session. The first request in the session sends
    /// `VGI-Session-Accept: true` (+ `token` when resuming); the server's
    /// `VGI-Session` response header is captured for subsequent requests.
    pub fn begin_session(&mut self, token: Option<String>) {
        if let Some(prev) = self.session.take() {
            self.session_stack.push(prev);
        }
        self.session = Some(SessionState {
            token,
            ..Default::default()
        });
    }

    /// The current session token (after the opening request), if any.
    pub fn current_session_token(&self) -> Option<String> {
        self.session.as_ref().and_then(|s| s.token.clone())
    }

    /// Server-directed echo headers captured during the session
    /// (`VGI-Echo-<name>` → `<name>: <value>`).
    pub fn current_echo_headers(&self) -> BTreeMap<String, String> {
        self.session
            .as_ref()
            .map(|s| s.echo.clone())
            .unwrap_or_default()
    }

    /// Hand the session token off, suppressing the exit-time DELETE. Returns
    /// the token.
    pub fn detach_session(&mut self) -> Option<String> {
        if let Some(s) = self.session.as_mut() {
            s.detached = true;
            return s.token.clone();
        }
        None
    }

    /// End the session: best-effort `DELETE {prefix}/__session__` when a live,
    /// non-detached token remains, then clear session state.
    pub fn end_session(&mut self) {
        if let Some(s) = self.session.take() {
            if !s.detached {
                if let Some(tok) = s.token {
                    let mut h = self.headers.clone();
                    if let Ok(v) = HeaderValue::from_str(&tok) {
                        h.insert(SESSION_HEADER, v);
                    }
                    let _ = self.backend.execute(
                        Method::DELETE,
                        self.target(SESSION_ENDPOINT),
                        h,
                        Vec::new(),
                    );
                }
            }
        }
        // Restore an outer session suspended by a nested begin_session.
        self.session = self.session_stack.pop();
    }

    // --- request externalization (413) -----------------------------------

    fn maybe_externalize_request(&mut self, body: Vec<u8>) -> Result<Vec<u8>> {
        let caps = self.caps.borrow().clone();
        if let Some(caps) = caps {
            if caps.upload_url_support {
                if let Some(max) = caps.max_request_bytes {
                    if body.len() as u64 > max {
                        return self.externalize_request_body(&body);
                    }
                }
            }
        }
        Ok(body)
    }

    /// Upload `body` to a server-vended URL and return a pointer-batch body
    /// carrying the original dispatch metadata + `vgi_rpc.location`.
    fn externalize_request_body(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        // Parse the original request batch + metadata.
        let (batch, mut md) = {
            let mut r = StreamReader::new(body)?;
            r.read_next()?.ok_or_else(|| {
                RpcError::new("TransportError", "empty request body to externalize")
            })?
        };
        let urls = self.request_upload_urls(1)?;
        let url = urls
            .into_iter()
            .next()
            .ok_or_else(|| RpcError::new("ProtocolError", "server returned no upload URLs"))?;
        // PUT the inline body to the upload URL.
        put_external_body(&self.external_client, &url.upload_url, body)?;
        // Build the pointer body: zero-row batch (original schema) + original
        // dispatch metadata + vgi_rpc.location.
        md.insert(LOCATION_KEY.to_string(), url.download_url);
        let pointer = empty_batch(batch.schema().as_ref())?;
        write_one_batch(&pointer, Some(&md))
    }
}

fn put_external_body(client: &ReqwestClient, url: &str, body: &[u8]) -> Result<()> {
    let response = client
        .put(url)
        .header(CONTENT_TYPE, ARROW_CONTENT_TYPE)
        .body(body.to_vec())
        .send()
        .map_err(|_| {
            RpcError::new(
                "ExternalUploadFailed",
                format!("PUT to upload URL failed for {}", redact_external_url(url)),
            )
        })?;
    if !response.status().is_success() {
        return Err(RpcError::new(
            "ExternalUploadFailed",
            format!("PUT to upload URL failed: HTTP {}", response.status()),
        ));
    }
    Ok(())
}

fn read_bounded_response(
    mut response: BackendResponse,
    max_bytes: usize,
    description: &str,
    limit_error_type: &str,
) -> Result<Vec<u8>> {
    if let Some(length) = response.content_length {
        if length > max_bytes as u64 {
            return Err(RpcError::new(
                limit_error_type,
                format!("{description} exceeds max_response_bytes ({length} > {max_bytes})"),
            ));
        }
    }
    read_bounded(&mut response.body, max_bytes, description, limit_error_type)
}

fn read_bounded(
    mut reader: impl Read,
    max_bytes: usize,
    description: &str,
    limit_error_type: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|error| {
            #[cfg(feature = "iroh")]
            if let Some(error) = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<vgi_iroh_transport::TransportError>())
            {
                return crate::httpi::transport_rpc_error(error.clone());
            }
            RpcError::new("TransportError", format!("read {description}: {error}"))
        })?;
        if n == 0 {
            return Ok(out);
        }
        if out.len().checked_add(n).is_none_or(|size| size > max_bytes) {
            let actual = out.len().saturating_add(n);
            return Err(RpcError::new(
                limit_error_type,
                format!("{description} exceeds max_response_bytes ({actual} > {max_bytes})"),
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
}

// ---------------------------------------------------------------------------
// Resume tokens
// ---------------------------------------------------------------------------

/// Pack a stream's cursor and call tokens into one opaque resume blob.
///
/// Callers of [`HttpStreamSession::next_with_token`] treat the result as
/// unstructured text to hand to
/// [`seek_to_token`](HttpStreamSession::seek_to_token) or
/// [`HttpClient::resume_stream`], possibly in another process. Both halves
/// have to travel: the node that serves the resumed turn may have no cached
/// knowledge of this stream.
///
/// Layout is `<cursor_len>:<cursor><call>`, and a stream with no call token
/// packs to the bare cursor. Both tokens are base64, whose alphabet contains
/// no `:`, so a bare cursor can never be mistaken for a packed pair — which
/// is what keeps tokens minted before the split readable.
///
/// This is deliberately *not* Python's binary
/// `[u32 LE cursor_len][cursor][call]` layout: the blob never crosses the
/// wire, it is a private encoding between nodes running this client, and
/// this port's API hands it out as a `String`.
fn pack_resume_token(cursor: &str, call_token: Option<&str>) -> String {
    match call_token {
        Some(call) => format!("{}:{}{}", cursor.len(), cursor, call),
        None => cursor.to_string(),
    }
}

/// Unpack a blob produced by [`pack_resume_token`].
///
/// A blob that carries no length prefix is a bare cursor — either minted by
/// a server that does not split its stream state, or by a client predating
/// the split.
fn unpack_resume_token(token: &str) -> (String, Option<String>) {
    let Some((len_str, rest)) = token.split_once(':') else {
        return (token.to_string(), None);
    };
    let Ok(cursor_len) = len_str.parse::<usize>() else {
        return (token.to_string(), None);
    };
    if cursor_len > rest.len() || !rest.is_char_boundary(cursor_len) {
        return (token.to_string(), None);
    }
    let (cursor, call) = rest.split_at(cursor_len);
    let call = if call.is_empty() {
        None
    } else {
        Some(call.to_string())
    };
    (cursor.to_string(), call)
}

// ---------------------------------------------------------------------------
// Stream session
// ---------------------------------------------------------------------------

/// One stateless HTTP stream session.
pub struct HttpStreamSession<'c> {
    client: &'c mut HttpClient,
    method: String,
    header: Option<(RecordBatch, Metadata)>,
    pending: VecDeque<(RecordBatch, Metadata)>,
    token: Option<String>,
    /// The stream's call token: handed over once by `/init` and echoed on
    /// every subsequent request. The server never re-issues it, so this is
    /// the only copy once the response is parsed.
    call_token: Option<String>,
    finished: bool,
    cancelled: bool,
}

impl HttpStreamSession<'_> {
    /// The stream's decoded header batch, if any.
    pub fn header(&self) -> Option<&(RecordBatch, Metadata)> {
        self.header.as_ref()
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Producer step: return the next emitted batch, or `None` at end-of-stream.
    pub fn tick(&mut self) -> Result<Option<(RecordBatch, Metadata)>> {
        self.tick_with_metadata(None)
    }

    /// Producer step with application custom metadata attached to the tick.
    pub fn tick_with_metadata(
        &mut self,
        metadata: Option<&Metadata>,
    ) -> Result<Option<(RecordBatch, Metadata)>> {
        if self.cancelled {
            return Err(RpcError::protocol_error("tick after cancel"));
        }
        loop {
            if let Some(item) = self.pending.pop_front() {
                return Ok(Some(item));
            }
            if self.finished || self.token.is_none() {
                self.finished = true;
                return Ok(None);
            }
            let token = self.token.clone().unwrap();
            let body = self.continuation_body(&token, false, metadata)?;
            // Producer continuation is idempotent (token-addressed) → retryable.
            let resp = self
                .client
                .post(&format!("{}/exchange", self.method), body, true)?;
            let relax = self.client.relax_nullability;
            let external = self.client.external.clone();
            let mut cursor = Cursor::new(resp);
            let parsed = parse_response(
                &mut cursor,
                &mut self.client.on_log,
                relax,
                false,
                external.as_ref(),
            )?;
            self.pending.extend(parsed.batches);
            self.token = parsed.token;
            self.finished = parsed.finished;
        }
    }

    /// Read one producer batch and surface the worker's continuation token.
    ///
    /// Reads exactly one data batch and returns it paired with the resume
    /// token that continues the stream AFTER that batch — the worker's own
    /// serialized producer state. A fresh session positioned at that token
    /// (see [`seek_to_token`](Self::seek_to_token) or
    /// [`HttpClient::resume_stream`]) resumes on any node, which is the
    /// basis for stateless, load-balanced relays that must not pin a scan
    /// to one process.
    ///
    /// Returns `None` at end-of-stream. Requires per-batch continuation
    /// tokens (the default server behaviour); errors if a single response
    /// carries more than one data batch (coarser-than-batch resume is not
    /// representable here).
    ///
    /// Drives the same wire protocol as [`tick`](Self::tick) but yields one
    /// `(batch, token)` per call instead of auto-following the token. Do not
    /// interleave with `tick`/`exchange` on the same session.
    #[allow(clippy::type_complexity)]
    pub fn next_with_token(&mut self) -> Result<Option<((RecordBatch, Metadata), Option<String>)>> {
        const MULTI: &str = "HTTP stream response contained more than one data batch";
        if self.cancelled {
            return Err(RpcError::protocol_error("next_with_token after cancel"));
        }
        // Init may have preloaded one data batch; its resume point is the
        // token already held by the session.
        if !self.pending.is_empty() {
            if self.pending.len() > 1 {
                return Err(RpcError::protocol_error(MULTI));
            }
            let item = self.pending.pop_front().unwrap();
            return Ok(Some((item, self.resume_token())));
        }

        if self.finished || self.token.is_none() {
            self.finished = true;
            return Ok(None);
        }

        let token = self.token.clone().unwrap();
        let body = self.continuation_body(&token, false, None)?;
        // Producer continuation is idempotent (token-addressed) → retryable.
        let resp = self
            .client
            .post(&format!("{}/exchange", self.method), body, true)?;
        let relax = self.client.relax_nullability;
        let external = self.client.external.clone();
        let mut cursor = Cursor::new(resp);
        let parsed = parse_response(
            &mut cursor,
            &mut self.client.on_log,
            relax,
            false,
            external.as_ref(),
        )?;
        if parsed.batches.len() > 1 {
            return Err(RpcError::protocol_error(MULTI));
        }
        self.token = parsed.token;
        match parsed.batches.into_iter().next() {
            Some(item) => Ok(Some((item, self.resume_token()))),
            None => {
                // No data this turn → the producer finished (no token).
                self.finished = true;
                Ok(None)
            }
        }
    }

    /// Reposition a freshly-initialised session to resume from `token`.
    ///
    /// Discards any init-preloaded batches and points the session at the
    /// given resume token (as returned by
    /// [`next_with_token`](Self::next_with_token)), so the next call
    /// continues from exactly there. Used to resume a scan on a new
    /// process/node — which is why the call token travels inside the blob
    /// too: that node may never have seen this stream's `/init`.
    pub fn seek_to_token(&mut self, token: impl Into<String>) {
        let (cursor, call_token) = unpack_resume_token(&token.into());
        self.pending.clear();
        self.token = Some(cursor);
        self.call_token = call_token;
        self.finished = false;
    }

    /// Exchange step: send `input`, return the server's response batch.
    pub fn exchange(
        &mut self,
        input: &RecordBatch,
        metadata: Option<&Metadata>,
    ) -> Result<Option<(RecordBatch, Metadata)>> {
        if self.cancelled {
            return Err(RpcError::protocol_error("exchange after cancel"));
        }
        let token = self
            .token
            .clone()
            .ok_or_else(|| RpcError::protocol_error("exchange without a stream token"))?;
        let mut md = metadata.cloned().unwrap_or_default();
        md.insert(STATE_KEY.to_string(), token);
        if let Some(call) = self.call_token.as_ref() {
            md.insert(CALL_STATE_KEY.to_string(), call.clone());
        }
        let body = write_one_batch(input, Some(&md))?;
        // Exchange is NEVER retried (process() may have side effects).
        let resp = self
            .client
            .post(&format!("{}/exchange", self.method), body, false)?;
        let relax = self.client.relax_nullability;
        let external = self.client.external.clone();
        let mut cursor = Cursor::new(resp);
        let parsed = parse_response(
            &mut cursor,
            &mut self.client.on_log,
            relax,
            true,
            external.as_ref(),
        )?;
        self.token = parsed.token;
        Ok(parsed.batches.into_iter().next())
    }

    /// Cancel the stream (best-effort POST then mark cancelled). Idempotent.
    pub fn cancel(&mut self) -> Result<()> {
        if self.cancelled {
            return Ok(());
        }
        if let Some(token) = self.token.clone() {
            let body = self.continuation_body(&token, true, None)?;
            let _ = self
                .client
                .post(&format!("{}/exchange", self.method), body, false);
        }
        self.cancelled = true;
        self.finished = true;
        Ok(())
    }

    /// No-op: HTTP streaming is stateless, nothing to tear down.
    pub fn close(&mut self) -> Result<()> {
        Ok(())
    }

    /// The current continuation token (for stateless relay / resume).
    ///
    /// This is the cursor half only. To hand a stream's position to another
    /// process, use [`next_with_token`](Self::next_with_token), whose blob
    /// also carries the call token that node will need.
    pub fn current_token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Encode this session's current position as one opaque resume blob.
    fn resume_token(&self) -> Option<String> {
        self.token
            .as_deref()
            .map(|cursor| pack_resume_token(cursor, self.call_token.as_deref()))
    }

    /// Build a continuation request body.
    ///
    /// The call token is echoed on every request because the server does not
    /// re-issue it; a request that omitted it would still succeed while the
    /// server's call-state cache is warm and fail once it is not — exactly
    /// the kind of load-dependent bug worth designing out.
    fn continuation_body(
        &self,
        token: &str,
        cancel: bool,
        application_metadata: Option<&Metadata>,
    ) -> Result<Vec<u8>> {
        let batch = empty_batch(&Schema::empty())?;
        let mut md = application_metadata.cloned().unwrap_or_default();
        md.insert(STATE_KEY.to_string(), token.to_string());
        if let Some(call) = self.call_token.as_ref() {
            md.insert(CALL_STATE_KEY.to_string(), call.clone());
        }
        md.insert(REQUEST_ID_KEY.to_string(), generate_request_id());
        if cancel {
            md.insert(CANCEL_KEY.to_string(), "1".to_string());
        }
        write_one_batch(&batch, Some(&md))
    }
}

// ---------------------------------------------------------------------------
// Response parsing helpers
// ---------------------------------------------------------------------------

struct ParsedStream {
    batches: Vec<(RecordBatch, Metadata)>,
    token: Option<String>,
    /// The call token, when the server split its stream state. Only `/init`
    /// carries one; continuations never re-issue it.
    call_token: Option<String>,
    finished: bool,
}

fn read_unary(
    bytes: &[u8],
    on_log: &mut Option<OnLog>,
    relax: bool,
    external: Option<&ExternalLocationConfig>,
) -> Result<(RecordBatch, Metadata)> {
    let mut cursor = Cursor::new(bytes);
    let parsed = parse_response(&mut cursor, on_log, relax, true, external)?;
    parsed
        .batches
        .into_iter()
        .next()
        .ok_or_else(|| RpcError::new("TransportError", "no result batch in http response"))
}

/// Parse one IPC stream, dispatching logs, resolving external-location
/// pointers, and collecting data batches + the continuation token.
fn parse_response(
    r: &mut impl Read,
    on_log: &mut Option<OnLog>,
    relax: bool,
    treat_state_frame_as_data: bool,
    external: Option<&ExternalLocationConfig>,
) -> Result<ParsedStream> {
    let mut reader = StreamReader::new(r)?;
    if relax {
        reader = reader.relax_nullability();
    }
    let mut out = ParsedStream {
        batches: Vec::new(),
        token: None,
        call_token: None,
        finished: true,
    };
    while let Some((batch, md)) = reader.read_next()? {
        if let Err(e) = process_frame(
            batch,
            md,
            on_log,
            relax,
            treat_state_frame_as_data,
            external,
            &mut out,
            true,
        ) {
            let _ = reader.drain();
            return Err(e);
        }
    }
    if out.batches.len() > 1 {
        return Err(RpcError::protocol_error(
            "HTTP response contained more than one data batch",
        ));
    }
    out.finished = out.token.is_none();
    Ok(out)
}

/// Process one response frame: dispatch logs, surface errors, collect data and
/// the continuation token. An external-location pointer is fetched and its
/// inner stream processed recursively (one level — redirect loops are rejected
/// by the fetch validator), so peers that externalize a whole
/// logs-then-data output (Python) resolve identically to those that
/// externalize only the data batch (Rust).
#[allow(clippy::too_many_arguments)]
fn process_frame(
    batch: RecordBatch,
    mut md: Metadata,
    on_log: &mut Option<OnLog>,
    relax: bool,
    treat_state_frame_as_data: bool,
    external: Option<&ExternalLocationConfig>,
    out: &mut ParsedStream,
    allow_external: bool,
) -> Result<()> {
    match classify(&batch, &md) {
        BatchKind::Log(m) => {
            if let Some(cb) = on_log.as_mut() {
                cb(m);
            }
            Ok(())
        }
        BatchKind::Exception(e) => Err(e),
        BatchKind::Data => {
            if allow_external {
                if let Some(cfg) = external {
                    if vgi_rpc::wire::md_get(&md, LOCATION_KEY).is_some() {
                        // The token may ride on the outer pointer (Rust) — keep it.
                        if let Some(tok) = md.remove(STATE_KEY) {
                            out.token = Some(tok);
                        }
                        if let Some(call) = md.remove(CALL_STATE_KEY) {
                            out.call_token = Some(call);
                        }
                        if let Some(inner) = vgi_rpc::external::fetch_external_ipc_bytes(&md, cfg)?
                        {
                            let mut ir = StreamReader::new(&inner[..])?;
                            if relax {
                                ir = ir.relax_nullability();
                            }
                            while let Some((ib, imd)) = ir.read_next()? {
                                // No nested external (loop guard).
                                process_frame(
                                    ib,
                                    imd,
                                    on_log,
                                    relax,
                                    treat_state_frame_as_data,
                                    external,
                                    out,
                                    false,
                                )?;
                            }
                        }
                        return Ok(());
                    }
                }
            }
            // `/init` pairs the call token with the cursor on the same frame;
            // strip it either way so it never leaks into user metadata.
            let call = md.remove(CALL_STATE_KEY);
            if call.is_some() {
                out.call_token = call;
            }
            if let Some(tok) = md.remove(STATE_KEY) {
                out.token = Some(tok);
                // Exchange servers normally merge the refreshed token onto
                // their one output batch. Older/raw-compatible peers may
                // instead write the DATA batch followed by a zero-row token
                // sentinel (notably when both schemas have zero columns).
                // Once this turn already yielded DATA, that trailing sentinel
                // is control, not a second DATA batch. A non-empty token frame
                // is always data and therefore remains subject to the
                // one-batch rejection below.
                if treat_state_frame_as_data && (batch.num_rows() != 0 || out.batches.is_empty()) {
                    out.batches.push((batch, md));
                }
            } else {
                out.batches.push((batch, md));
            }
            Ok(())
        }
    }
}

fn read_substream(
    r: &mut impl Read,
    on_log: &mut Option<OnLog>,
    relax: bool,
    external: Option<&ExternalLocationConfig>,
) -> Result<Option<(RecordBatch, Metadata)>> {
    let parsed = parse_response(r, on_log, relax, true, external)?;
    Ok(parsed.batches.into_iter().next())
}

fn parse_upload_urls(bytes: &[u8], on_log: &mut Option<OnLog>) -> Result<Vec<UploadUrl>> {
    use arrow_array::cast::AsArray;
    use arrow_array::Array;
    let mut reader = StreamReader::new(bytes)?;
    let mut out = Vec::new();
    while let Some((batch, md)) = reader.read_next()? {
        match classify(&batch, &md) {
            BatchKind::Log(m) => {
                if let Some(cb) = on_log.as_mut() {
                    cb(m);
                }
            }
            BatchKind::Exception(e) => {
                let _ = reader.drain();
                return Err(e);
            }
            BatchKind::Data => {
                let up = batch
                    .column_by_name("upload_url")
                    .ok_or_else(|| RpcError::new("ProtocolError", "upload_url missing"))?
                    .as_string::<i32>();
                let down = batch
                    .column_by_name("download_url")
                    .ok_or_else(|| RpcError::new("ProtocolError", "download_url missing"))?
                    .as_string::<i32>();
                let exp = batch.column_by_name("expires_at");
                for i in 0..batch.num_rows() {
                    let expires_at = exp.and_then(|c| {
                        c.as_any()
                            .downcast_ref::<arrow_array::Int64Array>()
                            .filter(|a| !a.is_null(i))
                            .map(|a| a.value(i))
                    });
                    out.push(UploadUrl {
                        upload_url: up.value(i).to_string(),
                        download_url: down.value(i).to_string(),
                        expires_at,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Read `VGI-Supported-Encodings`, keeping absent and present-but-empty
/// apart — a plain `split()` maps both to an empty list, which is wrong for
/// one of them.
///
/// Returns `None` only when the header is absent. Mirrors Python's
/// `http_capabilities` / `_refresh_supported_encodings_from_response`:
///
/// - absent ⇒ `None`; callers substitute `["zstd"]`, the pre-advertisement
///   server's capability.
/// - present but empty ⇒ `Some([])`, the server stating it speaks no
///   compression. Substituting zstd here would send it bodies it cannot
///   decode.
/// - present, non-empty ⇒ `Some(list)`, lowercased and trimmed, order
///   preserved.
fn parse_supported_encodings(h: &HeaderMap) -> Option<Vec<String>> {
    let raw = h
        .get(SUPPORTED_ENCODINGS_HEADER)
        .and_then(|v| v.to_str().ok())?;
    Some(
        raw.split(',')
            .map(|p| p.trim().to_ascii_lowercase())
            .filter(|p| !p.is_empty())
            .collect(),
    )
}

fn parse_max_response_bytes(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut values = headers.get_all(MAX_RESPONSE_BYTES_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RpcError::new(
            "ProtocolError",
            "VGI-Max-Response-Bytes must occur exactly once",
        ));
    }
    let raw = value.to_str().map_err(|_| {
        RpcError::new(
            "ProtocolError",
            "VGI-Max-Response-Bytes must be canonical ASCII digits",
        )
    })?;
    if raw.is_empty() || raw.starts_with('0') || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RpcError::new(
            "ProtocolError",
            "VGI-Max-Response-Bytes must match [1-9][0-9]*",
        ));
    }
    let parsed = raw.parse::<u64>().map_err(|_| {
        RpcError::new(
            "ProtocolError",
            "VGI-Max-Response-Bytes is outside the supported range",
        )
    })?;
    if !(MIN_ACCEPTED_MAX_RESPONSE_BYTES as u64..=MAX_SAFE_RESPONSE_BYTES).contains(&parsed) {
        return Err(RpcError::new(
            "ProtocolError",
            "VGI-Max-Response-Bytes must be in 65536..=2^53-1",
        ));
    }
    Ok(Some(parsed))
}

#[cfg(feature = "iroh")]
fn parse_content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut values = headers.get_all(reqwest::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RpcError::new(
            "ProtocolError",
            "Iroh HTTP Content-Length must occur at most once",
        ));
    }
    let value = value.to_str().map_err(|_| {
        RpcError::new(
            "ProtocolError",
            "Iroh HTTP Content-Length must contain ASCII digits",
        )
    })?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RpcError::new(
            "ProtocolError",
            "Iroh HTTP Content-Length must contain ASCII digits",
        ));
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| RpcError::new("ProtocolError", "Iroh HTTP Content-Length is too large"))
}

fn parse_caps(h: &HeaderMap) -> HttpServerCapabilities {
    let get = |name: &str| {
        h.get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let parse_u64 = |name: &str| get(name).and_then(|s| s.parse::<u64>().ok());
    let split = |name: &str| {
        get(name)
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    HttpServerCapabilities {
        sticky_enabled: get(STICKY_ENABLED_HEADER).as_deref() == Some("true"),
        sticky_default_ttl: parse_u64(STICKY_DEFAULT_TTL_HEADER),
        sticky_echo_headers: split(STICKY_ECHO_HEADERS_HEADER),
        upload_url_support: get(UPLOAD_URL_HEADER).as_deref() == Some("true"),
        max_request_bytes: parse_u64(MAX_REQUEST_BYTES_HEADER),
        max_response_bytes: parse_max_response_bytes(h).ok().flatten(),
        accept_max_response_bytes_support: has_single_response_budget_support(h),
        max_externalized_response_bytes: parse_u64(MAX_EXTERNALIZED_RESPONSE_BYTES_HEADER),
        externalization_enabled: get(EXTERNALIZATION_ENABLED_HEADER).as_deref() == Some("true"),
        max_upload_bytes: parse_u64(MAX_UPLOAD_BYTES_HEADER),
        // Absent ⇒ legacy server ⇒ assume zstd. `split` would have said
        // "no codecs", which is the present-but-empty answer.
        supported_encodings: parse_supported_encodings(h)
            .unwrap_or_else(|| vec![DEFAULT_REQUEST_ENCODING.to_string()]),
    }
}

fn has_single_response_budget_support(headers: &HeaderMap) -> bool {
    let mut values = headers
        .get_all(ACCEPT_MAX_RESPONSE_BYTES_SUPPORT_HEADER)
        .iter();
    matches!(
        values.next().and_then(|value| value.to_str().ok()),
        Some("true")
    ) && values.next().is_none()
}

fn require_response_budget_discovery(status: StatusCode, headers: &HeaderMap) -> Result<()> {
    if !status.is_success() {
        return Err(RpcError::new(
            "ProtocolError",
            format!("response-budget discovery returned HTTP {status}"),
        ));
    }
    if !has_single_response_budget_support(headers) {
        return Err(RpcError::new(
            "ProtocolError",
            "server does not advertise exactly one VGI-Accept-Max-Response-Bytes-Support: true",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::Int64Array;
    use arrow_schema::{DataType, Field, Schema};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn capability_parser_reports_accept_max_response_support() {
        assert!(!parse_caps(&HeaderMap::new()).accept_max_response_bytes_support);
        assert!(
            parse_caps(&headers(&[(
                ACCEPT_MAX_RESPONSE_BYTES_SUPPORT_HEADER,
                "true"
            )]))
            .accept_max_response_bytes_support
        );
        assert!(
            !parse_caps(&headers(&[(
                ACCEPT_MAX_RESPONSE_BYTES_SUPPORT_HEADER,
                "TRUE"
            )]))
            .accept_max_response_bytes_support
        );
        assert!(
            !parse_caps(&headers(&[(
                ACCEPT_MAX_RESPONSE_BYTES_SUPPORT_HEADER,
                "false"
            )]))
            .accept_max_response_bytes_support
        );
        let mut duplicate = HeaderMap::new();
        duplicate.append(
            HeaderName::from_static("vgi-accept-max-response-bytes-support"),
            HeaderValue::from_static("true"),
        );
        duplicate.append(
            HeaderName::from_static("vgi-accept-max-response-bytes-support"),
            HeaderValue::from_static("true"),
        );
        assert!(!parse_caps(&duplicate).accept_max_response_bytes_support);
    }

    #[test]
    fn response_budget_discovery_requires_success_and_exact_support() {
        let supported = headers(&[(ACCEPT_MAX_RESPONSE_BYTES_SUPPORT_HEADER, "true")]);
        assert!(require_response_budget_discovery(StatusCode::OK, &supported).is_ok());
        assert!(require_response_budget_discovery(StatusCode::NO_CONTENT, &supported).is_ok());
        assert!(
            require_response_budget_discovery(StatusCode::INTERNAL_SERVER_ERROR, &supported)
                .is_err()
        );
        assert!(require_response_budget_discovery(StatusCode::OK, &HeaderMap::new()).is_err());
    }

    #[test]
    fn advertised_max_response_bytes_uses_strict_safe_integer_grammar() {
        for valid in ["65536", "9007199254740991"] {
            let parsed =
                parse_max_response_bytes(&headers(&[(MAX_RESPONSE_BYTES_HEADER, valid)])).unwrap();
            assert_eq!(parsed, Some(valid.parse::<u64>().unwrap()));
        }
        for invalid in [
            "",
            "0",
            "065536",
            "+65536",
            "65535",
            "9007199254740992",
            "65536, 65536",
            " 65536",
        ] {
            assert!(
                parse_max_response_bytes(&headers(&[(MAX_RESPONSE_BYTES_HEADER, invalid)]))
                    .is_err(),
                "accepted invalid VGI-Max-Response-Bytes={invalid:?}"
            );
        }
        let mut duplicate = HeaderMap::new();
        duplicate.append(
            HeaderName::from_static("vgi-max-response-bytes"),
            HeaderValue::from_static("65536"),
        );
        duplicate.append(
            HeaderName::from_static("vgi-max-response-bytes"),
            HeaderValue::from_static("65536"),
        );
        assert!(parse_max_response_bytes(&duplicate).is_err());
    }

    #[test]
    fn native_client_sends_and_locally_enforces_the_same_default_budget() {
        let client = HttpClient::connect("http://127.0.0.1").build().unwrap();
        assert_eq!(
            client
                .build_headers(None)
                .get(ACCEPT_MAX_RESPONSE_BYTES_HEADER)
                .unwrap(),
            "268435456"
        );
        assert_eq!(client.accepted_max_response_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn decoded_acceptance_does_not_redefine_the_independent_encoded_cap() {
        let client = HttpClient::connect("http://127.0.0.1")
            .accepted_max_response_bytes(64 * 1024)
            .max_encoded_response_bytes(128 * 1024)
            .build()
            .unwrap();
        assert_eq!(client.accepted_max_response_bytes, 64 * 1024);
        assert_eq!(client.max_encoded_response_bytes, 128 * 1024);
    }

    #[test]
    fn advertised_acceptance_matches_the_actual_decoded_ceiling_in_any_option_order() {
        let one_gib = 1024 * 1024 * 1024;
        let expanded = HttpClient::connect("http://127.0.0.1")
            .accepted_max_response_bytes(one_gib)
            .build()
            .unwrap();
        assert_eq!(expanded.accepted_max_response_bytes, one_gib);
        assert_eq!(expanded.max_decoded_response_bytes, one_gib);
        assert_eq!(expanded.max_encoded_response_bytes, one_gib);
        assert_eq!(
            expanded
                .build_headers(None)
                .get(ACCEPT_MAX_RESPONSE_BYTES_HEADER)
                .unwrap(),
            "1073741824"
        );

        for constrained in [
            HttpClient::connect("http://127.0.0.1")
                .accepted_max_response_bytes(one_gib)
                .max_decoded_response_bytes(128 * 1024),
            HttpClient::connect("http://127.0.0.1")
                .max_decoded_response_bytes(128 * 1024)
                .accepted_max_response_bytes(one_gib),
            HttpClient::connect("http://127.0.0.1")
                .accepted_max_response_bytes(one_gib)
                .max_encoded_response_bytes(128 * 1024),
            HttpClient::connect("http://127.0.0.1")
                .max_encoded_response_bytes(128 * 1024)
                .accepted_max_response_bytes(one_gib),
        ] {
            let client = constrained.build().unwrap();
            assert_eq!(client.accepted_max_response_bytes, 128 * 1024);
            assert_eq!(
                client
                    .build_headers(None)
                    .get(ACCEPT_MAX_RESPONSE_BYTES_HEADER)
                    .unwrap(),
                "131072"
            );
        }
    }

    #[test]
    fn response_parser_rejects_multiple_data_batches() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int64,
            false,
        )]));
        let mut bytes = Vec::new();
        {
            let mut writer = vgi_rpc::wire::StreamWriter::new(&mut bytes, schema.as_ref()).unwrap();
            for value in [1, 2] {
                let batch = RecordBatch::try_new(
                    schema.clone(),
                    vec![Arc::new(Int64Array::from(vec![value]))],
                )
                .unwrap();
                writer.write(&batch, None).unwrap();
            }
            writer.finish().unwrap();
        }

        let err = parse_response(&mut Cursor::new(bytes), &mut None, false, false, None)
            .err()
            .expect("multiple DATA batches must fail");
        assert_eq!(err.error_type, "ProtocolError");
    }

    #[test]
    fn response_parser_accepts_data_then_zero_row_token_sentinel() {
        let schema = Arc::new(Schema::empty());
        let mut bytes = Vec::new();
        {
            let mut writer = vgi_rpc::wire::StreamWriter::new(&mut bytes, schema.as_ref()).unwrap();
            let empty = RecordBatch::new_empty(schema.clone());
            writer.write(&empty, None).unwrap();
            writer
                .write(
                    &empty,
                    Some(&Metadata::from([(
                        STATE_KEY.to_string(),
                        "cursor".to_string(),
                    )])),
                )
                .unwrap();
            writer.finish().unwrap();
        }

        let parsed = parse_response(&mut Cursor::new(bytes), &mut None, false, true, None).unwrap();
        assert_eq!(parsed.batches.len(), 1);
        assert_eq!(parsed.token.as_deref(), Some("cursor"));
    }

    /// The three answers `VGI-Supported-Encodings` can give must stay
    /// distinguishable. A plain `split()` collapses "absent" and "present but
    /// empty" into the same empty list, and they mean opposite things: the
    /// first is an old server that certainly accepts zstd, the second is a
    /// server stating it accepts none.
    #[test]
    fn supported_encodings_separates_absent_from_present_but_empty() {
        assert_eq!(parse_supported_encodings(&HeaderMap::new()), None);
        assert_eq!(
            parse_supported_encodings(&headers(&[(SUPPORTED_ENCODINGS_HEADER, "")])),
            Some(vec![])
        );
        // Whitespace-only is still "present but empty" — a server writing
        // ", ," is saying nothing, not naming a codec.
        assert_eq!(
            parse_supported_encodings(&headers(&[(SUPPORTED_ENCODINGS_HEADER, " , ")])),
            Some(vec![])
        );
        assert_eq!(
            parse_supported_encodings(&headers(&[(SUPPORTED_ENCODINGS_HEADER, "ZSTD, gzip")])),
            Some(vec!["zstd".to_string(), "gzip".to_string()]),
            "tokens are lowercased and the server's order is preserved"
        );
    }

    #[test]
    fn caps_assume_zstd_only_when_the_header_is_absent() {
        // Absent ⇒ a server predating the advertisement. Every such server
        // decoded zstd, so keep compressing.
        assert_eq!(
            parse_caps(&HeaderMap::new()).supported_encodings,
            vec!["zstd".to_string()]
        );
        // Present-but-empty ⇒ the server says it speaks no compression.
        // Substituting zstd here would send it bodies it rejects with a 415.
        assert!(parse_caps(&headers(&[(SUPPORTED_ENCODINGS_HEADER, "")]))
            .supported_encodings
            .is_empty());
        assert_eq!(
            parse_caps(&headers(&[(SUPPORTED_ENCODINGS_HEADER, "zstd")])).supported_encodings,
            vec!["zstd".to_string()]
        );
    }

    /// An undiscovered server is a legacy server, not one refusing
    /// compression — so the field's default is `zstd`, matching Python's
    /// `HttpServerCapabilities.supported_encodings = (Encoding.ZSTD,)`.
    #[test]
    fn default_caps_assume_zstd() {
        assert_eq!(
            HttpServerCapabilities::default().supported_encodings,
            vec!["zstd".to_string()]
        );
    }

    #[test]
    fn upload_url_request_uses_shared_nullable_count_schema() {
        let schema = upload_url_params_schema();
        assert_eq!(schema.fields().len(), 1);
        assert_eq!(schema.field(0).name(), "count");
        assert_eq!(schema.field(0).data_type(), &arrow_schema::DataType::Int64);
        assert!(schema.field(0).is_nullable());
    }

    #[test]
    fn external_upload_connection_error_redacts_signed_query() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let secret = "UPLOAD_QUERY_SECRET_7f33";
        let url = format!("http://{address}/upload?signature={secret}");
        let client = ReqwestClient::builder()
            .timeout(Duration::from_millis(250))
            .build()
            .unwrap();
        let error = put_external_body(&client, &url, b"body").unwrap_err();
        let rendered = format!("{error:?}");
        assert!(
            !rendered.contains(secret),
            "leaked signed query: {rendered}"
        );
        assert!(rendered.contains("/upload"));
    }
}
