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
use reqwest::blocking::Client as HttpInner;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::{Method, StatusCode};

use vgi_rpc::errors::{Result, RpcError};
use vgi_rpc::external::{
    any_url_validator, Compression, ExternalLocationConfig, ExternalStorage, Fetcher, UploadResult,
    UrlValidator,
};
use vgi_rpc::introspect::DESCRIBE_METHOD_NAME;
use vgi_rpc::metadata::{CANCEL_KEY, LOCATION_KEY, REQUEST_ID_KEY, STATE_KEY};
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
const MAX_EXTERNALIZED_RESPONSE_BYTES_HEADER: &str = "VGI-Max-Externalized-Response-Bytes";
const EXTERNALIZATION_ENABLED_HEADER: &str = "VGI-Externalization-Enabled";
const MAX_UPLOAD_BYTES_HEADER: &str = "VGI-Max-Upload-Bytes";
const UPLOAD_URL_HEADER: &str = "VGI-Upload-URL-Support";
const SESSION_ENDPOINT: &str = "__session__";
// The upload-URL method name is a shared public wire contract, not a
// client-local literal.
use vgi_rpc::external::UPLOAD_URL_METHOD;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// Server capabilities advertised on `OPTIONS {prefix}/health`.
#[derive(Debug, Clone, Default)]
pub struct HttpServerCapabilities {
    pub sticky_enabled: bool,
    pub sticky_default_ttl: Option<u64>,
    pub sticky_echo_headers: Vec<String>,
    pub upload_url_support: bool,
    pub max_request_bytes: Option<u64>,
    pub max_response_bytes: Option<u64>,
    pub max_externalized_response_bytes: Option<u64>,
    pub externalization_enabled: bool,
    pub max_upload_bytes: Option<u64>,
    pub supported_encodings: Vec<String>,
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

/// Reqwest-blocking `Fetcher` that transparently decompresses a `zstd`
/// `Content-Encoding` (mirrors httpx) and caps the buffered body.
struct ClientHttpFetcher {
    client: HttpInner,
}

impl Fetcher for ClientHttpFetcher {
    fn fetch(&self, url: &str, _compression: Compression, max_bytes: usize) -> Result<Vec<u8>> {
        let mut resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| RpcError::runtime_error(format!("external GET failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(RpcError::runtime_error(format!(
                "external GET returned {} for {url}",
                resp.status()
            )));
        }
        let zstd_encoded = resp
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("zstd"))
            .unwrap_or(false);
        let mut out = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = resp
                .read(&mut buf)
                .map_err(|e| RpcError::runtime_error(format!("external GET body: {e}")))?;
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
        if zstd_encoded {
            out = zstd::stream::decode_all(Cursor::new(out))
                .map_err(|e| RpcError::runtime_error(format!("zstd decode external body: {e}")))?;
        }
        Ok(out)
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
    inner: Option<HttpInner>,
    timeout: Option<Duration>,
    retry: RetryConfig,
    compression_level: Option<i32>,
    external_validator: Option<UrlValidator>,
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
    pub fn client(mut self, client: HttpInner) -> Self {
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

    /// Retry policy for connection-level failures on idempotent requests
    /// (unary / init / describe / capabilities / producer continuation).
    /// Exchange is never retried.
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

    /// Enable transparent external-location response resolution, validating
    /// fetched URLs with `validator` (use [`any_url_validator`] for trusted /
    /// test storage, [`safe_https_validator`] for production).
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
            Some(c) => c,
            None => {
                let mut b = HttpInner::builder();
                if let Some(t) = self.timeout {
                    b = b.timeout(t);
                }
                b.build().map_err(|e| {
                    RpcError::new("TransportError", format!("build http client: {e}"))
                })?
            }
        };
        // The fetcher uses its own redirect-free, timed client (SSRF-safer).
        let fetch_client = HttpInner::builder()
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
            inner,
            on_log: self.on_log,
            relax_nullability: self.relax_nullability,
            protocol_version: self.protocol_version,
            retry: self.retry,
            compression_level: self.compression_level,
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
    inner: HttpInner,
    on_log: Option<OnLog>,
    relax_nullability: bool,
    protocol_version: Option<String>,
    retry: RetryConfig,
    compression_level: Option<i32>,
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
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}/{}", self.base_url, self.prefix, path)
    }

    /// Build per-request headers: content type, codec advertisement, and
    /// (when a session is active) sticky session headers.
    fn build_headers(&self, content_encoding: Option<&str>) -> HeaderMap {
        let mut h = self.headers.clone();
        h.insert(CONTENT_TYPE, HeaderValue::from_static(ARROW_CONTENT_TYPE));
        if let Some(enc) = content_encoding {
            if let Ok(v) = HeaderValue::from_str(enc) {
                h.insert(reqwest::header::CONTENT_ENCODING, v);
            }
            // Advertise the codecs we can decode on responses.
            h.insert(
                reqwest::header::ACCEPT_ENCODING,
                HeaderValue::from_static("zstd, identity"),
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
    /// externalization (413), connection retry (idempotent ops only), and
    /// sticky-session header capture. Returns the response body bytes.
    fn post(&mut self, path: &str, body: Vec<u8>, retryable: bool) -> Result<Vec<u8>> {
        // Proactive externalization when caps are known and the body is large.
        let body = self.maybe_externalize_request(body)?;
        let (mut resp_headers, mut bytes, mut status) = self.send(path, &body, retryable)?;

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
    /// returning `(response headers, decoded body, status)`. Decodes a
    /// `Content-Encoding: zstd` response transparently.
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
        let url = self.url(path);

        let attempts = if retryable {
            self.retry.max_attempts
        } else {
            1
        };
        let mut last_err = None;
        for attempt in 0..attempts {
            if attempt > 0 {
                std::thread::sleep(self.retry.delay_before(attempt));
            }
            let res = self
                .inner
                .post(&url)
                .headers(headers.clone())
                .body(payload.clone())
                .send();
            match res {
                Ok(resp) => {
                    let status = resp.status();
                    let resp_headers = resp.headers().clone();
                    let zstd_resp = resp_headers
                        .get(reqwest::header::CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.eq_ignore_ascii_case("zstd"))
                        .unwrap_or(false);
                    let raw = resp.bytes().map_err(|e| {
                        RpcError::new("TransportError", format!("read http body: {e}"))
                    })?;
                    let decoded = if zstd_resp {
                        zstd::stream::decode_all(Cursor::new(raw.as_ref())).map_err(|e| {
                            RpcError::new("TransportError", format!("zstd decode response: {e}"))
                        })?
                    } else {
                        raw.to_vec()
                    };
                    return Ok((resp_headers, decoded, status));
                }
                Err(e) => {
                    last_err = Some(RpcError::new(
                        "TransportError",
                        format!("http post {path}: {e}"),
                    ));
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
            cancelled: false,
        })
    }

    /// Query server capabilities via `OPTIONS {prefix}/health` (cached).
    pub fn capabilities(&self) -> Result<HttpServerCapabilities> {
        if let Some(c) = self.caps.borrow().as_ref() {
            return Ok(c.clone());
        }
        let caps = self.fetch_capabilities()?;
        *self.caps.borrow_mut() = Some(caps.clone());
        Ok(caps)
    }

    fn fetch_capabilities(&self) -> Result<HttpServerCapabilities> {
        let resp = self
            .inner
            .request(Method::OPTIONS, self.url("health"))
            .headers(self.headers.clone())
            .send()
            .map_err(|e| RpcError::new("TransportError", format!("options health: {e}")))?;
        Ok(parse_caps(resp.headers()))
    }

    fn refresh_supported_encodings(&self, headers: &HeaderMap) {
        if let Some(list) = headers
            .get(SUPPORTED_ENCODINGS_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            let encs: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let mut c = self.caps.borrow_mut();
            let caps = c.get_or_insert_with(HttpServerCapabilities::default);
            caps.supported_encodings = encs;
        }
    }

    /// Request `count` pre-signed upload URLs from `__upload_url__/init`.
    pub fn request_upload_urls(&mut self, count: usize) -> Result<Vec<UploadUrl>> {
        use arrow_array::{Int64Array, RecordBatch as RB};
        use arrow_schema::{DataType, Field};
        let schema = Arc::new(Schema::new(vec![Field::new(
            "count",
            DataType::Int64,
            false,
        )]));
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
                    let _ = self
                        .inner
                        .request(Method::DELETE, self.url(SESSION_ENDPOINT))
                        .headers(h)
                        .send();
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
        let put = self
            .inner
            .put(&url.upload_url)
            .header(CONTENT_TYPE, ARROW_CONTENT_TYPE)
            .body(body.to_vec())
            .send()
            .map_err(|e| RpcError::new("ExternalUploadFailed", format!("PUT upload URL: {e}")))?;
        if !put.status().is_success() {
            return Err(RpcError::new(
                "ExternalUploadFailed",
                format!("PUT to upload URL failed: HTTP {}", put.status()),
            ));
        }
        // Build the pointer body: zero-row batch (original schema) + original
        // dispatch metadata + vgi_rpc.location.
        md.insert(LOCATION_KEY.to_string(), url.download_url);
        let pointer = empty_batch(batch.schema().as_ref())?;
        write_one_batch(&pointer, Some(&md))
    }
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
            let body = self.continuation_body(&token, false)?;
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
            let body = self.continuation_body(&token, true)?;
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
    pub fn current_token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    fn continuation_body(&self, token: &str, cancel: bool) -> Result<Vec<u8>> {
        let batch = empty_batch(&Schema::empty())?;
        let mut md = Metadata::new();
        md.insert(STATE_KEY.to_string(), token.to_string());
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
            if let Some(tok) = md.remove(STATE_KEY) {
                out.token = Some(tok);
                if treat_state_frame_as_data {
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
        max_response_bytes: parse_u64(MAX_RESPONSE_BYTES_HEADER),
        max_externalized_response_bytes: parse_u64(MAX_EXTERNALIZED_RESPONSE_BYTES_HEADER),
        externalization_enabled: get(EXTERNALIZATION_ENABLED_HEADER).as_deref() == Some("true"),
        max_upload_bytes: parse_u64(MAX_UPLOAD_BYTES_HEADER),
        supported_encodings: split(SUPPORTED_ENCODINGS_HEADER),
    }
}
