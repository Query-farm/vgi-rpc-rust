//! Blob-vendor client: region-pinned, single-object pre-signed URLs.
//!
//! The *blob vendor* is a small HTTP service that holds the object-storage
//! credentials so workers never do. A worker asks it for a pre-signed URL for
//! one object of a declared size and SHA-256, uploads straight to storage with
//! that URL, and hands a download URL (or an object id) to whoever needs the
//! bytes. The storage enforces the signed `Content-Length` and
//! `x-amz-checksum-sha256`, so whatever sits at the object's key is exactly the
//! declared bytes.
//!
//! Port of vgi-rpc-python's `vgi_rpc.vendor`; the wire format is the same.
//!
//! - [`VendorStorage`] implements both [`ExternalStorage`] (server-side
//!   externalization of large results, purpose `rpc`) and
//!   [`UploadUrlProvider`] (vending upload URLs to clients for large requests).
//! - [`VendorBlobClient`] puts, gets and deletes raw byte blobs (purpose `fs`)
//!   for callers that keep their own references, e.g. a key-value store that
//!   externalizes large values. Reads are verified against the reference's
//!   size and SHA-256.
//! - [`pinned_hosts_validator`] and [`vendor_url_validator`] accept only URLs
//!   on the vendor's storage hosts.
//! - [`external_config_from_env`] / [`client_external_config_from_env`] build
//!   configs from the environment.
//!
//! # Environment
//!
//! | Variable | Meaning |
//! |---|---|
//! | `VGI_BLOB_VENDOR_URL` | Vendor base URL. Unset: the `*_from_env` helpers return `None`. |
//! | `VGI_BLOB_VENDOR_TOKEN` | Bearer token; falls back to `VGI_CF_DO_TOKEN`. |
//! | `VGI_RPC_EXTERNALIZE_THRESHOLD_BYTES` | Result-batch size at which the server externalizes (default 1 MiB). |
//! | `VGI_RPC_EXTERNAL_COMPRESSION` | `none` (default) or `zstd`, optionally `zstd:<level>`. |
//! | `VGI_RPC_MAX_UPLOAD_BYTES` | Size advertised to clients for vendor upload URLs. |
//!
//! # Credentials
//!
//! Every `/v1` request carries `Authorization: Bearer <token>`. Signed-URL
//! requests (the storage PUT and GET) go through a separate bare client and
//! carry exactly the headers the grant requires, never the token. Neither the
//! token nor a signed query string appears in an error, a log line or `Debug`
//! output: URLs are redacted to scheme, host, port and path.

use std::fmt;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use vgi_rpc::external::{
    Compression, ExternalLocationConfig, ExternalStorage, UploadResult, UploadUrl,
    UploadUrlProvider, UrlValidator,
};
use vgi_rpc::{Result, RpcError};

use crate::redact_url;

/// Vendor base URL.
pub const ENV_URL: &str = "VGI_BLOB_VENDOR_URL";
/// Vendor bearer token.
pub const ENV_TOKEN: &str = "VGI_BLOB_VENDOR_TOKEN";
/// Token fallback: the vendor shares the storage service's per-deployment keys.
pub const ENV_TOKEN_FALLBACK: &str = "VGI_CF_DO_TOKEN";
/// Result-batch size at which the server externalizes.
pub const ENV_THRESHOLD: &str = "VGI_RPC_EXTERNALIZE_THRESHOLD_BYTES";
/// Compression of externalized results.
pub const ENV_COMPRESSION: &str = "VGI_RPC_EXTERNAL_COMPRESSION";
/// Size advertised to clients for vendor upload URLs.
pub const ENV_MAX_UPLOAD_BYTES: &str = "VGI_RPC_MAX_UPLOAD_BYTES";

const DEFAULT_THRESHOLD: usize = 1_048_576;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_INFO_TTL: Duration = Duration::from_secs(600);
const MAX_BACKOFF: Duration = Duration::from_secs(5);
/// Default cap on the size of a blob [`VendorBlobClient::get_bytes`] fetches
/// (the vendor's per-object limit).
pub const DEFAULT_MAX_FETCH_BYTES: u64 = 4 * 1024 * 1024 * 1024;

const PUT_PATH: &str = "/v1/blobs/put";
const GET_PATH: &str = "/v1/blobs/get";
const DELETE_PATH: &str = "/v1/blobs/delete";
const DELETE_SCOPE_PATH: &str = "/v1/blobs/delete_scope";
const INFO_PATH: &str = "/v1/info";
/// Most object ids one `/v1/blobs/delete` call takes.
pub const MAX_DELETE_IDS: usize = 1000;

/// What an object is for. `rpc` objects get a download URL at `put` and the
/// short lifecycle; `fs` objects are fetched through `get`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Externalized RPC payloads.
    Rpc,
    /// Function-storage values.
    Fs,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Purpose::Rpc => "rpc",
            Purpose::Fs => "fs",
        }
    }
}

/// A blob-vendor or signed-URL request failed.
///
/// The message never contains the bearer token or a signed query string.
#[derive(Clone, Debug)]
pub struct VendorError {
    /// Diagnostic text (already redacted).
    pub message: String,
    /// HTTP status of the failing response; `None` for a transport failure or
    /// a malformed response.
    pub status: Option<u16>,
    /// The vendor's machine-readable `error` code (`not_found`,
    /// `not_uploaded`, `quota_exceeded`, `idempotency_conflict`, ...), the
    /// storage's XML error code (`NoSuchKey`, `BadDigest`, ...), or, for the
    /// checks [`VendorBlobClient::get_bytes`] makes itself, `size_mismatch` /
    /// `sha256_mismatch`.
    pub code: Option<String>,
}

impl VendorError {
    fn new(message: impl Into<String>) -> Self {
        VendorError {
            message: message.into(),
            status: None,
            code: None,
        }
    }

    fn with(message: impl Into<String>, status: Option<u16>, code: Option<String>) -> Self {
        VendorError {
            message: message.into(),
            status,
            code,
        }
    }

    /// Whether the object is gone: a 404, or a `not_found` / `not_uploaded` /
    /// `NoSuchKey` code.
    pub fn is_missing(&self) -> bool {
        self.status == Some(404)
            || matches!(
                self.code.as_deref(),
                Some("not_found" | "not_uploaded" | "NoSuchKey")
            )
    }
}

impl fmt::Display for VendorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VendorError {}

impl From<VendorError> for RpcError {
    fn from(e: VendorError) -> Self {
        RpcError::runtime_error(e.message)
    }
}

type VResult<T> = std::result::Result<T, VendorError>;

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// The execution a blob belongs to, for scoped clean-up.
///
/// The vendor accepts 1-128 characters of `[A-Za-z0-9._:-]` for each field,
/// so encode binary ids as hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobScope {
    /// The storage shard key.
    pub shard: String,
    /// The execution identifier.
    pub execution_id: String,
}

/// A reference to one vendored blob, small enough to store inline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRef {
    /// The vendor's object id.
    pub object_id: String,
    /// Exact byte length of the blob.
    pub size: u64,
    /// Lowercase hex SHA-256 of the blob bytes.
    pub sha256: String,
}

/// The vendor's answer to `put`: where and how to upload one object.
#[derive(Clone)]
pub struct PutGrant {
    /// The server-chosen object id.
    pub object_id: String,
    /// Pre-signed PUT URL.
    pub upload_url: String,
    /// Headers the PUT must carry exactly as given.
    pub required_headers: Vec<(String, String)>,
    /// Pre-signed GET URL (only for `rpc` objects).
    pub download_url: Option<String>,
    /// When `upload_url` stops working, as Unix microseconds.
    pub expires_at_micros: i64,
    /// When `download_url` stops working, as Unix microseconds, if given.
    pub download_expires_at_micros: Option<i64>,
    /// The region the object lives in.
    pub region: Option<String>,
}

impl fmt::Debug for PutGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PutGrant")
            .field("object_id", &self.object_id)
            .field("upload_url", &redact_url(&self.upload_url))
            .field(
                "download_url",
                &self.download_url.as_deref().map(redact_url),
            )
            .field("expires_at_micros", &self.expires_at_micros)
            .finish()
    }
}

/// The vendor's answer to `get`: where one object can be downloaded.
#[derive(Clone)]
pub struct BlobLocation {
    /// Pre-signed GET URL.
    pub download_url: String,
    /// Declared byte length.
    pub size: u64,
    /// Declared SHA-256, standard base64.
    pub sha256_b64: String,
    /// `Content-Encoding` stored with the object.
    pub content_encoding: Option<String>,
    /// When `download_url` stops working, as Unix microseconds.
    pub expires_at_micros: i64,
}

impl fmt::Debug for BlobLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobLocation")
            .field("download_url", &redact_url(&self.download_url))
            .field("size", &self.size)
            .finish()
    }
}

/// The vendor's `/v1/info`: storage hosts for this tenant's region.
#[derive(Clone, Debug, Default)]
pub struct VendorInfo {
    /// The tenant's region name.
    pub region: String,
    /// Hosts upload URLs may point at.
    pub upload_hosts: Vec<String>,
    /// Hosts download URLs may point at.
    pub download_hosts: Vec<String>,
    /// The tenant the token resolves to.
    pub tenant: String,
    /// The storage jurisdiction (`eu`, `us`), if any.
    pub jurisdiction: Option<String>,
    /// URL prefixes this tenant's objects live under.
    pub url_prefixes: Vec<String>,
    /// Numeric limits (`max_object_bytes`, `quota_bytes`, ...).
    pub limits: Vec<(String, i64)>,
    /// URL lifetimes (`put`, `rpc_download`, `get`).
    pub ttl_seconds: Vec<(String, i64)>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse `expires_at` as ISO-8601 text or epoch seconds/milliseconds.
fn parse_expires(value: &Value) -> VResult<i64> {
    let bad = || VendorError::new("Blob vendor returned a malformed expires_at");
    match value {
        Value::Number(n) => {
            let v = n.as_f64().ok_or_else(bad)?;
            let seconds = if v > 1e11 { v / 1000.0 } else { v };
            Ok((seconds * 1_000_000.0) as i64)
        }
        Value::String(s) => {
            let normalized = s.replace('Z', "+00:00");
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&normalized) {
                return Ok(t.timestamp_micros());
            }
            // An offset-less timestamp is UTC.
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|t| t.and_utc().timestamp_micros())
                .map_err(|_| bad())
        }
        _ => Err(bad()),
    }
}

fn field<'a>(obj: &'a Map<String, Value>, key: &str, op: &str) -> VResult<&'a Value> {
    obj.get(key)
        .ok_or_else(|| VendorError::new(format!("Blob vendor {op} response is missing '{key}'")))
}

fn str_field(obj: &Map<String, Value>, key: &str, op: &str) -> VResult<String> {
    match field(obj, key, op)? {
        Value::String(s) if !s.is_empty() => Ok(s.clone()),
        _ => Err(VendorError::new(format!(
            "Blob vendor {op} response has a malformed '{key}'"
        ))),
    }
}

fn opt_str_field(obj: &Map<String, Value>, key: &str, op: &str) -> VResult<Option<String>> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(VendorError::new(format!(
            "Blob vendor {op} response has a malformed '{key}'"
        ))),
    }
}

fn u64_field(obj: &Map<String, Value>, key: &str, op: &str) -> VResult<u64> {
    field(obj, key, op)?.as_u64().ok_or_else(|| {
        VendorError::new(format!("Blob vendor {op} response has a malformed '{key}'"))
    })
}

fn int_map(obj: &Map<String, Value>, key: &str) -> Vec<(String, i64)> {
    match obj.get(key) {
        Some(Value::Object(m)) => m
            .iter()
            .filter_map(|(k, v)| v.as_i64().map(|n| (k.clone(), n)))
            .collect(),
        _ => Vec::new(),
    }
}

fn hosts_field(obj: &Map<String, Value>, key: &str) -> VResult<Vec<String>> {
    match obj.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|h| match h {
                Value::String(s) if !s.is_empty() => Ok(s.clone()),
                _ => Err(VendorError::new(format!(
                    "Blob vendor info response has a malformed '{key}'"
                ))),
            })
            .collect(),
        Some(_) => Err(VendorError::new(format!(
            "Blob vendor info response has a malformed '{key}'"
        ))),
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

/// Pull `(code, ": code: message")` out of a vendor `{error, message}` body.
fn error_detail(body: &[u8]) -> (Option<String>, String) {
    let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(body) else {
        return (None, String::new());
    };
    let code = obj
        .get("error")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(64).collect::<String>());
    let message = obj
        .get("message")
        .and_then(Value::as_str)
        .map(|s| s.chars().take(200).collect::<String>());
    let parts: Vec<String> = code.iter().cloned().chain(message).collect();
    let detail = if parts.is_empty() {
        String::new()
    } else {
        format!(": {}", parts.join(": "))
    };
    (code, detail)
}

/// The `<Code>` of an S3/R2 XML error body, if any.
fn s3_error_code(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find("<Code>")? + 6;
    let end = start + text[start..].find("</Code>")?;
    let code = &text[start..end];
    (code.len() <= 64 && !code.is_empty() && code.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| code.to_string())
}

// ---------------------------------------------------------------------------
// URL pinning
// ---------------------------------------------------------------------------

/// Split a pinned-host entry into `(host, port)`: `host`, `host:port` or
/// `[v6]:port`.
fn parse_host_entry(entry: &str) -> Option<(String, Option<u16>)> {
    let entry = entry.trim();
    if entry.is_empty() || entry.contains(['/', '?', '#', '@']) {
        return None;
    }
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?.parse().ok()?),
        };
        return (!host.is_empty()).then(|| (host.to_ascii_lowercase(), port));
    }
    match entry.split_once(':') {
        None => Some((entry.to_ascii_lowercase(), None)),
        Some((host, port)) if !host.is_empty() && !port.contains(':') => {
            Some((host.to_ascii_lowercase(), Some(port.parse().ok()?)))
        }
        _ => None,
    }
}

/// Build a [`UrlValidator`] that accepts only URLs on `hosts`.
///
/// A URL passes when its scheme is `https` (or `http` with `allow_http`), it
/// carries no userinfo, and its host and port are exactly one of `hosts`. An
/// entry is `host` or `host:port` (`[v6]:port` for IPv6); an entry without a
/// port matches the scheme's default port only. Subdomains do not match. With
/// `prefixes`, the URL (without its query) must also start with one of them.
///
/// `allow_http` is only for loopback test vendors; never enable it for a real
/// deployment.
///
/// # Errors
///
/// If `hosts` is empty or an entry will not parse.
pub fn pinned_hosts_validator(
    hosts: &[String],
    allow_http: bool,
    prefixes: &[String],
) -> Result<UrlValidator> {
    let schemes: &'static [&'static str] = if allow_http {
        &["https", "http"]
    } else {
        &["https"]
    };
    let mut allowed: Vec<(String, u16)> = Vec::new();
    for entry in hosts {
        let (host, port) = parse_host_entry(entry).ok_or_else(|| {
            RpcError::value_error(format!("Invalid pinned host entry: {entry:?}"))
        })?;
        match port {
            Some(p) => allowed.push((host, p)),
            None => {
                for scheme in schemes {
                    allowed.push((host.clone(), default_port(scheme)));
                }
            }
        }
    }
    if allowed.is_empty() {
        return Err(RpcError::value_error(
            "pinned_hosts_validator needs at least one host",
        ));
    }
    let prefixes: Vec<String> = prefixes.iter().filter(|p| !p.is_empty()).cloned().collect();
    Ok(Arc::new(move |raw: &str| {
        let url = url::Url::parse(raw).map_err(|_| RpcError::value_error("URL is malformed"))?;
        let scheme = url.scheme();
        if !schemes.contains(&scheme) {
            return Err(RpcError::value_error(format!(
                "URL scheme '{scheme}' not allowed (only {})",
                schemes.join(" or ")
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(RpcError::value_error("URL userinfo is not allowed"));
        }
        let host = url
            .host_str()
            .map(|h| {
                h.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let port = url.port().unwrap_or_else(|| default_port(scheme));
        if host.is_empty() || !allowed.iter().any(|(h, p)| *h == host && *p == port) {
            return Err(RpcError::value_error(format!(
                "URL host is not a pinned storage host: {}",
                redact_url(raw)
            )));
        }
        if !prefixes.is_empty() {
            let authority = match url.port() {
                Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
                None => url.host_str().unwrap_or_default().to_string(),
            };
            let bare = format!("{scheme}://{authority}{}", url.path());
            let raw_path_has_dots = raw
                .split(['?', '#'])
                .next()
                .unwrap_or_default()
                .split('/')
                .any(|seg| seg == ".." || seg.eq_ignore_ascii_case("%2e%2e"));
            if raw_path_has_dots || !prefixes.iter().any(|p| bare.starts_with(p.as_str())) {
                return Err(RpcError::value_error(format!(
                    "URL is outside the pinned storage prefixes: {}",
                    redact_url(raw)
                )));
            }
        }
        Ok(())
    }))
}

/// [`UrlValidator`] backed by the vendor's `/v1/info`, cached.
struct HostsValidator {
    api: Arc<VendorApi>,
    ttl: Duration,
    cache: Mutex<Option<(UrlValidator, Instant)>>,
}

impl HostsValidator {
    fn current(&self) -> Result<UrlValidator> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((validator, at)) = cache.as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(validator.clone());
            }
        }
        let fresh = self.api.info().map_err(RpcError::from).and_then(|info| {
            let hosts: Vec<String> = info
                .upload_hosts
                .iter()
                .chain(info.download_hosts.iter())
                .cloned()
                .collect();
            pinned_hosts_validator(&hosts, self.api.loopback_http, &info.url_prefixes)
        });
        match fresh {
            Ok(validator) => {
                *cache = Some((validator.clone(), Instant::now()));
                Ok(validator)
            }
            Err(err) => match cache.as_mut() {
                // Keep the last known-good pin through a vendor blip.
                Some((validator, at)) => {
                    tracing::warn!(
                        "Blob vendor info refresh failed; keeping cached hosts: {}",
                        err.message
                    );
                    *at = Instant::now();
                    Ok(validator.clone())
                }
                None => Err(RpcError::value_error(format!(
                    "Cannot pin storage hosts: {}",
                    err.message
                ))),
            },
        }
    }

    fn validator(self: &Arc<Self>) -> UrlValidator {
        let me = self.clone();
        Arc::new(move |url: &str| (me.current()?)(url))
    }

    fn check(&self, url: &str) -> VResult<()> {
        self.current().and_then(|v| v(url)).map_err(|e| {
            VendorError::new(format!(
                "Blob vendor returned a URL off its pinned hosts: {}",
                e.message
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// HTTP + wire mapping (the one place that knows the vendor's JSON shapes)
// ---------------------------------------------------------------------------

/// A finished HTTP exchange.
struct Reply {
    status: u16,
    body: Vec<u8>,
}

/// HTTP transport, retries, and the vendor's request/response shapes.
struct VendorApi {
    base_url: String,
    token: String,
    loopback_http: bool,
    max_attempts: u32,
    backoff: Duration,
    /// Vendor API requests.
    client: reqwest::blocking::Client,
    /// Storage-host (signed URL) requests: a separate bare client, so nothing
    /// configured for the vendor ever reaches a storage host.
    storage: reqwest::blocking::Client,
}

impl fmt::Debug for VendorApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VendorApi")
            .field("base_url", &redact_url(&self.base_url))
            .field("token", &"<redacted>")
            .finish()
    }
}

fn bare_client(timeout: Duration) -> reqwest::blocking::Client {
    // No redirects: a redirect could carry the bearer token or a signed URL to
    // a host nobody vetted.
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

impl VendorApi {
    fn new(url: &str, token: &str, timeout: Duration) -> Result<Self> {
        let parsed = url::Url::parse(url).map_err(|_| {
            RpcError::value_error(format!(
                "Blob vendor URL must be an absolute https URL: {}",
                redact_url(url)
            ))
        })?;
        let scheme = parsed.scheme();
        if !matches!(scheme, "https" | "http") || parsed.host_str().is_none() {
            return Err(RpcError::value_error(format!(
                "Blob vendor URL must be an absolute https URL: {}",
                redact_url(url)
            )));
        }
        let loopback_http = scheme == "http";
        if loopback_http && !is_loopback_host(parsed.host_str().unwrap_or_default()) {
            // The bearer token would cross the network in plain text.
            return Err(RpcError::value_error(format!(
                "Blob vendor URL must use https (http is allowed only for loopback): {}",
                redact_url(url)
            )));
        }
        if token.is_empty() {
            return Err(RpcError::value_error("Blob vendor token is empty"));
        }
        Ok(VendorApi {
            base_url: url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            loopback_http,
            max_attempts: 3,
            backoff: Duration::from_millis(250),
            client: bare_client(timeout),
            storage: bare_client(timeout),
        })
    }

    /// Send one request, retrying transport errors, 429 and 5xx with backoff.
    /// The request carries exactly `headers` (plus the transport's own
    /// framing headers).
    fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        op: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        storage: bool,
    ) -> VResult<Reply> {
        let client = if storage { &self.storage } else { &self.client };
        let mut last_error = String::new();
        let mut status = None;
        for attempt in 0..self.max_attempts {
            if attempt > 0 {
                let base = self
                    .backoff
                    .saturating_mul(1 << (attempt - 1))
                    .min(MAX_BACKOFF);
                let jitter = 0.5 + rand_unit() / 2.0;
                std::thread::sleep(base.mul_f64(jitter));
            }
            let mut req = client.request(method.clone(), url);
            for (k, v) in headers {
                req = req.header(k.as_str(), v.as_str());
            }
            if let Some(b) = body {
                req = req.body(b.to_vec());
            }
            let resp = match req.send() {
                Ok(r) => r,
                Err(e) => {
                    // Never the error's Display: it can embed the full URL.
                    status = None;
                    last_error = if e.is_timeout() {
                        "timeout".to_string()
                    } else if e.is_connect() {
                        "connect error".to_string()
                    } else {
                        "transport error".to_string()
                    };
                    tracing::debug!(
                        "Blob vendor {op} {last_error} (attempt {}/{}): {}",
                        attempt + 1,
                        self.max_attempts,
                        redact_url(url)
                    );
                    continue;
                }
            };
            let code = resp.status().as_u16();
            if code == 429 || code >= 500 {
                status = Some(code);
                last_error = format!("HTTP {code}");
                tracing::debug!(
                    "Blob vendor {op} got HTTP {code} (attempt {}/{}): {}",
                    attempt + 1,
                    self.max_attempts,
                    redact_url(url)
                );
                continue;
            }
            let body = read_capped(resp, u64::MAX).map_err(|_| {
                VendorError::with(
                    format!("Blob vendor {op} body read failed: {}", redact_url(url)),
                    Some(code),
                    None,
                )
            })?;
            return Ok(Reply { status: code, body });
        }
        Err(VendorError::with(
            format!(
                "Blob vendor {op} failed after {} attempts ({last_error}): {}",
                self.max_attempts,
                redact_url(url)
            ),
            status,
            None,
        ))
    }

    fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        op: &str,
        body: Option<Value>,
    ) -> VResult<Map<String, Value>> {
        let url = format!("{}{path}", self.base_url);
        let mut headers = vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", self.token),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let content = body.map(|b| serde_json::to_vec(&b).expect("serialize vendor request"));
        if content.is_some() {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }
        let reply = self.send(method, &url, op, &headers, content.as_deref(), false)?;
        if !(200..300).contains(&reply.status) {
            let (code, detail) = error_detail(&reply.body);
            return Err(VendorError::with(
                format!("Blob vendor {op} failed: HTTP {}{detail}", reply.status),
                Some(reply.status),
                code,
            ));
        }
        if reply.body.is_empty() {
            return Ok(Map::new());
        }
        match serde_json::from_slice::<Value>(&reply.body) {
            Ok(Value::Object(m)) => Ok(m),
            Ok(_) => Err(VendorError::with(
                format!("Blob vendor {op} returned a non-object JSON body"),
                Some(reply.status),
                None,
            )),
            Err(_) => Err(VendorError::with(
                format!("Blob vendor {op} returned non-JSON"),
                Some(reply.status),
                None,
            )),
        }
    }

    fn post(&self, path: &str, op: &str, body: Value) -> VResult<Map<String, Value>> {
        self.call(reqwest::Method::POST, path, op, Some(body))
    }

    fn put(
        &self,
        size: u64,
        sha256_b64: &str,
        purpose: Purpose,
        scope: Option<&BlobScope>,
        content_encoding: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> VResult<PutGrant> {
        let mut body = json!({"size": size, "sha256_b64": sha256_b64, "purpose": purpose.as_str()});
        if let Some(s) = scope {
            body["scope"] = json!({"shard": s.shard, "execution_id": s.execution_id});
        }
        if let Some(e) = content_encoding {
            body["content_encoding"] = json!(e);
        }
        if let Some(k) = idempotency_key {
            body["idempotency_key"] = json!(k);
        }
        let resp = self.post(PUT_PATH, "put", body)?;
        let method = resp
            .get("upload_method")
            .and_then(Value::as_str)
            .unwrap_or("PUT");
        if method != "PUT" {
            return Err(VendorError::new(format!(
                "Blob vendor put asked for unsupported upload_method {method:?}"
            )));
        }
        let required_headers = match field(&resp, "required_headers", "put")? {
            Value::Object(m) => m
                .iter()
                .map(|(k, v)| {
                    v.as_str()
                        .map(|s| (k.clone(), s.to_string()))
                        .ok_or_else(|| {
                            VendorError::new(
                                "Blob vendor put response has malformed 'required_headers'",
                            )
                        })
                })
                .collect::<VResult<Vec<_>>>()?,
            _ => {
                return Err(VendorError::new(
                    "Blob vendor put response has malformed 'required_headers'",
                ))
            }
        };
        Ok(PutGrant {
            object_id: str_field(&resp, "object_id", "put")?,
            upload_url: str_field(&resp, "upload_url", "put")?,
            required_headers,
            download_url: opt_str_field(&resp, "download_url", "put")?,
            expires_at_micros: parse_expires(field(&resp, "expires_at", "put")?)?,
            download_expires_at_micros: match resp.get("download_expires_at") {
                None | Some(Value::Null) => None,
                Some(v) => Some(parse_expires(v)?),
            },
            region: opt_str_field(&resp, "region", "put")?,
        })
    }

    fn get(&self, object_id: &str) -> VResult<BlobLocation> {
        let resp = self.post(GET_PATH, "get", json!({"object_id": object_id}))?;
        Ok(BlobLocation {
            download_url: str_field(&resp, "download_url", "get")?,
            size: u64_field(&resp, "size", "get")?,
            sha256_b64: str_field(&resp, "sha256_b64", "get")?,
            content_encoding: opt_str_field(&resp, "content_encoding", "get")?,
            expires_at_micros: parse_expires(field(&resp, "expires_at", "get")?)?,
        })
    }

    fn delete(&self, object_ids: &[String]) -> VResult<u64> {
        let resp = self.post(DELETE_PATH, "delete", json!({"object_ids": object_ids}))?;
        Ok(resp.get("deleted").and_then(Value::as_u64).unwrap_or(0))
    }

    fn delete_scope(&self, scope: &BlobScope) -> VResult<u64> {
        let resp = self.post(
            DELETE_SCOPE_PATH,
            "delete_scope",
            json!({"shard": scope.shard, "execution_id": scope.execution_id}),
        )?;
        Ok(resp.get("deleted").and_then(Value::as_u64).unwrap_or(0))
    }

    fn info(&self) -> VResult<VendorInfo> {
        let resp = self.call(reqwest::Method::GET, INFO_PATH, "info", None)?;
        Ok(VendorInfo {
            region: resp
                .get("region")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            upload_hosts: hosts_field(&resp, "upload_hosts")?,
            download_hosts: hosts_field(&resp, "download_hosts")?,
            tenant: resp
                .get("tenant")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            jurisdiction: opt_str_field(&resp, "jurisdiction", "info")?,
            url_prefixes: hosts_field(&resp, "url_prefixes")?,
            limits: int_map(&resp, "limits"),
            ttl_seconds: int_map(&resp, "ttl_seconds"),
        })
    }

    /// PUT `data` to a granted URL with exactly its required headers.
    fn put_object(
        &self,
        grant: &PutGrant,
        data: &[u8],
        content_encoding: Option<&str>,
    ) -> VResult<()> {
        let mut headers = Vec::new();
        let mut has_encoding = false;
        for (k, v) in &grant.required_headers {
            if k.eq_ignore_ascii_case("content-length") {
                // The transport frames the body itself; a declared length that
                // disagrees with the bytes is refused before anything is sent.
                if v.trim() != data.len().to_string() {
                    return Err(VendorError::new(format!(
                        "Blob vendor granted Content-Length {v} for a {}-byte object",
                        data.len()
                    )));
                }
                continue;
            }
            has_encoding |= k.eq_ignore_ascii_case("content-encoding");
            headers.push((k.clone(), v.clone()));
        }
        if let (Some(enc), false) = (content_encoding, has_encoding) {
            headers.push(("Content-Encoding".to_string(), enc.to_string()));
        }
        let reply = self.send(
            reqwest::Method::PUT,
            &grant.upload_url,
            "upload",
            &headers,
            Some(data),
            true,
        )?;
        if !(200..300).contains(&reply.status) {
            let code = s3_error_code(&reply.body);
            return Err(VendorError::with(
                format!(
                    "Signed upload failed: HTTP {}{}: {}",
                    reply.status,
                    code.as_deref().map(|c| format!(" {c}")).unwrap_or_default(),
                    redact_url(&grant.upload_url)
                ),
                Some(reply.status),
                code,
            ));
        }
        Ok(())
    }

    /// GET a signed download URL, capped at `max_bytes`.
    fn download(&self, url: &str, max_bytes: u64) -> VResult<Vec<u8>> {
        let mut last = None;
        for attempt in 0..self.max_attempts {
            if attempt > 0 {
                std::thread::sleep(
                    self.backoff
                        .saturating_mul(1 << (attempt - 1))
                        .min(MAX_BACKOFF),
                );
            }
            let resp = match self.storage.get(url).send() {
                Ok(r) => r,
                Err(_) => {
                    last = Some(VendorError::new(format!(
                        "Signed download failed (transport error): {}",
                        redact_url(url)
                    )));
                    continue;
                }
            };
            let status = resp.status().as_u16();
            if status == 429 || status >= 500 {
                last = Some(VendorError::with(
                    format!("Signed download failed: HTTP {status}: {}", redact_url(url)),
                    Some(status),
                    None,
                ));
                continue;
            }
            if !(200..300).contains(&status) {
                let body = read_capped(resp, 64 * 1024).unwrap_or_default();
                let code = s3_error_code(&body);
                return Err(VendorError::with(
                    format!(
                        "Signed download failed: HTTP {status}{}: {}",
                        code.as_deref().map(|c| format!(" {c}")).unwrap_or_default(),
                        redact_url(url)
                    ),
                    Some(status),
                    code,
                ));
            }
            if let Some(enc) = resp
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
            {
                if !enc.eq_ignore_ascii_case("identity") {
                    return Err(VendorError::new(format!(
                        "Signed download has unsupported Content-Encoding {enc:?}"
                    )));
                }
            }
            if resp.content_length().is_some_and(|n| n > max_bytes) {
                return Err(VendorError::new(format!(
                    "Signed download is larger than max_fetch_bytes ({max_bytes})"
                )));
            }
            return read_capped(resp, max_bytes).map_err(|e| match e {
                ReadError::TooLarge => VendorError::new(format!(
                    "Signed download is larger than max_fetch_bytes ({max_bytes})"
                )),
                ReadError::Io => VendorError::new(format!(
                    "Signed download body read failed: {}",
                    redact_url(url)
                )),
            });
        }
        Err(last.unwrap_or_else(|| VendorError::new("Signed download failed")))
    }
}

enum ReadError {
    TooLarge,
    Io,
}

fn read_capped(
    mut resp: reqwest::blocking::Response,
    max: u64,
) -> std::result::Result<Vec<u8>, ReadError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = resp.read(&mut buf).map_err(|_| ReadError::Io)?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() as u64 + n as u64 > max {
            return Err(ReadError::TooLarge);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// A uniform `[0, 1)` value for retry jitter (no RNG dependency needed).
fn rand_unit() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    (h.finish() >> 11) as f64 / (1u64 << 53) as f64
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn trimmed(lookup: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    lookup(name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn url_and_token(lookup: &dyn Fn(&str) -> Option<String>) -> Result<(String, String)> {
    let url = trimmed(lookup, ENV_URL)
        .ok_or_else(|| RpcError::value_error(format!("{ENV_URL} is not set")))?;
    let token = trimmed(lookup, ENV_TOKEN)
        .or_else(|| trimmed(lookup, ENV_TOKEN_FALLBACK))
        .ok_or_else(|| {
            RpcError::value_error(format!(
                "{ENV_URL} is set but neither {ENV_TOKEN} nor {ENV_TOKEN_FALLBACK} is"
            ))
        })?;
    Ok((url, token))
}

fn parse_positive(lookup: &dyn Fn(&str) -> Option<String>, name: &str) -> Result<Option<u64>> {
    let Some(raw) = trimmed(lookup, name) else {
        return Ok(None);
    };
    let value: i128 = raw
        .parse()
        .map_err(|_| RpcError::value_error(format!("{name} must be an integer, got {raw:?}")))?;
    if value <= 0 || value > u64::MAX as i128 {
        return Err(RpcError::value_error(format!(
            "{name} must be positive, got {value}"
        )));
    }
    Ok(Some(value as u64))
}

/// Parse a `VGI_RPC_EXTERNAL_COMPRESSION` value: `none` (also `off`,
/// `identity`, empty) or `zstd` / `zstd:<level>` (default level 3). `gzip` is
/// refused: this port's external payloads are zstd or plain.
///
/// # Errors
///
/// For any other value.
pub fn parse_compression(raw: &str) -> Result<Compression> {
    let text = raw.trim().to_ascii_lowercase();
    if matches!(text.as_str(), "" | "none" | "off" | "identity") {
        return Ok(Compression::None);
    }
    let (name, level) = match text.split_once(':') {
        Some((n, l)) => (n, Some(l)),
        None => (text.as_str(), None),
    };
    if name != "zstd" {
        return Err(RpcError::value_error(format!(
            "{ENV_COMPRESSION} must be none or zstd (optionally ':<level>'), got {raw:?}"
        )));
    }
    let level = match level {
        None | Some("") => 3,
        Some(l) => l.parse::<i32>().map_err(|_| {
            RpcError::value_error(format!(
                "{ENV_COMPRESSION} level must be an integer, got {raw:?}"
            ))
        })?,
    };
    Ok(Compression::Zstd(level))
}

// ---------------------------------------------------------------------------
// VendorStorage
// ---------------------------------------------------------------------------

/// [`ExternalStorage`] and [`UploadUrlProvider`] backed by the blob vendor.
///
/// `upload` asks the vendor for a sized, checksummed grant, PUTs the bytes
/// with exactly the grant's required headers, and returns the grant's download
/// URL. `generate_upload_url` asks for the same sized grant (purpose `rpc`)
/// for the client's declared size and SHA-256, so the storage itself refuses a
/// client body that does not match. Objects are cleaned up by the vendor; vgi-rpc never deletes them.
/// Thread-safe.
pub struct VendorStorage {
    api: Arc<VendorApi>,
    hosts: Arc<HostsValidator>,
    purpose: Purpose,
    pin: bool,
}

impl fmt::Debug for VendorStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VendorStorage")
            .field("api", &self.api)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl VendorStorage {
    /// A vendor-backed storage for `url` (`https`; `http` only for loopback)
    /// authenticating with `token`, purpose `rpc`, pinning every vended URL to
    /// the vendor's hosts.
    ///
    /// # Errors
    ///
    /// For a malformed or non-loopback `http` URL, or an empty token.
    pub fn new(url: &str, token: &str) -> Result<Self> {
        Self::with_options(
            url,
            token,
            Purpose::Rpc,
            true,
            DEFAULT_TIMEOUT,
            DEFAULT_INFO_TTL,
        )
    }

    /// [`new`](Self::new) with every knob.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn with_options(
        url: &str,
        token: &str,
        purpose: Purpose,
        pin_hosts: bool,
        timeout: Duration,
        info_ttl: Duration,
    ) -> Result<Self> {
        let api = Arc::new(VendorApi::new(url, token, timeout)?);
        let hosts = Arc::new(HostsValidator {
            api: api.clone(),
            ttl: info_ttl,
            cache: Mutex::new(None),
        });
        Ok(VendorStorage {
            api,
            hosts,
            purpose,
            pin: pin_hosts,
        })
    }

    /// Build from `VGI_BLOB_VENDOR_URL` and the vendor token variables.
    ///
    /// # Errors
    ///
    /// If the URL or token is missing or invalid.
    pub fn from_env() -> Result<Self> {
        let (url, token) = url_and_token(&env_lookup)?;
        Self::new(&url, &token)
    }

    /// A [`UrlValidator`] pinned to the vendor's storage hosts (`/v1/info`,
    /// cached).
    pub fn url_validator(&self) -> UrlValidator {
        self.hosts.validator()
    }

    /// Fetch the vendor's region and storage hosts (uncached).
    ///
    /// # Errors
    ///
    /// If the vendor call fails.
    pub fn info(&self) -> std::result::Result<VendorInfo, VendorError> {
        self.api.info()
    }
}

impl ExternalStorage for VendorStorage {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult> {
        let digest = Sha256::digest(ipc_bytes);
        let encoding = match compression {
            Compression::None => None,
            Compression::Zstd(_) => Some("zstd"),
        };
        let grant = self.api.put(
            ipc_bytes.len() as u64,
            &B64.encode(digest),
            self.purpose,
            None,
            encoding,
            None,
        )?;
        if self.pin {
            self.hosts.check(&grant.upload_url)?;
        }
        self.api.put_object(&grant, ipc_bytes, encoding)?;
        let download_url = match grant.download_url {
            Some(u) => u,
            None => self.api.get(&grant.object_id)?.download_url,
        };
        if self.pin {
            self.hosts.check(&download_url)?;
        }
        tracing::debug!(
            "Vendored {} bytes as {}",
            ipc_bytes.len(),
            redact_url(&download_url)
        );
        Ok(UploadResult {
            url: download_url,
            sha256: hex(&digest),
        })
    }
}

impl UploadUrlProvider for VendorStorage {
    fn generate_upload_url(&self, size: u64, sha256_hex: &str) -> Result<UploadUrl> {
        let sha256_b64 = vgi_rpc::external::sha256_hex_to_b64(sha256_hex)?;
        // Client uploads are request pointers the server fetches back, so
        // they are always `rpc` objects (a GET URL at `put`), whatever purpose
        // this storage writes its own results under.
        let grant = self
            .api
            .put(size, &sha256_b64, Purpose::Rpc, None, None, None)?;
        if self.pin {
            self.hosts.check(&grant.upload_url)?;
        }
        let Some(download_url) = grant.download_url else {
            return Err(RpcError::runtime_error(
                "Blob vendor put for purpose 'rpc' returned no download_url",
            ));
        };
        if self.pin {
            self.hosts.check(&download_url)?;
        }
        // Both URLs must still work: report the earlier expiry.
        let expires_at_micros = grant
            .download_expires_at_micros
            .map_or(grant.expires_at_micros, |d| d.min(grant.expires_at_micros));
        // The client frames the body itself with a plain Content-Length, which
        // the signature covers; `upload_headers` never carries it.
        let headers = grant
            .required_headers
            .into_iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("content-length"))
            .collect();
        Ok(UploadUrl {
            upload_url: grant.upload_url,
            download_url,
            expires_at_micros,
            headers,
        })
    }
}

// ---------------------------------------------------------------------------
// VendorBlobClient
// ---------------------------------------------------------------------------

/// Raw byte blobs through the vendor, referenced by [`BlobRef`].
///
/// For callers that store references themselves (e.g. a key-value store that
/// externalizes large values). Objects use purpose `fs` by default: no
/// download URL at `put`; [`get_bytes`](Self::get_bytes) asks the vendor for
/// a fresh one. Thread-safe.
pub struct VendorBlobClient {
    api: Arc<VendorApi>,
    hosts: Arc<HostsValidator>,
    purpose: Purpose,
    max_fetch_bytes: u64,
}

impl fmt::Debug for VendorBlobClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VendorBlobClient")
            .field("api", &self.api)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl VendorBlobClient {
    /// A blob client for `url` (`https`; `http` only for loopback),
    /// authenticating with `token`, purpose `fs`.
    ///
    /// # Errors
    ///
    /// For a malformed or non-loopback `http` URL, or an empty token.
    pub fn new(url: &str, token: &str) -> Result<Self> {
        Self::with_options(
            url,
            token,
            Purpose::Fs,
            DEFAULT_TIMEOUT,
            DEFAULT_INFO_TTL,
            DEFAULT_MAX_FETCH_BYTES,
        )
    }

    /// [`new`](Self::new) with every knob. `max_fetch_bytes` caps the size of
    /// a blob [`get_bytes`](Self::get_bytes) will fetch.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn with_options(
        url: &str,
        token: &str,
        purpose: Purpose,
        timeout: Duration,
        info_ttl: Duration,
        max_fetch_bytes: u64,
    ) -> Result<Self> {
        let api = Arc::new(VendorApi::new(url, token, timeout)?);
        let hosts = Arc::new(HostsValidator {
            api: api.clone(),
            ttl: info_ttl,
            cache: Mutex::new(None),
        });
        Ok(VendorBlobClient {
            api,
            hosts,
            purpose,
            max_fetch_bytes,
        })
    }

    /// Build from `VGI_BLOB_VENDOR_URL` and the vendor token variables, or
    /// `None` when `VGI_BLOB_VENDOR_URL` is unset.
    ///
    /// # Errors
    ///
    /// If the URL is set but the token is missing, or either is invalid.
    pub fn from_env() -> Result<Option<Self>> {
        if trimmed(&env_lookup, ENV_URL).is_none() {
            return Ok(None);
        }
        let (url, token) = url_and_token(&env_lookup)?;
        Self::new(&url, &token).map(Some)
    }

    /// A [`UrlValidator`] pinned to the vendor's storage hosts.
    pub fn url_validator(&self) -> UrlValidator {
        self.hosts.validator()
    }

    /// Store `data` and return its reference.
    ///
    /// `scope` lets [`delete_scope`](Self::delete_scope) remove it later.
    /// `idempotency_key` makes a retried logical write reuse the same object:
    /// the same key with the same bytes returns the same `object_id`; with
    /// other bytes the vendor refuses (`code == "idempotency_conflict"`).
    ///
    /// # Errors
    ///
    /// If the vendor or the signed upload fails.
    pub fn put_bytes(
        &self,
        data: &[u8],
        scope: Option<&BlobScope>,
        idempotency_key: Option<&str>,
    ) -> std::result::Result<BlobRef, VendorError> {
        let digest = Sha256::digest(data);
        let grant = self.api.put(
            data.len() as u64,
            &B64.encode(digest),
            self.purpose,
            scope,
            None,
            idempotency_key,
        )?;
        self.hosts.check(&grant.upload_url)?;
        self.api.put_object(&grant, data, None)?;
        Ok(BlobRef {
            object_id: grant.object_id,
            size: data.len() as u64,
            sha256: hex(&digest),
        })
    }

    /// Fetch and verify the blob `blob` names.
    ///
    /// The download is pinned to the vendor's storage hosts, capped at
    /// `max_fetch_bytes`, and checked against the size and SHA-256 in `blob`
    /// (not the vendor's own report).
    ///
    /// # Errors
    ///
    /// If the vendor fails, the object is missing ([`VendorError::is_missing`]),
    /// the download fails, or the bytes do not match `blob` (`code` is
    /// `size_mismatch` or `sha256_mismatch`).
    pub fn get_bytes(&self, blob: &BlobRef) -> std::result::Result<Vec<u8>, VendorError> {
        let id = &blob.object_id;
        if blob.size > self.max_fetch_bytes {
            return Err(VendorError::new(format!(
                "Blob {id} is {} bytes, over max_fetch_bytes ({})",
                blob.size, self.max_fetch_bytes
            )));
        }
        let location = self.api.get(id)?;
        if let Some(enc) = location.content_encoding.as_deref() {
            if enc != "identity" {
                return Err(VendorError::new(format!(
                    "Blob {id} has unsupported content_encoding {enc:?}"
                )));
            }
        }
        if location.size != blob.size {
            return Err(VendorError::with(
                format!(
                    "Blob {id} size mismatch: vendor reports {}, ref has {}",
                    location.size, blob.size
                ),
                None,
                Some("size_mismatch".into()),
            ));
        }
        self.hosts
            .check(&location.download_url)
            .map_err(|e| VendorError::new(format!("Blob {id} download rejected: {}", e.message)))?;
        let data = self
            .api
            .download(&location.download_url, blob.size.max(1))
            .map_err(
                |e| match e.message.contains("larger than max_fetch_bytes") {
                    // More bytes than the reference declares: the same failure as
                    // a short read, reported the same way.
                    true => VendorError::with(
                        format!("Blob {id} size mismatch: expected {}, got more", blob.size),
                        None,
                        Some("size_mismatch".into()),
                    ),
                    false => VendorError::with(
                        format!("Blob {id} download failed: {}", e.message),
                        e.status,
                        e.code,
                    ),
                },
            )?;
        if data.len() as u64 != blob.size {
            return Err(VendorError::with(
                format!(
                    "Blob {id} size mismatch: expected {}, got {}",
                    blob.size,
                    data.len()
                ),
                None,
                Some("size_mismatch".into()),
            ));
        }
        let actual = hex(&Sha256::digest(&data));
        if actual != blob.sha256.to_ascii_lowercase() {
            return Err(VendorError::with(
                format!(
                    "Blob {id} SHA-256 mismatch: expected {}, got {actual}",
                    blob.sha256
                ),
                None,
                Some("sha256_mismatch".into()),
            ));
        }
        Ok(data)
    }

    /// Delete objects by id (missing objects are ignored), in chunks of
    /// [`MAX_DELETE_IDS`]. Returns how many the vendor deleted.
    ///
    /// # Errors
    ///
    /// If a vendor call fails.
    pub fn delete(&self, object_ids: &[String]) -> std::result::Result<u64, VendorError> {
        let mut total = 0;
        for chunk in object_ids.chunks(MAX_DELETE_IDS) {
            total += self.api.delete(chunk)?;
        }
        Ok(total)
    }

    /// Delete every object put under `(shard, execution_id)`. Returns how many
    /// the vendor deleted.
    ///
    /// # Errors
    ///
    /// If the vendor call fails.
    pub fn delete_scope(
        &self,
        shard: &str,
        execution_id: &str,
    ) -> std::result::Result<u64, VendorError> {
        self.api.delete_scope(&BlobScope {
            shard: shard.to_string(),
            execution_id: execution_id.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Env-driven configs
// ---------------------------------------------------------------------------

/// Build a [`UrlValidator`] pinned to the vendor's storage hosts, from
/// `GET /v1/info` fetched on first use and cached for `ttl` (a failed refresh
/// keeps the last good list). Only `https` URLs pass, or `http` when the
/// vendor itself is a loopback `http` URL (a local test vendor).
///
/// # Errors
///
/// For a malformed vendor URL or an empty token.
pub fn vendor_url_validator(url: &str, token: &str, ttl: Duration) -> Result<UrlValidator> {
    let api = Arc::new(VendorApi::new(url, token, DEFAULT_TIMEOUT)?);
    Ok(Arc::new(HostsValidator {
        api,
        ttl,
        cache: Mutex::new(None),
    })
    .validator())
}

/// A server external-location config from the blob-vendor environment, and
/// the [`VendorStorage`] behind it.
///
/// Uploads go through the vendor, inbound pointer URLs are pinned to the
/// vendor's hosts and fetched with a bare [`HttpFetcher`](crate::HttpFetcher),
/// and `VGI_RPC_EXTERNALIZE_THRESHOLD_BYTES` (default 1 MiB) and
/// `VGI_RPC_EXTERNAL_COMPRESSION` (default none) are honoured. Pass the
/// returned storage to `HttpStateBuilder::upload_url_provider` to also vend
/// client upload URLs.
///
/// # Errors
///
/// If the vendor URL is set but the token is missing, or a variable will not
/// parse.
pub fn external_config_from_env() -> Result<Option<(ExternalLocationConfig, Arc<VendorStorage>)>> {
    external_config_from_lookup(&env_lookup)
}

/// [`external_config_from_env`] over an explicit variable lookup.
///
/// # Errors
///
/// As [`external_config_from_env`].
pub fn external_config_from_lookup(
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<(ExternalLocationConfig, Arc<VendorStorage>)>> {
    if trimmed(lookup, ENV_URL).is_none() {
        return Ok(None);
    }
    let (url, token) = url_and_token(lookup)?;
    let storage = Arc::new(VendorStorage::new(&url, &token)?);
    let threshold = parse_positive(lookup, ENV_THRESHOLD)?
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
        .unwrap_or(DEFAULT_THRESHOLD);
    let compression = parse_compression(&lookup(ENV_COMPRESSION).unwrap_or_default())?;
    let config = ExternalLocationConfig::new(storage.clone(), Arc::new(crate::HttpFetcher::new()))
        .with_threshold_bytes(threshold)
        .with_compression(compression)
        .with_url_validator(storage.url_validator());
    Ok(Some((config, storage)))
}

/// A URL validator for clients that hold a vendor token (e.g. a worker calling
/// another worker): pointer and upload URLs are accepted only on the vendor's
/// storage hosts. `None` when `VGI_BLOB_VENDOR_URL` is unset.
///
/// # Errors
///
/// If the vendor URL is set but the token is missing.
pub fn client_external_config_from_env() -> Result<Option<UrlValidator>> {
    if trimmed(&env_lookup, ENV_URL).is_none() {
        return Ok(None);
    }
    let (url, token) = url_and_token(&env_lookup)?;
    vendor_url_validator(&url, &token, DEFAULT_INFO_TTL).map(Some)
}

/// Read `VGI_RPC_MAX_UPLOAD_BYTES` (the advertised client-upload size), or
/// `None` when unset.
///
/// # Errors
///
/// If the value is not a positive integer.
pub fn max_upload_bytes_from_env() -> Result<Option<u64>> {
    parse_positive(&env_lookup, ENV_MAX_UPLOAD_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pinned_hosts_accept_only_exact_hosts_and_ports() {
        let v = pinned_hosts_validator(&strings(&["r2.example.com", "127.0.0.1:9000"]), false, &[])
            .unwrap();
        assert!(v("https://r2.example.com/bucket/obj?sig=1").is_ok());
        assert!(v("https://r2.example.com:443/bucket/obj").is_ok());
        assert!(v("https://R2.Example.com/x").is_ok());
        assert!(v("https://r2.example.com:8443/x").is_err(), "other port");
        assert!(v("https://evil.r2.example.com/x").is_err(), "subdomain");
        assert!(
            v("http://r2.example.com/x").is_err(),
            "http without allow_http"
        );
        assert!(v("https://user@r2.example.com/x").is_err(), "userinfo");
        assert!(v("https://127.0.0.1:9000/x").is_ok());
        assert!(v("not a url").is_err());
    }

    #[test]
    fn pinned_hosts_http_and_prefixes() {
        let v = pinned_hosts_validator(
            &strings(&["127.0.0.1:5000"]),
            true,
            &strings(&["http://127.0.0.1:5000/r2/"]),
        )
        .unwrap();
        assert!(v("http://127.0.0.1:5000/r2/get/abc?X-Amz-Signature=s").is_ok());
        assert!(v("http://127.0.0.1:5000/other/abc").is_err());
        assert!(v("http://127.0.0.1:5000/r2/../v1/info").is_err());
        let v6 = pinned_hosts_validator(&strings(&["[::1]:8080"]), true, &[]).unwrap();
        assert!(v6("http://[::1]:8080/x").is_ok());
        assert!(pinned_hosts_validator(&[], false, &[]).is_err());
        assert!(pinned_hosts_validator(&strings(&["a/b"]), false, &[]).is_err());
    }

    #[test]
    fn rejection_messages_never_carry_the_signed_query() {
        let v = pinned_hosts_validator(&strings(&["good.example"]), false, &[]).unwrap();
        let err = v("https://bad.example/obj?X-Amz-Signature=SECRET123").unwrap_err();
        assert!(!err.message.contains("SECRET123"), "{}", err.message);
    }

    #[test]
    fn vendor_url_must_be_https_unless_loopback() {
        assert!(VendorStorage::new("https://blobs.example", "t").is_ok());
        assert!(VendorStorage::new("http://127.0.0.1:1234", "t").is_ok());
        assert!(VendorStorage::new("http://localhost:1234", "t").is_ok());
        assert!(VendorStorage::new("http://blobs.example", "t").is_err());
        assert!(VendorStorage::new("ftp://blobs.example", "t").is_err());
        assert!(VendorStorage::new("https://blobs.example", "").is_err());
        let dbg = format!(
            "{:?}",
            VendorStorage::new("https://blobs.example", "tok-SECRET").unwrap()
        );
        assert!(!dbg.contains("tok-SECRET"));
    }

    #[test]
    fn compression_parsing() {
        assert_eq!(parse_compression("").unwrap(), Compression::None);
        assert_eq!(parse_compression("None").unwrap(), Compression::None);
        assert_eq!(parse_compression("zstd").unwrap(), Compression::Zstd(3));
        assert_eq!(parse_compression("zstd:7").unwrap(), Compression::Zstd(7));
        assert!(parse_compression("gzip").is_err());
        assert!(parse_compression("zstd:x").is_err());
    }

    #[test]
    fn expires_parsing() {
        assert_eq!(parse_expires(&json!(10)).unwrap(), 10_000_000);
        assert_eq!(
            parse_expires(&json!(200_000_000_000u64)).unwrap(),
            200_000_000_000_000
        );
        assert_eq!(
            parse_expires(&json!("1970-01-01T00:00:01Z")).unwrap(),
            1_000_000
        );
        assert_eq!(
            parse_expires(&json!("1970-01-01T00:00:01.5")).unwrap(),
            1_500_000
        );
        assert!(parse_expires(&json!(true)).is_err());
        assert!(parse_expires(&json!("soon")).is_err());
    }

    #[test]
    fn env_config() {
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert!(external_config_from_lookup(&vars(&[])).unwrap().is_none());
        assert!(external_config_from_lookup(&vars(&[(ENV_URL, "https://v.example")])).is_err());
        let (cfg, _) = external_config_from_lookup(&vars(&[
            (ENV_URL, "https://v.example"),
            (ENV_TOKEN_FALLBACK, "t"),
            (ENV_THRESHOLD, "4096"),
            (ENV_COMPRESSION, "zstd:2"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(cfg.threshold_bytes, 4096);
        assert_eq!(cfg.compression, Compression::Zstd(2));
        assert!(external_config_from_lookup(&vars(&[
            (ENV_URL, "https://v.example"),
            (ENV_TOKEN, "t"),
            (ENV_THRESHOLD, "0"),
        ]))
        .is_err());
    }

    #[test]
    fn error_bodies() {
        assert_eq!(
            error_detail(br#"{"error":"not_found","message":"gone"}"#),
            (
                Some("not_found".to_string()),
                ": not_found: gone".to_string()
            )
        );
        assert_eq!(error_detail(b"<html>"), (None, String::new()));
        assert_eq!(
            s3_error_code(b"<Error><Code>NoSuchKey</Code></Error>").as_deref(),
            Some("NoSuchKey")
        );
        assert_eq!(s3_error_code(b"<Code>a b</Code>"), None);
        let missing = VendorError::with("x", Some(404), None);
        assert!(missing.is_missing());
        assert!(VendorError::with("x", Some(400), Some("not_uploaded".into())).is_missing());
        assert!(!VendorError::with("x", Some(400), None).is_missing());
    }
}
