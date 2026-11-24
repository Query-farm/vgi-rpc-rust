//! S3-backed `ExternalStorage` for vgi-rpc.
//!
//! Rather than pulling `aws-sdk-s3` (and its ~1-minute transitive compile
//! surface) into the core, this crate ships a pluggable pre-signed URL
//! factory. The caller produces short-lived PUT and GET URLs for each object
//! (typically via the corresponding `aws-sdk-s3` presign operations); we do the
//! blocking HTTPS transfer via `reqwest::blocking`. Upload and download URLs
//! are method-bound and generated as a pair for the same object key: publishing
//! a PUT URL as the external-location pointer is both incorrect and unsafe.
//!
//! Fetching mirrors the pattern: the `Fetcher` accepts any HTTPS URL the
//! server wrote into a pointer batch.
//!
//! Every storage transfer (the PUT, the object GET, the pointer fetch) has a
//! 30 s connect timeout and a 30 s **stall** timeout (no bytes moving), never a
//! whole-request deadline, and retries transient failures (connect, stall,
//! reset, 429, 5xx) up to 3 attempts. Set
//! `VGI_RPC_STORAGE_STALL_TIMEOUT_SECONDS` to change the stall timeout. See
//! [`transfer`].
//!
//! Example:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use vgi_rpc::external::{ExternalLocationConfig, Compression};
//! use vgi_rpc_s3::{PresignedS3Storage, HttpFetcher};
//!
//! let storage = PresignedS3Storage::new(
//!     "my-bucket",
//!     "vgi-rpc/",
//!     Arc::new(|req: &vgi_rpc_s3::PresignRequest| {
//!         // Your AWS SDK calls here — presign PUT and GET independently. Sign
//!         // the PUT for `req.size` bytes (content-length) and
//!         // `x-amz-checksum-sha256: req.sha256_b64()` so S3 itself refuses a
//!         // mismatched body, and return the signed headers.
//!         let (bucket, key) = (req.bucket, req.key);
//!         Ok(vgi_rpc::external::UploadUrl {
//!             upload_url: format!("https://{bucket}.s3.amazonaws.com/{key}?put-signature=..."),
//!             download_url: format!("https://{bucket}.s3.amazonaws.com/{key}?get-signature=..."),
//!             expires_at_micros: 0,
//!             headers: req.s3_checksum_headers(),
//!             // `object_id` defaults to `req.key` when left empty.
//!             ..Default::default()
//!         })
//!     }),
//! );
//! let fetcher = HttpFetcher::new();
//! let cfg = ExternalLocationConfig::new(Arc::new(storage), Arc::new(fetcher))
//!     .with_compression(Compression::Zstd(3));
//! ```

use std::sync::Arc;

pub mod transfer;
pub mod vendor;

use transfer::{ReadError, RetryPolicy, StorageClient, StorageResponse, TransferTimeouts};

use vgi_rpc::external::{
    object_missing_error, validate_external_url, Compression, ExternalStorage, FetchedPayload,
    Fetcher, ObjectStore, UploadResult, UploadUrl, UploadUrlProvider, UrlValidator,
};
use vgi_rpc::{Result, RpcError};

/// Build a `reqwest::blocking::Client` with a 30 s total timeout.
///
/// No longer used for storage transfers: the S3 / GCS backends and
/// [`HttpFetcher`] use [`transfer::StorageClient`] (connect + stall timeouts,
/// no total deadline), because a total deadline fails large transfers on
/// slow links. Kept for callers that use it for small requests.
///
/// Redirects are **disabled**: a presigned PUT or a fetch of an
/// already-validated `https://` URL has no legitimate reason to be
/// redirected, and following one would let an allowlisted host bounce
/// the request to an internal address (SSRF). A redirect is surfaced as
/// a non-success status instead.
pub fn default_blocking_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

/// Strip the query string (and fragment) from a URL before it goes into
/// a client-facing error. Presigned URLs carry their credentials in the
/// query string — those must never be echoed back to a caller.
pub(crate) fn redact_url(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return "<invalid external URL>".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

/// What one presigned PUT is for: the object, and the exact size and SHA-256
/// of the body that will be uploaded to it.
#[derive(Clone, Copy, Debug)]
pub struct PresignRequest<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    /// Exact byte length of the body; sign it as the content length.
    pub size: u64,
    /// SHA-256 of the body, 64 lowercase hex characters.
    pub sha256_hex: &'a str,
}

impl PresignRequest<'_> {
    /// The SHA-256 as S3's `x-amz-checksum-sha256` value (base64 of the raw
    /// 32 digest bytes).
    pub fn sha256_b64(&self) -> String {
        vgi_rpc::external::sha256_hex_to_b64(self.sha256_hex)
            .expect("PresignRequest carries a validated sha256")
    }

    /// The headers an S3/R2 PUT signed for this body must carry:
    /// `x-amz-checksum-sha256`. A factory that signs other headers adds them.
    pub fn s3_checksum_headers(&self) -> Vec<(String, String)> {
        vec![("x-amz-checksum-sha256".to_string(), self.sha256_b64())]
    }

    /// The header a GCS V4 PUT signed for exactly this size must carry
    /// (`x-goog-content-length-range: N,N`). GCS cannot verify SHA-256 at
    /// storage; the server's pointer check catches a wrong body instead.
    pub fn gcs_length_headers(&self) -> Vec<(String, String)> {
        vec![(
            "x-goog-content-length-range".to_string(),
            format!("{0},{0}", self.size),
        )]
    }
}

/// User-supplied factory: given a [`PresignRequest`], return independently
/// signed upload (PUT) and download (GET) URLs for that same object, the PUT
/// signed for the request's size (and SHA-256 where the backend can verify
/// it), with the signed headers in [`UploadUrl::headers`].
pub type PresignUrlPairFactory =
    Arc<dyn Fn(&PresignRequest<'_>) -> Result<UploadUrl> + Send + Sync>;

/// Generic `ExternalStorage` that PUTs objects via a caller-supplied
/// pre-signed URL factory. Shared between S3 and GCS backends — the only
/// difference is the `label` used in error messages.
pub struct PresignedPutStorage {
    label: &'static str,
    bucket: String,
    prefix: String,
    factory: PresignUrlPairFactory,
    client: StorageClient,
    retry: RetryPolicy,
}

impl PresignedPutStorage {
    pub fn new(
        label: &'static str,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        factory: PresignUrlPairFactory,
    ) -> Self {
        Self {
            label,
            bucket: bucket.into(),
            prefix: prefix.into(),
            factory,
            client: StorageClient::new(TransferTimeouts::from_env()),
            retry: RetryPolicy::default(),
        }
    }

    /// Replace the transfer timeouts (default [`TransferTimeouts::from_env`]).
    #[must_use]
    pub fn with_transfer_timeouts(mut self, timeouts: TransferTimeouts) -> Self {
        self.client = StorageClient::new(timeouts);
        self
    }

    /// Replace the retry policy (default 3 attempts).
    #[must_use]
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn object_key(&self) -> String {
        let id = uuid::Uuid::new_v4();
        format!("{}{id}.arrow", self.prefix)
    }

    fn generate_pair(&self, size: u64, sha256_hex: &str) -> Result<UploadUrl> {
        if !vgi_rpc::external::is_sha256_hex(sha256_hex) {
            return Err(RpcError::value_error(
                "sha256 must be 64 lowercase hex characters",
            ));
        }
        let key = self.object_key();
        self.presign(&key, size, sha256_hex)
    }

    /// Run the factory for `key`; an `object_id` the factory left empty is
    /// the key (the S3/GCS object id, `STATE_REF_V1.md` §10.1).
    fn presign(&self, key: &str, size: u64, sha256_hex: &str) -> Result<UploadUrl> {
        let mut urls = (self.factory)(&PresignRequest {
            bucket: &self.bucket,
            key,
            size,
            sha256_hex,
        })?;
        if urls.object_id.is_empty() {
            urls.object_id = key.to_string();
        }
        Ok(urls)
    }

    /// PUT `body` to a presigned URL with exactly its signed headers,
    /// retrying transient failures (connect, stall, reset, 429, 5xx).
    fn put_body(
        &self,
        urls: &UploadUrl,
        body: &[u8],
        content_type: &str,
        compression: Compression,
    ) -> Result<()> {
        let signed = |name: &str| {
            urls.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(name))
        };
        let mut headers = Vec::new();
        if !signed("content-type") {
            headers.push(("content-type".to_string(), content_type.to_string()));
        }
        if let (Compression::Zstd(_), false) = (compression, signed("content-encoding")) {
            headers.push(("content-encoding".to_string(), "zstd".to_string()));
        }
        for (k, v) in &urls.headers {
            if !k.eq_ignore_ascii_case("content-length") {
                headers.push((k.clone(), v.clone()));
            }
        }
        let label = self.label;
        let data = bytes::Bytes::copy_from_slice(body);
        let mut last = String::new();
        for attempt in 0..self.retry.attempts() {
            self.retry.pause(attempt);
            let resp = match self.client.send(
                reqwest::Method::PUT,
                &urls.upload_url,
                &headers,
                Some(data.clone()),
            ) {
                Ok(r) => r,
                Err(e) => {
                    last = e.label().to_string();
                    continue;
                }
            };
            let status = resp.status();
            if status.as_u16() == 429 || status.is_server_error() {
                last = format!("HTTP {status}");
                continue;
            }
            if !status.is_success() {
                return Err(RpcError::runtime_error(format!(
                    "{label} PUT returned {status} for {}",
                    redact_url(&urls.upload_url)
                )));
            }
            // Drain the (empty) body so the connection can be reused; a
            // failure here does not undo the stored object.
            let _ = resp.read_capped(64 * 1024);
            return Ok(());
        }
        Err(RpcError::runtime_error(format!(
            "{label} PUT failed after {} attempts ({last}) for {}",
            self.retry.attempts(),
            redact_url(&urls.upload_url)
        )))
    }

    /// GET `url` with retries; `None` for a 404.
    fn get_body(&self, url: &str, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        let label = self.label;
        let mut last = String::new();
        for attempt in 0..self.retry.attempts() {
            self.retry.pause(attempt);
            let resp = match self.client.send(reqwest::Method::GET, url, &[], None) {
                Ok(r) => r,
                Err(e) => {
                    last = e.label().to_string();
                    continue;
                }
            };
            let status = resp.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if status.as_u16() == 429 || status.is_server_error() {
                last = format!("HTTP {status}");
                continue;
            }
            if !status.is_success() {
                return Err(RpcError::runtime_error(format!(
                    "{label} GET returned {status} for {}",
                    redact_url(url)
                )));
            }
            if resp.content_length().is_some_and(|n| n > max_bytes as u64) {
                return Err(RpcError::runtime_error(format!(
                    "{label} object exceeds max_fetch_bytes ({max_bytes})"
                )));
            }
            match resp.read_capped(max_bytes as u64) {
                Ok(out) => return Ok(Some(out)),
                Err(ReadError::TooLarge) => {
                    return Err(RpcError::runtime_error(format!(
                        "{label} object exceeds max_fetch_bytes ({max_bytes})"
                    )))
                }
                Err(ReadError::Transfer(e)) => {
                    last = format!("body {}", e.label());
                    continue;
                }
            }
        }
        Err(RpcError::runtime_error(format!(
            "{label} GET failed after {} attempts ({last}) for {}",
            self.retry.attempts(),
            redact_url(url)
        )))
    }
}

fn sha256_hex_of(data: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The object API (`STATE_REF_V1.md` §10.1). `object_id` is the object key.
///
/// `put_object` stores under a fresh key with a PUT signed for the body's
/// size and SHA-256 (the factory's [`PresignRequest::s3_checksum_headers`]
/// make S3/R2 verify it). `get` asks the same factory to presign `object_id`
/// and uses only the GET URL (the PUT half, presigned for an empty body, is
/// discarded), so a factory needs no second entry point. Objects carry no
/// TTL: set a bucket lifecycle rule of at least one day on the prefix.
impl ObjectStore for PresignedPutStorage {
    fn put_object(&self, data: &[u8]) -> Result<String> {
        let sha = sha256_hex_of(data);
        let key = format!("{}{}.bin", self.prefix, uuid::Uuid::new_v4());
        let urls = self.presign(&key, data.len() as u64, &sha)?;
        self.put_body(&urls, data, "application/octet-stream", Compression::None)?;
        Ok(key)
    }

    fn get(&self, object_id: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let label = self.label;
        let urls = self.presign(object_id, 0, &sha256_hex_of(b""))?;
        self.get_body(&urls.download_url, max_bytes)?
            .ok_or_else(|| object_missing_error(format!("{label} object is gone")))
    }
}

impl ExternalStorage for PresignedPutStorage {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult> {
        let sha = sha256_hex_of(ipc_bytes);
        let urls = self.generate_pair(ipc_bytes.len() as u64, &sha)?;
        self.put_body(
            &urls,
            ipc_bytes,
            "application/vnd.apache.arrow.stream",
            compression,
        )?;
        // sha256 is computed by ExternalLocationConfig's caller; return an
        // empty string here as the field is populated upstream.
        Ok(UploadResult {
            url: urls.download_url,
            sha256: String::new(),
        })
    }

    fn object_store(&self) -> Option<&dyn ObjectStore> {
        Some(self)
    }
}

impl UploadUrlProvider for PresignedPutStorage {
    fn generate_upload_url(&self, size: u64, sha256_hex: &str) -> Result<UploadUrl> {
        self.generate_pair(size, sha256_hex)
    }
}

/// S3-flavored alias for [`PresignedPutStorage`].
pub struct PresignedS3Storage(PresignedPutStorage);

impl PresignedS3Storage {
    pub fn new(
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        factory: PresignUrlPairFactory,
    ) -> Self {
        Self(PresignedPutStorage::new("s3", bucket, prefix, factory))
    }

    pub fn bucket(&self) -> &str {
        self.0.bucket()
    }

    pub fn prefix(&self) -> &str {
        self.0.prefix()
    }

    #[cfg(test)]
    fn object_key(&self) -> String {
        self.0.object_key()
    }
}

impl ExternalStorage for PresignedS3Storage {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult> {
        self.0.upload(ipc_bytes, compression)
    }

    fn object_store(&self) -> Option<&dyn ObjectStore> {
        Some(&self.0)
    }
}

impl UploadUrlProvider for PresignedS3Storage {
    fn generate_upload_url(&self, size: u64, sha256_hex: &str) -> Result<UploadUrl> {
        self.0.generate_upload_url(size, sha256_hex)
    }
}

/// Shared HTTPS `Fetcher`. Reusable across S3 / GCS / any signed URL
/// source.
///
/// Connect + stall timeouts, no total deadline (see [`transfer`]); connect
/// errors, stalls (also mid-body), resets, 429 and 5xx are retried.
pub struct HttpFetcher {
    client: StorageClient,
    retry: RetryPolicy,
}

impl HttpFetcher {
    pub fn new() -> Self {
        Self::with_timeouts(TransferTimeouts::from_env())
    }

    /// A fetcher with explicit transfer timeouts.
    pub fn with_timeouts(timeouts: TransferTimeouts) -> Self {
        Self {
            client: StorageClient::new(timeouts),
            retry: RetryPolicy::default(),
        }
    }

    /// Replace the retry policy (default 3 attempts).
    #[must_use]
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// GET `url` once per attempt until a non-transient answer: a response
    /// whose status is neither 429 nor 5xx, with its body read by `body`.
    /// Redirect statuses are returned to the caller unread.
    fn get_with_retries<T>(
        &self,
        url: &reqwest::Url,
        mut body: impl FnMut(StorageResponse) -> std::result::Result<T, FetchStep>,
    ) -> Result<T> {
        let mut last = String::new();
        for attempt in 0..self.retry.attempts() {
            self.retry.pause(attempt);
            let resp = match self
                .client
                .send_url(reqwest::Method::GET, url.clone(), &[], None)
            {
                Ok(r) => r,
                Err(e) => {
                    last = e.label().to_string();
                    continue;
                }
            };
            let status = resp.status();
            if status.as_u16() == 429 || status.is_server_error() {
                last = format!("HTTP {status}");
                continue;
            }
            match body(resp) {
                Ok(v) => return Ok(v),
                Err(FetchStep::Fatal(e)) => return Err(e),
                Err(FetchStep::Retry(why)) => last = why,
            }
        }
        Err(RpcError::runtime_error(format!(
            "external GET failed after {} attempts ({last}) for {}",
            self.retry.attempts(),
            redact_url(url.as_str())
        )))
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

/// What one fetch attempt's body handler decided.
enum FetchStep {
    Fatal(RpcError),
    Retry(String),
}

/// Read a fetched body, capped at `max_bytes`; a stall or reset is retried.
fn read_fetched(
    resp: StorageResponse,
    max_bytes: usize,
    cap_name: &str,
) -> std::result::Result<Vec<u8>, FetchStep> {
    // Fast reject on a declared Content-Length over the cap; the streamed
    // read below also aborts once the body grows past it, so a remote that
    // lies about (or omits) Content-Length cannot OOM the process.
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(FetchStep::Fatal(RpcError::runtime_error(format!(
                "external payload Content-Length {len} exceeds {cap_name}={max_bytes}"
            ))));
        }
    }
    match resp.read_capped(max_bytes as u64) {
        Ok(out) => Ok(out),
        Err(ReadError::TooLarge) => Err(FetchStep::Fatal(RpcError::runtime_error(format!(
            "external payload exceeds {cap_name}={max_bytes}"
        )))),
        Err(ReadError::Transfer(e)) => Err(FetchStep::Retry(format!("body {}", e.label()))),
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, url: &str, _compression: Compression, max_bytes: usize) -> Result<Vec<u8>> {
        let parsed = reqwest::Url::parse(url).map_err(|_| {
            RpcError::runtime_error(format!("external GET failed for {}", redact_url(url)))
        })?;
        self.get_with_retries(&parsed, |resp| {
            if !resp.status().is_success() {
                return Err(FetchStep::Fatal(RpcError::runtime_error(format!(
                    "external GET returned {} for {}",
                    resp.status(),
                    redact_url(url)
                ))));
            }
            read_fetched(resp, max_bytes, "max_bytes")
        })
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
            enum Hop {
                Redirect(Option<String>),
                Done(FetchedPayload),
            }
            let hop = self.get_with_retries(&current, |resp| {
                if resp.status().is_redirection() {
                    let location = resp
                        .headers()
                        .get(LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    return Ok(Hop::Redirect(location));
                }
                if !resp.status().is_success() {
                    return Err(FetchStep::Fatal(RpcError::runtime_error(format!(
                        "external GET returned {} for {}",
                        resp.status(),
                        redact_url(current.as_str())
                    ))));
                }
                let compression = resp
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| value.eq_ignore_ascii_case("zstd"))
                    .map_or(Compression::None, |_| Compression::Zstd(0));
                let bytes = read_fetched(resp, max_bytes, "max_fetch_bytes")?;
                Ok(Hop::Done(FetchedPayload { bytes, compression }))
            })?;
            match hop {
                Hop::Done(payload) => return Ok(payload),
                Hop::Redirect(location) => {
                    if redirects >= max_redirects {
                        return Err(RpcError::runtime_error(format!(
                            "external fetch redirect limit ({max_redirects}) exceeded"
                        )));
                    }
                    let location = location.ok_or_else(|| {
                        RpcError::runtime_error("external redirect missing Location")
                    })?;
                    let next = current.join(&location).map_err(|_| {
                        RpcError::runtime_error("external redirect has invalid Location")
                    })?;
                    validate_external_url(validator, next.as_str())?;
                    current = next;
                    redirects += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn read_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut received = Vec::new();
        let header_end = loop {
            if let Some(pos) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap();
            assert_ne!(n, 0, "request ended before headers");
            received.extend_from_slice(&buf[..n]);
        };
        let head = String::from_utf8(received[..header_end].to_vec()).unwrap();
        let content_length = head
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
            })
            .unwrap_or(0);
        while received.len() - header_end < content_length {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap();
            assert_ne!(n, 0, "request ended before body");
            received.extend_from_slice(&buf[..n]);
        }
        (
            head.lines().next().unwrap().to_string(),
            received[header_end..header_end + content_length].to_vec(),
        )
    }

    #[test]
    fn object_key_uses_prefix() {
        let storage = PresignedS3Storage::new(
            "bkt",
            "tenant-a/vgi/",
            Arc::new(|_: &PresignRequest| {
                Ok(UploadUrl {
                    upload_url: String::from("https://example/upload"),
                    download_url: String::from("https://example/download"),
                    expires_at_micros: 0,
                    headers: Vec::new(),
                    ..Default::default()
                })
            }),
        );
        let k = storage.object_key();
        assert!(k.starts_with("tenant-a/vgi/"));
        assert!(k.ends_with(".arrow"));
    }

    #[test]
    fn factory_error_propagates() {
        let storage = PresignedS3Storage::new(
            "bkt",
            "",
            Arc::new(|_: &PresignRequest| Err(RpcError::runtime_error("nope"))),
        );
        let err = storage
            .upload(&[1, 2, 3], Compression::None)
            .expect_err("should fail");
        assert!(err.message.contains("nope"));
    }

    #[test]
    fn fetch_connection_error_redacts_signed_query() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let secret = "FETCH_QUERY_SECRET_91ad";
        let url = format!("http://{address}/download?signature={secret}");
        let error = HttpFetcher::new()
            .fetch(&url, Compression::None, 1024)
            .unwrap_err();
        let rendered = format!("{error:?}");
        assert!(
            !rendered.contains(secret),
            "leaked signed query: {rendered}"
        );
        assert!(rendered.contains("/download"));
    }

    #[test]
    fn method_bound_url_pair_round_trips_locally() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = b"method-bound-arrow-payload".to_vec();
        let expected = payload.clone();
        let server = std::thread::spawn(move || {
            let (mut put, _) = listener.accept().unwrap();
            let (line, body) = read_request(&mut put);
            assert!(line.starts_with("PUT /upload?put-secret=1 "), "got {line}");
            assert_eq!(body, expected);
            put.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();

            let (mut get, _) = listener.accept().unwrap();
            let (line, body) = read_request(&mut get);
            assert!(
                line.starts_with("GET /download?get-secret=2 "),
                "got {line}"
            );
            assert!(body.is_empty());
            write!(
                get,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                expected.len()
            )
            .unwrap();
            get.write_all(&expected).unwrap();
        });

        let upload_url = format!("http://{addr}/upload?put-secret=1");
        let download_url = format!("http://{addr}/download?get-secret=2");
        let expected_download = download_url.clone();
        let storage = PresignedS3Storage::new(
            "bucket",
            "prefix/",
            Arc::new(move |_: &PresignRequest| {
                Ok(UploadUrl {
                    upload_url: upload_url.clone(),
                    download_url: download_url.clone(),
                    expires_at_micros: 123,
                    headers: Vec::new(),
                    ..Default::default()
                })
            }),
        );

        let uploaded = storage.upload(&payload, Compression::None).unwrap();
        assert_eq!(uploaded.url, expected_download);
        let fetched = HttpFetcher::new()
            .fetch(&uploaded.url, Compression::None, 1024)
            .unwrap();
        assert_eq!(fetched, payload);
        server.join().unwrap();
    }

    fn storage_for(base: &str) -> PresignedS3Storage {
        let (up, down) = (format!("{base}/up?sig=1"), format!("{base}/down?sig=2"));
        PresignedS3Storage(
            PresignedPutStorage::new(
                "s3",
                "bucket",
                "p/",
                Arc::new(move |_: &PresignRequest| {
                    Ok(UploadUrl {
                        upload_url: up.clone(),
                        download_url: down.clone(),
                        ..Default::default()
                    })
                }),
            )
            .with_transfer_timeouts(TransferTimeouts {
                connect: std::time::Duration::from_secs(5),
                stall: std::time::Duration::from_secs(1),
            }),
        )
    }

    /// Throttle: a 24 MiB upload the server takes at ~3 MiB/s (about 8 s,
    /// twice the 4 s stall timeout) succeeds with exactly one PUT.
    #[test]
    fn throttled_put_succeeds_in_one_attempt() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        const TOTAL: usize = 24 * 1024 * 1024;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let puts = Arc::new(AtomicUsize::new(0));
        let seen = puts.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut s = stream.unwrap();
                seen.fetch_add(1, Ordering::SeqCst);
                let mut got = Vec::new();
                let mut b = [0u8; 8192];
                while got.windows(4).position(|w| w == b"\r\n\r\n").is_none() {
                    let n = s.read(&mut b).unwrap();
                    got.extend_from_slice(&b[..n]);
                }
                let head_end = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let mut body = got.len() - head_end;
                while body < TOTAL {
                    let n = s.read(&mut b).unwrap();
                    assert_ne!(n, 0);
                    body += n;
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
            }
        });
        let start = std::time::Instant::now();
        storage_for(&base)
            .0
            .with_transfer_timeouts(TransferTimeouts {
                connect: std::time::Duration::from_secs(5),
                stall: std::time::Duration::from_secs(4),
            })
            .upload(&vec![3u8; TOTAL], Compression::None)
            .unwrap();
        assert!(start.elapsed() > std::time::Duration::from_secs(4));
        assert_eq!(puts.load(Ordering::SeqCst), 1);
    }

    /// A storage host that stops sending mid-body is retried (3 attempts in
    /// all), each attempt failing within the stall timeout.
    #[test]
    fn stalled_get_is_retried_then_fails() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gets = Arc::new(AtomicUsize::new(0));
        let seen = gets.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut s = stream.unwrap();
                seen.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    let mut b = [0u8; 8192];
                    let _ = s.read(&mut b);
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nabc");
                    std::thread::sleep(std::time::Duration::from_secs(20));
                });
            }
        });
        let start = std::time::Instant::now();
        let err = storage_for(&base).0.get("p/x.bin", 1 << 20).unwrap_err();
        let took = start.elapsed();
        assert!(err.message.contains("after 3 attempts"), "{}", err.message);
        assert!(err.message.contains("stalled"), "{}", err.message);
        assert!(!err.message.contains("sig="), "{}", err.message);
        assert_eq!(gets.load(Ordering::SeqCst), 3);
        assert!(took < std::time::Duration::from_secs(8), "took {took:?}");
    }
}
