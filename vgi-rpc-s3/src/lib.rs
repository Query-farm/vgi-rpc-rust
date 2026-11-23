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

pub mod vendor;

use vgi_rpc::external::{
    object_missing_error, validate_external_url, Compression, ExternalStorage, FetchedPayload,
    Fetcher, ObjectStore, UploadResult, UploadUrl, UploadUrlProvider, UrlValidator,
};
use vgi_rpc::{Result, RpcError};

/// Build a `reqwest::blocking::Client` with the default 30 s timeout used
/// by both the S3 / GCS storage backends and the shared `HttpFetcher`.
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
    client: reqwest::blocking::Client,
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
            client: default_blocking_client(),
        }
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

    /// PUT `body` to a presigned URL with exactly its signed headers.
    fn put_body(
        &self,
        urls: &UploadUrl,
        body: &[u8],
        content_type: &str,
        compression: Compression,
    ) -> Result<()> {
        let mut req = self.client.put(&urls.upload_url).body(body.to_vec());
        let signed = |name: &str| {
            urls.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(name))
        };
        if !signed("content-type") {
            req = req.header("content-type", content_type);
        }
        if let (Compression::Zstd(_), false) = (compression, signed("content-encoding")) {
            req = req.header("content-encoding", "zstd");
        }
        for (k, v) in &urls.headers {
            if !k.eq_ignore_ascii_case("content-length") {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        let label = self.label;
        let resp = req
            .send()
            .map_err(|_| RpcError::runtime_error(format!("{label} PUT failed")))?;
        if !resp.status().is_success() {
            return Err(RpcError::runtime_error(format!(
                "{label} PUT returned {} for {}",
                resp.status(),
                redact_url(&urls.upload_url)
            )));
        }
        Ok(())
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
        use std::io::Read;
        let label = self.label;
        let urls = self.presign(object_id, 0, &sha256_hex_of(b""))?;
        let mut resp = self.client.get(&urls.download_url).send().map_err(|_| {
            RpcError::runtime_error(format!(
                "{label} GET failed for {}",
                redact_url(&urls.download_url)
            ))
        })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(object_missing_error(format!("{label} object is gone")));
        }
        if !resp.status().is_success() {
            return Err(RpcError::runtime_error(format!(
                "{label} GET returned {} for {}",
                resp.status(),
                redact_url(&urls.download_url)
            )));
        }
        if resp.content_length().is_some_and(|n| n > max_bytes as u64) {
            return Err(RpcError::runtime_error(format!(
                "{label} object exceeds max_fetch_bytes ({max_bytes})"
            )));
        }
        let mut out = Vec::new();
        resp.by_ref()
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| RpcError::runtime_error(format!("{label} GET body read failed")))?;
        if out.len() > max_bytes {
            return Err(RpcError::runtime_error(format!(
                "{label} object exceeds max_fetch_bytes ({max_bytes})"
            )));
        }
        Ok(out)
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
pub struct HttpFetcher {
    client: reqwest::blocking::Client,
}

impl HttpFetcher {
    pub fn new() -> Self {
        Self {
            client: default_blocking_client(),
        }
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, url: &str, _compression: Compression, max_bytes: usize) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut resp = self.client.get(url).send().map_err(|_| {
            RpcError::runtime_error(format!("external GET failed for {}", redact_url(url)))
        })?;
        if !resp.status().is_success() {
            return Err(RpcError::runtime_error(format!(
                "external GET returned {} for {}",
                resp.status(),
                redact_url(url)
            )));
        }
        // Fast reject on a declared Content-Length over the cap.
        if let Some(len) = resp.content_length() {
            if len > max_bytes as u64 {
                return Err(RpcError::runtime_error(format!(
                    "external payload Content-Length {len} exceeds max_bytes={max_bytes}"
                )));
            }
        }
        // Stream the body, aborting once it grows past the cap — a
        // remote that lies about (or omits) Content-Length must not be
        // able to OOM the process by dribbling an unbounded response.
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
        use std::io::Read;

        validate_external_url(validator, url)?;
        let mut current = reqwest::Url::parse(url)
            .map_err(|_| RpcError::value_error("URL rejected: invalid external URL"))?;
        let mut redirects = 0usize;
        loop {
            let mut resp = self.client.get(current.clone()).send().map_err(|_| {
                RpcError::runtime_error(format!(
                    "external GET failed for {}",
                    redact_url(current.as_str())
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
                    redact_url(current.as_str())
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
}
