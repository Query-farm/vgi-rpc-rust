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
//!     Arc::new(|bucket: &str, key: &str| {
//!         // Your AWS SDK calls here — presign PUT and GET independently.
//!         Ok(vgi_rpc::external::UploadUrl {
//!             upload_url: format!("https://{bucket}.s3.amazonaws.com/{key}?put-signature=..."),
//!             download_url: format!("https://{bucket}.s3.amazonaws.com/{key}?get-signature=..."),
//!             expires_at_micros: 0,
//!         })
//!     }),
//! );
//! let fetcher = HttpFetcher::new();
//! let cfg = ExternalLocationConfig::new(Arc::new(storage), Arc::new(fetcher))
//!     .with_compression(Compression::Zstd(3));
//! ```

use std::sync::Arc;

use vgi_rpc::external::{
    validate_external_url, Compression, ExternalStorage, FetchedPayload, Fetcher, UploadResult,
    UploadUrl, UploadUrlProvider, UrlValidator,
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
fn redact_url(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return "<invalid external URL>".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

/// User-supplied factory: given `(bucket, key)`, return independently signed
/// upload (PUT) and download (GET) URLs for that same object.
pub type PresignUrlPairFactory = Arc<dyn Fn(&str, &str) -> Result<UploadUrl> + Send + Sync>;

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

    fn generate_pair(&self) -> Result<UploadUrl> {
        let key = self.object_key();
        (self.factory)(&self.bucket, &key)
    }
}

impl ExternalStorage for PresignedPutStorage {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult> {
        let urls = self.generate_pair()?;
        let mut req = self
            .client
            .put(&urls.upload_url)
            .body(ipc_bytes.to_vec())
            .header("content-type", "application/vnd.apache.arrow.stream");
        if let Compression::Zstd(_) = compression {
            req = req.header("content-encoding", "zstd");
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
        // sha256 is computed by ExternalLocationConfig's caller; return an
        // empty string here as the field is populated upstream.
        Ok(UploadResult {
            url: urls.download_url,
            sha256: String::new(),
        })
    }
}

impl UploadUrlProvider for PresignedPutStorage {
    fn generate_upload_url(&self) -> Result<UploadUrl> {
        self.generate_pair()
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
}

impl UploadUrlProvider for PresignedS3Storage {
    fn generate_upload_url(&self) -> Result<UploadUrl> {
        self.0.generate_upload_url()
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
            Arc::new(|_, _| {
                Ok(UploadUrl {
                    upload_url: String::from("https://example/upload"),
                    download_url: String::from("https://example/download"),
                    expires_at_micros: 0,
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
            Arc::new(|_, _| Err(RpcError::runtime_error("nope"))),
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
            Arc::new(move |_, _| {
                Ok(UploadUrl {
                    upload_url: upload_url.clone(),
                    download_url: download_url.clone(),
                    expires_at_micros: 123,
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
