//! GCS-backed `ExternalStorage` for vgi-rpc.
//!
//! Follows the same pattern as `vgi-rpc-s3`: the caller supplies a factory for
//! method-bound V4-signed PUT and GET URLs (`cloud-storage` or a GCP signing
//! library of their choice), and this crate performs the blocking HTTPS
//! transfer + exposes an HTTPS fetcher for the read side.

pub use vgi_rpc_s3::HttpFetcher;

use vgi_rpc::external::{
    Compression, ExternalStorage, ObjectStore, UploadResult, UploadUrl, UploadUrlProvider,
};
use vgi_rpc::Result;
pub use vgi_rpc_s3::PresignRequest;
use vgi_rpc_s3::{PresignUrlPairFactory, PresignedPutStorage};

/// User-supplied factory returning method-bound V4-signed PUT and GET URLs.
///
/// GCS cannot verify a SHA-256 at storage, so sign the PUT for the exact
/// length instead ([`PresignRequest::gcs_length_headers`]) and return the
/// signed headers; the server's `vgi_rpc.location.sha256` check catches a
/// wrong body.
pub type SignedUrlFactory = PresignUrlPairFactory;

/// `ExternalStorage` that PUTs objects via a GCS V4-signed URL factory.
pub struct SignedGcsStorage(PresignedPutStorage);

impl SignedGcsStorage {
    pub fn new(
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        factory: SignedUrlFactory,
    ) -> Self {
        Self(PresignedPutStorage::new("gcs", bucket, prefix, factory))
    }
}

impl ExternalStorage for SignedGcsStorage {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult> {
        self.0.upload(ipc_bytes, compression)
    }

    /// The object API; `object_id` is the blob name. GCS cannot verify a
    /// SHA-256 at storage: the upload is length-exact and callers verify the
    /// digest on read. Set Object Lifecycle Management of at least one day on
    /// the prefix.
    fn object_store(&self) -> Option<&dyn ObjectStore> {
        Some(&self.0)
    }
}

impl UploadUrlProvider for SignedGcsStorage {
    fn generate_upload_url(&self, size: u64, sha256_hex: &str) -> Result<UploadUrl> {
        self.0.generate_upload_url(size, sha256_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use vgi_rpc::external::Fetcher;

    #[test]
    fn uploads_via_factory() {
        let storage = SignedGcsStorage::new(
            "bkt",
            "tenant-a/",
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
        let err = storage
            .upload(&[1, 2, 3], Compression::None)
            .expect_err("example URL won't actually accept PUT");
        assert!(err.message.contains("gcs PUT"));
    }

    #[test]
    fn method_bound_urls_round_trip_through_gcs_wrapper() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = b"gcs-method-pair".to_vec();
        let expected = payload.clone();
        let server = std::thread::spawn(move || {
            let mut stored = Vec::new();
            for method in ["PUT", "GET"] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap();
                    request.extend_from_slice(&buf[..n]);
                };
                let head = String::from_utf8(request[..header_end].to_vec()).unwrap();
                assert!(head.starts_with(method));
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                    })
                    .unwrap_or(0);
                while request.len() - header_end < length {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap();
                    request.extend_from_slice(&buf[..n]);
                }
                if method == "PUT" {
                    stored = request[header_end..header_end + length].to_vec();
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        stored.len()
                    )
                    .unwrap();
                    stream.write_all(&stored).unwrap();
                }
            }
            assert_eq!(stored, expected);
        });
        let upload_url = format!("http://{addr}/upload");
        let download_url = format!("http://{addr}/download");
        let expected_download = download_url.clone();
        let storage = SignedGcsStorage::new(
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
