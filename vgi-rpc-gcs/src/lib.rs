//! GCS-backed `ExternalStorage` for vgi-rpc.
//!
//! Follows the same pattern as `vgi-rpc-s3`: the caller supplies a
//! V4-signed PUT URL factory (`cloud-storage` or a GCP signing library
//! of their choice), and this crate performs the blocking HTTPS
//! transfer + exposes an HTTPS fetcher for the read side.

use std::sync::Arc;

pub use vgi_rpc_s3::HttpFetcher;

use vgi_rpc::external::{Compression, ExternalStorage, UploadResult};
use vgi_rpc::{Result, RpcError};

/// User-supplied factory: given `(bucket, object)`, return a short-lived
/// V4-signed HTTPS PUT URL.
pub type SignedUrlFactory = Arc<dyn Fn(&str, &str) -> Result<String> + Send + Sync>;

/// `ExternalStorage` that PUTs objects via a GCS V4-signed URL factory.
pub struct SignedGcsStorage {
    bucket: String,
    prefix: String,
    factory: SignedUrlFactory,
    client: reqwest::blocking::Client,
}

impl SignedGcsStorage {
    pub fn new(
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        factory: SignedUrlFactory,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: prefix.into(),
            factory,
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }

    fn object_key(&self) -> String {
        let id = uuid::Uuid::new_v4();
        format!("{}{id}.arrow", self.prefix)
    }
}

impl ExternalStorage for SignedGcsStorage {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult> {
        let key = self.object_key();
        let url = (self.factory)(&self.bucket, &key)?;
        let mut req = self
            .client
            .put(&url)
            .body(ipc_bytes.to_vec())
            .header("content-type", "application/vnd.apache.arrow.stream");
        if let Compression::Zstd(_) = compression {
            req = req.header("content-encoding", "zstd");
        }
        let resp = req
            .send()
            .map_err(|e| RpcError::runtime_error(format!("gcs PUT failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(RpcError::runtime_error(format!(
                "gcs PUT returned {} for {url}",
                resp.status()
            )));
        }
        Ok(UploadResult {
            url,
            sha256: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_uses_prefix() {
        let storage = SignedGcsStorage::new(
            "bkt",
            "tenant-a/",
            Arc::new(|_, _| Ok(String::from("https://example/"))),
        );
        let k = storage.object_key();
        assert!(k.starts_with("tenant-a/"));
    }
}
