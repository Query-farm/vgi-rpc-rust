//! GCS-backed `ExternalStorage` for vgi-rpc.
//!
//! Follows the same pattern as `vgi-rpc-s3`: the caller supplies a
//! V4-signed PUT URL factory (`cloud-storage` or a GCP signing library
//! of their choice), and this crate performs the blocking HTTPS
//! transfer + exposes an HTTPS fetcher for the read side.

use std::sync::Arc;

pub use vgi_rpc_s3::HttpFetcher;

use vgi_rpc::external::{Compression, ExternalStorage, UploadResult};
use vgi_rpc::Result;
use vgi_rpc_s3::PresignedPutStorage;

/// User-supplied factory: given `(bucket, object)`, return a short-lived
/// V4-signed HTTPS PUT URL.
pub type SignedUrlFactory = Arc<dyn Fn(&str, &str) -> Result<String> + Send + Sync>;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uploads_via_factory() {
        let storage = SignedGcsStorage::new(
            "bkt",
            "tenant-a/",
            Arc::new(|_, _| Ok(String::from("https://example/"))),
        );
        let err = storage
            .upload(&[1, 2, 3], Compression::None)
            .expect_err("example URL won't actually accept PUT");
        assert!(err.message.contains("gcs PUT"));
    }
}
