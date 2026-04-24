//! S3-backed `ExternalStorage` for vgi-rpc.
//!
//! Rather than pulling `aws-sdk-s3` (and its ~1-minute transitive compile
//! surface) into the core, this crate ships a pluggable pre-signed URL
//! factory. The caller produces a short-lived PUT URL for each upload
//! (typically via `aws-sdk-s3::Client::presigned_put_object`); we do the
//! blocking HTTPS transfer via `reqwest::blocking`.
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
//!         // Your AWS SDK call here — return a short-lived PUT URL.
//!         Ok(format!("https://{bucket}.s3.amazonaws.com/{key}?X-Amz-Signature=..."))
//!     }),
//! );
//! let fetcher = HttpFetcher::new();
//! let cfg = ExternalLocationConfig::new(Arc::new(storage), Arc::new(fetcher))
//!     .with_compression(Compression::Zstd(3));
//! ```

use std::sync::Arc;

use vgi_rpc::external::{Compression, ExternalStorage, Fetcher, UploadResult};
use vgi_rpc::{Result, RpcError};

/// User-supplied factory: given `(bucket, key)`, return a short-lived
/// pre-signed HTTPS PUT URL.
pub type PresignUrlFactory = Arc<dyn Fn(&str, &str) -> Result<String> + Send + Sync>;

/// `ExternalStorage` implementation that PUTs objects via a pre-signed
/// URL the caller supplies.
pub struct PresignedS3Storage {
    bucket: String,
    prefix: String,
    factory: PresignUrlFactory,
    client: reqwest::blocking::Client,
}

impl PresignedS3Storage {
    pub fn new(
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        factory: PresignUrlFactory,
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
}

impl ExternalStorage for PresignedS3Storage {
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
            .map_err(|e| RpcError::runtime_error(format!("s3 PUT failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(RpcError::runtime_error(format!(
                "s3 PUT returned {} for {url}",
                resp.status()
            )));
        }
        // sha256 is computed by ExternalLocationConfig's caller; return an
        // empty string here as the field is populated upstream.
        Ok(UploadResult {
            url,
            sha256: String::new(),
        })
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
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, url: &str, _compression: Compression) -> Result<Vec<u8>> {
        let resp = self
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
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| RpcError::runtime_error(format!("external GET body: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_uses_prefix() {
        let storage = PresignedS3Storage::new(
            "bkt",
            "tenant-a/vgi/",
            Arc::new(|_, _| Ok(String::from("https://example/"))),
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
}
