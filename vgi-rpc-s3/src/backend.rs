//! Storage backend selection from the environment (direct-storage contract
//! v1, §1): `VGI_STORAGE_BACKEND` = `vendor` | `s3` | `gcs` | `none`.
//!
//! Unset, the backend is `vendor` when `VGI_BLOB_VENDOR_URL` is set, else
//! `s3` when `VGI_STORAGE_S3_BUCKET` is set, else `gcs` when
//! `VGI_STORAGE_GCS_BUCKET` is set, else `none` (everything inline). More than
//! one of those set without an explicit `VGI_STORAGE_BACKEND` is refused.
//!
//! This port has no GCS signer, so `gcs` is refused at startup; `s3` needs the
//! crate's `aws` feature.

use std::sync::Arc;

use vgi_rpc::external::{ExternalLocationConfig, UploadUrlProvider};
use vgi_rpc::{Result, RpcError};

/// Selects the backend explicitly.
pub const ENV_BACKEND: &str = "VGI_STORAGE_BACKEND";
/// The GCS bucket (contract §5).
pub const ENV_GCS_BUCKET: &str = "VGI_STORAGE_GCS_BUCKET";

/// A storage backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// The Query.Farm blob vendor (`VGI_BLOB_VENDOR_URL`).
    Vendor,
    /// The operator's S3 (or S3-compatible) bucket.
    S3,
    /// The operator's GCS bucket.
    Gcs,
    /// No external storage: everything stays inline.
    None,
}

impl Backend {
    /// The `VGI_STORAGE_BACKEND` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Vendor => "vendor",
            Backend::S3 => "s3",
            Backend::Gcs => "gcs",
            Backend::None => "none",
        }
    }
}

fn set(lookup: &dyn Fn(&str) -> Option<String>, name: &str) -> bool {
    lookup(name).is_some_and(|v| !v.trim().is_empty())
}

/// The backend the environment selects.
///
/// # Errors
///
/// An unknown `VGI_STORAGE_BACKEND`, or more than one backend configured
/// without it.
pub fn select_backend(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Backend> {
    if let Some(raw) = lookup(ENV_BACKEND).map(|v| v.trim().to_ascii_lowercase()) {
        if !raw.is_empty() {
            return match raw.as_str() {
                "vendor" => Ok(Backend::Vendor),
                "s3" => Ok(Backend::S3),
                "gcs" => Ok(Backend::Gcs),
                "none" => Ok(Backend::None),
                other => Err(RpcError::value_error(format!(
                    "{ENV_BACKEND} must be vendor, s3, gcs or none, got {other:?}"
                ))),
            };
        }
    }
    let candidates: Vec<(&str, Backend)> = [
        (crate::vendor::ENV_URL, Backend::Vendor),
        ("VGI_STORAGE_S3_BUCKET", Backend::S3),
        (ENV_GCS_BUCKET, Backend::Gcs),
    ]
    .into_iter()
    .filter(|(name, _)| set(lookup, name))
    .collect();
    match candidates.as_slice() {
        [] => Ok(Backend::None),
        [(_, b)] => Ok(*b),
        many => Err(RpcError::value_error(format!(
            "storage configuration conflict: {} are all set; set {ENV_BACKEND} to choose one",
            many.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// What a server needs from the selected backend.
pub struct StorageWiring {
    /// The selected backend.
    pub backend: Backend,
    /// Result externalization and inbound pointer fetching.
    pub config: ExternalLocationConfig,
    /// Vends client upload URLs; `None` when the backend issues no upload
    /// grants (`VGI_STORAGE_S3_CHECKSUM=none`), in which case the server must
    /// advertise neither upload-URL support nor argument references.
    pub upload_url_provider: Option<Arc<dyn UploadUrlProvider>>,
    /// The vendor storage, for the vendor backend.
    pub vendor: Option<Arc<crate::vendor::VendorStorage>>,
    /// The S3 storage, for the s3 backend.
    #[cfg(feature = "aws")]
    pub s3: Option<Arc<crate::s3::S3Storage>>,
}

/// Build the selected backend from the process environment; `None` for the
/// `none` backend.
///
/// # Errors
///
/// A conflict or malformed variable, `gcs` (no GCS signer in this port), `s3`
/// without the `aws` feature, or (with `VGI_STORAGE_S3_VERIFY=1`) a failed
/// bucket check.
pub fn storage_from_env() -> Result<Option<StorageWiring>> {
    storage_from_lookup(&|name| std::env::var(name).ok())
}

/// [`storage_from_env`] over an explicit variable lookup.
///
/// # Errors
///
/// As [`storage_from_env`].
pub fn storage_from_lookup(
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<StorageWiring>> {
    match select_backend(lookup)? {
        Backend::None => Ok(None),
        Backend::Vendor => {
            let Some((config, storage)) = crate::vendor::external_config_from_lookup(lookup)?
            else {
                return Err(RpcError::value_error(format!(
                    "{ENV_BACKEND}=vendor needs {}",
                    crate::vendor::ENV_URL
                )));
            };
            Ok(Some(StorageWiring {
                backend: Backend::Vendor,
                config,
                upload_url_provider: Some(storage.clone()),
                vendor: Some(storage),
                #[cfg(feature = "aws")]
                s3: None,
            }))
        }
        Backend::Gcs => Err(RpcError::value_error(format!(
            "{ENV_BACKEND}=gcs: the Rust SDK has no GCS backend yet (it cannot sign GCS V4 URLs); \
             use vendor or s3 (GCS's S3-interoperable XML API with HMAC keys works as s3 with \
             VGI_STORAGE_S3_ENDPOINT=https://storage.googleapis.com and \
             VGI_STORAGE_S3_CHECKSUM=none)"
        ))),
        #[cfg(not(feature = "aws"))]
        Backend::S3 => Err(RpcError::value_error(format!(
            "{ENV_BACKEND}=s3 needs vgi-rpc-s3's `aws` feature"
        ))),
        #[cfg(feature = "aws")]
        Backend::S3 => {
            let settings = crate::s3::S3Settings::from_lookup(lookup)?;
            let storage = Arc::new(crate::s3::S3Storage::new(settings));
            if storage.settings().verify_at_startup {
                storage.verify()?;
            }
            let config = crate::vendor::external_config_with(
                lookup,
                storage.clone(),
                storage.url_validator()?,
            )?;
            let upload_url_provider: Option<Arc<dyn UploadUrlProvider>> =
                if storage.issues_upload_grants() {
                    Some(storage.clone())
                } else {
                    tracing::warn!(
                        "VGI_STORAGE_S3_CHECKSUM=none: no upload grants or argument references \
                         (large inputs stay inline); results and objects are still stored in s3"
                    );
                    None
                };
            tracing::info!(
                "storage backend s3: bucket {:?}, prefix {:?}, region {:?}, path-style {}",
                storage.settings().bucket,
                storage.settings().prefix,
                storage.settings().region,
                storage.settings().force_path_style
            );
            Ok(Some(StorageWiring {
                backend: Backend::S3,
                config,
                upload_url_provider,
                vendor: None,
                s3: Some(storage),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn selection() {
        assert_eq!(select_backend(&lookup(&[])).unwrap(), Backend::None);
        assert_eq!(
            select_backend(&lookup(&[("VGI_BLOB_VENDOR_URL", "https://v")])).unwrap(),
            Backend::Vendor
        );
        assert_eq!(
            select_backend(&lookup(&[("VGI_STORAGE_S3_BUCKET", "b")])).unwrap(),
            Backend::S3
        );
        assert_eq!(
            select_backend(&lookup(&[("VGI_STORAGE_GCS_BUCKET", "b")])).unwrap(),
            Backend::Gcs
        );
        let err = select_backend(&lookup(&[
            ("VGI_BLOB_VENDOR_URL", "https://v"),
            ("VGI_STORAGE_S3_BUCKET", "b"),
        ]))
        .unwrap_err();
        assert!(
            err.message
                .contains("VGI_BLOB_VENDOR_URL, VGI_STORAGE_S3_BUCKET"),
            "{}",
            err.message
        );
        assert_eq!(
            select_backend(&lookup(&[
                ("VGI_BLOB_VENDOR_URL", "https://v"),
                ("VGI_STORAGE_S3_BUCKET", "b"),
                ("VGI_STORAGE_BACKEND", "S3"),
            ]))
            .unwrap(),
            Backend::S3
        );
        assert_eq!(
            select_backend(&lookup(&[
                ("VGI_STORAGE_S3_BUCKET", "b"),
                ("VGI_STORAGE_BACKEND", "none")
            ]))
            .unwrap(),
            Backend::None
        );
        assert!(select_backend(&lookup(&[("VGI_STORAGE_BACKEND", "r2")])).is_err());
        assert!(
            storage_from_lookup(&lookup(&[("VGI_STORAGE_GCS_BUCKET", "b")]))
                .err()
                .unwrap()
                .message
                .contains("no GCS backend")
        );
        assert!(storage_from_lookup(&lookup(&[("VGI_STORAGE_BACKEND", "vendor")])).is_err());
    }
}
