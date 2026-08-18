//! `ExternalStorage` adapter for the Python `vgi_rpc.conformance.fake_storage`
//! HTTP service used by the cross-language external-location conformance tests.
//!
//! Wire contract (from `fake_storage.py`):
//! - `POST {base}/alloc` (optional JSON `{"content_encoding": "zstd"}`)
//!   → `{"object_url": "{base}/blob/{id}"}`
//! - `PUT  {object_url}`  upload raw bytes (echo `Content-Encoding`).
//! - `GET  {object_url}`  download raw bytes.

use vgi_rpc::external::{Compression, ExternalStorage, UploadResult, UploadUrl, UploadUrlProvider};
use vgi_rpc::{Result, RpcError};

pub struct FakeStorage {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl FakeStorage {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: vgi_rpc_s3::default_blocking_client(),
        }
    }
}

impl ExternalStorage for FakeStorage {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult> {
        let alloc_url = format!("{}/alloc", self.base_url);
        let alloc_body = match compression {
            Compression::None => "{}",
            Compression::Zstd(_) => r#"{"content_encoding":"zstd"}"#,
        };
        let alloc_resp: serde_json::Value = self
            .client
            .post(&alloc_url)
            .header("content-type", "application/json")
            .body(alloc_body)
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json())
            .map_err(|e| RpcError::runtime_error(format!("fake-storage alloc failed: {e}")))?;
        let legacy_url = alloc_resp
            .get("object_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::runtime_error("alloc response missing object_url"))?;
        let upload_url = alloc_resp
            .get("upload_url")
            .and_then(|v| v.as_str())
            .unwrap_or(legacy_url)
            .to_string();
        let download_url = alloc_resp
            .get("download_url")
            .and_then(|v| v.as_str())
            .unwrap_or(legacy_url)
            .to_string();

        let mut req = self
            .client
            .put(&upload_url)
            .body(ipc_bytes.to_vec())
            .header("content-type", "application/vnd.apache.arrow.stream");
        if matches!(compression, Compression::Zstd(_)) {
            req = req.header("content-encoding", "zstd");
        }
        req.send()
            .and_then(|r| r.error_for_status())
            .map_err(|e| RpcError::runtime_error(format!("fake-storage PUT failed: {e}")))?;

        Ok(UploadResult {
            url: download_url,
            sha256: String::new(),
        })
    }
}

impl UploadUrlProvider for FakeStorage {
    fn generate_upload_url(&self) -> Result<UploadUrl> {
        let alloc_url = format!("{}/alloc", self.base_url);
        let alloc_resp: serde_json::Value = self
            .client
            .post(&alloc_url)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json())
            .map_err(|e| RpcError::runtime_error(format!("fake-storage alloc failed: {e}")))?;
        let legacy_url = alloc_resp
            .get("object_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::runtime_error("alloc response missing object_url"))?
            .to_string();
        let upload_url = alloc_resp
            .get("upload_url")
            .and_then(|v| v.as_str())
            .unwrap_or(&legacy_url)
            .to_string();
        let download_url = alloc_resp
            .get("download_url")
            .and_then(|v| v.as_str())
            .unwrap_or(&legacy_url)
            .to_string();
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);
        let expires_at_micros = now_us + 60 * 60 * 1_000_000; // +1h
        Ok(UploadUrl {
            upload_url,
            download_url,
            expires_at_micros,
        })
    }
}
