//! `ExternalStorage` adapter for the Python `vgi_rpc.conformance.fake_storage`
//! HTTP service used by the cross-language external-location conformance tests.
//!
//! Wire contract (from `fake_storage.py`):
//! - `POST {base}/alloc` (optional JSON `{"content_encoding": "zstd"}`)
//!   → `{"object_url": "{base}/blob/{id}"}`
//! - `PUT  {object_url}`  upload raw bytes (echo `Content-Encoding`).
//! - `GET  {object_url}`  download raw bytes.
//! - Protocol 3.4 object API: every `/alloc` response carries `object_id`;
//!   `"purpose": "object"` marks a `put_object` (counted `object_puts`);
//!   `GET /objects/{id}` is `get` (counted `object_gets`, 404 when absent).

use vgi_rpc::external::{
    object_missing_error, Compression, ExternalStorage, ObjectStore, UploadResult, UploadUrl,
    UploadUrlProvider,
};
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
    fn object_store(&self) -> Option<&dyn ObjectStore> {
        Some(self)
    }

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
    fn generate_upload_url(&self, size: u64, sha256_hex: &str) -> Result<UploadUrl> {
        let alloc_url = format!("{}/alloc", self.base_url);
        // A sized allocation: the fake then verifies the PUT like S3/R2
        // (length, `x-amz-checksum-sha256`) and returns the header to send.
        let alloc_body = serde_json::json!({
            "size": size,
            "sha256_b64": vgi_rpc::external::sha256_hex_to_b64(sha256_hex)?,
        })
        .to_string();
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
        let headers = alloc_resp
            .get("upload_headers")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);
        let expires_at_micros = now_us + 60 * 60 * 1_000_000; // +1h
        let object_id = alloc_resp
            .get("object_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(UploadUrl {
            upload_url,
            download_url,
            expires_at_micros,
            headers,
            object_id,
            argument_ref: Vec::new(),
        })
    }
}

impl ObjectStore for FakeStorage {
    fn put_object(&self, data: &[u8]) -> Result<String> {
        use sha2::Digest as _;
        let sha_hex: String = sha2::Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let body = serde_json::json!({
            "size": data.len(),
            "sha256_b64": vgi_rpc::external::sha256_hex_to_b64(&sha_hex)?,
            "purpose": "object",
        })
        .to_string();
        let alloc: serde_json::Value = self
            .client
            .post(format!("{}/alloc", self.base_url))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json())
            .map_err(|e| RpcError::runtime_error(format!("fake-storage alloc failed: {e}")))?;
        let object_id = alloc
            .get("object_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::runtime_error("alloc response missing object_id"))?
            .to_string();
        let upload_url = alloc
            .get("upload_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::runtime_error("alloc response missing upload_url"))?;
        let mut req = self
            .client
            .put(upload_url)
            .body(data.to_vec())
            .header("content-type", "application/octet-stream");
        if let Some(headers) = alloc.get("upload_headers").and_then(|v| v.as_object()) {
            for (k, v) in headers {
                if let Some(v) = v.as_str() {
                    req = req.header(k.as_str(), v);
                }
            }
        }
        req.send()
            .and_then(|r| r.error_for_status())
            .map_err(|e| RpcError::runtime_error(format!("fake-storage PUT failed: {e}")))?;
        Ok(object_id)
    }

    fn get(&self, object_id: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(format!("{}/objects/{object_id}", self.base_url))
            .send()
            .map_err(|e| RpcError::runtime_error(format!("fake-storage GET failed: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(object_missing_error("fake storage object is gone"));
        }
        let data = resp
            .error_for_status()
            .and_then(|r| r.bytes())
            .map_err(|e| RpcError::runtime_error(format!("fake-storage GET failed: {e}")))?;
        if data.len() > max_bytes {
            return Err(RpcError::runtime_error(format!(
                "object is {} bytes, over max_fetch_bytes ({max_bytes})",
                data.len()
            )));
        }
        Ok(data.to_vec())
    }
}
