//! External-location batches.
//!
//! Large result / stream batches can be uploaded to an external object
//! store (S3 / GCS / in-memory) and replaced on the wire with a
//! zero-row "pointer" batch carrying only metadata:
//!
//!   `vgi_rpc.location`         → URL (HTTPS by default).
//!   `vgi_rpc.location.sha256`  → lowercase hex SHA-256 of the raw IPC bytes.
//!   `vgi_rpc.location.source`  → debug annotation (filled when resolved).
//!
//! The remote payload is an Arrow IPC stream containing one batch with the
//! original data. When compression is set, that stream is zstd-encoded
//! before upload — the hash is over the raw (uncompressed) IPC bytes so
//! integrity checks remain stable across compression changes.
//!
//! The crate stays storage-agnostic: users register an [`ExternalStorage`]
//! implementation and a [`Fetcher`] for resolution. The companion
//! `vgi-rpc-s3` and `vgi-rpc-gcs` crates ship ready-made backends.

use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::{Schema, SchemaRef};
use sha2::{Digest, Sha256};

use crate::errors::{Result, RpcError};
use crate::metadata::{LOCATION_FETCH_MS_KEY, LOCATION_KEY, LOCATION_SHA256_KEY};
use crate::wire::{bytes_to_hex, empty_batch, md_get, write_one_batch, Metadata, StreamReader};
use std::collections::HashMap;

/// Optional body compression for externalized payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    /// zstd at the given level (1..=22).
    Zstd(i32),
}

/// Result of uploading a payload to external storage.
#[derive(Clone, Debug)]
pub struct UploadResult {
    /// Caller-fetchable URL for the payload (typically a pre-signed URL).
    pub url: String,
    /// SHA-256 of the **raw** IPC bytes, hex-lowercased.
    pub sha256: String,
}

/// Pluggable storage backend. Implementations upload Arrow IPC bytes and
/// return a fetchable URL.
///
/// Kept synchronous to preserve compatibility with the current pipe/unix
/// dispatch loop; async-only backends should offload via a blocking
/// thread pool.
pub trait ExternalStorage: Send + Sync {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult>;
}

/// Pre-signed URL pair for client-side data upload.
///
/// `expires_at` is a Unix-epoch microseconds timestamp (UTC). Mirrors
/// `vgi_rpc.external.UploadUrl`.
#[derive(Clone, Debug)]
pub struct UploadUrl {
    pub upload_url: String,
    pub download_url: String,
    /// Expiration time as microseconds since the Unix epoch (UTC).
    pub expires_at_micros: i64,
}

/// Generates pre-signed upload URL pairs for client-vended uploads.
///
/// Mirror of Python `vgi_rpc.external.UploadUrlProvider`. Implementations
/// must be thread-safe — `generate_upload_url()` may be called concurrently
/// from different request handlers.
pub trait UploadUrlProvider: Send + Sync {
    fn generate_upload_url(&self) -> Result<UploadUrl>;
}

/// Callback verifying an external location URL. Called on both the
/// upload path (post-signing) and the fetch path (pre-download). Return
/// `Err` to reject the URL with a typed [`RpcError`].
pub type UrlValidator = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Pluggable fetcher used to resolve pointer batches back into data.
///
/// Takes a URL (and the declared compression) and returns the decompressed
/// IPC bytes. `vgi-rpc` ships an HTTPS fetcher; tests plug in an
/// in-memory implementation.
pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &str, compression: Compression) -> Result<Vec<u8>>;
}

/// Externalization configuration.
#[derive(Clone)]
pub struct ExternalLocationConfig {
    /// Payload size in bytes at which a batch is eligible for
    /// externalization. Smaller batches stay inline. Default 1 MiB.
    pub threshold_bytes: usize,
    /// Compression applied to the IPC bytes before upload. Default
    /// `Compression::None`.
    pub compression: Compression,
    /// Upload backend. Required when externalization is enabled.
    pub storage: Arc<dyn ExternalStorage>,
    /// Resolver used on the read side. Required when resolving inbound
    /// pointer batches.
    pub fetcher: Arc<dyn Fetcher>,
    /// URL validator; default enforces `https://` unless
    /// [`https_only`](Self::https_only) is set to `false`. Reject the
    /// URL by returning `Err`.
    pub url_validator: UrlValidator,
    /// Hard ceiling on the post-decompression size of a fetched
    /// payload. Zstd frames carry their decompressed size in the
    /// header and `zstd::decode_all` would otherwise trust it
    /// eagerly — a small malicious payload claiming gigabytes of
    /// output would OOM the client. Default 1 GiB. Set to `usize::MAX`
    /// to disable.
    pub max_decompressed_bytes: usize,
}

impl std::fmt::Debug for ExternalLocationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalLocationConfig")
            .field("threshold_bytes", &self.threshold_bytes)
            .field("compression", &self.compression)
            .finish_non_exhaustive()
    }
}

/// Helper: default HTTPS-only URL validator.
pub fn https_only_validator() -> UrlValidator {
    Arc::new(|url: &str| {
        if url.starts_with("https://") {
            Ok(())
        } else {
            Err(RpcError::value_error(format!(
                "external location URL must be https:// ({url})"
            )))
        }
    })
}

/// Helper: accept any URL (useful for local tests + MinIO).
pub fn any_url_validator() -> UrlValidator {
    Arc::new(|_: &str| Ok(()))
}

impl ExternalLocationConfig {
    pub fn new(storage: Arc<dyn ExternalStorage>, fetcher: Arc<dyn Fetcher>) -> Self {
        Self {
            threshold_bytes: 1024 * 1024,
            compression: Compression::None,
            storage,
            fetcher,
            url_validator: https_only_validator(),
            max_decompressed_bytes: 1024 * 1024 * 1024,
        }
    }

    pub fn with_threshold_bytes(mut self, n: usize) -> Self {
        self.threshold_bytes = n;
        self
    }

    pub fn with_compression(mut self, c: Compression) -> Self {
        self.compression = c;
        self
    }

    pub fn with_url_validator(mut self, v: UrlValidator) -> Self {
        self.url_validator = v;
        self
    }

    /// Override the hard ceiling on post-decompression payload size.
    /// Pass `usize::MAX` to disable. Default is 1 GiB.
    pub fn with_max_decompressed_bytes(mut self, n: usize) -> Self {
        self.max_decompressed_bytes = n;
        self
    }
}

// ---------------------------------------------------------------------------
// Serialize a batch as an IPC stream with no custom metadata.
// ---------------------------------------------------------------------------

/// Serialize one record batch as a complete IPC stream (schema + batch + EOS).
pub fn serialize_batch_to_ipc(batch: &RecordBatch) -> Result<Vec<u8>> {
    // Strip any custom metadata: external payloads carry the raw data
    // only; the pointer batch on the outside owns the metadata.
    let stripped = batch.clone().with_custom_metadata(HashMap::new());
    write_one_batch(&stripped)
}

/// Read back an IPC stream containing a single batch.
pub fn deserialize_single_batch(ipc_bytes: &[u8]) -> Result<RecordBatch> {
    let mut r = StreamReader::new(ipc_bytes)?;
    let batch = r
        .read_next()?
        .ok_or_else(|| RpcError::runtime_error("external batch stream is empty"))?;
    Ok(batch)
}

fn sha256_hex(bytes: &[u8]) -> String {
    bytes_to_hex(&Sha256::digest(bytes))
}

fn compress(ipc_bytes: &[u8], compression: Compression) -> Result<Vec<u8>> {
    match compression {
        Compression::None => Ok(ipc_bytes.to_vec()),
        Compression::Zstd(level) => {
            // Use the bulk API and explicitly include the decompressed
            // size in the frame header. Python's `zstandard.ZstdDecompressor`
            // requires `Content-Size` to be present when decompressing
            // a single frame in one shot.
            let mut enc = zstd::bulk::Compressor::new(level)
                .map_err(|e| RpcError::runtime_error(format!("zstd encoder: {e}")))?;
            enc.set_parameter(zstd::stream::raw::CParameter::ContentSizeFlag(true))
                .map_err(|e| RpcError::runtime_error(format!("zstd contentsize: {e}")))?;
            enc.compress(ipc_bytes)
                .map_err(|e| RpcError::runtime_error(format!("zstd encode: {e}")))
        }
    }
}

fn decompress(bytes: &[u8], compression: Compression, max_size: usize) -> Result<Vec<u8>> {
    match compression {
        Compression::None => {
            if bytes.len() > max_size {
                return Err(RpcError::runtime_error(format!(
                    "external payload {} bytes exceeds max_decompressed_bytes={max_size}",
                    bytes.len()
                )));
            }
            Ok(bytes.to_vec())
        }
        // Stream-decode and stop if we exceed the cap. Avoids trusting
        // the zstd frame header's declared decompressed size (which
        // `decode_all` would otherwise allocate eagerly), blocking a
        // remote OOM via a tiny payload claiming gigabytes of output.
        Compression::Zstd(_) => {
            use std::io::Read;
            let mut decoder = zstd::Decoder::new(bytes)
                .map_err(|e| RpcError::runtime_error(format!("zstd decode: {e}")))?;
            let mut out = Vec::new();
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = decoder
                    .read(&mut buf)
                    .map_err(|e| RpcError::runtime_error(format!("zstd decode: {e}")))?;
                if n == 0 {
                    break;
                }
                if out.len() + n > max_size {
                    return Err(RpcError::runtime_error(format!(
                        "zstd decode: output exceeds max_decompressed_bytes={max_size}"
                    )));
                }
                out.extend_from_slice(&buf[..n]);
            }
            Ok(out)
        }
    }
}

// ---------------------------------------------------------------------------
// Server-side: externalize large batches
// ---------------------------------------------------------------------------

/// Pointer-batch schema — a zero-field, zero-row batch. The Python
/// canonical externalizes into an empty-schema batch with location
/// metadata; we match that so the on-wire bytes are identical.
pub fn pointer_schema() -> SchemaRef {
    Arc::new(Schema::empty())
}

/// Decide whether to externalize `batch`; return the pointer (zero-row)
/// batch + pointer metadata when yes, else `None`. The original batch is
/// left untouched so the caller can emit it inline.
///
/// `inline_metadata` — optional custom metadata the caller wants to
/// attach alongside the location keys (merged; location keys win).
pub fn maybe_externalize_batch(
    batch: &RecordBatch,
    inline_metadata: Option<&Metadata>,
    cfg: &ExternalLocationConfig,
) -> Result<Option<(RecordBatch, Metadata)>> {
    if batch.num_rows() == 0 {
        return Ok(None);
    }
    let ipc_bytes = serialize_batch_to_ipc(batch)?;
    if ipc_bytes.len() < cfg.threshold_bytes {
        return Ok(None);
    }
    let sha = sha256_hex(&ipc_bytes);
    let payload = compress(&ipc_bytes, cfg.compression)?;
    let upload = cfg.storage.upload(&payload, cfg.compression)?;
    // Validator runs over the final URL.
    (cfg.url_validator)(&upload.url)?;

    // Build pointer metadata, merging the caller-supplied metadata first.
    let mut md: Metadata = inline_metadata.cloned().unwrap_or_default();
    md.remove(LOCATION_KEY);
    md.remove(LOCATION_SHA256_KEY);
    md.remove(LOCATION_FETCH_MS_KEY);
    md.insert(LOCATION_KEY.to_string(), upload.url);
    md.insert(LOCATION_SHA256_KEY.to_string(), sha);

    // Pointer batch: zero-row but matching the input batch's schema,
    // matching Python's `make_external_location_batch` shape so the
    // client's IPC reader sees a consistent column count.
    let ptr = empty_batch(batch.schema().as_ref())?;
    Ok(Some((ptr, md)))
}

// ---------------------------------------------------------------------------
// Client-side: resolve pointer batches
// ---------------------------------------------------------------------------

/// Resolve a pointer batch (zero-row batch with `vgi_rpc.location`
/// metadata) back into the original record batch. Non-pointer batches
/// are returned untouched.
///
/// Returns `(resolved_batch, user_metadata)` where the location keys
/// have been stripped from the metadata visible to the caller. A
/// `vgi_rpc.location.fetch_ms` claim is appended so callers / access
/// logs can observe the fetch latency.
pub fn resolve_external_location(
    batch: &RecordBatch,
    metadata: &Metadata,
    cfg: &ExternalLocationConfig,
) -> Result<(RecordBatch, Metadata)> {
    let Some(url) = md_get(metadata, LOCATION_KEY) else {
        return Ok((batch.clone(), metadata.clone()));
    };
    (cfg.url_validator)(url)?;

    let start = std::time::Instant::now();
    let compressed = cfg.fetcher.fetch(url, cfg.compression)?;
    let ipc_bytes = decompress(&compressed, cfg.compression, cfg.max_decompressed_bytes)?;

    // Integrity check.
    if let Some(expected) = md_get(metadata, LOCATION_SHA256_KEY) {
        let actual = sha256_hex(&ipc_bytes);
        if expected != actual.as_str() {
            return Err(RpcError::runtime_error(format!(
                "external location SHA-256 mismatch (expected {expected}, got {actual})"
            )));
        }
    }
    let resolved = deserialize_single_batch(&ipc_bytes)?;
    let fetch_ms = start.elapsed().as_secs_f64() * 1000.0;

    let mut user_md: Metadata = metadata
        .iter()
        .filter(|(k, _)| {
            *k != LOCATION_KEY && *k != LOCATION_SHA256_KEY && *k != LOCATION_FETCH_MS_KEY
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    user_md.insert(
        LOCATION_FETCH_MS_KEY.to_string(),
        format!("{:.2}", fetch_ms),
    );
    Ok((resolved, user_md))
}

// ---------------------------------------------------------------------------
// In-memory test backend
// ---------------------------------------------------------------------------

/// In-memory storage backend + fetcher pair; used by tests and CI.
/// Thread-safe, no I/O.
pub struct InMemoryStorage {
    map: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    next_id: std::sync::atomic::AtomicU64,
    base_url: String,
}

impl InMemoryStorage {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            map: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
            base_url: "https://inmem.test/".to_string(),
        })
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ExternalStorage for InMemoryStorage {
    fn upload(&self, ipc_bytes: &[u8], _compression: Compression) -> Result<UploadResult> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let url = format!("{}{:016x}", self.base_url, id);
        let sha = sha256_hex(
            // Storage receives the already-compressed bytes; the sha recorded
            // in the pointer metadata tracks the RAW ipc bytes so the
            // caller of upload() is responsible for that value — we only
            // store, not hash, here. Return a placeholder hash (caller
            // replaces it from maybe_externalize_batch).
            ipc_bytes,
        );
        self.map
            .lock()
            .unwrap()
            .insert(url.clone(), ipc_bytes.to_vec());
        Ok(UploadResult { url, sha256: sha })
    }
}

impl Fetcher for InMemoryStorage {
    fn fetch(&self, url: &str, _compression: Compression) -> Result<Vec<u8>> {
        self.map
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| RpcError::runtime_error(format!("inmem fetch miss: {url}")))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc as Ar;

    use arrow_array::{Int64Array, RecordBatch};
    use arrow_schema::{DataType, Field, Schema};

    use super::*;

    fn big_batch(rows: usize) -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int64,
            false,
        )]));
        let col: Ar<dyn arrow_array::Array> =
            Arc::new(Int64Array::from((0..rows as i64).collect::<Vec<_>>()));
        RecordBatch::try_new(schema, vec![col]).unwrap()
    }

    fn cfg_with(storage: Arc<InMemoryStorage>, threshold: usize) -> ExternalLocationConfig {
        let s: Arc<dyn ExternalStorage> = storage.clone();
        let f: Arc<dyn Fetcher> = storage;
        ExternalLocationConfig::new(s, f)
            .with_threshold_bytes(threshold)
            .with_url_validator(any_url_validator())
    }

    #[test]
    fn small_batch_stays_inline() {
        let storage = InMemoryStorage::new();
        let cfg = cfg_with(storage.clone(), 1024 * 1024);
        let batch = big_batch(10);
        let out = maybe_externalize_batch(&batch, None, &cfg).unwrap();
        assert!(out.is_none());
        assert!(storage.is_empty());
    }

    #[test]
    fn large_batch_externalizes_and_round_trips() {
        let storage = InMemoryStorage::new();
        let cfg = cfg_with(storage.clone(), 1024);
        let batch = big_batch(50_000);

        let (ptr, md) = maybe_externalize_batch(&batch, None, &cfg)
            .unwrap()
            .unwrap();
        assert_eq!(ptr.num_rows(), 0);
        // Pointer batch carries the original schema (zero-row); cross-language
        // clients expect the column count to match the result schema.
        assert_eq!(ptr.schema().fields().len(), batch.schema().fields().len());
        assert!(md_get(&md, LOCATION_KEY).unwrap().starts_with("https://"));
        assert_eq!(storage.len(), 1);

        let (resolved, user_md) = resolve_external_location(&ptr, &md, &cfg).unwrap();
        assert_eq!(resolved.num_rows(), batch.num_rows());
        assert!(md_get(&user_md, LOCATION_KEY).is_none());
        assert!(md_get(&user_md, LOCATION_FETCH_MS_KEY).is_some());
    }

    #[test]
    fn zstd_compression_round_trip() {
        let storage = InMemoryStorage::new();
        let cfg = cfg_with(storage.clone(), 1024).with_compression(Compression::Zstd(3));
        let batch = big_batch(20_000);
        let (ptr, md) = maybe_externalize_batch(&batch, None, &cfg)
            .unwrap()
            .unwrap();
        let (resolved, _) = resolve_external_location(&ptr, &md, &cfg).unwrap();
        assert_eq!(resolved.num_rows(), batch.num_rows());
    }

    #[test]
    fn https_only_validator_rejects_plaintext() {
        let storage = InMemoryStorage::new();
        let s: Arc<dyn ExternalStorage> = storage.clone();
        let f: Arc<dyn Fetcher> = storage;
        let cfg = ExternalLocationConfig::new(s, f).with_threshold_bytes(0);
        // In-memory URL is https, so build a forged metadata entry.
        let batch = big_batch(1);
        let mut bogus_md = Metadata::new();
        bogus_md.insert("vgi_rpc.location".into(), "http://not-secure/x".into());
        let err = resolve_external_location(&batch, &bogus_md, &cfg).unwrap_err();
        assert!(err.message.contains("https://"));
    }

    #[test]
    fn sha_mismatch_is_rejected() {
        let storage = InMemoryStorage::new();
        let cfg = cfg_with(storage.clone(), 1024);
        let batch = big_batch(10_000);
        let (ptr, mut md) = maybe_externalize_batch(&batch, None, &cfg)
            .unwrap()
            .unwrap();
        // Corrupt the recorded hash.
        if let Some(v) = md.get_mut(LOCATION_SHA256_KEY) {
            *v = "deadbeef".into();
        }
        let err = resolve_external_location(&ptr, &md, &cfg).unwrap_err();
        assert!(err.message.contains("SHA-256 mismatch"));
    }
}
