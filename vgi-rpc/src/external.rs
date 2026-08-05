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

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::{Schema, SchemaRef};
use sha2::{Digest, Sha256};

use crate::errors::{Result, RpcError};
use crate::metadata::{LOCATION_FETCH_MS_KEY, LOCATION_KEY, LOCATION_SHA256_KEY};
use crate::wire::{bytes_to_hex, empty_batch, md_get, write_one_batch_as, Metadata, StreamReader};

thread_local! {
    /// Bytes uploaded to external storage during the call in flight.
    ///
    /// Externalised payloads never appear in the response body — only a
    /// pointer batch does — so they are invisible to any accounting done at
    /// the transport, and for egress they are usually the larger number by
    /// orders of magnitude. Incremented at the single upload choke point in
    /// [`maybe_externalize_batch`], so a new upload path cannot drift from
    /// the total; scoped and read by [`ExternalizedScope`].
    static EXTERNALIZED_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Per-call accounting scope for externalised uploads.
///
/// Reads the total on [`finish`](Self::finish) and restores whatever the
/// enclosing scope had accumulated, so a nested dispatch cannot swallow its
/// caller's count. Uploads run synchronously on the dispatch thread (the HTTP
/// path enters them via `block_in_place`), which is what makes a thread-local
/// the right carrier here — but it also means the scope must not straddle an
/// `.await`.
pub struct ExternalizedScope {
    outer: u64,
}

impl ExternalizedScope {
    /// Begin counting this call's uploads from zero.
    pub fn new() -> Self {
        let outer = EXTERNALIZED_BYTES.with(|c| c.replace(0));
        Self { outer }
    }

    /// Bytes uploaded within this scope; restores the enclosing total.
    pub fn finish(self) -> u64 {
        EXTERNALIZED_BYTES.with(|c| c.replace(self.outer))
    }
}

impl Default for ExternalizedScope {
    fn default() -> Self {
        Self::new()
    }
}

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

// ---------------------------------------------------------------------------
// Public `__upload_url__` wire contract
// ---------------------------------------------------------------------------
//
// An intermediary (proxy, gateway) that terminates or serves the upload-URL
// flow needs the method name and both schemas. They are published here — rather
// than duplicated as private literals in the server and client — so the contract
// has exactly one definition. Mirrors Python's `vgi_rpc.http` re-exports.

/// The RPC method name of the upload-URL flow (`POST /__upload_url__/init`).
pub const UPLOAD_URL_METHOD: &str = "__upload_url__";

/// Upper bound on the `count` an `__upload_url__` request may ask for. The
/// server clamps to `[1, MAX_UPLOAD_URL_COUNT]`.
pub const MAX_UPLOAD_URL_COUNT: i64 = 100;

/// Parameter schema of an `__upload_url__` request: a single `count` int64.
pub fn upload_url_params_schema() -> SchemaRef {
    use arrow_schema::{DataType, Field};
    Arc::new(Schema::new(vec![Field::new(
        "count",
        DataType::Int64,
        true,
    )]))
}

/// Response schema of an `__upload_url__` reply: one row per generated URL pair.
pub fn upload_url_response_schema() -> SchemaRef {
    use arrow_schema::{DataType, Field, TimeUnit};
    Arc::new(Schema::new(vec![
        Field::new("upload_url", DataType::Utf8, false),
        Field::new("download_url", DataType::Utf8, false),
        Field::new(
            "expires_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
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
/// Takes a URL (and the declared compression) and returns the still-encoded
/// payload bytes. `vgi-rpc` ships an HTTPS fetcher; tests plug in an
/// in-memory implementation.
///
/// `max_bytes` is a hard ceiling on the number of bytes the fetcher may
/// read from the remote — implementations **must** abort once it is
/// exceeded rather than buffering an unbounded response into memory. A
/// hostile or compromised storage URL would otherwise OOM the process
/// before decompression's own cap is ever reached.
pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &str, compression: Compression, max_bytes: usize) -> Result<Vec<u8>>;
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
    /// URL validator run on both the upload (post-signing) and fetch
    /// (pre-download) paths. Defaults to [`safe_https_validator`], which
    /// rejects non-`https` URLs and internal/non-routable hosts. Reject
    /// a URL by returning `Err`.
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

/// Helper: scheme-only HTTPS validator.
///
/// **Insufficient for untrusted input** — it accepts `https://localhost`,
/// `https://169.254.169.254` (cloud metadata), and any internal-network
/// host. Use it only when the set of external-location URLs is fully
/// trusted (e.g. URLs your own backend minted). For anything that can
/// carry a client-supplied location, use [`safe_https_validator`].
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

/// Helper: default-deny HTTPS validator with SSRF protection.
///
/// Requires the `https` scheme, then rejects the URL when its host is —
/// or resolves to — a loopback, private, link-local, unique-local,
/// carrier-grade-NAT, broadcast, documentation, or unspecified address.
/// This is the default for [`ExternalLocationConfig::new`] because the
/// unary HTTP path resolves a *client-supplied* `vgi_rpc.location`
/// server-side; without this a client could pivot the server into
/// fetching `https://169.254.169.254/...` or an internal service.
///
/// Note: a hostname is resolved here and again at fetch time, so a
/// DNS-rebinding attacker could still slip through the gap. Pair this
/// with a redirect-free, size-capped fetcher (the bundled `HttpFetcher`
/// is both) and, for high-assurance deployments, an egress firewall.
pub fn safe_https_validator() -> UrlValidator {
    Arc::new(|raw: &str| {
        let url = url::Url::parse(raw)
            .map_err(|e| RpcError::value_error(format!("invalid external location URL: {e}")))?;
        if url.scheme() != "https" {
            return Err(RpcError::value_error(
                "external location URL must be https://",
            ));
        }
        let host = url
            .host()
            .ok_or_else(|| RpcError::value_error("external location URL has no host"))?;
        match host {
            url::Host::Ipv4(ip) => reject_unsafe_ip(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => reject_unsafe_ip(IpAddr::V6(ip)),
            url::Host::Domain(name) => {
                let lname = name.to_ascii_lowercase();
                if lname == "localhost" || lname.ends_with(".localhost") {
                    return Err(RpcError::value_error(
                        "external location host is not publicly routable",
                    ));
                }
                let port = url.port_or_known_default().unwrap_or(443);
                let addrs = (name, port).to_socket_addrs().map_err(|e| {
                    RpcError::value_error(format!("external location host does not resolve: {e}"))
                })?;
                let mut saw_any = false;
                for sa in addrs {
                    saw_any = true;
                    reject_unsafe_ip(sa.ip())?;
                }
                if !saw_any {
                    return Err(RpcError::value_error(
                        "external location host does not resolve",
                    ));
                }
                Ok(())
            }
        }
    })
}

/// Reject an IP address that is not safe for the server to dial: any
/// loopback / private / link-local / unique-local / CGNAT / broadcast /
/// documentation / unspecified / multicast address.
fn reject_unsafe_ip(ip: IpAddr) -> Result<()> {
    let unsafe_addr = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // 100.64.0.0/10 — carrier-grade NAT.
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 — unique local.
                || (seg0 & 0xfe00) == 0xfc00
                // fe80::/10 — link local.
                || (seg0 & 0xffc0) == 0xfe80
                // IPv4-mapped (::ffff:0:0/96) — classify the embedded v4.
                || v6
                    .to_ipv4_mapped()
                    .map(|m| reject_unsafe_ip(IpAddr::V4(m)).is_err())
                    .unwrap_or(false)
        }
    };
    if unsafe_addr {
        return Err(RpcError::value_error(
            "external location host resolves to a non-routable / internal address",
        ));
    }
    Ok(())
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
            url_validator: safe_https_validator(),
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
    // External payloads carry the raw data only; the pointer batch on
    // the outside owns the metadata. Pass `None` to omit any
    // `custom_metadata` field on the wire.
    write_one_batch_as(batch, batch.schema().as_ref(), None)
}

/// Read back an IPC stream containing a single batch.
/// Fetch, decompress, and integrity-check an external-location pointer's
/// payload, returning the raw inner IPC stream bytes. The inner stream may
/// contain **multiple** batches (e.g. a peer that externalizes a whole
/// per-iteration output — logs followed by the data batch), so callers that
/// need log/exception handling should process the returned bytes as a full
/// response stream rather than assuming a single batch.
///
/// Returns `Ok(None)` when `metadata` carries no `vgi_rpc.location` pointer.
pub fn fetch_external_ipc_bytes(
    metadata: &Metadata,
    cfg: &ExternalLocationConfig,
) -> Result<Option<Vec<u8>>> {
    let Some(url) = md_get(metadata, LOCATION_KEY) else {
        return Ok(None);
    };
    (cfg.url_validator)(url)?;
    let compressed = cfg
        .fetcher
        .fetch(url, cfg.compression, cfg.max_decompressed_bytes)?;
    let ipc_bytes = decompress(&compressed, cfg.compression, cfg.max_decompressed_bytes)?;
    if let Some(expected) = md_get(metadata, LOCATION_SHA256_KEY) {
        let actual = sha256_hex(&ipc_bytes);
        if expected != actual.as_str() {
            return Err(RpcError::runtime_error(format!(
                "external location SHA-256 mismatch (expected {expected}, got {actual})"
            )));
        }
    }
    Ok(Some(ipc_bytes))
}

pub fn deserialize_single_batch(ipc_bytes: &[u8]) -> Result<RecordBatch> {
    Ok(deserialize_single_batch_with_metadata(ipc_bytes)?.0)
}

/// Like [`deserialize_single_batch`] but also returns the batch's per-message
/// custom metadata — some peers carry keys (e.g. the stream-state token) on the
/// externalized inner batch rather than the outer pointer.
pub fn deserialize_single_batch_with_metadata(ipc_bytes: &[u8]) -> Result<(RecordBatch, Metadata)> {
    let mut r = StreamReader::new(ipc_bytes)?;
    r.read_next()?
        .ok_or_else(|| RpcError::runtime_error("external batch stream is empty"))
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

/// A batch that has been serialized (and compressed) for external storage
/// but **not yet uploaded**.
///
/// Splitting the prepare step out of [`maybe_externalize_batch`] is what
/// makes an operator cap (`max_externalized_response_bytes`) enforceable
/// *before* the bytes leave the process: the exact payload is already in
/// hand, so a response that would violate the cap can be refused without
/// paying for the storage round trip. Nothing observable happens until
/// [`upload_prepared`] is called, so dropping a `PreparedExternal` is a
/// clean abort.
pub struct PreparedExternal {
    /// Raw (pre-compression) IPC bytes — what the cap is measured in.
    raw_len: usize,
    /// The bytes that will actually be uploaded.
    payload: Vec<u8>,
    /// SHA-256 of the **raw** IPC bytes.
    sha: String,
    /// Zero-row pointer batch matching the source batch's schema.
    ptr: RecordBatch,
    /// Caller metadata with any stale location keys already stripped.
    md: Metadata,
}

impl PreparedExternal {
    /// Size of this payload as `max_externalized_response_bytes` measures
    /// it: the **raw** IPC bytes, captured *before* external compression.
    ///
    /// Pre-compression on purpose, and identical whether or not
    /// [`ExternalLocationConfig::with_compression`] is in effect. Python's
    /// `maybe_externalize_batch` returns exactly this quantity for cap
    /// accounting (`raw_size = original_bytes ...`, taken before
    /// `_codec_compress`), and TypeScript compares an uncompressed batch
    /// size too. Charging the compressed upload instead would make one
    /// configuration mean different things on different ports, and would
    /// silently loosen the cap by the compression ratio — which for the
    /// repetitive payloads that provoke externalisation is enormous.
    ///
    /// The access-log counter (`DispatchInfo::externalized_bytes`) stays on
    /// the compressed number: that one answers "what left the machine",
    /// this one answers "what did the operator allow".
    ///
    /// One deliberate deviation from the reference: Python's *pre-flight*
    /// predicts with `batch.get_total_buffer_size()` and then charges the
    /// raw IPC count, so its two numbers are only approximately equal.
    /// Rust has already serialized by this point (the threshold gate needs
    /// the IPC length anyway), so the pre-flight and the charge are the
    /// same number and cannot disagree. Same units, same
    /// "uncompressed size of the data" semantics, no estimate error.
    pub fn cap_bytes(&self) -> usize {
        self.raw_len
    }
}

/// Serialize `batch` for external storage without uploading it.
///
/// Returns `None` under exactly the conditions [`maybe_externalize_batch`]
/// declines to externalize (empty batch, or IPC bytes below the configured
/// threshold), so a caller that pre-flights with this and then uploads sees
/// the same decision it would have gotten from the one-shot helper.
///
/// `declared_schema` is the schema of the **enclosing** IPC stream — the one
/// the peer already read and will validate the fetched payload against. It
/// is not always `batch.schema()`: a worker may emit a batch that differs
/// from its stream's declared schema in nullability, dictionary encoding or
/// schema metadata, and inline delivery hides that completely (see
/// [`crate::wire::write_one_batch_as`]). Declaring the batch's own schema on
/// the uploaded payload is what turns such a difference into a client-side
/// `Schema mismatch` the moment externalisation is switched on.
pub fn prepare_externalize_batch(
    batch: &RecordBatch,
    declared_schema: &Schema,
    inline_metadata: Option<&Metadata>,
    cfg: &ExternalLocationConfig,
) -> Result<Option<PreparedExternal>> {
    if batch.num_rows() == 0 {
        return Ok(None);
    }
    // Build pointer metadata, merging the caller-supplied metadata first.
    // The location keys are added by `upload_prepared`, which is the only
    // place that knows the URL.
    let mut md: Metadata = inline_metadata.cloned().unwrap_or_default();
    md.remove(LOCATION_KEY);
    md.remove(LOCATION_SHA256_KEY);
    md.remove(LOCATION_FETCH_MS_KEY);

    // The caller's metadata is written on BOTH sides of the indirection:
    // inside the uploaded stream and on the pointer batch. Ports disagree
    // about which one carries per-batch keys — Python's resolver returns the
    // *inner* batch's metadata and discards the pointer's, while this crate's
    // resolver merges both. Writing it twice is what makes a key that must
    // survive externalisation (the exchange cursor
    // `vgi_rpc.stream_state#b64`, `vgi_batch_index`, partition values)
    // survive for either client. The duplicate costs a few bytes and the
    // values are identical, so a merge in any order agrees.
    let ipc_bytes = write_one_batch_as(
        batch,
        declared_schema,
        if md.is_empty() { None } else { Some(&md) },
    )?;
    if ipc_bytes.len() < cfg.threshold_bytes {
        return Ok(None);
    }
    let raw_len = ipc_bytes.len();
    let sha = sha256_hex(&ipc_bytes);
    let payload = compress(&ipc_bytes, cfg.compression)?;

    // Pointer batch: zero-row but matching the enclosing stream's schema,
    // matching Python's `make_external_location_batch` shape so the
    // client's IPC reader sees a consistent column count — and so the
    // schema it validates the fetched payload against is the one the
    // payload declares.
    let ptr = empty_batch(declared_schema)?;
    Ok(Some(PreparedExternal {
        raw_len,
        payload,
        sha,
        ptr,
        md,
    }))
}

/// Upload a [`PreparedExternal`] and return the pointer batch + metadata.
///
/// This is the single upload choke point: the externalised-bytes counter
/// read by [`ExternalizedScope`] is incremented here, so a new call site
/// cannot make the total drift from reality.
pub fn upload_prepared(
    prepared: PreparedExternal,
    cfg: &ExternalLocationConfig,
) -> Result<(RecordBatch, Metadata)> {
    let PreparedExternal {
        payload,
        sha,
        ptr,
        mut md,
        ..
    } = prepared;
    EXTERNALIZED_BYTES.with(|c| c.set(c.get() + payload.len() as u64));
    let upload = cfg.storage.upload(&payload, cfg.compression)?;
    // Validator runs over the final URL.
    (cfg.url_validator)(&upload.url)?;
    md.insert(LOCATION_KEY.to_string(), upload.url);
    md.insert(LOCATION_SHA256_KEY.to_string(), sha);
    Ok((ptr, md))
}

/// Decide whether to externalize `batch`; return the pointer (zero-row)
/// batch + pointer metadata when yes, else `None`. The original batch is
/// left untouched so the caller can emit it inline.
///
/// `inline_metadata` — optional custom metadata the caller wants to
/// attach alongside the location keys (merged; location keys win).
///
/// Callers that must enforce a byte cap should use
/// [`prepare_externalize_batch`] + [`upload_prepared`] instead, which lets
/// them see the payload size before the upload happens.
///
/// `declared_schema` is the enclosing IPC stream's schema; see
/// [`prepare_externalize_batch`].
pub fn maybe_externalize_batch(
    batch: &RecordBatch,
    declared_schema: &Schema,
    inline_metadata: Option<&Metadata>,
    cfg: &ExternalLocationConfig,
) -> Result<Option<(RecordBatch, Metadata)>> {
    match prepare_externalize_batch(batch, declared_schema, inline_metadata, cfg)? {
        None => Ok(None),
        Some(prepared) => upload_prepared(prepared, cfg).map(Some),
    }
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
    // Cap the fetched (still-encoded) payload at `max_decompressed_bytes`:
    // any well-formed compressed body is smaller than its decompressed
    // form, so this is a safe ceiling that also bounds the uncompressed
    // case. `decompress` enforces the post-decompression cap on top.
    let compressed = cfg
        .fetcher
        .fetch(url, cfg.compression, cfg.max_decompressed_bytes)?;
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
    let (resolved, inner_md) = deserialize_single_batch_with_metadata(&ipc_bytes)?;
    let fetch_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Start from the outer pointer's non-location keys, then overlay the inner
    // (externalized) batch's metadata. Implementations differ on where they
    // carry per-batch keys like `vgi_rpc.stream_state#b64`: the Rust server
    // stamps them on the outer pointer, the Python server on the inner payload
    // batch. Merging both (inner wins) recovers the token either way and
    // matches Python's resolver, which uses the inner batch's metadata.
    let mut user_md: Metadata = metadata
        .iter()
        .filter(|(k, _)| {
            *k != LOCATION_KEY && *k != LOCATION_SHA256_KEY && *k != LOCATION_FETCH_MS_KEY
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, v) in inner_md {
        if k != LOCATION_KEY && k != LOCATION_SHA256_KEY && k != LOCATION_FETCH_MS_KEY {
            user_md.insert(k, v);
        }
    }
    user_md.insert(
        LOCATION_FETCH_MS_KEY.to_string(),
        format!("{:.2}", fetch_ms),
    );
    Ok((resolved, user_md))
}

// ---------------------------------------------------------------------------
// In-memory test backend
// ---------------------------------------------------------------------------
//
// Gated behind the `test-utils` feature so it doesn't show up on
// crates.io / docs.rs for normal users. Internal tests + the
// `external_integration` integration test enable the feature
// transitively via the workspace.

/// In-memory storage backend + fetcher pair; used by tests and CI.
/// Thread-safe, no I/O. **Not for production use.**
#[cfg(any(test, feature = "test-utils"))]
pub struct InMemoryStorage {
    map: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    next_id: std::sync::atomic::AtomicU64,
    base_url: String,
}

#[cfg(any(test, feature = "test-utils"))]
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

#[cfg(any(test, feature = "test-utils"))]
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

#[cfg(any(test, feature = "test-utils"))]
impl Fetcher for InMemoryStorage {
    fn fetch(&self, url: &str, _compression: Compression, max_bytes: usize) -> Result<Vec<u8>> {
        let bytes = self
            .map
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| RpcError::runtime_error(format!("inmem fetch miss: {url}")))?;
        if bytes.len() > max_bytes {
            return Err(RpcError::runtime_error(format!(
                "inmem fetch payload {} bytes exceeds max_bytes={max_bytes}",
                bytes.len()
            )));
        }
        Ok(bytes)
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
        let out = maybe_externalize_batch(&batch, batch.schema().as_ref(), None, &cfg).unwrap();
        assert!(out.is_none());
        assert!(storage.is_empty());
    }

    #[test]
    fn large_batch_externalizes_and_round_trips() {
        let storage = InMemoryStorage::new();
        let cfg = cfg_with(storage.clone(), 1024);
        let batch = big_batch(50_000);

        let (ptr, md) = maybe_externalize_batch(&batch, batch.schema().as_ref(), None, &cfg)
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
        let (ptr, md) = maybe_externalize_batch(&batch, batch.schema().as_ref(), None, &cfg)
            .unwrap()
            .unwrap();
        let (resolved, _) = resolve_external_location(&ptr, &md, &cfg).unwrap();
        assert_eq!(resolved.num_rows(), batch.num_rows());
    }

    // An externalised payload is a standalone IPC stream and declares its own
    // schema, whereas an inline batch rides a stream whose schema was declared
    // once, up front. A batch differing from that declared schema only
    // cosmetically — here, field nullability — is invisible inline (the writer
    // never reconciles the two) and becomes a hard `Schema mismatch` at a peer
    // that validates the fetched payload the moment externalisation is turned
    // on. The declared schema must therefore travel with the payload.
    #[test]
    fn externalized_payload_declares_the_enclosing_stream_schema() {
        let storage = InMemoryStorage::new();
        let cfg = cfg_with(storage.clone(), 1024);
        // What the stream promised: `value` is nullable.
        let declared = Schema::new(vec![Field::new("value", DataType::Int64, true)]);
        // What the worker emitted: same data, non-nullable field.
        let batch = big_batch(50_000);
        assert!(!batch.schema().field(0).is_nullable());

        let (ptr, md) = maybe_externalize_batch(&batch, &declared, None, &cfg)
            .unwrap()
            .unwrap();
        // The pointer the peer decodes carries the declared schema...
        assert!(ptr.schema().field(0).is_nullable());
        // ...and so does the payload behind it, so a validating peer sees
        // the two agree.
        let raw = cfg
            .fetcher
            .fetch(
                md_get(&md, LOCATION_KEY).unwrap(),
                cfg.compression,
                cfg.max_decompressed_bytes,
            )
            .unwrap();
        let mut reader = StreamReader::new(raw.as_slice()).unwrap();
        let (fetched, _) = reader.read_next().unwrap().unwrap();
        assert_eq!(fetched.schema().as_ref(), &declared);
        assert_eq!(fetched.num_rows(), batch.num_rows());
    }

    // Java's uploader cannot carry dictionaries, so its port has to keep
    // dictionary-encoded batches inline. Rust's writer emits the dictionary
    // messages and the reader consumes them transparently, so no such
    // carve-out is needed here — pinned so a future change to either side
    // cannot quietly reintroduce the constraint.
    #[test]
    fn dictionary_encoded_batch_round_trips_externally() {
        use arrow_array::types::Int32Type;
        use arrow_array::{Array, DictionaryArray};

        let storage = InMemoryStorage::new();
        let cfg = cfg_with(storage.clone(), 1024);
        let values: Vec<&str> = (0..20_000)
            .map(|i| ["alpha", "beta", "gamma"][i % 3])
            .collect();
        let dict: DictionaryArray<Int32Type> = values.into_iter().collect();
        let schema = Arc::new(Schema::new(vec![Field::new(
            "label",
            dict.data_type().clone(),
            false,
        )]));
        let col: Ar<dyn arrow_array::Array> = Arc::new(dict);
        let batch = RecordBatch::try_new(schema.clone(), vec![col]).unwrap();

        let (ptr, md) = maybe_externalize_batch(&batch, schema.as_ref(), None, &cfg)
            .unwrap()
            .unwrap();
        assert_eq!(storage.len(), 1);
        let (resolved, _) = resolve_external_location(&ptr, &md, &cfg).unwrap();
        assert_eq!(resolved.num_rows(), batch.num_rows());
        assert_eq!(resolved.column(0).as_ref(), batch.column(0).as_ref());
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
    fn safe_https_validator_blocks_ssrf_targets() {
        let v = safe_https_validator();
        // Non-https.
        assert!(v("http://example.com/x").is_err());
        // IP-literal internal / non-routable targets.
        assert!(v("https://169.254.169.254/latest/meta-data/").is_err());
        assert!(v("https://127.0.0.1/").is_err());
        assert!(v("https://10.0.0.1/").is_err());
        assert!(v("https://192.168.1.1/").is_err());
        assert!(v("https://[::1]/").is_err());
        assert!(v("https://0.0.0.0/").is_err());
        // Hostname forms of loopback.
        assert!(v("https://localhost/x").is_err());
        assert!(v("https://api.localhost/x").is_err());
        // A public IP literal is allowed.
        assert!(v("https://1.1.1.1/x").is_ok());
    }

    #[test]
    fn sha_mismatch_is_rejected() {
        let storage = InMemoryStorage::new();
        let cfg = cfg_with(storage.clone(), 1024);
        let batch = big_batch(10_000);
        let (ptr, mut md) = maybe_externalize_batch(&batch, batch.schema().as_ref(), None, &cfg)
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
