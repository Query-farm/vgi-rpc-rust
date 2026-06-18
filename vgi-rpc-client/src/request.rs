//! Request-side metadata construction.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use vgi_rpc::metadata::{
    PROTOCOL_VERSION_KEY, REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::wire::Metadata;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a 16-hex-char request id, mirroring Python's `uuid4().hex[:16]`
/// in shape (not in randomness guarantees). Unique within a process run.
pub fn generate_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix the timestamp and counter so concurrent calls stay distinct.
    let mixed = nanos.rotate_left(17) ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    format!("{mixed:016x}")
}

/// Build the request batch metadata: method, mandatory request version,
/// request id, optional protocol version, plus any caller-supplied extras.
pub fn build_request_metadata(
    method: &str,
    request_id: &str,
    protocol_version: Option<&str>,
    extra: Option<&Metadata>,
) -> Metadata {
    let mut md = Metadata::new();
    if let Some(e) = extra {
        md.extend(e.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    md.insert(RPC_METHOD_KEY.to_string(), method.to_string());
    md.insert(REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string());
    md.insert(REQUEST_ID_KEY.to_string(), request_id.to_string());
    if let Some(pv) = protocol_version.filter(|s| !s.is_empty()) {
        md.insert(PROTOCOL_VERSION_KEY.to_string(), pv.to_string());
    }
    md
}
