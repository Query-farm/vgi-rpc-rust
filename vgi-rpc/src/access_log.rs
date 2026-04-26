//! Structured access logging as a [`DispatchHook`].
//!
//! Emits one JSON record per RPC call via a writer the caller supplies.
//! The schema matches the Python canonical (`vgi_rpc.access_log_conformance`
//! validator) so logs are portable across implementations.

use std::io::Write;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::json;

use crate::errors::RpcError;
use crate::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};

/// Where the hook sends formatted JSON lines.
enum Sink {
    /// Synchronous: dispatch thread holds the sink mutex during the write.
    Sync(Arc<Mutex<dyn Write + Send>>),
    /// Asynchronous: dispatch thread queues the line into a bounded
    /// channel; a background writer thread drains it.
    Async {
        tx: SyncSender<Vec<u8>>,
        dropped: Arc<std::sync::atomic::AtomicU64>,
    },
}

/// A `DispatchHook` that writes one JSON line per call to an arbitrary
/// `Write` sink. Entries carry the `vgi_rpc.access` logger name so the
/// Python validator's filter (`.logger == "vgi_rpc.access"`) matches.
///
/// Two modes:
/// - [`AccessLogHook::new`] / [`to_stderr`] write synchronously on the
///   dispatch thread (acceptable for stderr or in-memory test sinks).
/// - [`AccessLogHook::buffered`] queues into a bounded mpsc channel and
///   drains on a background thread; on overflow it drops the entry and
///   bumps a counter rather than blocking dispatch.
pub struct AccessLogHook {
    sink: Sink,
    server_version: String,
    /// Start instants keyed by request_id for duration tracking. For server
    /// loads where request_id is always empty, a simple monotonically
    /// increasing counter token is used instead.
    starts: Mutex<std::collections::HashMap<HookToken, Instant>>,
    next_token: std::sync::atomic::AtomicU64,
}

impl AccessLogHook {
    /// Create an access log hook that writes synchronously to `sink`.
    /// Suitable for stderr or in-memory sinks; for production file I/O
    /// prefer [`AccessLogHook::buffered`] to keep dispatch threads off
    /// the disk path.
    pub fn new<W: Write + Send + 'static>(sink: W, server_version: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            sink: Sink::Sync(Arc::new(Mutex::new(sink))),
            server_version: server_version.into(),
            starts: Mutex::new(std::collections::HashMap::new()),
            next_token: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Create a hook that writes asynchronously: the dispatch thread
    /// pushes a formatted line into a bounded channel of `capacity`
    /// entries and a background thread drains it into `sink`. When the
    /// channel is full, the entry is *dropped* (counted by
    /// [`dropped_count`](Self::dropped_count)) instead of blocking
    /// dispatch — this is the right tradeoff for high-throughput servers
    /// where occasional log loss is preferable to head-of-line blocking
    /// behind a stalled disk.
    ///
    /// The writer thread exits when the hook is dropped (sender closes).
    pub fn buffered<W: Write + Send + 'static>(
        sink: W,
        server_version: impl Into<String>,
        capacity: usize,
    ) -> Arc<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(capacity.max(1));
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut sink = sink;
        std::thread::Builder::new()
            .name("vgi-rpc-access-log".into())
            .spawn(move || {
                while let Ok(line) = rx.recv() {
                    if sink.write_all(&line).is_err() {
                        return;
                    }
                    if sink.write_all(b"\n").is_err() {
                        return;
                    }
                    let _ = sink.flush();
                }
            })
            .expect("spawn access-log writer thread");
        Arc::new(Self {
            sink: Sink::Async { tx, dropped },
            server_version: server_version.into(),
            starts: Mutex::new(std::collections::HashMap::new()),
            next_token: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Convenience: write access logs to stderr synchronously
    /// (one JSON line per entry).
    pub fn to_stderr(server_version: impl Into<String>) -> Arc<Self> {
        Self::new(std::io::stderr(), server_version)
    }

    /// Number of entries dropped because the async channel was full.
    /// Always zero for synchronous hooks.
    pub fn dropped_count(&self) -> u64 {
        match &self.sink {
            Sink::Async { dropped, .. } => dropped.load(std::sync::atomic::Ordering::Relaxed),
            Sink::Sync(_) => 0,
        }
    }
}

impl DispatchHook for AccessLogHook {
    fn on_dispatch_start(&self, _info: &DispatchInfo) -> HookToken {
        let token = self
            .next_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.starts.lock().unwrap().insert(token, Instant::now());
        token
    }

    fn on_dispatch_end(
        &self,
        token: HookToken,
        info: &DispatchInfo,
        error: Option<&RpcError>,
        stats: &CallStatistics,
    ) {
        let start = self.starts.lock().unwrap().remove(&token);
        let duration_ms = start
            .map(|t| t.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        let status = if error.is_some() { "error" } else { "ok" };

        // Build the record as a JSON object — schema-aligned with
        // docs/access-log-spec.md in the Python reference repo.
        let mut rec = serde_json::Map::new();
        rec.insert("timestamp".into(), json!(rfc3339_utc_millis()));
        rec.insert("level".into(), json!("INFO"));
        rec.insert("logger".into(), json!("vgi_rpc.access"));
        rec.insert(
            "message".into(),
            json!(format!("{}.{} {}", info.protocol, info.method, status)),
        );
        rec.insert("server_id".into(), json!(info.server_id));
        rec.insert("protocol".into(), json!(info.protocol));
        rec.insert("protocol_hash".into(), json!(info.protocol_hash));
        rec.insert("method".into(), json!(info.method));
        rec.insert("method_type".into(), json!(info.method_type));
        rec.insert("principal".into(), json!(info.principal));
        rec.insert("auth_domain".into(), json!(info.auth_domain));
        rec.insert("authenticated".into(), json!(info.authenticated));
        rec.insert("remote_addr".into(), json!(info.remote_addr));
        rec.insert(
            "duration_ms".into(),
            json!((duration_ms * 100.0).round() / 100.0),
        );
        rec.insert("status".into(), json!(status));
        rec.insert(
            "error_type".into(),
            json!(error.map(|e| e.error_type.clone()).unwrap_or_default()),
        );

        if let Some(err) = error {
            rec.insert("error_message".into(), json!(err.message));
        }
        if !self.server_version.is_empty() {
            rec.insert("server_version".into(), json!(self.server_version));
        }
        if !info.protocol_version.is_empty() {
            rec.insert("protocol_version".into(), json!(info.protocol_version));
        }
        if !info.request_id.is_empty() {
            rec.insert("request_id".into(), json!(info.request_id));
        }
        if info.http_status > 0 {
            rec.insert("http_status".into(), json!(info.http_status));
        }
        if !info.request_data.is_empty() {
            rec.insert(
                "request_data".into(),
                json!(base64_encode(&info.request_data)),
            );
        }
        if info.method_type == "stream" {
            let sid = if info.stream_id.is_empty() {
                random_stream_id()
            } else {
                info.stream_id.clone()
            };
            rec.insert("stream_id".into(), json!(sid));
        }
        if info.cancelled {
            rec.insert("cancelled".into(), json!(true));
        }
        if stats.input_batches
            + stats.output_batches
            + stats.input_rows
            + stats.output_rows
            + stats.input_bytes
            + stats.output_bytes
            != 0
        {
            rec.insert("input_batches".into(), json!(stats.input_batches));
            rec.insert("output_batches".into(), json!(stats.output_batches));
            rec.insert("input_rows".into(), json!(stats.input_rows));
            rec.insert("output_rows".into(), json!(stats.output_rows));
            rec.insert("input_bytes".into(), json!(stats.input_bytes));
            rec.insert("output_bytes".into(), json!(stats.output_bytes));
        }

        let line = serde_json::Value::Object(rec).to_string();
        match &self.sink {
            Sink::Sync(m) => {
                let mut w = m.lock().unwrap();
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
            Sink::Async { tx, dropped } => {
                if let Err(e) = tx.try_send(line.into_bytes()) {
                    match e {
                        TrySendError::Full(_) => {
                            dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        TrySendError::Disconnected(_) => {
                            // Writer thread exited; treat as dropped silently.
                            dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }
}

/// Format the current wall-clock time as RFC 3339 UTC with millisecond
/// precision, matching the access-log spec's `timestamp` regex.
pub fn rfc3339_utc_millis() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_ms = dur.as_millis() as i64;
    let secs = total_ms / 1000;
    let millis = (total_ms % 1000) as u32;

    // Civil time conversion using Howard Hinnant's algorithm.
    let z = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let h = sod / 3600;
    let mi = (sod / 60) % 60;
    let s = sod % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, m, d, h, mi, s, millis
    )
}

/// Standard base64 (RFC 4648, padded). Inlined here so the access-log module
/// stays usable without the optional `base64` crate dependency.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in chunks.by_ref() {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Mint a 32-character lowercase hex stream_id. Use this at the start of a
/// stream call and reuse the same value across init and continuations.
pub fn random_stream_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 128 bits drawn from time + a per-process atomic counter. Not
    // cryptographic — adequate for log correlation.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let lo = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let hi = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    format!("{:016x}{:016x}", hi ^ pid, lo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn emits_json_line_per_call() {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        struct BufSink(Arc<Mutex<Vec<u8>>>);
        impl Write for BufSink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let hook: Arc<dyn DispatchHook> = AccessLogHook::new(BufSink(buf.clone()), "1.2.3");

        let info = DispatchInfo {
            method: "echo_string".into(),
            method_type: "unary",
            server_id: "srv".into(),
            request_id: "req-1".into(),
            transport_metadata: Arc::new(Default::default()),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
            protocol: "Test".into(),
            remote_addr: String::new(),
            http_status: 0,
            request_data: Vec::new(),
            stream_id: String::new(),
            cancelled: false,
        };
        let tok = hook.on_dispatch_start(&info);
        hook.on_dispatch_end(tok, &info, None, &CallStatistics::default());

        let line = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let rec: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(rec["logger"], "vgi_rpc.access");
        assert_eq!(rec["method"], "echo_string");
        assert_eq!(rec["server_version"], "1.2.3");
        assert_eq!(rec["status"], "ok");
        assert_eq!(rec["authenticated"], false);
    }

    #[test]
    fn buffered_writes_via_background_thread() {
        // Sink that records every write; cloned across threads via Arc<Mutex>.
        struct ChanSink(std::sync::mpsc::Sender<Vec<u8>>);
        impl Write for ChanSink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                let _ = self.0.send(b.to_vec());
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let hook: Arc<dyn DispatchHook> = AccessLogHook::buffered(ChanSink(tx), "1.2.3", 128);

        let info = DispatchInfo {
            method: "echo_string".into(),
            method_type: "unary",
            server_id: "srv".into(),
            request_id: "req-1".into(),
            transport_metadata: Arc::new(Default::default()),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
            protocol: "Test".into(),
            remote_addr: String::new(),
            http_status: 0,
            request_data: Vec::new(),
            stream_id: String::new(),
            cancelled: false,
        };
        let tok = hook.on_dispatch_start(&info);
        hook.on_dispatch_end(tok, &info, None, &CallStatistics::default());

        // Drain the receiver until we see the JSON body. The writer thread
        // will write the line and a trailing newline as separate writes.
        let mut acc = Vec::new();
        while let Ok(chunk) = rx.recv_timeout(std::time::Duration::from_millis(500)) {
            acc.extend(chunk);
            if acc.contains(&b'\n') {
                break;
            }
        }
        let line = String::from_utf8(acc).unwrap();
        assert!(line.contains("\"method\":\"echo_string\""), "got: {line}");
        assert!(line.contains("\"server_version\":\"1.2.3\""), "got: {line}");
    }

    #[test]
    fn buffered_drops_when_channel_full_instead_of_blocking() {
        // Sink whose writes block forever — the writer thread will park
        // on the very first entry, leaving the channel saturated.
        struct ParkingSink;
        impl Write for ParkingSink {
            fn write(&mut self, _b: &[u8]) -> std::io::Result<usize> {
                std::thread::park();
                Ok(0)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let hook = AccessLogHook::buffered(ParkingSink, "1.2.3", 1);
        let dyn_hook: Arc<dyn DispatchHook> = hook.clone();
        let info = DispatchInfo {
            method: "m".into(),
            method_type: "unary",
            server_id: "s".into(),
            request_id: String::new(),
            transport_metadata: Arc::new(Default::default()),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
            protocol: "Test".into(),
            remote_addr: String::new(),
            http_status: 0,
            request_data: Vec::new(),
            stream_id: String::new(),
            cancelled: false,
        };
        // Push enough entries that the bounded channel overflows.
        for _ in 0..50 {
            let tok = dyn_hook.on_dispatch_start(&info);
            dyn_hook.on_dispatch_end(tok, &info, None, &CallStatistics::default());
        }
        // Some entries must have been dropped — this is the property under
        // test (dispatch never blocked even though the sink is wedged).
        assert!(
            hook.dropped_count() > 0,
            "expected drops on saturated buffered sink, got {}",
            hook.dropped_count()
        );
    }

    #[test]
    fn error_entries_carry_error_message() {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        struct BufSink(Arc<Mutex<Vec<u8>>>);
        impl Write for BufSink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let hook: Arc<dyn DispatchHook> = AccessLogHook::new(BufSink(buf.clone()), "1.2.3");
        let info = DispatchInfo {
            method: "raise_value_error".into(),
            method_type: "unary",
            server_id: "srv".into(),
            request_id: String::new(),
            transport_metadata: Arc::new(Default::default()),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
            protocol: "Test".into(),
            remote_addr: String::new(),
            http_status: 0,
            request_data: Vec::new(),
            stream_id: String::new(),
            cancelled: false,
        };
        let tok = hook.on_dispatch_start(&info);
        let err = RpcError::value_error("boom");
        hook.on_dispatch_end(tok, &info, Some(&err), &CallStatistics::default());
        let line = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let rec: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(rec["status"], "error");
        assert_eq!(rec["error_type"], "ValueError");
        assert_eq!(rec["error_message"], "boom");
    }
}
