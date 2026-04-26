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

        // Build the record as a JSON object.
        let mut rec = serde_json::Map::new();
        rec.insert("logger".into(), json!("vgi_rpc.access"));
        rec.insert("method".into(), json!(info.method));
        rec.insert("method_type".into(), json!(info.method_type));
        rec.insert("server_id".into(), json!(info.server_id));
        rec.insert("server_version".into(), json!(self.server_version));
        rec.insert("request_id".into(), json!(info.request_id));
        rec.insert("status".into(), json!(status));
        rec.insert("authenticated".into(), json!(info.authenticated));
        rec.insert("principal".into(), json!(info.principal));
        rec.insert("auth_domain".into(), json!(info.auth_domain));
        rec.insert(
            "duration_ms".into(),
            json!((duration_ms * 100.0).round() / 100.0),
        );
        rec.insert("input_batches".into(), json!(stats.input_batches));
        rec.insert("output_batches".into(), json!(stats.output_batches));
        rec.insert("input_rows".into(), json!(stats.input_rows));
        rec.insert("output_rows".into(), json!(stats.output_rows));
        rec.insert("input_bytes".into(), json!(stats.input_bytes));
        rec.insert("output_bytes".into(), json!(stats.output_bytes));
        if let Some(err) = error {
            rec.insert("error_type".into(), json!(err.error_type));
            rec.insert("error_message".into(), json!(err.message));
        }
        // stream methods need a stream_id; use request_id (or a derived token)
        // when present. The hook has no built-in stream_id today; we reuse
        // request_id when it is set and fall back to the hook token.
        if info.method_type == "stream" {
            let sid = if info.request_id.is_empty() {
                format!("{token:x}")
            } else {
                info.request_id.clone()
            };
            rec.insert("stream_id".into(), json!(sid));
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
