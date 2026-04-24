//! Structured access logging as a [`DispatchHook`].
//!
//! Emits one JSON record per RPC call via a writer the caller supplies.
//! The schema matches the Python canonical (`vgi_rpc.access_log_conformance`
//! validator) so logs are portable across implementations.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::json;

use crate::errors::RpcError;
use crate::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};

/// A `DispatchHook` that writes one JSON line per call to an arbitrary
/// `Write` sink. Entries carry the `vgi_rpc.access` logger name so the
/// Python validator's filter (`.logger == "vgi_rpc.access"`) matches.
pub struct AccessLogHook {
    sink: Arc<Mutex<dyn Write + Send>>,
    server_version: String,
    /// Start instants keyed by request_id for duration tracking. For server
    /// loads where request_id is always empty, a simple monotonically
    /// increasing counter token is used instead.
    starts: Mutex<std::collections::HashMap<HookToken, Instant>>,
    next_token: std::sync::atomic::AtomicU64,
}

impl AccessLogHook {
    /// Create an access log hook that writes to `sink`. The sink is
    /// wrapped in a mutex so the hook is `Sync`.
    pub fn new<W: Write + Send + 'static>(sink: W, server_version: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            sink: Arc::new(Mutex::new(sink)),
            server_version: server_version.into(),
            starts: Mutex::new(std::collections::HashMap::new()),
            next_token: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Convenience: write access logs to stderr (one JSON line per entry).
    pub fn to_stderr(server_version: impl Into<String>) -> Arc<Self> {
        Self::new(std::io::stderr(), server_version)
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
        rec.insert("duration_ms".into(), json!((duration_ms * 100.0).round() / 100.0));
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
        let mut w = self.sink.lock().unwrap();
        let _ = writeln!(w, "{line}");
        let _ = w.flush();
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
        let hook: Arc<dyn DispatchHook> =
            AccessLogHook::new(BufSink(buf.clone()), "1.2.3");

        let info = DispatchInfo {
            method: "echo_string".into(),
            method_type: "unary",
            server_id: "srv".into(),
            request_id: "req-1".into(),
            transport_metadata: Arc::new(Vec::new()),
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
        let hook: Arc<dyn DispatchHook> =
            AccessLogHook::new(BufSink(buf.clone()), "1.2.3");
        let info = DispatchInfo {
            method: "raise_value_error".into(),
            method_type: "unary",
            server_id: "srv".into(),
            request_id: String::new(),
            transport_metadata: Arc::new(Vec::new()),
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
