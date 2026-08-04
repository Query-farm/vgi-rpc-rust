//! Trace correlation on access-log records.
//!
//! `request_id` only joins records within one service; `trace_id` / `span_id`
//! are what join a record to the surrounding distributed trace.
//!
//! Deliberately the **only** test in this binary, and a single test function.
//! The provider is process-global (it has to be — it reads whatever span is
//! current, which no per-hook wiring can know), so a sibling test running
//! concurrently would see whichever provider happened to be installed and turn
//! every assertion here into a coin flip.

use std::io::Write;
use std::sync::{Arc, Mutex};

use vgi_rpc::access_log::{clear_trace_context_provider, set_trace_context_provider};
use vgi_rpc::{AccessLogHook, CallStatistics, DispatchHook, DispatchInfo};

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

/// Emit one record and return it parsed.
fn emit_one() -> serde_json::Value {
    let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let hook: Arc<dyn DispatchHook> = AccessLogHook::new(BufSink(buf.clone()), "v");
    let info = DispatchInfo {
        method: "echo_string".into(),
        method_type: "unary",
        server_id: "srv".into(),
        protocol: "Test".into(),
        transport_metadata: Arc::new(Default::default()),
        ..Default::default()
    };
    let token = hook.on_dispatch_start(&info);
    hook.on_dispatch_end(token, &info, None, &CallStatistics::default());
    let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    serde_json::from_str(text.trim()).unwrap()
}

const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const SPAN: &str = "00f067aa0ba902b7";

#[test]
fn trace_ids_are_emitted_together_and_only_when_valid() {
    // No provider: a framework that ships no tracer emits no correlation.
    clear_trace_context_provider();
    let rec = emit_one();
    assert!(rec.get("trace_id").is_none());
    assert!(rec.get("span_id").is_none());

    // A valid current span correlates the record with the trace.
    set_trace_context_provider(Arc::new(|| Some((TRACE.to_string(), SPAN.to_string()))));
    let rec = emit_one();
    assert_eq!(rec["trace_id"], TRACE);
    assert_eq!(rec["span_id"], SPAN);

    // A dashed UUID would fail the schema's `^[0-9a-f]{32}$` for every record
    // in the file, so it is dropped rather than emitted.
    set_trace_context_provider(Arc::new(|| {
        Some((
            "4bf92f35-77b3-4da6-a3ce-929d0e0e4736".to_string(),
            SPAN.to_string(),
        ))
    }));
    let rec = emit_one();
    assert!(rec.get("trace_id").is_none());
    assert!(rec.get("span_id").is_none());

    // OTel's all-zero id means "no valid span", not "this identifier".
    set_trace_context_provider(Arc::new(|| Some(("0".repeat(32), SPAN.to_string()))));
    let rec = emit_one();
    assert!(rec.get("trace_id").is_none());

    // One id without the other correlates with nothing: both or neither.
    set_trace_context_provider(Arc::new(|| Some((TRACE.to_string(), String::new()))));
    let rec = emit_one();
    assert!(rec.get("trace_id").is_none());
    assert!(rec.get("span_id").is_none());

    // An observability failure must not surface as a request failure — the
    // record is still written, minus the correlation.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    set_trace_context_provider(Arc::new(|| panic!("tracer is wedged")));
    let rec = emit_one();
    std::panic::set_hook(previous);
    assert_eq!(rec["status"], "ok");
    assert!(rec.get("trace_id").is_none());

    clear_trace_context_provider();
    let rec = emit_one();
    assert!(rec.get("trace_id").is_none());
}
