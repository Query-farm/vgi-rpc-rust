//! OpenTelemetry-compatible dispatch hook.
//!
//! Enabled by the `otel` feature. The hook opens a real `tracing::Span`
//! per RPC dispatch — created on `on_dispatch_start` and dropped on
//! `on_dispatch_end` — and records method / principal / auth_domain /
//! status / duration / batch-counts as span fields. A
//! `tracing-opentelemetry` `Layer` installed by the user converts the
//! span into a real OpenTelemetry span (with start/end times, status,
//! attributes) for export via OTLP, Jaeger, Tempo, etc.
//!
//! That layered design keeps `vgi-rpc` free of the heavy
//! `opentelemetry`/`opentelemetry-sdk` dependency tree: users opt into
//! the exporter pipeline they want, and the hook produces span data
//! that any `tracing-opentelemetry` layer picks up automatically.
//!
//! W3C trace context (`traceparent` / `tracestate`) carried by the
//! request's `transport_metadata` is surfaced as span fields so
//! `tracing-opentelemetry` can use them as the parent context.
//!
//! The hook also exposes a tiny counter + latency histogram updated in
//! memory, queryable for test assertions and scrape-style pulls.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::errors::RpcError;
use crate::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};
use crate::metadata::{TRACEPARENT_KEY, TRACESTATE_KEY};

/// Configuration for the OTel hook.
#[derive(Clone, Debug)]
pub struct OtelConfig {
    pub service_name: String,
    /// Whether to include full exception messages on error spans.
    pub record_exceptions: bool,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            service_name: "vgi-rpc".into(),
            record_exceptions: true,
        }
    }
}

/// Simple in-memory metrics maintained by [`OtelHook`]. Not a full OTel
/// MeterProvider — good enough for smoke tests and `/metrics`-style
/// debug endpoints; real exporters can layer over `tracing-opentelemetry`.
#[derive(Default)]
pub struct OtelMetrics {
    pub requests_total: AtomicU64,
    pub errors_total: AtomicU64,
    /// Sum of durations in nanoseconds; used to compute average latency.
    pub duration_sum_ns: AtomicU64,
    /// Per-method request counters.
    pub by_method: Mutex<HashMap<String, u64>>,
}

impl OtelMetrics {
    pub fn requests(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }
    pub fn errors(&self) -> u64 {
        self.errors_total.load(Ordering::Relaxed)
    }
    pub fn average_duration(&self) -> Duration {
        let total = self.requests_total.load(Ordering::Relaxed).max(1);
        let sum = self.duration_sum_ns.load(Ordering::Relaxed);
        Duration::from_nanos(sum / total)
    }
}

/// Span state retained between `on_dispatch_start` and
/// `on_dispatch_end` for one RPC call.
struct InflightSpan {
    started: Instant,
    /// Live `tracing::Span` recorded at start; dropped at end so
    /// `tracing-opentelemetry` sees a complete span lifetime
    /// (`new_span` → `close`) and produces an exported OTel span.
    span: tracing::Span,
}

/// OTel-style dispatch hook. Records a real `tracing::Span` per call
/// (consumed by `tracing-opentelemetry` as an OTel span) and bumps
/// [`OtelMetrics`] counters.
pub struct OtelHook {
    cfg: OtelConfig,
    metrics: Arc<OtelMetrics>,
    starts: Mutex<HashMap<HookToken, InflightSpan>>,
    next_token: AtomicU64,
}

impl OtelHook {
    pub fn new(cfg: OtelConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            metrics: Arc::new(OtelMetrics::default()),
            starts: Mutex::new(HashMap::new()),
            next_token: AtomicU64::new(1),
        })
    }

    pub fn metrics(&self) -> Arc<OtelMetrics> {
        self.metrics.clone()
    }

    /// Extract `traceparent` + `tracestate` headers/metadata keys so
    /// callers can propagate them when constructing downstream spans.
    /// Returns `(traceparent, tracestate)`.
    pub fn extract_w3c_context(
        metadata: &std::collections::HashMap<String, String>,
    ) -> (Option<String>, Option<String>) {
        let mut tp = None;
        let mut ts = None;
        for (k, v) in metadata {
            if k.eq_ignore_ascii_case(TRACEPARENT_KEY) {
                tp = Some(v.clone());
            } else if k.eq_ignore_ascii_case(TRACESTATE_KEY) {
                ts = Some(v.clone());
            }
        }
        (tp, ts)
    }
}

impl DispatchHook for OtelHook {
    fn on_dispatch_start(&self, info: &DispatchInfo) -> HookToken {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let (traceparent, tracestate) = Self::extract_w3c_context(&info.transport_metadata);
        // Span name follows OTel RPC semantic conventions
        // (`rpc.system / rpc.service / rpc.method`); the
        // tracing-opentelemetry layer maps the span fields to OTel
        // attributes verbatim. Status / duration / error_* are
        // recorded at end via `Span::record`.
        let span = tracing::info_span!(
            target: "vgi_rpc.otel",
            "rpc.call",
            service = %self.cfg.service_name,
            rpc.system = "vgi_rpc",
            rpc.service = %info.protocol,
            rpc.method = %info.method,
            method = %info.method,
            method_type = info.method_type,
            server_id = %info.server_id,
            principal = %info.principal,
            auth_domain = %info.auth_domain,
            authenticated = info.authenticated,
            traceparent = traceparent.as_deref().unwrap_or(""),
            tracestate = tracestate.as_deref().unwrap_or(""),
            // Declared up front so `Span::record` at end can populate.
            status = tracing::field::Empty,
            error_type = tracing::field::Empty,
            error_message = tracing::field::Empty,
            duration_ms = tracing::field::Empty,
            input_batches = tracing::field::Empty,
            output_batches = tracing::field::Empty,
            input_rows = tracing::field::Empty,
            output_rows = tracing::field::Empty,
        );
        self.starts.lock().unwrap().insert(
            token,
            InflightSpan {
                started: Instant::now(),
                span,
            },
        );
        token
    }

    fn on_dispatch_end(
        &self,
        token: HookToken,
        info: &DispatchInfo,
        error: Option<&RpcError>,
        stats: &CallStatistics,
    ) {
        let inflight = self.starts.lock().unwrap().remove(&token);
        let elapsed = inflight
            .as_ref()
            .map(|i| i.started.elapsed())
            .unwrap_or_default();
        let elapsed_ns = elapsed.as_nanos().min(u64::MAX as u128) as u64;

        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .duration_sum_ns
            .fetch_add(elapsed_ns, Ordering::Relaxed);
        if error.is_some() {
            self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
        }
        *self
            .metrics
            .by_method
            .lock()
            .unwrap()
            .entry(info.method.clone())
            .or_insert(0) += 1;

        let status = if error.is_some() { "error" } else { "ok" };
        let error_type = error.map(|e| e.error_type.as_str()).unwrap_or("");
        let error_message = if self.cfg.record_exceptions {
            error.map(|e| e.message.as_str()).unwrap_or("")
        } else {
            ""
        };

        if let Some(inflight) = inflight {
            // Populate the closing fields on the span. Dropping the
            // `InflightSpan` (and its `tracing::Span`) afterwards is
            // what signals the tracing-opentelemetry layer to close
            // and export the OTel span. The drop runs unconditionally
            // here even if an exporter inside the layer panics —
            // that's the Rust equivalent of Python's
            // `try/finally: otel_context.detach()` from `3d31a21`.
            inflight.span.record("status", status);
            inflight.span.record("error_type", error_type);
            inflight.span.record("error_message", error_message);
            inflight
                .span
                .record("duration_ms", elapsed.as_secs_f64() * 1000.0);
            inflight.span.record("input_batches", stats.input_batches);
            inflight.span.record("output_batches", stats.output_batches);
            inflight.span.record("input_rows", stats.input_rows);
            inflight.span.record("output_rows", stats.output_rows);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(method: &str) -> DispatchInfo {
        DispatchInfo {
            method: method.into(),
            method_type: "unary",
            server_id: "srv".into(),
            protocol: String::new(),
            request_id: String::new(),
            transport_metadata: Arc::new(std::collections::HashMap::from([(
                "traceparent".into(),
                "00-aaaa-bbbb-01".into(),
            )])),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
            remote_addr: String::new(),
            http_status: 0,
            request_data: Vec::new(),
            stream_id: String::new(),
            cancelled: false,
            claims: std::collections::BTreeMap::new(),
            protocol_hash: String::new(),
            protocol_version: String::new(),
        }
    }

    #[test]
    fn counts_requests_and_errors() {
        let hook = OtelHook::new(OtelConfig::default());
        let m = hook.metrics();

        let t = hook.on_dispatch_start(&info("echo"));
        hook.on_dispatch_end(t, &info("echo"), None, &CallStatistics::default());

        let t = hook.on_dispatch_start(&info("raise"));
        let err = RpcError::value_error("boom");
        hook.on_dispatch_end(t, &info("raise"), Some(&err), &CallStatistics::default());

        assert_eq!(m.requests(), 2);
        assert_eq!(m.errors(), 1);
        let per = m.by_method.lock().unwrap();
        assert_eq!(per.get("echo").copied(), Some(1));
        assert_eq!(per.get("raise").copied(), Some(1));
    }

    #[test]
    fn extracts_traceparent() {
        let md = std::collections::HashMap::from([
            ("Traceparent".to_string(), "00-xxxx-01".to_string()),
            ("Tracestate".to_string(), "vendor=yyyy".to_string()),
        ]);
        let (tp, ts) = OtelHook::extract_w3c_context(&md);
        assert_eq!(tp.as_deref(), Some("00-xxxx-01"));
        assert_eq!(ts.as_deref(), Some("vendor=yyyy"));
    }
}
