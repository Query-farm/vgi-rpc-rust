//! Structured access logging as a [`DispatchHook`].
//!
//! Emits one JSON record per RPC call via a writer the caller supplies.
//! The schema matches the Python canonical (`vgi_rpc.access_log_conformance`
//! validator) so logs are portable across implementations; the normative
//! contract is `docs/access-log-spec.md` in the reference repo.
//!
//! # Trace correlation
//!
//! `request_id` only joins records within one service. `trace_id` / `span_id`
//! join them to the surrounding distributed trace, and are read from whatever
//! span is *current* rather than from anything this framework threads through,
//! so a record correlates with an application-opened span as readily as with a
//! framework-opened one. The crate carries no OpenTelemetry dependency (the
//! `otel` feature is tracing-only), so the reader is pluggable — install one
//! with [`set_trace_context_provider`]:
//!
//! ```no_run
//! # fn my_current_span_ids() -> Option<(String, String)> { None }
//! use std::sync::Arc;
//! // e.g. via tracing_opentelemetry::OpenTelemetrySpanExt on Span::current()
//! vgi_rpc::access_log::set_trace_context_provider(Arc::new(my_current_span_ids));
//! ```
//!
//! Ids that are not 32 / 16 lowercase hex, or that are all zeroes (OTel's
//! "invalid" sentinel), are dropped rather than emitted — and the pair is
//! always emitted together or not at all.

use std::collections::BTreeMap;
use std::io::Write;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use serde_json::json;

use crate::errors::RpcError;
use crate::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};

/// Default per-record byte cap, matching the Python reference's 1 MiB.
/// Log shippers impose a per-line ceiling (Vector 100 KiB, Fluent Bit
/// 256 KiB by default) and silently drop longer lines, so a record that
/// cannot be shipped is worse than a record that admits it shed a field.
pub const DEFAULT_MAX_RECORD_BYTES: usize = 1_048_576;

/// Where the hook sends formatted JSON lines.
enum Sink {
    /// Synchronous: dispatch thread holds the sink mutex during the write.
    Sync(Arc<Mutex<dyn Write + Send>>),
    /// Asynchronous: dispatch thread queues the line into a bounded
    /// channel; a background writer thread drains it.
    Async {
        tx: SyncSender<Vec<u8>>,
        /// Records lost since the last one that made it onto the queue.
        /// Behind a mutex rather than an atomic so read-stamp-adjust is
        /// one step: the count must reach the same file the losses would
        /// have, exactly once.
        dropped: Arc<Mutex<u64>>,
    },
}

impl Clone for Sink {
    fn clone(&self) -> Self {
        match self {
            Sink::Sync(m) => Sink::Sync(m.clone()),
            Sink::Async { tx, dropped } => Sink::Async {
                tx: tx.clone(),
                dropped: dropped.clone(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Trace correlation
// ---------------------------------------------------------------------------

/// Returns the current span's `(trace_id, span_id)` as W3C hex, or `None`.
pub type TraceContextProvider = Arc<dyn Fn() -> Option<(String, String)> + Send + Sync>;

static TRACE_PROVIDER: RwLock<Option<TraceContextProvider>> = RwLock::new(None);
/// Fast path for the overwhelmingly common case of no provider installed:
/// one relaxed load instead of a lock on every record.
static HAS_TRACE_PROVIDER: AtomicBool = AtomicBool::new(false);

/// Install the reader used to correlate records with the surrounding trace.
///
/// Called once at startup. The provider runs on the dispatch thread while
/// the call's span is still current, so it must be cheap; it must not be
/// relied upon to be correct, either — a provider that panics or returns
/// malformed ids costs the two correlation fields and nothing else.
pub fn set_trace_context_provider(provider: TraceContextProvider) {
    if let Ok(mut slot) = TRACE_PROVIDER.write() {
        *slot = Some(provider);
        HAS_TRACE_PROVIDER.store(true, Ordering::Relaxed);
    }
}

/// Remove any installed provider, returning to trace-less records.
pub fn clear_trace_context_provider() {
    if let Ok(mut slot) = TRACE_PROVIDER.write() {
        *slot = None;
        HAS_TRACE_PROVIDER.store(false, Ordering::Relaxed);
    }
}

/// Read `(trace_id, span_id)` from the current span, validated.
///
/// Returns `None` unless both ids are well-formed: the schema's
/// `^[0-9a-f]{32}$` / `^[0-9a-f]{16}$` patterns are the cross-language
/// enforcement, and emitting a dashed UUID would fail validation for every
/// record rather than just skipping correlation on one.
fn current_trace_context() -> Option<(String, String)> {
    if !HAS_TRACE_PROVIDER.load(Ordering::Relaxed) {
        return None;
    }
    let provider = TRACE_PROVIDER.read().ok()?.clone()?;
    // Observability must never surface as a request failure.
    let (trace_id, span_id) = std::panic::catch_unwind(AssertUnwindSafe(|| provider())).ok()??;
    (is_trace_hex(&trace_id, 32) && is_trace_hex(&span_id, 16)).then_some((trace_id, span_id))
}

/// Lowercase hex of exactly `len` digits, and not all zeroes — an all-zero
/// id is OTel's "no valid span" sentinel, not an identifier.
fn is_trace_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

// ---------------------------------------------------------------------------
// Claim redaction
// ---------------------------------------------------------------------------

/// Substituted for a sensitive claim value.
pub const REDACTED: &str = "[redacted]";

/// Applied to `claims` before they reach a record.
pub type ClaimRedactor =
    Arc<dyn Fn(&BTreeMap<String, String>) -> BTreeMap<String, String> + Send + Sync>;

/// Claim names whose values never reach the log verbatim: credentials, plus
/// the standard OIDC claims that are personal data.
const SENSITIVE_CLAIM_FRAGMENTS: &[&str] = &[
    // Credential-shaped. Same list `sentry_sdk` redacts, so the two
    // observability paths do not disagree about what is sensitive.
    "password",
    "token",
    "secret",
    "key",
    "authorization",
    // Standard OIDC claims that are personal data.
    "email",
    "phone",
    "address",
    "birthdate",
    "gender",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "picture",
    "profile",
    "website",
];

/// Replace sensitive claim *values* with [`REDACTED`].
///
/// An access log outlives the token it describes by months or years and is
/// shipped to systems chosen for searchability rather than for holding
/// personal data, so `email` / `phone` / `*_token` reaching it verbatim is a
/// retention problem rather than a debugging feature.
///
/// Matching is **key-based**: a value is judged by the name it arrived under,
/// never by its content. A claim called `context` holding an email address is
/// not caught, and cannot be without guessing at free text — a boundary worth
/// stating rather than pretending to exceed.
///
/// Values are **replaced, not dropped**. "Did this credential carry an email
/// claim?" is a question an audit log exists to answer; "what was it?" is not.
pub fn redact_claims(claims: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    claims
        .iter()
        .map(|(key, value)| {
            let lowered = key.to_ascii_lowercase();
            let sensitive = lowered == "name"
                || SENSITIVE_CLAIM_FRAGMENTS
                    .iter()
                    .any(|fragment| lowered.contains(fragment));
            let value = if sensitive {
                REDACTED.to_string()
            } else {
                value.clone()
            };
            (key.clone(), value)
        })
        .collect()
}

/// Pass claims through verbatim. Only for logs you own end to end.
pub fn no_redaction(claims: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    claims.clone()
}

/// A `DispatchHook` that writes one JSON line per call to an arbitrary
/// `Write` sink. Entries carry the `vgi_rpc.access` logger name so the
/// Python validator's filter (`.logger == "vgi_rpc.access"`) matches.
///
/// Two modes:
/// - [`AccessLogHook::new`] / [`AccessLogHook::to_stderr`] write synchronously on the
///   dispatch thread (acceptable for stderr or in-memory test sinks).
/// - [`AccessLogHook::buffered`] queues into a bounded mpsc channel and
///   drains on a background thread; on overflow it drops the entry and
///   bumps a counter rather than blocking dispatch.
pub struct AccessLogHook {
    sink: Sink,
    server_version: String,
    /// When true, emit the full base64-encoded request batch as
    /// `request_data` (DEBUG-equivalent — see [`Self::with_verbose`]).
    /// When false (default), emit `original_request_bytes` +
    /// `truncated: "payload_omitted"` instead so the access-log schema's
    /// "unary requires request_data unless truncated" invariant still
    /// holds without ballooning every record by 8+ KiB.
    verbose: bool,
    /// Per-record byte cap; `0` disables it. See [`Self::with_max_record_bytes`].
    max_record_bytes: usize,
    /// Fraction of non-error calls kept; `1.0` keeps everything.
    sample_rate: f64,
    claim_redactor: ClaimRedactor,
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
        Arc::new(Self::with_sink(
            Sink::Sync(Arc::new(Mutex::new(sink))),
            server_version.into(),
        ))
    }

    fn with_sink(sink: Sink, server_version: String) -> Self {
        Self {
            sink,
            server_version,
            verbose: false,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            sample_rate: 1.0,
            claim_redactor: Arc::new(redact_claims),
            starts: Mutex::new(std::collections::HashMap::new()),
            next_token: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Clone this hook's configuration, apply `mutate`, and return the result.
    ///
    /// The in-flight call table is deliberately not carried over: these are
    /// startup knobs, and a hook reconfigured mid-serve would report a
    /// duration of zero for every call already running.
    fn derive(&self, mutate: impl FnOnce(&mut Self)) -> Arc<Self> {
        let mut next = Self {
            sink: self.sink.clone(),
            server_version: self.server_version.clone(),
            verbose: self.verbose,
            max_record_bytes: self.max_record_bytes,
            sample_rate: self.sample_rate,
            claim_redactor: self.claim_redactor.clone(),
            starts: Mutex::new(std::collections::HashMap::new()),
            next_token: std::sync::atomic::AtomicU64::new(1),
        };
        mutate(&mut next);
        Arc::new(next)
    }

    /// Return a new `Arc<AccessLogHook>` with verbose request-data
    /// emission enabled. Mirrors Python's
    /// `_access_logger.isEnabledFor(logging.DEBUG)` behaviour where
    /// the full base64-encoded request batch is included verbatim
    /// rather than being elided via `truncated: "payload_omitted"`.
    pub fn with_verbose(self: Arc<Self>, verbose: bool) -> Arc<Self> {
        if self.verbose == verbose {
            return self;
        }
        self.derive(|h| h.verbose = verbose)
    }

    /// Cap each record at `max_bytes`, shedding optional fields to fit;
    /// `0` disables the cap. Pair it with shipper configs that raise their
    /// per-line limits to match (Vector's `max_line_bytes`, Fluent Bit's
    /// `Buffer_Max_Size`) — a line above the shipper's ceiling is dropped
    /// without a word.
    pub fn with_max_record_bytes(self: Arc<Self>, max_bytes: usize) -> Arc<Self> {
        self.derive(|h| h.max_record_bytes = max_bytes)
    }

    /// Keep only `rate` of the *successful* calls.
    ///
    /// Three properties separate a sampler that helps from one that quietly
    /// costs someone an incident, and all three are enforced here:
    ///
    /// - **Errors are never sampled.** A rate below 1 exists because
    ///   successful calls are repetitive, which is exactly what failures are
    ///   not; a consumer has to be able to read a falling error count as a
    ///   fix landing rather than as the dice going the other way.
    /// - **The decision is deterministic, per call.** It is keyed on
    ///   `stream_id` when present and `request_id` otherwise, so every record
    ///   of one stream shares its init's fate. Random per-record sampling
    ///   shreds a multi-record call into fragments indistinguishable from
    ///   data loss, and the calls likeliest to be split are the long streams
    ///   most worth studying.
    /// - **The rate rides on every kept record** as `sample_rate`, because a
    ///   consumer scaling counts must divide by it, and a rate discoverable
    ///   only from a deployment's flags is one that gets guessed wrong.
    ///
    /// # Errors
    ///
    /// Returns a `ValueError` when `rate` is outside `0.0..=1.0`. Failing
    /// here rather than at the first request is the point: `100` meaning
    /// "100%" would otherwise silently log everything, and a negative rate
    /// silently nothing.
    pub fn with_sample_rate(self: Arc<Self>, rate: f64) -> crate::errors::Result<Arc<Self>> {
        if !(0.0..=1.0).contains(&rate) {
            return Err(RpcError::value_error(format!(
                "access-log sample rate must be between 0.0 and 1.0, got {rate}"
            )));
        }
        Ok(self.derive(|h| h.sample_rate = rate))
    }

    /// Replace the redaction policy applied to `claims`.
    ///
    /// Pass [`no_redaction`] to disable it — appropriate only for a service
    /// that owns its logs end to end. A redactor that panics fails **closed**:
    /// the claims are dropped from the record rather than emitted raw.
    pub fn with_claim_redactor(self: Arc<Self>, redactor: ClaimRedactor) -> Arc<Self> {
        self.derive(|h| h.claim_redactor = redactor)
    }

    /// Create a hook that writes asynchronously: the dispatch thread
    /// pushes a formatted line into a bounded channel of `capacity`
    /// entries and a background thread drains it into `sink`.
    ///
    /// The queue is bounded and a full queue **drops** rather than blocks:
    /// an unbounded queue turns a stalled disk into an OOM, and a blocking
    /// send reintroduces exactly the latency the thread was meant to remove.
    /// What makes dropping acceptable rather than silent corruption is that
    /// it is reported — the next record through carries `dropped_records`,
    /// so the loss shows up in the log itself and not only in a counter
    /// nobody exports.
    ///
    /// This trades durability. With a synchronous sink, a record on disk
    /// means the call completed; here a crash loses whatever is still
    /// queued. Right for high throughput, wrong for audit — hence opt-in.
    ///
    /// The writer thread exits when the hook is dropped (sender closes).
    pub fn buffered<W: Write + Send + 'static>(
        sink: W,
        server_version: impl Into<String>,
        capacity: usize,
    ) -> Arc<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(capacity.max(1));
        let dropped = Arc::new(Mutex::new(0u64));
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
        Arc::new(Self::with_sink(
            Sink::Async { tx, dropped },
            server_version.into(),
        ))
    }

    /// Convenience: write access logs to stderr synchronously
    /// (one JSON line per entry).
    pub fn to_stderr(server_version: impl Into<String>) -> Arc<Self> {
        Self::new(std::io::stderr(), server_version)
    }

    /// Records dropped since the last one that made it onto the queue.
    /// Always zero for synchronous hooks; reset once the count has been
    /// reported in-band as `dropped_records`.
    pub fn dropped_count(&self) -> u64 {
        match &self.sink {
            Sink::Async { dropped, .. } => *dropped.lock().unwrap_or_else(|e| e.into_inner()),
            Sink::Sync(_) => 0,
        }
    }

    /// Decide whether a record for this call survives sampling.
    ///
    /// Keyed on a stable identifier for the *call*, not for the record, so a
    /// stream's continuations share the fate of their init. `fallback` is
    /// used only when the transport supplies neither id, which degrades to
    /// per-record sampling rather than dropping the record on the floor.
    fn sampled_in(&self, info: &DispatchInfo, fallback: HookToken) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        let key = if !info.stream_id.is_empty() {
            info.stream_id.clone()
        } else if !info.request_id.is_empty() {
            info.request_id.clone()
        } else {
            format!("{}:{fallback}", info.server_id)
        };
        // A 32-bit hash prefix is exact enough for sampling and keeps the
        // decision to one digest plus one integer compare.
        use sha2::Digest;
        let digest = sha2::Sha256::digest(key.as_bytes());
        let prefix = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        u64::from(prefix) <= (self.sample_rate * f64::from(u32::MAX)) as u64
    }

    /// Serialize the record, apply the size cap, and hand it to the sink.
    fn write_record(&self, rec: serde_json::Map<String, serde_json::Value>) {
        write_record(&self.sink, self.max_record_bytes, rec);
    }
}

type Record = serde_json::Map<String, serde_json::Value>;

/// Serialize `rec`, apply the size cap, and hand it to `sink`.
///
/// Free-standing rather than a method because a deferred record outlives the
/// dispatch call that built it and needs only these two pieces of the hook.
fn write_record(sink: &Sink, max_record_bytes: usize, rec: Record) {
    match sink {
        Sink::Sync(m) => {
            let line = render(max_record_bytes, rec);
            if let Ok(mut w) = m.lock() {
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
        }
        Sink::Async { tx, dropped } => {
            // Read-stamp-adjust under one lock, so a drop count is attributed
            // exactly once and to a record that actually reaches the file.
            let mut guard = dropped.lock().unwrap_or_else(|e| e.into_inner());
            let pending = *guard;
            let mut rec = rec;
            if pending > 0 {
                rec.insert("dropped_records".into(), json!(pending));
            }
            let line = render(max_record_bytes, rec);
            match tx.try_send(line.into_bytes()) {
                Ok(()) => *guard = 0,
                // Full means drop — never block dispatch behind a stalled
                // disk. Disconnected means the writer thread is gone, which
                // is the same loss by a different route.
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    *guard = pending + 1;
                }
            }
        }
    }
}

/// Render a record to one JSON line, shedding fields when it exceeds
/// `max_record_bytes` (`0` disables the cap).
///
/// The shed order is the spec's: `request_data` first (it is almost always
/// what blew the budget), then `claims`, then the sentinel form.
/// `error_message` is never truncated — the full server-side message is what
/// an operator is reading the record for.
fn render(max_record_bytes: usize, mut rec: Record) -> String {
    let mut line = serde_json::Value::Object(rec.clone()).to_string();
    if max_record_bytes == 0 || line.len() <= max_record_bytes {
        return line;
    }

    if let Some(serde_json::Value::String(payload)) = rec.remove("request_data") {
        rec.insert("original_request_bytes".into(), json!(payload.len()));
        // `true` here and nowhere else: this record genuinely lost data to a
        // cap, as distinct from a deployment that simply never logs payloads
        // (`"payload_omitted"`).
        rec.insert("truncated".into(), json!(true));
        line = serde_json::Value::Object(rec.clone()).to_string();
        if line.len() <= max_record_bytes {
            return line;
        }
    }

    if rec.contains_key("claims") {
        rec.insert("claims".into(), json!({}));
        rec.insert("truncated".into(), json!(true));
        line = serde_json::Value::Object(rec.clone()).to_string();
        if line.len() <= max_record_bytes {
            return line;
        }
    }

    // Sentinel: everything the schema requires, plus the error message, and
    // nothing else. A record too large to ship is worth less than one that
    // says what it lost.
    let mut sentinel = serde_json::Map::new();
    for key in REQUIRED_RECORD_FIELDS {
        if let Some(value) = rec.get(*key) {
            sentinel.insert((*key).to_string(), value.clone());
        }
    }
    if let Some(message) = rec.get("error_message") {
        sentinel.insert("error_message".into(), message.clone());
    }
    sentinel.insert("truncated".into(), json!("record_too_large"));
    serde_json::Value::Object(sentinel).to_string()
}

/// Fields every record must carry, and therefore the ones the sentinel form
/// keeps. Mirrors the schema's `required` list.
const REQUIRED_RECORD_FIELDS: &[&str] = &[
    "timestamp",
    "level",
    "logger",
    "message",
    "server_id",
    "protocol",
    "protocol_hash",
    "method",
    "method_type",
    "principal",
    "auth_domain",
    "authenticated",
    "remote_addr",
    "duration_ms",
    "status",
    "error_type",
];

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

        // Sampling decision first: everything below is work a sampled-out
        // record does not need. Errors bypass it entirely — a rate below 1
        // exists because successes repeat, which failures do not.
        let sampled = error.is_some() || self.sampled_in(info, token);
        if !sampled {
            return;
        }

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
        // Trace correlation. `request_id` only joins records within this
        // service; these join them to the surrounding distributed trace.
        // Both or neither — a lone id correlates with nothing.
        if let Some((trace_id, span_id)) = current_trace_context() {
            rec.insert("trace_id".into(), json!(trace_id));
            rec.insert("span_id".into(), json!(span_id));
        }
        // Payload capture. A record that would carry `request_data` but does
        // not must say so, or the schema's "unary requires request_data"
        // invariant fails.
        let carries_payload = info.method_type == "unary" || !info.request_data.is_empty();
        if self.verbose && !info.request_data.is_empty() {
            rec.insert(
                "request_data".into(),
                json!(base64_encode(&info.request_data)),
            );
        } else if carries_payload {
            // `"payload_omitted"`, not `true`: nothing was lost to a size
            // cap here — this deployment simply does not log payloads at
            // this level. Sharing one marker with genuine shedding made it
            // fire on essentially every record and left a consumer looking
            // for real data loss with nothing to filter on.
            if !info.request_data.is_empty() {
                let encoded_len = info.request_data.len().div_ceil(3) * 4;
                rec.insert("original_request_bytes".into(), json!(encoded_len));
            }
            rec.insert("truncated".into(), json!("payload_omitted"));
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
        if !info.claims.is_empty() {
            // Redacted by key before the record exists. Which claims a
            // credential carried is what an audit log is for; what they
            // contained is a retention problem.
            let redactor = self.claim_redactor.clone();
            let redacted = std::panic::catch_unwind(AssertUnwindSafe(|| redactor(&info.claims)))
                .unwrap_or_else(|_| {
                    // Fail closed. A broken redactor must not take the
                    // request down, and it must not fail open either.
                    tracing::warn!(
                        target: "vgi_rpc.access",
                        "claim redactor panicked; dropping claims from the record"
                    );
                    BTreeMap::new()
                });
            if !redacted.is_empty() {
                rec.insert("claims".into(), json!(redacted));
            }
        }
        // Egress accounting. The `input_bytes`/`output_bytes` pair below
        // measures logical Arrow buffers — what the worker processed. These
        // measure what crossed the network, which differs in both
        // directions: compression shrinks the body, and externalised
        // payloads leave it entirely. `response_bytes` is stamped later by
        // the transport, since compression runs after this hook.
        if let Some(request_bytes) = info.request_bytes {
            rec.insert("request_bytes".into(), json!(request_bytes));
        }
        if info.externalized_bytes > 0 {
            rec.insert("externalized_bytes".into(), json!(info.externalized_bytes));
        }
        if self.sample_rate < 1.0 && error.is_none() {
            // Errors bypass the decision, so they carry no rate to divide by.
            rec.insert("sample_rate".into(), json!(self.sample_rate));
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

        // `response_bytes` cannot be measured here: the handler has finished
        // but response compression has not run, so a record written now
        // could only ever report the uncompressed body. When the transport
        // offers a sink, hand the record over and let it emit once the final
        // body exists. The cost is that a crash between handler and response
        // loses the record; the alternative is a permanently wrong number.
        match info.access_sink.as_ref() {
            Some(sink) => {
                let deferred_sink = self.sink.clone();
                let max_record_bytes = self.max_record_bytes;
                sink.defer(Box::new(move |response_bytes| {
                    let mut rec = rec;
                    if let Some(n) = response_bytes {
                        rec.insert("response_bytes".into(), json!(n));
                    }
                    write_record(&deferred_sink, max_record_bytes, rec);
                }));
            }
            None => self.write_record(rec),
        }
    }
}

/// Format the current wall-clock time as RFC 3339 UTC with millisecond
/// precision, matching the access-log spec's `timestamp` regex.
pub(crate) fn rfc3339_utc_millis() -> String {
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
pub(crate) fn random_stream_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 128 bits drawn from time + a per-process atomic counter. Not
    // cryptographic — adequate for log correlation.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let lo = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let hi = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // wasm32-wasi has no process ids (`std::process::id()` aborts); the
    // time+counter mix already disambiguates within the single wasm process.
    #[cfg(not(target_arch = "wasm32"))]
    let pid = std::process::id() as u64;
    #[cfg(target_arch = "wasm32")]
    let pid: u64 = 0;
    format!("{:016x}{:016x}", hi ^ pid, lo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::AccessSink;
    use std::sync::Arc;

    /// Sink that appends every write into a shared buffer.
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

    fn buffer() -> (Arc<Mutex<Vec<u8>>>, BufSink) {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        (buf.clone(), BufSink(buf))
    }

    fn lines(buf: &Arc<Mutex<Vec<u8>>>) -> Vec<serde_json::Value> {
        String::from_utf8(buf.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn info(method: &str) -> DispatchInfo {
        DispatchInfo {
            method: method.into(),
            method_type: "unary",
            server_id: "srv".into(),
            protocol: "Test".into(),
            request_id: "req-1".into(),
            transport_metadata: Arc::new(Default::default()),
            ..Default::default()
        }
    }

    fn run(hook: &Arc<AccessLogHook>, info: &DispatchInfo, error: Option<&RpcError>) {
        let dyn_hook: &dyn DispatchHook = hook.as_ref();
        let token = dyn_hook.on_dispatch_start(info);
        dyn_hook.on_dispatch_end(token, info, error, &CallStatistics::default());
    }

    #[test]
    fn emits_json_line_per_call() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "1.2.3");
        run(&hook, &info("echo_string"), None);

        let rec = &lines(&buf)[0];
        assert_eq!(rec["logger"], "vgi_rpc.access");
        assert_eq!(rec["method"], "echo_string");
        assert_eq!(rec["server_version"], "1.2.3");
        assert_eq!(rec["status"], "ok");
        assert_eq!(rec["authenticated"], false);
    }

    #[test]
    fn error_entries_carry_error_message() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "1.2.3");
        run(
            &hook,
            &info("raise_value_error"),
            Some(&RpcError::value_error("boom")),
        );

        let rec = &lines(&buf)[0];
        assert_eq!(rec["status"], "error");
        assert_eq!(rec["error_type"], "ValueError");
        assert_eq!(rec["error_message"], "boom");
    }

    // -- truncation ---------------------------------------------------------

    #[test]
    fn payload_omission_is_distinct_from_size_driven_shedding() {
        // Not logging payloads at this level loses nothing, so it must not
        // look like data loss to a consumer scanning for exactly that.
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v");
        let mut i = info("echo_string");
        i.request_data = vec![7u8; 4096];
        run(&hook, &i, None);
        let rec = &lines(&buf)[0];
        assert_eq!(rec["truncated"], "payload_omitted");
        assert!(rec.get("request_data").is_none());
        assert!(rec["original_request_bytes"].as_u64().unwrap() > 0);

        // A cap that actually sheds the payload reports `true`.
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v")
            .with_verbose(true)
            .with_max_record_bytes(1024);
        run(&hook, &i, None);
        let rec = &lines(&buf)[0];
        assert_eq!(rec["truncated"], true);
        assert!(rec.get("request_data").is_none());
        assert_eq!(rec["original_request_bytes"].as_u64().unwrap(), 5464);
        assert_eq!(rec["method"], "echo_string");
    }

    #[test]
    fn unshippable_record_collapses_to_the_sentinel_form() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v")
            .with_verbose(true)
            // Below even the envelope, so shedding the payload cannot save it.
            .with_max_record_bytes(64);
        let mut i = info("echo_string");
        i.request_data = vec![7u8; 4096];
        run(&hook, &i, Some(&RpcError::value_error("boom")));

        let rec = &lines(&buf)[0];
        assert_eq!(rec["truncated"], "record_too_large");
        // The full server-side message survives: it is what an operator is
        // reading the record for.
        assert_eq!(rec["error_message"], "boom");
        assert_eq!(rec["status"], "error");
        assert!(rec.get("original_request_bytes").is_none());
    }

    // -- sampling -----------------------------------------------------------

    #[test]
    fn sample_rate_out_of_range_fails_at_construction() {
        let (_, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v");
        // 100 meaning "100%" must not silently log everything.
        assert!(hook.clone().with_sample_rate(100.0).is_err());
        assert!(hook.clone().with_sample_rate(-0.1).is_err());
        assert!(hook.with_sample_rate(0.25).is_ok());
    }

    #[test]
    fn sampling_decision_is_deterministic_per_stream() {
        // Every record of one stream must share its init's fate; a split
        // stream reads as data loss rather than as sampling.
        let mut kept_by_stream: Vec<(String, usize)> = Vec::new();
        for n in 0..40u32 {
            let stream_id = format!("{n:032x}");
            let (buf, sink) = buffer();
            let hook = AccessLogHook::new(sink, "v")
                .with_sample_rate(0.5)
                .expect("valid rate");
            let mut i = info("produce");
            i.method_type = "stream";
            i.stream_id = stream_id.clone();
            // Init plus four continuations of the same call.
            for _ in 0..5 {
                run(&hook, &i, None);
            }
            kept_by_stream.push((stream_id, lines(&buf).len()));
        }
        for (stream_id, kept) in &kept_by_stream {
            assert!(
                *kept == 0 || *kept == 5,
                "stream {stream_id} was shredded: {kept}/5 records kept"
            );
        }
        // ...and the rate has to actually bite, or the assertion above is vacuous.
        let sampled_out = kept_by_stream.iter().filter(|(_, k)| *k == 0).count();
        assert!(
            sampled_out > 0 && sampled_out < kept_by_stream.len(),
            "expected a mix at rate 0.5, got {sampled_out}/40 sampled out"
        );
    }

    #[test]
    fn sampling_never_drops_errors() {
        let (buf, sink) = buffer();
        // Rate 0 keeps nothing that is allowed to be dropped.
        let hook = AccessLogHook::new(sink, "v")
            .with_sample_rate(0.0)
            .expect("valid rate");
        for n in 0..20 {
            let mut i = info("call");
            i.request_id = format!("req-{n}");
            run(&hook, &i, None);
        }
        assert!(lines(&buf).is_empty(), "rate 0.0 kept a successful call");

        run(&hook, &info("boom"), Some(&RpcError::value_error("x")));
        let recs = lines(&buf);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["status"], "error");
        // Errors bypass the decision, so they carry no rate to divide by.
        assert!(recs[0].get("sample_rate").is_none());
    }

    #[test]
    fn kept_records_carry_the_rate() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v")
            .with_sample_rate(1.0)
            .expect("valid rate");
        run(&hook, &info("call"), None);
        // A rate of 1 is not sampling, so nothing to divide by.
        assert!(lines(&buf)[0].get("sample_rate").is_none());

        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v")
            .with_sample_rate(1.0 - f64::EPSILON)
            .expect("valid rate");
        run(&hook, &info("call"), None);
        assert!(lines(&buf)[0]["sample_rate"].as_f64().unwrap() < 1.0);
    }

    // -- claim redaction ----------------------------------------------------

    fn claims() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("sub".to_string(), "user-42".to_string()),
            ("email".to_string(), "alice@example.com".to_string()),
            ("api_key".to_string(), "sk-live-abc".to_string()),
            ("Access_Token".to_string(), "eyJ...".to_string()),
            ("name".to_string(), "Alice".to_string()),
            ("tenant".to_string(), "acme".to_string()),
        ])
    }

    #[test]
    fn claims_are_redacted_by_key_without_dropping_keys() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v");
        let mut i = info("call");
        i.claims = claims();
        run(&hook, &i, None);

        let rec = &lines(&buf)[0];
        let logged = rec["claims"].as_object().unwrap();
        // Which claims the credential carried stays answerable...
        assert_eq!(logged.len(), 6);
        assert!(logged.contains_key("email"));
        // ...while none of the sensitive values reach the log.
        assert_eq!(logged["email"], REDACTED);
        assert_eq!(logged["api_key"], REDACTED);
        assert_eq!(logged["Access_Token"], REDACTED);
        assert_eq!(logged["name"], REDACTED);
        // Key-based matching means non-credential keys pass through.
        assert_eq!(logged["sub"], "user-42");
        assert_eq!(logged["tenant"], "acme");
    }

    #[test]
    fn redactor_that_panics_fails_closed() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v")
            .with_claim_redactor(Arc::new(|_| panic!("redactor is broken")));
        let mut i = info("call");
        i.claims = claims();
        // Silence the default panic hook's stderr noise for the duration.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        run(&hook, &i, None);
        std::panic::set_hook(previous);

        let rec = &lines(&buf)[0];
        // Dropped entirely rather than emitted unredacted, and the call
        // itself still produced a record.
        assert!(rec.get("claims").is_none());
        assert_eq!(rec["status"], "ok");
    }

    #[test]
    fn no_redaction_opts_out() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v").with_claim_redactor(Arc::new(no_redaction));
        let mut i = info("call");
        i.claims = claims();
        run(&hook, &i, None);
        assert_eq!(lines(&buf)[0]["claims"]["email"], "alice@example.com");
    }

    // -- egress accounting --------------------------------------------------

    #[test]
    fn egress_fields_are_absent_when_unmeasured() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v");
        run(&hook, &info("call"), None);
        let rec = &lines(&buf)[0];
        assert!(rec.get("request_bytes").is_none());
        assert!(rec.get("externalized_bytes").is_none());
        assert!(rec.get("response_bytes").is_none());
    }

    #[test]
    fn deferred_records_wait_for_the_response_size() {
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v");
        let access_sink = AccessSink::new();
        let mut i = info("call");
        i.access_sink = Some(access_sink.clone());
        i.request_bytes = Some(1234);
        i.externalized_bytes = 10_000_000;
        run(&hook, &i, None);

        // Nothing written yet: the body it describes does not exist.
        assert!(lines(&buf).is_empty());
        access_sink.emit(Some(183));

        let rec = &lines(&buf)[0];
        assert_eq!(rec["request_bytes"], 1234);
        assert_eq!(rec["response_bytes"], 183);
        assert_eq!(rec["externalized_bytes"], 10_000_000u64);
    }

    #[test]
    fn undrained_sink_still_emits() {
        // A transport that forgets to drain loses the size, not the record.
        let (buf, sink) = buffer();
        let hook = AccessLogHook::new(sink, "v");
        let mut i = info("call");
        {
            let access_sink = AccessSink::new();
            i.access_sink = Some(access_sink.clone());
            run(&hook, &i, None);
            assert!(lines(&buf).is_empty());
            i.access_sink = None;
        }
        let rec = &lines(&buf)[0];
        assert_eq!(rec["method"], "call");
        assert!(rec.get("response_bytes").is_none());
    }

    // -- asynchronous emission ----------------------------------------------

    #[test]
    fn buffered_writes_via_background_thread() {
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
        let hook = AccessLogHook::buffered(ChanSink(tx), "1.2.3", 128);
        run(&hook, &info("echo_string"), None);

        // The writer thread writes the line and its newline separately.
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

    /// Sink whose first write blocks forever, leaving the queue saturated.
    struct WedgedSink(Arc<std::sync::Barrier>);
    impl Write for WedgedSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.wait();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn buffered_drops_when_channel_full_instead_of_blocking() {
        // Three parties would have to arrive for this barrier to release, so
        // the writer thread parks on the first line and never takes another.
        let hook =
            AccessLogHook::buffered(WedgedSink(Arc::new(std::sync::Barrier::new(3))), "v", 1);
        for _ in 0..50 {
            run(&hook, &info("m"), None);
        }
        assert!(
            hook.dropped_count() > 0,
            "expected drops on a saturated queue; dispatch must never block"
        );
    }

    /// A sink whose writes park until the test opens the gate, so the queue
    /// overflows on demand rather than on timing.
    ///
    /// `entered` fires the first time the writer thread is *inside* `write`.
    /// The test waits for it before flooding: until the writer has parked,
    /// how many records the queue swallows is a scheduling question, and
    /// "did the queue overflow" is not yet a fact the test can assert.
    struct GatedSink {
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
        entered: std::sync::mpsc::SyncSender<()>,
        out: Arc<Mutex<Vec<u8>>>,
    }
    impl Write for GatedSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            // Non-blocking: only the first send needs to land, and the
            // receiver may already be gone by a later write.
            let _ = self.entered.try_send(());
            let (lock, cv) = &*self.gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            drop(open);
            self.out.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn dropped_records_is_reported_on_the_next_record_through() {
        // A log that loses records without saying so is worse than a slow
        // one: a consumer cannot tell a quiet period from a lossy one.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let hook = AccessLogHook::buffered(
            GatedSink {
                gate: gate.clone(),
                entered: entered_tx,
                out: buf.clone(),
            },
            "v",
            1,
        );
        // Park the writer *before* asserting anything about overflow. This
        // record is the one it takes off the queue and blocks on; until it
        // is provably inside `write`, the queue has a consumer and how much
        // it swallows is up to the scheduler, not the test.
        run(&hook, &info("park"), None);
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("access-log writer thread never reached the sink");

        // Writer parked, queue holds one more, everything after that drops.
        for _ in 0..10 {
            run(&hook, &info("flood"), None);
        }
        let dropped = hook.dropped_count();
        assert!(dropped > 0, "queue never overflowed");

        // Let the writer run, then keep offering records until one gets
        // through — that one has to carry the loss.
        {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while hook.dropped_count() > 0 && std::time::Instant::now() < deadline {
            run(&hook, &info("retry"), None);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(hook.dropped_count(), 0, "queue never drained");

        let mut reported = 0u64;
        while reported == 0 && std::time::Instant::now() < deadline {
            reported = lines(&buf)
                .iter()
                .filter_map(|r| r.get("dropped_records").and_then(|v| v.as_u64()))
                .sum();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            reported >= dropped,
            "{dropped} records were dropped but only {reported} were reported"
        );
    }
}
