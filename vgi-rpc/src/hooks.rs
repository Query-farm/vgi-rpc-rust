//! Dispatch hook interface used by observability integrations.
//!
//! Each call dispatches through `on_dispatch_start` before the handler runs
//! and `on_dispatch_end` after completion (success or error). The hook
//! receives `CallStatistics` tallied by the framework and may record
//! spans / metrics / sentry events.

use std::sync::{Arc, Mutex};

use crate::errors::RpcError;
use crate::wire::Metadata;

/// A record that cannot be written yet because it is still missing a figure
/// only the transport knows. Called with the final on-wire response size, or
/// `None` when that size is unknowable (a streamed body with no length).
pub type DeferredRecord = Box<dyn FnOnce(Option<u64>) + Send>;

/// Holds records back until the response they describe actually exists.
///
/// A handler knows what it produced; it does not know what was sent. Response
/// compression runs after the handler returns, so a record emitted there can
/// only ever report the uncompressed body — which is the wrong number for
/// anything that costs money. A transport that can measure the final body
/// installs a sink here, hooks defer into it, and the transport drains it once
/// the body is final. A transport that installs no sink gets inline emission,
/// so the immediate-vs-deferred choice is made in exactly one place.
#[derive(Clone, Default)]
pub struct AccessSink {
    inner: Arc<SinkInner>,
}

#[derive(Default)]
struct SinkInner {
    pending: Mutex<Vec<DeferredRecord>>,
}

impl SinkInner {
    fn drain(&self, response_bytes: Option<u64>) {
        let pending = match self.pending.lock() {
            Ok(mut p) => std::mem::take(&mut *p),
            Err(_) => return,
        };
        for record in pending {
            record(response_bytes);
        }
    }
}

impl Drop for SinkInner {
    /// A sink nobody drained still emits, minus the size it was waiting on.
    /// Losing a record because a transport forgot to drain would be
    /// indistinguishable, to a log reader, from a call that never happened.
    fn drop(&mut self) {
        self.drain(None);
    }
}

impl AccessSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a record for emission once the response size is known.
    pub fn defer(&self, record: DeferredRecord) {
        if let Ok(mut pending) = self.inner.pending.lock() {
            pending.push(record);
        }
    }

    /// Emit every deferred record, stamping `response_bytes` when known.
    pub fn emit(&self, response_bytes: Option<u64>) {
        self.inner.drain(response_bytes);
    }

    /// True when no record is waiting — the transport can skip attaching it.
    pub fn is_empty(&self) -> bool {
        self.inner
            .pending
            .lock()
            .map(|p| p.is_empty())
            .unwrap_or(true)
    }
}

impl std::fmt::Debug for AccessSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessSink")
            .field("pending", &!self.is_empty())
            .finish()
    }
}

/// Per-call statistics accumulated during dispatch.
///
/// All fields start at zero and are incremented by the server as batches
/// are read/written. Values are a best-effort snapshot at the moment the
/// `on_dispatch_end` hook fires.
#[derive(Clone, Debug, Default)]
pub struct CallStatistics {
    pub input_batches: u64,
    pub output_batches: u64,
    pub input_rows: u64,
    pub output_rows: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
}

/// Information passed to a dispatch hook at start and end of each call.
///
/// `Default` exists so a hook test (or a transport that only fills a few
/// fields) can use struct-update syntax and not be broken by a field added
/// later; the defaults are inert, not meaningful.
#[derive(Clone, Debug, Default)]
pub struct DispatchInfo {
    pub method: String,
    pub method_type: &'static str,
    pub server_id: String,
    /// Logical service / protocol name.
    pub protocol: String,
    /// SHA-256 hex of the canonical __describe__ payload (always required in access log).
    pub protocol_hash: String,
    /// Operator-supplied free-form protocol-contract version label (optional).
    pub protocol_version: String,
    pub request_id: String,
    /// Transport-level metadata (HTTP peer addr / pipe contextvar payload).
    pub transport_metadata: Arc<Metadata>,
    /// Authenticated principal name, empty when anonymous.
    pub principal: String,
    /// Authentication domain identifier, empty when anonymous.
    pub auth_domain: String,
    /// True when the call was authenticated.
    pub authenticated: bool,
    /// HTTP transport: remote IP:port. Empty otherwise.
    pub remote_addr: String,
    /// HTTP transport: response status; 0 when not applicable.
    pub http_status: u16,
    /// Self-contained Arrow IPC stream of the request batch (unary + stream init only).
    pub request_data: Vec<u8>,
    /// Stream lifecycle identifier (32-char lowercase hex); empty on unary.
    pub stream_id: String,
    /// True when a stream was cancelled by the client.
    pub cancelled: bool,
    /// Authentication claims — e.g. decoded JWT claims, X.509 cert
    /// extensions, OAuth introspection fields. Cloned from
    /// [`AuthContext::claims`](crate::auth::AuthContext::claims) at
    /// dispatch start. Used by the Sentry hook to enrich user / tag
    /// fields per Python `2d93987`.
    pub claims: std::collections::BTreeMap<String, String>,
    /// On-wire size of the request body as received, **before**
    /// decompression — what the peer actually sent. `None` on transports
    /// with no discrete request body (pipe / unix / tcp), where the framing
    /// is a continuous IPC stream rather than a message with a length.
    ///
    /// Distinct from [`CallStatistics::input_bytes`], which counts logical
    /// Arrow buffers after decoding and is routinely orders of magnitude
    /// larger. One figure is what egress is billed on, the other what the
    /// worker had to process.
    pub request_bytes: Option<u64>,
    /// Bytes uploaded to external storage during this call. Externalised
    /// payloads leave only a pointer batch on the wire, so transport-level
    /// accounting cannot see them at all — and they are frequently the
    /// largest of the three byte figures.
    pub externalized_bytes: u64,
    /// Where a hook parks a record it cannot finish yet. `None` means emit
    /// inline. See [`AccessSink`].
    pub access_sink: Option<AccessSink>,
}

impl DispatchInfo {
    /// Build a `DispatchInfo` from the serving server + request + resolved
    /// auth context. `method_type` is either `"unary"` or `"stream"`.
    pub fn from_request(
        server: &crate::server::RpcServer,
        req: &crate::server::Request,
        method_type: &'static str,
        auth: &crate::auth::AuthContext,
    ) -> Self {
        Self {
            method: req.method.clone(),
            method_type,
            server_id: server.server_id.clone(),
            protocol: server.protocol_name().to_string(),
            protocol_hash: server.protocol_hash().to_string(),
            protocol_version: server.protocol_version().to_string(),
            request_id: req.request_id.clone(),
            transport_metadata: req.metadata.clone(),
            principal: auth.principal.clone(),
            auth_domain: auth.domain.clone(),
            authenticated: auth.authenticated,
            remote_addr: String::new(),
            http_status: 0,
            request_data: Vec::new(),
            stream_id: String::new(),
            cancelled: false,
            claims: auth.claims.clone(),
            request_bytes: None,
            externalized_bytes: 0,
            access_sink: None,
        }
    }
}

/// Token returned by a hook's start callback and passed back to `on_end`.
pub type HookToken = u64;

/// Trait implemented by dispatch observability hooks.
pub trait DispatchHook: Send + Sync {
    /// Invoked just before the handler runs. Return a token that will be
    /// passed to `on_dispatch_end`.
    fn on_dispatch_start(&self, info: &DispatchInfo) -> HookToken;

    /// Invoked once the handler has returned and all logs/batches have been
    /// written to the transport.
    fn on_dispatch_end(
        &self,
        token: HookToken,
        info: &DispatchInfo,
        error: Option<&RpcError>,
        stats: &CallStatistics,
    );
}

/// A shared reference to a boxed hook.
pub type SharedHook = Arc<dyn DispatchHook>;

/// A hook that delegates to two hooks in sequence.
pub struct ChainHook {
    inner: Vec<SharedHook>,
}

impl ChainHook {
    pub fn new(hooks: Vec<SharedHook>) -> Self {
        Self { inner: hooks }
    }
}

impl DispatchHook for ChainHook {
    fn on_dispatch_start(&self, info: &DispatchInfo) -> HookToken {
        // Tokens aren't individually recoverable here; each inner hook gets
        // a best-effort fresh token. Callers that need per-hook tokens can
        // wrap them individually.
        for h in &self.inner {
            let _ = h.on_dispatch_start(info);
        }
        0
    }

    fn on_dispatch_end(
        &self,
        token: HookToken,
        info: &DispatchInfo,
        error: Option<&RpcError>,
        stats: &CallStatistics,
    ) {
        for h in &self.inner {
            h.on_dispatch_end(token, info, error, stats);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct CountingHook {
        starts: AtomicU64,
        ends: AtomicU64,
    }

    impl DispatchHook for CountingHook {
        fn on_dispatch_start(&self, _info: &DispatchInfo) -> HookToken {
            self.starts.fetch_add(1, Ordering::Relaxed) + 1
        }
        fn on_dispatch_end(
            &self,
            _token: HookToken,
            _info: &DispatchInfo,
            _error: Option<&RpcError>,
            _stats: &CallStatistics,
        ) {
            self.ends.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn chain_hook_fans_out() {
        let a = Arc::new(CountingHook {
            starts: AtomicU64::new(0),
            ends: AtomicU64::new(0),
        });
        let b = Arc::new(CountingHook {
            starts: AtomicU64::new(0),
            ends: AtomicU64::new(0),
        });
        let chain = ChainHook::new(vec![a.clone(), b.clone()]);
        let info = DispatchInfo {
            method: "echo".into(),
            method_type: "unary",
            server_id: "test".into(),
            ..Default::default()
        };
        let token = chain.on_dispatch_start(&info);
        chain.on_dispatch_end(token, &info, None, &CallStatistics::default());
        assert_eq!(a.starts.load(Ordering::Relaxed), 1);
        assert_eq!(b.starts.load(Ordering::Relaxed), 1);
        assert_eq!(a.ends.load(Ordering::Relaxed), 1);
        assert_eq!(b.ends.load(Ordering::Relaxed), 1);
    }
}
