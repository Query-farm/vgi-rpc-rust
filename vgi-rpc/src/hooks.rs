//! Dispatch hook interface used by observability integrations.
//!
//! Each call dispatches through `on_dispatch_start` before the handler runs
//! and `on_dispatch_end` after completion (success or error). The hook
//! receives `CallStatistics` tallied by the framework and may record
//! spans / metrics / sentry events.

use std::sync::Arc;

use crate::errors::RpcError;
use crate::wire::Metadata;

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
#[derive(Clone, Debug)]
pub struct DispatchInfo {
    pub method: String,
    pub method_type: &'static str,
    pub server_id: String,
    /// Logical service / protocol name.
    pub protocol: String,
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
            request_id: req.request_id.clone(),
            transport_metadata: Arc::new(req.metadata.clone()),
            principal: auth.principal.clone(),
            auth_domain: auth.domain.clone(),
            authenticated: auth.authenticated,
            remote_addr: String::new(),
            http_status: 0,
            request_data: Vec::new(),
            stream_id: String::new(),
            cancelled: false,
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
            request_id: String::new(),
            transport_metadata: Arc::new(Default::default()),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
        };
        let token = chain.on_dispatch_start(&info);
        chain.on_dispatch_end(token, &info, None, &CallStatistics::default());
        assert_eq!(a.starts.load(Ordering::Relaxed), 1);
        assert_eq!(b.starts.load(Ordering::Relaxed), 1);
        assert_eq!(a.ends.load(Ordering::Relaxed), 1);
        assert_eq!(b.ends.load(Ordering::Relaxed), 1);
    }
}
