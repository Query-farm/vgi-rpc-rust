//! Sentry-style dispatch hook.
//!
//! Enabled by the `sentry` feature. The hook is library-agnostic — it
//! emits structured `tracing::error!` events tagged `vgi_rpc.sentry` on
//! each handler error, plus a counter mirroring Python's
//! `SentryConfig.record_exceptions` behavior. A user wiring the real
//! `sentry` crate layers its `SentryLayer` on top of the `tracing`
//! subscriber.
//!
//! Keeping the integration at the `tracing` boundary means `vgi-rpc`
//! doesn't pull in `sentry`'s heavy transitive dependency tree just to
//! emit errors.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::errors::RpcError;
use crate::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};

/// Configuration for the Sentry hook.
#[derive(Clone, Debug)]
pub struct SentryConfig {
    /// Logical service name attached as a tag.
    pub service_name: String,
    /// Record full exception messages. Set to `false` for public servers
    /// that must not leak error detail into their Sentry project.
    pub record_exceptions: bool,
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            service_name: "vgi-rpc".into(),
            record_exceptions: true,
        }
    }
}

/// Sentry dispatch hook. Bumps an error counter and emits tagged
/// `tracing::error!` events that an upstream `sentry`-tracing layer can
/// capture.
pub struct SentryHook {
    cfg: SentryConfig,
    errors: AtomicU64,
}

impl SentryHook {
    pub fn new(cfg: SentryConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            errors: AtomicU64::new(0),
        })
    }

    pub fn errors_observed(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
}

impl DispatchHook for SentryHook {
    fn on_dispatch_start(&self, _info: &DispatchInfo) -> HookToken {
        0
    }

    fn on_dispatch_end(
        &self,
        _token: HookToken,
        info: &DispatchInfo,
        error: Option<&RpcError>,
        _stats: &CallStatistics,
    ) {
        let Some(err) = error else {
            return;
        };
        self.errors.fetch_add(1, Ordering::Relaxed);
        let message = if self.cfg.record_exceptions {
            err.message.as_str()
        } else {
            ""
        };
        tracing::error!(
            target: "vgi_rpc.sentry",
            service = %self.cfg.service_name,
            method = %info.method,
            method_type = info.method_type,
            server_id = %info.server_id,
            principal = %info.principal,
            auth_domain = %info.auth_domain,
            error_type = %err.error_type,
            error_message = %message,
            traceback = %err.traceback,
            "rpc.exception"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> DispatchInfo {
        DispatchInfo {
            method: "raise".into(),
            method_type: "unary",
            server_id: "srv".into(),
            request_id: String::new(),
            transport_metadata: Arc::new(Vec::new()),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
        }
    }

    #[test]
    fn counts_only_errors() {
        let hook = SentryHook::new(SentryConfig::default());
        let t = hook.on_dispatch_start(&info());
        hook.on_dispatch_end(t, &info(), None, &CallStatistics::default());
        assert_eq!(hook.errors_observed(), 0);

        let err = RpcError::runtime_error("boom");
        let t = hook.on_dispatch_start(&info());
        hook.on_dispatch_end(t, &info(), Some(&err), &CallStatistics::default());
        assert_eq!(hook.errors_observed(), 1);
    }
}
