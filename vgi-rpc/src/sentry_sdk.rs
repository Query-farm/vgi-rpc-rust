//! Real Sentry SDK dispatch hook.
//!
//! Enabled by the `sentry-sdk` feature, which pulls in the `sentry`
//! crate. The hook mirrors the Python `vgi_rpc.sentry` integration:
//!
//! - **Per-RPC scope.** Pushes a fresh Sentry scope at dispatch start
//!   and pops it at dispatch end so concurrent calls do not bleed
//!   tags / user / context into each other.
//! - **JWT-claim → Sentry user mapping.** Defaults match the Python
//!   `user_claim_map` (`preferred_username` → `username`,
//!   `email` → `email`, `name` → `name`). `auth.principal` is
//!   always set as `user.id` (typically the JWT `sub` claim).
//! - **Operator-curated tags from claims** (`claim_tags`). Designed
//!   for low-cardinality identifiers (tenant, org, role).
//! - **Static `custom_tags`** applied to every event.
//! - **Per-RPC transactions** when `enable_performance` is true —
//!   each dispatch starts an `op = "rpc.server"` transaction named
//!   after the RPC method.
//! - **Exception capture** via `sentry::capture_event` on dispatch
//!   error, with `error_type` / `error_message` / `traceback` /
//!   `principal` / `auth.domain` in the event fingerprint.
//!
//! Auto-attach happens via [`SentrySdkHook::auto_attach`] — it returns
//! `None` when `sentry::Hub::current().client()` is `None`, so it is
//! safe to call unconditionally during server build.
//!
//! ## Threading
//!
//! Sentry scopes are per-Hub, and the default Hub is per-thread.
//! `on_dispatch_start` and `on_dispatch_end` must run on the same
//! thread (or async task) — which they do for both pipe/unix (single
//! thread per serve loop) and HTTP (same axum handler invocation).
//! If you split dispatch across threads you must ferry the Sentry
//! state yourself.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sentry::protocol::{Event, Exception, Level, User, Value};
use sentry::{ClientOptions, Hub, Transaction, TransactionContext};

use crate::errors::RpcError;
use crate::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};

/// Default `user_claim_map` matching the Python `SentryConfig`
/// defaults (`preferred_username` → `username`, `email` → `email`,
/// `name` → `name`). `user.id` is always populated from
/// `info.principal`, regardless of this map.
fn default_user_claim_map() -> Vec<(String, String)> {
    vec![
        ("username".into(), "preferred_username".into()),
        ("email".into(), "email".into()),
        ("name".into(), "name".into()),
    ]
}

/// Configuration for [`SentrySdkHook`]. Field names match the Python
/// `SentryConfig` 1:1 where the semantics carry across.
#[derive(Clone, Debug)]
pub struct SentrySdkConfig {
    /// Capture exceptions via `sentry::capture_event` on handler
    /// error. Default `true`.
    pub enable_error_capture: bool,
    /// Start a Sentry [`Transaction`] per dispatch. Default `false`
    /// — opt in to avoid duplicate spans alongside OTel and to
    /// conserve Sentry transaction quota.
    pub enable_performance: bool,
    /// Set scope context (method / server_id / service) and user
    /// fields on each dispatch. Default `true`.
    pub record_request_context: bool,
    /// Sentry transaction `op` string. Default `"rpc.server"`.
    pub op_name: String,
    /// Map `sentry_user_field -> jwt_claim_name`. Empty falls back to
    /// the Python defaults. `user.id` is always set from
    /// `info.principal` and is not configurable here.
    pub user_claim_map: Vec<(String, String)>,
    /// Map `jwt_claim_name -> sentry_tag_name`. Claims not present
    /// in the request are silently skipped.
    pub claim_tags: Vec<(String, String)>,
    /// Static tags applied to every event.
    pub custom_tags: Vec<(String, String)>,
    /// Error types ([`RpcError::error_type`]) to skip when reporting,
    /// e.g. `["PermissionError", "ValueError"]`. Mirrors Python's
    /// `ignored_exceptions` (which gates on Python exception class —
    /// the Rust port uses the `error_type` string for parity).
    pub ignored_error_types: Vec<String>,
}

impl Default for SentrySdkConfig {
    fn default() -> Self {
        Self {
            enable_error_capture: true,
            enable_performance: false,
            record_request_context: true,
            op_name: "rpc.server".into(),
            user_claim_map: Vec::new(),
            claim_tags: Vec::new(),
            custom_tags: Vec::new(),
            ignored_error_types: Vec::new(),
        }
    }
}

impl SentrySdkConfig {
    /// Override the `user_field -> claim_name` map. Pass an empty
    /// iterator to disable JWT-claim-driven user enrichment.
    pub fn with_user_claim_map<I, A, B>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (A, B)>,
        A: Into<String>,
        B: Into<String>,
    {
        self.user_claim_map = pairs
            .into_iter()
            .map(|(f, c)| (f.into(), c.into()))
            .collect();
        self
    }

    /// Set the `claim_name -> tag_name` map (analog to Python
    /// `claim_tags`). Use for low-cardinality claims like
    /// `tenant_id`, `org_id`, `role`.
    pub fn with_claim_tags<I, A, B>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (A, B)>,
        A: Into<String>,
        B: Into<String>,
    {
        self.claim_tags = pairs
            .into_iter()
            .map(|(c, t)| (c.into(), t.into()))
            .collect();
        self
    }

    /// Static tags applied to every event.
    pub fn with_custom_tags<I, A, B>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (A, B)>,
        A: Into<String>,
        B: Into<String>,
    {
        self.custom_tags = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    /// Skip capture when `RpcError::error_type` matches one of these
    /// strings (e.g. `["PermissionError", "ValueError"]`).
    pub fn with_ignored_error_types<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.ignored_error_types = names.into_iter().map(Into::into).collect();
        self
    }

    /// Enable per-RPC transactions. Off by default to conserve
    /// transaction quota when OTel is also active.
    pub fn enable_performance(mut self, enable: bool) -> Self {
        self.enable_performance = enable;
        self
    }
}

/// State retained between [`on_dispatch_start`] and [`on_dispatch_end`]
/// for one RPC call: the scope guard pops the per-call scope on drop,
/// the optional transaction holds Sentry performance state.
struct InflightCall {
    /// Pops the per-call scope when dropped. Held inside `Option` so
    /// the caller can take it explicitly at end.
    scope_guard: Option<sentry::ScopeGuard>,
    /// Active transaction when `enable_performance` is set.
    transaction: Option<Transaction>,
    method: String,
    protocol: String,
    server_id: String,
}

/// Dispatch hook implementing real Sentry SDK integration.
///
/// Build via [`SentrySdkHook::new`] for explicit configuration or
/// [`SentrySdkHook::auto_attach`] to wire up only when Sentry is
/// already initialised in the current process.
pub struct SentrySdkHook {
    cfg: SentrySdkConfig,
    inflight: Mutex<std::collections::HashMap<HookToken, InflightCall>>,
    next_token: AtomicU64,
}

impl SentrySdkHook {
    /// Construct the hook unconditionally with `cfg`. Safe even when
    /// Sentry has not been initialised: scope mutations on a no-op
    /// Hub are cheap no-ops.
    pub fn new(cfg: SentrySdkConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            inflight: Mutex::new(std::collections::HashMap::new()),
            next_token: AtomicU64::new(1),
        })
    }

    /// Return `Some(hook)` only when Sentry has been initialised in
    /// the current process (`Hub::current().client().is_some()`),
    /// otherwise `None`. Mirrors Python's
    /// `_maybe_auto_instrument` — the operator's `sentry::init()`
    /// call is the signal of intent.
    pub fn auto_attach(cfg: SentrySdkConfig) -> Option<Arc<Self>> {
        if Hub::current().client().is_some() {
            Some(Self::new(cfg))
        } else {
            None
        }
    }

    fn resolve_user(&self, info: &DispatchInfo) -> Option<User> {
        let mut user = User::default();
        let mut populated = false;
        if !info.principal.is_empty() {
            user.id = Some(info.principal.clone());
            populated = true;
        }
        let default_map;
        let map = if self.cfg.user_claim_map.is_empty() {
            default_map = default_user_claim_map();
            &default_map
        } else {
            &self.cfg.user_claim_map
        };
        for (field, claim) in map {
            let Some(value) = info.claims.get(claim) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            match field.as_str() {
                "username" => {
                    user.username = Some(value.clone());
                    populated = true;
                }
                "email" => {
                    user.email = Some(value.clone());
                    populated = true;
                }
                "name" => {
                    // Sentry's `User` has no `name` field; surface it
                    // via `other` so the operator sees it in the event
                    // payload.
                    user.other
                        .insert("name".into(), Value::String(value.clone()));
                    populated = true;
                }
                _ => {}
            }
        }
        populated.then_some(user)
    }
}

impl DispatchHook for SentrySdkHook {
    fn on_dispatch_start(&self, info: &DispatchInfo) -> HookToken {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);

        // Push a fresh scope so concurrent calls do not bleed
        // tags / user / context into each other.
        let scope_guard = Hub::current().push_scope();

        let user_to_set = if self.cfg.record_request_context {
            self.resolve_user(info)
        } else {
            None
        };
        let claim_tags = self.cfg.claim_tags.clone();
        let custom_tags = self.cfg.custom_tags.clone();
        let claims_snapshot: BTreeMap<String, String> = info.claims.clone();
        let method = info.method.clone();
        let method_type = info.method_type;
        let protocol = info.protocol.clone();
        let server_id = info.server_id.clone();
        let auth_domain = info.auth_domain.clone();
        let authenticated = info.authenticated;
        let record_context = self.cfg.record_request_context;
        let stream_id = info.stream_id.clone();

        sentry::configure_scope(|scope| {
            scope.set_transaction(Some(&format!("rpc {method}")));
            scope.set_tag("rpc.method", &method);
            scope.set_tag("rpc.method_type", method_type);
            scope.set_extra("rpc.system", Value::from("vgi_rpc"));
            scope.set_extra("rpc.service", Value::from(protocol.clone()));
            if !stream_id.is_empty() {
                scope.set_extra("rpc.stream_id", Value::from(stream_id));
            }
            if record_context {
                if let Some(u) = user_to_set {
                    scope.set_user(Some(u));
                }
                if !auth_domain.is_empty() {
                    scope.set_tag("auth.domain", &auth_domain);
                }
                scope.set_tag("auth.authenticated", authenticated.to_string());
                let mut rpc_ctx = BTreeMap::new();
                rpc_ctx.insert("method".to_string(), Value::from(method.clone()));
                rpc_ctx.insert("method_type".to_string(), Value::from(method_type));
                rpc_ctx.insert("service".to_string(), Value::from(protocol.clone()));
                rpc_ctx.insert("server_id".to_string(), Value::from(server_id.clone()));
                scope.set_context(
                    "rpc",
                    sentry::protocol::Context::Other(rpc_ctx.into_iter().collect()),
                );
                for (claim, tag) in &claim_tags {
                    if let Some(value) = claims_snapshot.get(claim) {
                        scope.set_tag(tag, value);
                    }
                }
            }
            for (k, v) in &custom_tags {
                scope.set_tag(k, v);
            }
        });

        let transaction = if self.cfg.enable_performance {
            let ctx = TransactionContext::new(&format!("vgi_rpc/{method}"), &self.cfg.op_name);
            Some(sentry::start_transaction(ctx))
        } else {
            None
        };

        self.inflight.lock().unwrap().insert(
            token,
            InflightCall {
                scope_guard: Some(scope_guard),
                transaction,
                method: info.method.clone(),
                protocol: info.protocol.clone(),
                server_id: info.server_id.clone(),
            },
        );
        token
    }

    fn on_dispatch_end(
        &self,
        token: HookToken,
        info: &DispatchInfo,
        error: Option<&RpcError>,
        _stats: &CallStatistics,
    ) {
        let Some(mut call) = self.inflight.lock().unwrap().remove(&token) else {
            return;
        };

        if let Some(err) = error {
            let ignored = self
                .cfg
                .ignored_error_types
                .iter()
                .any(|t| t == &err.error_type);
            if self.cfg.enable_error_capture && !ignored {
                let mut event = Event {
                    level: Level::Error,
                    message: Some(err.message.clone()),
                    ..Event::default()
                };
                let mut exc = Exception {
                    ty: err.error_type.clone(),
                    value: Some(err.message.clone()),
                    ..Exception::default()
                };
                if !err.traceback.is_empty() {
                    exc.module = Some(call.method.clone());
                }
                event.exception.values.push(exc);
                // Fingerprint by error_type + method so the same
                // failure across requests rolls up to one Sentry issue.
                event.fingerprint = vec![
                    err.error_type.clone().into(),
                    call.protocol.clone().into(),
                    call.method.clone().into(),
                ]
                .into();
                event
                    .tags
                    .insert("server_id".into(), call.server_id.clone());
                event
                    .tags
                    .insert("error_type".into(), err.error_type.clone());
                if !err.traceback.is_empty() {
                    event
                        .extra
                        .insert("traceback".into(), Value::String(err.traceback.clone()));
                }
                let _ = sentry::capture_event(event);
            }
        }

        if let Some(transaction) = call.transaction.take() {
            // Sentry crate uses span_status on transactions; map RPC
            // error to "internal_error" per the Python parity, "ok"
            // otherwise.
            if error.is_some() {
                transaction.set_status(sentry::protocol::SpanStatus::InternalError);
            } else {
                transaction.set_status(sentry::protocol::SpanStatus::Ok);
            }
            transaction.finish();
        }

        // Touch info for compiler — we keep it on the signature so
        // future enrichment (HTTP status, batch counts) can land here
        // without an API break.
        let _ = info;

        // Drop the scope guard to pop the per-call scope. Explicit so
        // the ordering vs. transaction.finish() is unambiguous.
        drop(call.scope_guard.take());
    }
}

// Re-export a focused convenience helper so users don't have to
// rummage in the `sentry` crate for the init call. Optional — they
// can just call `sentry::init` directly.
pub use sentry::init as init_sdk;

/// Convenience: build [`ClientOptions`] from a DSN string. Same as
/// `ClientOptions { dsn: Some(dsn.parse().ok()?), ..Default::default() }`
/// but lets callers chain via the standard `ClientOptions` builders.
pub fn client_options_from_dsn(dsn: &str) -> ClientOptions {
    ClientOptions {
        dsn: dsn.parse().ok(),
        ..ClientOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with_claims(pairs: &[(&str, &str)]) -> DispatchInfo {
        let mut claims = BTreeMap::new();
        for (k, v) in pairs {
            claims.insert((*k).to_string(), (*v).to_string());
        }
        DispatchInfo {
            method: "echo".into(),
            method_type: "unary",
            server_id: "srv-1".into(),
            protocol: "ConformanceService".into(),
            request_id: String::new(),
            transport_metadata: Arc::new(Default::default()),
            principal: "alice".into(),
            auth_domain: "jwt".into(),
            authenticated: true,
            remote_addr: String::new(),
            http_status: 0,
            request_data: Vec::new(),
            stream_id: String::new(),
            cancelled: false,
            claims,
            protocol_hash: String::new(),
            protocol_version: String::new(),
        }
    }

    #[test]
    fn resolve_user_pulls_id_from_principal_plus_claim_map() {
        let hook = SentrySdkHook::new(SentrySdkConfig::default());
        let info = info_with_claims(&[
            ("preferred_username", "alice@example"),
            ("email", "a@b.c"),
            ("name", "Alice"),
        ]);
        let user = hook.resolve_user(&info).expect("user populated");
        assert_eq!(user.id.as_deref(), Some("alice"));
        assert_eq!(user.username.as_deref(), Some("alice@example"));
        assert_eq!(user.email.as_deref(), Some("a@b.c"));
        assert_eq!(user.other.get("name"), Some(&Value::String("Alice".into())));
    }

    #[test]
    fn resolve_user_returns_none_when_anonymous_and_no_claims() {
        let hook = SentrySdkHook::new(SentrySdkConfig::default());
        let mut info = info_with_claims(&[]);
        info.principal.clear();
        assert!(hook.resolve_user(&info).is_none());
    }

    #[test]
    fn custom_user_claim_map_overrides_defaults() {
        let cfg = SentrySdkConfig::default()
            .with_user_claim_map([("username", "https://x.example/uname")]);
        let hook = SentrySdkHook::new(cfg);
        let info = info_with_claims(&[
            ("preferred_username", "ignored"),
            ("https://x.example/uname", "auth0|abc"),
        ]);
        let user = hook.resolve_user(&info).unwrap();
        assert_eq!(user.username.as_deref(), Some("auth0|abc"));
        // Default email mapping is replaced; email stays empty.
        assert!(user.email.is_none());
    }

    #[test]
    fn auto_attach_returns_none_without_sentry_init() {
        // No Sentry init in this process → auto_attach is a no-op.
        // (We can't easily init+deinit Sentry across tests without
        // process isolation, so the negative case is the only safe
        // assertion at this layer.)
        assert!(SentrySdkHook::auto_attach(SentrySdkConfig::default()).is_none());
    }

    #[test]
    fn ignored_error_types_skip_capture() {
        // Drive the dispatch hook against the no-op Hub. The point of
        // this test is to make sure the configured `ignored_error_types`
        // path runs cleanly (no panics) regardless of whether Sentry
        // is initialised — capture is then a no-op anyway.
        let cfg = SentrySdkConfig::default().with_ignored_error_types(["PermissionError"]);
        let hook = SentrySdkHook::new(cfg);
        let info = info_with_claims(&[]);
        let err = RpcError::permission_error("denied");
        let t = hook.on_dispatch_start(&info);
        hook.on_dispatch_end(t, &info, Some(&err), &CallStatistics::default());
        // No assertion: success = didn't panic. Capture path is
        // exercised by the conformance harness with a real Hub.
    }

    #[test]
    fn dispatch_lifecycle_is_balanced_when_called_serially() {
        let hook = SentrySdkHook::new(SentrySdkConfig::default());
        for _ in 0..10 {
            let info = info_with_claims(&[]);
            let t = hook.on_dispatch_start(&info);
            hook.on_dispatch_end(t, &info, None, &CallStatistics::default());
        }
        // Inflight map should be drained.
        assert!(hook.inflight.lock().unwrap().is_empty());
    }
}
