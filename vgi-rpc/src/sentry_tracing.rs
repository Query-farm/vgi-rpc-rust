//! Lightweight, tracing-based Sentry dispatch hook.
//!
//! Enabled by the `sentry-tracing` feature. The hook is library-agnostic — it
//! emits structured `tracing::error!` events tagged `vgi_rpc.sentry` on
//! each handler error, plus a counter mirroring Python's
//! `TracingSentryConfig.record_exceptions` behavior. A user wiring the real
//! `sentry` crate layers `sentry-tracing` on top of the `tracing`
//! subscriber and the user / tag / transaction fields below propagate
//! automatically — matching the Python `sentry.py` integration's
//! "users must initialize Sentry themselves" pattern.
//!
//! Keeping the integration at the `tracing` boundary means `vgi-rpc`
//! doesn't pull in `sentry`'s heavy transitive dependency tree just to
//! emit errors.
//!
//! The hook understands the same JWT-claim mapping Python's `2d93987`
//! introduced — `sub`/`email`/`name` claims become the Sentry user
//! id/email/username, and operator-selected extra claims become tags.
//! Configure via [`TracingSentryConfig::with_user_claims`] and
//! [`TracingSentryConfig::with_tag_claims`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::errors::RpcError;
use crate::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};

/// Default mapping from JWT claim name → Sentry user field. Mirrors
/// Python's defaults: `sub` → `id`, `email` → `email`, `name` →
/// `username`. Used when [`TracingSentryConfig::user_claims`] is empty.
fn default_user_claim_map() -> Vec<(String, String)> {
    vec![
        ("sub".into(), "id".into()),
        ("email".into(), "email".into()),
        ("name".into(), "username".into()),
    ]
}

/// Configuration for the Sentry hook.
#[derive(Clone, Debug)]
pub struct TracingSentryConfig {
    /// Logical service name attached as a tag.
    pub service_name: String,
    /// Record full exception messages. Set to `false` for public servers
    /// that must not leak error detail into their Sentry project.
    pub record_exceptions: bool,
    /// Pairs of `(claim_name, sentry_user_field)`. When the request's
    /// `AuthContext` carries the named claim, its value is emitted as
    /// the corresponding Sentry user field (`id`, `email`, or
    /// `username`). Empty falls back to the Python defaults
    /// (`sub` → `id`, `email` → `email`, `name` → `username`).
    pub user_claims: Vec<(String, String)>,
    /// Claim names to surface as `rpc.claim.<name>` tags packed into
    /// the `tag.claims` JSON field. Empty by default — operators opt
    /// in per claim because leaking attributes into a shared
    /// observability project can be a privacy issue.
    pub tag_claims: Vec<String>,
}

impl Default for TracingSentryConfig {
    fn default() -> Self {
        Self {
            service_name: "vgi-rpc".into(),
            record_exceptions: true,
            user_claims: Vec::new(),
            tag_claims: Vec::new(),
        }
    }
}

impl TracingSentryConfig {
    /// Override the JWT claim → Sentry user field map. Pass an empty
    /// iterator to disable user enrichment.
    pub fn with_user_claims<I, A, B>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (A, B)>,
        A: Into<String>,
        B: Into<String>,
    {
        self.user_claims = pairs
            .into_iter()
            .map(|(c, f)| (c.into(), f.into()))
            .collect();
        self
    }

    /// Override the list of claim names emitted as Sentry tags. Values
    /// land inside the `tag.claims` JSON object on each event so a
    /// sentry-tracing layer can iterate and call `scope.set_tag`.
    pub fn with_tag_claims<I, S>(mut self, claims: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tag_claims = claims.into_iter().map(Into::into).collect();
        self
    }
}

/// Sentry dispatch hook. Bumps an error counter and emits tagged
/// `tracing::error!` events that an upstream `sentry-tracing` layer
/// can capture as Sentry events. Successful calls additionally emit a
/// `tracing::info!` event tagged with `transaction = info.method` so
/// the same layer can associate a transaction with each RPC method.
pub struct TracingSentryHook {
    cfg: TracingSentryConfig,
    errors: AtomicU64,
}

impl TracingSentryHook {
    pub fn new(cfg: TracingSentryConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            errors: AtomicU64::new(0),
        })
    }

    pub fn errors_observed(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Resolve user fields from the request's claims, using the
    /// configured map (or the Python defaults when unset).
    fn resolve_user(&self, claims: &std::collections::BTreeMap<String, String>) -> UserFields {
        let default_map;
        let map = if self.cfg.user_claims.is_empty() {
            default_map = default_user_claim_map();
            &default_map
        } else {
            &self.cfg.user_claims
        };
        let mut out = UserFields::default();
        for (claim, field) in map {
            let Some(value) = claims.get(claim) else {
                continue;
            };
            match field.as_str() {
                "id" => out.id = value.clone(),
                "email" => out.email = value.clone(),
                "username" => out.username = value.clone(),
                _ => {}
            }
        }
        out
    }

    /// Pack configured tag claims into a JSON object so the tracing
    /// event stays single-field rather than ballooning the event-field
    /// count. A sentry-tracing layer can unpack and call set_tag per
    /// entry.
    fn tag_claims_json(&self, claims: &std::collections::BTreeMap<String, String>) -> String {
        let obj: serde_json::Map<String, serde_json::Value> = self
            .cfg
            .tag_claims
            .iter()
            .filter_map(|name| {
                claims
                    .get(name)
                    .map(|v| (name.clone(), serde_json::Value::String(v.clone())))
            })
            .collect();
        serde_json::Value::Object(obj).to_string()
    }
}

#[derive(Default)]
struct UserFields {
    id: String,
    email: String,
    username: String,
}

impl DispatchHook for TracingSentryHook {
    fn on_dispatch_start(&self, info: &DispatchInfo) -> HookToken {
        let user = self.resolve_user(&info.claims);
        tracing::info!(
            target: "vgi_rpc.sentry",
            service = %self.cfg.service_name,
            transaction = %info.method,
            method = %info.method,
            method_type = info.method_type,
            server_id = %info.server_id,
            principal = %info.principal,
            auth_domain = %info.auth_domain,
            authenticated = info.authenticated,
            user.id = %user.id,
            user.email = %user.email,
            user.username = %user.username,
            "rpc.start"
        );
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
        let user = self.resolve_user(&info.claims);
        let tag_claims = self.tag_claims_json(&info.claims);

        tracing::error!(
            target: "vgi_rpc.sentry",
            service = %self.cfg.service_name,
            transaction = %info.method,
            method = %info.method,
            method_type = info.method_type,
            server_id = %info.server_id,
            principal = %info.principal,
            auth_domain = %info.auth_domain,
            authenticated = info.authenticated,
            user.id = %user.id,
            user.email = %user.email,
            user.username = %user.username,
            tag.claims = %tag_claims,
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
    use std::collections::BTreeMap;

    fn info_with_claims(pairs: &[(&str, &str)]) -> DispatchInfo {
        let mut claims = BTreeMap::new();
        for (k, v) in pairs {
            claims.insert((*k).to_string(), (*v).to_string());
        }
        DispatchInfo {
            method: "raise".into(),
            method_type: "unary",
            server_id: "srv".into(),
            protocol: String::new(),
            request_id: String::new(),
            transport_metadata: Arc::new(Default::default()),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
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

    fn info() -> DispatchInfo {
        info_with_claims(&[])
    }

    #[test]
    fn counts_only_errors() {
        let hook = TracingSentryHook::new(TracingSentryConfig::default());
        let t = hook.on_dispatch_start(&info());
        hook.on_dispatch_end(t, &info(), None, &CallStatistics::default());
        assert_eq!(hook.errors_observed(), 0);

        let err = RpcError::runtime_error("boom");
        let t = hook.on_dispatch_start(&info());
        hook.on_dispatch_end(t, &info(), Some(&err), &CallStatistics::default());
        assert_eq!(hook.errors_observed(), 1);
    }

    #[test]
    fn default_user_claim_map_maps_sub_email_name() {
        let hook = TracingSentryHook::new(TracingSentryConfig::default());
        let info = info_with_claims(&[
            ("sub", "user-42"),
            ("email", "a@b.c"),
            ("name", "alice"),
            ("ignored", "x"),
        ]);
        let user = hook.resolve_user(&info.claims);
        assert_eq!(user.id, "user-42");
        assert_eq!(user.email, "a@b.c");
        assert_eq!(user.username, "alice");
    }

    #[test]
    fn custom_user_claim_map_overrides_defaults() {
        let cfg = TracingSentryConfig::default().with_user_claims([("https://x.example/id", "id")]);
        let hook = TracingSentryHook::new(cfg);
        let info = info_with_claims(&[
            ("sub", "ignored-default-mapping"),
            ("https://x.example/id", "auth0|abc"),
        ]);
        let user = hook.resolve_user(&info.claims);
        assert_eq!(user.id, "auth0|abc");
        // `sub` no longer maps when an explicit map is supplied.
        assert!(user.email.is_empty());
        assert!(user.username.is_empty());
    }

    #[test]
    fn tag_claims_round_trip_through_json_field() {
        let cfg = TracingSentryConfig::default().with_tag_claims(["org_id", "tenant"]);
        let hook = TracingSentryHook::new(cfg);
        let info = info_with_claims(&[("org_id", "org-7"), ("ignored", "x")]);
        let s = hook.tag_claims_json(&info.claims);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["org_id"], "org-7");
        // Unspecified tags are absent rather than emitting empty strings.
        assert!(v.get("tenant").is_none());
        // Unconfigured claims are not surfaced.
        assert!(v.get("ignored").is_none());
    }
}
