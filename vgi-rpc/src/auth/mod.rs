//! Authentication framework.
//!
//! Servers configure an [`Authenticate`] callback (or chain of callbacks)
//! that inspects each incoming request and returns an [`AuthContext`]
//! describing the caller. The context is propagated onto
//! [`crate::CallContext`] so handlers can gate access on `principal`
//! / `auth_domain` / `claims`.
//!
//! Built-in helpers:
//!   - [`bearer::bearer_authenticate`] / [`bearer::bearer_authenticate_static`]
//!   - [`mtls::mtls_authenticate_fingerprint`] / [`mtls::mtls_authenticate_subject`]
//!     / [`mtls::mtls_authenticate_xfcc`]
//!   - [`oauth::OAuthResourceMetadata`] (RFC 9728)
//!   - [`proof::proof_authenticate`] (feature `http`)
//!   - [`jwt::jwt_authenticate`] (feature `jwt`)
//!   - [`pkce`] (feature `oauth-pkce`)
//!
//! The inverse direction -- resolving an opaque credential to a principal *on
//! behalf of a fronting proxy* -- is not authentication and does not live here:
//! it is the co-hosted `vgi_rpc.Identity.v2` protocol, in
//! [`crate::token_identity`].

pub mod bearer;
pub mod identity;
#[cfg(feature = "crypto")]
pub mod identity_bearer;
pub mod iroh;
pub mod mtls;
pub mod oauth;
pub mod spiffe_proxy;
pub mod tailscale;

#[cfg(feature = "mtls-pem")]
pub(crate) mod spiffe_x509;

#[cfg(feature = "http")]
pub mod proof;

#[cfg(feature = "jwt")]
pub mod jwt;

#[cfg(feature = "oauth-pkce")]
pub mod pkce;

#[cfg(feature = "oauth-pkce-server")]
pub mod pkce_server;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::errors::RpcError;

/// Authentication state attached to every RPC call.
///
/// Mirrors the canonical Python frozen dataclass
/// (`vgi_rpc.rpc._common.AuthContext`). Anonymous callers get the value
/// returned by [`AuthContext::anonymous`].
#[derive(Clone, Debug, Default)]
pub struct AuthContext {
    /// Logical auth domain (e.g. "bearer", "mtls", "oauth:issuer.example").
    /// Empty for anonymous callers.
    pub domain: String,
    /// `true` when the call was authenticated (even if `principal` is empty).
    pub authenticated: bool,
    /// Principal name (e.g. subject DN, OAuth `sub` claim, bearer token alias).
    pub principal: String,
    /// Opaque string-keyed claims (e.g. JWT claims, cert extensions).
    ///
    /// A claim that is not a JSON string is stored as its JSON text
    /// (`true`, `1700000000`, `["a","b"]`). When the claim's JSON type
    /// matters, read it from [`claim_values`](Self::claim_values) instead.
    pub claims: BTreeMap<String, String>,
    /// The same claims with their JSON types, for authenticators whose
    /// credential is JSON (a JWT's payload): `email_verified` stays a
    /// boolean and `exp` a number, so code can tell `true` from `"true"`.
    /// Empty for authenticators whose claims are plain strings. Set it with
    /// [`with_claim_value`](Self::with_claim_value), which also keeps
    /// [`claims`](Self::claims) in step; read it with
    /// [`claim_value`](Self::claim_value).
    pub claim_values: BTreeMap<String, serde_json::Value>,
}

impl AuthContext {
    /// Anonymous / unauthenticated context.
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// Build an authenticated context with a principal and optional domain.
    pub fn for_principal(domain: impl Into<String>, principal: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            authenticated: true,
            principal: principal.into(),
            claims: BTreeMap::new(),
            claim_values: BTreeMap::new(),
        }
    }

    /// Require authentication; returns a `PermissionError` when anonymous.
    pub fn require_authenticated(&self) -> crate::errors::Result<()> {
        if self.authenticated {
            Ok(())
        } else {
            Err(RpcError::permission_error("authentication required"))
        }
    }

    /// Attach a claim (fluent builder used mainly by helpers).
    pub fn with_claim(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.claims.insert(key.into(), value.into());
        self
    }

    /// Attach a JSON-typed claim. It lands in
    /// [`claim_values`](Self::claim_values) as given and in
    /// [`claims`](Self::claims) as a string: a JSON string's own text, any
    /// other value's JSON text.
    pub fn with_claim_value(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        let key = key.into();
        let text = match &value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        self.claims.insert(key.clone(), text);
        self.claim_values.insert(key, value);
        self
    }

    /// One claim with its JSON type: from
    /// [`claim_values`](Self::claim_values) when the authenticator recorded
    /// one, otherwise the string claim as a JSON string. `None` when the
    /// claim is absent.
    pub fn claim_value(&self, key: &str) -> Option<serde_json::Value> {
        self.claim_values
            .get(key)
            .cloned()
            .or_else(|| self.claims.get(key).cloned().map(serde_json::Value::String))
    }
}

/// Minimal view of an incoming request exposed to authenticate callbacks.
///
/// Abstracts over transports: HTTP provides headers + peer addr + method;
/// pipe/unix dispatchers use [`AuthRequest::anonymous_pipe`].
#[derive(Debug)]
pub struct AuthRequest<'a> {
    pub method: &'a str,
    pub headers: &'a [(String, String)],
    pub peer_addr: Option<&'a str>,
}

impl<'a> AuthRequest<'a> {
    /// Build a trivial request describing an anonymous pipe/unix call.
    pub fn anonymous_pipe(method: &'a str) -> Self {
        Self {
            method,
            headers: &[],
            peer_addr: None,
        }
    }

    /// Return the value of a header by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Outcome of an authenticate callback.
///
/// `Ok(ctx)` — caller is accepted with the given context (may be anonymous).
/// `Err(_)` — caller is rejected; HTTP maps the error to a 401/403 status.
pub type AuthResult = std::result::Result<AuthContext, RpcError>;

/// Trait object holding an authenticate callback.
///
/// Every enterprise auth helper produces one of these. Use
/// [`chain_authenticate`] to try several in sequence.
pub type Authenticate = Arc<dyn Fn(&AuthRequest<'_>) -> AuthResult + Send + Sync>;

/// Compose two authenticate callbacks: if the first returns anonymous,
/// try the second.
///
/// Matches the Python `chain_authenticate` semantics: first-non-anonymous
/// wins, errors short-circuit.
///
/// "Not my credential, try the next" is `Ok(anonymous)` here — never an `Err` —
/// which is what keeps [`RpcError::auth_unavailable`] intact across the chain.
/// An outage must not be read as a miss and re-emerge as a 401 from the end of
/// the chain: that turns a sidecar restart into a fleet-wide re-login storm and
/// invites callers to negative-cache the outage. Every `Err` propagates
/// unchanged, and the HTTP layer decides between `401` and `503` from the
/// error's type.
pub fn chain_authenticate(a: Authenticate, b: Authenticate) -> Authenticate {
    Arc::new(move |req| {
        let first = (a)(req)?;
        if first.authenticated {
            return Ok(first);
        }
        (b)(req)
    })
}

/// Extract the opaque token from a `Authorization: Bearer <token>` header.
///
/// Case-insensitive prefix match. Returns `None` when the header is absent,
/// does not start with the `Bearer ` scheme, or carries an empty token.
pub(crate) fn extract_bearer<'a>(req: &'a AuthRequest<'a>) -> Option<&'a str> {
    let h = req.header("authorization")?;
    let prefix = "Bearer ";
    if h.len() > prefix.len() && h[..prefix.len()].eq_ignore_ascii_case(prefix) {
        let tok = h[prefix.len()..].trim();
        (!tok.is_empty()).then_some(tok)
    } else {
        None
    }
}

/// Utility: fold an iterator of callbacks into a single chain.
pub fn chain_all<I: IntoIterator<Item = Authenticate>>(cbs: I) -> Option<Authenticate> {
    let mut it = cbs.into_iter();
    let mut acc = it.next()?;
    for next in it {
        acc = chain_authenticate(acc, next);
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_authenticated_rejects_anonymous() {
        let anon = AuthContext::anonymous();
        assert!(anon.require_authenticated().is_err());
        let authd = AuthContext::for_principal("bearer", "alice");
        assert!(authd.require_authenticated().is_ok());
    }

    #[test]
    fn claim_values_keep_json_types_and_string_view() {
        let ctx = AuthContext::for_principal("jwt", "alice")
            .with_claim_value("email_verified", serde_json::json!(true))
            .with_claim_value("exp", serde_json::json!(1_700_000_000_i64))
            .with_claim_value("name", serde_json::json!("Ada"))
            .with_claim("plain", "x");
        assert_eq!(
            ctx.claim_value("email_verified"),
            Some(serde_json::json!(true))
        );
        assert_eq!(
            ctx.claim_value("exp"),
            Some(serde_json::json!(1_700_000_000_i64))
        );
        assert_eq!(
            ctx.claims.get("email_verified").map(String::as_str),
            Some("true")
        );
        assert_eq!(ctx.claims.get("name").map(String::as_str), Some("Ada"));
        assert_eq!(ctx.claim_value("plain"), Some(serde_json::json!("x")));
        assert_eq!(ctx.claim_value("missing"), None);
    }

    #[test]
    fn chain_tries_second_when_first_anonymous() {
        let a: Authenticate = Arc::new(|_| Ok(AuthContext::anonymous()));
        let b: Authenticate = Arc::new(|_| Ok(AuthContext::for_principal("bearer", "alice")));
        let chain = chain_authenticate(a, b);
        let req = AuthRequest::anonymous_pipe("echo");
        let ctx = chain(&req).unwrap();
        assert_eq!(ctx.principal, "alice");
    }

    #[test]
    fn chain_propagates_a_transient_failure_rather_than_advancing() {
        // The distinction the whole definitive/transient split rests on: an
        // authority that could not answer must not look like a miss, or the
        // chain ends in a 401 and every caller re-authenticates against a
        // service that is merely down.
        let down: Authenticate = Arc::new(|_| Err(RpcError::auth_unavailable("jwks fetch failed")));
        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = reached.clone();
        let next: Authenticate = Arc::new(move |_| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(AuthContext::for_principal("bearer", "alice"))
        });
        let req = AuthRequest::anonymous_pipe("echo");

        for chain in [
            chain_authenticate(down.clone(), next.clone()),
            chain_all([down.clone(), next.clone()]).expect("non-empty"),
        ] {
            let err = chain(&req).expect_err("an outage must not resolve to an identity");
            assert!(err.is_auth_unavailable(), "reclassified as {err}");
            assert_eq!(err.retry_after_seconds, Some(5));
        }
        assert!(
            !reached.load(std::sync::atomic::Ordering::SeqCst),
            "the chain advanced past an outage"
        );
    }

    #[test]
    fn chain_uses_first_when_authenticated() {
        let a: Authenticate = Arc::new(|_| Ok(AuthContext::for_principal("mtls", "bob")));
        let b: Authenticate = Arc::new(|_| Ok(AuthContext::for_principal("bearer", "alice")));
        let chain = chain_authenticate(a, b);
        let req = AuthRequest::anonymous_pipe("echo");
        assert_eq!(chain(&req).unwrap().principal, "bob");
    }
}
