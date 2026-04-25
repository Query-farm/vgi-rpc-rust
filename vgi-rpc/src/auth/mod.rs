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
//!   - [`jwt::jwt_authenticate`] (feature `jwt`)
//!   - [`pkce`] (feature `oauth-pkce`)

pub mod bearer;
pub mod mtls;
pub mod oauth;

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
    pub claims: BTreeMap<String, String>,
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
    fn chain_tries_second_when_first_anonymous() {
        let a: Authenticate = Arc::new(|_| Ok(AuthContext::anonymous()));
        let b: Authenticate = Arc::new(|_| Ok(AuthContext::for_principal("bearer", "alice")));
        let chain = chain_authenticate(a, b);
        let req = AuthRequest::anonymous_pipe("echo");
        let ctx = chain(&req).unwrap();
        assert_eq!(ctx.principal, "alice");
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
