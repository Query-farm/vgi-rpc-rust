//! Bearer token authentication.
//!
//! A handler takes the opaque token string and returns an [`AuthContext`]
//! (or `None` to fall through). The framework extracts the `Authorization:
//! Bearer <token>` header; empty/missing headers produce anonymous.

use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::{extract_bearer, AuthContext, AuthRequest, AuthResult, Authenticate};

/// Build an authenticate callback from a validator closure.
///
/// - Request carries no `Authorization: Bearer` header → `Anonymous()`.
/// - Validator returns `Some(ctx)` → that context (must be `authenticated`).
/// - Validator returns `None` → anonymous (so a chain can continue).
pub fn bearer_authenticate<F>(validator: F) -> Authenticate
where
    F: Fn(&str) -> Option<AuthContext> + Send + Sync + 'static,
{
    Arc::new(move |req: &AuthRequest<'_>| -> AuthResult {
        let Some(token) = extract_bearer(req) else {
            return Ok(AuthContext::anonymous());
        };
        Ok(validator(token).unwrap_or_else(AuthContext::anonymous))
    })
}

/// Build an authenticate callback from a static map of `token → AuthContext`.
///
/// Convenience for test servers and simple bearer deployments. Not intended
/// for large token sets (linear lookup is fine up to ~10k tokens).
pub fn bearer_authenticate_static(tokens: HashMap<String, AuthContext>) -> Authenticate {
    bearer_authenticate(move |tok| tokens.get(tok).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(headers: Vec<(String, String)>) -> (Vec<(String, String)>, &'static str) {
        (headers, "echo")
    }

    #[test]
    fn static_map_authenticates_known_token() {
        let mut tokens = HashMap::new();
        tokens.insert("t-1".into(), AuthContext::for_principal("bearer", "alice"));
        let auth = bearer_authenticate_static(tokens);

        let hs = vec![("authorization".into(), "Bearer t-1".into())];
        let (hv, m) = req_with(hs);
        let req = AuthRequest {
            method: m,
            headers: &hv,
            peer_addr: None,
        };
        let ctx = auth(&req).unwrap();
        assert!(ctx.authenticated);
        assert_eq!(ctx.principal, "alice");
    }

    #[test]
    fn missing_header_is_anonymous() {
        let auth = bearer_authenticate_static(HashMap::new());
        let req = AuthRequest::anonymous_pipe("echo");
        let ctx = auth(&req).unwrap();
        assert!(!ctx.authenticated);
    }

    #[test]
    fn unknown_token_is_anonymous() {
        let auth = bearer_authenticate(|_| None);
        let hs = vec![("Authorization".into(), "Bearer garbage".into())];
        let (hv, m) = req_with(hs);
        let req = AuthRequest {
            method: m,
            headers: &hv,
            peer_addr: None,
        };
        let ctx = auth(&req).unwrap();
        assert!(!ctx.authenticated);
    }

    #[test]
    fn case_insensitive_prefix() {
        let mut tokens = HashMap::new();
        tokens.insert("abc".into(), AuthContext::for_principal("bearer", "x"));
        let auth = bearer_authenticate_static(tokens);
        let hs = vec![("authorization".into(), "bearer abc".into())];
        let (hv, m) = req_with(hs);
        let req = AuthRequest {
            method: m,
            headers: &hv,
            peer_addr: None,
        };
        assert_eq!(auth(&req).unwrap().principal, "x");
    }
}
