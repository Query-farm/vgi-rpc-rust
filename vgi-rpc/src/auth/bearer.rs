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
///
/// The lookup performs a constant-time comparison against *every* known
/// entry rather than a `HashMap::get` — the underlying string equality
/// would short-circuit on the first mismatching byte and let a remote
/// attacker brute-force a valid token byte-by-byte through response
/// timing. Mirrors Python's `bearer_authenticate_static` (uses
/// `hmac.compare_digest`).
pub fn bearer_authenticate_static(tokens: HashMap<String, AuthContext>) -> Authenticate {
    // Pre-encode known tokens once so the hot path only does compare.
    let encoded: Vec<(Vec<u8>, AuthContext)> = tokens
        .into_iter()
        .map(|(k, v)| (k.into_bytes(), v))
        .collect();
    bearer_authenticate(move |tok| {
        let needle = tok.as_bytes();
        let mut found: Option<AuthContext> = None;
        for (known, ctx) in &encoded {
            // Always run the compare for every entry — short-circuiting
            // on the first hit reintroduces the timing side channel.
            if constant_time_eq(needle, known) && found.is_none() {
                found = Some(ctx.clone());
            }
        }
        found
    })
}

/// Constant-time byte-slice equality. Returns `false` immediately when
/// the lengths differ (parity with Python's `hmac.compare_digest`,
/// which also leaks length); otherwise OR's per-byte XOR so the loop's
/// runtime is independent of where (or whether) the slices match.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
