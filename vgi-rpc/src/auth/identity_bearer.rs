//! Bearer authenticators that close the `vgi_rpc.Identity.v1` loop
//! (WIRE_PROTOCOL.md §16 "Accepting identity credentials", IDENTITY_V1_SPEC §9).
//!
//! `issue_grant` mints a credential "presented later by unattended automation
//! as an ordinary bearer", and `resolve_token` answers which principal an
//! opaque credential is -- but until this module neither fed back into
//! authentication. Two authenticators do:
//!
//! - [`grant_authenticate`] accepts the framework's own sealed grants;
//! - [`resolve_token_authenticate`] asks the worker's `resolve_token`.
//!
//! [`compose_identity_authenticate`] puts them after the deployment's own
//! authenticator in the normative order -- the deployment's (JWT, static
//! bearer, ...), then sealed grants (a cheap prefix check), then
//! `resolve_token` -- and the HTTP transport calls it automatically for a
//! server hosting `vgi_rpc.Identity.v1` with grant keys or a resolver.
//!
//! Routing is by prefix and strict in both directions. A token without the
//! `vgig1.` prefix never reaches the grant verifier. A token *with* it that
//! does not verify is refused outright (401) and never reaches
//! `resolve_token`: a forged or stale grant must not get a second chance from
//! a resolver that might answer for it.
//!
//! In this port "not my credential" is `Ok(anonymous)` (see
//! [`chain_authenticate`](super::chain_authenticate)); a refusal is `Err`.

use std::sync::Arc;

use crate::auth::{extract_bearer, AuthContext, AuthRequest, Authenticate};
use crate::errors::RpcError;
use crate::grants::{verify_grant_token, GrantKeys, GRANT_TOKEN_PREFIX};
use crate::token_identity::{reject_jws_shaped, TokenResolver};
use crate::unauthorized::AuthReason;

/// `AuthContext::domain` of a grant-authenticated request.
pub const GRANT_AUTH_DOMAIN: &str = "grant";
/// `AuthContext::domain` of a request authenticated through `resolve_token`.
pub const TOKEN_AUTH_DOMAIN: &str = "token";

/// The `scopes` claim of a grant-authenticated request: a JSON array of
/// strings, as text. This port's [`AuthContext::claims`] is string-valued, so
/// a list-valued claim travels as its JSON spelling; decode it with
/// [`grant_scopes`].
pub const GRANT_SCOPES_CLAIM: &str = "scopes";

/// The scopes a grant-authenticated caller carries, decoded from the
/// [`GRANT_SCOPES_CLAIM`] claim. Empty for any other caller.
pub fn grant_scopes(auth: &AuthContext) -> Vec<String> {
    if auth.domain != GRANT_AUTH_DOMAIN {
        return Vec::new();
    }
    auth.claims
        .get(GRANT_SCOPES_CLAIM)
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Accept the framework's own sealed grants as bearer credentials.
///
/// The resulting `AuthContext` has `domain = "grant"`, the grant's principal,
/// and claims `grant_id`, `purpose` and `scopes` -- and **no `auth_time`**, so
/// a grant-authenticated caller cannot `issue_grant`: grants never mint grants.
///
/// A bearer without the exact `vgig1.` prefix (or no bearer) is not this
/// authenticator's: `Ok(anonymous)`, and the chain moves on. One with it that
/// does not verify is `Err` with `invalid_credential` -- or
/// `expired_credential` when it is authentic but outside its lifetime -- which
/// stops the chain with a 401.
pub fn grant_authenticate(keys: GrantKeys) -> Authenticate {
    Arc::new(move |req: &AuthRequest<'_>| {
        let Some(token) = extract_bearer(req) else {
            return Ok(AuthContext::anonymous());
        };
        if !token.starts_with(GRANT_TOKEN_PREFIX) {
            return Ok(AuthContext::anonymous());
        }
        match verify_grant_token(&keys, token, None) {
            Ok(claims) => Ok(AuthContext {
                domain: GRANT_AUTH_DOMAIN.to_string(),
                authenticated: true,
                principal: claims.principal,
                claims: [
                    ("grant_id".to_string(), claims.grant_id),
                    ("purpose".to_string(), claims.purpose),
                    (
                        GRANT_SCOPES_CLAIM.to_string(),
                        serde_json::to_string(&claims.scopes).unwrap_or_else(|_| "[]".into()),
                    ),
                ]
                .into_iter()
                .collect(),
            }),
            Err(invalid) => Err(RpcError::auth_failure(
                if invalid.expired {
                    AuthReason::ExpiredCredential
                } else {
                    AuthReason::InvalidCredential
                },
                format!("sealed grant rejected: {invalid}"),
            )),
        }
    })
}

/// Accept bearer credentials the worker's `resolve_token` resolves.
///
/// A resolved identity authenticates with `domain = "token"`, its principal,
/// and `{"token_name": ...}` (no `auth_time`, so such a caller cannot mint
/// either). `Ok(None)` from the hook means "unknown" and is not this
/// authenticator's: the chain falls through, ending in 401 if nothing else
/// accepts. Any error from the hook -- the transport-auth unavailable error,
/// the identity-unavailable error, or a fault -- is "not knowable": 503 with
/// the hook's `Retry-After`, never 401, so a blip does not log a fleet out.
///
/// The hook never sees a `vgig1.` token, a JWS-shaped token, a blank one, or
/// one over 4096 UTF-8 bytes -- the shape guards `introspect_token` applies.
pub fn resolve_token_authenticate(resolve_token: TokenResolver) -> Authenticate {
    Arc::new(move |req: &AuthRequest<'_>| {
        let Some(token) = extract_bearer(req) else {
            return Ok(AuthContext::anonymous());
        };
        if token.starts_with(GRANT_TOKEN_PREFIX) || reject_jws_shaped(token).is_err() {
            return Ok(AuthContext::anonymous());
        }
        match (resolve_token)(token) {
            Ok(Some(identity)) => Ok(AuthContext {
                domain: TOKEN_AUTH_DOMAIN.to_string(),
                authenticated: true,
                principal: identity.principal,
                claims: [("token_name".to_string(), identity.token_name)]
                    .into_iter()
                    .collect(),
            }),
            Ok(None) => Ok(AuthContext::anonymous()),
            Err(err) => {
                let retry = err
                    .retry_after_seconds
                    .unwrap_or(crate::errors::DEFAULT_AUTH_RETRY_AFTER_SECONDS);
                Err(RpcError::auth_unavailable(if err.is_auth_unavailable() {
                    err.message
                } else {
                    "identity lookup failed".to_string()
                })
                .with_retry_after(retry))
            }
        }
    })
}

/// Append the identity bearer authenticators after the deployment's own.
///
/// Order (IDENTITY_V1_SPEC §9.3): `deployment`, then sealed grants, then
/// `resolve_token`. With neither identity source, `deployment` is returned
/// unchanged. Otherwise:
///
/// - the deployment's acceptance wins; its *outage* (`auth_unavailable`)
///   propagates (503); its *rejection* falls through to the identity members
///   -- this port's authenticators do not separate "not mine" from "invalid",
///   and a JWT verifier rejecting a sealed grant must not stop the grant from
///   being tried -- and stands if none of them accepts;
/// - a request with no `Authorization` header that nothing accepted stays
///   anonymous, exactly as before; one carrying a credential that nothing
///   accepted is 401.
pub fn compose_identity_authenticate(
    deployment: Option<Authenticate>,
    grant_keys: Option<GrantKeys>,
    resolve_token: Option<TokenResolver>,
) -> Option<Authenticate> {
    let mut members: Vec<Authenticate> = Vec::new();
    if let Some(keys) = grant_keys {
        members.push(grant_authenticate(keys));
    }
    if let Some(resolver) = resolve_token {
        members.push(resolve_token_authenticate(resolver));
    }
    if members.is_empty() {
        return deployment;
    }
    Some(Arc::new(move |req: &AuthRequest<'_>| {
        let mut deployment_refusal = None;
        if let Some(first) = deployment.as_ref() {
            match first(req) {
                Ok(ctx) if ctx.authenticated => return Ok(ctx),
                Ok(_) => {}
                Err(err) if err.is_auth_unavailable() => return Err(err),
                Err(err) => deployment_refusal = Some(err),
            }
        }
        for member in &members {
            let ctx = member(req)?;
            if ctx.authenticated {
                return Ok(ctx);
            }
        }
        if let Some(err) = deployment_refusal {
            return Err(err);
        }
        if req.header("authorization").is_some() {
            return Err(RpcError::auth_failure(
                AuthReason::InvalidCredential,
                "bearer credential not accepted",
            ));
        }
        Ok(AuthContext::anonymous())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{mint_grant_token, MintOverrides};
    use crate::token_identity::TokenIdentity;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn keys() -> GrantKeys {
        GrantKeys::new([vec![0x10; 32]], "aud", 3600, 60).unwrap()
    }

    fn bearer(token: &str) -> Vec<(String, String)> {
        vec![("Authorization".to_string(), format!("Bearer {token}"))]
    }

    fn call(auth: &Authenticate, headers: &[(String, String)]) -> crate::auth::AuthResult {
        auth(&AuthRequest {
            method: "whoami",
            headers,
            peer_addr: None,
        })
    }

    /// A resolver that answers for anything and counts its calls, so a token
    /// that wrongly reaches it is loud.
    fn counting() -> (TokenResolver, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        (
            Arc::new(move |_t: &str| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(Some(TokenIdentity::new("resolved@example")))
            }),
            calls,
        )
    }

    fn grant(now: i64, ttl: i64) -> String {
        mint_grant_token(
            &keys(),
            "alice",
            &["read".into(), "write".into()],
            "nightly",
            ttl,
            MintOverrides {
                now: Some(now),
                ..Default::default()
            },
        )
        .unwrap()
        .0
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn a_grant_authenticates_without_auth_time() {
        let (resolver, calls) = counting();
        let auth = compose_identity_authenticate(None, Some(keys()), Some(resolver)).unwrap();
        let ctx = call(&auth, &bearer(&grant(now(), 600))).unwrap();
        assert_eq!((ctx.domain.as_str(), ctx.principal.as_str()), ("grant", "alice"));
        assert_eq!(grant_scopes(&ctx), ["read", "write"]);
        assert_eq!(ctx.claims["purpose"], "nightly");
        assert!(!ctx.claims.contains_key("auth_time"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// A bad `vgig1.` token stops the chain: the (answer-anything) resolver is
    /// never consulted, and the expired one says so.
    #[test]
    fn a_bad_grant_is_401_and_never_reaches_the_resolver() {
        let (resolver, calls) = counting();
        let auth = compose_identity_authenticate(None, Some(keys()), Some(resolver)).unwrap();
        let good = grant(now(), 600);
        let tampered = format!("{}A", &good[..good.len() - 1]);
        let err = call(&auth, &bearer(&tampered)).unwrap_err();
        assert_eq!(err.auth_reason, Some(AuthReason::InvalidCredential));
        let expired = grant(now() - 3000, 60);
        let err = call(&auth, &bearer(&expired)).unwrap_err();
        assert_eq!(err.auth_reason, Some(AuthReason::ExpiredCredential));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "a grant reached resolve_token");
    }

    /// Only the exact prefix routes to the grant verifier.
    #[test]
    fn other_prefixes_go_to_the_resolver() {
        let (resolver, calls) = counting();
        let auth = compose_identity_authenticate(None, Some(keys()), Some(resolver)).unwrap();
        let body = grant(now(), 600)[GRANT_TOKEN_PREFIX.len()..].to_string();
        for token in [format!("vgig2.{body}"), body] {
            let ctx = call(&auth, &bearer(&token)).unwrap();
            assert_eq!(ctx.domain, "token");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn resolver_outcomes_map_to_token_401_and_503() {
        let resolver: TokenResolver = Arc::new(|t: &str| match t {
            "known" => Ok(Some(
                TokenIdentity::new("subject").with_token_name("laptop"),
            )),
            "down" => Err(RpcError::auth_unavailable("store down").with_retry_after(7)),
            _ => Ok(None),
        });
        let auth = compose_identity_authenticate(None, None, Some(resolver)).unwrap();
        let ctx = call(&auth, &bearer("known")).unwrap();
        assert_eq!(ctx.domain, "token");
        assert_eq!(ctx.claims["token_name"], "laptop");
        let err = call(&auth, &bearer("unknown")).unwrap_err();
        assert_eq!(err.auth_reason, Some(AuthReason::InvalidCredential));
        let err = call(&auth, &bearer("down")).unwrap_err();
        assert!(err.is_auth_unavailable());
        assert_eq!(err.retry_after_seconds, Some(7));
        // A JWS never reaches the hook.
        let err = call(&auth, &bearer("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln")).unwrap_err();
        assert_eq!(err.auth_reason, Some(AuthReason::InvalidCredential));
        // No credential stays anonymous.
        assert!(!call(&auth, &[]).unwrap().authenticated);
    }

    /// The deployment's authenticator comes first; its rejection does not
    /// stop a grant from being tried, and stands if nothing accepts.
    #[test]
    fn the_deployment_authenticator_runs_first() {
        let deployment: Authenticate = Arc::new(|req| match extract_bearer(req) {
            Some("static") => Ok(AuthContext::for_principal("bearer", "static-user")),
            Some(_) => Err(RpcError::auth_failure(AuthReason::InvalidCredential, "jwt says no")),
            None => Ok(AuthContext::anonymous()),
        });
        let auth = compose_identity_authenticate(Some(deployment), Some(keys()), None).unwrap();
        assert_eq!(call(&auth, &bearer("static")).unwrap().domain, "bearer");
        assert_eq!(call(&auth, &bearer(&grant(now(), 600))).unwrap().domain, "grant");
        let err = call(&auth, &bearer("other")).unwrap_err();
        assert_eq!(err.message, "jwt says no");
        assert!(compose_identity_authenticate(None, None, None).is_none());
    }
}
