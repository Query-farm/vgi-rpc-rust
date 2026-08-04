//! Token introspection — resolving an opaque bearer credential to a principal.
//!
//! A reverse proxy that terminates the only public listener has to know *which
//! principal a credential authenticates as* before it can authorize anything:
//! that principal becomes the policy principal, the row-rule literal, and the
//! bind parameter of every entitlement query. When the credential is opaque the
//! proxy holds no local copy of it, so it has to ask the worker.
//!
//! **The response is an identity assertion made by the thing being protected,
//! and the asker acts on it with credentials the worker does not hold** —
//! storage credentials on the data-plane host, service-credential attachments
//! in an entitlement resolver, policy-tier selection. "Trust it as much as you
//! trust the worker" is therefore the wrong frame: it must be trusted *more*,
//! because it steers privileges the worker never has. Every guard here follows
//! from that.
//!
//! What the endpoint returns is deliberately tiny: a principal, a display name
//! for the credential, and how long the answer may be cached. **It never
//! returns claims.** A pass-through claims field would let a worker choose its
//! caller's tenant routing, its row scope, and its policy branch — the single
//! most dangerous thing this feature could grow.
//!
//! It is also **not** "replay the credential through the worker's own
//! authenticate chain", which is the attractive design and breaks four ways: a
//! precondition gate wrapping the chain makes the replay unimplementable; it
//! would run the worker's independently-configured audience/issuer set, so a
//! credential the *asker* rejected could be accepted here; cookie- and
//! mTLS/IP-derived identity cannot be replayed at all, and a synthesized
//! request carries the proxy's own address, silently elevating any
//! address-allowlist member; and it invents a fake-request contract every
//! future authenticator would have to honour with no type to enforce it. The
//! resolver is a narrow callable instead.
//!
//! Wired into the HTTP server via
//! [`HttpStateBuilder::introspect_resolver`](crate::http::HttpStateBuilder::introspect_resolver);
//! the route is absent — a fixed `404 not_enabled` — until it is.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::auth::AuthContext;
use crate::errors::RpcError;

/// Endpoint path, appended to the app's prefix. Matches the de-facto contract
/// the existing proxy client already speaks; changing it would cost a lockstep
/// release for no benefit.
pub const INTROSPECT_ENDPOINT: &str = "/__introspect_token__";

/// Advertised on every response (including `OPTIONS /health`) when the route is
/// enabled, so a proxy can preflight at boot rather than discovering at first
/// login that the worker it depends on cannot answer.
pub const INTROSPECT_ENABLED_HEADER: &str = "vgi-token-introspection";

/// Hard cap on the request body. The generic body limit would otherwise admit
/// megabytes into a JSON parse for a body whose only legitimate content is one
/// credential.
pub const MAX_INTROSPECT_BODY_BYTES: usize = 8192;

/// Cap on a credential we will even attempt to resolve. Anything longer is not
/// a bearer token; refusing early keeps a resolver from being handed megabytes.
const MAX_TOKEN_CHARS: usize = 4096;

/// Cache window handed to the caller when a resolver does not choose one.
pub const DEFAULT_INTROSPECT_TTL_SECONDS: u64 = 300;

/// Introspection requests allowed per caller per second by default.
pub const DEFAULT_INTROSPECT_RATE_LIMIT: u32 = 20;

/// Return a SHA-256 hex digest of `token`, for diagnostics.
///
/// The credential itself must never reach a log, a span, or an error message. A
/// digest is stable enough to correlate one credential's failures across
/// records without being the credential.
pub fn token_digest(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    format!("{:x}", h.finalize())
}

/// Three dot-separated base64url segments — a JWS.
///
/// Such a credential is validated locally against a key set and MUST NOT be
/// routed here: doing so sends a bearer token the asker may itself have
/// rejected (expired, wrong audience) to a third party that might accept it.
/// The trailing segment may be empty (an unsecured JWS still has the shape).
pub fn is_jws_shaped(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let b64url = |s: &str| {
        s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    };
    !a.is_empty() && !b.is_empty() && b64url(a) && b64url(b) && b64url(c)
}

/// The identity an opaque credential authenticates as.
#[derive(Clone, Debug)]
pub struct TokenIdentity {
    /// The canonical principal. Return it in the exact form the worker itself
    /// would derive, so an asker that normalises differently does not authorize
    /// as one identity while the worker serves another.
    pub principal: String,
    /// Human-readable name for the credential, for audit trails. Never the
    /// credential.
    pub token_name: String,
    /// How long the answer may be cached. `None` takes the server's configured
    /// default. The *caller* does the caching; this endpoint holds none of its
    /// own. Treat it as an authorization window, because for any path the asker
    /// serves without re-presenting the credential it is exactly that.
    pub ttl_seconds: Option<u64>,
}

impl TokenIdentity {
    /// Identity with no display name and the server's default TTL.
    pub fn new(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            token_name: String::new(),
            ttl_seconds: None,
        }
    }

    /// Attach the credential's display name (never the credential).
    pub fn with_token_name(mut self, name: impl Into<String>) -> Self {
        self.token_name = name.into();
        self
    }

    /// Override the server's default cache window for this credential.
    pub fn with_ttl_seconds(mut self, ttl: u64) -> Self {
        self.ttl_seconds = Some(ttl);
        self
    }
}

/// Resolves an opaque credential.
///
/// `Ok(None)` means "did not resolve" — unknown, expired and malformed are one
/// answer, because reporting which would confirm that a guessed credential
/// exists. `Err(`[`RpcError::auth_unavailable`]`)` means the answer is not
/// *knowable*: a backing store that is down is not a credential that is
/// unknown, and a caller that negative-caches the second must not cache the
/// first. Any other `Err` is a server fault and surfaces the same way.
pub type TokenResolver =
    Arc<dyn Fn(&str) -> std::result::Result<Option<TokenIdentity>, RpcError> + Send + Sync>;

/// What the endpoint should answer. Rendering lives in the HTTP layer so this
/// module stays free of axum.
#[derive(Debug)]
pub enum IntrospectOutcome {
    /// `200` with the closed three-key body.
    Resolved {
        principal: String,
        token_name: String,
        ttl_seconds: u64,
    },
    /// `403` — the caller may not introspect. Distinct from `Unresolved`
    /// because it is about the *caller*, and a proxy that is refused outright
    /// needs to fix its configuration rather than its subject credential.
    NotAnIntrospector,
    /// `404` — the *subject* credential did not resolve. One answer for
    /// unknown, expired, malformed, and JWS-shaped.
    Unresolved,
    /// `429` — the caller is over its per-second budget.
    RateLimited,
    /// `503` + `Retry-After` — could not determine. The caller must retry
    /// rather than cache.
    Unavailable { retry_after_seconds: u32 },
}

/// Fixed-window request limiter, keyed by caller.
///
/// Present because the endpoint is a credential→identity oracle even when
/// correctly restricted: an allowlisted caller whose own credential leaks can
/// still test guesses. Rate limiting does not close that, it bounds it — a
/// lower ceiling on how fast an attacker converts guesses to answers.
///
/// Fixed-window rather than a token bucket: a window admits at most twice the
/// rate across a boundary, which is a rounding error here, and the state is one
/// integer per caller rather than a float that has to be aged.
struct RateLimiter {
    per_window: u32,
    window: std::time::Duration,
    state: Mutex<(Instant, std::collections::HashMap<String, u32>)>,
}

impl RateLimiter {
    fn new(per_window: u32) -> Self {
        Self {
            per_window,
            window: std::time::Duration::from_secs(1),
            state: Mutex::new((Instant::now(), std::collections::HashMap::new())),
        }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (start, counts) = &mut *guard;
        if now.duration_since(*start) >= self.window {
            // Whole-map reset rather than per-key ageing: a caller cycling keys
            // cannot grow the map beyond one window's worth.
            counts.clear();
            *start = now;
        }
        let count = counts.entry(key.to_string()).or_insert(0);
        if *count >= self.per_window {
            return false;
        }
        *count += 1;
        true
    }
}

/// The configured endpoint: an allowlist, a resolver, and a rate limiter.
///
/// Constructed only when an operator supplies a resolver, so a worker cannot
/// grow this oracle by upgrading a dependency.
pub struct TokenIntrospector {
    resolver: TokenResolver,
    principals: BTreeSet<String>,
    default_ttl_seconds: u64,
    limiter: RateLimiter,
}

impl std::fmt::Debug for TokenIntrospector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenIntrospector")
            .field("principals", &self.principals.len())
            .field("default_ttl_seconds", &self.default_ttl_seconds)
            .finish_non_exhaustive()
    }
}

impl TokenIntrospector {
    /// Build the endpoint's state.
    ///
    /// # Panics
    ///
    /// If `principals` is empty. There is no permissive default: "any
    /// authenticated caller" is precisely the configuration that turns this
    /// endpoint into an open oracle — any user could test guesses of any other
    /// user's credential at unlimited rate, and resolve a stolen one to its
    /// owner — so it must not be reachable by omission. A misconfiguration
    /// fails at construction rather than at the first proxy preflight.
    pub fn new<I, S>(
        resolver: TokenResolver,
        principals: I,
        default_ttl_seconds: u64,
        rate_limit_per_second: u32,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let principals: BTreeSet<String> = principals
            .into_iter()
            .map(Into::into)
            .filter(|p| !p.is_empty())
            .collect();
        assert!(
            !principals.is_empty(),
            "introspect_principals must name at least one principal. Introspection \
             is a distinct capability from authentication: allowing any \
             authenticated caller lets any user resolve any other user's \
             credential to its owner."
        );
        assert!(
            default_ttl_seconds > 0,
            "introspect_default_ttl must be positive: a zero or absent TTL silently \
             disables the caller's cache and turns every request into a round trip."
        );
        Self {
            resolver,
            principals,
            default_ttl_seconds,
            limiter: RateLimiter::new(rate_limit_per_second),
        }
    }

    /// Decide the answer for one request.
    ///
    /// `body` is the raw request body, already bounded by the caller;
    /// over-length or unparsable bodies collapse onto [`IntrospectOutcome::Unresolved`]
    /// because a malformed body is not worth a separate signal, and giving one
    /// lets a caller probe the parser.
    pub fn introspect(&self, auth: &AuthContext, body: &[u8]) -> IntrospectOutcome {
        // Caller authorization first: an unauthorized caller must not learn
        // anything about a subject credential, including how long it took.
        if !auth.authenticated || !self.principals.contains(&auth.principal) {
            tracing::warn!(
                target: "vgi_rpc.http.introspect",
                principal = %auth.principal,
                authenticated = auth.authenticated,
                "introspection refused: caller is not an introspector"
            );
            return IntrospectOutcome::NotAnIntrospector;
        }

        if !self.limiter.allow(&auth.principal) {
            tracing::warn!(
                target: "vgi_rpc.http.introspect",
                principal = %auth.principal,
                "introspection rate limit exceeded"
            );
            return IntrospectOutcome::RateLimited;
        }

        let Some(token) = parse_token(body) else {
            return IntrospectOutcome::Unresolved;
        };
        // Every diagnostic below names the digest, never the credential.
        let digest = token_digest(&token);

        if is_jws_shaped(&token) {
            // Refused without ever reaching the resolver. A JWS is validated
            // locally against a key set; one arriving here is either a caller
            // bug or an attempt to have this worker vouch for a token its asker
            // already rejected.
            tracing::warn!(
                target: "vgi_rpc.http.introspect",
                principal = %auth.principal,
                token_digest = %digest,
                "introspection refused: JWS-shaped subject"
            );
            return IntrospectOutcome::Unresolved;
        }

        match (self.resolver)(&token) {
            Ok(Some(identity)) => {
                tracing::info!(
                    target: "vgi_rpc.http.introspect",
                    principal = %auth.principal,
                    token_digest = %digest,
                    resolved_principal = %identity.principal,
                    "introspection: resolved"
                );
                IntrospectOutcome::Resolved {
                    principal: identity.principal,
                    token_name: identity.token_name,
                    ttl_seconds: identity.ttl_seconds.unwrap_or(self.default_ttl_seconds),
                }
            }
            Ok(None) => {
                tracing::info!(
                    target: "vgi_rpc.http.introspect",
                    principal = %auth.principal,
                    token_digest = %digest,
                    "introspection: credential did not resolve"
                );
                IntrospectOutcome::Unresolved
            }
            Err(err) => {
                // Transient by construction: the resolver could not answer, so
                // the caller must retry rather than negative-cache. Anything
                // else it returns is a server fault and is treated the same
                // way — a wrong answer here is worse than a retry.
                tracing::error!(
                    target: "vgi_rpc.http.introspect",
                    principal = %auth.principal,
                    token_digest = %digest,
                    error = %err.message,
                    "introspection unavailable"
                );
                IntrospectOutcome::Unavailable {
                    retry_after_seconds: err
                        .retry_after_seconds
                        .unwrap_or(crate::errors::DEFAULT_AUTH_RETRY_AFTER_SECONDS),
                }
            }
        }
    }
}

/// Pull the one credential out of a `{"token": "..."}` body.
///
/// `None` for anything unusable, which the caller collapses onto the same
/// rejection an unknown credential gets.
fn parse_token(body: &[u8]) -> Option<String> {
    if body.len() > MAX_INTROSPECT_BODY_BYTES {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let token = value.get("token")?.as_str()?;
    if token.is_empty() || token.len() > MAX_TOKEN_CHARS {
        return None;
    }
    Some(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBJECT: &str = "opaque-subject-token";

    fn introspector() -> TokenIntrospector {
        TokenIntrospector::new(
            Arc::new(|token: &str| {
                Ok((token == SUBJECT || is_jws_shaped(token))
                    .then(|| TokenIdentity::new("subject@example").with_token_name("laptop")))
            }),
            ["proxy"],
            DEFAULT_INTROSPECT_TTL_SECONDS,
            DEFAULT_INTROSPECT_RATE_LIMIT,
        )
    }

    fn caller(principal: &str) -> AuthContext {
        AuthContext::for_principal("conformance", principal)
    }

    fn body(token: &str) -> Vec<u8> {
        serde_json::json!({ "token": token })
            .to_string()
            .into_bytes()
    }

    #[test]
    fn resolves_a_known_credential() {
        let outcome = introspector().introspect(&caller("proxy"), &body(SUBJECT));
        let IntrospectOutcome::Resolved {
            principal,
            token_name,
            ttl_seconds,
        } = outcome
        else {
            panic!("expected a resolution, got {outcome:?}");
        };
        assert_eq!(principal, "subject@example");
        assert_eq!(token_name, "laptop");
        assert_eq!(ttl_seconds, DEFAULT_INTROSPECT_TTL_SECONDS);
    }

    #[test]
    fn authentication_alone_does_not_grant_introspection() {
        // The oracle guard: a port that checks only `authenticated` passes
        // every other case here.
        let outcome = introspector().introspect(&caller("someone-else"), &body(SUBJECT));
        assert!(matches!(outcome, IntrospectOutcome::NotAnIntrospector));
        let outcome = introspector().introspect(&AuthContext::anonymous(), &body(SUBJECT));
        assert!(matches!(outcome, IntrospectOutcome::NotAnIntrospector));
    }

    #[test]
    #[should_panic(expected = "at least one principal")]
    fn empty_allowlist_is_not_a_permissive_default() {
        let _ = TokenIntrospector::new(
            Arc::new(|_: &str| Ok(None)),
            Vec::<String>::new(),
            DEFAULT_INTROSPECT_TTL_SECONDS,
            DEFAULT_INTROSPECT_RATE_LIMIT,
        );
    }

    #[test]
    fn jws_shaped_subject_never_reaches_the_resolver() {
        // Resolvable on purpose: against an unknown JWS a missing shape guard
        // rejects it as unknown and passes for the wrong reason.
        let jws = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
        assert!(is_jws_shaped(jws));
        let resolver_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = resolver_ran.clone();
        let it = TokenIntrospector::new(
            Arc::new(move |_: &str| {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(Some(TokenIdentity::new("subject@example")))
            }),
            ["proxy"],
            DEFAULT_INTROSPECT_TTL_SECONDS,
            DEFAULT_INTROSPECT_RATE_LIMIT,
        );
        assert!(matches!(
            it.introspect(&caller("proxy"), &body(jws)),
            IntrospectOutcome::Unresolved
        ));
        assert!(
            !resolver_ran.load(std::sync::atomic::Ordering::SeqCst),
            "the resolver was handed a JWS"
        );
    }

    #[test]
    fn jws_shape_test_does_not_catch_opaque_credentials() {
        assert!(!is_jws_shaped("conformance-opaque-subject-token"));
        assert!(!is_jws_shaped("a.b"));
        assert!(!is_jws_shaped("a.b.c.d"));
        assert!(!is_jws_shaped("a.b.c!"));
        assert!(!is_jws_shaped(".b.c"));
        assert!(
            is_jws_shaped("a.b."),
            "an unsecured JWS still has the shape"
        );
    }

    #[test]
    fn unknown_expired_and_malformed_are_one_answer() {
        let it = introspector();
        for probe in [
            body("no-such-credential"),
            body("expired-credential"),
            body("!!malformed!!"),
            b"not json at all".to_vec(),
            b"{}".to_vec(),
            serde_json::json!({ "token": 7 }).to_string().into_bytes(),
            serde_json::json!({ "token": "x".repeat(MAX_TOKEN_CHARS + 1) })
                .to_string()
                .into_bytes(),
        ] {
            assert!(matches!(
                it.introspect(&caller("proxy"), &probe),
                IntrospectOutcome::Unresolved
            ));
        }
    }

    #[test]
    fn an_oversized_body_is_refused_without_being_parsed() {
        let huge =
            serde_json::json!({ "token": "x", "pad": "p".repeat(MAX_INTROSPECT_BODY_BYTES) })
                .to_string()
                .into_bytes();
        assert!(matches!(
            introspector().introspect(&caller("proxy"), &huge),
            IntrospectOutcome::Unresolved
        ));
    }

    #[test]
    fn a_resolver_outage_is_transient_not_a_rejection() {
        let it = TokenIntrospector::new(
            Arc::new(|_: &str| {
                Err(RpcError::auth_unavailable("token store down").with_retry_after(7))
            }),
            ["proxy"],
            DEFAULT_INTROSPECT_TTL_SECONDS,
            DEFAULT_INTROSPECT_RATE_LIMIT,
        );
        assert!(matches!(
            it.introspect(&caller("proxy"), &body(SUBJECT)),
            IntrospectOutcome::Unavailable {
                retry_after_seconds: 7
            }
        ));
    }

    #[test]
    fn rate_limit_bounds_the_oracle() {
        let it = TokenIntrospector::new(
            Arc::new(|_: &str| Ok(None)),
            ["proxy"],
            DEFAULT_INTROSPECT_TTL_SECONDS,
            2,
        );
        let probe = body("guess");
        assert!(matches!(
            it.introspect(&caller("proxy"), &probe),
            IntrospectOutcome::Unresolved
        ));
        assert!(matches!(
            it.introspect(&caller("proxy"), &probe),
            IntrospectOutcome::Unresolved
        ));
        assert!(matches!(
            it.introspect(&caller("proxy"), &probe),
            IntrospectOutcome::RateLimited
        ));
    }

    // "The credential never reaches a log record" is asserted in
    // `tests/introspect_logging.rs`, which is a separate binary on purpose:
    // tracing caches callsite interest globally, so a sibling test hitting
    // these same log statements without a subscriber installed can leave the
    // capture empty and make the assertion pass — or fail — by scheduling luck.

    #[test]
    fn token_digest_is_stable_and_is_not_the_credential() {
        let d = token_digest(SUBJECT);
        assert_eq!(d, token_digest(SUBJECT));
        assert_eq!(d.len(), 64);
        assert!(!d.contains(SUBJECT));
    }
}
