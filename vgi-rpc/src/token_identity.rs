//! `vgi_rpc.Identity.v1` -- resolving a credential, and minting a grant.
//!
//! Identity lives here, at the RPC layer, rather than in any application
//! protocol: a bearer token is not an application concept, the auth primitives
//! it builds on ([`AuthContext`], [`RpcError::auth_unavailable`]) are already
//! here, and implementing it once is the whole point. It was previously an
//! HTTP JSON route, `POST {prefix}/__introspect_token__` (still served by
//! [`crate::auth::introspect`] for callers that speak it), which meant it
//! existed on one transport only and had to be hand-written in every port.
//!
//! Two methods share this module's guards, and they are guarded *differently*
//! on purpose.
//!
//! `introspect_token` answers "which principal is this credential" for a
//! reverse proxy that terminates the only public listener. The answer is an
//! identity assertion made by the thing being protected, which the asker then
//! acts on using credentials the worker does not hold -- storage credentials,
//! entitlement lookups, policy-tier selection. "Trust it as much as you trust
//! the worker" is the wrong frame: it must be trusted *more*. So every
//! rejection is uniform, the caller must be on an allowlist with no permissive
//! default, a JWS-shaped subject never reaches the resolver, and the whole
//! thing is rate limited.
//!
//! `issue_grant` mints a credential for the *calling* user, so it is not an
//! oracle about anybody else. It therefore needs no allowlist and no rate
//! limit, and its rejections are deliberately *actionable*: a console that
//! cannot tell "your login is too old" from "no" cannot know to re-prompt.
//!
//! Errors carry a stable [`RpcError::error_kind`]. That is load-bearing rather
//! than decorative: these used to be a bespoke HTTP route whose callers
//! classified definitive-vs-transient on the HTTP status (404 vs 503). As
//! protocol methods every handler failure surfaces the same way, so
//! `error_kind` is now the *only* signal a caller has. A caller that
//! negative-caches a transient failure locks out valid users; one that retries
//! a definitive rejection hammers the worker.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use crate::auth::AuthContext;
use crate::errors::{Result, RpcError};
use crate::server::{CallContext, MethodInfo, Request};

// Re-exported so a caller wiring this protocol needs one import, and so the
// *same* resolver backs both this protocol and the legacy HTTP route -- two
// copies of "what does this credential resolve to" is exactly how two answers
// for one credential appear.
pub use crate::auth::introspect::{
    is_jws_shaped, token_digest, TokenIdentity, TokenResolver, DEFAULT_INTROSPECT_RATE_LIMIT,
    DEFAULT_INTROSPECT_TTL_SECONDS,
};

/// The wire name of the identity protocol.
///
/// Under the reserved `vgi_rpc.` prefix because the framework defines it: an
/// application that could claim this name could impersonate the surface a
/// fronting proxy resolves identities against.
pub const IDENTITY_PROTOCOL_NAME: &str = "vgi_rpc.Identity.v1";

/// Cap on a credential we will even attempt to resolve. Anything longer is not
/// a bearer token; refusing early keeps a resolver from being handed megabytes.
pub const MAX_TOKEN_CHARS: usize = 4096;

/// How recently a caller must have authenticated to mint a grant.
pub const DEFAULT_MAX_AUTH_AGE_SECONDS: f64 = 900.0;

/// `Retry-After` carried by [`identity_unavailable`]. Short on purpose: it is
/// a hint to retry, not a backoff schedule.
pub const DEFAULT_IDENTITY_RETRY_AFTER_SECONDS: u32 = 5;

// ---------------------------------------------------------------------------
// Error taxonomy
//
// The `error_kind` strings below are the wire contract -- see the module
// docstring for why they, and not the HTTP status or the message text, are
// what a caller branches on.
// ---------------------------------------------------------------------------

/// The caller may not introspect. Definitive: a caller may cache this.
pub const ERROR_KIND_INTROSPECTION_REFUSED: &str = "introspection_refused";
/// The subject credential did not resolve. Definitive, and uniform across
/// unknown, expired and malformed.
pub const ERROR_KIND_TOKEN_UNRESOLVED: &str = "token_unresolved";
/// The caller has not authenticated recently enough to mint. Definitive but
/// actionable.
pub const ERROR_KIND_STALE_AUTH: &str = "stale_auth";
/// The worker declined to mint. Definitive.
pub const ERROR_KIND_GRANT_REFUSED: &str = "grant_refused";
/// The answer is not *knowable*. Transient; carries `retry_after`.
pub const ERROR_KIND_IDENTITY_UNAVAILABLE: &str = "identity_unavailable";

/// The caller may not introspect.
///
/// Definitive: a caller may cache this. Authentication is not the same
/// capability as introspection -- a deployment where any valid credential may
/// introspect lets any user test guesses of any other user's credential at
/// unlimited rate, and resolve a stolen one to its owner.
pub fn introspection_refused(detail: impl Into<String>) -> RpcError {
    RpcError::permission_error(detail).with_error_kind(ERROR_KIND_INTROSPECTION_REFUSED)
}

/// The subject credential did not resolve.
///
/// Definitive, and deliberately uniform: unknown, expired and malformed are
/// one answer, because reporting which would confirm that a guessed credential
/// exists. It takes no detail argument for the same reason -- a detail
/// parameter is an invitation to distinguish them later.
pub fn token_unresolved() -> RpcError {
    RpcError::value_error("unresolved").with_error_kind(ERROR_KIND_TOKEN_UNRESOLVED)
}

/// The caller has not authenticated recently enough to mint a grant.
///
/// Definitive but *actionable*, unlike the introspection rejections: this is
/// always about the caller themselves, so naming the reason leaks nothing and
/// is the only way a console learns to re-prompt.
pub fn stale_auth(detail: impl Into<String>) -> RpcError {
    RpcError::permission_error(detail).with_error_kind(ERROR_KIND_STALE_AUTH)
}

/// The worker declined to mint this grant.
///
/// Definitive. The worker holds the policy; the framework only asked.
pub fn grant_refused(detail: impl Into<String>) -> RpcError {
    RpcError::permission_error(detail).with_error_kind(ERROR_KIND_GRANT_REFUSED)
}

/// The answer is not *knowable* -- a backing store is down, a 5xx upstream.
///
/// Transient, and distinct from a definitive rejection: a caller that
/// negative-caches "unknown" must not cache this. It is built on
/// [`RpcError::auth_unavailable`] rather than on the rejection constructors,
/// which is this port's equivalent of the reference's "deliberately not a
/// `ValueError`": [`crate::auth::chain_authenticate`] treats *every* `Err` as
/// short-circuiting rather than as "not my credential, try the next", so what
/// the distinct type buys here is the HTTP mapping (503 + `Retry-After`
/// instead of 401) and the fact that no caller can mistake it for
/// [`token_unresolved`], which is a `ValueError`.
pub fn identity_unavailable(detail: impl Into<String>) -> RpcError {
    RpcError::auth_unavailable(detail)
        .with_retry_after(DEFAULT_IDENTITY_RETRY_AFTER_SECONDS)
        .with_error_kind(ERROR_KIND_IDENTITY_UNAVAILABLE)
}

/// Normalise whatever a hook returned into the transient signal.
///
/// A hook that already said "unavailable" keeps its own `Retry-After`; any
/// other failure is a server fault and is treated the same way, because a
/// wrong answer here is worse than a retry.
fn as_unavailable(err: RpcError) -> RpcError {
    let retry = err
        .retry_after_seconds
        .unwrap_or(DEFAULT_IDENTITY_RETRY_AFTER_SECONDS);
    RpcError::auth_unavailable(err.message)
        .with_retry_after(retry)
        .with_error_kind(ERROR_KIND_IDENTITY_UNAVAILABLE)
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Fixed-window request limiter, keyed by caller.
///
/// Present because introspection is a credential-to-identity oracle even when
/// correctly restricted: an allowlisted caller whose own credential leaks can
/// still test guesses. Rate limiting does not close that, it bounds it.
///
/// Fixed-window rather than a token bucket: a window admits at most twice the
/// rate across a boundary, which is a rounding error here, and the state is one
/// integer per caller rather than a float that has to be aged.
///
/// One `Mutex` around the whole `(window_start, counts)` pair, because the two
/// are only meaningful together -- a reader that saw a rolled window and a
/// stale count would admit a caller that is over budget.
pub struct RateLimiter {
    per_window: u32,
    window: Duration,
    state: Mutex<(Instant, HashMap<String, u32>)>,
}

impl RateLimiter {
    /// Build a limiter admitting `per_window` requests per one-second window.
    pub fn new(per_window: u32) -> Self {
        Self {
            per_window,
            window: Duration::from_secs(1),
            state: Mutex::new((Instant::now(), HashMap::new())),
        }
    }

    /// Whether `key` may make a request now.
    pub fn allow(&self, key: &str) -> bool {
        self.allow_at(key, Instant::now())
    }

    /// Whether `key` may make a request at `now`.
    ///
    /// The clock is a parameter so the window-roll behaviour is testable
    /// without sleeping -- a limiter verified by `sleep` is a limiter verified
    /// flakily.
    pub fn allow_at(&self, key: &str, now: Instant) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (start, counts) = &mut *guard;
        if now.saturating_duration_since(*start) >= self.window {
            // Whole-map reset rather than per-key ageing: an attacker cycling
            // keys cannot grow the map beyond one window's worth.
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

    /// Number of keys currently tracked. Exposed for the test that pins the
    /// whole-map reset; a growing map is the failure mode it guards.
    pub fn tracked_keys(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1.len()
    }
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// A standing delegation credential.
///
/// OAuth cannot express durable delegation: it fuses the grant, the credential
/// and the session into one refresh token, so an IdP shortening session
/// lifetime shortens the grant. This is the durable record -- minted while the
/// user is present, presented later by unattended automation as an ordinary
/// bearer.
#[derive(Clone, Debug)]
pub struct IssuedGrant {
    /// The credential. **Opaque to the framework** -- the worker owns the
    /// format entirely (a sealed envelope, a database row, or a credential
    /// brokered from the IdP are all equally valid and equally invisible
    /// here). Never parsed, never logged.
    pub token: String,
    /// Unix timestamp after which the worker will stop honouring the grant.
    /// Required *because* the framework cannot enforce it: the real lifetime
    /// lives inside the opaque token, so this is a declaration rather than an
    /// enforcement. A worker that must state a lifetime has thought about one.
    pub expires_at: f64,
    /// Correlation handle for the audit trail. Not a credential and not secret
    /// -- it is what ties a mint record to later use.
    pub grant_id: String,
}

impl IssuedGrant {
    /// A grant with no correlation handle.
    pub fn new(token: impl Into<String>, expires_at: f64) -> Self {
        Self {
            token: token.into(),
            expires_at,
            grant_id: String::new(),
        }
    }

    /// Attach the audit-trail correlation handle.
    pub fn with_grant_id(mut self, id: impl Into<String>) -> Self {
        self.grant_id = id.into();
        self
    }
}

/// Mints a standing grant for the calling principal.
///
/// `(caller_principal, purpose, scopes, ttl_seconds) -> IssuedGrant`. The
/// first argument is the *caller*, never a request parameter -- see
/// [`IdentityImpl::issue_grant`].
///
/// `Err(`[`RpcError`]`)` is the worker declining; return
/// [`grant_refused`] to say so definitively, or
/// [`identity_unavailable`] when the answer is not knowable.
pub type GrantMinter = Arc<dyn Fn(&str, &str, &[String], i64) -> Result<IssuedGrant> + Send + Sync>;

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

/// Validate the introspector allowlist.
///
/// # Panics
///
/// If the allowlist is missing or empty. There is no permissive default: "any
/// authenticated caller" is precisely the configuration that turns
/// introspection into an open oracle, so it must not be reachable by omission.
/// A panic rather than a returned error because this is a *construction*
/// check -- a worker that would refuse every introspection should fail to
/// start rather than serve traffic until someone tries. It matches
/// [`crate::auth::introspect::TokenIntrospector::new`], which guards the same
/// configuration on the HTTP route.
pub fn normalise_principals<I, S>(principals: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let allowed: BTreeSet<String> = principals
        .into_iter()
        .map(Into::into)
        .filter(|p| !p.is_empty())
        .collect();
    assert!(
        !allowed.is_empty(),
        "introspect_principals must name at least one principal. Introspection is a \
         distinct capability from authentication: allowing any authenticated caller \
         lets any user resolve any other user's credential to its owner."
    );
    allowed
}

/// Return the caller principal, or refuse.
///
/// Checked before anything touches the subject credential: an unauthorized
/// caller must not learn anything about it, including how long it took.
pub fn check_introspector<'a>(
    auth: &'a AuthContext,
    principals: &BTreeSet<String>,
) -> Result<&'a str> {
    if !auth.authenticated || !principals.contains(&auth.principal) {
        return Err(introspection_refused("caller is not an introspector"));
    }
    Ok(&auth.principal)
}

/// Refuse a JWS-shaped, empty or over-long subject before it reaches a
/// resolver.
///
/// A JWS is validated locally against a key set; forwarding one -- which the
/// asker may itself have rejected as expired or wrong-audience -- to a third
/// party that might accept it turns this method into a laundering step.
pub fn reject_jws_shaped(token: &str) -> Result<()> {
    if token.is_empty() || token.chars().count() > MAX_TOKEN_CHARS || is_jws_shaped(token) {
        return Err(token_unresolved());
    }
    Ok(())
}

/// Seconds since the Unix epoch, for the freshness comparison.
fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Return the caller's `auth_time`, or refuse if it is missing or stale.
///
/// A credential with no verifiable `auth_time` cannot mint. That single rule is
/// what stops a grant being used to mint another grant: a grant is not an
/// IdP-issued token, so it carries no `auth_time`, so the lineage cannot escape
/// the identity provider. It also makes subprocess and unix transports fail
/// closed for free -- there is no authenticated principal there at all.
///
/// A static bearer proves a machine holds a secret, never that a human just
/// authenticated, so it is refused here too.
///
/// **Caveat:** `auth_time` is an OIDC claim meaning *when this session began*,
/// which can be arbitrarily old while still present and cryptographically
/// valid. Requiring it is not the same as requiring a recent login: the
/// deployment must send `max_age` (or an appropriate `acr`) at the authorize
/// endpoint for this guard to mean what it says.
pub fn check_freshness(auth: &AuthContext, max_auth_age: f64) -> Result<f64> {
    check_freshness_at(auth, max_auth_age, now_unix())
}

/// [`check_freshness`] with the clock supplied, so the ceiling is testable
/// without waiting fifteen minutes.
pub fn check_freshness_at(auth: &AuthContext, max_auth_age: f64, now: f64) -> Result<f64> {
    if !auth.authenticated || auth.principal.is_empty() {
        return Err(stale_auth("caller is not authenticated"));
    }
    let Some(raw) = auth.claims.get("auth_time") else {
        return Err(stale_auth(
            "credential carries no auth_time; only a recently authenticated user may mint a grant",
        ));
    };
    let Ok(auth_time) = raw.trim().parse::<f64>() else {
        return Err(stale_auth("credential carries an unusable auth_time"));
    };
    if !auth_time.is_finite() {
        return Err(stale_auth("credential carries an unusable auth_time"));
    }
    let age = now - auth_time;
    if age > max_auth_age {
        return Err(stale_auth(format!(
            "last authentication was {age:.0}s ago, which exceeds the {max_auth_age:.0}s \
             ceiling for minting a grant; re-authenticate"
        )));
    }
    Ok(auth_time)
}

// ---------------------------------------------------------------------------
// The implementation
// ---------------------------------------------------------------------------

/// Applies this module's guards, then delegates to worker-supplied hooks.
///
/// The framework owns the guards and owns none of the policy. It decides who
/// may ask, how often, and what shape of credential is refused outright; the
/// worker decides what a credential resolves to and whether a grant is minted.
/// That split is deliberate -- the guards are the part that is identical in
/// every deployment and catastrophic to get wrong, and the policy is the part
/// that is different in every deployment and cannot be guessed.
///
/// **A method whose hook is absent is not registered at all**, so the protocol
/// a server hosts describes what it actually does. A worker that resolves
/// credentials but does not mint grants hosts `introspect_token` and not
/// `issue_grant`, and a client discovers that through ordinary reflection
/// rather than by calling and reading an error. Absent beats
/// routed-and-refusing: it is what keeps a dependency upgrade from growing a
/// credential-to-identity oracle on every existing worker.
pub struct IdentityImpl {
    resolve_token: Option<TokenResolver>,
    mint_grant: Option<GrantMinter>,
    principals: BTreeSet<String>,
    default_ttl_seconds: u64,
    max_auth_age: f64,
    limiter: RateLimiter,
}

impl std::fmt::Debug for IdentityImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityImpl")
            .field("offered_methods", &self.offered_methods())
            .field("principals", &self.principals.len())
            .field("max_auth_age", &self.max_auth_age)
            .finish_non_exhaustive()
    }
}

/// Builder for [`IdentityImpl`].
#[derive(Default)]
pub struct IdentityImplBuilder {
    resolve_token: Option<TokenResolver>,
    mint_grant: Option<GrantMinter>,
    principals: Vec<String>,
    default_ttl_seconds: Option<u64>,
    rate_limit: Option<u32>,
    max_auth_age: Option<f64>,
}

impl IdentityImplBuilder {
    /// `(token) -> Option<TokenIdentity>`. `Ok(None)` means the store answered
    /// and the credential is unknown; return [`identity_unavailable`] for "not
    /// knowable".
    ///
    /// Supplying this hosts `introspect_token`, and *requires*
    /// [`introspect_principals`](Self::introspect_principals).
    pub fn resolve_token(mut self, resolver: TokenResolver) -> Self {
        self.resolve_token = Some(resolver);
        self
    }

    /// `(caller_principal, purpose, scopes, ttl_seconds) -> IssuedGrant`.
    /// Supplying this hosts `issue_grant`.
    pub fn mint_grant(mut self, minter: GrantMinter) -> Self {
        self.mint_grant = Some(minter);
        self
    }

    /// Who may call `introspect_token`. Required whenever
    /// [`resolve_token`](Self::resolve_token) is supplied; there is no
    /// permissive default.
    pub fn introspect_principals<I, S>(mut self, principals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.principals = principals.into_iter().map(Into::into).collect();
        self
    }

    /// Introspections allowed per caller per second (default 20).
    pub fn introspect_rate_limit(mut self, per_second: u32) -> Self {
        self.rate_limit = Some(per_second);
        self
    }

    /// Cache window advertised for a resolution that does not name its own
    /// (default 300 s). Treat it as an authorization window: for any path the
    /// asker serves without re-presenting the credential it is exactly that,
    /// and therefore also the revocation lag.
    pub fn introspect_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl_seconds = Some(ttl.as_secs());
        self
    }

    /// How recently a caller must have authenticated to mint a grant
    /// (default 900 s).
    pub fn max_auth_age(mut self, age: Duration) -> Self {
        self.max_auth_age = Some(age.as_secs_f64());
        self
    }

    /// Finish the implementation.
    ///
    /// # Panics
    ///
    /// If `resolve_token` was supplied without an allowlist -- see
    /// [`normalise_principals`]. Validated here, not at first call: a worker
    /// that would refuse every introspection should fail to start rather than
    /// serve traffic until someone tries.
    pub fn build(self) -> IdentityImpl {
        let principals = if self.resolve_token.is_some() {
            normalise_principals(self.principals)
        } else {
            BTreeSet::new()
        };
        IdentityImpl {
            resolve_token: self.resolve_token,
            mint_grant: self.mint_grant,
            principals,
            default_ttl_seconds: self
                .default_ttl_seconds
                .unwrap_or(DEFAULT_INTROSPECT_TTL_SECONDS),
            max_auth_age: self.max_auth_age.unwrap_or(DEFAULT_MAX_AUTH_AGE_SECONDS),
            limiter: RateLimiter::new(self.rate_limit.unwrap_or(DEFAULT_INTROSPECT_RATE_LIMIT)),
        }
    }
}

impl IdentityImpl {
    /// Start building an implementation.
    pub fn builder() -> IdentityImplBuilder {
        IdentityImplBuilder::default()
    }

    /// The methods this deployment can actually answer.
    ///
    /// A method whose hook is absent is not registered, so the protocol a
    /// server hosts describes what it does. A client learns that from
    /// reflection rather than by calling and reading an error.
    pub fn offered_methods(&self) -> BTreeSet<&'static str> {
        let mut offered = BTreeSet::new();
        if self.resolve_token.is_some() {
            offered.insert(INTROSPECT_TOKEN_METHOD);
        }
        if self.mint_grant.is_some() {
            offered.insert(ISSUE_GRANT_METHOD);
        }
        offered
    }

    /// Resolve `token`, after checking the caller may ask.
    ///
    /// The guard order is load-bearing and must not be tidied: authorization
    /// and rate limiting come *before* anything looks at the subject
    /// credential -- before its length is measured, before its shape is
    /// tested. An unauthorized caller must learn nothing about the subject,
    /// including how long looking at it took.
    pub fn introspect_token(&self, token: &str, auth: &AuthContext) -> Result<TokenIdentity> {
        // 1. The hook is absent. Belt to the braces of not registering the
        //    method at all, for a caller that reached it anyway.
        let Some(resolve) = self.resolve_token.as_ref() else {
            return Err(introspection_refused(
                "this worker does not resolve credentials",
            ));
        };

        // 2. Authorization.
        let caller = check_introspector(auth, &self.principals)?;

        // 3. Rate limit, keyed by caller.
        if !self.limiter.allow(caller) {
            tracing::warn!(
                target: "vgi_rpc.identity",
                principal = %caller,
                "introspection rate limit exceeded"
            );
            return Err(introspection_refused("introspection rate limit exceeded"));
        }

        // 4. Only now does the subject credential get looked at.
        reject_jws_shaped(token)?;

        // Every diagnostic below names the digest, never the credential.
        let digest = token_digest(token);
        match resolve(token) {
            Ok(Some(identity)) => {
                tracing::info!(
                    target: "vgi_rpc.identity",
                    principal = %caller,
                    token_digest = %digest,
                    resolved_principal = %identity.principal,
                    "introspection: resolved"
                );
                Ok(identity)
            }
            // 5. Uniform with malformed and expired: reporting which would
            //    confirm that a guessed credential exists.
            Ok(None) => {
                tracing::info!(
                    target: "vgi_rpc.identity",
                    principal = %caller,
                    token_digest = %digest,
                    "introspection: credential did not resolve"
                );
                Err(token_unresolved())
            }
            Err(err) => {
                tracing::error!(
                    target: "vgi_rpc.identity",
                    principal = %caller,
                    token_digest = %digest,
                    error = %err.message,
                    "introspection unavailable"
                );
                Err(as_unavailable(err))
            }
        }
    }

    /// Mint a grant for the caller, after checking they authenticated recently.
    ///
    /// **There is no subject parameter.** The subject is always the caller's
    /// authenticated principal, so cross-subject minting is closed by
    /// construction rather than by a check that could be forgotten in one of
    /// seven ports. That is also why this method needs no allowlist while
    /// `introspect_token` has one: introspection resolves *other people's*
    /// credentials, so "any authenticated caller" is an open oracle there;
    /// issuance is always about the caller themselves.
    pub fn issue_grant(
        &self,
        purpose: &str,
        scopes: &[String],
        ttl_seconds: i64,
        auth: &AuthContext,
    ) -> Result<IssuedGrant> {
        let Some(mint) = self.mint_grant.as_ref() else {
            return Err(grant_refused("this worker does not mint grants"));
        };
        check_freshness(auth, self.max_auth_age)?;
        mint(&auth.principal, purpose, scopes, ttl_seconds)
    }

    /// The TTL a resolution that named none is advertised with.
    fn ttl_for(&self, identity: &TokenIdentity) -> i64 {
        identity.ttl_seconds.unwrap_or(self.default_ttl_seconds) as i64
    }
}

// ---------------------------------------------------------------------------
// Wire shape
//
// Field declaration order is part of the schema and therefore part of the
// protocol hash. Nothing here may be reordered "for tidiness", and the list
// item's nullability below is not a detail: `list<item?:utf8>` and
// `list<item:utf8>` are different protocols.
// ---------------------------------------------------------------------------

/// Method name: resolve an opaque credential to the identity it authenticates as.
pub const INTROSPECT_TOKEN_METHOD: &str = "introspect_token";
/// Method name: mint a standing delegation credential for the calling user.
pub const ISSUE_GRANT_METHOD: &str = "issue_grant";

/// `introspect_token(token: utf8 non-null)`.
pub fn introspect_token_params_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "token",
        DataType::Utf8,
        false,
    )]))
}

/// `issue_grant(purpose: utf8, scopes: list<item?: utf8>, ttl_seconds: int64)`,
/// all non-null.
///
/// `scopes`'s element type comes from this port's own `Vec<String>` mapping
/// rather than being spelled out here, so the item nullability the hash
/// depends on cannot drift from what every other list-valued parameter uses.
pub fn issue_grant_params_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("purpose", DataType::Utf8, false),
        Field::new(
            "scopes",
            <Vec<String> as crate::arrow_type::VgiArrow>::arrow_data_type(),
            false,
        ),
        Field::new("ttl_seconds", DataType::Int64, false),
    ]))
}

/// The single `result: binary non-null` column both methods return, carrying
/// the payload as a nested IPC stream -- the framework's ordinary convention
/// for a structured return.
pub fn identity_result_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "result",
        DataType::Binary,
        false,
    )]))
}

/// `TokenIdentity`'s payload schema.
///
/// **Never carries claims.** A pass-through claims field would let a worker
/// choose its caller's tenant routing, its row scope, and its policy branch,
/// and the asker derives everything it needs from the principal alone.
pub fn token_identity_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("principal", DataType::Utf8, false),
        Field::new("token_name", DataType::Utf8, false),
        Field::new("ttl_seconds", DataType::Int64, false),
    ]))
}

/// `IssuedGrant`'s payload schema.
pub fn issued_grant_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("token", DataType::Utf8, false),
        Field::new("expires_at", DataType::Float64, false),
        Field::new("grant_id", DataType::Utf8, false),
    ]))
}

/// Wrap a payload batch in the `result` binary column.
fn nest_payload(batch: &RecordBatch) -> Result<RecordBatch> {
    let nested = crate::reflection::batch_to_ipc(batch)?;
    RecordBatch::try_new(
        identity_result_schema(),
        vec![Arc::new(arrow_array::BinaryArray::from(vec![nested.as_slice()])) as ArrayRef],
    )
    .map_err(|e| RpcError::protocol_error(format!("building identity result: {e}")))
}

/// Serialize a [`TokenIdentity`] into the `result` column.
pub fn token_identity_batch(identity: &TokenIdentity, ttl_seconds: i64) -> Result<RecordBatch> {
    let payload = RecordBatch::try_new(
        token_identity_schema(),
        vec![
            Arc::new(arrow_array::StringArray::from(vec![identity
                .principal
                .as_str()])) as ArrayRef,
            Arc::new(arrow_array::StringArray::from(vec![identity
                .token_name
                .as_str()])) as ArrayRef,
            Arc::new(arrow_array::Int64Array::from(vec![ttl_seconds])) as ArrayRef,
        ],
    )
    .map_err(|e| RpcError::protocol_error(format!("building TokenIdentity batch: {e}")))?;
    nest_payload(&payload)
}

/// Serialize an [`IssuedGrant`] into the `result` column.
pub fn issued_grant_batch(grant: &IssuedGrant) -> Result<RecordBatch> {
    let payload = RecordBatch::try_new(
        issued_grant_schema(),
        vec![
            Arc::new(arrow_array::StringArray::from(vec![grant.token.as_str()])) as ArrayRef,
            Arc::new(arrow_array::Float64Array::from(vec![grant.expires_at])) as ArrayRef,
            Arc::new(arrow_array::StringArray::from(vec![grant
                .grant_id
                .as_str()])) as ArrayRef,
        ],
    )
    .map_err(|e| RpcError::protocol_error(format!("building IssuedGrant batch: {e}")))?;
    nest_payload(&payload)
}

/// Read the `token` argument off an `introspect_token` request batch.
fn read_token(req: &Request) -> Result<String> {
    let col = req
        .column("token")
        .ok_or_else(|| RpcError::type_error("introspect_token requires a 'token' parameter"))?;
    <String as crate::arrow_type::VgiArrow>::read(col, 0)
}

/// Read the three `issue_grant` arguments off a request batch.
fn read_grant_args(req: &Request) -> Result<(String, Vec<String>, i64)> {
    use crate::arrow_type::VgiArrow;
    let purpose = <String as VgiArrow>::read(
        req.column("purpose")
            .ok_or_else(|| RpcError::type_error("issue_grant requires a 'purpose' parameter"))?,
        0,
    )?;
    let scopes = <Vec<String> as VgiArrow>::read(
        req.column("scopes")
            .ok_or_else(|| RpcError::type_error("issue_grant requires a 'scopes' parameter"))?,
        0,
    )?;
    let ttl_seconds = <i64 as VgiArrow>::read(
        req.column("ttl_seconds").ok_or_else(|| {
            RpcError::type_error("issue_grant requires a 'ttl_seconds' parameter")
        })?,
        0,
    )?;
    Ok((purpose, scopes, ttl_seconds))
}

/// One protocol hosted by a server: the implementation, the methods its hooks
/// actually justify, and the fingerprint that narrows with them.
pub struct IdentityBinding {
    /// The methods this deployment hosts -- never the full protocol, only what
    /// the configured hooks can answer.
    pub methods: HashMap<String, MethodInfo>,
    /// `protocol_hash` over exactly [`Self::methods`]. Narrowing the method set
    /// narrows the hash with it, which is correct: a server offering half the
    /// methods is not offering the same surface.
    pub protocol_hash: String,
}

impl IdentityBinding {
    /// Build the binding for `identity`, hosting only the methods whose hooks
    /// exist.
    ///
    /// Returns `None` when neither hook is configured: with nothing to answer,
    /// the protocol is not registered at all.
    pub fn new(identity: Arc<IdentityImpl>) -> Option<Self> {
        let offered = identity.offered_methods();
        if offered.is_empty() {
            return None;
        }
        let mut methods: HashMap<String, MethodInfo> = HashMap::new();
        if offered.contains(INTROSPECT_TOKEN_METHOD) {
            let impl_ = identity.clone();
            methods.insert(
                INTROSPECT_TOKEN_METHOD.to_string(),
                MethodInfo::unary(
                    INTROSPECT_TOKEN_METHOD,
                    introspect_token_params_schema(),
                    identity_result_schema(),
                    move |req: &Request, ctx: &CallContext| {
                        // The credential is read before the guards run only
                        // because it has to be read to be passed; nothing
                        // *inspects* it until `introspect_token` has
                        // authorized the caller.
                        let token = read_token(req)?;
                        let resolved = impl_.introspect_token(&token, &ctx.auth)?;
                        let ttl = impl_.ttl_for(&resolved);
                        token_identity_batch(&resolved, ttl).map(Some)
                    },
                )
                .doc("Resolve an opaque bearer credential to the identity it authenticates as.")
                .param_type("token", "str"),
            );
        }
        if offered.contains(ISSUE_GRANT_METHOD) {
            let impl_ = identity.clone();
            methods.insert(
                ISSUE_GRANT_METHOD.to_string(),
                MethodInfo::unary(
                    ISSUE_GRANT_METHOD,
                    issue_grant_params_schema(),
                    identity_result_schema(),
                    move |req: &Request, ctx: &CallContext| {
                        let (purpose, scopes, ttl_seconds) = read_grant_args(req)?;
                        let grant = impl_.issue_grant(&purpose, &scopes, ttl_seconds, &ctx.auth)?;
                        issued_grant_batch(&grant).map(Some)
                    },
                )
                .doc("Mint a standing delegation credential for the calling user.")
                .param_type("purpose", "str")
                .param_type("scopes", "list[str]")
                .param_type("ttl_seconds", "int"),
            );
        }
        let protocol_hash =
            crate::reflection::binding_hash(IDENTITY_PROTOCOL_NAME, &methods).unwrap_or_default();
        Some(Self {
            methods,
            protocol_hash,
        })
    }

    /// Method names, sorted -- for the "no such method" diagnostic.
    pub fn sorted_method_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.methods.keys().map(String::as_str).collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "good";

    fn resolver() -> TokenResolver {
        Arc::new(|token: &str| {
            Ok((token == GOOD).then(|| TokenIdentity::new("bob").with_token_name("ci-key")))
        })
    }

    fn minter() -> GrantMinter {
        Arc::new(
            |principal: &str, _purpose: &str, _scopes: &[String], ttl: i64| {
                Ok(
                    IssuedGrant::new(format!("grant-for-{principal}"), now_unix() + ttl as f64)
                        .with_grant_id("g1"),
                )
            },
        )
    }

    fn introspecting() -> IdentityImpl {
        IdentityImpl::builder()
            .resolve_token(resolver())
            .introspect_principals(["proxy"])
            .build()
    }

    fn minting() -> IdentityImpl {
        IdentityImpl::builder().mint_grant(minter()).build()
    }

    /// An authenticated caller, optionally carrying an `auth_time` claim.
    fn auth(principal: &str) -> AuthContext {
        AuthContext::for_principal("test", principal)
    }

    fn auth_at(principal: &str, auth_time: f64) -> AuthContext {
        auth(principal).with_claim("auth_time", format!("{auth_time}"))
    }

    fn unauthenticated(principal: &str) -> AuthContext {
        AuthContext {
            domain: "test".into(),
            authenticated: false,
            principal: principal.into(),
            claims: Default::default(),
        }
    }

    // -- Registration: absent beats routed-and-refusing --------------------

    /// A dependency upgrade must not grow an oracle on every worker.
    #[test]
    fn absent_by_default() {
        let server = crate::server::RpcServer::new("srv");
        assert!(!server
            .hosted_protocol_names()
            .contains(&IDENTITY_PROTOCOL_NAME));
    }

    /// What the server hosts describes what it actually does.
    #[test]
    fn only_methods_with_hooks_are_hosted() {
        assert_eq!(
            introspecting()
                .offered_methods()
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["introspect_token"]
        );
        assert_eq!(
            minting().offered_methods().into_iter().collect::<Vec<_>>(),
            vec!["issue_grant"]
        );
        let both = IdentityImpl::builder()
            .resolve_token(resolver())
            .mint_grant(minter())
            .introspect_principals(["proxy"])
            .build();
        assert_eq!(
            both.offered_methods().into_iter().collect::<Vec<_>>(),
            vec!["introspect_token", "issue_grant"]
        );
    }

    /// Narrowing the method set narrows the protocol hash with it.
    #[test]
    fn hosted_binding_carries_only_the_offered_methods() {
        let binding = IdentityBinding::new(Arc::new(minting())).unwrap();
        assert_eq!(binding.sorted_method_names(), vec!["issue_grant"]);
    }

    /// Neither hook configured: the protocol is not registered at all.
    #[test]
    fn no_hooks_means_no_binding() {
        let empty = IdentityImpl::builder().build();
        assert!(IdentityBinding::new(Arc::new(empty)).is_none());
    }

    /// Framework-owned, so an application cannot impersonate it.
    #[test]
    fn claims_the_reserved_prefix() {
        assert!(IDENTITY_PROTOCOL_NAME.starts_with(crate::binding::RESERVED_PROTOCOL_PREFIX));
        // And an application may not register it.
        assert!(crate::binding::validate_protocol_name(IDENTITY_PROTOCOL_NAME, false).is_err());
        assert!(crate::binding::validate_protocol_name(IDENTITY_PROTOCOL_NAME, true).is_ok());
    }

    // -- The hash vectors --------------------------------------------------

    fn hash_for(methods: &[&str]) -> String {
        let identity = IdentityImpl::builder()
            .resolve_token(resolver())
            .mint_grant(minter())
            .introspect_principals(["proxy"])
            .build();
        let mut binding = IdentityBinding::new(Arc::new(identity)).unwrap();
        binding
            .methods
            .retain(|name, _| methods.contains(&name.as_str()));
        crate::reflection::binding_hash(IDENTITY_PROTOCOL_NAME, &binding.methods).unwrap()
    }

    /// The cross-port contract. A mismatch means this port and the reference
    /// would disagree about whether they speak the same protocol.
    ///
    /// A failure is a JSON diff, not a guess: print
    /// [`crate::protocol_hash::canonical_description`] and compare against the
    /// preimage pinned in `canonical_preimage_matches_the_reference` below.
    #[test]
    fn matches_the_reference_hash_vectors() {
        assert_eq!(
            hash_for(&["introspect_token", "issue_grant"]),
            "8317f2ad8e2476bb99e8b94800ab79b19a8cf0c6bdd6d66c2d82bd62ffbe69d5",
            "both methods"
        );
        assert_eq!(
            hash_for(&["introspect_token"]),
            "27b75bef22e4c70baab92a5188a473506b89055d2cb2b58cc187f6fe7a436385",
            "introspect_token only"
        );
        assert_eq!(
            hash_for(&["issue_grant"]),
            "c71b12f453310139b6b6a445378064661c52711d03ae1e4fba29b8f7976ef4d8",
            "issue_grant only"
        );
    }

    /// The single-method digests above are not decoration: they prove
    /// method-level narrowing actually narrows the hash rather than hosting a
    /// method that refuses.
    #[test]
    fn narrowing_the_method_set_changes_the_hash() {
        let both = hash_for(&["introspect_token", "issue_grant"]);
        assert_ne!(both, hash_for(&["introspect_token"]));
        assert_ne!(both, hash_for(&["issue_grant"]));
    }

    /// Pinned so a digest mismatch is diffable rather than a mystery.
    #[test]
    fn canonical_preimage_matches_the_reference() {
        let identity = IdentityImpl::builder()
            .resolve_token(resolver())
            .mint_grant(minter())
            .introspect_principals(["proxy"])
            .build();
        let binding = IdentityBinding::new(Arc::new(identity)).unwrap();
        let entries = crate::reflection::hash_methods(&binding.methods);
        let preimage =
            crate::protocol_hash::canonical_description(IDENTITY_PROTOCOL_NAME, &entries).unwrap();
        assert_eq!(
            preimage,
            r#"{"methods":[{"has_header":false,"has_return":true,"name":"introspect_token","params":[{"name":"token","nullable":false,"type":"utf8"}],"result":[{"name":"result","nullable":false,"type":"binary"}],"type":"unary"},{"has_header":false,"has_return":true,"name":"issue_grant","params":[{"name":"purpose","nullable":false,"type":"utf8"},{"name":"scopes","nullable":false,"type":"list<item?:utf8>"},{"name":"ttl_seconds","nullable":false,"type":"int64"}],"result":[{"name":"result","nullable":false,"type":"binary"}],"type":"unary"}],"protocol":"vgi_rpc.Identity.v1"}"#
        );
    }

    /// The list *item* is nullable. Getting this wrong changes the hash, and
    /// TypeScript already shipped that bug once across every list type.
    #[test]
    fn scopes_list_item_is_nullable() {
        let schema = issue_grant_params_schema();
        let DataType::List(item) = schema.field_with_name("scopes").unwrap().data_type() else {
            panic!("scopes must be a list");
        };
        assert!(item.is_nullable(), "the list item must be nullable");
        assert_eq!(
            crate::type_tokens::type_token(schema.field_with_name("scopes").unwrap().data_type())
                .unwrap(),
            "list<item?:utf8>"
        );
    }

    // -- Introspection is locked down --------------------------------------

    /// The happy path, for the reverse proxy the method exists for.
    #[test]
    fn resolves_for_an_allowlisted_caller() {
        let got = introspecting()
            .introspect_token(GOOD, &auth("proxy"))
            .unwrap();
        assert_eq!(got.principal, "bob");
        assert_eq!(got.token_name, "ci-key");
    }

    /// Authentication is not the same capability as introspection. A
    /// deployment where any valid credential may introspect lets any user test
    /// guesses of any other user's credential at unlimited rate, and resolve a
    /// stolen one to its owner.
    #[test]
    fn a_caller_off_the_allowlist_is_refused() {
        for caller in ["alice", ""] {
            let err = introspecting()
                .introspect_token(GOOD, &auth(caller))
                .unwrap_err();
            assert_eq!(
                err.error_kind.as_deref(),
                Some(ERROR_KIND_INTROSPECTION_REFUSED),
                "caller {caller:?}"
            );
        }
    }

    /// Subprocess and unix transports carry no authenticated principal.
    #[test]
    fn an_unauthenticated_caller_is_refused() {
        let err = introspecting()
            .introspect_token(GOOD, &unauthenticated("proxy"))
            .unwrap_err();
        assert_eq!(
            err.error_kind.as_deref(),
            Some(ERROR_KIND_INTROSPECTION_REFUSED)
        );
    }

    /// An unauthorized caller learns nothing, including how long it took.
    #[test]
    fn refusal_precedes_the_resolver() {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let spy = seen.clone();
        let impl_ = IdentityImpl::builder()
            .resolve_token(Arc::new(move |token: &str| {
                spy.lock().unwrap().push(token.to_string());
                Ok(None)
            }))
            .introspect_principals(["proxy"])
            .build();
        assert!(impl_.introspect_token("secret", &auth("mallory")).is_err());
        assert!(
            seen.lock().unwrap().is_empty(),
            "the resolver must not see a credential from an unauthorized caller"
        );
    }

    /// The guard *order* is the security property, not just the guard set.
    ///
    /// An unauthorized caller presenting an over-long or JWS-shaped token
    /// still gets `introspection_refused`, never `token_unresolved`: the
    /// second answer would tell them their subject reached the shape check,
    /// which is one bit more than nothing.
    #[test]
    fn authorization_precedes_every_look_at_the_subject() {
        let impl_ = introspecting();
        for probe in [
            "x".repeat(MAX_TOKEN_CHARS + 1),
            "aaa.bbb.ccc".to_string(),
            String::new(),
        ] {
            let err = impl_
                .introspect_token(&probe, &auth("mallory"))
                .unwrap_err();
            assert_eq!(
                err.error_kind.as_deref(),
                Some(ERROR_KIND_INTROSPECTION_REFUSED),
                "an unauthorized caller must not learn the subject was even looked at"
            );
        }
    }

    /// Rate limiting also precedes the subject: an allowlisted caller that has
    /// exhausted its budget is refused before the credential is inspected.
    #[test]
    fn the_rate_limit_precedes_every_look_at_the_subject() {
        let impl_ = IdentityImpl::builder()
            .resolve_token(resolver())
            .introspect_principals(["proxy"])
            .introspect_rate_limit(1)
            .build();
        assert!(impl_.introspect_token(GOOD, &auth("proxy")).is_ok());
        let err = impl_
            .introspect_token("aaa.bbb.ccc", &auth("proxy"))
            .unwrap_err();
        assert_eq!(
            err.error_kind.as_deref(),
            Some(ERROR_KIND_INTROSPECTION_REFUSED)
        );
        assert!(err.message.contains("rate limit"));
    }

    /// Unknown, malformed and over-long are one answer. Distinguishing them
    /// would confirm that a guessed credential exists.
    #[test]
    fn rejections_are_uniform() {
        let impl_ = introspecting();
        for probe in ["", "unknown", &"x".repeat(MAX_TOKEN_CHARS + 1)] {
            let err = impl_.introspect_token(probe, &auth("proxy")).unwrap_err();
            assert_eq!(
                err.error_kind.as_deref(),
                Some(ERROR_KIND_TOKEN_UNRESOLVED),
                "probe {probe:?}"
            );
            assert_eq!(err.message, "unresolved", "probe {probe:?}");
        }
    }

    /// Routing a JWS onward hands a third party a token the asker may have
    /// rejected -- expired, wrong audience -- turning this method into a
    /// laundering step. The spy resolves *everything* on purpose: against an
    /// unknown JWS a missing shape guard rejects it as unknown and the test
    /// would pass for the wrong reason.
    #[test]
    fn a_jws_never_reaches_the_resolver() {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let spy = seen.clone();
        let impl_ = IdentityImpl::builder()
            .resolve_token(Arc::new(move |token: &str| {
                spy.lock().unwrap().push(token.to_string());
                Ok(Some(TokenIdentity::new("bob")))
            }))
            .introspect_principals(["proxy"])
            .build();
        let err = impl_
            .introspect_token("aaa.bbb.ccc", &auth("proxy"))
            .unwrap_err();
        assert_eq!(err.error_kind.as_deref(), Some(ERROR_KIND_TOKEN_UNRESOLVED));
        assert!(
            seen.lock().unwrap().is_empty(),
            "the resolver was handed a JWS"
        );
    }

    /// A caller that negative-caches "unknown" must not cache this. Cache an
    /// outage and a worker restart takes the fleet down for the cache's
    /// lifetime; retry a rejection and the worker is hammered.
    #[test]
    fn unavailable_is_transient_not_definitive() {
        let impl_ = IdentityImpl::builder()
            .resolve_token(Arc::new(|_: &str| {
                Err(identity_unavailable("store is down"))
            }))
            .introspect_principals(["proxy"])
            .build();
        let err = impl_.introspect_token(GOOD, &auth("proxy")).unwrap_err();
        assert_eq!(
            err.error_kind.as_deref(),
            Some(ERROR_KIND_IDENTITY_UNAVAILABLE)
        );
        assert!(err.retry_after_seconds.unwrap_or(0) > 0);
        // Must not be mistakable for the definitive rejection: that is a
        // `ValueError`, and this is the transient type the HTTP layer maps to
        // 503 + Retry-After rather than to a 4xx a caller may cache.
        assert!(err.is_auth_unavailable());
        assert_ne!(err.error_type, "ValueError");
        assert_ne!(err.error_type, token_unresolved().error_type);
    }

    /// Bounds, rather than closes, the oracle an allowlisted caller still has.
    #[test]
    fn rate_limited() {
        let impl_ = IdentityImpl::builder()
            .resolve_token(resolver())
            .introspect_principals(["proxy"])
            .introspect_rate_limit(2)
            .build();
        assert_eq!(
            impl_
                .introspect_token(GOOD, &auth("proxy"))
                .unwrap()
                .principal,
            "bob"
        );
        assert_eq!(
            impl_
                .introspect_token(GOOD, &auth("proxy"))
                .unwrap()
                .principal,
            "bob"
        );
        let err = impl_.introspect_token(GOOD, &auth("proxy")).unwrap_err();
        assert!(err.message.contains("rate limit"));
    }

    /// There is no permissive default, so it cannot be reached by omission.
    #[test]
    #[should_panic(expected = "at least one principal")]
    fn an_allowlist_is_mandatory() {
        let _ = IdentityImpl::builder().resolve_token(resolver()).build();
    }

    /// Nor by supplying an empty one.
    #[test]
    #[should_panic(expected = "at least one principal")]
    fn an_empty_allowlist_is_not_an_allowlist() {
        let _ = IdentityImpl::builder()
            .resolve_token(resolver())
            .introspect_principals(Vec::<String>::new())
            .build();
    }

    // -- Issuance is not an oracle -----------------------------------------

    /// The happy path: a present user minting their own standing grant.
    #[test]
    fn mints_for_the_caller() {
        let grant = minting()
            .issue_grant(
                "reports",
                &["read".to_string()],
                3600,
                &auth_at("alice", now_unix()),
            )
            .unwrap();
        assert_eq!(grant.token, "grant-for-alice");
        assert!(grant.expires_at > now_unix());
    }

    /// Cross-subject minting is closed by construction, not by a check.
    ///
    /// A check is something one of seven ports can forget; a missing parameter
    /// is not. The wire shape is where that is enforced, so this asserts on
    /// the declared parameter schema rather than on a Rust signature.
    #[test]
    fn the_subject_is_the_caller_and_is_not_a_parameter() {
        let schema = issue_grant_params_schema();
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert_eq!(names, vec!["purpose", "scopes", "ttl_seconds"]);
        assert!(!names.contains(&"subject"));
        assert!(!names.contains(&"principal"));
    }

    /// The minter is handed the *caller*, whatever the request said.
    #[test]
    fn the_minter_receives_the_caller_principal() {
        let seen = Arc::new(Mutex::new(String::new()));
        let spy = seen.clone();
        let impl_ = IdentityImpl::builder()
            .mint_grant(Arc::new(
                move |principal: &str, _p: &str, _s: &[String], _t: i64| {
                    *spy.lock().unwrap() = principal.to_string();
                    Ok(IssuedGrant::new("t", 0.0))
                },
            ))
            .build();
        impl_
            .issue_grant("p", &[], 60, &auth_at("alice", now_unix()))
            .unwrap();
        assert_eq!(*seen.lock().unwrap(), "alice");
    }

    /// Unlike introspection -- and the asymmetry is the whole design.
    #[test]
    fn needs_no_allowlist() {
        assert_eq!(
            minting().offered_methods().into_iter().collect::<Vec<_>>(),
            vec!["issue_grant"]
        );
    }

    // -- Freshness ---------------------------------------------------------

    /// A static bearer proves a machine holds a secret, never that a human
    /// just logged in.
    #[test]
    fn absent_auth_time_is_refused() {
        let err = minting()
            .issue_grant("p", &[], 60, &auth("alice"))
            .unwrap_err();
        assert_eq!(err.error_kind.as_deref(), Some(ERROR_KIND_STALE_AUTH));
        assert!(err.message.contains("no auth_time"));
    }

    /// Naming the reason leaks nothing here: it is always about the caller. A
    /// console that cannot tell "your login is too old" from "no" cannot know
    /// to re-prompt.
    #[test]
    fn stale_auth_time_is_refused_actionably() {
        let err = minting()
            .issue_grant("p", &[], 60, &auth_at("alice", now_unix() - 5000.0))
            .unwrap_err();
        assert_eq!(err.error_kind.as_deref(), Some(ERROR_KIND_STALE_AUTH));
        assert!(err.message.contains("re-authenticate"));
    }

    /// The ceiling is a ceiling, not an equality.
    #[test]
    fn fresh_auth_time_is_accepted() {
        let grant = minting()
            .issue_grant("p", &[], 60, &auth_at("alice", now_unix() - 10.0))
            .unwrap();
        assert_eq!(grant.token, "grant-for-alice");
    }

    /// An `auth_time` that is present but not a number is not an `auth_time`.
    #[test]
    fn unparseable_auth_time_is_refused() {
        let caller = auth("alice").with_claim("auth_time", "yesterday");
        let err = minting().issue_grant("p", &[], 60, &caller).unwrap_err();
        assert_eq!(err.error_kind.as_deref(), Some(ERROR_KIND_STALE_AUTH));
        assert!(err.message.contains("unusable auth_time"));
    }

    /// The lineage cannot escape the identity provider.
    ///
    /// A grant is not an IdP-issued token, so it carries no `auth_time`, so
    /// presenting one here fails the freshness check. That single rule is what
    /// stops indefinite self-renewal.
    #[test]
    fn a_grant_cannot_mint_another_grant() {
        // No auth_time: this is what a grant-bearing caller looks like.
        let grant_bearer = auth("alice");
        assert!(minting().issue_grant("p", &[], 60, &grant_bearer).is_err());
    }

    /// Subprocess and unix have no authenticated principal at all.
    #[test]
    fn unauthenticated_transport_fails_closed() {
        let err = minting()
            .issue_grant("p", &[], 60, &AuthContext::anonymous())
            .unwrap_err();
        assert_eq!(err.error_kind.as_deref(), Some(ERROR_KIND_STALE_AUTH));
        assert!(err.message.contains("not authenticated"));
    }

    // -- Absent hooks ------------------------------------------------------

    /// Refused rather than crashing, for a caller that reached it anyway.
    #[test]
    fn introspection_without_a_resolver() {
        let err = minting()
            .introspect_token(GOOD, &auth("proxy"))
            .unwrap_err();
        assert_eq!(
            err.error_kind.as_deref(),
            Some(ERROR_KIND_INTROSPECTION_REFUSED)
        );
        assert!(err.message.contains("does not resolve"));
    }

    /// Same, on the other side.
    #[test]
    fn issuance_without_a_minter() {
        let err = introspecting()
            .issue_grant("p", &[], 60, &auth_at("alice", now_unix()))
            .unwrap_err();
        assert_eq!(err.error_kind.as_deref(), Some(ERROR_KIND_GRANT_REFUSED));
        assert!(err.message.contains("does not mint"));
    }

    // -- Diagnostics -------------------------------------------------------

    /// Stable enough to correlate one credential's failures; not the
    /// credential.
    #[test]
    fn the_digest_is_not_the_token() {
        assert_ne!(token_digest("secret"), "secret");
        assert_eq!(token_digest("secret"), token_digest("secret"));
        assert_ne!(token_digest("secret"), token_digest("other"));
        assert_eq!(token_digest("secret").len(), 64);
    }

    /// The `error_kind` strings are the only definitive/transient signal a
    /// caller has. These were an HTTP route whose callers classified on the
    /// status code (404 vs 503); as protocol methods every handler failure
    /// surfaces the same way, so `error_kind` carries the whole distinction.
    #[test]
    fn error_kinds_are_stable() {
        assert_eq!(
            introspection_refused("x").error_kind.as_deref(),
            Some("introspection_refused")
        );
        assert_eq!(
            token_unresolved().error_kind.as_deref(),
            Some("token_unresolved")
        );
        assert_eq!(stale_auth("x").error_kind.as_deref(), Some("stale_auth"));
        assert_eq!(
            grant_refused("x").error_kind.as_deref(),
            Some("grant_refused")
        );
        assert_eq!(
            identity_unavailable("x").error_kind.as_deref(),
            Some("identity_unavailable")
        );
    }

    /// The credential must never reach an error message.
    #[test]
    fn a_rejection_never_quotes_the_credential() {
        let err = introspecting()
            .introspect_token("super-secret-credential", &auth("proxy"))
            .unwrap_err();
        assert!(!err.message.contains("super-secret-credential"));
    }

    // -- The rate limiter --------------------------------------------------

    /// Within a window.
    #[test]
    fn admits_up_to_the_limit() {
        let limiter = RateLimiter::new(3);
        let t = Instant::now();
        assert_eq!(
            (0..4).map(|_| limiter.allow_at("a", t)).collect::<Vec<_>>(),
            vec![true, true, true, false]
        );
    }

    /// A new window resets the count.
    #[test]
    fn window_rolls() {
        let limiter = RateLimiter::new(1);
        let t = Instant::now();
        assert!(limiter.allow_at("a", t));
        assert!(!limiter.allow_at("a", t + Duration::from_millis(500)));
        assert!(limiter.allow_at("a", t + Duration::from_millis(1500)));
    }

    /// One caller exhausting its budget must not refuse another.
    #[test]
    fn callers_are_independent() {
        let limiter = RateLimiter::new(1);
        let t = Instant::now();
        assert!(limiter.allow_at("a", t));
        assert!(limiter.allow_at("b", t));
        assert!(!limiter.allow_at("a", t));
    }

    /// Whole-map reset rather than per-key ageing, so an attacker cycling keys
    /// cannot grow the map without bound between sweeps.
    #[test]
    fn cycling_keys_cannot_grow_the_map() {
        let limiter = RateLimiter::new(1);
        let t = Instant::now();
        for i in 0..1000 {
            limiter.allow_at(&format!("k{i}"), t);
        }
        limiter.allow_at("fresh", t + Duration::from_secs(100));
        assert_eq!(limiter.tracked_keys(), 1);
    }

    // -- Payload shapes ----------------------------------------------------

    /// `TokenIdentity` never carries claims: a pass-through claims field would
    /// let a worker choose its caller's tenant routing, row scope and policy
    /// branch.
    #[test]
    fn the_token_identity_payload_carries_no_claims() {
        let schema = token_identity_schema();
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert_eq!(names, vec!["principal", "token_name", "ttl_seconds"]);
    }

    /// A resolution that names no TTL is advertised with the configured
    /// default rather than zero -- a zero TTL silently disables the caller's
    /// cache and turns every request into a round trip.
    #[test]
    fn a_resolution_without_a_ttl_takes_the_default() {
        let impl_ = introspecting();
        let resolved = impl_.introspect_token(GOOD, &auth("proxy")).unwrap();
        assert_eq!(impl_.ttl_for(&resolved), 300);
        let batch = token_identity_batch(&resolved, impl_.ttl_for(&resolved)).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.schema().field(0).name(), "result");
    }

    /// The grant payload declares a lifetime the framework cannot enforce:
    /// the real one lives inside the opaque token.
    #[test]
    fn the_grant_payload_declares_an_expiry() {
        let schema = issued_grant_schema();
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert_eq!(names, vec!["token", "expires_at", "grant_id"]);
        let batch = issued_grant_batch(&IssuedGrant::new("tok", 1.0)).unwrap();
        assert_eq!(batch.num_rows(), 1);
    }
}
