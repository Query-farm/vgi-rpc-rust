//! Fixed deployment policy for the `vgi_rpc.Identity.v1` conformance group.
//!
//! `vgi_rpc.Identity.v1` is nearly all *guards*, and every guard reads
//! deployment policy: who may introspect, what a credential resolves to,
//! whether a grant is minted, how recently the caller authenticated. A
//! cross-port assertion is impossible unless every port's conformance worker
//! configures the same policy, so it is pinned in
//! `IDENTITY_CONFORMANCE_FIXTURE.md` and transcribed here. The reference
//! implementation of the same policy is
//! `vgi-rpc-python/vgi_rpc/conformance/identity_fixture.py`.
//!
//! Two design rules shape the values below.
//!
//! **The resolver resolves almost everything.** Rejections are deliberately
//! uniform -- unknown, expired, malformed and over-long are one answer -- so
//! an over-long credential is *also* an unknown one, and a test that probes
//! the cap with a credential the resolver does not know stays green when the
//! cap is deleted. With a resolver that answers for whatever it is handed, a
//! rejection can only have come from a guard, and the *success* a broken guard
//! produces is loud.
//!
//! **Both hooks are pure functions of their arguments.** No clock, no counter,
//! no shared state: a conformance worker must answer identically on the first
//! call and the thousandth, and on a runtime that dispatches the two methods
//! on different threads. The one value that would otherwise need a clock -- a
//! grant's `expires_at` -- is a fixed constant so the wire value can be
//! asserted exactly rather than within a tolerance.
//!
//! # Warning
//!
//! The authentication this fixture relies on is header-driven and therefore
//! **trivially spoofable by anyone who can reach the port**. It exists to give
//! six language ports a deterministic authenticated caller without an identity
//! provider. It is a *test fixture* and must never be deployed.
//!
//! It lives in the library, beside [`crate::conformance_secondary`], so the
//! port's conformance worker and every VGI SDK fixture built on this crate
//! answer with the *same* policy rather than transcriptions of it.

use crate::auth::{AuthContext, AuthRequest, AuthResult};
use crate::errors::RpcError;
use crate::token_identity::{grant_refused, identity_unavailable, IssuedGrant, TokenIdentity};

// ---------------------------------------------------------------------------
// Authentication: two request headers, no identity provider
// ---------------------------------------------------------------------------

/// Header naming the authenticated principal. Absent means *unauthenticated*
/// -- not "anonymous but present" -- so an unauthenticated probe needs no
/// special casing anywhere, and `/health` keeps working. Already the
/// convention for the sticky fixture (`sticky-sessions-spec.md` §9), reused
/// rather than invented.
pub const PRINCIPAL_HEADER: &str = "x-conformance-principal";

/// Header carrying the `auth_time` claim, placed in the claim map **verbatim
/// as a string and unparsed**.
///
/// Verbatim matters. A fixture that parses the header and drops it when
/// parsing fails converts "carries an unusable auth_time" into "carries no
/// auth_time" -- the same `stale_auth` answer for a different reason, which
/// makes the unparseable case untestable rather than failing. The guard is
/// what parses; the fixture only transports.
pub const AUTH_TIME_HEADER: &str = "x-conformance-auth-time";

/// The single principal on the introspector allowlist. One, so "on the list"
/// and "authenticated but not on the list" are both reachable.
pub const INTROSPECTOR_PRINCIPAL: &str = "conformance-introspector";

// There is no `introspect_rate_limit` to configure: introspection is not rate
// limited (`TestIntrospectionIsNotThrottled` pins that). The fixture used to
// set it to 100,000 so a production-tuned limiter could not fire mid-group.

/// `max_auth_age` the worker must configure -- the documented default.
pub const MAX_AUTH_AGE_SECONDS: u64 = 900;

// ---------------------------------------------------------------------------
// What the resolver answers
// ---------------------------------------------------------------------------

/// The identity every resolvable credential maps to.
pub const SUBJECT_PRINCIPAL: &str = "subject@conformance.example";
/// The display name a fully-specified resolution carries.
pub const SUBJECT_TOKEN_NAME: &str = "conformance-subject";
/// The cache window a fully-specified resolution carries.
pub const SUBJECT_TTL: u64 = 300;

/// The one credential the resolver reports as **unknown**. Everything else it
/// has no rule for resolves, so a rejection of anything else can only have
/// come from a guard.
pub const TOKEN_UNKNOWN: &str = "conformance-unknown-token";

/// The credential the resolver reports as *unknowable* rather than unknown. A
/// caller may negative-cache "unknown"; caching an outage locks out a valid
/// user for as long as the cache holds, so the two must not share an answer.
pub const TOKEN_UNAVAILABLE: &str = "conformance-unavailable-token";

/// The credential whose resolver raises the **transport-auth** "unavailable"
/// error ([`RpcError::auth_unavailable`]) -- what a hook calling the same
/// store an authenticator calls raises when the store is down -- with a
/// retry hint of 7 seconds. WIRE_PROTOCOL.md §16 makes the *framework*
/// translate it to `identity_unavailable` + `RetryInfo{7}`; raising the
/// identity error here would make the test pass with the rule unimplemented.
pub const TOKEN_AUTH_UNAVAILABLE: &str = "conformance-auth-unavailable-token";

/// The hint the auth-unavailable probes carry. Deliberately not any port's
/// default, so a framework that translates but substitutes its own is caught.
pub const AUTH_UNAVAILABLE_RETRY_SECONDS: u32 = 7;

/// The pinned hint on [`TOKEN_UNAVAILABLE`].
pub const UNAVAILABLE_RETRY_SECONDS: u32 = 5;

/// A resolver naming a TTL of zero is saying *do not cache this*. This port
/// has an `Option<u64>` where zero is a value the hook set rather than an
/// absent one, and the group asserts the wire carries `0`: normalising `<= 0`
/// up to the 300 default would silently convert "do not cache" into five
/// minutes of continued access after revocation.
pub const TOKEN_ZERO_TTL: &str = "conformance-zero-ttl-token";

/// Resolves to an identity built with **only** the principal supplied, so the
/// other two fields land on their documented defaults (`""` and 300). The
/// other half of the rule above: a default is for an omitted field, never a
/// coercion applied to a value a hook actually set.
pub const TOKEN_MINIMAL: &str = "conformance-minimal-token";

/// A credential carrying two leading and two trailing ASCII spaces, resolved
/// to a *distinguishable* `token_name`. The shape test runs on the trimmed
/// credential while the resolver receives the untrimmed original; a port that
/// trims before resolving hands the resolver a different string, falls through
/// to the catch-all rule, and reports the wrong name. Nothing else can see
/// that -- the padded credential still resolves either way.
pub const TOKEN_PADDED_PROBE: &str = "  conformance-padded-probe  ";
/// The name the padded credential -- and only the padded credential -- carries.
pub const TOKEN_PADDED_PROBE_NAME: &str = "conformance-padded";

/// Resolve a credential under the fixed conformance policy.
///
/// Everything with no rule of its own resolves. That is the point: see the
/// module docs.
pub fn conformance_resolve_token(token: &str) -> Result<Option<TokenIdentity>, RpcError> {
    if token == TOKEN_UNAVAILABLE {
        return Err(
            identity_unavailable("conformance: mapping store unreachable")
                .with_retry_after(UNAVAILABLE_RETRY_SECONDS),
        );
    }
    if token == TOKEN_AUTH_UNAVAILABLE {
        return Err(
            RpcError::auth_unavailable("conformance: authority unreachable")
                .with_retry_after(AUTH_UNAVAILABLE_RETRY_SECONDS),
        );
    }
    if token == TOKEN_UNKNOWN {
        return Ok(None);
    }
    if token == TOKEN_ZERO_TTL {
        return Ok(Some(
            TokenIdentity::new(SUBJECT_PRINCIPAL)
                .with_token_name(SUBJECT_TOKEN_NAME)
                .with_ttl_seconds(0),
        ));
    }
    if token == TOKEN_MINIMAL {
        // Only the principal: `token_name` and `ttl_seconds` must land on
        // their documented defaults rather than being passed explicitly,
        // which would test the wrong thing.
        return Ok(Some(TokenIdentity::new(SUBJECT_PRINCIPAL)));
    }
    if token == TOKEN_PADDED_PROBE {
        return Ok(Some(
            TokenIdentity::new(SUBJECT_PRINCIPAL)
                .with_token_name(TOKEN_PADDED_PROBE_NAME)
                .with_ttl_seconds(SUBJECT_TTL),
        ));
    }
    Ok(Some(
        TokenIdentity::new(SUBJECT_PRINCIPAL)
            .with_token_name(SUBJECT_TOKEN_NAME)
            .with_ttl_seconds(SUBJECT_TTL),
    ))
}

// ---------------------------------------------------------------------------
// What the minter answers
// ---------------------------------------------------------------------------

/// Prefix of a minted grant's token. The caller's principal is appended, which
/// is how "the subject is the caller, never a parameter" becomes observable:
/// two callers get two different tokens from identical requests.
pub const GRANT_TOKEN_PREFIX: &str = "conformance-grant-for:";
/// Separator between the principal and the echoed scopes, so the scope list's
/// round trip is visible in the response.
pub const SCOPE_SEPARATOR: &str = "|";
/// Fixed rather than `now + ttl`: a constant can be asserted exactly, which
/// also pins the float64 round trip. `expires_at` is a declaration rather than
/// an enforcement -- the real lifetime lives inside the opaque token -- so
/// nothing is lost. 2030-01-01T00:00:00Z.
pub const GRANT_EXPIRES_AT: f64 = 1_893_456_000.0;
/// Correlation handle a full grant carries.
pub const GRANT_ID: &str = "conformance-grant-id";
/// The purpose this policy refuses, so `grant_refused` reaches the wire.
pub const REFUSED_PURPOSE: &str = "conformance-refused";
/// The purpose that mints a grant built without `grant_id`, so the field's
/// documented default (`""`) is observable.
pub const MINIMAL_PURPOSE: &str = "conformance-minimal";
/// The purpose whose minter raises the transport-auth "unavailable" error
/// with the 7-second hint: the translation rule covers both hooks.
pub const AUTH_UNAVAILABLE_PURPOSE: &str = "conformance-auth-unavailable";

/// Mint a grant under the fixed conformance policy.
///
/// `ttl_seconds` is deliberately ignored. It is a *request*, the returned
/// `expires_at` is authoritative, and a fixture that honoured it would need a
/// clock and become unassertable.
pub fn conformance_mint_grant(
    principal: &str,
    purpose: &str,
    scopes: &[String],
    _ttl_seconds: i64,
) -> Result<IssuedGrant, RpcError> {
    if purpose == AUTH_UNAVAILABLE_PURPOSE {
        return Err(
            RpcError::auth_unavailable("conformance: grant store unreachable")
                .with_retry_after(AUTH_UNAVAILABLE_RETRY_SECONDS),
        );
    }
    if purpose == REFUSED_PURPOSE {
        return Err(grant_refused("conformance: this purpose is refused"));
    }
    let token = format!(
        "{GRANT_TOKEN_PREFIX}{principal}{SCOPE_SEPARATOR}{}",
        scopes.join(",")
    );
    let grant = IssuedGrant::new(token, GRANT_EXPIRES_AT);
    // Omitted for MINIMAL_PURPOSE rather than passed as `""`, so the default
    // is what reaches the wire.
    Ok(if purpose == MINIMAL_PURPOSE {
        grant
    } else {
        grant.with_grant_id(GRANT_ID)
    })
}

/// Authenticate from [`PRINCIPAL_HEADER`] / [`AUTH_TIME_HEADER`], or stay
/// anonymous.
///
/// Naming yourself in a header is obviously not authentication -- it is the
/// cheapest thing every port can implement identically. Requests without the
/// header stay anonymous rather than being rejected -- in this port that
/// anonymous answer *is* "not mine", so a request carrying an `Authorization`
/// header but no principal header passes through to the identity bearer
/// authenticators (sealed grants, `resolve_token`) the grant worker composes
/// after this one (IDENTITY_CONFORMANCE_FIXTURE.md §10). `X-Conformance-Auth-Time`
/// rides along as the `auth_time` claim **verbatim and unparsed**: the guard
/// parses, the fixture only transports.
///
/// # Warning
///
/// Trivially spoofable by anyone who can reach the port. Never deploy it.
pub fn authenticate_from_headers(req: &AuthRequest) -> AuthResult {
    Ok(match req.header(PRINCIPAL_HEADER) {
        Some(principal) if !principal.is_empty() => {
            let ctx = AuthContext::for_principal("conformance", principal);
            match req.header(AUTH_TIME_HEADER) {
                Some(auth_time) => ctx.with_claim("auth_time", auth_time),
                None => ctx,
            }
        }
        _ => AuthContext::anonymous(),
    })
}

/// The full fixture deployment: both hooks, the one-principal allowlist and
/// the documented `max_auth_age`.
pub fn conformance_identity() -> crate::token_identity::IdentityImpl {
    crate::token_identity::IdentityImpl::builder()
        .resolve_token(std::sync::Arc::new(conformance_resolve_token))
        .mint_grant(std::sync::Arc::new(conformance_mint_grant))
        .introspect_principals([INTROSPECTOR_PRINCIPAL])
        .max_auth_age(std::time::Duration::from_secs(MAX_AUTH_AGE_SECONDS))
        .build()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_identity::MAX_TOKEN_BYTES;

    /// The multibyte probe the group sends is under the cap in codepoints and
    /// over it in bytes. Asserted here so a build that moved the cap's unit
    /// fails in `cargo test` rather than only in a conformance run.
    #[test]
    fn the_multibyte_probe_straddles_the_cap() {
        let probe = "\u{00E9}".repeat(2100);
        assert!(probe.chars().count() < MAX_TOKEN_BYTES);
        assert!(probe.len() > MAX_TOKEN_BYTES);
    }

    #[test]
    fn the_minimal_credential_leaves_both_optional_fields_unset() {
        let identity = conformance_resolve_token(TOKEN_MINIMAL).unwrap().unwrap();
        assert_eq!(identity.token_name, "");
        assert_eq!(
            identity.ttl_seconds, None,
            "the default must not be spelled"
        );
    }

    #[test]
    fn a_zero_ttl_is_a_value_the_hook_set() {
        let identity = conformance_resolve_token(TOKEN_ZERO_TTL).unwrap().unwrap();
        assert_eq!(identity.ttl_seconds, Some(0));
    }

    #[test]
    fn the_padded_credential_is_distinguishable_from_its_trimmed_form() {
        let padded = conformance_resolve_token(TOKEN_PADDED_PROBE)
            .unwrap()
            .unwrap();
        let trimmed = conformance_resolve_token(TOKEN_PADDED_PROBE.trim())
            .unwrap()
            .unwrap();
        assert_eq!(padded.token_name, TOKEN_PADDED_PROBE_NAME);
        assert_eq!(trimmed.token_name, SUBJECT_TOKEN_NAME);
    }

    #[test]
    fn an_empty_scope_list_still_echoes_its_separator() {
        let grant = conformance_mint_grant("minter@conformance.example", "conformance", &[], 60)
            .expect("minted");
        assert_eq!(
            grant.token,
            "conformance-grant-for:minter@conformance.example|"
        );
        assert_eq!(grant.grant_id, GRANT_ID);
        assert_eq!(grant.expires_at, GRANT_EXPIRES_AT);
    }

    #[test]
    fn the_minimal_purpose_omits_the_correlation_handle() {
        let grant = conformance_mint_grant("m", MINIMAL_PURPOSE, &["read".into()], 60).unwrap();
        assert_eq!(grant.grant_id, "");
    }

    /// Both auth-unavailable probes raise the *transport-auth* error with the
    /// pinned hint, untranslated: translating is the framework's job.
    #[test]
    fn auth_unavailable_probes_raise_the_transport_error() {
        let err = conformance_resolve_token(TOKEN_AUTH_UNAVAILABLE).unwrap_err();
        assert!(err.is_auth_unavailable());
        assert_eq!(err.error_kind, None);
        assert_eq!(
            err.retry_after_seconds,
            Some(AUTH_UNAVAILABLE_RETRY_SECONDS)
        );
        let err = conformance_mint_grant("m", AUTH_UNAVAILABLE_PURPOSE, &[], 60).unwrap_err();
        assert!(err.is_auth_unavailable());
        assert_eq!(
            err.retry_after_seconds,
            Some(AUTH_UNAVAILABLE_RETRY_SECONDS)
        );
    }
}

// ---------------------------------------------------------------------------
// Sealed grants and bearer acceptance (IDENTITY_CONFORMANCE_FIXTURE.md §10)
// ---------------------------------------------------------------------------

/// The grant worker's minting key: bytes `0x10..0x2f`. Published on purpose
/// -- the shared suite mints with it to prove this port's *verifier* accepts
/// reference-minted grants, and decodes this port's grants to prove its
/// *minter* matches. A fixture key, never a deployment one.
pub const GRANT_KEY_CURRENT: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = 0x10 + i as u8;
        i += 1;
    }
    k
};

/// The previous key, still configured to verify (rotation): `0x30..0x4f`.
pub const GRANT_KEY_PREVIOUS: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = 0x30 + i as u8;
        i += 1;
    }
    k
};

/// Audience bound into the grant worker's tokens.
pub const GRANT_AUDIENCE: &str = "conformance";

/// The grant worker's lifetime ceiling, in seconds.
pub const GRANT_MAX_TTL: i64 = 3600;

/// The grant worker's configuration: the current key mints, both verify.
#[cfg(feature = "crypto")]
pub fn conformance_grant_keys() -> crate::grants::GrantKeys {
    crate::grants::GrantKeys::new(
        [GRANT_KEY_CURRENT.to_vec(), GRANT_KEY_PREVIOUS.to_vec()],
        GRANT_AUDIENCE,
        GRANT_MAX_TTL,
        crate::grants::DEFAULT_CLOCK_SKEW_SECONDS,
    )
    .expect("the fixture grant keys are well-formed")
}

/// The grant worker's identity deployment: the fixture resolver, allowlist
/// and `max_auth_age`, the fixture grant keys, and **no mint hook** -- the
/// framework mints sealed grants.
#[cfg(feature = "crypto")]
pub fn conformance_grant_identity() -> crate::token_identity::IdentityImpl {
    crate::token_identity::IdentityImpl::builder()
        .resolve_token(std::sync::Arc::new(conformance_resolve_token))
        .grant_keys(conformance_grant_keys())
        .introspect_principals([INTROSPECTOR_PRINCIPAL])
        .max_auth_age(std::time::Duration::from_secs(MAX_AUTH_AGE_SECONDS))
        .build()
}

/// Routing key of the probe that reports how a request was authenticated.
pub const WHOAMI_PROTOCOL_NAME: &str = "conformance.Whoami.v1";

/// Pinned digest of `conformance.Whoami.v1`.
pub const WHOAMI_PROTOCOL_HASH: &str =
    "a280333ba72432020e162cab388a78355969a30aa74f0665ad9d2932d7a10b8f";

/// The caller's `AuthContext` as compact JSON with sorted keys:
/// `{"authenticated":bool,"claims":{...},"domain":str,"principal":str}`.
///
/// This port's claims are string-valued; a claim whose text is a JSON array
/// (a grant's `scopes`) is rendered as that array, so the probe reports the
/// same document the reference does.
pub fn whoami_json(auth: &AuthContext) -> String {
    let claims: serde_json::Map<String, serde_json::Value> = auth
        .claims
        .iter()
        .map(|(k, v)| {
            let value = match serde_json::from_str::<serde_json::Value>(v) {
                Ok(array @ serde_json::Value::Array(_)) => array,
                _ => serde_json::Value::String(v.clone()),
            };
            (k.clone(), value)
        })
        .collect();
    serde_json::json!({
        "authenticated": auth.authenticated,
        "claims": claims,
        "domain": auth.domain,
        "principal": auth.principal,
    })
    .to_string()
}

/// `conformance.Whoami.v1`: `whoami() -> utf8`, answering [`whoami_json`].
pub fn whoami_protocol() -> crate::server::HostedProtocol {
    use arrow_schema::{DataType, Field, Schema};
    let result = std::sync::Arc::new(Schema::new(vec![Field::new(
        "result",
        DataType::Utf8,
        false,
    )]));
    let out = result.clone();
    crate::server::HostedProtocol::new(WHOAMI_PROTOCOL_NAME).with_method(
        crate::server::MethodInfo::unary(
            "whoami",
            std::sync::Arc::new(Schema::empty()),
            result,
            move |_req, ctx| {
                let value = arrow_array::StringArray::from(vec![whoami_json(&ctx.auth)]);
                Ok(Some(arrow_array::RecordBatch::try_new(
                    out.clone(),
                    vec![std::sync::Arc::new(value)],
                )?))
            },
        ),
    )
}

#[cfg(test)]
mod grant_fixture_tests {
    use super::*;

    #[test]
    fn whoami_hashes_to_the_pin() {
        assert_eq!(whoami_protocol().protocol_hash(), WHOAMI_PROTOCOL_HASH);
    }

    #[test]
    fn whoami_renders_list_claims_as_arrays() {
        let ctx = AuthContext::for_principal("grant", "p")
            .with_claim("scopes", "[\"a\",\"b\"]")
            .with_claim("purpose", "x");
        assert_eq!(
            whoami_json(&ctx),
            r#"{"authenticated":true,"claims":{"purpose":"x","scopes":["a","b"]},"domain":"grant","principal":"p"}"#
        );
        assert_eq!(
            whoami_json(&AuthContext::anonymous()),
            r#"{"authenticated":false,"claims":{},"domain":"","principal":""}"#
        );
    }

    #[test]
    fn the_fixture_keys_are_the_published_bytes() {
        assert_eq!(GRANT_KEY_CURRENT[0], 0x10);
        assert_eq!(GRANT_KEY_CURRENT[31], 0x2f);
        assert_eq!(GRANT_KEY_PREVIOUS[0], 0x30);
        assert_eq!(GRANT_KEY_PREVIOUS[31], 0x4f);
    }
}
