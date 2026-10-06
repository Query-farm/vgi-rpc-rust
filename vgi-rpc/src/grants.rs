//! Sealed grants: the framework's own `issue_grant` credential, and its
//! verifier (IDENTITY_V1_SPEC.md §9, WIRE_PROTOCOL.md §16).
//!
//! `vgi_rpc.Identity.v1`'s `issue_grant` mints a standing delegation that
//! unattended automation later presents *as an ordinary bearer*. Until this
//! module nothing in this port accepted one: the loop was open. A sealed grant
//! closes it without storage and without author code. When a deployment
//! configures a **grant key**, the framework mints grants itself (unless the
//! worker supplies its own `mint_grant`) and accepts them back as bearer
//! credentials (see `http::grant_authenticate`). When it does not, nothing
//! changes -- absent beats hosted-and-refusing, so no worker grows a credential
//! issuer by upgrading.
//!
//! ```text
//! token    = "vgig1." base64url_nopad( kid(8) || envelope )
//! kid      = SHA-256("vgi_rpc.grant.kid.v1" 0x00 || key)[0:8]
//! envelope = 0x01 || nonce(24) || XChaCha20-Poly1305(payload, aad)   (ciphertext || tag)
//! aad      = "vgi_rpc.grant.v1" 0x00 || kid || UTF-8(audience)
//! payload  = issued_at i64 LE || expires_at i64 LE || grant_id || principal
//!            || purpose || scope_count u16 LE || scope*      (text = u16 LE len || UTF-8)
//! ```
//!
//! The envelope is [`crate::crypto`]'s, byte for byte -- the same construction
//! the stream-state tokens use, so no new cipher. Every port mints and
//! verifies byte-identically; `vgi_rpc/conformance/grant_token_vectors.json`
//! (copied into `tests/data/`) pins it.
//!
//! **Not individually revocable.** A sealed grant is valid until it expires;
//! the levers are a short maximum lifetime with re-issue, and removing a key
//! (which revokes every grant it minted). There is deliberately no revocation
//! list.

use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::errors::{Result, RpcError};
use crate::token_identity::{grant_refused, GrantMinter, IssuedGrant};

/// Token prefix. The version is in the prefix, so an incompatible format is a
/// different prefix -- routed elsewhere, never half-parsed.
pub const GRANT_TOKEN_PREFIX: &str = "vgig1.";
/// Comma-separated standard-base64 keys, minting key first.
pub const GRANT_KEYS_ENV: &str = "VGI_RPC_GRANT_KEYS";
/// Audience bound into every grant's associated data (default `""`).
pub const GRANT_AUDIENCE_ENV: &str = "VGI_RPC_GRANT_AUDIENCE";
/// Ceiling on a grant's lifetime, in seconds.
pub const GRANT_MAX_TTL_ENV: &str = "VGI_RPC_GRANT_MAX_TTL_SECONDS";
/// Default lifetime ceiling: seven days. Short on purpose -- expiry is the only
/// revocation a sealed grant has.
pub const DEFAULT_MAX_TTL_SECONDS: i64 = 7 * 24 * 3600;
/// Allowance for clocks disagreeing between the minting and verifying worker.
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;
/// Longest token text considered at all -- the same cap `introspect_token`
/// applies to a credential.
pub const MAX_GRANT_TOKEN_CHARS: usize = 4096;

const KEY_LEN: usize = 32;
const KID_LEN: usize = 8;
const ENVELOPE_VERSION: u8 = 1;
const KID_DOMAIN: &[u8] = b"vgi_rpc.grant.kid.v1\x00";
const AAD_DOMAIN: &[u8] = b"vgi_rpc.grant.v1\x00";
const MAX_FIELD: usize = 0xFFFF;

/// A token carrying the grant prefix that could not be accepted.
///
/// One type for every cause -- malformed, wrong key, wrong audience, tampered,
/// expired -- so a caller cannot tell a forged token from a stale one except
/// by [`Self::expired`], which is set only once the token was proven authentic
/// and so reveals nothing a forger could use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantInvalid {
    /// Operator-facing text. Never contains the token.
    pub detail: String,
    /// Authentic, but outside its lifetime.
    pub expired: bool,
}

impl GrantInvalid {
    fn new(detail: &str) -> Self {
        Self {
            detail: detail.to_string(),
            expired: false,
        }
    }
    fn lifetime(detail: &str) -> Self {
        Self {
            detail: detail.to_string(),
            expired: true,
        }
    }
}

impl std::fmt::Display for GrantInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for GrantInvalid {}

/// The 8-byte id a token names its sealing key with:
/// `SHA-256("vgi_rpc.grant.kid.v1" 0x00 || key)[0:8]`.
pub fn grant_key_id(key: &[u8]) -> [u8; KID_LEN] {
    let digest = Sha256::new()
        .chain_update(KID_DOMAIN)
        .chain_update(key)
        .finalize();
    let mut kid = [0u8; KID_LEN];
    kid.copy_from_slice(&digest[..KID_LEN]);
    kid
}

/// A deployment's grant configuration.
///
/// The first key mints; every key verifies. Rotation: add the new key first,
/// keep the old one after it until every grant it minted has expired, then
/// drop it.
#[derive(Clone)]
pub struct GrantKeys {
    keys: Vec<[u8; KEY_LEN]>,
    audience: String,
    max_ttl_seconds: i64,
    clock_skew_seconds: i64,
}

impl std::fmt::Debug for GrantKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key material.
        f.debug_struct("GrantKeys")
            .field("keys", &self.keys.len())
            .field("audience", &self.audience)
            .field("max_ttl_seconds", &self.max_ttl_seconds)
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .finish()
    }
}

impl GrantKeys {
    /// Build from raw 32-byte keys, minting key first.
    ///
    /// Errors (a worker refuses to start rather than run with them): no key, a
    /// key that is not exactly 32 bytes, two keys with one id, a non-positive
    /// lifetime, a negative skew, or an audience over 65535 bytes.
    pub fn new(
        keys: impl IntoIterator<Item = Vec<u8>>,
        audience: impl Into<String>,
        max_ttl_seconds: i64,
        clock_skew_seconds: i64,
    ) -> Result<Self> {
        let mut out: Vec<[u8; KEY_LEN]> = Vec::new();
        for key in keys {
            let key: [u8; KEY_LEN] = key.as_slice().try_into().map_err(|_| {
                RpcError::value_error(format!("every grant key must be exactly {KEY_LEN} bytes"))
            })?;
            out.push(key);
        }
        if out.is_empty() {
            return Err(RpcError::value_error(
                "grant configuration needs at least one key",
            ));
        }
        let mut kids: Vec<[u8; KID_LEN]> = out.iter().map(|k| grant_key_id(k)).collect();
        kids.sort_unstable();
        kids.dedup();
        if kids.len() != out.len() {
            return Err(RpcError::value_error("grant keys must be distinct"));
        }
        if max_ttl_seconds <= 0 {
            return Err(RpcError::value_error("max_ttl_seconds must be positive"));
        }
        if clock_skew_seconds < 0 {
            return Err(RpcError::value_error(
                "clock_skew_seconds must not be negative",
            ));
        }
        let audience = audience.into();
        if audience.len() > MAX_FIELD {
            return Err(RpcError::value_error("audience is too long"));
        }
        Ok(Self {
            keys: out,
            audience,
            max_ttl_seconds,
            clock_skew_seconds,
        })
    }

    /// Build from standard-base64 key text (padded or not), minting key first.
    pub fn parse<I, S>(encoded_keys: I, audience: &str, max_ttl_seconds: i64) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut keys = Vec::new();
        for (index, text) in encoded_keys.into_iter().enumerate() {
            let stripped = text.as_ref().trim().trim_end_matches('=');
            let key = STANDARD_NO_PAD.decode(stripped).map_err(|_| {
                RpcError::value_error(format!("grant key #{} is not valid base64", index + 1))
            })?;
            if key.len() != KEY_LEN {
                return Err(RpcError::value_error(format!(
                    "grant key #{} decodes to {} bytes; exactly {KEY_LEN} are required",
                    index + 1,
                    key.len()
                )));
            }
            keys.push(key);
        }
        Self::new(keys, audience, max_ttl_seconds, DEFAULT_CLOCK_SKEW_SECONDS)
    }

    /// Read `VGI_RPC_GRANT_*` through `get`; `Ok(None)` when no key is set
    /// (grants off).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        let raw = get(GRANT_KEYS_ENV).unwrap_or_default();
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let ttl_raw = get(GRANT_MAX_TTL_ENV).unwrap_or_default();
        let ttl_raw = ttl_raw.trim();
        let max_ttl = if ttl_raw.is_empty() {
            DEFAULT_MAX_TTL_SECONDS
        } else {
            ttl_raw.parse::<i64>().map_err(|_| {
                RpcError::value_error(format!("{GRANT_MAX_TTL_ENV}={ttl_raw:?} is not an integer"))
            })?
        };
        let audience = get(GRANT_AUDIENCE_ENV).unwrap_or_default();
        Self::parse(
            raw.split(',').filter(|p| !p.trim().is_empty()),
            &audience,
            max_ttl,
        )
        .map(Some)
    }

    /// [`Self::from_lookup`] over the process environment.
    pub fn from_env() -> Result<Option<Self>> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// The same configuration with the CLI's `--grant-key` values (repeatable,
    /// first mints) replacing the environment's keys; audience and lifetime
    /// still come from the environment. `Ok(None)` when neither names a key.
    pub fn from_cli_or_env(cli_keys: &[String]) -> Result<Option<Self>> {
        if cli_keys.is_empty() {
            return Self::from_env();
        }
        let joined = cli_keys.join(",");
        Self::from_lookup(|name| {
            if name == GRANT_KEYS_ENV {
                Some(joined.clone())
            } else {
                std::env::var(name).ok()
            }
        })
    }

    /// The audience bound into every token.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The lifetime ceiling, in seconds.
    pub fn max_ttl_seconds(&self) -> i64 {
        self.max_ttl_seconds
    }

    fn aad(&self, kid: &[u8; KID_LEN]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + KID_LEN + self.audience.len());
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(kid);
        aad.extend_from_slice(self.audience.as_bytes());
        aad
    }
}

/// What a verified grant says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantClaims {
    /// Whose standing delegation this is -- the caller it was minted for.
    pub principal: String,
    /// What it may do; the worker interprets them.
    pub scopes: Vec<String>,
    /// Why it was minted, for the audit trail.
    pub purpose: String,
    /// Correlation handle.
    pub grant_id: String,
    /// Seconds since the Unix epoch.
    pub issued_at: i64,
    /// Seconds since the Unix epoch.
    pub expires_at: i64,
}

fn pack_text(out: &mut Vec<u8>, value: &str) -> Result<()> {
    if value.len() > MAX_FIELD {
        return Err(RpcError::value_error("grant field longer than 65535 bytes"));
    }
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_payload(claims: &GrantClaims) -> Result<Vec<u8>> {
    if claims.scopes.len() > MAX_FIELD {
        return Err(RpcError::value_error("too many scopes"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&claims.issued_at.to_le_bytes());
    out.extend_from_slice(&claims.expires_at.to_le_bytes());
    pack_text(&mut out, &claims.grant_id)?;
    pack_text(&mut out, &claims.principal)?;
    pack_text(&mut out, &claims.purpose)?;
    out.extend_from_slice(&(claims.scopes.len() as u16).to_le_bytes());
    for scope in &claims.scopes {
        pack_text(&mut out, scope)?;
    }
    Ok(out)
}

/// A bounds-checked cursor over an opened payload.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], GrantInvalid> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| GrantInvalid::new("grant payload is truncated"))?;
        let chunk = &self.data[self.pos..end];
        self.pos = end;
        Ok(chunk)
    }

    fn i64(&mut self) -> std::result::Result<i64, GrantInvalid> {
        Ok(i64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn u16(&mut self) -> std::result::Result<usize, GrantInvalid> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")) as usize)
    }

    fn text(&mut self) -> std::result::Result<String, GrantInvalid> {
        let len = self.u16()?;
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| GrantInvalid::new("grant payload is not UTF-8"))
    }
}

/// Parse a payload strictly: exact lengths, valid UTF-8, no trailing bytes.
fn decode_payload(payload: &[u8]) -> std::result::Result<GrantClaims, GrantInvalid> {
    let mut c = Cursor {
        data: payload,
        pos: 0,
    };
    let issued_at = c.i64()?;
    let expires_at = c.i64()?;
    let grant_id = c.text()?;
    let principal = c.text()?;
    let purpose = c.text()?;
    let count = c.u16()?;
    let mut scopes = Vec::with_capacity(count);
    for _ in 0..count {
        scopes.push(c.text()?);
    }
    if c.pos != payload.len() {
        return Err(GrantInvalid::new("grant payload has trailing bytes"));
    }
    Ok(GrantClaims {
        principal,
        scopes,
        purpose,
        grant_id,
        issued_at,
        expires_at,
    })
}

/// Decode unpadded base64url, rejecting any non-canonical spelling: only the
/// URL-safe alphabet, no padding, a length that is not 1 mod 4, and bytes that
/// re-encode to the same text (rejects non-zero trailing bits), so one token
/// has exactly one spelling.
fn b64url_strict(text: &str) -> std::result::Result<Vec<u8>, GrantInvalid> {
    let alphabet_ok = !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !alphabet_ok || text.len() % 4 == 1 {
        return Err(GrantInvalid::new("grant token is not unpadded base64url"));
    }
    let raw = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(text)
    .map_err(|_| GrantInvalid::new("grant token is not unpadded base64url"))?;
    if URL_SAFE_NO_PAD.encode(&raw) != text {
        return Err(GrantInvalid::new("grant token is not canonical base64url"));
    }
    Ok(raw)
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn random_grant_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The parts of a mint a test vector pins. Production leaves every field
/// `None`.
#[derive(Debug, Clone, Default)]
pub struct MintOverrides {
    /// The clock, in seconds.
    pub now: Option<i64>,
    /// The grant id (otherwise 16 random bytes as 32 lowercase hex).
    pub grant_id: Option<String>,
    /// A fixed nonce -- **test vectors only**: reusing a nonce under one key
    /// destroys the AEAD's guarantees.
    pub nonce: Option<[u8; crate::crypto::NONCE_LEN]>,
}

/// Mint a sealed grant with the first configured key.
///
/// The lifetime is `min(ttl_seconds, max_ttl_seconds)`; a non-positive
/// `ttl_seconds` is an error.
pub fn mint_grant_token(
    keys: &GrantKeys,
    principal: &str,
    scopes: &[String],
    purpose: &str,
    ttl_seconds: i64,
    overrides: MintOverrides,
) -> Result<(String, GrantClaims)> {
    if ttl_seconds <= 0 {
        return Err(RpcError::value_error("ttl_seconds must be positive"));
    }
    let issued_at = overrides.now.unwrap_or_else(|| unix_now() as i64);
    let claims = GrantClaims {
        principal: principal.to_string(),
        scopes: scopes.to_vec(),
        purpose: purpose.to_string(),
        grant_id: overrides.grant_id.unwrap_or_else(random_grant_id),
        issued_at,
        expires_at: issued_at + ttl_seconds.min(keys.max_ttl_seconds),
    };
    let key = &keys.keys[0];
    let kid = grant_key_id(key);
    let payload = encode_payload(&claims)?;
    let aad = keys.aad(&kid);
    let envelope = match overrides.nonce {
        Some(nonce) => {
            crate::crypto::seal_bytes_with_nonce(&payload, key, &aad, ENVELOPE_VERSION, &nonce)
        }
        None => crate::crypto::seal_bytes(&payload, key, &aad, ENVELOPE_VERSION),
    };
    let mut raw = kid.to_vec();
    raw.extend_from_slice(&envelope);
    Ok((
        format!("{GRANT_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)),
        claims,
    ))
}

/// Verify a sealed grant and return its claims.
///
/// Order, normative (IDENTITY_V1_SPEC §9.1): prefix, length, canonical
/// base64url, key id, AEAD open, strict payload, then lifetime -- the lifetime
/// is inside the ciphertext, so it is trusted only after the tag verified.
/// `now` overrides the clock (seconds), for tests.
pub fn verify_grant_token(
    keys: &GrantKeys,
    token: &str,
    now: Option<f64>,
) -> std::result::Result<GrantClaims, GrantInvalid> {
    let Some(body) = token.strip_prefix(GRANT_TOKEN_PREFIX) else {
        return Err(GrantInvalid::new("not a sealed grant"));
    };
    if token.len() > MAX_GRANT_TOKEN_CHARS {
        return Err(GrantInvalid::new("grant token is too long"));
    }
    let raw = b64url_strict(body)?;
    if raw.len() < KID_LEN {
        return Err(GrantInvalid::new("grant token is truncated"));
    }
    let (kid, envelope) = raw.split_at(KID_LEN);
    let kid: [u8; KID_LEN] = kid.try_into().expect("8 bytes");
    let Some(key) = keys.keys.iter().find(|k| grant_key_id(&k[..]) == kid) else {
        return Err(GrantInvalid::new(
            "grant was sealed with a key this deployment does not hold",
        ));
    };
    let payload = crate::crypto::open_bytes(envelope, key, &keys.aad(&kid), ENVELOPE_VERSION)
        .map_err(|_| GrantInvalid::new("grant failed verification"))?;
    let claims = decode_payload(&payload)?;
    if claims.principal.is_empty() {
        return Err(GrantInvalid::new("grant names no principal"));
    }
    if claims.expires_at <= claims.issued_at
        || claims.expires_at.saturating_sub(claims.issued_at) > keys.max_ttl_seconds
    {
        return Err(GrantInvalid::new(
            "grant lifetime exceeds this deployment's maximum",
        ));
    }
    let current = now.unwrap_or_else(unix_now);
    let skew = keys.clock_skew_seconds as f64;
    if claims.issued_at as f64 > current + skew {
        return Err(GrantInvalid::lifetime("grant is not yet valid"));
    }
    if current >= claims.expires_at as f64 + skew {
        return Err(GrantInvalid::lifetime("grant has expired"));
    }
    Ok(claims)
}

/// A `mint_grant` hook issuing sealed grants -- what
/// [`IdentityImplBuilder::grant_keys`](crate::token_identity::IdentityImplBuilder::grant_keys)
/// installs when the worker supplies no hook of its own.
pub fn sealed_mint_grant(keys: GrantKeys) -> GrantMinter {
    Arc::new(move |principal, purpose, scopes, ttl_seconds| {
        if ttl_seconds <= 0 {
            return Err(grant_refused("ttl_seconds must be positive"));
        }
        let (token, claims) = mint_grant_token(
            &keys,
            principal,
            scopes,
            purpose,
            ttl_seconds,
            MintOverrides::default(),
        )
        .map_err(|e| grant_refused(e.message))?;
        Ok(IssuedGrant::new(token, claims.expires_at as f64).with_grant_id(claims.grant_id))
    })
}

/// Standard base64 of a key, for configuration text.
pub fn encode_grant_key(key: &[u8]) -> String {
    STANDARD.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/data/grant_token_vectors.json"))
            .expect("vector file is JSON")
    }

    fn b64(s: &str) -> Vec<u8> {
        STANDARD.decode(s).unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn strings(v: &Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn mint_reproduces_every_vector_token() {
        let v = vectors();
        for case in v["mint"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let key = b64(case["minting_key_b64"].as_str().unwrap());
            let keys = GrantKeys::new(
                [key.clone()],
                case["audience"].as_str().unwrap(),
                case["max_ttl_seconds"].as_i64().unwrap(),
                DEFAULT_CLOCK_SKEW_SECONDS,
            )
            .unwrap();
            let req = &case["request"];
            let nonce: [u8; 24] = hex(case["nonce_hex"].as_str().unwrap()).try_into().unwrap();
            let (token, claims) = mint_grant_token(
                &keys,
                req["principal"].as_str().unwrap(),
                &strings(&req["scopes"]),
                req["purpose"].as_str().unwrap(),
                req["ttl_seconds"].as_i64().unwrap(),
                MintOverrides {
                    now: Some(case["now"].as_i64().unwrap()),
                    grant_id: Some(req["grant_id"].as_str().unwrap().to_string()),
                    nonce: Some(nonce),
                },
            )
            .unwrap();
            assert_eq!(
                grant_key_id(&key).to_vec(),
                hex(case["kid_hex"].as_str().unwrap()),
                "{name}: kid"
            );
            assert_eq!(
                keys.aad(&grant_key_id(&key)),
                hex(case["aad_hex"].as_str().unwrap()),
                "{name}: aad"
            );
            assert_eq!(
                encode_payload(&claims).unwrap(),
                hex(case["payload_hex"].as_str().unwrap()),
                "{name}: payload"
            );
            assert_eq!(token, case["token"].as_str().unwrap(), "{name}: token");
            let want = &case["claims"];
            assert_eq!(claims.expires_at, want["expires_at"].as_i64().unwrap());
            // And the verifier opens what the minter made.
            let verified =
                verify_grant_token(&keys, &token, Some((claims.issued_at + 60) as f64)).unwrap();
            assert_eq!(verified, claims, "{name}: round trip");
        }
    }

    fn verify_case(v: &Value, case: &Value) -> std::result::Result<GrantClaims, GrantInvalid> {
        let d = &v["defaults"];
        let keys_b64 = case.get("verify_keys_b64").unwrap_or(&d["verify_keys_b64"]);
        let keys = GrantKeys::new(
            strings(keys_b64).iter().map(|k| b64(k)),
            case.get("audience")
                .unwrap_or(&d["audience"])
                .as_str()
                .unwrap(),
            case.get("max_ttl_seconds")
                .unwrap_or(&d["max_ttl_seconds"])
                .as_i64()
                .unwrap(),
            case.get("clock_skew_seconds")
                .unwrap_or(&d["clock_skew_seconds"])
                .as_i64()
                .unwrap(),
        )
        .unwrap();
        let now = case.get("now").unwrap_or(&d["now"]).as_f64().unwrap();
        verify_grant_token(&keys, case["token"].as_str().unwrap(), Some(now))
    }

    #[test]
    fn verifier_accepts_every_accept_vector() {
        let v = vectors();
        for case in v["accept"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            assert!(verify_case(&v, case).is_ok(), "{name} must be accepted");
        }
    }

    #[test]
    fn verifier_rejects_every_reject_vector_with_its_expired_flag() {
        let v = vectors();
        for case in v["reject"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let err = verify_case(&v, case).expect_err(name);
            assert_eq!(
                err.expired,
                case["expired"].as_bool().unwrap(),
                "{name}: expired flag ({})",
                err.detail
            );
        }
    }

    #[test]
    fn configuration_is_refused_at_startup_when_malformed() {
        let short = STANDARD.encode([1u8; 31]);
        assert!(GrantKeys::parse([short], "", 60).is_err());
        assert!(GrantKeys::parse(["not base64!"], "", 60).is_err());
        let key = STANDARD.encode([1u8; 32]);
        assert!(GrantKeys::parse([key.clone(), key.clone()], "", 60).is_err());
        assert!(GrantKeys::parse([key.clone()], "", 0).is_err());
        // Padding is optional.
        assert!(GrantKeys::parse([key.trim_end_matches('=')], "", 60).is_ok());
        let none = GrantKeys::from_lookup(|_| None).unwrap();
        assert!(none.is_none(), "no key means grants off");
        let bad_ttl = GrantKeys::from_lookup(|n| match n {
            GRANT_KEYS_ENV => Some(key.clone()),
            GRANT_MAX_TTL_ENV => Some("soon".into()),
            _ => None,
        });
        assert!(bad_ttl.is_err());
    }

    #[test]
    fn sealed_mint_refuses_a_non_positive_ttl_and_caps_the_lifetime() {
        let keys = GrantKeys::new([vec![7u8; 32]], "aud", 100, 60).unwrap();
        let mint = sealed_mint_grant(keys.clone());
        let err = mint("alice", "p", &[], 0).unwrap_err();
        assert_eq!(err.error_kind(), "grant_refused");
        let grant = mint("alice", "p", &["r".to_string()], 10_000).unwrap();
        let claims = verify_grant_token(&keys, &grant.token, None).unwrap();
        assert_eq!(claims.expires_at - claims.issued_at, 100);
        assert_eq!(claims.grant_id.len(), 32);
        assert_eq!(grant.grant_id, claims.grant_id);
        assert_eq!(grant.expires_at, claims.expires_at as f64);
    }
}
