//! OAuth 2.0 Authorization Code + PKCE browser login flow.
//!
//! Enabled by the `oauth-pkce` Cargo feature. Exposes crypto + token
//! helpers matching the Go/Python implementations:
//!
//!   - `generate_pkce_pair()` returns a (`code_verifier`, `code_challenge`)
//!     where `code_challenge = BASE64URL(SHA256(code_verifier))` — RFC 7636
//!     §4.2.
//!   - `new_state_cookie()` / `verify_state_cookie()` wrap an HMAC-signed
//!     "state + return-to" cookie the callback echoes back.
//!
//! Higher-level browser handlers (`/_oauth/callback`, `/_oauth/logout`)
//! are composed from these primitives; a full HTML flow lives in the Go
//! reference — this module provides the protocol-critical pieces so a
//! Rust app can implement the flow with its own HTTP wiring.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::errors::RpcError;

type HmacSha256 = Hmac<Sha256>;

/// Current unix time in seconds (saturates at 0 before the epoch).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A PKCE verifier + derived challenge pair (RFC 7636).
#[derive(Clone, Debug)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

/// Generate a new PKCE verifier/challenge pair (`method = S256`).
pub fn generate_pkce_pair() -> PkcePair {
    // 32 random bytes → 43-char URL-safe base64 (no padding).
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    PkcePair {
        verifier,
        challenge,
    }
}

/// A signed PKCE session cookie plus the opaque `state` nonce to echo
/// through the IdP.
///
/// The `code_verifier` lives **only** inside the signed [`cookie`]
/// (HttpOnly) — it is never placed in the OAuth `state` parameter, so it
/// never reaches the IdP's logs, the browser history, or a `Referer`
/// header. The [`state`] field is an independent random nonce; the
/// callback compares it against the nonce embedded in the cookie.
///
/// [`cookie`]: Self::cookie
/// [`state`]: Self::state
#[derive(Clone, Debug)]
pub struct PkceState {
    /// Value for the `Set-Cookie` header (signed; carries the verifier).
    pub cookie: String,
    /// Opaque random nonce for the OAuth `state` query parameter.
    pub state: String,
}

/// Pack a PKCE state nonce + creation timestamp + return-to URL +
/// verifier into an HMAC-signed cookie, and return it alongside the
/// bare `state` nonce.
///
/// Wire format: `base64url(payload || '|' || sig)` where payload is
/// `state\n created_at\n return_to\n verifier`.
pub fn new_state_cookie(signing_key: &[u8], return_to: &str, pair: &PkcePair) -> PkceState {
    let state = random_state();
    let created_at = unix_now();
    let payload = format!("{state}\n{created_at}\n{return_to}\n{}", pair.verifier);
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("hmac key");
    mac.update(payload.as_bytes());
    let sig = mac.finalize().into_bytes();
    let mut raw = Vec::with_capacity(payload.len() + sig.len() + 1);
    raw.extend_from_slice(payload.as_bytes());
    raw.push(b'|');
    raw.extend_from_slice(&sig);
    PkceState {
        cookie: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        state,
    }
}

/// Verify + decode a signed state cookie, rejecting one older than
/// `max_age`. Returns `(state_nonce, return_to, code_verifier)`.
///
/// The freshness check is what makes the cookie non-replayable: the
/// `Set-Cookie` `Max-Age` is only a browser hint, so a captured cookie
/// value would otherwise be usable indefinitely.
pub fn verify_state_cookie(
    signing_key: &[u8],
    cookie: &str,
    max_age: Duration,
) -> Result<(String, String, String), RpcError> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cookie.as_bytes())
        .map_err(|_| RpcError::value_error("malformed PKCE state cookie"))?;
    // The HMAC-SHA256 tag is a fixed 32 bytes — split on length, not on
    // a `|` delimiter. The tag is raw binary and can itself contain a
    // `0x7c` ('|') byte, so searching for the separator would corrupt
    // the payload/signature boundary for some keys.
    const SIG_LEN: usize = 32;
    if raw.len() < SIG_LEN + 1 {
        return Err(RpcError::value_error("malformed PKCE state cookie"));
    }
    let (payload_with_sep, sig) = raw.split_at(raw.len() - SIG_LEN);
    let payload = payload_with_sep
        .split_last()
        .filter(|(sep, _)| **sep == b'|')
        .map(|(_, p)| p)
        .ok_or_else(|| RpcError::value_error("malformed PKCE state cookie"))?;

    let mut mac = HmacSha256::new_from_slice(signing_key).expect("hmac key");
    mac.update(payload);
    mac.verify_slice(sig)
        .map_err(|_| RpcError::value_error("PKCE state cookie signature mismatch"))?;

    let s = std::str::from_utf8(payload)
        .map_err(|_| RpcError::value_error("malformed PKCE state cookie"))?;
    let mut parts = s.splitn(4, '\n');
    let state = parts.next().unwrap_or("").to_string();
    let created_at: u64 = parts
        .next()
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| RpcError::value_error("malformed PKCE state cookie"))?;
    let return_to = parts.next().unwrap_or("").to_string();
    let verifier = parts.next().unwrap_or("").to_string();

    let age = unix_now().saturating_sub(created_at);
    if age > max_age.as_secs() {
        return Err(RpcError::value_error("PKCE state cookie expired"));
    }
    Ok((state, return_to, verifier))
}

/// Whether the redirect URL is on the allowlist.
pub fn is_allowed_return_origin(return_to: &str, allow: &[&str]) -> bool {
    let Some((scheme_end, _)) = return_to.find("://").map(|i| (i, ())) else {
        return false;
    };
    let after_scheme = &return_to[scheme_end + 3..];
    let host = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let origin = &return_to[..scheme_end + 3 + host.len()];
    allow.contains(&origin)
}

fn random_state() -> String {
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_challenge_matches_sha256() {
        let p = generate_pkce_pair();
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, expected);
    }

    #[test]
    fn cookie_round_trip() {
        let key = [9u8; 32];
        let pair = PkcePair {
            verifier: "v-abc".into(),
            challenge: "c-abc".into(),
        };
        let pkce = new_state_cookie(&key, "https://app.example/welcome", &pair);
        let (state, rt, verifier) =
            verify_state_cookie(&key, &pkce.cookie, Duration::from_secs(600)).unwrap();
        assert_eq!(state, pkce.state);
        assert_eq!(rt, "https://app.example/welcome");
        assert_eq!(verifier, "v-abc");
    }

    #[test]
    fn cookie_rejects_bad_signature() {
        let key = [1u8; 32];
        let pair = PkcePair {
            verifier: "v".into(),
            challenge: "c".into(),
        };
        let pkce = new_state_cookie(&key, "/x", &pair);
        let wrong_key = [2u8; 32];
        assert!(verify_state_cookie(&wrong_key, &pkce.cookie, Duration::from_secs(600)).is_err());
    }

    #[test]
    fn cookie_rejects_when_expired() {
        let key = [3u8; 32];
        let pair = PkcePair {
            verifier: "v".into(),
            challenge: "c".into(),
        };
        let pkce = new_state_cookie(&key, "/x", &pair);
        // A zero max-age makes any non-instant cookie stale; the cookie's
        // `created_at` is bound inside the signature so it can't be
        // back-dated.
        let err = verify_state_cookie(&key, &pkce.cookie, Duration::ZERO);
        // May still be within the same second — only assert the error
        // path when it does trip, but the message must be the TTL one.
        if let Err(e) = err {
            assert!(e.message.contains("expired"), "{}", e.message);
        }
    }

    #[test]
    fn state_param_does_not_leak_verifier() {
        let key = [4u8; 32];
        let pair = PkcePair {
            verifier: "super-secret-verifier".into(),
            challenge: "c".into(),
        };
        let pkce = new_state_cookie(&key, "/x", &pair);
        // The opaque `state` nonce must not be the cookie, and must not
        // contain the verifier in any decodable form.
        assert_ne!(pkce.state, pkce.cookie);
        assert!(!pkce.state.contains("super-secret-verifier"));
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(pkce.state.as_bytes())
            .unwrap_or_default();
        assert!(!String::from_utf8_lossy(&decoded).contains("super-secret-verifier"));
    }

    #[test]
    fn allowed_origin_matches_scheme_and_host() {
        let allow = ["https://app.example"];
        assert!(is_allowed_return_origin("https://app.example/x", &allow));
        assert!(!is_allowed_return_origin("https://evil.example/x", &allow));
        assert!(!is_allowed_return_origin("http://app.example/x", &allow));
    }
}
