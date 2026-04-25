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

use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::errors::RpcError;

type HmacSha256 = Hmac<Sha256>;

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

/// Pack a PKCE state + return-to URL into an HMAC-signed cookie value.
///
/// Wire format: `base64url(payload || sig)` where payload is
/// `state\n return_to\n verifier`.
pub fn new_state_cookie(signing_key: &[u8], return_to: &str, pair: &PkcePair) -> String {
    let state = random_state();
    let payload = format!("{state}\n{return_to}\n{}", pair.verifier);
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("hmac key");
    mac.update(payload.as_bytes());
    let sig = mac.finalize().into_bytes();
    let mut raw = Vec::with_capacity(payload.len() + sig.len() + 1);
    raw.extend_from_slice(payload.as_bytes());
    raw.push(b'|');
    raw.extend_from_slice(&sig);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// Verify + decode a signed state cookie. Returns
/// `(state, return_to, code_verifier)`.
pub fn verify_state_cookie(
    signing_key: &[u8],
    cookie: &str,
) -> Result<(String, String, String), RpcError> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cookie.as_bytes())
        .map_err(|_| RpcError::value_error("malformed PKCE state cookie"))?;
    let pipe = raw
        .iter()
        .rposition(|&b| b == b'|')
        .ok_or_else(|| RpcError::value_error("malformed PKCE state cookie"))?;
    let (payload, sig_with_pipe) = raw.split_at(pipe);
    let sig = &sig_with_pipe[1..];

    let mut mac = HmacSha256::new_from_slice(signing_key).expect("hmac key");
    mac.update(payload);
    mac.verify_slice(sig)
        .map_err(|_| RpcError::value_error("PKCE state cookie signature mismatch"))?;

    let s = std::str::from_utf8(payload)
        .map_err(|_| RpcError::value_error("malformed PKCE state cookie"))?;
    let mut parts = s.splitn(3, '\n');
    let state = parts.next().unwrap_or("").to_string();
    let return_to = parts.next().unwrap_or("").to_string();
    let verifier = parts.next().unwrap_or("").to_string();
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
    allow.iter().any(|a| *a == origin)
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
        let cookie = new_state_cookie(&key, "https://app.example/welcome", &pair);
        let (_state, rt, verifier) = verify_state_cookie(&key, &cookie).unwrap();
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
        let cookie = new_state_cookie(&key, "/x", &pair);
        let wrong_key = [2u8; 32];
        assert!(verify_state_cookie(&wrong_key, &cookie).is_err());
    }

    #[test]
    fn allowed_origin_matches_scheme_and_host() {
        let allow = ["https://app.example"];
        assert!(is_allowed_return_origin("https://app.example/x", &allow));
        assert!(!is_allowed_return_origin("https://evil.example/x", &allow));
        assert!(!is_allowed_return_origin("http://app.example/x", &allow));
    }
}
