//! Generic AEAD seal/open primitive (XChaCha20-Poly1305).
//!
//! A small envelope for any value that must be both confidential and
//! authenticated on the wire. The HTTP streaming state token
//! ([`crate::http`]) is the consumer today.
//!
//! Payload framing is the caller's concern; this module only handles the
//! AEAD envelope. Bind identity (or any context that must not be swapped)
//! into the `aad` — associated data is authenticated but not encrypted,
//! and a mismatch on open fails the tag check.
//!
//! Wire format:
//!
//! ```text
//! version (1 byte) || nonce (24 bytes) || ciphertext+tag
//! ```
//!
//! Mirrors Python's `vgi_rpc/crypto.py`. The plaintext encoding inside the
//! ciphertext is *not* expected to round-trip across language ports — only
//! the envelope shape and the behavioural contract (round-trip integrity,
//! AAD-bound replay protection) are shared.

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// XChaCha20-Poly1305 key length (256 bits).
const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length (192 bits).
const NONCE_LEN: usize = 24;
/// Poly1305 authentication-tag length appended by the AEAD construction.
const TAG_LEN: usize = 16;
/// Single version-selector byte.
const VERSION_LEN: usize = 1;
/// Smallest envelope that could possibly carry an (empty) ciphertext.
const MIN_TOKEN_LEN: usize = VERSION_LEN + NONCE_LEN + TAG_LEN;

/// Raised by [`open_bytes`] for any token it cannot open.
///
/// Malformed, wrong-version, tampered, wrong-key, and wrong-AAD tokens all
/// map to this single error so callers cannot distinguish them (e.g. via
/// type or message) — "wrong AAD" (cross-principal replay) is
/// indistinguishable from "garbage input".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealError;

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("token verification failed")
    }
}

impl std::error::Error for SealError {}

/// Stretch or compress an operator-supplied key to the 32-byte AEAD key length.
///
/// XChaCha20-Poly1305 requires exactly 32 bytes. Operators may supply keys
/// of any length; hashing through SHA-256 yields a 32-byte pseudo-random
/// key for any input. A key already 32 bytes long is used as-is.
pub fn normalize_key(key: &[u8]) -> [u8; KEY_LEN] {
    if key.len() == KEY_LEN {
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(key);
        return out;
    }
    let digest = Sha256::digest(key);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Seal `payload` into an authenticated-encrypted envelope.
///
/// `aad` is authenticated but not encrypted; the identical `aad` must be
/// supplied to [`open_bytes`]. `version` is a 1-byte format selector
/// echoed as the first output byte.
///
/// Returns the sealed envelope: `version || nonce || ciphertext+tag`.
pub fn seal_bytes(payload: &[u8], key: &[u8], aad: &[u8], version: u8) -> Vec<u8> {
    let normalized = normalize_key(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&normalized));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: payload, aad },
        )
        .expect("XChaCha20-Poly1305 encrypt cannot fail for in-memory plaintext");

    let mut wire = Vec::with_capacity(VERSION_LEN + NONCE_LEN + ciphertext.len());
    wire.push(version);
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ciphertext);
    wire
}

/// Open and verify an envelope produced by [`seal_bytes`].
///
/// `key` and `aad` must match the values used to seal, and `version` the
/// expected format selector. Every malformed, wrong-version, tampered,
/// wrong-key, or wrong-AAD token fails with [`SealError`] — all failure
/// modes are indistinguishable.
pub fn open_bytes(token: &[u8], key: &[u8], aad: &[u8], version: u8) -> Result<Vec<u8>, SealError> {
    if token.len() < MIN_TOKEN_LEN || token[0] != version {
        return Err(SealError);
    }
    let normalized = normalize_key(key);
    let nonce = &token[VERSION_LEN..VERSION_LEN + NONCE_LEN];
    let ciphertext = &token[VERSION_LEN + NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&normalized));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SealError)
}

/// Convenience: [`seal_bytes`] followed by standard base64 encoding.
pub fn seal_base64(payload: &[u8], key: &[u8], aad: &[u8], version: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode(seal_bytes(payload, key, aad, version))
}

/// Convenience: base64 decode followed by [`open_bytes`]. A base64 failure
/// is folded into [`SealError`] like every other bad-token mode.
pub fn open_base64(token: &str, key: &[u8], aad: &[u8], version: u8) -> Result<Vec<u8>, SealError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token.as_bytes())
        .map_err(|_| SealError)?;
    open_bytes(&raw, key, aad, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let sealed = seal_bytes(b"hello world", &key, b"aad", 4);
        assert_eq!(sealed[0], 4);
        let opened = open_bytes(&sealed, &key, b"aad", 4).unwrap();
        assert_eq!(opened, b"hello world");
    }

    #[test]
    fn wrong_key_aad_version_all_fail_uniformly() {
        let key = [7u8; 32];
        let sealed = seal_bytes(b"payload", &key, b"aad", 4);
        assert_eq!(open_bytes(&sealed, &[9u8; 32], b"aad", 4), Err(SealError));
        assert_eq!(open_bytes(&sealed, &key, b"other", 4), Err(SealError));
        assert_eq!(open_bytes(&sealed, &key, b"aad", 5), Err(SealError));
        assert_eq!(open_bytes(b"short", &key, b"aad", 4), Err(SealError));
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert_eq!(open_bytes(&tampered, &key, b"aad", 4), Err(SealError));
    }

    #[test]
    fn normalize_key_passthrough_and_hash() {
        let exact = [3u8; 32];
        assert_eq!(normalize_key(&exact), exact);
        // Any non-32-byte key is hashed; output is deterministic.
        assert_eq!(normalize_key(b"short"), normalize_key(b"short"));
        assert_ne!(normalize_key(b"short"), normalize_key(b"other"));
    }

    #[test]
    fn base64_helpers_roundtrip() {
        let key = b"operator-supplied-key-of-any-length";
        let tok = seal_base64(b"state", key, b"id", 4);
        assert_eq!(open_base64(&tok, key, b"id", 4).unwrap(), b"state");
        assert_eq!(open_base64("!!!notb64!!!", key, b"id", 4), Err(SealError));
    }
}
