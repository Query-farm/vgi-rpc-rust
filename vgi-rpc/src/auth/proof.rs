//! Proxy proof: HMAC evidence that a request arrived through a trusted proxy.
//!
//! A proxy mints a per-request HMAC-SHA256 over a timestamp, a fresh nonce and
//! the worker's own identifier, keyed by a secret shared only with that worker.
//! The proof establishes the *hop*, never the caller — it is ANDed with
//! whatever authenticates the user rather than replacing it.
//!
//! Unlike a forwarded assertion about what happened at a TLS terminator, a
//! proof cannot be produced by someone who merely reaches the worker directly:
//! without the secret there is nothing to replay.
//!
//! ```no_run
//! use vgi_rpc::auth::proof::{ProofConfig, ProofMode, proof_authenticate};
//! use std::collections::HashMap;
//!
//! let mut secrets = HashMap::new();
//! secrets.insert("prod-use1".to_string(), ([0u8; 32], "prod-use1".to_string()));
//! let cfg = ProofConfig::new(ProofMode::Require, "worker-a", secrets);
//! let gate = proof_authenticate(cfg, None).expect("valid config");
//! ```
//!
//! The normative cross-language contract is `docs/proxy-proof-spec.md` in the
//! vgi-rpc repository.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{AuthContext, AuthRequest, Authenticate};
use crate::RpcError;

type HmacSha256 = Hmac<Sha256>;

/// Header carrying the proof on the wire.
pub const PROOF_HEADER: &str = "vgi-proxy-proof";
/// Header advertising that this worker rejects unproofed requests.
pub const PROOF_REQUIRED_HEADER: &str = "VGI-Proxy-Proof-Required";

const PROOF_VERSION: &str = "v1";
const DOMAIN_PREFIX: &[u8] = b"vgi.proxy.proof.v1";
const DERIVE_LABEL: &[u8] = b"vgi.proxy.proof.v1/";
const MAX_HEADER_LEN: usize = 512;
const SECRET_LEN: usize = 32;
const CLAIMS_PREFIX: &str = "vgi_proxy_proof";
const DEFAULT_REPLAY_CAPACITY: usize = 100_000;

/// How strictly a worker treats the proof header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    /// Install no gate at all — zero per-request cost.
    Off,
    /// Verify and record but never deny. A rollout lever.
    Allow,
    /// Reject a request whose proof does not verify.
    Require,
}

/// Worker-side proof configuration.
#[derive(Debug, Clone)]
pub struct ProofConfig {
    pub mode: ProofMode,
    /// This worker's identifier. Folded into every MAC but never transmitted,
    /// so a proof minted for another worker cannot verify here.
    pub origin_id: String,
    /// Maps a key id to its secret and the proxy label it attributes to.
    pub secrets: HashMap<String, ([u8; SECRET_LEN], String)>,
    /// Half-width of the timestamp acceptance window.
    pub skew_seconds: i64,
    /// Hard bound on the nonce cache.
    pub replay_capacity: usize,
    /// Whether replayed nonces are rejected.
    pub enable_replay_cache: bool,
}

impl ProofConfig {
    /// Build a configuration with the standard defaults.
    pub fn new(
        mode: ProofMode,
        origin_id: impl Into<String>,
        secrets: HashMap<String, ([u8; SECRET_LEN], String)>,
    ) -> Self {
        Self {
            mode,
            origin_id: origin_id.into(),
            secrets,
            skew_seconds: 30,
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
            enable_replay_cache: true,
        }
    }

    /// Set the acceptance half-window.
    pub fn with_skew_seconds(mut self, skew: i64) -> Self {
        self.skew_seconds = skew;
        self
    }

    /// Disable nonce tracking, leaving only the timestamp window.
    pub fn without_replay_cache(mut self) -> Self {
        self.enable_replay_cache = false;
        self
    }
}

/// A proof rejection and its reason code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofError {
    pub reason: &'static str,
}

impl ProofError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

// Charsets are load-bearing, not cosmetic: the canonical string is
// NUL-separated, so framing is only unambiguous because no field can contain a
// NUL (and `kid` cannot contain the '.' separating wire fields).
fn is_kid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_ts(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_nonce(s: &str) -> bool {
    s.len() == 22
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_mac(s: &str) -> bool {
    // Charset-checked rather than left to the base64 decoder: decoders
    // disagree about invalid input across languages, and the reason code is
    // part of the wire contract.
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_origin(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

/// Derive the secret shared between one proxy and one worker.
///
/// A worker is configured with its derived secret only, never the base key —
/// otherwise it could mint proofs its siblings would accept.
pub fn derive_proof_secret(
    base_key: &[u8; SECRET_LEN],
    proxy_id: &str,
    origin_id: &str,
) -> Result<[u8; SECRET_LEN], RpcError> {
    if !is_origin(proxy_id) || !is_origin(origin_id) {
        return Err(RpcError::value_error("invalid proxy_id or origin_id"));
    }
    let mut msg = Vec::with_capacity(DERIVE_LABEL.len() + proxy_id.len() + origin_id.len() + 1);
    msg.extend_from_slice(DERIVE_LABEL);
    msg.extend_from_slice(proxy_id.as_bytes());
    // NUL-separated, and neither identifier may contain NUL — so ("a", "b\0c")
    // cannot collide with ("a\0b", "c").
    msg.push(0);
    msg.extend_from_slice(origin_id.as_bytes());

    let mut mac = HmacSha256::new_from_slice(base_key).expect("hmac accepts any key length");
    mac.update(&msg);
    let out = mac.finalize().into_bytes();
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&out);
    Ok(secret)
}

/// Build the MAC input.
///
/// `origin_id` is folded in but never transmitted: the worker supplies its
/// own, which is what binds a proof to a single audience.
fn canonical_string(kid: &str, ts: &str, nonce: &str, origin_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_PREFIX.len() + kid.len() + ts.len() + nonce.len() + origin_id.len() + 4,
    );
    out.extend_from_slice(DOMAIN_PREFIX);
    for part in [kid, ts, nonce, origin_id] {
        out.push(0);
        out.extend_from_slice(part.as_bytes());
    }
    out
}

/// Mint a proof token. Primarily for tests and for clients fronting a worker.
pub fn mint_proof(
    secret: &[u8; SECRET_LEN],
    kid: &str,
    origin_id: &str,
    now: i64,
    nonce: &str,
) -> Result<String, RpcError> {
    if !is_kid(kid) || !is_origin(origin_id) {
        return Err(RpcError::value_error("invalid kid or origin_id"));
    }
    let ts = now.to_string();
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&canonical_string(kid, &ts, nonce, origin_id));
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{PROOF_VERSION}.{kid}.{ts}.{nonce}.{sig}"))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Verify a proof token, returning the claims to record.
///
/// Cheap rejections run before any MAC is computed, so an unparseable header
/// costs a few charset checks rather than a hash.
pub fn verify_proof(
    token: &str,
    cfg: &ProofConfig,
    cache: Option<&NonceCache>,
    now: i64,
) -> Result<Vec<(String, String)>, ProofError> {
    if token.len() > MAX_HEADER_LEN {
        return Err(ProofError::new("malformed"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 {
        return Err(ProofError::new("malformed"));
    }
    let (version, kid, ts_raw, nonce, mac_b64) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
    if version != PROOF_VERSION
        || !is_kid(kid)
        || !is_ts(ts_raw)
        || !is_nonce(nonce)
        || !is_mac(mac_b64)
    {
        return Err(ProofError::new("malformed"));
    }

    let (secret, label) = cfg
        .secrets
        .get(kid)
        .ok_or_else(|| ProofError::new("unknown_kid"))?;

    // Two-sided. Checking only the upper bound would let a far-future
    // timestamp pass forever.
    let ts: i64 = ts_raw.parse().map_err(|_| ProofError::new("malformed"))?;
    let age = now - ts;
    if age > cfg.skew_seconds {
        return Err(ProofError::new("expired"));
    }
    if -age > cfg.skew_seconds {
        return Err(ProofError::new("not_yet_valid"));
    }

    let received = URL_SAFE_NO_PAD
        .decode(mac_b64)
        .map_err(|_| ProofError::new("malformed"))?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&canonical_string(kid, ts_raw, nonce, &cfg.origin_id));
    // `kid` is public, so selecting one candidate secret is a safe branch;
    // `verify_slice` is constant-time internally.
    mac.verify_slice(&received)
        .map_err(|_| ProofError::new("bad_mac"))?;

    if let Some(cache) = cache {
        if !cache.check_and_add(nonce, now) {
            return Err(ProofError::new("replayed"));
        }
    }

    Ok(vec![
        ("verified".into(), "true".into()),
        ("proxy".into(), label.clone()),
        ("kid".into(), kid.to_string()),
        ("origin_id".into(), cfg.origin_id.clone()),
        ("reason".into(), "ok".into()),
    ])
}

/// A bounded, TTL-expiring set of recently-seen nonces.
///
/// The capacity cap is not optional: a TTL bounds how long an entry lives,
/// never how many arrive inside the window, so a TTL-only cache is a remote
/// memory-exhaustion vector.
#[derive(Debug)]
pub struct NonceCache {
    inner: Mutex<NonceCacheInner>,
    ttl: i64,
    capacity: usize,
}

#[derive(Debug)]
struct NonceCacheInner {
    order: VecDeque<(String, i64)>,
    seen: HashMap<String, ()>,
}

impl NonceCache {
    /// Create a cache retaining nonces for `ttl` seconds, bounded by `capacity`.
    pub fn new(ttl: i64, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(NonceCacheInner {
                order: VecDeque::new(),
                seen: HashMap::new(),
            }),
            ttl,
            capacity,
        }
    }

    /// Atomically report whether a nonce is fresh, remembering it if so.
    ///
    /// Test and insert are one locked operation: a separate contains-then-add
    /// would let two concurrent replays both observe "not seen".
    pub fn check_and_add(&self, nonce: &str, now: i64) -> bool {
        let mut inner = self.inner.lock().expect("nonce cache poisoned");
        // Uniform TTL means insertion order is expiry order, so expired
        // entries are always a prefix and this sweep is exact.
        while let Some((n, expires)) = inner.order.front().cloned() {
            if expires > now {
                break;
            }
            inner.order.pop_front();
            inner.seen.remove(&n);
        }
        if inner.seen.contains_key(nonce) {
            return false;
        }
        // Evict oldest rather than refuse: a burst past capacity is an
        // availability problem, not an authentication one, and the timestamp
        // window still bounds the evicted nonce's usefulness.
        while inner.order.len() >= self.capacity {
            if let Some((n, _)) = inner.order.pop_front() {
                inner.seen.remove(&n);
            }
        }
        inner.order.push_back((nonce.to_string(), now + self.ttl));
        inner.seen.insert(nonce.to_string(), ());
        true
    }

    /// Number of retained nonces.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("nonce cache poisoned").seen.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Wrap an authenticate callback with a proof precondition.
///
/// The gate runs first; on failure `inner` is never invoked. This is an AND,
/// not an alternative — do not pass a proof gate to
/// [`super::chain_authenticate`], whose first-non-anonymous-wins semantics
/// would let any later credential bypass it.
///
/// `inner` may be `None`: proof alone means "only my proxy may call this
/// worker", with user identity handled upstream.
pub fn proof_authenticate(
    cfg: ProofConfig,
    inner: Option<Authenticate>,
) -> Result<Authenticate, RpcError> {
    if cfg.mode == ProofMode::Off {
        return Err(RpcError::value_error(
            "proof_authenticate called with mode=Off; install no gate instead",
        ));
    }
    if !is_origin(&cfg.origin_id) {
        return Err(RpcError::value_error(
            "origin_id is required and must be valid",
        ));
    }
    if cfg.secrets.is_empty() {
        return Err(RpcError::value_error("at least one secret is required"));
    }
    for kid in cfg.secrets.keys() {
        if !is_kid(kid) {
            return Err(RpcError::value_error("invalid kid in secrets"));
        }
    }
    if cfg.skew_seconds <= 0 {
        return Err(RpcError::value_error("skew_seconds must be positive"));
    }

    let cache = cfg
        .enable_replay_cache
        .then(|| NonceCache::new(cfg.skew_seconds, cfg.replay_capacity));
    let required = cfg.mode == ProofMode::Require;

    Ok(std::sync::Arc::new(move |req: &AuthRequest<'_>| {
        let claims = match verify_request(req, &cfg, cache.as_ref()) {
            Ok(c) => c,
            Err(err) => {
                if required {
                    // Uniform message: the caller controls `kid`, so echoing
                    // any detail would reflect attacker-supplied text. The
                    // reason goes to logs only.
                    tracing_reason(err.reason);
                    return Err(RpcError::permission_error("proxy proof required"));
                }
                vec![
                    ("verified".to_string(), "false".to_string()),
                    ("proxy".to_string(), String::new()),
                    ("kid".to_string(), String::new()),
                    ("origin_id".to_string(), cfg.origin_id.clone()),
                    ("reason".to_string(), err.reason.to_string()),
                ]
            }
        };

        let proxy_label = claims
            .iter()
            .find(|(k, _)| k == "proxy")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        // AuthContext claims are string-valued, so the namespace is flattened
        // with a dotted prefix rather than nested.
        let mut merged: BTreeMapAlias = match &inner {
            Some(f) => f(req)?.claims,
            None => Default::default(),
        };
        let (domain, authenticated, principal) = match &inner {
            Some(f) => {
                let ctx = f(req)?;
                (ctx.domain, ctx.authenticated, ctx.principal)
            }
            None => (CLAIMS_PREFIX.to_string(), true, proxy_label.clone()),
        };
        for (k, v) in claims {
            merged.insert(format!("{CLAIMS_PREFIX}.{k}"), v);
        }
        Ok(AuthContext {
            domain,
            authenticated,
            principal,
            claims: merged,
        })
    }))
}

type BTreeMapAlias = std::collections::BTreeMap<String, String>;

fn tracing_reason(reason: &str) {
    tracing::warn!(proof_reason = reason, "proxy proof rejected");
}

fn verify_request(
    req: &AuthRequest<'_>,
    cfg: &ProofConfig,
    cache: Option<&NonceCache>,
) -> Result<Vec<(String, String)>, ProofError> {
    let raw = req
        .header(PROOF_HEADER)
        .ok_or_else(|| ProofError::new("no_proof"))?;
    if raw.is_empty() {
        return Err(ProofError::new("no_proof"));
    }
    if raw.contains(',') {
        return Err(ProofError::new("malformed"));
    }
    verify_proof(raw, cfg, cache, unix_now())
}

/// Parse a `kid:hex,kid:hex` secret specification.
///
/// The `kid` doubles as the proxy's label, so attribution needs no extra
/// configuration. Any malformed entry fails the whole parse rather than
/// silently dropping one proxy's access.
pub fn parse_proof_secrets(
    raw: &str,
) -> Result<HashMap<String, ([u8; SECRET_LEN], String)>, RpcError> {
    let mut out = HashMap::new();
    for chunk in raw.split(',') {
        let item = chunk.trim();
        if item.is_empty() {
            continue;
        }
        let (kid, hex_secret) = item
            .split_once(':')
            .ok_or_else(|| RpcError::value_error("expected 'kid:hex'"))?;
        if !is_kid(kid) {
            return Err(RpcError::value_error("invalid kid"));
        }
        if hex_secret.len() != SECRET_LEN * 2 {
            return Err(RpcError::value_error("secret must be 64 hex chars"));
        }
        let mut secret = [0u8; SECRET_LEN];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_secret[i * 2..i * 2 + 2], 16)
                .map_err(|_| RpcError::value_error("secret is not valid hex"))?;
        }
        out.insert(kid.to_string(), (secret, kid.to_string()));
    }
    if out.is_empty() {
        return Err(RpcError::value_error("no secrets parsed"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors from the Python reference implementation. Verifying these
    // is the only thing that proves Rust frames the canonical string
    // identically — a port can round-trip against itself while framing the MAC
    // input differently from every other language.
    const GOLDEN_TOKEN: &str = "v1.conformance-proxy.1700000000.Q0ZPUk1BTkNFTk9OQ0UxMQ.XQ2QBf35oajjaP7HIas3OfyEvNhyXTTptbrxWFxWk3I";
    const GOLDEN_ORIGIN: &str = "conformance-origin";
    const GOLDEN_KID: &str = "conformance-proxy";
    const GOLDEN_TIME: i64 = 1700000000;
    const GOLDEN_DERIVED: &str = "af85db125b8270bc0a0971736340dc8476ba70e1fad472b72b68ba739bd1cd94";

    fn secret() -> [u8; 32] {
        [0x11u8; 32]
    }

    fn config() -> ProofConfig {
        let mut secrets = HashMap::new();
        secrets.insert(GOLDEN_KID.to_string(), (secret(), GOLDEN_KID.to_string()));
        ProofConfig::new(ProofMode::Require, GOLDEN_ORIGIN, secrets)
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn verifies_python_minted_token() {
        let claims = verify_proof(GOLDEN_TOKEN, &config(), None, GOLDEN_TIME)
            .expect("cross-language token must verify");
        assert!(claims.contains(&("proxy".to_string(), GOLDEN_KID.to_string())));
    }

    #[test]
    fn mint_matches_python() {
        let token = mint_proof(
            &secret(),
            GOLDEN_KID,
            GOLDEN_ORIGIN,
            GOLDEN_TIME,
            "Q0ZPUk1BTkNFTk9OQ0UxMQ",
        )
        .unwrap();
        assert_eq!(token, GOLDEN_TOKEN, "Rust mint diverged from Python");
    }

    #[test]
    fn derivation_matches_python() {
        let mut base = [0u8; 32];
        for (i, b) in base.iter_mut().enumerate() {
            *b = i as u8;
        }
        let got = derive_proof_secret(&base, "prod-use1", "worker-a").unwrap();
        assert_eq!(to_hex(&got), GOLDEN_DERIVED);
    }

    #[test]
    fn derivation_separator_is_unambiguous() {
        let base = [0u8; 32];
        let a = derive_proof_secret(&base, "ab", "c.d").unwrap();
        let b = derive_proof_secret(&base, "a", "b.c.d").unwrap();
        assert_ne!(a, b, "component boundaries can be shifted");
    }

    #[test]
    fn malformed_tokens_rejected() {
        let cfg = config();
        for token in [
            "",
            "garbage",
            "v1.a.b.c",
            "v1.a.b.c.d.e",
            "v2.conformance-proxy.1.Q0ZPUk1BTkNFTk9OQ0UxMQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "v1.bad!kid.1.Q0ZPUk1BTkNFTk9OQ0UxMQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "v1.conformance-proxy.xyz.Q0ZPUk1BTkNFTk9OQ0UxMQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "v1.conformance-proxy.1.short.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "v1.conformance-proxy.1.Q0ZPUk1BTkNFTk9OQ0UxMQ.!!!",
        ] {
            let err = verify_proof(token, &cfg, None, GOLDEN_TIME).unwrap_err();
            assert_eq!(err.reason, "malformed", "token {token:?}");
        }
    }

    #[test]
    fn unknown_kid_rejected() {
        let mut cfg = config();
        cfg.secrets = HashMap::new();
        cfg.secrets
            .insert("other".to_string(), (secret(), "other".to_string()));
        assert_eq!(
            verify_proof(GOLDEN_TOKEN, &cfg, None, GOLDEN_TIME)
                .unwrap_err()
                .reason,
            "unknown_kid"
        );
    }

    #[test]
    fn wrong_origin_rejected() {
        // Audience binding: origin_id is in the MAC but not on the wire.
        let mut cfg = config();
        cfg.origin_id = "some-other-worker".to_string();
        assert_eq!(
            verify_proof(GOLDEN_TOKEN, &cfg, None, GOLDEN_TIME)
                .unwrap_err()
                .reason,
            "bad_mac"
        );
    }

    #[test]
    fn time_window_is_two_sided() {
        let cfg = config();
        // The future case catches a verifier checking only an upper bound,
        // which would let a future-dated proof pass indefinitely.
        assert_eq!(
            verify_proof(GOLDEN_TOKEN, &cfg, None, GOLDEN_TIME + 91)
                .unwrap_err()
                .reason,
            "expired"
        );
        assert_eq!(
            verify_proof(GOLDEN_TOKEN, &cfg, None, GOLDEN_TIME - 91)
                .unwrap_err()
                .reason,
            "not_yet_valid"
        );
        assert!(verify_proof(GOLDEN_TOKEN, &cfg, None, GOLDEN_TIME + 20).is_ok());
    }

    #[test]
    fn mac_framing_must_be_separated() {
        // A MAC over concatenated-without-separators fields must not verify.
        // Catches a port whose crypto is right but whose framing is not.
        let mut bad = Vec::from(DOMAIN_PREFIX);
        bad.extend_from_slice(GOLDEN_KID.as_bytes());
        bad.extend_from_slice(b"1700000000");
        bad.extend_from_slice(b"Q0ZPUk1BTkNFTk9OQ0UxMQ");
        bad.extend_from_slice(GOLDEN_ORIGIN.as_bytes());
        let mut mac = HmacSha256::new_from_slice(&secret()).unwrap();
        mac.update(&bad);
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("v1.{GOLDEN_KID}.1700000000.Q0ZPUk1BTkNFTk9OQ0UxMQ.{sig}");
        assert_eq!(
            verify_proof(&token, &config(), None, GOLDEN_TIME)
                .unwrap_err()
                .reason,
            "bad_mac"
        );
    }

    #[test]
    fn replay_rejected() {
        let cache = NonceCache::new(30, 100);
        let cfg = config();
        assert!(verify_proof(GOLDEN_TOKEN, &cfg, Some(&cache), GOLDEN_TIME).is_ok());
        assert_eq!(
            verify_proof(GOLDEN_TOKEN, &cfg, Some(&cache), GOLDEN_TIME)
                .unwrap_err()
                .reason,
            "replayed"
        );
    }

    #[test]
    fn nonce_cache_capacity_is_hard() {
        // A TTL bounds how long an entry lives, never how many arrive inside
        // the window, so TTL-only is a remote memory-exhaustion vector.
        let cache = NonceCache::new(3600, 10);
        for i in 0..500 {
            cache.check_and_add(&format!("nonce-{i}"), GOLDEN_TIME);
        }
        assert!(
            cache.len() <= 10,
            "capacity cap not enforced: {}",
            cache.len()
        );
    }

    #[test]
    fn nonce_cache_expires() {
        let cache = NonceCache::new(30, 100);
        assert!(cache.check_and_add("n1", 1000));
        assert!(!cache.check_and_add("n1", 1000));
        assert!(
            cache.check_and_add("n1", 1031),
            "entry should expire past the TTL"
        );
    }

    #[test]
    fn off_mode_refuses_to_build() {
        let mut cfg = config();
        cfg.mode = ProofMode::Off;
        assert!(proof_authenticate(cfg, None).is_err());
    }

    #[test]
    fn parse_secrets_round_trip() {
        let parsed = parse_proof_secrets(&format!("prod-use1:{}", "11".repeat(32))).unwrap();
        assert_eq!(parsed["prod-use1"].1, "prod-use1");
        for bad in ["prod-use1", "prod-use1:zz", "bad!kid:11", ""] {
            assert!(parse_proof_secrets(bad).is_err(), "accepted {bad:?}");
        }
    }
}
