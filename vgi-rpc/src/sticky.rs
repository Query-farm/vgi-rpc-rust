//! Sticky-session machinery for the HTTP transport.
//!
//! Sticky sessions let an RPC method bind a Rust object (a DB cursor, a
//! loaded model, an open file handle) to the worker process that opened
//! it, keyed by a short-lived AEAD-sealed token. Subsequent requests
//! carrying the same `VGI-Session` header restore the object as
//! [`CallContext::session`](crate::CallContext::session); requests that
//! miss (wrong worker, expired, evicted) surface
//! [`RpcError::session_lost_error`].
//!
//! The feature is **HTTP-only and opt-in**: it ships off by default and
//! the non-sticky wire path is byte-identical to the pre-sticky framework.
//! The session token rides exclusively in HTTP headers — no cookies — so
//! multiple concurrent sticky sessions to one host from a single client
//! multiplex correctly (each call carries its own header, not an ambient
//! jar entry).
//!
//! Mirrors Python's `vgi_rpc/http/server/_sticky.py`. The token wire
//! format (version `0x01`, the plaintext framing, the AAD prefix) matches
//! the Python module byte-for-byte so a Rust worker and a Python worker
//! sharing a `token_key` could in principle validate each other's session
//! tokens (cross-worker resume is still gated on matching `server_id`).

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::RngCore;

use crate::auth::AuthContext;
use crate::crypto;
use crate::errors::{Result, RpcError};
use crate::server::StickySink;

/// Token format: `version=0x01 | nonce(24) | ciphertext+tag`, base64url
/// (no padding). Matches Python `_sticky._TOKEN_VERSION`.
const TOKEN_VERSION: u8 = 0x01;
/// Framework-minted session id length in bytes (24 hex chars).
const SESSION_ID_LEN: usize = 12;

/// AAD prefix binding a session token to its issuing principal. Distinct
/// from the stream-state token prefix (`vgi_rpc.state.v4`) so the two
/// token classes can never be cross-replayed. Mirrors Python
/// `_sticky`/`_state_token` AAD conventions for the session namespace.
fn compute_session_aad(auth: &AuthContext) -> Vec<u8> {
    let binding = auth
        .claims
        .get("peer_evidence_binding")
        .filter(|value| !value.is_empty());
    let prefix = if binding.is_some() {
        b"vgi_rpc.session.v2\x00".as_slice()
    } else {
        b"vgi_rpc.session.v1\x00".as_slice()
    };
    if !auth.authenticated {
        let mut out = Vec::with_capacity(
            prefix.len() + b"\x00anonymous".len() + binding.map_or(0, |value| value.len() + 1),
        );
        out.extend_from_slice(prefix);
        out.extend_from_slice(b"\x00anonymous");
        if let Some(binding) = binding {
            out.push(0);
            out.extend_from_slice(binding.as_bytes());
        }
        return out;
    }
    let mut out = Vec::with_capacity(
        prefix.len()
            + 1
            + auth.domain.len()
            + 1
            + auth.principal.len()
            + binding.map_or(0, |value| value.len() + 1),
    );
    out.extend_from_slice(prefix);
    out.push(0x01);
    out.extend_from_slice(auth.domain.as_bytes());
    out.push(0);
    out.extend_from_slice(auth.principal.as_bytes());
    if let Some(binding) = binding {
        out.push(0);
        out.extend_from_slice(binding.as_bytes());
    }
    out
}

/// Stable per-request principal key for registry partitioning. Mirrors
/// Python `_StickyMiddleware._principal_key`: `"\x00anonymous"` when
/// unauthenticated, `"{domain}\x00{principal}"` otherwise.
pub(crate) fn principal_key(auth: &AuthContext) -> String {
    let binding = auth
        .claims
        .get("peer_evidence_binding")
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .unwrap_or("");
    if !auth.authenticated {
        return if binding.is_empty() {
            "\u{0}anonymous".to_string()
        } else {
            format!("\u{0}anonymous\u{0}{binding}")
        };
    }
    let key = format!("{}\u{0}{}", auth.domain, auth.principal);
    if binding.is_empty() {
        key
    } else {
        format!("{key}\u{0}{binding}")
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Token sealing
// ---------------------------------------------------------------------------

/// Seal a session token. Returns the base64url (no-pad) value for the
/// `VGI-Session` header. Plaintext framing:
/// `created_at:u64 LE | server_id_len:u8 | server_id | session_id(12B) | expires_at:u64 LE`.
fn seal_session_token(
    server_id: &str,
    session_id: &[u8; SESSION_ID_LEN],
    expires_at: u64,
    token_key: &[u8; 32],
    aad: &[u8],
) -> String {
    let sid_bytes = server_id.as_bytes();
    debug_assert!(sid_bytes.len() <= 255, "server_id must fit in u8 length");
    let mut plaintext = Vec::with_capacity(8 + 1 + sid_bytes.len() + SESSION_ID_LEN + 8);
    plaintext.extend_from_slice(&now_unix_secs().to_le_bytes());
    plaintext.push(sid_bytes.len() as u8);
    plaintext.extend_from_slice(sid_bytes);
    plaintext.extend_from_slice(session_id);
    plaintext.extend_from_slice(&expires_at.to_le_bytes());
    let sealed = crypto::seal_bytes(&plaintext, token_key, aad, TOKEN_VERSION);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed)
}

/// Open a session token, returning `(server_id, session_id, expires_at)`.
/// Every malformed / tampered / wrong-key / wrong-principal / expired
/// token yields [`RpcError::session_lost_error`] — failure modes are
/// indistinguishable from the caller's perspective.
fn open_session_token(
    token: &str,
    token_key: &[u8; 32],
    aad: &[u8],
) -> Result<(String, [u8; SESSION_ID_LEN], u64)> {
    let lost = || RpcError::session_lost_error("session token verification failed");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| lost())?;
    let plaintext = crypto::open_bytes(&raw, token_key, aad, TOKEN_VERSION).map_err(|_| lost())?;

    // created_at:u64 | server_id_len:u8 | server_id | session_id(12) | expires_at:u64
    if plaintext.len() < 8 + 1 {
        return Err(lost());
    }
    let server_id_len = plaintext[8] as usize;
    let sid_pos = 9 + server_id_len;
    let end_pos = sid_pos + SESSION_ID_LEN + 8;
    if plaintext.len() != end_pos {
        return Err(lost());
    }
    let server_id = String::from_utf8_lossy(&plaintext[9..sid_pos]).into_owned();
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&plaintext[sid_pos..sid_pos + SESSION_ID_LEN]);
    let mut exp = [0u8; 8];
    exp.copy_from_slice(&plaintext[sid_pos + SESSION_ID_LEN..end_pos]);
    let expires_at = u64::from_le_bytes(exp);
    Ok((server_id, session_id, expires_at))
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

struct SessionEntry {
    state: Arc<dyn Any + Send + Sync>,
    expires_at: Instant,
    principal_key: String,
}

/// Per-worker in-process map of live sticky sessions.
///
/// The map is guarded by an `RwLock`; entries hold an opaque
/// `Arc<dyn Any>` state value plus a TTL and the principal that opened
/// them. Expired entries are evicted in-line on lookup so a miss is
/// observationally identical whether the session never existed or aged
/// out between reaper ticks.
pub struct SessionRegistry {
    default_ttl: Duration,
    entries: RwLock<HashMap<[u8; SESSION_ID_LEN], SessionEntry>>,
    draining: AtomicBool,
}

impl SessionRegistry {
    pub(crate) fn new(default_ttl: Duration) -> Self {
        Self {
            default_ttl,
            entries: RwLock::new(HashMap::new()),
            draining: AtomicBool::new(false),
        }
    }

    /// Default session TTL when `open` is called with `ttl = None`.
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Whether the server is draining; new opens raise `ServerDrainingError`.
    pub fn draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Flip the draining flag. Existing sessions continue to serve.
    pub fn set_draining(&self, value: bool) {
        self.draining.store(value, Ordering::Relaxed);
    }

    /// Register a session. Returns `(session_id, expires_at_unix_secs)`.
    fn open(
        &self,
        state: Arc<dyn Any + Send + Sync>,
        ttl: Option<Duration>,
        principal_key: String,
    ) -> Result<([u8; SESSION_ID_LEN], u64)> {
        if self.draining() {
            return Err(RpcError::server_draining_error(
                "server is draining — new sessions are rejected",
            ));
        }
        let effective = ttl.unwrap_or(self.default_ttl);
        let expires_at = Instant::now() + effective;
        let expires_at_unix = now_unix_secs() + effective.as_secs();
        let mut sid = [0u8; SESSION_ID_LEN];
        rand::thread_rng().fill_bytes(&mut sid);
        let entry = SessionEntry {
            state,
            expires_at,
            principal_key,
        };
        self.entries.write().unwrap().insert(sid, entry);
        Ok((sid, expires_at_unix))
    }

    /// Look up the live state for `sid`, evicting it in-line if expired.
    /// Returns `None` on miss, expiry, or principal mismatch.
    fn get(
        &self,
        sid: &[u8; SESSION_ID_LEN],
        principal_key: &str,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        let now = Instant::now();
        let mut map = self.entries.write().unwrap();
        let entry = map.get(sid)?;
        if entry.expires_at < now {
            map.remove(sid);
            return None;
        }
        if entry.principal_key != principal_key {
            return None;
        }
        Some(entry.state.clone())
    }

    /// Remove a session. Returns whether one was present.
    fn close(&self, sid: &[u8; SESSION_ID_LEN]) -> bool {
        self.entries.write().unwrap().remove(sid).is_some()
    }

    /// Evict every session past its TTL. Returns the eviction count.
    pub fn drain_expired(&self) -> usize {
        let now = Instant::now();
        let mut map = self.entries.write().unwrap();
        let expired: Vec<[u8; SESSION_ID_LEN]> = map
            .iter()
            .filter(|(_, e)| e.expires_at < now)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in &expired {
            map.remove(sid);
        }
        expired.len()
    }

    /// Drop every live session and clear the registry.
    pub fn shutdown(&self) {
        self.entries.write().unwrap().clear();
    }

    /// Number of live sessions.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Whether the registry holds no sessions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Drain handle
// ---------------------------------------------------------------------------

/// Operator-facing handle for graceful drain of a sticky-enabled server.
///
/// Returned by [`crate::http::HttpState::sticky_drain_handle`].
/// Wire it into a SIGTERM handler or a worker-exit hook:
///
/// * [`DrainHandle::drain`] flips the registry's drain flag so subsequent
///   `ctx.open_session` calls raise `ServerDrainingError`; existing
///   sessions keep serving.
/// * [`DrainHandle::shutdown`] drops every live session.
#[derive(Clone)]
pub struct DrainHandle {
    registry: Arc<SessionRegistry>,
}

impl DrainHandle {
    pub(crate) fn new(registry: Arc<SessionRegistry>) -> Self {
        Self { registry }
    }

    /// Set the drain flag; new `ctx.open_session` calls raise `ServerDrainingError`.
    pub fn drain(&self) {
        self.registry.set_draining(true);
    }

    /// Whether [`DrainHandle::drain`] has been invoked.
    pub fn is_draining(&self) -> bool {
        self.registry.draining()
    }

    /// Set the drain flag to an explicit value. Production code only ever
    /// drains; the `false` direction exists for test harnesses that reuse
    /// a long-lived server across cases.
    pub fn set_draining(&self, value: bool) {
        self.registry.set_draining(value);
    }

    /// Drop every live session and clear the registry.
    pub fn shutdown(&self) {
        self.registry.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Shared sticky context (held by HttpState)
// ---------------------------------------------------------------------------

/// Server-wide sticky-session state attached to `HttpState` when sticky is
/// enabled. Bundles the registry, the AEAD key, the default TTL, the
/// server id (for token `server_id` binding), and the echo-header map.
pub(crate) struct StickyContext {
    pub registry: Arc<SessionRegistry>,
    pub token_key: [u8; 32],
    pub default_ttl: Duration,
    /// Ordered `(name, value)` pairs emitted as `VGI-Echo-<name>: <value>`
    /// on session-opening responses.
    pub echo_headers: Vec<(String, String)>,
    pub server_id: String,
}

impl StickyContext {
    pub(crate) fn new(
        token_key: [u8; 32],
        default_ttl: Duration,
        echo_headers: Vec<(String, String)>,
        server_id: String,
    ) -> Arc<Self> {
        let registry = Arc::new(SessionRegistry::new(default_ttl));
        // Best-effort proactive reaper. Inline eviction in `get` is the
        // correctness guarantee; this just trims sessions never touched
        // again. Only spawn when a tokio runtime is present (it always is
        // under the HTTP server's `block_on`).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let reg = registry.clone();
            handle.spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tick.tick().await;
                    reg.drain_expired();
                }
            });
        }
        Arc::new(Self {
            registry,
            token_key,
            default_ttl,
            echo_headers,
            server_id,
        })
    }

    pub(crate) fn drain_handle(&self) -> DrainHandle {
        DrainHandle::new(self.registry.clone())
    }
}

// ---------------------------------------------------------------------------
// Per-request sink
// ---------------------------------------------------------------------------

struct SinkInner {
    current_state: Option<Arc<dyn Any + Send + Sync>>,
    current_sid: Option<String>,
    mint_token: Option<String>,
    closed: bool,
}

/// Concrete [`StickySink`] for one HTTP request. Bridges
/// `CallContext::open_session` / `close_session` to the per-worker
/// registry and stashes the mint/close signals the response layer reads.
pub(crate) struct StickySinkImpl {
    ctx: Arc<StickyContext>,
    aad: Vec<u8>,
    principal_key: String,
    accept_opens: bool,
    inner: Mutex<SinkInner>,
}

impl StickySinkImpl {
    /// The session token to stamp on the response (`Some` after a successful open).
    pub(crate) fn mint_token(&self) -> Option<String> {
        self.inner.lock().unwrap().mint_token.clone()
    }

    /// Whether the request closed its session (response stamps `VGI-Session-Close`).
    pub(crate) fn was_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }
}

impl StickySink for StickySinkImpl {
    fn accept_opens(&self) -> bool {
        self.accept_opens
    }

    fn current_state(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        self.inner.lock().unwrap().current_state.clone()
    }

    fn current_session_id(&self) -> Option<String> {
        self.inner.lock().unwrap().current_sid.clone()
    }

    fn open(&self, state: Arc<dyn Any + Send + Sync>, ttl: Option<Duration>) -> Result<()> {
        let (sid, expires_at) =
            self.ctx
                .registry
                .open(state.clone(), ttl, self.principal_key.clone())?;
        let token = seal_session_token(
            &self.ctx.server_id,
            &sid,
            expires_at,
            &self.ctx.token_key,
            &self.aad,
        );
        let mut inner = self.inner.lock().unwrap();
        inner.current_state = Some(state);
        inner.current_sid = Some(bytes_to_hex(&sid));
        inner.mint_token = Some(token);
        inner.closed = false;
        Ok(())
    }

    fn close(&self) -> Result<bool> {
        let sid_hex = { self.inner.lock().unwrap().current_sid.clone() };
        let hit = match sid_hex.as_deref().and_then(hex_to_sid) {
            Some(sid) => self.ctx.registry.close(&sid),
            None => false,
        };
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        // Clear live state so subsequent `ctx.session` reads return None;
        // keep `current_sid` so the access log can still report the id.
        inner.current_state = None;
        Ok(hit)
    }
}

/// Outcome of resolving the sticky headers on an incoming request.
pub(crate) enum StickyResolution {
    /// Sink installed; carries the concrete impl for response stamping.
    Sink(Arc<StickySinkImpl>),
    /// Presented token failed to resolve — short-circuit with this error.
    Lost(RpcError),
}

/// Resolve the `VGI-Session` / `VGI-Session-Accept` headers against the
/// registry and build the per-request sink. Mirrors
/// `_StickyMiddleware.process_request`.
pub(crate) fn resolve(
    ctx: &Arc<StickyContext>,
    auth: &AuthContext,
    accept_opens: bool,
    session_header: Option<&str>,
) -> StickyResolution {
    let aad = compute_session_aad(auth);
    let pkey = principal_key(auth);

    let mut current_state = None;
    let mut current_sid = None;

    if let Some(token) = session_header.map(str::trim).filter(|t| !t.is_empty()) {
        match open_session_token(token, &ctx.token_key, &aad) {
            Ok((server_id, sid, _expires_at)) => {
                if server_id != ctx.server_id {
                    return StickyResolution::Lost(RpcError::session_lost_error(
                        "session token was issued by a different worker (server_id mismatch)",
                    ));
                }
                match ctx.registry.get(&sid, &pkey) {
                    Some(state) => {
                        current_state = Some(state);
                        current_sid = Some(bytes_to_hex(&sid));
                    }
                    None => {
                        return StickyResolution::Lost(RpcError::session_lost_error(
                            "session not found, expired, or principal mismatch",
                        ));
                    }
                }
            }
            Err(e) => return StickyResolution::Lost(e),
        }
    }

    StickyResolution::Sink(Arc::new(StickySinkImpl {
        ctx: ctx.clone(),
        aad,
        principal_key: pkey,
        accept_opens,
        inner: Mutex::new(SinkInner {
            current_state,
            current_sid,
            mint_token: None,
            closed: false,
        }),
    }))
}

/// Idempotent `DELETE {prefix}/__session__` outcome.
pub(crate) enum DeleteOutcome {
    /// 200 — no token, or stale/forged token (no info leak).
    Idempotent,
    /// 204 — a live session was found and closed; stamp `VGI-Session-Close`.
    Closed,
}

/// Resolve a `DELETE /__session__` request. Mirrors `_SessionResource.on_delete`.
pub(crate) fn handle_delete(
    ctx: &Arc<StickyContext>,
    auth: &AuthContext,
    session_header: Option<&str>,
) -> DeleteOutcome {
    let Some(token) = session_header.map(str::trim).filter(|t| !t.is_empty()) else {
        return DeleteOutcome::Idempotent;
    };
    let aad = compute_session_aad(auth);
    let Ok((server_id, sid, _expires_at)) = open_session_token(token, &ctx.token_key, &aad) else {
        return DeleteOutcome::Idempotent;
    };
    if server_id != ctx.server_id {
        return DeleteOutcome::Idempotent;
    }
    let pkey = principal_key(auth);
    if ctx.registry.get(&sid, &pkey).is_none() {
        return DeleteOutcome::Idempotent;
    }
    ctx.registry.close(&sid);
    DeleteOutcome::Closed
}

// ---------------------------------------------------------------------------
// Hex helpers (local to avoid leaking wire internals)
// ---------------------------------------------------------------------------

fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn hex_to_sid(hex: &str) -> Option<[u8; SESSION_ID_LEN]> {
    if hex.len() != SESSION_ID_LEN * 2 {
        return None;
    }
    let mut out = [0u8; SESSION_ID_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [9u8; 32]
    }

    fn auth_anon() -> AuthContext {
        AuthContext::anonymous()
    }

    fn auth_user(domain: &str, principal: &str) -> AuthContext {
        let mut a = AuthContext::anonymous();
        a.authenticated = true;
        a.domain = domain.to_string();
        a.principal = principal.to_string();
        a
    }

    #[test]
    fn token_roundtrip() {
        let aad = compute_session_aad(&auth_anon());
        let sid = [3u8; SESSION_ID_LEN];
        let tok = seal_session_token("srv-1", &sid, 9999, &key(), &aad);
        let (server_id, got_sid, exp) = open_session_token(&tok, &key(), &aad).unwrap();
        assert_eq!(server_id, "srv-1");
        assert_eq!(got_sid, sid);
        assert_eq!(exp, 9999);
    }

    #[test]
    fn cross_principal_rejected() {
        let aad_a = compute_session_aad(&auth_user("d", "alice"));
        let aad_b = compute_session_aad(&auth_user("d", "bob"));
        let sid = [1u8; SESSION_ID_LEN];
        let tok = seal_session_token("srv", &sid, 1, &key(), &aad_a);
        assert!(open_session_token(&tok, &key(), &aad_b).is_err());
    }

    #[test]
    fn cross_peer_evidence_rejected_for_anonymous_application_auth() {
        let mut first = auth_anon();
        first
            .claims
            .insert("peer_evidence_binding".into(), "first".into());
        let mut second = auth_anon();
        second
            .claims
            .insert("peer_evidence_binding".into(), "second".into());
        let aad_first = compute_session_aad(&first);
        let aad_second = compute_session_aad(&second);
        let sid = [1u8; SESSION_ID_LEN];
        let token = seal_session_token("srv", &sid, 1, &key(), &aad_first);
        assert!(open_session_token(&token, &key(), &aad_second).is_err());
        assert_ne!(principal_key(&first), principal_key(&second));
    }

    #[test]
    fn wrong_key_rejected() {
        let aad = compute_session_aad(&auth_anon());
        let sid = [1u8; SESSION_ID_LEN];
        let tok = seal_session_token("srv", &sid, 1, &key(), &aad);
        assert!(open_session_token(&tok, &[1u8; 32], &aad).is_err());
    }

    #[test]
    fn garbage_token_rejected() {
        let aad = compute_session_aad(&auth_anon());
        assert!(open_session_token("not-a-token", &key(), &aad).is_err());
    }

    #[test]
    fn registry_open_get_close() {
        let reg = SessionRegistry::new(Duration::from_secs(300));
        let state: Arc<dyn Any + Send + Sync> = Arc::new(42i64);
        let (sid, _) = reg.open(state, None, "p".into()).unwrap();
        let got = reg.get(&sid, "p").unwrap();
        assert_eq!(*got.downcast::<i64>().unwrap(), 42);
        // wrong principal misses
        assert!(reg.get(&sid, "other").is_none());
        assert!(reg.close(&sid));
        assert!(reg.get(&sid, "p").is_none());
        assert!(!reg.close(&sid));
    }

    #[test]
    fn registry_expired_evicted_inline() {
        let reg = SessionRegistry::new(Duration::from_secs(0));
        let state: Arc<dyn Any + Send + Sync> = Arc::new(1u8);
        let (sid, _) = reg
            .open(state, Some(Duration::from_millis(0)), "p".into())
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(reg.get(&sid, "p").is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn draining_rejects_open() {
        let reg = SessionRegistry::new(Duration::from_secs(300));
        reg.set_draining(true);
        let state: Arc<dyn Any + Send + Sync> = Arc::new(1u8);
        let err = reg.open(state, None, "p".into()).unwrap_err();
        assert_eq!(err.error_type, "ServerDrainingError");
    }
}
