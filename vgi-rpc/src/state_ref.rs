//! `StateRef`, argument references and the turn budget (`STATE_REF_V1.md`).
//!
//! On HTTP every stream continuation echoes the stream's state back to the
//! server. A [`StateRef`] is how a server says "this part of my stream state
//! does not change": store it once, carry a small sealed tag in the state,
//! read it back on any later turn on any replica.
//!
//! ```ignore
//! // In the stream method (the init request), and only there:
//! let query = ctx.state_ref(query_bytes)?;
//! // ... keep `query: StateRef` in the stream state (it is serde-able) ...
//!
//! // On any turn, any replica, any transport:
//! let bytes = ctx.resolve(&state.query)?;
//! ```
//!
//! The client never parses a `StateRef`: it echoes the opaque state token as it
//! always has. Worker code never branches on transport or storage either: the
//! same calls work on pipe, stdio, Unix and TCP (where the state never leaves
//! the process, so the value is simply held in memory) and on HTTP with or
//! without object storage configured.
//!
//! Byte layouts (`STATE_REF_V1.md` §16):
//!
//! ```text
//! StateRef (inline)  = 0x01 || codec || body
//! StateRef (stored)  = 0x02 || 0x01 || nonce24 || AEAD(tag_plaintext, STATEREF_TAG_AAD)
//! tag_plaintext      = 0x01 || created_at u64le || size u64le || sha256[32]
//!                      || id_len u16le || object_id
//! stored object      = 0x01 || nonce24 || AEAD(codec || body, STATEREF_OBJECT_AAD)
//! argument ref       = 0x01 || nonce24 || AEAD(0x01 || size u64le || sha256[32]
//!                      || id_len u16le || object_id, ARGREF_AAD)
//! ```
//!
//! Sealing scopes, all under the server's one token key:
//!
//! ```text
//! STATEREF_TAG_AAD    = b"vgi_rpc.stateref.v1\0"        || BASE_AAD(auth, protocol) || call_id
//! STATEREF_OBJECT_AAD = b"vgi_rpc.stateref.object.v1\0" || BASE_AAD(auth, protocol) || call_id
//! ARGREF_AAD          = b"vgi_rpc.argref.v1\0"          || BASE_AAD(auth, SERVER_SCOPE)
//! ```
//!
//! **Multi-replica deployments must configure a shared token key**
//! (`HttpStateBuilder::token_key*`): a tag opens only under the key that sealed
//! it, exactly as a cursor does.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;

use crate::error_model::Code;
use crate::errors::{Result, RpcError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Scope for tokens that belong to the server rather than to one protocol.
/// Spelled with a leading NUL so it cannot collide with a protocol name.
pub const SERVER_SCOPE: &str = "\u{0}server";
/// Domain prefix of a stored `StateRef`'s tag AAD.
pub const STATEREF_TAG_AAD_PREFIX: &[u8] = b"vgi_rpc.stateref.v1\x00";
/// Domain prefix of a stored `StateRef`'s object AAD.
pub const STATEREF_OBJECT_AAD_PREFIX: &[u8] = b"vgi_rpc.stateref.object.v1\x00";
/// Domain prefix of an argument reference's AAD.
pub const ARGREF_AAD_PREFIX: &[u8] = b"vgi_rpc.argref.v1\x00";

/// Default `VGI_RPC_STATE_REF_INLINE_BYTES`.
pub const DEFAULT_STATE_REF_INLINE_BYTES: usize = 16_384;
/// Environment variable capping the inline payload size.
pub const STATE_REF_INLINE_BYTES_ENV: &str = "VGI_RPC_STATE_REF_INLINE_BYTES";
/// Room left in a continuation request for everything but the two tokens.
pub const TURN_BUDGET_HEADROOM_BYTES: usize = 4096;
/// A request cap below this disables the cursor rule (with a startup warning).
pub const CURSOR_RULE_FLOOR_BYTES: usize = 16_384;
/// Default maximum age of cursor tokens, call tokens and stored tags: 6 h,
/// the maximum stream duration.
pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 21_600;
/// Largest `object_id`, in UTF-8 bytes.
pub const MAX_OBJECT_ID_BYTES: usize = 1024;

const FORM_INLINE: u8 = 0x01;
const FORM_STORED: u8 = 0x02;
#[cfg(feature = "http")]
const SEAL_VERSION: u8 = 0x01;
#[cfg(feature = "http")]
const TAG_VERSION: u8 = 0x01;
#[cfg(feature = "http")]
const ARGREF_VERSION: u8 = 0x01;
#[cfg(feature = "http")]
const SHA256_LEN: usize = 32;
#[cfg(feature = "http")]
const TAG_FIXED_LEN: usize = 1 + 8 + 8 + SHA256_LEN + 2;
#[cfg(feature = "http")]
const ARGREF_FIXED_LEN: usize = 1 + 8 + SHA256_LEN + 2;
/// Bound on a decompressed inline value without a server runtime (64 MiB,
/// the token bound).
const MAX_INLINE_VALUE_BYTES: usize = 64 << 20;

// ---------------------------------------------------------------------------
// Errors (STATE_REF_V1.md §6; argument-reference kinds per the vgi spec)
// ---------------------------------------------------------------------------

/// Unknown form byte, tag unseal or scope failure, bad layout, expired tag,
/// size/digest mismatch, object unseal failure. Answered HTTP 400.
pub const ERROR_KIND_INVALID_STATE_REF: &str = "invalid_state_ref";
/// Storage reports a stored `StateRef`'s object absent.
pub const ERROR_KIND_STATE_REF_MISSING: &str = "state_ref_missing";
/// A stored object over `max_fetch_bytes` (at store or resolve).
pub const ERROR_KIND_STATE_REF_TOO_LARGE: &str = "state_ref_too_large";
/// `state_ref()` called outside the handling of a stream's init request.
pub const ERROR_KIND_STATE_REF_MISUSE: &str = "state_ref_misuse";
/// A sealed cursor over the turn budget under [`CursorRule::Error`].
pub const ERROR_KIND_CURSOR_TOO_LARGE: &str = "cursor_too_large";
/// The `cursor_large` warning event (never an error kind on the wire).
pub const EVENT_CURSOR_LARGE: &str = "cursor_large";
/// A transient storage failure (5xx, timeout) while fetching an object.
pub const ERROR_KIND_STORAGE_UNAVAILABLE: &str = "storage_unavailable";
/// An argument reference does not open, does not match its location, or
/// cannot be resolved by this server.
pub const ERROR_KIND_INVALID_ARGUMENTS_REF: &str = "invalid_arguments_ref";
/// The fetched argument object's length or SHA-256 differs from the sealed
/// values.
pub const ERROR_KIND_ARGUMENTS_REF_INTEGRITY: &str = "arguments_ref_integrity";
/// Storage reports an argument object absent.
pub const ERROR_KIND_ARGUMENTS_REF_MISSING: &str = "arguments_ref_missing";

/// `invalid_state_ref` (`INVALID_ARGUMENT`).
pub fn invalid_state_ref(message: impl Into<String>) -> RpcError {
    RpcError::new("InvalidStateRefError", message)
        .with_status(Code::InvalidArgument, ERROR_KIND_INVALID_STATE_REF)
}

/// `state_ref_missing` (`NOT_FOUND`), with the normative message.
pub fn state_ref_missing() -> RpcError {
    RpcError::new(
        "StateRefMissingError",
        "stream state object is gone (StateRef object expired or deleted); restart the query",
    )
    .with_status(Code::NotFound, ERROR_KIND_STATE_REF_MISSING)
}

/// `state_ref_too_large` (`RESOURCE_EXHAUSTED`).
pub fn state_ref_too_large(message: impl Into<String>) -> RpcError {
    RpcError::new("StateRefTooLargeError", message)
        .with_status(Code::ResourceExhausted, ERROR_KIND_STATE_REF_TOO_LARGE)
}

/// `state_ref_misuse` (`FAILED_PRECONDITION`), naming the method.
pub fn state_ref_misuse(protocol: &str, method: &str) -> RpcError {
    RpcError::new(
        "StateRefMisuseError",
        format!(
            "state_ref() may only be called while handling a stream's init request ({protocol}.{method})"
        ),
    )
    .with_status(Code::FailedPrecondition, ERROR_KIND_STATE_REF_MISUSE)
}

/// `cursor_too_large` (`RESOURCE_EXHAUSTED`).
pub fn cursor_too_large(message: impl Into<String>) -> RpcError {
    RpcError::new("CursorTooLargeError", message)
        .with_status(Code::ResourceExhausted, ERROR_KIND_CURSOR_TOO_LARGE)
}

/// `storage_unavailable` (`UNAVAILABLE`).
pub fn storage_unavailable(message: impl Into<String>) -> RpcError {
    RpcError::new("StorageUnavailableError", message)
        .with_status(Code::Unavailable, ERROR_KIND_STORAGE_UNAVAILABLE)
}

/// `invalid_arguments_ref` (`INVALID_ARGUMENT`).
pub fn invalid_arguments_ref(message: impl Into<String>) -> RpcError {
    RpcError::new("InvalidArgumentsRefError", message)
        .with_status(Code::InvalidArgument, ERROR_KIND_INVALID_ARGUMENTS_REF)
}

/// `arguments_ref_integrity` (`DATA_LOSS`).
pub fn arguments_ref_integrity(message: impl Into<String>) -> RpcError {
    RpcError::new("ArgumentsRefIntegrityError", message)
        .with_status(Code::DataLoss, ERROR_KIND_ARGUMENTS_REF_INTEGRITY)
}

/// `arguments_ref_missing` (`NOT_FOUND`).
pub fn arguments_ref_missing(message: impl Into<String>) -> RpcError {
    RpcError::new("ArgumentsRefMissingError", message)
        .with_status(Code::NotFound, ERROR_KIND_ARGUMENTS_REF_MISSING)
}

/// Whether `err` is one the HTTP transport answers with 400, like any other
/// token failure (`invalid_state_ref`).
pub fn is_invalid_state_ref(err: &RpcError) -> bool {
    err.error_kind() == ERROR_KIND_INVALID_STATE_REF
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// What a server does with a cursor over its turn budget (§9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CursorRule {
    /// Log `cursor_large`, send the client a `WARN` log, and continue.
    #[default]
    Warn,
    /// Refuse the turn with `cursor_too_large` (only when a request cap is
    /// set). A framework that keeps its unchanging state in `StateRef`s
    /// passes this.
    Error,
}

impl std::str::FromStr for CursorRule {
    type Err = RpcError;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "warn" => Ok(CursorRule::Warn),
            "error" => Ok(CursorRule::Error),
            other => Err(RpcError::value_error(format!(
                "cursor_rule must be 'warn' or 'error', got {other:?}"
            ))),
        }
    }
}

/// Read `VGI_RPC_STATE_REF_INLINE_BYTES` (default 16384).
///
/// # Errors
///
/// When the variable is set to anything but a positive integer.
pub fn state_ref_inline_bytes_from_env() -> Result<usize> {
    inline_bytes_from(std::env::var(STATE_REF_INLINE_BYTES_ENV).ok().as_deref())
}

fn inline_bytes_from(raw: Option<&str>) -> Result<usize> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(DEFAULT_STATE_REF_INLINE_BYTES);
    };
    match raw.parse::<usize>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(RpcError::value_error(format!(
            "{STATE_REF_INLINE_BYTES_ENV} must be a positive integer, got {raw:?}"
        ))),
    }
}

/// The sealed bytes a cursor may take on a continuation, or `None` when the
/// request size is unbounded:
/// `floor((max_request_bytes - 4096) / 1.34) - call_token_bytes`.
///
/// `max_request_bytes` is the advertised `VGI-Max-Request-Bytes`; `None` or
/// `0` means unbounded. The result may be negative under a tiny cap.
pub fn turn_budget(max_request_bytes: Option<usize>, call_token_bytes: usize) -> Option<i64> {
    let cap = max_request_bytes.filter(|n| *n > 0)? as i64;
    Some(
        ((cap - TURN_BUDGET_HEADROOM_BYTES as i64) * 100).div_euclid(134) - call_token_bytes as i64,
    )
}

// ---------------------------------------------------------------------------
// StateRef
// ---------------------------------------------------------------------------

/// Where a [`StateRef`]'s value lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateRefForm {
    /// Not yet encoded: held in process memory (pipe, stdio, Unix, TCP, or
    /// an HTTP init turn before the cursor is minted).
    Memory,
    /// A compressed payload inside the state token.
    Inline,
    /// Uploaded once; the state token carries a sealed tag.
    Stored,
    /// Encoded bytes with an unknown form byte (refused on resolve).
    Invalid,
}

impl StateRefForm {
    /// `memory`, `inline`, `stored` or `invalid`.
    pub fn as_str(self) -> &'static str {
        match self {
            StateRefForm::Memory => "memory",
            StateRefForm::Inline => "inline",
            StateRefForm::Stored => "stored",
            StateRefForm::Invalid => "invalid",
        }
    }
}

struct RefInner {
    /// The value, while this ref was created in this process.
    value: Option<Bytes>,
    /// The encoded form, once decided (or as read back from a token).
    encoded: OnceLock<Bytes>,
}

/// An immutable value carried in stream state by reference.
///
/// Create one with [`CallContext::state_ref`](crate::CallContext::state_ref)
/// while handling a stream's init request, keep it in a field of the stream
/// state (it implements `serde::Serialize` / `Deserialize`, so a bincode or
/// any other serde codec carries it), and read it back with
/// [`CallContext::resolve`](crate::CallContext::resolve) on any turn.
///
/// The value is held in memory until the state is first serialized into an
/// HTTP state token. That serialization decides the form -- inline (a
/// compressed payload inside the token) or stored (uploaded once, a sealed tag
/// in the token) -- and caches the encoded bytes on the ref (shared by every
/// clone), so later serializations re-emit them exactly: no re-compression,
/// no re-seal, no second upload. A ref read back from a token holds only those
/// bytes. On pipe, stdio, Unix and TCP nothing is ever encoded.
///
/// A ref belongs to exactly one stream (its tag is bound to that stream's call
/// id): state transitions copy the ref, never call `state_ref()` again.
#[derive(Clone)]
pub struct StateRef(Arc<RefInner>);

impl StateRef {
    pub(crate) fn from_value(value: Bytes) -> Self {
        StateRef(Arc::new(RefInner {
            value: Some(value),
            encoded: OnceLock::new(),
        }))
    }

    /// Rebuild a ref from its wire bytes. Validated only when resolved.
    pub fn from_encoded(encoded: impl Into<Bytes>) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(encoded.into());
        StateRef(Arc::new(RefInner {
            value: None,
            encoded: cell,
        }))
    }

    /// Where the value lives.
    pub fn form(&self) -> StateRefForm {
        match self.0.encoded.get() {
            None => StateRefForm::Memory,
            Some(e) => match e.first() {
                Some(&FORM_INLINE) => StateRefForm::Inline,
                Some(&FORM_STORED) => StateRefForm::Stored,
                _ => StateRefForm::Invalid,
            },
        }
    }

    /// The encoded bytes once the form is decided, else `None`.
    pub fn encoded(&self) -> Option<Bytes> {
        self.0.encoded.get().cloned()
    }

    /// The field's wire bytes.
    ///
    /// Inside an HTTP state-token mint the form is decided, any store
    /// performed, and the result cached. Outside one -- a caller serializing a
    /// state for its own reasons -- an un-encoded ref renders inline *without*
    /// caching, so the next token mint still decides the form properly.
    ///
    /// # Errors
    ///
    /// Inside a mint: `state_ref_too_large`, or a storage failure while
    /// storing.
    pub fn to_bytes(&self) -> Result<Bytes> {
        if let Some(e) = self.0.encoded.get() {
            return Ok(e.clone());
        }
        let value = self
            .0
            .value
            .as_ref()
            .expect("an un-encoded StateRef holds its value");
        #[cfg(feature = "http")]
        if let Some(encoder) = encoder::current() {
            let encoded = match encode_value(value, &encoder) {
                Ok(encoded) => encoded,
                Err(err) => {
                    encoder.record_error(err.clone());
                    return Err(err);
                }
            };
            return Ok(self.0.encoded.get_or_init(|| encoded).clone());
        }
        Ok(inline_encoding(value))
    }

    fn identity(&self) -> Bytes {
        match (self.0.encoded.get(), self.0.value.as_ref()) {
            (Some(e), _) => e.clone(),
            (None, Some(v)) => {
                let mut out = Vec::with_capacity(1 + v.len());
                out.push(0xff);
                out.extend_from_slice(v);
                out.into()
            }
            (None, None) => Bytes::new(),
        }
    }
}

impl PartialEq for StateRef {
    /// Compare by encoded bytes, or by value when neither is encoded.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.identity() == other.identity()
    }
}

impl Eq for StateRef {}

impl std::fmt::Debug for StateRef {
    /// Describe the form and size, never the value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.0.encoded.get(), self.0.value.as_ref()) {
            (Some(e), _) => write!(
                f,
                "StateRef(form={:?}, encoded_bytes={})",
                self.form().as_str(),
                e.len()
            ),
            (None, Some(v)) => write!(f, "StateRef(form=\"memory\", bytes={})", v.len()),
            (None, None) => f.write_str("StateRef(empty)"),
        }
    }
}

impl serde::Serialize for StateRef {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let bytes = self
            .to_bytes()
            .map_err(|e| serde::ser::Error::custom(e.message))?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> serde::Deserialize<'de> for StateRef {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = StateRef;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("encoded StateRef bytes")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                v: &[u8],
            ) -> std::result::Result<StateRef, E> {
                Ok(StateRef::from_encoded(Bytes::copy_from_slice(v)))
            }
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                v: Vec<u8>,
            ) -> std::result::Result<StateRef, E> {
                Ok(StateRef::from_encoded(v))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<StateRef, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(StateRef::from_encoded(out))
            }
        }
        deserializer.deserialize_byte_buf(V)
    }
}

/// The inline encoding of `value`: `0x01 || codec || body`.
fn inline_encoding(value: &[u8]) -> Bytes {
    #[cfg(feature = "external")]
    let payload = crate::token_codec::pack(value);
    #[cfg(not(feature = "external"))]
    let payload = {
        let mut p = Vec::with_capacity(1 + value.len());
        p.push(0x00);
        p.extend_from_slice(value);
        p
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(FORM_INLINE);
    out.extend_from_slice(&payload);
    out.into()
}

fn unpack_inline(payload: &[u8], cap: usize) -> Result<Bytes> {
    #[cfg(feature = "external")]
    {
        crate::token_codec::unpack(payload, cap)
            .map(Bytes::from)
            .map_err(|e| invalid_state_ref(format!("StateRef payload is malformed: {e}")))
    }
    #[cfg(not(feature = "external"))]
    {
        match payload.split_first() {
            Some((0x00, body)) if body.len() <= cap => Ok(Bytes::copy_from_slice(body)),
            Some((0x00, _)) => Err(invalid_state_ref(
                "StateRef payload is malformed: decompressed body exceeds the bound",
            )),
            Some((tag, _)) => Err(invalid_state_ref(format!(
                "StateRef payload is malformed: unknown codec 0x{tag:02x}"
            ))),
            None => Err(invalid_state_ref(
                "StateRef payload is malformed: empty payload",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// The per-request scope a CallContext delegates to
// ---------------------------------------------------------------------------

/// The `StateRef` view of one request.
///
/// The framework attaches one to every [`CallContext`](crate::CallContext). On
/// HTTP it carries the server runtime and (on continuations) the stream's call
/// id; on the byte-stream transports there is no runtime (values never leave
/// memory). `init` is set only while the stream method itself runs -- the one
/// place `state_ref()` is allowed.
pub(crate) struct StateRefScope {
    #[cfg(feature = "http")]
    pub(crate) runtime: Option<Arc<StateRefRuntime>>,
    pub(crate) protocol: String,
    pub(crate) method: String,
    #[cfg(feature = "http")]
    pub(crate) call_id: Option<[u8; 16]>,
    pub(crate) init: AtomicBool,
    /// Init-turn memo: SHA-256 of the value -> the ref, so byte-equal values
    /// share one ref (and so one stored object).
    memo: Mutex<HashMap<[u8; 32], StateRef>>,
}

impl StateRefScope {
    pub(crate) fn new(protocol: &str, method: &str) -> Self {
        Self {
            #[cfg(feature = "http")]
            runtime: None,
            protocol: protocol.to_string(),
            method: method.to_string(),
            #[cfg(feature = "http")]
            call_id: None,
            init: AtomicBool::new(false),
            memo: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn set_init(&self, init: bool) {
        self.init.store(init, Ordering::SeqCst);
        if !init {
            self.memo.lock().unwrap_or_else(|p| p.into_inner()).clear();
        }
    }

    pub(crate) fn state_ref(&self, value: &[u8]) -> Result<StateRef> {
        if !self.init.load(Ordering::SeqCst) {
            return Err(state_ref_misuse(&self.protocol, &self.method));
        }
        use sha2::Digest as _;
        let digest: [u8; 32] = sha2::Sha256::digest(value).into();
        let mut memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = memo.get(&digest) {
            if existing.0.value.as_deref() == Some(value) {
                return Ok(existing.clone());
            }
        }
        let r = StateRef::from_value(Bytes::copy_from_slice(value));
        memo.insert(digest, r.clone());
        Ok(r)
    }

    pub(crate) fn resolve(
        &self,
        r: &StateRef,
        #[cfg_attr(not(feature = "http"), allow(unused_variables))] auth: &crate::auth::AuthContext,
    ) -> Result<Bytes> {
        if let Some(v) = r.0.value.as_ref() {
            return Ok(v.clone());
        }
        let encoded = r.0.encoded.get().cloned().unwrap_or_default();
        #[cfg(feature = "http")]
        if let Some(runtime) = self.runtime.as_ref() {
            let base = base_aad(auth, &self.protocol);
            return resolve_encoded(&encoded, Some(runtime), Some(&base), self.call_id.as_ref());
        }
        resolve_encoded_offline(&encoded)
    }

    pub(crate) fn resolve_argument_ref(
        &self,
        #[cfg_attr(not(feature = "http"), allow(unused_variables))] auth: &crate::auth::AuthContext,
        #[cfg_attr(not(feature = "http"), allow(unused_variables))] r: &[u8],
        #[cfg_attr(not(feature = "http"), allow(unused_variables))] size: u64,
        #[cfg_attr(not(feature = "http"), allow(unused_variables))] sha256: &str,
    ) -> Result<Bytes> {
        #[cfg(feature = "http")]
        if let Some(runtime) = self.runtime.as_ref() {
            return runtime.resolve_argument_ref(auth, r, size, sha256);
        }
        Err(invalid_arguments_ref(
            "argument references can only be resolved by an HTTP server",
        ))
    }
}

/// Resolve encoded bytes with no server runtime: inline only.
fn resolve_encoded_offline(encoded: &[u8]) -> Result<Bytes> {
    match encoded.first() {
        None => Err(invalid_state_ref("StateRef is empty")),
        Some(&FORM_INLINE) => unpack_inline(&encoded[1..], MAX_INLINE_VALUE_BYTES),
        Some(&FORM_STORED) => Err(invalid_state_ref(
            "a stored StateRef cannot be resolved outside an HTTP stream turn",
        )),
        Some(&form) => Err(invalid_state_ref(format!(
            "StateRef has unknown form 0x{form:02x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// HTTP: runtime, AAD, encoder, resolve, argument references
// ---------------------------------------------------------------------------

#[cfg(feature = "http")]
pub use http_impl::*;

#[cfg(feature = "http")]
mod http_impl {
    use super::*;
    use crate::external::{ExternalStorage, ObjectStore};
    use crate::object_cache::ObjectCache;
    use sha2::Digest as _;

    /// Seconds since the Unix epoch.
    pub type SecondsClock = Arc<dyn Fn() -> u64 + Send + Sync>;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Return the cursor-token AAD for `auth` and `protocol` (`BASE_AAD`, §4):
    ///
    /// ```text
    /// prefix := b"vgi_rpc.state.v7\0" if a peer-evidence binding digest is present
    ///           else b"vgi_rpc.state.v6\0"
    /// tail   := b"\0anonymous"                                (unauthenticated)
    ///         | b"\x01" || domain || b"\0" || principal        (authenticated)
    ///           then, if binding present: || b"\0" || binding
    /// BASE_AAD := prefix || tail || b"\0" || protocol
    /// ```
    pub fn base_aad(auth: &crate::auth::AuthContext, protocol: &str) -> Vec<u8> {
        let binding = auth
            .claims
            .get("peer_evidence_binding")
            .filter(|b| !b.is_empty());
        let mut out = Vec::with_capacity(64 + protocol.len());
        out.extend_from_slice(if binding.is_some() {
            b"vgi_rpc.state.v7\x00"
        } else {
            b"vgi_rpc.state.v6\x00"
        });
        if auth.authenticated {
            out.push(0x01);
            out.extend_from_slice(auth.domain.as_bytes());
            out.push(0);
            out.extend_from_slice(auth.principal.as_bytes());
        } else {
            out.extend_from_slice(b"\x00anonymous");
        }
        if let Some(binding) = binding {
            out.push(0);
            out.extend_from_slice(binding.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(protocol.as_bytes());
        out
    }

    fn tag_aad(base: &[u8], call_id: &[u8; 16]) -> Vec<u8> {
        [STATEREF_TAG_AAD_PREFIX, base, call_id].concat()
    }

    fn object_aad(base: &[u8], call_id: &[u8; 16]) -> Vec<u8> {
        [STATEREF_OBJECT_AAD_PREFIX, base, call_id].concat()
    }

    /// `ARGREF_AAD` for `auth`: bound to the principal, not to a protocol.
    pub fn argument_ref_aad(auth: &crate::auth::AuthContext) -> Vec<u8> {
        [ARGREF_AAD_PREFIX, &base_aad(auth, SERVER_SCOPE)].concat()
    }

    /// One server's `StateRef` machinery: key, storage, budgets and cache.
    ///
    /// Built by the HTTP transport; the byte-stream transports never need one,
    /// because their state never leaves the process.
    pub struct StateRefRuntime {
        token_key: [u8; 32],
        token_ttl: u64,
        storage: Option<Arc<dyn ExternalStorage>>,
        max_fetch_bytes: usize,
        max_request_bytes: Option<usize>,
        inline_bytes_cap: usize,
        cursor_rule: CursorRule,
        cursor_rule_disabled: bool,
        cache: Arc<ObjectCache>,
        clock: SecondsClock,
    }

    impl std::fmt::Debug for StateRefRuntime {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("StateRefRuntime")
                .field("token_ttl", &self.token_ttl)
                .field("max_fetch_bytes", &self.max_fetch_bytes)
                .field("max_request_bytes", &self.max_request_bytes)
                .field("inline_bytes_cap", &self.inline_bytes_cap)
                .field("cursor_rule", &self.cursor_rule)
                .finish_non_exhaustive()
        }
    }

    impl StateRefRuntime {
        /// A runtime sealing under `token_key` and fetching at most
        /// `max_fetch_bytes`, with the defaults: `token_ttl` 21600 s, no
        /// storage, no request cap, the 16 KiB inline cap, the `warn` cursor
        /// rule and the process-wide object cache.
        pub fn new(token_key: [u8; 32], max_fetch_bytes: usize) -> Self {
            Self {
                token_key,
                token_ttl: DEFAULT_TOKEN_TTL_SECONDS,
                storage: None,
                max_fetch_bytes,
                max_request_bytes: None,
                inline_bytes_cap: DEFAULT_STATE_REF_INLINE_BYTES,
                cursor_rule: CursorRule::Warn,
                cursor_rule_disabled: false,
                cache: crate::object_cache::default_object_cache(),
                clock: Arc::new(now_secs),
            }
        }

        /// Maximum age of a stored tag in seconds; `0` disables expiry.
        pub fn with_token_ttl(mut self, seconds: u64) -> Self {
            self.token_ttl = seconds;
            self
        }

        /// The server's storage. One whose
        /// [`object_store`](ExternalStorage::object_store) is `None` counts
        /// as none: refs stay inline.
        pub fn with_storage(mut self, storage: Option<Arc<dyn ExternalStorage>>) -> Self {
            self.storage = storage;
            self
        }

        /// The advertised request cap (`None`/`0` = unbounded). Below 16384
        /// the cursor rule is disabled, with a warning logged here.
        pub fn with_max_request_bytes(mut self, max_request_bytes: Option<usize>) -> Self {
            self.max_request_bytes = max_request_bytes.filter(|n| *n > 0);
            self.cursor_rule_disabled = self
                .max_request_bytes
                .is_some_and(|n| n < CURSOR_RULE_FLOOR_BYTES);
            if let (true, Some(n)) = (self.cursor_rule_disabled, self.max_request_bytes) {
                tracing::warn!(
                    target: "vgi_rpc.state_ref",
                    "max_request_bytes ({n}) is below {CURSOR_RULE_FLOOR_BYTES}: the cursor rule is \
                     disabled and stream continuations may not fit"
                );
            }
            self
        }

        /// `VGI_RPC_STATE_REF_INLINE_BYTES`.
        ///
        /// # Panics
        ///
        /// When `n` is zero.
        pub fn with_inline_bytes_cap(mut self, n: usize) -> Self {
            assert!(n > 0, "state_ref_inline_bytes must be a positive integer");
            self.inline_bytes_cap = n;
            self
        }

        /// The cursor rule.
        pub fn with_cursor_rule(mut self, rule: CursorRule) -> Self {
            self.cursor_rule = rule;
            self
        }

        /// The object cache (default: the process-wide one).
        pub fn with_cache(mut self, cache: Arc<ObjectCache>) -> Self {
            self.cache = cache;
            self
        }

        /// The wall clock, in seconds (tests).
        pub fn with_clock(mut self, clock: SecondsClock) -> Self {
            self.clock = clock;
            self
        }

        /// The object cache this runtime resolves through.
        pub fn cache(&self) -> &Arc<ObjectCache> {
            &self.cache
        }

        /// The cursor rule.
        pub fn cursor_rule(&self) -> CursorRule {
            self.cursor_rule
        }

        /// Whether over-budget cursors warn or error at all (off below the
        /// 16 KiB floor).
        pub fn cursor_rule_enabled(&self) -> bool {
            !self.cursor_rule_disabled
        }

        /// The inbound fetch cap.
        pub fn max_fetch_bytes(&self) -> usize {
            self.max_fetch_bytes
        }

        pub(crate) fn token_key(&self) -> &[u8; 32] {
            &self.token_key
        }

        /// The configured object store, or `None`.
        pub fn object_store(&self) -> Option<&dyn ObjectStore> {
            self.storage.as_deref().and_then(|s| s.object_store())
        }

        /// Largest decompressed value: 64 MiB or `max_fetch_bytes`, whichever
        /// is larger.
        pub fn decompress_cap(&self) -> usize {
            crate::token_codec::MAX_TOKEN_PLAINTEXT_BYTES.max(self.max_fetch_bytes)
        }

        /// [`turn_budget`] for this server's request cap.
        pub fn turn_budget(&self, call_token_bytes: usize) -> Option<i64> {
            turn_budget(self.max_request_bytes, call_token_bytes)
        }

        /// `state_ref_inline_bytes = min(cap, floor(turn_budget / 4))`,
        /// floored at 0.
        pub fn inline_bytes(&self, call_token_bytes: usize) -> usize {
            match self.turn_budget(call_token_bytes) {
                None => self.inline_bytes_cap,
                Some(b) => (b.div_euclid(4).max(0) as usize).min(self.inline_bytes_cap),
            }
        }

        /// Apply the cursor rule to one sealed cursor of `cursor_bytes`.
        ///
        /// Returns `Ok(None)` when the cursor fits (or the rule is off), and
        /// under [`CursorRule::Warn`] `Ok(Some(text))` with the
        /// `cursor_large: ...` warning the transport sends the client.
        ///
        /// # Errors
        ///
        /// `cursor_too_large` under [`CursorRule::Error`] with a request cap.
        pub fn check_cursor(
            &self,
            cursor_bytes: usize,
            call_token_bytes: usize,
            protocol: &str,
            method: &str,
        ) -> Result<Option<String>> {
            if self.cursor_rule_disabled {
                return Ok(None);
            }
            let Some(budget) = self.turn_budget(call_token_bytes) else {
                return Ok(None);
            };
            if cursor_bytes as i64 <= budget {
                return Ok(None);
            }
            let detail = format!(
                "stream state for {protocol}.{method} is {cursor_bytes} bytes, over this server's \
                 turn budget of {budget} bytes (VGI-Max-Request-Bytes {}). Wrap data that does not \
                 change across turns in ctx.state_ref().",
                self.max_request_bytes.unwrap_or(0)
            );
            match self.cursor_rule {
                CursorRule::Error => {
                    tracing::warn!(
                        target: "vgi_rpc.state_ref",
                        event = ERROR_KIND_CURSOR_TOO_LARGE,
                        protocol, method, cursor_bytes, budget,
                        "cursor_too_large: {detail}"
                    );
                    Err(cursor_too_large(format!("cursor_too_large: {detail}")))
                }
                CursorRule::Warn => {
                    tracing::warn!(
                        target: "vgi_rpc.state_ref",
                        event = EVENT_CURSOR_LARGE,
                        protocol, method, cursor_bytes, budget,
                        "cursor_large: {detail}"
                    );
                    Ok(Some(format!("cursor_large: {detail}")))
                }
            }
        }

        /// Encode `value` as a `StateRef` directly (the call token's
        /// `schemas_ref`; `call_token_bytes` is 0 there).
        ///
        /// # Errors
        ///
        /// As [`StateRef::to_bytes`] inside a mint.
        pub(crate) fn encode_value(
            self: &Arc<Self>,
            value: &[u8],
            auth: &crate::auth::AuthContext,
            protocol: &str,
            method: &str,
            call_id: &[u8; 16],
            call_token_bytes: usize,
        ) -> Result<Bytes> {
            let encoder =
                encoder::Encoder::new(self, auth, protocol, method, call_id, call_token_bytes);
            encode_value(value, &encoder)
        }

        /// Resolve encoded `StateRef` bytes for the stream `call_id`.
        ///
        /// # Errors
        ///
        /// The §6 kinds.
        pub fn resolve_encoded(
            self: &Arc<Self>,
            encoded: &[u8],
            auth: &crate::auth::AuthContext,
            protocol: &str,
            call_id: &[u8; 16],
        ) -> Result<Bytes> {
            let base = base_aad(auth, protocol);
            resolve_encoded(encoded, Some(self), Some(&base), Some(call_id))
        }

        /// Resolve an argument reference minted by this server's grant for
        /// `auth` (see [`resolve_argument_ref`]).
        ///
        /// # Errors
        ///
        /// `invalid_arguments_ref`, `arguments_ref_integrity`,
        /// `arguments_ref_missing`, `storage_unavailable`.
        pub fn resolve_argument_ref(
            &self,
            auth: &crate::auth::AuthContext,
            r: &[u8],
            size: u64,
            sha256: &str,
        ) -> Result<Bytes> {
            resolve_argument_ref(
                r,
                size,
                sha256,
                &self.token_key,
                auth,
                self.object_store(),
                self.max_fetch_bytes,
                &self.cache,
            )
        }

        /// Seal an argument reference for one granted upload.
        ///
        /// # Errors
        ///
        /// On a bad size, digest or object id.
        pub fn mint_argument_ref(
            &self,
            auth: &crate::auth::AuthContext,
            size: u64,
            sha256: &str,
            object_id: &str,
        ) -> Result<Vec<u8>> {
            mint_argument_ref(&self.token_key, auth, size, sha256, object_id)
        }
    }

    // -- The encoder installed while a state token is minted -----------------

    pub(crate) mod encoder {
        use super::*;
        use std::cell::RefCell;
        use std::rc::Rc;

        /// Everything needed to decide a ref's form and seal it, for one mint.
        pub(crate) struct Encoder {
            pub runtime: Arc<StateRefRuntime>,
            pub base_aad: Vec<u8>,
            pub call_id: [u8; 16],
            pub inline_bytes: usize,
            pub protocol: String,
            pub method: String,
            error: RefCell<Option<RpcError>>,
        }

        impl Encoder {
            pub(crate) fn new(
                runtime: &Arc<StateRefRuntime>,
                auth: &crate::auth::AuthContext,
                protocol: &str,
                method: &str,
                call_id: &[u8; 16],
                call_token_bytes: usize,
            ) -> Self {
                Self {
                    runtime: runtime.clone(),
                    base_aad: base_aad(auth, protocol),
                    call_id: *call_id,
                    inline_bytes: runtime.inline_bytes(call_token_bytes),
                    protocol: protocol.to_string(),
                    method: method.to_string(),
                    error: RefCell::new(None),
                }
            }

            pub(crate) fn record_error(&self, err: RpcError) {
                self.error.borrow_mut().get_or_insert(err);
            }
        }

        thread_local! {
            static CURRENT: RefCell<Option<Rc<Encoder>>> = const { RefCell::new(None) };
        }

        pub(crate) fn current() -> Option<Rc<Encoder>> {
            CURRENT.with(|c| c.borrow().clone())
        }

        struct Restore(Option<Rc<Encoder>>);

        impl Drop for Restore {
            fn drop(&mut self) {
                let previous = self.0.take();
                CURRENT.with(|c| *c.borrow_mut() = previous);
            }
        }

        /// Run `f` (which serializes a stream state) with `encoder` deciding
        /// the forms of the un-encoded refs it serializes. Returns `f`'s
        /// result and the first typed error a ref raised, which a serde-based
        /// codec would otherwise flatten into a string.
        pub(crate) fn encoding<T>(
            encoder: Encoder,
            f: impl FnOnce() -> T,
        ) -> (T, Option<RpcError>) {
            let encoder = Rc::new(encoder);
            let previous = CURRENT.with(|c| c.borrow_mut().replace(encoder.clone()));
            let restore = Restore(previous);
            let out = f();
            drop(restore);
            let err = encoder.error.borrow_mut().take();
            (out, err)
        }
    }

    /// Decide a value's form and encode it (§5.2), storing it when stored.
    pub(super) fn encode_value(value: &[u8], encoder: &encoder::Encoder) -> Result<Bytes> {
        let payload = crate::token_codec::pack(value);
        let runtime = &encoder.runtime;
        let storage = runtime.object_store();
        let Some(storage) = storage.filter(|_| payload.len() > encoder.inline_bytes) else {
            tracing::debug!(
                target: "vgi_rpc.state_ref",
                event = "state_ref.store",
                protocol = encoder.protocol.as_str(),
                method = encoder.method.as_str(),
                payload_bytes = payload.len(),
                object_bytes = 0usize,
                form = "inline",
                "state_ref.store"
            );
            let mut out = Vec::with_capacity(1 + payload.len());
            out.push(FORM_INLINE);
            out.extend_from_slice(&payload);
            return Ok(out.into());
        };
        let object_bytes = crate::crypto::seal_bytes(
            &payload,
            runtime.token_key(),
            &object_aad(&encoder.base_aad, &encoder.call_id),
            SEAL_VERSION,
        );
        if object_bytes.len() > runtime.max_fetch_bytes {
            return Err(state_ref_too_large(format!(
                "StateRef object for {}.{} is {} bytes, over this server's max_fetch_bytes ({}); \
                 no replica could fetch it back",
                encoder.protocol,
                encoder.method,
                object_bytes.len(),
                runtime.max_fetch_bytes
            )));
        }
        let object_id = storage.put_object(&object_bytes)?;
        let id_bytes = object_id.as_bytes();
        if id_bytes.is_empty() || id_bytes.len() > MAX_OBJECT_ID_BYTES {
            return Err(RpcError::runtime_error(format!(
                "storage returned an object_id of {} bytes (must be 1-{MAX_OBJECT_ID_BYTES})",
                id_bytes.len()
            )));
        }
        let mut tag_plaintext = Vec::with_capacity(TAG_FIXED_LEN + id_bytes.len());
        tag_plaintext.push(TAG_VERSION);
        tag_plaintext.extend_from_slice(&(runtime.clock)().to_le_bytes());
        tag_plaintext.extend_from_slice(&(object_bytes.len() as u64).to_le_bytes());
        tag_plaintext.extend_from_slice(&sha2::Sha256::digest(&object_bytes));
        tag_plaintext.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
        tag_plaintext.extend_from_slice(id_bytes);
        let tag = crate::crypto::seal_bytes(
            &tag_plaintext,
            runtime.token_key(),
            &tag_aad(&encoder.base_aad, &encoder.call_id),
            SEAL_VERSION,
        );
        tracing::debug!(
            target: "vgi_rpc.state_ref",
            event = "state_ref.store",
            protocol = encoder.protocol.as_str(),
            method = encoder.method.as_str(),
            payload_bytes = payload.len(),
            object_bytes = object_bytes.len(),
            form = "stored",
            "state_ref.store"
        );
        let mut out = Vec::with_capacity(1 + tag.len());
        out.push(FORM_STORED);
        out.extend_from_slice(&tag);
        Ok(out.into())
    }

    /// `storage.get` with the error mapping both resolvers share.
    fn fetch_object(
        storage: &dyn ObjectStore,
        object_id: &str,
        max_bytes: usize,
        missing: impl FnOnce() -> RpcError,
    ) -> Result<Vec<u8>> {
        storage.get(object_id, max_bytes).map_err(|err| {
            if crate::external::is_object_missing(&err) {
                missing()
            } else {
                storage_unavailable(format!(
                    "object storage fetch failed ({}): {}",
                    err.error_type, err.message
                ))
            }
        })
    }

    fn resolve_stored(
        tag_envelope: &[u8],
        runtime: &StateRefRuntime,
        base: &[u8],
        call_id: &[u8; 16],
    ) -> Result<Bytes> {
        let tag = crate::crypto::open_bytes(
            tag_envelope,
            runtime.token_key(),
            &tag_aad(base, call_id),
            SEAL_VERSION,
        )
        .map_err(|_| {
            invalid_state_ref("StateRef tag does not open (tampered, or minted for another stream)")
        })?;
        if tag.len() < TAG_FIXED_LEN || tag[0] != TAG_VERSION {
            return Err(invalid_state_ref(
                "StateRef tag has an unknown version or a malformed layout",
            ));
        }
        let created_at = u64::from_le_bytes(tag[1..9].try_into().expect("8 bytes"));
        let size = u64::from_le_bytes(tag[9..17].try_into().expect("8 bytes"));
        let digest: [u8; 32] = tag[17..17 + SHA256_LEN].try_into().expect("32 bytes");
        let id_len = u16::from_le_bytes(
            tag[17 + SHA256_LEN..TAG_FIXED_LEN]
                .try_into()
                .expect("2 bytes"),
        ) as usize;
        if id_len == 0 || id_len > MAX_OBJECT_ID_BYTES || TAG_FIXED_LEN + id_len != tag.len() {
            return Err(invalid_state_ref("StateRef tag has a malformed layout"));
        }
        let object_id = std::str::from_utf8(&tag[TAG_FIXED_LEN..])
            .map_err(|_| invalid_state_ref("StateRef tag has a malformed layout"))?
            .to_string();
        if runtime.token_ttl > 0 && (runtime.clock)().saturating_sub(created_at) > runtime.token_ttl
        {
            return Err(invalid_state_ref("StateRef expired"));
        }
        if size > runtime.max_fetch_bytes as u64 {
            return Err(state_ref_too_large(format!(
                "StateRef object is {size} bytes, over this server's max_fetch_bytes ({})",
                runtime.max_fetch_bytes
            )));
        }
        let Some(storage) = runtime.object_store() else {
            return Err(invalid_state_ref(
                "a stored StateRef cannot be resolved: this server has no object storage",
            ));
        };
        let (value, hit) = runtime.cache.get_or_fetch(&object_id, || {
            let object_bytes = fetch_object(
                storage,
                &object_id,
                runtime.max_fetch_bytes,
                state_ref_missing,
            )?;
            if object_bytes.len() as u64 != size {
                return Err(invalid_state_ref("StateRef object size mismatch"));
            }
            if sha2::Sha256::digest(&object_bytes)[..] != digest[..] {
                return Err(invalid_state_ref("StateRef object digest mismatch"));
            }
            let payload = crate::crypto::open_bytes(
                &object_bytes,
                runtime.token_key(),
                &object_aad(base, call_id),
                SEAL_VERSION,
            )
            .map_err(|_| invalid_state_ref("StateRef object does not open"))?;
            unpack_inline(&payload, runtime.decompress_cap())
        })?;
        tracing::debug!(
            target: "vgi_rpc.state_ref",
            event = "state_ref.resolve",
            form = "stored",
            cache = if hit { "hit" } else { "miss" },
            bytes = value.len(),
            "state_ref.resolve"
        );
        Ok(value)
    }

    pub(super) fn resolve_encoded(
        encoded: &[u8],
        runtime: Option<&Arc<StateRefRuntime>>,
        base: Option<&[u8]>,
        call_id: Option<&[u8; 16]>,
    ) -> Result<Bytes> {
        match encoded.first() {
            None => Err(invalid_state_ref("StateRef is empty")),
            Some(&FORM_INLINE) => {
                let cap = runtime.map_or(MAX_INLINE_VALUE_BYTES, |r| r.decompress_cap());
                let value = unpack_inline(&encoded[1..], cap)?;
                tracing::debug!(
                    target: "vgi_rpc.state_ref",
                    event = "state_ref.resolve",
                    form = "inline",
                    cache = "miss",
                    bytes = value.len(),
                    "state_ref.resolve"
                );
                Ok(value)
            }
            Some(&FORM_STORED) => match (runtime, base, call_id) {
                (Some(runtime), Some(base), Some(call_id)) => {
                    resolve_stored(&encoded[1..], runtime, base, call_id)
                }
                _ => Err(invalid_state_ref(
                    "a stored StateRef cannot be resolved outside an HTTP stream turn",
                )),
            },
            Some(&form) => Err(invalid_state_ref(format!(
                "StateRef has unknown form 0x{form:02x}"
            ))),
        }
    }

    // -- Argument references (§10.2) -----------------------------------------

    /// The opened contents of an argument reference.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ArgumentRef {
        /// The sealed byte length.
        pub size: u64,
        /// The sealed SHA-256, 64 lowercase hex.
        pub sha256: String,
        /// The storage id.
        pub object_id: String,
    }

    fn hex_to_digest(sha256: &str) -> Option<[u8; 32]> {
        if !crate::external::is_sha256_hex(sha256) {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&sha256[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(out)
    }

    /// Seal an argument reference for one granted upload.
    ///
    /// Minted from the *claimed* `(size, sha256)` without seeing the bytes:
    /// storage enforces them on the PUT where it can, and the resolver
    /// verifies them on the GET. There is no expiry; on an unauthenticated
    /// server a reference is a bearer capability for as long as the object
    /// lives.
    ///
    /// # Errors
    ///
    /// On a size below 1, a digest that is not 64 lowercase hex characters,
    /// or an object id outside 1..=1024 bytes.
    pub fn mint_argument_ref(
        token_key: &[u8; 32],
        auth: &crate::auth::AuthContext,
        size: u64,
        sha256: &str,
        object_id: &str,
    ) -> Result<Vec<u8>> {
        if size < 1 {
            return Err(RpcError::value_error(format!(
                "argument ref size must be an integer >= 1, got {size}"
            )));
        }
        let digest = hex_to_digest(sha256).ok_or_else(|| {
            RpcError::value_error("argument ref sha256 must be 64 lowercase hex characters")
        })?;
        let id = object_id.as_bytes();
        if id.is_empty() || id.len() > MAX_OBJECT_ID_BYTES {
            return Err(RpcError::value_error(format!(
                "object_id must be 1-{MAX_OBJECT_ID_BYTES} bytes of UTF-8, got {}",
                id.len()
            )));
        }
        let mut plaintext = Vec::with_capacity(ARGREF_FIXED_LEN + id.len());
        plaintext.push(ARGREF_VERSION);
        plaintext.extend_from_slice(&size.to_le_bytes());
        plaintext.extend_from_slice(&digest);
        plaintext.extend_from_slice(&(id.len() as u16).to_le_bytes());
        plaintext.extend_from_slice(id);
        let sealed =
            crate::crypto::seal_bytes(&plaintext, token_key, &argument_ref_aad(auth), SEAL_VERSION);
        tracing::debug!(target: "vgi_rpc.state_ref", event = "arguments_ref.mint", size, "arguments_ref.mint");
        Ok(sealed)
    }

    /// Open an argument reference sealed for `auth`.
    ///
    /// # Errors
    ///
    /// `invalid_arguments_ref` for a wrong key, principal or scope,
    /// tampering, an unknown version, or a malformed layout.
    pub fn open_argument_ref(
        token_key: &[u8; 32],
        auth: &crate::auth::AuthContext,
        r: &[u8],
    ) -> Result<ArgumentRef> {
        let plaintext =
            crate::crypto::open_bytes(r, token_key, &argument_ref_aad(auth), SEAL_VERSION)
                .map_err(|_| {
                    invalid_arguments_ref(
                        "argument reference does not open (tampered, or granted to another \
                         principal or server)",
                    )
                })?;
        if plaintext.len() < ARGREF_FIXED_LEN || plaintext[0] != ARGREF_VERSION {
            return Err(invalid_arguments_ref(
                "argument reference has an unknown version or a malformed layout",
            ));
        }
        let size = u64::from_le_bytes(plaintext[1..9].try_into().expect("8 bytes"));
        let digest = &plaintext[9..9 + SHA256_LEN];
        let id_len = u16::from_le_bytes(
            plaintext[9 + SHA256_LEN..ARGREF_FIXED_LEN]
                .try_into()
                .expect("2 bytes"),
        ) as usize;
        if id_len == 0
            || id_len > MAX_OBJECT_ID_BYTES
            || ARGREF_FIXED_LEN + id_len != plaintext.len()
        {
            return Err(invalid_arguments_ref(
                "argument reference has a malformed layout",
            ));
        }
        let object_id = std::str::from_utf8(&plaintext[ARGREF_FIXED_LEN..])
            .map_err(|_| invalid_arguments_ref("argument reference has a malformed layout"))?
            .to_string();
        Ok(ArgumentRef {
            size,
            sha256: crate::wire::bytes_to_hex(digest),
            object_id,
        })
    }

    /// Open, fetch (through the object cache) and verify an argument
    /// reference.
    ///
    /// Order: validate the claimed location; open the ref with `ARGREF_AAD`;
    /// check the sealed size and SHA-256 equal the claimed ones; look the
    /// `object_id` up in the object cache; on a miss, single-flight
    /// `storage.get`; verify length and SHA-256; return.
    ///
    /// # Errors
    ///
    /// `invalid_arguments_ref` (malformed location, no storage, a ref that
    /// does not open for this caller, sealed values that differ from the
    /// claimed ones, an object over `max_fetch_bytes`),
    /// `arguments_ref_integrity` (fetched bytes differ), `arguments_ref_missing`
    /// (storage reports the object absent), `storage_unavailable` (transient).
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_argument_ref(
        r: &[u8],
        size: u64,
        sha256: &str,
        token_key: &[u8; 32],
        auth: &crate::auth::AuthContext,
        storage: Option<&dyn ObjectStore>,
        max_fetch_bytes: usize,
        cache: &ObjectCache,
    ) -> Result<Bytes> {
        if size < 1 {
            return Err(invalid_arguments_ref(format!(
                "argument location size must be an integer >= 1, got {size}"
            )));
        }
        let Some(expected_digest) = hex_to_digest(sha256) else {
            return Err(invalid_arguments_ref(
                "argument location sha256 must be 64 lowercase hex characters",
            ));
        };
        let Some(storage) = storage else {
            return Err(invalid_arguments_ref(
                "this server has no object storage configured to resolve argument references",
            ));
        };
        let opened = open_argument_ref(token_key, auth, r)?;
        if opened.size != size || opened.sha256 != sha256 {
            return Err(invalid_arguments_ref(
                "argument reference does not match the size and sha256 it was sent with",
            ));
        }
        if size > max_fetch_bytes as u64 {
            return Err(invalid_arguments_ref(format!(
                "argument object is {size} bytes, over this server's max_fetch_bytes ({max_fetch_bytes})"
            )));
        }
        let (value, hit) = cache.get_or_fetch(&opened.object_id, || {
            let data = fetch_object(storage, &opened.object_id, max_fetch_bytes, || {
                arguments_ref_missing("the uploaded argument object is gone (expired or deleted)")
            })?;
            if data.len() as u64 != size {
                return Err(arguments_ref_integrity(format!(
                    "argument object size mismatch: expected {size}, got {}",
                    data.len()
                )));
            }
            if sha2::Sha256::digest(&data)[..] != expected_digest[..] {
                return Err(arguments_ref_integrity("argument object sha256 mismatch"));
            }
            Ok(Bytes::from(data))
        })?;
        if value.len() as u64 != size {
            // A cached value always passed the checks above for this object
            // id; a length change means the id was reused, which storage
            // never does.
            return Err(arguments_ref_integrity(format!(
                "argument object size mismatch: expected {size}, got {}",
                value.len()
            )));
        }
        tracing::debug!(
            target: "vgi_rpc.state_ref",
            event = "arguments_ref.resolve",
            cache = if hit { "hit" } else { "miss" },
            bytes = value.len(),
            "arguments_ref.resolve"
        );
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_budget_formula() {
        assert_eq!(turn_budget(None, 100), None);
        assert_eq!(turn_budget(Some(0), 100), None);
        // floor((32768 - 4096) / 1.34) = 21397
        assert_eq!(turn_budget(Some(32_768), 0), Some(21_397));
        assert_eq!(turn_budget(Some(32_768), 397), Some(21_000));
        assert!(turn_budget(Some(1000), 0).unwrap() < 0);
    }

    #[test]
    fn inline_bytes_env_parsing() {
        assert_eq!(
            inline_bytes_from(None).unwrap(),
            DEFAULT_STATE_REF_INLINE_BYTES
        );
        assert_eq!(inline_bytes_from(Some(" 4096 ")).unwrap(), 4096);
        assert!(inline_bytes_from(Some("0")).is_err());
        assert!(inline_bytes_from(Some("-3")).is_err());
        assert!(inline_bytes_from(Some("big")).is_err());
    }

    #[test]
    fn cursor_rule_parses() {
        assert_eq!("warn".parse::<CursorRule>().unwrap(), CursorRule::Warn);
        assert_eq!("error".parse::<CursorRule>().unwrap(), CursorRule::Error);
        assert!("loud".parse::<CursorRule>().is_err());
    }

    #[test]
    fn misuse_outside_init_and_memo_inside() {
        let scope = StateRefScope::new("P", "m");
        let err = scope.state_ref(b"x").unwrap_err();
        assert_eq!(err.error_kind(), ERROR_KIND_STATE_REF_MISUSE);
        assert_eq!(err.error_code(), "FAILED_PRECONDITION");
        assert!(err.message.contains("(P.m)"));
        scope.set_init(true);
        let a = scope.state_ref(b"value").unwrap();
        let b = scope.state_ref(b"value").unwrap();
        assert!(Arc::ptr_eq(&a.0, &b.0), "byte-equal values share one ref");
        assert_eq!(a.form(), StateRefForm::Memory);
        scope.set_init(false);
        assert!(scope.state_ref(b"value").is_err());
    }

    #[test]
    fn in_memory_resolve_and_offline_inline_round_trip() {
        let scope = StateRefScope::new("P", "m");
        scope.set_init(true);
        let r = scope.state_ref(&vec![3u8; 10_000]).unwrap();
        let auth = crate::auth::AuthContext::anonymous();
        assert_eq!(scope.resolve(&r, &auth).unwrap().len(), 10_000);
        // Serialized outside a mint: inline, not cached on the ref.
        let bytes = r.to_bytes().unwrap();
        assert_eq!(bytes[0], FORM_INLINE);
        assert_eq!(r.form(), StateRefForm::Memory);
        let back = StateRef::from_encoded(bytes);
        assert_eq!(back.form(), StateRefForm::Inline);
        assert_eq!(scope.resolve(&back, &auth).unwrap(), vec![3u8; 10_000]);
        let bad = StateRef::from_encoded(&b"\x07abc"[..]);
        assert_eq!(
            scope.resolve(&bad, &auth).unwrap_err().error_kind(),
            ERROR_KIND_INVALID_STATE_REF
        );
    }

    #[cfg(feature = "stream-codec")]
    #[test]
    fn serde_round_trip_keeps_encoded_bytes() {
        let r = StateRef::from_encoded(&b"\x01\x00hello"[..]);
        let bytes = crate::stream_codec::bincode_encode(&r).unwrap();
        let back: StateRef = crate::stream_codec::bincode_decode(&bytes).unwrap();
        assert_eq!(back.encoded().unwrap(), &b"\x01\x00hello"[..]);
        assert_eq!(back, r);
    }

    #[cfg(feature = "http")]
    mod http {
        use super::super::*;
        use crate::external::{ExternalStorage, InMemoryStorage};
        use crate::object_cache::ObjectCache;
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        const KEY: [u8; 32] = [9u8; 32];
        const CALL: [u8; 16] = [4u8; 16];

        fn runtime(storage: &Arc<InMemoryStorage>, clock: Arc<AtomicU64>) -> Arc<StateRefRuntime> {
            let s: Arc<dyn ExternalStorage> = storage.clone();
            Arc::new(
                StateRefRuntime::new(KEY, 1 << 20)
                    .with_storage(Some(s))
                    .with_cache(Arc::new(ObjectCache::new(1 << 20)))
                    .with_token_ttl(60)
                    .with_clock(Arc::new(move || clock.load(AtomicOrdering::SeqCst))),
            )
        }

        fn incompressible(n: usize) -> Vec<u8> {
            use sha2::Digest as _;
            (0..n.div_ceil(32))
                .flat_map(|i: usize| sha2::Sha256::digest(i.to_le_bytes()).to_vec())
                .take(n)
                .collect()
        }

        fn encode_in_mint(
            rt: &Arc<StateRefRuntime>,
            auth: &crate::auth::AuthContext,
            r: &StateRef,
        ) -> Bytes {
            let enc = encoder::Encoder::new(rt, auth, "P", "m", &CALL, 0);
            let (out, err) = encoder::encoding(enc, || r.to_bytes());
            assert!(err.is_none());
            out.unwrap()
        }

        #[test]
        fn stored_ref_reserializes_identically_without_a_second_put() {
            let storage = InMemoryStorage::new();
            let rt = runtime(&storage, Arc::new(AtomicU64::new(1000)));
            let auth = crate::auth::AuthContext::anonymous();
            let r = StateRef::from_value(incompressible(65_536).into());
            let first = encode_in_mint(&rt, &auth, &r);
            assert_eq!(r.form(), StateRefForm::Stored);
            let second = encode_in_mint(&rt, &auth, &r);
            assert_eq!(first, second);
            assert_eq!(storage.object_calls(), (1, 0));
            // Resolve: one GET, then the cache.
            let back = StateRef::from_encoded(first.clone());
            let base = base_aad(&auth, "P");
            for _ in 0..3 {
                let v = resolve_encoded(&first, Some(&rt), Some(&base), Some(&CALL)).unwrap();
                assert_eq!(v.len(), 65_536);
            }
            assert_eq!(storage.object_calls(), (1, 1));
            // Another stream's call id, another principal: refused.
            let other = resolve_encoded(
                &back.to_bytes().unwrap(),
                Some(&rt),
                Some(&base),
                Some(&[5u8; 16]),
            );
            assert_eq!(
                other.unwrap_err().error_kind(),
                ERROR_KIND_INVALID_STATE_REF
            );
            let bob = base_aad(&crate::auth::AuthContext::for_principal("d", "bob"), "P");
            let other = resolve_encoded(&first, Some(&rt), Some(&bob), Some(&CALL));
            assert_eq!(
                other.unwrap_err().error_kind(),
                ERROR_KIND_INVALID_STATE_REF
            );
        }

        #[test]
        fn small_value_stays_inline_and_codec_tags_the_payload() {
            let storage = InMemoryStorage::new();
            let rt = runtime(&storage, Arc::new(AtomicU64::new(1000)));
            let auth = crate::auth::AuthContext::anonymous();
            let big = StateRef::from_value(Bytes::from(b"abc ".repeat(2000)));
            let enc = encode_in_mint(&rt, &auth, &big);
            assert_eq!(&enc[..2], &[FORM_INLINE, crate::token_codec::CODEC_ZSTD]);
            let tiny = StateRef::from_value(Bytes::from_static(b"xyz"));
            assert_eq!(&encode_in_mint(&rt, &auth, &tiny)[..], b"\x01\x00xyz");
            assert_eq!(storage.object_calls(), (0, 0));
        }

        #[test]
        fn expired_tag_is_refused_before_any_get() {
            let storage = InMemoryStorage::new();
            let clock = Arc::new(AtomicU64::new(1000));
            let rt = runtime(&storage, clock.clone());
            let auth = crate::auth::AuthContext::anonymous();
            let r = StateRef::from_value(incompressible(65_536).into());
            let enc = encode_in_mint(&rt, &auth, &r);
            clock.store(1000 + 61, AtomicOrdering::SeqCst);
            let base = base_aad(&auth, "P");
            let err = resolve_encoded(&enc, Some(&rt), Some(&base), Some(&CALL)).unwrap_err();
            assert_eq!(err.error_kind(), ERROR_KIND_INVALID_STATE_REF);
            assert!(err.message.contains("expired"));
            assert_eq!(storage.object_calls().1, 0, "an expired tag must not fetch");
        }

        #[test]
        fn store_over_max_fetch_bytes_is_too_large() {
            let storage = InMemoryStorage::new();
            let s: Arc<dyn ExternalStorage> = storage.clone();
            let rt = Arc::new(StateRefRuntime::new(KEY, 1024).with_storage(Some(s)));
            let auth = crate::auth::AuthContext::anonymous();
            let r = StateRef::from_value(incompressible(65_536).into());
            let enc = encoder::Encoder::new(&rt, &auth, "P", "m", &CALL, 0);
            let (out, err) = encoder::encoding(enc, || r.to_bytes());
            assert!(out.is_err());
            assert_eq!(err.unwrap().error_kind(), ERROR_KIND_STATE_REF_TOO_LARGE);
        }

        #[test]
        fn argument_ref_round_trip_and_binding() {
            use crate::external::ObjectStore;
            let storage = InMemoryStorage::new();
            let cache = ObjectCache::new(1 << 20);
            let data = b"an argument".to_vec();
            let id = storage.put_object(&data).unwrap();
            let sha = crate::wire::bytes_to_hex(&{
                use sha2::Digest as _;
                sha2::Sha256::digest(&data)
            });
            let alice = crate::auth::AuthContext::for_principal("d", "alice");
            let r = mint_argument_ref(&KEY, &alice, data.len() as u64, &sha, &id).unwrap();
            let store: &dyn ObjectStore = storage.as_ref();
            let got = resolve_argument_ref(
                &r,
                data.len() as u64,
                &sha,
                &KEY,
                &alice,
                Some(store),
                1 << 20,
                &cache,
            )
            .unwrap();
            assert_eq!(&got[..], &data[..]);
            let bob = crate::auth::AuthContext::for_principal("d", "bob");
            let err = resolve_argument_ref(
                &r,
                data.len() as u64,
                &sha,
                &KEY,
                &bob,
                Some(store),
                1 << 20,
                &cache,
            )
            .unwrap_err();
            assert_eq!(err.error_kind(), ERROR_KIND_INVALID_ARGUMENTS_REF);
            let err =
                resolve_argument_ref(&r, 99, &sha, &KEY, &alice, Some(store), 1 << 20, &cache)
                    .unwrap_err();
            assert_eq!(err.error_kind(), ERROR_KIND_INVALID_ARGUMENTS_REF);
            // Peer-evidence binding is part of the AAD: refs do not cross bindings.
            let mut bound = alice.clone();
            bound
                .claims
                .insert("peer_evidence_binding".into(), "b1".into());
            assert_ne!(argument_ref_aad(&alice), argument_ref_aad(&bound));
            assert!(open_argument_ref(&KEY, &bound, &r).is_err());
            // Missing object.
            let gone = storage.put_object(b"gone").unwrap();
            let gsha = crate::wire::bytes_to_hex(&{
                use sha2::Digest as _;
                sha2::Sha256::digest(b"gone")
            });
            let gr = mint_argument_ref(&KEY, &alice, 4, &gsha, &gone).unwrap();
            assert!(storage.delete_object(&gone));
            let err =
                resolve_argument_ref(&gr, 4, &gsha, &KEY, &alice, Some(store), 1 << 20, &cache)
                    .unwrap_err();
            assert_eq!(err.error_kind(), ERROR_KIND_ARGUMENTS_REF_MISSING);
        }

        #[test]
        fn cursor_rule_warns_errors_and_floors() {
            let warn = StateRefRuntime::new(KEY, 1 << 20).with_max_request_bytes(Some(32_768));
            assert!(warn.check_cursor(100, 0, "P", "m").unwrap().is_none());
            assert!(warn
                .check_cursor(30_000, 0, "P", "m")
                .unwrap()
                .unwrap()
                .starts_with("cursor_large:"));
            let error = StateRefRuntime::new(KEY, 1 << 20)
                .with_max_request_bytes(Some(32_768))
                .with_cursor_rule(CursorRule::Error);
            let err = error.check_cursor(30_000, 0, "P", "m").unwrap_err();
            assert_eq!(err.error_kind(), ERROR_KIND_CURSOR_TOO_LARGE);
            assert!(err.message.contains("ctx.state_ref()"));
            let floor = StateRefRuntime::new(KEY, 1 << 20)
                .with_max_request_bytes(Some(9000))
                .with_cursor_rule(CursorRule::Error);
            assert!(!floor.cursor_rule_enabled());
            assert!(floor.check_cursor(1 << 20, 0, "P", "m").unwrap().is_none());
            // Still computed by the formula below the floor: floor(3659 / 4).
            assert_eq!(floor.inline_bytes(0), 914);
            let unbounded = StateRefRuntime::new(KEY, 1 << 20).with_cursor_rule(CursorRule::Error);
            assert!(unbounded
                .check_cursor(1 << 30, 0, "P", "m")
                .unwrap()
                .is_none());
            assert_eq!(unbounded.inline_bytes(0), DEFAULT_STATE_REF_INLINE_BYTES);
        }
    }
}
