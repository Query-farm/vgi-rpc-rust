//! Error types used throughout the vgi-rpc framework.

use std::fmt;

/// An RPC-level error, serialized on the wire as an EXCEPTION log batch.
#[derive(Debug, Clone)]
pub struct RpcError {
    /// Error category (matches Python exception class names: "ValueError",
    /// "RuntimeError", "TypeError", "ProtocolError", "VersionError", ...).
    pub error_type: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional stack trace or remote traceback string.
    pub traceback: String,
    /// Optional request ID attached when the error was produced.
    pub request_id: String,
    /// Machine-readable reason when this error is an authentication
    /// rejection. `None` means unclassified, which renders as
    /// [`crate::unauthorized::AuthReason::Unauthorized`] — guessing a finer
    /// code from an unclassified failure would mean matching on message
    /// text.
    pub auth_reason: Option<crate::unauthorized::AuthReason>,
    /// `Retry-After` hint, in seconds, carried by a *transient* failure —
    /// see [`RpcError::auth_unavailable`]. `None` on every other error.
    pub retry_after_seconds: Option<u32>,
}

/// [`RpcError::error_type`] marking "I could not determine whether the
/// credential is good", as distinct from "the credential is bad".
///
/// Mirrors the reference implementation's `AuthUnavailableError`, whose whole
/// point is that it is *not* the rejection type: a chain that reads an outage
/// as "not my credential, try the next" emerges as a 401 from the end of the
/// chain, and a caller that negative-caches rejections then caches an outage.
pub const AUTH_UNAVAILABLE_ERROR_TYPE: &str = "AuthUnavailableError";

/// Default `Retry-After` for a transient authentication failure. Short on
/// purpose: it is a hint to retry, not a backoff schedule.
pub const DEFAULT_AUTH_RETRY_AFTER_SECONDS: u32 = 5;

impl RpcError {
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_type: error_type.into(),
            message: message.into(),
            traceback: String::new(),
            request_id: String::new(),
            auth_reason: None,
            retry_after_seconds: None,
        }
    }

    /// An authenticator could not answer. **Not** a rejection.
    ///
    /// "The credential is bad" and "I could not find out whether the
    /// credential is bad" are different answers, and collapsing them is
    /// expensive in both directions. A sidecar restart surfacing as 401 makes
    /// every caller re-authenticate at once; a caller that negative-caches
    /// rejections will cache the outage and stay down after the sidecar comes
    /// back.
    ///
    /// [`crate::auth::chain_authenticate`] propagates it — every `Err` from an
    /// authenticator short-circuits the chain, so unlike the Python reference
    /// there is no exception hierarchy to get wrong here; what the distinct
    /// `error_type` buys is the HTTP mapping, which renders `503` +
    /// `Retry-After` instead of `401`.
    ///
    /// Raise it for transport failures, timeouts, and 5xx from a remote
    /// authority. Never for a credential the authority answered about.
    pub fn auth_unavailable(detail: impl Into<String>) -> Self {
        let mut err = Self::new(AUTH_UNAVAILABLE_ERROR_TYPE, detail);
        err.retry_after_seconds = Some(DEFAULT_AUTH_RETRY_AFTER_SECONDS);
        err
    }

    /// Override the `Retry-After` hint on a transient failure.
    pub fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    /// Whether this is the transient "could not determine" signal rather than
    /// a rejection.
    pub fn is_auth_unavailable(&self) -> bool {
        self.error_type == AUTH_UNAVAILABLE_ERROR_TYPE
    }

    /// Classify this error as an authentication rejection with `reason`.
    ///
    /// Returned from an authenticate callback, this is what lets the 401
    /// carry a code a client can branch on rather than the
    /// [`crate::unauthorized::AuthReason::Unauthorized`] fallback.
    pub fn auth_failure(
        reason: crate::unauthorized::AuthReason,
        detail: impl Into<String>,
    ) -> Self {
        let mut err = Self::new("PermissionError", detail);
        err.auth_reason = Some(reason);
        err
    }

    pub fn value_error(msg: impl Into<String>) -> Self {
        Self::new("ValueError", msg)
    }

    pub fn runtime_error(msg: impl Into<String>) -> Self {
        Self::new("RuntimeError", msg)
    }

    pub fn type_error(msg: impl Into<String>) -> Self {
        Self::new("TypeError", msg)
    }

    pub fn protocol_error(msg: impl Into<String>) -> Self {
        Self::new("ProtocolError", msg)
    }

    pub fn version_error(msg: impl Into<String>) -> Self {
        Self::new("VersionError", msg)
    }

    pub fn permission_error(msg: impl Into<String>) -> Self {
        Self::new("PermissionError", msg)
    }

    pub fn attribute_error(msg: impl Into<String>) -> Self {
        Self::new("AttributeError", msg)
    }

    /// Sticky-session token did not resolve to a live registry entry
    /// (missing, expired, evicted, wrong worker, or principal mismatch).
    /// Mirrors Python's `vgi_rpc.rpc.SessionLostError`.
    pub fn session_lost_error(msg: impl Into<String>) -> Self {
        Self::new("SessionLostError", msg)
    }

    /// Server is draining: new `ctx.open_session` calls are rejected while
    /// existing sessions continue to serve. Mirrors Python's
    /// `vgi_rpc.rpc.ServerDrainingError`.
    pub fn server_draining_error(msg: impl Into<String>) -> Self {
        Self::new("ServerDrainingError", msg)
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_type, self.message)
    }
}

impl std::error::Error for RpcError {}

/// Convenience alias for `Result<T, RpcError>`.
pub type Result<T> = std::result::Result<T, RpcError>;

impl From<arrow_schema::ArrowError> for RpcError {
    fn from(e: arrow_schema::ArrowError) -> Self {
        RpcError::new("ArrowError", e.to_string())
    }
}

impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> Self {
        RpcError::new("IOError", e.to_string())
    }
}
