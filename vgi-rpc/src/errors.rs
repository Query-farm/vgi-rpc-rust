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
}

impl RpcError {
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_type: error_type.into(),
            message: message.into(),
            traceback: String::new(),
            request_id: String::new(),
        }
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
