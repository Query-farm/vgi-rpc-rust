//! Error types used throughout the vgi-rpc framework.

use std::fmt;

pub use crate::error_model::{Code, ErrorDetail};

/// An RPC-level error, serialized on the wire as an EXCEPTION log batch.
#[derive(Debug, Clone)]
pub struct RpcError {
    /// Error category (matches Python exception class names: "ValueError",
    /// "RuntimeError", "TypeError", "ProtocolError", "VersionError", ...).
    pub error_type: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional stack trace or remote traceback string.
    ///
    /// A `Box<str>` rather than a `String`: this is written once and never
    /// grown, and `RpcError` is returned by value from every `Result` in the
    /// framework, so eight bytes of unused capacity ride along on every call
    /// that can fail. Keeping the whole error under clippy's
    /// `result_large_err` threshold is the point -- an error type that is
    /// expensive to return gets returned less carefully.
    pub traceback: Box<str>,
    /// Optional request ID attached when the error was produced.
    ///
    /// `Box<str>` for the same reason as [`Self::traceback`]: written once,
    /// never grown, and carried by value on every fallible return.
    pub request_id: Box<str>,
    /// Machine-readable reason when this error is an authentication
    /// rejection. `None` means unclassified, which renders as
    /// [`crate::unauthorized::AuthReason::Unauthorized`] — guessing a finer
    /// code from an unclassified failure would mean matching on message
    /// text.
    pub auth_reason: Option<crate::unauthorized::AuthReason>,
    /// `Retry-After` hint, in seconds, carried by a *transient* failure —
    /// see [`RpcError::auth_unavailable`]. `None` on every other error.
    pub retry_after_seconds: Option<u32>,
    /// Stable, machine-readable classification, surfaced on the wire as
    /// `vgi_rpc.error_kind` (see [`crate::metadata::ERROR_KIND_KEY`]).
    ///
    /// An open enum, and deliberately separate from [`Self::error_type`]:
    /// `error_type` names the *language* exception a port happened to raise,
    /// which differs across ports, while `error_kind` is the contract. It
    /// exists because some errors used to be distinguishable only by HTTP
    /// status — `vgi_rpc.Identity.v1` was an HTTP route whose callers read
    /// definitive-vs-transient off `404` versus `503`. As protocol methods
    /// every handler failure surfaces the same way, so without this a caller
    /// would have to substring-match a message to know whether retrying is
    /// correct or abusive.
    pub error_kind: Option<Box<str>>,
    /// The canonical code and typed details (WIRE_PROTOCOL.md §8), boxed so
    /// an error that carries neither -- most of them -- pays one pointer.
    /// Read through [`Self::error_code`] / [`Self::error_details`]; set
    /// through [`Self::with_code`] / [`Self::with_details`].
    status: Option<Box<ErrorStatus>>,
}

/// The code and details layers of an [`RpcError`].
#[derive(Debug, Clone, Default)]
struct ErrorStatus {
    /// The code's wire name. Kept as a string, not a [`Code`], so a client
    /// reports what the server sent verbatim -- `""` (absent) and an
    /// unrecognised value are different answers from `"UNKNOWN"`.
    code: String,
    /// The detail objects in wire order, unknown types included.
    details: Vec<serde_json::Value>,
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

/// `RetryInfo` a draining server attaches to `server_draining`.
pub const DEFAULT_DRAINING_RETRY_AFTER_SECONDS: f64 = 1.0;

/// Framework error kinds (WIRE_PROTOCOL.md §8), each with its fixed code.
pub const ERROR_KIND_METHOD_NOT_IMPLEMENTED: &str = "method_not_implemented";
/// `protocol_not_specified` -> `INVALID_ARGUMENT`.
pub const ERROR_KIND_PROTOCOL_NOT_SPECIFIED: &str = "protocol_not_specified";
/// `protocol_not_supported` -> `UNIMPLEMENTED`.
pub const ERROR_KIND_PROTOCOL_NOT_SUPPORTED: &str = "protocol_not_supported";
/// `protocol_version_mismatch` -> `FAILED_PRECONDITION`.
pub const ERROR_KIND_PROTOCOL_VERSION_MISMATCH: &str = "protocol_version_mismatch";
/// `session_lost` -> `ABORTED`.
pub const ERROR_KIND_SESSION_LOST: &str = "session_lost";
/// `server_draining` -> `UNAVAILABLE` + `RetryInfo`.
pub const ERROR_KIND_SERVER_DRAINING: &str = "server_draining";

impl RpcError {
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_type: error_type.into(),
            message: message.into(),
            traceback: String::new().into_boxed_str(),
            request_id: String::new().into_boxed_str(),
            auth_reason: None,
            retry_after_seconds: None,
            error_kind: None,
            status: None,
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
        let mut err = Self::new(AUTH_UNAVAILABLE_ERROR_TYPE, detail).with_code(Code::Unavailable);
        err.retry_after_seconds = Some(DEFAULT_AUTH_RETRY_AFTER_SECONDS);
        err
    }

    /// Override the `Retry-After` hint on a transient failure.
    pub fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    /// Attach the stable machine-readable [`Self::error_kind`].
    pub fn with_error_kind(mut self, kind: impl Into<String>) -> Self {
        self.error_kind = Some(kind.into().into_boxed_str());
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
        Self::new("SessionLostError", msg).with_status(Code::Aborted, ERROR_KIND_SESSION_LOST)
    }

    /// Server is draining: new `ctx.open_session` calls are rejected while
    /// existing sessions continue to serve. Mirrors Python's
    /// `vgi_rpc.rpc.ServerDrainingError`.
    ///
    /// Carries `RetryInfo` of [`DEFAULT_DRAINING_RETRY_AFTER_SECONDS`]: a
    /// retry is usually routed to a worker that is not draining.
    pub fn server_draining_error(msg: impl Into<String>) -> Self {
        Self::new("ServerDrainingError", msg)
            .with_status(Code::Unavailable, ERROR_KIND_SERVER_DRAINING)
            .with_details([ErrorDetail::retry_info(
                DEFAULT_DRAINING_RETRY_AFTER_SECONDS,
            )])
    }

    /// The protocol the request addresses is hosted, but has no such method.
    /// Kind `method_not_implemented`, code `UNIMPLEMENTED`: the capability
    /// probe signal, distinct from "this server does not host that protocol".
    pub fn method_not_implemented(msg: impl Into<String>) -> Self {
        Self::attribute_error(msg)
            .with_status(Code::Unimplemented, ERROR_KIND_METHOD_NOT_IMPLEMENTED)
    }

    /// The client's `vgi_rpc.protocol_version` is absent, malformed or
    /// incompatible with the resolved binding's. Kind
    /// `protocol_version_mismatch`, code `FAILED_PRECONDITION`, and one
    /// `PreconditionFailure` violation naming `protocol`. `client_version` is
    /// `""` when the client sent none; `direction` says which side to upgrade.
    pub fn protocol_version_mismatch(
        protocol: &str,
        client_version: &str,
        server_version: &str,
        direction: &str,
    ) -> Self {
        let client = if client_version.is_empty() {
            "<not declared>"
        } else {
            client_version
        };
        Self::version_error(format!(
            "protocol_version mismatch for protocol {protocol:?}.\n  Client: {client}\n  \
             Server: {server_version}\n  Direction: {direction}"
        ))
        .with_status(
            Code::FailedPrecondition,
            ERROR_KIND_PROTOCOL_VERSION_MISMATCH,
        )
        .with_details([ErrorDetail::PreconditionFailure {
            violations: vec![crate::error_model::PreconditionViolation {
                r#type: "protocol_version".into(),
                subject: protocol.into(),
                description: format!(
                    "client declares {client}, server requires {server_version}; \
                     major and minor must match"
                ),
            }],
        }])
    }

    // --- The error model (WIRE_PROTOCOL.md §8) --------------------------

    /// Set the canonical code.
    pub fn with_code(mut self, code: Code) -> Self {
        self.status.get_or_insert_with(Default::default).code = code.as_str().to_string();
        self
    }

    /// Set the code and the kind together -- the pair a kind is defined with.
    pub fn with_status(self, code: Code, kind: impl Into<String>) -> Self {
        self.with_code(code).with_error_kind(kind)
    }

    /// Append catalog details. Each type at most once; a list breaking the
    /// rules, or over [`MAX_ERROR_DETAILS_BYTES`](crate::error_model::MAX_ERROR_DETAILS_BYTES)
    /// serialized, is dropped whole on the wire.
    pub fn with_details(self, details: impl IntoIterator<Item = ErrorDetail>) -> Self {
        self.with_raw_details(details.into_iter().map(|d| d.to_json()))
    }

    /// Append already-built detail objects -- the way a protocol-defined type
    /// (under the protocol's own name) is attached.
    pub fn with_raw_details(
        mut self,
        details: impl IntoIterator<Item = serde_json::Value>,
    ) -> Self {
        self.status
            .get_or_insert_with(Default::default)
            .details
            .extend(details);
        self
    }

    /// Install a decoded wire status verbatim. Used by clients.
    pub fn set_wire_status(&mut self, code: &str, details: Vec<serde_json::Value>) {
        if code.is_empty() && details.is_empty() {
            self.status = None;
        } else {
            self.status = Some(Box::new(ErrorStatus {
                code: code.to_string(),
                details,
            }));
        }
    }

    /// The `vgi_rpc.error_code` value: the code's name, or `""` when none was
    /// set (on a client: when the server sent none, i.e. predates the model).
    pub fn error_code(&self) -> &str {
        self.status.as_ref().map_or("", |s| s.code.as_str())
    }

    /// The canonical code; [`Code::Unknown`] when absent or unrecognised.
    pub fn code(&self) -> Code {
        Code::parse(self.error_code())
    }

    /// The `vgi_rpc.error_kind` value, or `""`.
    pub fn error_kind(&self) -> &str {
        self.error_kind.as_deref().unwrap_or("")
    }

    /// The detail objects as received (or as attached), unknown types
    /// included, in order.
    pub fn error_details(&self) -> &[serde_json::Value] {
        self.status.as_ref().map_or(&[], |s| s.details.as_slice())
    }

    /// The catalog details this crate understands, in order; unknown or
    /// malformed ones skipped.
    pub fn details(&self) -> Vec<ErrorDetail> {
        self.error_details()
            .iter()
            .filter_map(ErrorDetail::from_json)
            .collect()
    }

    fn detail_of(&self, ty: &str) -> Option<ErrorDetail> {
        self.details().into_iter().find(|d| d.type_name() == ty)
    }

    /// The `vgi_rpc.ErrorInfo` metadata, if present.
    pub fn error_info(&self) -> Option<std::collections::BTreeMap<String, String>> {
        match self.detail_of(crate::error_model::ERROR_INFO_TYPE)? {
            ErrorDetail::ErrorInfo { metadata } => Some(metadata),
            _ => None,
        }
    }

    /// The `vgi_rpc.RetryInfo` delay in seconds, if present.
    pub fn retry_info(&self) -> Option<f64> {
        match self.detail_of(crate::error_model::RETRY_INFO_TYPE)? {
            ErrorDetail::RetryInfo {
                retry_delay_seconds,
            } => Some(retry_delay_seconds),
            _ => None,
        }
    }

    /// The `vgi_rpc.BadRequest` detail, if present.
    pub fn bad_request(&self) -> Option<ErrorDetail> {
        self.detail_of(crate::error_model::BAD_REQUEST_TYPE)
    }

    /// The `vgi_rpc.PreconditionFailure` detail, if present.
    pub fn precondition_failure(&self) -> Option<ErrorDetail> {
        self.detail_of(crate::error_model::PRECONDITION_FAILURE_TYPE)
    }

    /// The `vgi_rpc.QuotaFailure` detail, if present.
    pub fn quota_failure(&self) -> Option<ErrorDetail> {
        self.detail_of(crate::error_model::QUOTA_FAILURE_TYPE)
    }

    /// The `vgi_rpc.ResourceInfo` detail, if present.
    pub fn resource_info(&self) -> Option<ErrorDetail> {
        self.detail_of(crate::error_model::RESOURCE_INFO_TYPE)
    }

    /// The `vgi_rpc.Help` detail, if present.
    pub fn help(&self) -> Option<ErrorDetail> {
        self.detail_of(crate::error_model::HELP_TYPE)
    }

    /// The `vgi_rpc.LocalizedMessage` detail, if present.
    pub fn localized_message(&self) -> Option<ErrorDetail> {
        self.detail_of(crate::error_model::LOCALIZED_MESSAGE_TYPE)
    }

    /// Whether retrying *this call* is warranted, by WIRE_PROTOCOL.md §8:
    /// `UNAVAILABLE` always, `RESOURCE_EXHAUSTED` only with `RetryInfo`.
    /// When [`Self::retry_info`] is present a retry waits at least that long.
    ///
    /// A classification, not a policy: no client in this crate retries an RPC
    /// error automatically, because a method may not be idempotent.
    pub fn is_retryable(&self) -> bool {
        crate::error_model::is_retryable(self.error_code(), self.error_details())
    }

    /// The code a server emits: the one set, else `UNKNOWN`.
    pub(crate) fn wire_code(&self) -> &str {
        match self.error_code() {
            "" => Code::Unknown.as_str(),
            code => code,
        }
    }

    /// The details a server emits: those attached, plus a `RetryInfo` built
    /// from [`Self::retry_after_seconds`] when the error carries a hint and no
    /// `RetryInfo` of its own -- which is how a transient auth failure's
    /// `Retry-After` reaches every transport, not only the HTTP header.
    pub(crate) fn wire_details(&self) -> Vec<serde_json::Value> {
        let mut details = self.error_details().to_vec();
        if let Some(seconds) = self.retry_after_seconds {
            let has_retry = details.iter().any(|d| {
                d.get("@type").and_then(serde_json::Value::as_str)
                    == Some(crate::error_model::RETRY_INFO_TYPE)
            });
            if !has_retry {
                details.push(ErrorDetail::retry_info(f64::from(seconds)).to_json());
            }
        }
        details
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
