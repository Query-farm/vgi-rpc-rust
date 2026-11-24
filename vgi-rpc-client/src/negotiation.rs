//! Client-side protocol version negotiation (`PROTOCOL_VERSIONS_V1.md` §6).
//!
//! One [`Negotiation`] per endpoint (an HTTP client, a pipe connection):
//! the windows learned from the server, and the version chosen per protocol.
//!
//! - Before anything is learned, the client speaks its newest version.
//! - A server window learned from `VGI-Protocol-Versions` (every HTTP
//!   response), from `vgi_rpc.protocol_versions` (reflection results,
//!   refusals) or from a refusal's `ErrorInfo` picks the highest common
//!   `major.minor`; the client's own patch is kept (`3.5.2` → `3.4.2`).
//! - A pre-negotiation refusal (`protocol_version_mismatch`, no windows)
//!   names one server version (`Server: X.Y.Z` / `server requires X.Y.Z`),
//!   which is then spoken.
//! - With no window and no legacy version, the client keeps its own newest.
//! - Once a server window is known to be disjoint from the client's, calls
//!   fail before sending, naming both windows.

use std::collections::BTreeMap;

use vgi_rpc::protocol_versions::{
    legacy_server_version, parse_major_minor, parse_versions, MajorMinor, VersionRange,
    PROTOCOL_VERSIONS_KEY, PROTOCOL_VERSION_MISMATCH_LEGACY, PROTOCOL_VERSION_UNSUPPORTED,
};
use vgi_rpc::{Code, RpcError};

/// What a client bound to one protocol speaks.
#[derive(Debug, Clone)]
pub struct Negotiation {
    protocol: String,
    newest: MajorMinor,
    patch: u64,
    window: VersionRange,
    server: Option<BTreeMap<String, VersionRange>>,
    legacy: Option<MajorMinor>,
}

impl Negotiation {
    /// A client of `protocol` whose newest version is `version` (semver) and
    /// which supports `window` (`MIN-MAX`, default exactly `version`).
    /// `None` when `version` is not semver.
    pub fn new(protocol: &str, version: &str, window: Option<&str>) -> Option<Self> {
        let newest = parse_major_minor(version)?;
        let patch = version
            .split('.')
            .nth(2)
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let window = match window {
            Some(w) => VersionRange::parse(w)?,
            None => VersionRange {
                min: newest,
                max: newest,
            },
        };
        Some(Negotiation {
            protocol: protocol.to_string(),
            newest,
            patch,
            window,
            server: None,
            legacy: None,
        })
    }

    /// The client's window, as the §4.2 value `protocol=MIN-MAX`.
    pub fn client_versions(&self) -> String {
        format!("{}={}", self.protocol, self.window)
    }

    /// Whether the client's window holds more than one version (a byte-stream
    /// client then probes reflection before its first call).
    pub fn is_wide(&self) -> bool {
        self.window.min != self.window.max
    }

    /// Whether the server's windows have been learned.
    pub fn learned(&self) -> bool {
        self.server.is_some()
    }

    /// The server's window for this protocol, when advertised.
    pub fn server_window(&self) -> Option<VersionRange> {
        self.server.as_ref()?.get(&self.protocol).copied()
    }

    /// The version to send: chosen `major.minor` plus the client's patch.
    ///
    /// # Errors
    ///
    /// `protocol_version_unsupported` when the server's window is known and
    /// shares no version with the client's.
    pub fn version_to_send(&self) -> Result<String, RpcError> {
        let mm = match self.server_window() {
            Some(server) => self
                .window
                .highest_common(&server)
                .ok_or_else(|| self.no_common_version(server))?,
            None => self.legacy.unwrap_or(self.newest),
        };
        Ok(format!("{}.{}.{}", mm.0, mm.1, self.patch))
    }

    fn no_common_version(&self, server: VersionRange) -> RpcError {
        let p = &self.protocol;
        let direction = if self.window.max < server.min {
            "The client is too old (the server is too new for it). Upgrade the client."
        } else {
            "The server is too old (the client is too new for it). Upgrade the worker."
        };
        RpcError::new(
            "ProtocolVersionError",
            format!(
                "{PROTOCOL_VERSION_UNSUPPORTED}: no common version of {p}: this client supports {p} {}, \
                 the server supports {p} {server}. {direction}",
                self.window
            ),
        )
        .with_status(Code::FailedPrecondition, PROTOCOL_VERSION_UNSUPPORTED)
    }

    /// Learn from a `VGI-Protocol-Versions` / `vgi_rpc.protocol_versions`
    /// value. A present value replaces what was cached (a redeploy behind one
    /// URL); an empty one says the server gates nothing here.
    pub fn learn_advertisement(&mut self, value: &str) {
        self.server = Some(parse_versions(value));
    }

    /// Learn from a refusal: its `ErrorInfo` windows, else a legacy refusal's
    /// single server version. Returns whether it was a version refusal.
    pub fn learn_refusal(&mut self, err: &RpcError) -> bool {
        let kind = err.error_kind.as_deref().unwrap_or("");
        if kind != PROTOCOL_VERSION_UNSUPPORTED && kind != PROTOCOL_VERSION_MISMATCH_LEGACY {
            return false;
        }
        if let Some(v) = err
            .error_info()
            .and_then(|m| m.get(PROTOCOL_VERSIONS_KEY).cloned())
        {
            self.learn_advertisement(&v);
            return true;
        }
        if self.server_window().is_none() {
            let details = serde_json::to_string(err.error_details()).unwrap_or_default();
            if let Some(v) =
                legacy_server_version(&err.message).or_else(|| legacy_server_version(&details))
            {
                self.legacy = Some(v);
            }
        }
        true
    }

    /// The protocol this client is bound to.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }
}

/// Whether a call may be retried once after a version refusal (§6, Decision
/// 9): reflection only, until methods can declare idempotency here.
pub fn is_retry_safe(protocol: &str) -> bool {
    protocol == "vgi_rpc.Reflection.v1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_versions() {
        let mut n = Negotiation::new("p", "3.5.2", Some("3.4-3.5")).unwrap();
        assert_eq!(n.version_to_send().unwrap(), "3.5.2");
        assert_eq!(n.client_versions(), "p=3.4-3.5");
        n.learn_advertisement("p=3.4-3.4, q=1.0-1.0");
        assert_eq!(n.version_to_send().unwrap(), "3.4.2");
        n.learn_advertisement("p=3.6-3.7");
        let err = n.version_to_send().unwrap_err();
        assert_eq!(
            err.error_kind.as_deref(),
            Some(PROTOCOL_VERSION_UNSUPPORTED)
        );
        assert!(err.message.contains("3.4-3.5") && err.message.contains("3.6-3.7"));
        assert!(err.message.contains("too old"));
        // An advertisement that omits the protocol: fall back to own newest.
        n.learn_advertisement("");
        assert_eq!(n.version_to_send().unwrap(), "3.5.2");
    }

    #[test]
    fn legacy_refusal_names_the_version() {
        let mut n = Negotiation::new("p", "3.5.2", Some("3.4-3.5")).unwrap();
        let err = RpcError::new(
            "VersionError",
            "mismatch\n  Client: 3.5.2\n  Server: 3.4.0\n",
        )
        .with_status(Code::FailedPrecondition, PROTOCOL_VERSION_MISMATCH_LEGACY);
        assert!(n.learn_refusal(&err));
        assert_eq!(n.version_to_send().unwrap(), "3.4.2");
        assert!(!n.learn_refusal(&RpcError::new("ValueError", "x")));
    }
}
