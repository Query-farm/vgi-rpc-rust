//! The standardized 401, per `docs/unauthorized-spec.md` in the reference
//! repo.
//!
//! A rejection carries a machine-readable reason code so a client can switch
//! on it — refresh on [`AuthReason::ExpiredCredential`], give up on
//! [`AuthReason::InsufficientScope`] — instead of matching on message text,
//! which misclassifies the moment someone rewords a string.

use std::fmt;

/// Header carrying one [`AuthReason`] on every 401.
pub const AUTH_REASON_HEADER: &str = "vgi-auth-reason";

/// Header set to `"true"` on 401s from a service whose authentication depends
/// on a reverse proxy. Omitted otherwise — never `"false"`.
pub const AUTH_PROXY_REQUIRED_HEADER: &str = "vgi-auth-proxy-required";

/// The closed set of reason codes.
///
/// Readers must treat an unrecognised code as [`AuthReason::Unauthorized`] —
/// that means the server is newer, not broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthReason {
    /// No credential was presented at all.
    MissingCredential,
    /// A credential was presented and rejected.
    InvalidCredential,
    /// Well-formed, but outside its validity window.
    ExpiredCredential,
    /// Identified, but not permitted.
    ///
    /// Deliberately a 401 rather than a 403: the authenticate callback runs
    /// before any method is resolved, so there is no route yet whose
    /// permissions could be evaluated. A service wanting a true 403 raises it
    /// from the method body.
    InsufficientScope,
    /// The request carried no evidence of arriving through the trusted proxy.
    /// Derived from server configuration, never from the request.
    ProxyRequired,
    /// Refused, unclassified. The fallback.
    Unauthorized,
}

impl AuthReason {
    /// The wire spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::InvalidCredential => "invalid_credential",
            Self::ExpiredCredential => "expired_credential",
            Self::InsufficientScope => "insufficient_scope",
            Self::ProxyRequired => "proxy_required",
            Self::Unauthorized => "unauthorized",
        }
    }
}

impl fmt::Display for AuthReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Build the operator-facing proxy note.
///
/// The wording is not normative — it is prose for a human. It must convey
/// that the service is only reachable through its proxy, which header names
/// the proxy must set, and that a rejection here is at least as likely to be
/// a proxy misconfiguration as a bad credential.
pub(crate) fn proxy_hint(headers: &[String]) -> String {
    format!(
        "This service only accepts requests that arrive through its configured \
         reverse proxy, which must set the {} header(s). A rejection here is at \
         least as likely to be a proxy misconfiguration as a bad credential — \
         check that the proxy is forwarding them before re-issuing credentials.",
        headers.join(", ")
    )
}

/// Render the JSON envelope of spec §4.3.
///
/// `proxy_hint` is absent, not empty, when it does not apply, so its presence
/// alone is a usable signal.
pub(crate) fn envelope(reason: AuthReason, detail: &str, hint: Option<&str>) -> String {
    let mut out = String::from("{\"error\":\"unauthorized\",\"reason\":\"");
    out.push_str(reason.as_str());
    out.push_str("\",\"detail\":");
    out.push_str(&json_string(detail));
    if let Some(hint) = hint {
        out.push_str(",\"proxy_hint\":");
        out.push_str(&json_string(hint));
    }
    out.push('}');
    out
}

/// Minimal JSON string escaping — the envelope has no other dynamic shape,
/// so pulling in a serializer for it would not earn its keep.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_omits_the_hint_when_it_does_not_apply() {
        // Absent, not empty — presence alone has to be a usable signal.
        let body = envelope(AuthReason::InvalidCredential, "nope", None);
        assert!(!body.contains("proxy_hint"), "{body}");
        assert!(body.contains("\"reason\":\"invalid_credential\""), "{body}");
        assert!(body.contains("\"error\":\"unauthorized\""), "{body}");
    }

    #[test]
    fn envelope_carries_the_hint_when_it_applies() {
        let hint = proxy_hint(&["vgi-proxy-proof".to_string()]);
        let body = envelope(AuthReason::ProxyRequired, "", Some(&hint));
        assert!(body.contains("proxy_hint"), "{body}");
        assert!(body.contains("vgi-proxy-proof"), "{body}");
    }

    #[test]
    fn detail_is_escaped() {
        let body = envelope(AuthReason::Unauthorized, "a \"quoted\"\nline", None);
        assert!(body.contains("\\\"quoted\\\""), "{body}");
        assert!(body.contains("\\n"), "{body}");
    }
}
