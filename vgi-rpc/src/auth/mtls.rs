//! Mutual-TLS authentication via `x-forwarded-client-cert` (RFC 8705).
//!
//! Production deployments typically terminate TLS at a front proxy
//! (Envoy/NGINX/Istio) that forwards the verified client certificate (or
//! a derived identity) in the `x-forwarded-client-cert` header. These
//! helpers parse that header and expose helpers keyed on certificate
//! fingerprint, subject DN, or raw field access.
//!
//! XFCC element grammar (Envoy/NGINX interpretation):
//!   `Key=Value;Key="Value, with commas";` repeated per certificate hop.
//!   Multiple hops are comma-separated at the top level (not inside quotes).
//!   We only parse the leaf (leftmost) certificate — mirrors the Python
//!   and Go ports.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::auth::{AuthContext, AuthRequest, AuthResult, Authenticate};

/// A parsed XFCC leaf element.
#[derive(Clone, Debug, Default)]
pub struct XfccElement {
    /// Key → value map. Keys are lowercased for lookup.
    pub fields: BTreeMap<String, String>,
}

impl XfccElement {
    /// Hex-encoded SHA-256 fingerprint of the client cert (`Hash=`).
    pub fn hash(&self) -> Option<&str> {
        self.fields.get("hash").map(|s| s.as_str())
    }

    /// RFC 4514 subject DN (`Subject=`).
    pub fn subject(&self) -> Option<&str> {
        self.fields.get("subject").map(|s| s.as_str())
    }

    /// URI-form SAN identity (`URI=`).
    pub fn uri(&self) -> Option<&str> {
        self.fields.get("uri").map(|s| s.as_str())
    }

    /// DNS-form SAN identity (`DNS=`).
    pub fn dns(&self) -> Option<&str> {
        self.fields.get("dns").map(|s| s.as_str())
    }

    fn into_claims(self) -> BTreeMap<String, String> {
        self.fields
    }
}

/// Parse the value of an `x-forwarded-client-cert` header, returning the
/// leaf (leftmost) certificate's fields. Returns `None` when empty.
pub fn parse_xfcc(header_value: &str) -> Option<XfccElement> {
    // Split top-level hops on commas that are not inside quotes.
    let first_hop = split_top_level(header_value).next()?;
    parse_kv_list(first_hop)
}

fn split_top_level(s: &str) -> impl Iterator<Item = &str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut in_quotes = false;
    let mut start = 0;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b'(' | b'[' if !in_quotes => depth += 1,
            b')' | b']' if !in_quotes => {
                depth = depth.saturating_sub(1);
            }
            b',' if !in_quotes && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out.into_iter().map(str::trim).filter(|t| !t.is_empty())
}

fn parse_kv_list(hop: &str) -> Option<XfccElement> {
    let mut fields = BTreeMap::new();
    // Semicolons separate key/value pairs within one hop.
    for part in split_kv(hop) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = strip_quotes(v.trim());
        if !key.is_empty() {
            fields.insert(key, val.to_string());
        }
    }
    if fields.is_empty() {
        None
    } else {
        Some(XfccElement { fields })
    }
}

fn split_kv(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, ch) in s.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                out.push(&s[start..i]);
                start = i + ch.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out.into_iter()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect()
}

fn strip_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

/// Authenticate via an allowlist of SHA-256 fingerprints (hex, lowercase).
pub fn mtls_authenticate_fingerprint(allow: HashSet<String>) -> Authenticate {
    Arc::new(move |req: &AuthRequest<'_>| -> AuthResult {
        let Some(h) = req.header("x-forwarded-client-cert") else {
            return Ok(AuthContext::anonymous());
        };
        let Some(el) = parse_xfcc(h) else {
            return Ok(AuthContext::anonymous());
        };
        let Some(fp) = el.hash() else {
            return Ok(AuthContext::anonymous());
        };
        let fp_lower = fp.to_ascii_lowercase();
        if allow.contains(&fp_lower) {
            let principal = el
                .subject()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("sha256:{fp_lower}"));
            let mut ctx = AuthContext::for_principal("mtls", principal);
            ctx.claims = el.into_claims();
            Ok(ctx)
        } else {
            Ok(AuthContext::anonymous())
        }
    })
}

/// Authenticate via a closure matching the subject DN string.
pub fn mtls_authenticate_subject<F>(matches: F) -> Authenticate
where
    F: Fn(&str) -> Option<AuthContext> + Send + Sync + 'static,
{
    Arc::new(move |req: &AuthRequest<'_>| -> AuthResult {
        let Some(h) = req.header("x-forwarded-client-cert") else {
            return Ok(AuthContext::anonymous());
        };
        let Some(el) = parse_xfcc(h) else {
            return Ok(AuthContext::anonymous());
        };
        let Some(subject) = el.subject() else {
            return Ok(AuthContext::anonymous());
        };
        Ok(matches(subject).unwrap_or_else(AuthContext::anonymous))
    })
}

/// Generic XFCC callback — pass the parsed element straight to the user.
pub fn mtls_authenticate_xfcc<F>(handler: F) -> Authenticate
where
    F: Fn(&XfccElement) -> Option<AuthContext> + Send + Sync + 'static,
{
    Arc::new(move |req: &AuthRequest<'_>| -> AuthResult {
        let Some(h) = req.header("x-forwarded-client-cert") else {
            return Ok(AuthContext::anonymous());
        };
        let Some(el) = parse_xfcc(h) else {
            return Ok(AuthContext::anonymous());
        };
        Ok(handler(&el).unwrap_or_else(AuthContext::anonymous))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_hop() {
        let h = "Hash=deadbeef;Subject=\"CN=alice,O=example\";URI=spiffe://x/y";
        let el = parse_xfcc(h).unwrap();
        assert_eq!(el.hash(), Some("deadbeef"));
        assert_eq!(el.subject(), Some("CN=alice,O=example"));
        assert_eq!(el.uri(), Some("spiffe://x/y"));
    }

    #[test]
    fn takes_leaf_of_chain() {
        let h = "Hash=leaf,Hash=middle,Hash=root";
        assert_eq!(parse_xfcc(h).unwrap().hash(), Some("leaf"));
    }

    #[test]
    fn quoted_value_preserves_commas() {
        let h = r#"Subject="CN=alice,OU=eng";Hash=abc"#;
        let el = parse_xfcc(h).unwrap();
        assert_eq!(el.subject(), Some("CN=alice,OU=eng"));
        assert_eq!(el.hash(), Some("abc"));
    }

    #[test]
    fn fingerprint_allowlist() {
        let mut allow = HashSet::new();
        allow.insert("deadbeef".into());
        let auth = mtls_authenticate_fingerprint(allow);
        let hv = vec![(
            "x-forwarded-client-cert".into(),
            "Hash=DEADBEEF;Subject=CN=alice".into(),
        )];
        let req = AuthRequest {
            method: "echo",
            headers: &hv,
            peer_addr: None,
        };
        let ctx = auth(&req).unwrap();
        assert!(ctx.authenticated);
        assert_eq!(ctx.domain, "mtls");
        assert_eq!(ctx.principal, "CN=alice");
    }

    #[test]
    fn fingerprint_mismatch_anonymous() {
        let allow: HashSet<String> = HashSet::new();
        let auth = mtls_authenticate_fingerprint(allow);
        let hv = vec![("x-forwarded-client-cert".into(), "Hash=deadbeef".into())];
        let req = AuthRequest {
            method: "echo",
            headers: &hv,
            peer_addr: None,
        };
        assert!(!auth(&req).unwrap().authenticated);
    }
}
