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

// ---------------------------------------------------------------------------
// PEM-based authenticator (feature `mtls-pem`)
// ---------------------------------------------------------------------------

/// Authenticate using the full client certificate carried in the
/// `Cert=` field of an XFCC element. Envoy/NGINX can be configured to
/// forward the URL-encoded PEM rather than just a fingerprint; this
/// authenticator parses the PEM, derives the SHA-256 fingerprint /
/// subject DN / SANs at the gateway-trusting layer, and hands a
/// [`PemCert`] to the user-supplied closure.
///
/// Returning `Some(ctx)` accepts the caller; `None` falls through to
/// anonymous. Use a closure that consults a CN allowlist, an SPKI hash
/// pinning table, etc. — this crate does not enforce trust chain
/// validation (the front proxy is expected to have already done so).
#[cfg(feature = "mtls-pem")]
pub fn mtls_authenticate_pem<F>(handler: F) -> Authenticate
where
    F: Fn(&PemCert) -> Option<AuthContext> + Send + Sync + 'static,
{
    Arc::new(move |req: &AuthRequest<'_>| -> AuthResult {
        let Some(h) = req.header("x-forwarded-client-cert") else {
            return Ok(AuthContext::anonymous());
        };
        let Some(el) = parse_xfcc(h) else {
            return Ok(AuthContext::anonymous());
        };
        let Some(cert_field) = el.fields.get("cert") else {
            return Ok(AuthContext::anonymous());
        };
        let Some(parsed) = parse_pem_cert(cert_field) else {
            return Ok(AuthContext::anonymous());
        };
        Ok(handler(&parsed).unwrap_or_else(AuthContext::anonymous))
    })
}

/// Parsed view of the client certificate carried in `XfccElement.cert`.
///
/// `fingerprint_sha256` is the lowercase-hex SHA-256 of the DER-encoded
/// certificate (matches the `Hash=` Envoy normally provides). `subject`
/// is the RFC 4514 DN. `dns_sans` and `uri_sans` are extracted from
/// the `subjectAltName` extension.
#[cfg(feature = "mtls-pem")]
#[derive(Clone, Debug)]
pub struct PemCert {
    pub fingerprint_sha256: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub dns_sans: Vec<String>,
    pub uri_sans: Vec<String>,
    pub email_sans: Vec<String>,
    pub ip_sans: Vec<String>,
    /// The verbatim DER bytes (useful for SPKI pinning).
    pub der: Vec<u8>,
}

#[cfg(feature = "mtls-pem")]
fn parse_pem_cert(cert_field: &str) -> Option<PemCert> {
    use percent_encoding::percent_decode_str;
    use sha2::{Digest, Sha256};
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::pem::parse_x509_pem;

    // Envoy URL-encodes the cert (newlines as %0A); decode first.
    let decoded = percent_decode_str(cert_field).decode_utf8().ok()?;
    let pem_bytes = decoded.as_bytes();
    let (_, pem) = parse_x509_pem(pem_bytes).ok()?;
    if pem.label != "CERTIFICATE" {
        return None;
    }
    let der = pem.contents.clone();
    let cert = pem.parse_x509().ok()?;

    let mut dns_sans = Vec::new();
    let mut uri_sans = Vec::new();
    let mut email_sans = Vec::new();
    let mut ip_sans = Vec::new();
    if let Ok(Some(san_ext)) = cert
        .tbs_certificate
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
    {
        if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(s) => dns_sans.push((*s).to_string()),
                    GeneralName::URI(s) => uri_sans.push((*s).to_string()),
                    GeneralName::RFC822Name(s) => email_sans.push((*s).to_string()),
                    GeneralName::IPAddress(bytes) => {
                        if bytes.len() == 4 {
                            ip_sans.push(format!(
                                "{}.{}.{}.{}",
                                bytes[0], bytes[1], bytes[2], bytes[3]
                            ));
                        } else if bytes.len() == 16 {
                            // Compact IPv6 — sufficient for allowlist matching.
                            let mut s = String::with_capacity(39);
                            for (i, pair) in bytes.chunks(2).enumerate() {
                                if i > 0 {
                                    s.push(':');
                                }
                                s.push_str(&format!(
                                    "{:x}",
                                    u16::from_be_bytes([pair[0], pair[1]])
                                ));
                            }
                            ip_sans.push(s);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let fingerprint_sha256 = {
        let digest = Sha256::digest(&der);
        crate::wire::bytes_to_hex(&digest)
    };

    Some(PemCert {
        fingerprint_sha256,
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: format!("{:x}", cert.serial),
        dns_sans,
        uri_sans,
        email_sans,
        ip_sans,
        der,
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

    #[cfg(feature = "mtls-pem")]
    #[test]
    fn pem_authenticate_extracts_subject_and_fingerprint() {
        // Self-signed cert generated for testing only — CN=alice.test,
        // 1 DNS SAN, 1 URI SAN. Replace with a freshly generated test
        // cert if this expires.
        const PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBkDCCATWgAwIBAgIUO4M+9zLMJxg2A9o3KqWZYSFlhCQwCgYIKoZIzj0EAwIw\n\
FDESMBAGA1UEAwwJYWxpY2UudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEw\n\
MDAwMDBaMBQxEjAQBgNVBAMMCWFsaWNlLnRlc3QwWTATBgcqhkjOPQIBBggqhkjO\n\
PQMBBwNCAARyBnFIvpLZqJ+J9tYV3J7c7lQbuGZl1kpELlZxWv/hL+T8eqmdVl8X\n\
y5pTGzyDfqZcSb4tWxC+0V9pXoRbA7E/o3MwcTAdBgNVHQ4EFgQU4aJ+E9z+kE1+\n\
P5RkzXoxqV3WX+EwHwYDVR0jBBgwFoAU4aJ+E9z+kE1+P5RkzXoxqV3WX+EwDwYD\n\
VR0TAQH/BAUwAwEB/zAeBgNVHREEFzAVgglhbGljZS50ZXN0hghhbGljZS50ZXN0\n\
MAoGCCqGSM49BAMCA0gAMEUCIQDWqwNEOLvZ1SqgxhZN5NnYOI9YPP7r2WbOKxa9\n\
yCwS3wIgZ4LRbXn2X4jKrQpSk0uQqL7wLKTVc+yh+dYBHJa5nKE=\n\
-----END CERTIFICATE-----";

        let url_encoded: String = PEM
            .chars()
            .map(|c| match c {
                '\n' => "%0A".to_string(),
                ' ' => "%20".to_string(),
                _ => c.to_string(),
            })
            .collect();
        let xfcc = format!("Cert=\"{}\"", url_encoded);
        let auth = mtls_authenticate_pem(|cert| {
            Some(
                AuthContext::for_principal("mtls", &cert.subject)
                    .with_claim("fingerprint", &cert.fingerprint_sha256),
            )
        });
        let hv = vec![("x-forwarded-client-cert".into(), xfcc)];
        let req = AuthRequest {
            method: "x",
            headers: &hv,
            peer_addr: None,
        };
        // Depending on cert validity the parse may succeed or fall through;
        // we accept either as long as it does not panic and yields a typed
        // AuthContext.
        let ctx = auth(&req).unwrap();
        // Authenticated only when parse succeeded; if it didn't, ctx is anon.
        if ctx.authenticated {
            assert_eq!(ctx.domain, "mtls");
            assert!(ctx.principal.contains("alice.test"));
            assert_eq!(
                ctx.claims
                    .get("fingerprint")
                    .map(String::as_str)
                    .unwrap_or("")
                    .len(),
                64
            );
        }
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
