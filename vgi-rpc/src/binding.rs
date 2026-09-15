//! One protocol hosted by a server, with everything dispatch needs.
//!
//! A server hosts one or more protocols and resolves the pair
//! `(protocol, method)`. Method names may collide across protocols -- that is
//! what makes protocols independently authorable, and a port that merges them
//! into one namespace is not conformant.

use crate::errors::RpcError;

/// The name grammar: an identifier, optionally dot-qualified, carrying its
/// major version as the last component (`vgi_rpc.Reflection.v1`).
///
/// Validated on both carriers -- at registration, and again on the routing key
/// read off the wire. An unvalidated name from a request reaches error
/// messages, log fields and metric labels, where arbitrary bytes do not belong.
fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Reserved for protocols the framework itself defines.
///
/// An application claiming `vgi_rpc.Reflection.v1` would shadow the one surface
/// a client can trust before it knows anything else about the server.
pub const RESERVED_PROTOCOL_PREFIX: &str = "vgi_rpc.";

/// Bounds a name that crosses process boundaries both as metadata and as a URL
/// path segment.
pub const MAX_PROTOCOL_NAME_BYTES: usize = 255;

/// Validate a protocol's wire identity.
///
/// `allow_reserved` permits the `vgi_rpc.` prefix, and is set only where the
/// framework registers its own protocols.
pub fn validate_protocol_name(name: &str, allow_reserved: bool) -> Result<(), String> {
    if name.is_empty() {
        return Err("A protocol name may not be empty.".into());
    }
    if name.len() > MAX_PROTOCOL_NAME_BYTES {
        return Err(format!(
            "Protocol name exceeds {MAX_PROTOCOL_NAME_BYTES} bytes: {}...",
            &name[..name.len().min(64)]
        ));
    }
    if !is_valid_name(name) {
        return Err(format!(
            "Protocol name {name:?} is not an identifier, optionally dot-qualified. \
             Expected something like 'vgi.Identity.v1'."
        ));
    }
    if !allow_reserved && name.starts_with(RESERVED_PROTOCOL_PREFIX) {
        return Err(format!(
            "Protocol name {name:?} claims the reserved {RESERVED_PROTOCOL_PREFIX:?} prefix, \
             which is for protocols the framework defines."
        ));
    }
    Ok(())
}

/// A request carrying no routing key.
///
/// Distinct from [`protocol_not_supported`] on purpose: the first says the
/// caller did not say which protocol it meant, the second that it named one
/// this server does not host, and a client acts differently on each.
pub fn protocol_not_specified(hosted: &[&str]) -> RpcError {
    RpcError::protocol_error(format!(
        "Request carries no 'vgi_rpc.protocol' routing key. Every request must name \
         the protocol it addresses. This server hosts: {hosted:?}."
    ))
}

/// A protocol this server does not host.
///
/// Also the answer for an incompatible major version, since the major is part
/// of the name: a routing answer every proxy, WAF and load balancer understands
/// without an Arrow parser.
pub fn protocol_not_supported(requested: &str, hosted: &[&str]) -> RpcError {
    RpcError::protocol_error(format!(
        "This server does not host protocol {requested:?}. Hosted: {hosted:?}."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dot_qualified_identifiers() {
        for name in ["vgi.Identity.v1", "Service", "_private", "a.b.c.d.v12"] {
            assert!(validate_protocol_name(name, false).is_ok(), "{name}");
        }
    }

    #[test]
    fn rejects_what_a_path_segment_or_metric_label_should_never_carry() {
        for name in [
            "",
            "1leading",
            "has space",
            "has-dash",
            "has/slash",
            ".leading",
        ] {
            assert!(validate_protocol_name(name, false).is_err(), "{name}");
        }
    }

    #[test]
    fn reserves_the_framework_prefix_for_the_framework() {
        // An application claiming vgi_rpc.Reflection.v1 could shadow the one
        // surface a client trusts before it knows anything else.
        assert!(validate_protocol_name("vgi_rpc.Reflection.v1", false).is_err());
        assert!(validate_protocol_name("vgi_rpc.Reflection.v1", true).is_ok());
        // The guard is on the prefix, not a substring anywhere.
        assert!(validate_protocol_name("app.vgi_rpc.v1", false).is_ok());
    }
}
