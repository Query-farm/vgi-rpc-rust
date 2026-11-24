//! Protocol version negotiation (`PROTOCOL_VERSIONS_V1.md`).
//!
//! A server advertises the `major.minor` window of every protocol it gates as
//! `name=MIN-MAX[, name=MIN-MAX]...`: the `VGI-Protocol-Versions` header on
//! every HTTP response, and the `vgi_rpc.protocol_versions` metadata key on
//! reflection results, `__transport_options__` replies and refusals. A request
//! whose `vgi_rpc.protocol_version` lies outside its protocol's window is
//! refused with `protocol_version_unsupported` (`FAILED_PRECONDITION`), naming
//! both windows and which side to upgrade. Clients send their own windows as
//! `vgi_rpc.protocol_versions_client` (and, on HTTP,
//! `VGI-Client-Protocol-Versions`), purely informational.
//!
//! In the 3.4 wave every binding advertises exactly its declared
//! `protocol_version`'s `major.minor` (`3.4-3.4`), so 3.4 ↔ 3.4 behaviour is
//! unchanged; a server may override a protocol's window
//! ([`crate::server::RpcServerBuilder::protocol_version_range`]), which is how
//! fixture workers impersonate an older server.

use std::collections::BTreeMap;
use std::fmt;

/// The HTTP response header carrying the server's windows.
pub const PROTOCOL_VERSIONS_HEADER: &str = "VGI-Protocol-Versions";
/// The HTTP request header carrying the client's windows.
pub const CLIENT_PROTOCOL_VERSIONS_HEADER: &str = "VGI-Client-Protocol-Versions";
/// The metadata key carrying the server's windows.
pub const PROTOCOL_VERSIONS_KEY: &str = "vgi_rpc.protocol_versions";
/// The request metadata key carrying the client's windows.
pub const CLIENT_PROTOCOL_VERSIONS_KEY: &str = "vgi_rpc.protocol_versions_client";
/// The `error_kind` of a refusal.
pub const PROTOCOL_VERSION_UNSUPPORTED: &str = "protocol_version_unsupported";
/// The `error_kind` servers released before negotiation sent.
pub const PROTOCOL_VERSION_MISMATCH_LEGACY: &str = "protocol_version_mismatch";

/// A `(major, minor)` version.
pub type MajorMinor = (u64, u64);

/// An inclusive window of `(major, minor)` versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionRange {
    /// Oldest version accepted.
    pub min: MajorMinor,
    /// Newest version accepted.
    pub max: MajorMinor,
}

fn parse_component(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// Parse `MAJOR.MINOR`, or `MAJOR.MINOR.PATCH` (the patch dropped).
pub fn parse_major_minor(text: &str) -> Option<MajorMinor> {
    let mut parts = text.trim().split('.');
    let major = parse_component(parts.next()?)?;
    let minor = parse_component(parts.next()?)?;
    match parts.next() {
        None => Some((major, minor)),
        Some(patch) => {
            parse_component(patch)?;
            if parts.next().is_some() {
                None
            } else {
                Some((major, minor))
            }
        }
    }
}

impl VersionRange {
    /// `MIN-MAX`, or a single version meaning `V-V`. `None` when malformed or
    /// inverted.
    pub fn parse(text: &str) -> Option<Self> {
        let (lo, hi) = match text.trim().split_once('-') {
            Some((lo, hi)) => (parse_major_minor(lo)?, parse_major_minor(hi)?),
            None => {
                let v = parse_major_minor(text)?;
                (v, v)
            }
        };
        (lo <= hi).then_some(VersionRange { min: lo, max: hi })
    }

    /// The single-version window of a version's `major.minor`.
    pub fn exactly(version: &str) -> Option<Self> {
        let v = parse_major_minor(version)?;
        Some(VersionRange { min: v, max: v })
    }

    /// Whether `v` lies inside the window.
    pub fn contains(&self, v: MajorMinor) -> bool {
        self.min <= v && v <= self.max
    }

    /// The highest version inside both windows, or `None` when disjoint.
    pub fn highest_common(&self, other: &VersionRange) -> Option<MajorMinor> {
        let top = self.max.min(other.max);
        (top >= self.min && top >= other.min).then_some(top)
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}-{}.{}",
            self.min.0, self.min.1, self.max.0, self.max.1
        )
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'))
}

/// Render `name=MIN-MAX[, name=MIN-MAX]...` in the given order.
pub fn format_versions<'a>(ranges: impl IntoIterator<Item = (&'a str, VersionRange)>) -> String {
    ranges
        .into_iter()
        .map(|(n, r)| format!("{n}={r}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse a `VGI-Protocol-Versions` value. Tolerant: a malformed entry is
/// skipped, and a repeated name keeps its first window.
pub fn parse_versions(text: &str) -> BTreeMap<String, VersionRange> {
    let mut out = BTreeMap::new();
    for entry in text.split(',') {
        let Some((name, range)) = entry.trim().split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !valid_name(name) || out.contains_key(name) {
            continue;
        }
        if let Some(r) = VersionRange::parse(range) {
            out.insert(name.to_string(), r);
        }
    }
    out
}

/// A pre-negotiation refusal's server version: `Server: X.Y[.Z]` or
/// `server requires X.Y[.Z]` in `text`.
pub fn legacy_server_version(text: &str) -> Option<MajorMinor> {
    for marker in ["Server:", "server requires"] {
        let mut rest = text;
        while let Some(i) = rest.find(marker) {
            let after = rest[i + marker.len()..].trim_start();
            let token: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let token = token.trim_end_matches('.');
            let mut parts = token.split('.');
            if let (Some(a), Some(b)) = (parts.next(), parts.next()) {
                if let (Ok(a), Ok(b)) = (a.parse(), b.parse()) {
                    return Some((a, b));
                }
            }
            rest = &rest[i + marker.len()..];
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse_and_format() {
        let r = VersionRange::parse("3.4-3.5").unwrap();
        assert_eq!(r.to_string(), "3.4-3.5");
        assert_eq!(VersionRange::parse("3.4").unwrap().to_string(), "3.4-3.4");
        assert_eq!(
            VersionRange::parse(" 3.4.2 - 3.5.0 ").unwrap().to_string(),
            "3.4-3.5"
        );
        for bad in ["", "3", "3.5-3.4", "03.4", "3.x", "3.4-", "1.2.3.4"] {
            assert!(VersionRange::parse(bad).is_none(), "{bad}");
        }
        assert!(r.contains((3, 4)) && r.contains((3, 5)) && !r.contains((3, 6)));
        let s = VersionRange::parse("3.4-3.4").unwrap();
        assert_eq!(r.highest_common(&s), Some((3, 4)));
        assert_eq!(
            VersionRange::parse("3.5-3.6").unwrap().highest_common(&s),
            None
        );
    }

    #[test]
    fn versions_parse_tolerantly() {
        let v = parse_versions(" vgi.v3=3.4-3.4 ,vgi.secret.v1=1.0, bad entry, x=3.x, vgi.v3=9.9");
        assert_eq!(v.len(), 2);
        assert_eq!(v["vgi.v3"].to_string(), "3.4-3.4");
        assert_eq!(v["vgi.secret.v1"].to_string(), "1.0-1.0");
        assert!(parse_versions("").is_empty());
        let r = VersionRange::parse("3.4-3.4").unwrap();
        assert_eq!(
            format_versions([
                ("vgi.v3", r),
                ("vgi.secret.v1", VersionRange::exactly("1.0.0").unwrap())
            ]),
            "vgi.v3=3.4-3.4, vgi.secret.v1=1.0-1.0"
        );
    }

    #[test]
    fn legacy_refusal_versions() {
        assert_eq!(
            legacy_server_version("mismatch\n  Client: 3.5.0\n  Server: 3.4.1\n"),
            Some((3, 4))
        );
        assert_eq!(
            legacy_server_version("client declares 3.5.0, server requires 3.3.0; major"),
            Some((3, 3))
        );
        assert_eq!(legacy_server_version("nothing here"), None);
    }
}
