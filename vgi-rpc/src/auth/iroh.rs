//! Trusted forwarding of bridge-authenticated Iroh EndpointIds.
//!
//! The bridge proves the remote Iroh peer cryptographically. Ordinary workers
//! prove only their adjacent hop to that configured bridge, so forwarded
//! evidence deliberately has `configured_proxy` assurance while retaining the
//! original cryptographic assurance as an attribute.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde_json::Value;

use super::identity::{
    IdentityAssurance, PeerIdentity, PeerIdentityProvider, PeerIdentityResult, PeerIdentityStatus,
    SubjectKind, SubjectStability,
};
use crate::RpcError;

const PROVIDER: &str = "iroh";
pub const IROH_FORWARDED_ENDPOINT_HEADER: &str = "VGI-Forwarded-Iroh-Endpoint";

/// Exact HTTP bridge trust and worker-local identity namespace.
#[derive(Clone, Debug)]
pub struct IrohForwardedHeaderConfig {
    pub issuer: String,
    pub trusted_proxy_addresses: BTreeSet<IpAddr>,
}

impl IrohForwardedHeaderConfig {
    pub fn new<I, S>(issuer: impl Into<String>, trusted_proxy_addresses: I) -> crate::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let issuer = issuer.into();
        validate_issuer(&issuer)?;
        let mut trusted = BTreeSet::new();
        for configured in trusted_proxy_addresses {
            let configured = configured.into();
            let address = configured
                .parse::<IpAddr>()
                .map(normalize_ip)
                .map_err(|_| {
                    RpcError::value_error(
                        "Iroh bridge addresses must be exact IPv4 or IPv6 addresses",
                    )
                })?;
            if !trusted.insert(address) {
                return Err(RpcError::value_error("duplicate Iroh bridge address"));
            }
        }
        if trusted.is_empty() {
            return Err(RpcError::value_error(
                "at least one exact Iroh bridge address is required",
            ));
        }
        Ok(Self {
            issuer,
            trusted_proxy_addresses: trusted,
        })
    }

    fn validate(&self) -> crate::Result<()> {
        validate_issuer(&self.issuer)?;
        if self.trusted_proxy_addresses.is_empty() {
            return Err(RpcError::value_error(
                "at least one exact Iroh bridge address is required",
            ));
        }
        Ok(())
    }
}

/// Resolve one canonical EndpointId only after the exact immediate bridge
/// address is trusted. The bridge must strip any client-supplied copy of the
/// header before setting its own.
pub fn iroh_forwarded_header_provider(
    config: IrohForwardedHeaderConfig,
) -> crate::Result<PeerIdentityProvider> {
    config.validate()?;
    PeerIdentityProvider::new(PROVIDER, move |context| {
        let immediate = context
            .immediate_peer()
            .and_then(|value| value.parse::<IpAddr>().ok())
            .map(normalize_ip);
        if !immediate.is_some_and(|peer| config.trusted_proxy_addresses.contains(&peer)) {
            return PeerIdentityResult::without_identity(
                PROVIDER,
                PeerIdentityStatus::UntrustedProxy,
            );
        }
        let endpoint = match context.header(IROH_FORWARDED_ENDPOINT_HEADER) {
            Ok(Some(endpoint)) => endpoint,
            Ok(None) => {
                return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::NoMatch)
            }
            Err(_) => {
                return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid)
            }
        };
        if !canonical_endpoint(endpoint) {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
        }
        match forwarded_identity(
            endpoint,
            &config.issuer,
            "http",
            "http_proxy",
            context
                .immediate_peer()
                .expect("trusted immediate peer exists"),
        ) {
            Ok(identity) => Ok(PeerIdentityResult::available(identity)),
            Err(_) => PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid),
        }
    })
}

pub(crate) fn validate_issuer(issuer: &str) -> crate::Result<()> {
    if issuer.is_empty()
        || issuer
            .chars()
            .any(|character| character <= '\u{1f}' || character == '\u{7f}')
    {
        return Err(RpcError::value_error(
            "Iroh issuer must be a non-empty Unicode string without controls",
        ));
    }
    Ok(())
}

pub(crate) fn canonical_endpoint(endpoint: &str) -> bool {
    endpoint.len() == 64
        && endpoint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn endpoint_subject(endpoint: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in endpoint {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(crate) fn forwarded_identity(
    endpoint: &str,
    issuer: &str,
    transport: &str,
    evidence_source: &str,
    proxy_address: &str,
) -> crate::Result<PeerIdentity> {
    validate_issuer(issuer)?;
    if !canonical_endpoint(endpoint) {
        return Err(RpcError::value_error(
            "Iroh EndpointId must be canonical lowercase hexadecimal",
        ));
    }
    PeerIdentity::new(
        PROVIDER,
        evidence_source,
        IdentityAssurance::ConfiguredProxy,
        issuer,
        transport,
    )?
    .with_subject(
        SubjectKind::Endpoint,
        endpoint,
        SubjectStability::Stable,
        true,
    )?
    .with_attributes(BTreeMap::from([(
        "original_assurance".into(),
        Value::String("cryptographic_peer".into()),
    )]))
    .map(|identity| {
        identity.with_addresses(Some(endpoint.to_owned()), Some(proxy_address.to_owned()))
    })
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerResolutionContext;

    const ENDPOINT: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn provider() -> PeerIdentityProvider {
        iroh_forwarded_header_provider(
            IrohForwardedHeaderConfig::new("production-mesh", ["127.0.0.1"]).unwrap(),
        )
        .unwrap()
    }

    fn context(peer: &str, values: Vec<String>) -> crate::Result<PeerResolutionContext> {
        let headers = if values.is_empty() {
            Vec::new()
        } else {
            vec![(IROH_FORWARDED_ENDPOINT_HEADER.to_owned(), values)]
        };
        PeerResolutionContext::new("http")?
            .with_peers(Some(peer), None::<String>)
            .with_headers(headers)
    }

    #[test]
    fn forwarded_http_identity_is_stable_and_worker_namespaced() {
        let result = provider()(&context("127.0.0.1", vec![ENDPOINT.into()]).unwrap()).unwrap();
        assert_eq!(result.status(), PeerIdentityStatus::Available);
        let identity = &result.identities()[0];
        assert_eq!(identity.provider(), "iroh");
        assert_eq!(identity.evidence_source(), "http_proxy");
        assert_eq!(identity.assurance(), IdentityAssurance::ConfiguredProxy);
        assert_eq!(identity.issuer(), "production-mesh");
        assert_eq!(identity.transport(), "http");
        assert_eq!(identity.subject_kind(), SubjectKind::Endpoint);
        assert_eq!(identity.subject_key(), Some(ENDPOINT));
        assert_eq!(identity.subject_stability(), SubjectStability::Stable);
        assert!(identity.subject_verified());
        assert_eq!(
            identity.attributes().get("original_assurance"),
            Some(&Value::String("cryptographic_peer".into()))
        );
        assert_eq!(identity.source_address(), Some(ENDPOINT));
        assert_eq!(identity.proxy_address(), Some("127.0.0.1"));
    }

    #[test]
    fn forwarded_http_identity_fails_closed() {
        let provider = provider();
        assert_eq!(
            provider(&context("192.0.2.1", vec![ENDPOINT.into()]).unwrap())
                .unwrap()
                .status(),
            PeerIdentityStatus::UntrustedProxy
        );
        assert_eq!(
            provider(&context("::ffff:127.0.0.1", vec![ENDPOINT.into()]).unwrap())
                .unwrap()
                .status(),
            PeerIdentityStatus::Available
        );
        assert_eq!(
            provider(&context("127.0.0.1", Vec::new()).unwrap())
                .unwrap()
                .status(),
            PeerIdentityStatus::NoMatch
        );
        for invalid in ["00".to_owned(), ENDPOINT.to_ascii_uppercase()] {
            assert_eq!(
                provider(&context("127.0.0.1", vec![invalid]).unwrap())
                    .unwrap()
                    .status(),
                PeerIdentityStatus::Invalid
            );
        }
        assert_eq!(
            provider(&context("127.0.0.1", vec![ENDPOINT.into(), ENDPOINT.into()]).unwrap())
                .unwrap()
                .status(),
            PeerIdentityStatus::Invalid
        );
        assert!(context("127.0.0.1", vec![format!("{ENDPOINT}\r")]).is_err());
        assert!(PeerResolutionContext::new("http")
            .unwrap()
            .with_peers(Some("127.0.0.1"), None::<String>)
            .with_headers([
                (IROH_FORWARDED_ENDPOINT_HEADER.into(), vec![ENDPOINT.into()]),
                ("vgi-forwarded-iroh-endpoint".into(), vec![ENDPOINT.into()]),
            ])
            .is_err());
    }

    #[test]
    fn forwarded_http_provider_requires_an_exact_trust_boundary() {
        assert!(IrohForwardedHeaderConfig::new("production-mesh", Vec::<String>::new()).is_err());
        assert!(IrohForwardedHeaderConfig::new("production-mesh", ["localhost"]).is_err());
        assert!(IrohForwardedHeaderConfig::new("bad\nissuer", ["127.0.0.1"]).is_err());
        assert!(IrohForwardedHeaderConfig::new(
            "production-mesh",
            ["127.0.0.1", "::ffff:127.0.0.1"],
        )
        .is_err());
    }
}
