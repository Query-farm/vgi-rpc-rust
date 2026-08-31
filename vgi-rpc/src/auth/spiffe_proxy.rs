//! Strict SPIFFE identity evidence from adjacent trusted HTTP proxies.
//!
//! These providers do not validate a proxy's network placement or configure
//! its TLS listener. Construction is the operator's explicit declaration that
//! the listed exact IP addresses are adjacent, cannot be bypassed, and replace
//! every identity header consumed here.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde_json::Value;

use super::identity::{
    IdentityAssurance, PeerIdentity, PeerIdentityProvider, PeerIdentityResult, PeerIdentityStatus,
    PeerResolutionContext, SubjectKind, SubjectStability,
};
use crate::RpcError;

const PROVIDER: &str = "spiffe";
const DEFAULT_MAX_HEADER_BYTES: usize = 16_384;

/// Exact trust boundary shared by every HTTP SPIFFE adapter.
#[derive(Clone, Debug)]
pub struct SpiffeProxyConfig {
    pub trust_domains: BTreeSet<String>,
    pub trusted_proxy_addresses: BTreeSet<IpAddr>,
    pub max_header_bytes: usize,
}

impl SpiffeProxyConfig {
    pub fn new<D, DS, P, PS>(trust_domains: D, trusted_proxy_addresses: P) -> crate::Result<Self>
    where
        D: IntoIterator<Item = DS>,
        DS: Into<String>,
        P: IntoIterator<Item = PS>,
        PS: Into<String>,
    {
        let trust_domains = trust_domains
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        let trusted_proxy_addresses = trusted_proxy_addresses
            .into_iter()
            .map(|value| {
                value
                    .into()
                    .parse::<IpAddr>()
                    .map(normalize_ip)
                    .map_err(|_| {
                        RpcError::value_error("trusted proxy addresses must be exact IP addresses")
                    })
            })
            .collect::<crate::Result<BTreeSet<_>>>()?;
        let config = Self {
            trust_domains,
            trusted_proxy_addresses,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_max_header_bytes(mut self, maximum: usize) -> crate::Result<Self> {
        self.max_header_bytes = maximum;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> crate::Result<()> {
        if self.trust_domains.is_empty()
            || self.trusted_proxy_addresses.is_empty()
            || self.max_header_bytes == 0
            || self
                .trust_domains
                .iter()
                .any(|domain| !valid_trust_domain(domain))
        {
            return Err(RpcError::value_error(
                "SPIFFE trust domains, exact trusted proxy addresses, and a positive limit are required",
            ));
        }
        Ok(())
    }

    fn trusts(&self, context: &PeerResolutionContext) -> bool {
        context
            .immediate_peer()
            .and_then(|peer| peer.parse::<IpAddr>().ok())
            .map(normalize_ip)
            .is_some_and(|peer| self.trusted_proxy_addresses.contains(&peer))
    }
}

/// Validate canonical SPIFFE syntax and return the allowed trust domain.
pub fn validate_spiffe_id<'a>(
    value: &str,
    trust_domains: &'a BTreeSet<String>,
) -> crate::Result<&'a str> {
    if value.is_empty()
        || value.len() > 2_048
        || !value.is_ascii()
        || value.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
        || value.contains('%')
        || !value.starts_with("spiffe://")
    {
        return Err(RpcError::value_error("invalid SPIFFE ID size or encoding"));
    }
    let remainder = &value["spiffe://".len()..];
    let (domain, path) = remainder
        .split_once('/')
        .ok_or_else(|| RpcError::value_error("SPIFFE ID requires a workload path"))?;
    if !valid_trust_domain(domain) || !trust_domains.contains(domain) {
        return Err(RpcError::value_error(
            "SPIFFE trust domain is invalid or not allowed",
        ));
    }
    if path.is_empty()
        || path.ends_with('/')
        || path.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(RpcError::value_error("SPIFFE path is not canonical"));
    }
    Ok(trust_domains
        .get(domain)
        .expect("membership was checked")
        .as_str())
}

pub(crate) fn valid_trust_domain(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
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

fn invalid() -> crate::Result<PeerIdentityResult> {
    PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid)
}

fn no_match() -> crate::Result<PeerIdentityResult> {
    PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::NoMatch)
}

fn untrusted() -> crate::Result<PeerIdentityResult> {
    PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::UntrustedProxy)
}

fn workload_identity(
    context: &PeerResolutionContext,
    id: &str,
    trust_domain: &str,
    evidence_source: &str,
    attributes: BTreeMap<String, Value>,
) -> crate::Result<PeerIdentityResult> {
    let identity = PeerIdentity::new(
        PROVIDER,
        evidence_source,
        IdentityAssurance::ConfiguredProxy,
        format!("spiffe://{trust_domain}"),
        "http",
    )?
    .with_subject(SubjectKind::Workload, id, SubjectStability::Stable, true)?
    .with_attributes(attributes)?
    .with_addresses(
        context.asserted_peer().map(str::to_owned),
        context.immediate_peer().map(str::to_owned),
    );
    Ok(PeerIdentityResult::available(identity))
}

/// Configuration for one strict Envoy `SANITIZE_SET` XFCC header.
#[derive(Clone, Debug)]
pub struct EnvoyXfccSpiffeConfig {
    pub proxy: SpiffeProxyConfig,
    pub header: String,
}

impl EnvoyXfccSpiffeConfig {
    pub fn new(proxy: SpiffeProxyConfig) -> Self {
        Self {
            proxy,
            header: "X-Forwarded-Client-Cert".into(),
        }
    }

    pub fn with_header(mut self, header: impl Into<String>) -> crate::Result<Self> {
        self.header = header.into();
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> crate::Result<()> {
        self.proxy.validate()?;
        if !is_http_field_name(&self.header) {
            return Err(RpcError::value_error("invalid Envoy XFCC header name"));
        }
        Ok(())
    }
}

/// Consume exactly one text-format XFCC element emitted by adjacent Envoy in
/// `SANITIZE_SET` mode.
pub fn envoy_xfcc_spiffe_provider(
    config: EnvoyXfccSpiffeConfig,
) -> crate::Result<PeerIdentityProvider> {
    config.validate()?;
    PeerIdentityProvider::new(PROVIDER, move |context| resolve_envoy(&config, context))
}

fn resolve_envoy(
    config: &EnvoyXfccSpiffeConfig,
    context: &PeerResolutionContext,
) -> crate::Result<PeerIdentityResult> {
    if !config.proxy.trusts(context) {
        return untrusted();
    }
    let raw = match context.header(&config.header) {
        Ok(Some(raw)) => raw,
        Ok(None) => return no_match(),
        Err(_) => return invalid(),
    };
    let fields = match parse_xfcc(raw, config.proxy.max_header_bytes) {
        Ok(fields) => fields,
        Err(()) => return invalid(),
    };
    let Some([uri]) = fields.get("uri").map(Vec::as_slice) else {
        return invalid();
    };
    let Some([hash]) = fields.get("hash").map(Vec::as_slice) else {
        return invalid();
    };
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid();
    }
    let trust_domain = match validate_spiffe_id(uri, &config.proxy.trust_domains) {
        Ok(domain) => domain,
        Err(_) => return invalid(),
    };
    let mut attributes = BTreeMap::from([(
        "certificate_sha256".into(),
        Value::String(hash.to_ascii_lowercase()),
    )]);
    if let Some(by) = fields.get("by") {
        attributes.insert(
            "proxy_identities".into(),
            Value::Array(by.iter().cloned().map(Value::String).collect()),
        );
    }
    workload_identity(
        context,
        uri,
        trust_domain,
        "envoy_xfcc_sanitize_set",
        attributes,
    )
}

fn parse_xfcc(raw: &str, maximum_bytes: usize) -> Result<BTreeMap<String, Vec<String>>, ()> {
    if raw.is_empty()
        || raw.len() > maximum_bytes
        || !raw.is_ascii()
        || raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(());
    }
    let elements = split_xfcc(raw, b',')?;
    if elements.len() != 1 || elements[0].trim().is_empty() {
        return Err(());
    }
    let allowed = BTreeSet::from([
        "by", "hash", "cert", "chain", "subject", "uri", "dns", "issuer",
    ]);
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    for pair in split_xfcc(&elements[0], b';')? {
        let (key_raw, value_raw) = pair.split_once('=').ok_or(())?;
        let key_raw = key_raw.trim();
        let key = key_raw.to_ascii_lowercase();
        if !valid_xfcc_key(key_raw) || !allowed.contains(key.as_str()) {
            return Err(());
        }
        let value = xfcc_value(value_raw.trim())?;
        let value = if matches!(key.as_str(), "by" | "uri" | "cert" | "chain") {
            strict_percent_decode(&value, false)?
        } else {
            value
        };
        if !matches!(key.as_str(), "by" | "uri" | "dns") && fields.contains_key(&key) {
            return Err(());
        }
        fields.entry(key).or_default().push(value);
    }
    Ok(fields)
}

fn split_xfcc(value: &str, delimiter: u8) -> Result<Vec<String>, ()> {
    let mut parts = Vec::new();
    let mut current = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    for byte in value.bytes() {
        if escaped {
            if !matches!(byte, b'"' | b'\\') {
                return Err(());
            }
            current.push(byte);
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
            current.push(byte);
        } else if byte == delimiter && !quoted {
            parts.push(String::from_utf8(current).map_err(|_| ())?);
            current = Vec::new();
        } else {
            current.push(byte);
        }
    }
    if quoted || escaped {
        return Err(());
    }
    parts.push(String::from_utf8(current).map_err(|_| ())?);
    Ok(parts)
}

fn xfcc_value(value: &str) -> Result<String, ()> {
    if value.starts_with('"') || value.ends_with('"') {
        value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .map(str::to_owned)
            .ok_or(())
    } else if value.is_empty() || value.bytes().any(|byte| matches!(byte, b',' | b';' | b'=')) {
        Err(())
    } else {
        Ok(value.to_owned())
    }
}

fn valid_xfcc_key(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Configurable GCP frontend-mTLS custom headers.
#[derive(Clone, Debug)]
pub struct GcpSpiffeConfig {
    pub proxy: SpiffeProxyConfig,
    pub spiffe_id_header: String,
    pub present_header: String,
    pub chain_verified_header: String,
    pub error_header: String,
}

impl GcpSpiffeConfig {
    pub fn new(proxy: SpiffeProxyConfig) -> Self {
        Self {
            proxy,
            spiffe_id_header: "X-Client-Cert-Spiffe-Id".into(),
            present_header: "X-Client-Cert-Present".into(),
            chain_verified_header: "X-Client-Cert-Chain-Verified".into(),
            error_header: "X-Client-Cert-Error".into(),
        }
    }

    pub fn with_headers(
        mut self,
        spiffe_id: impl Into<String>,
        present: impl Into<String>,
        chain_verified: impl Into<String>,
        error: impl Into<String>,
    ) -> crate::Result<Self> {
        self.spiffe_id_header = spiffe_id.into();
        self.present_header = present.into();
        self.chain_verified_header = chain_verified.into();
        self.error_header = error.into();
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> crate::Result<()> {
        self.proxy.validate()?;
        let mut headers = BTreeSet::new();
        for header in [
            &self.spiffe_id_header,
            &self.present_header,
            &self.chain_verified_header,
            &self.error_header,
        ] {
            if !is_http_field_name(header) || !headers.insert(header.to_ascii_lowercase()) {
                return Err(RpcError::value_error(
                    "GCP mTLS headers must be valid and case-insensitively distinct",
                ));
            }
        }
        Ok(())
    }
}

pub fn gcp_load_balancer_spiffe_provider(
    config: GcpSpiffeConfig,
) -> crate::Result<PeerIdentityProvider> {
    config.validate()?;
    PeerIdentityProvider::new(PROVIDER, move |context| resolve_gcp(&config, context))
}

fn resolve_gcp(
    config: &GcpSpiffeConfig,
    context: &PeerResolutionContext,
) -> crate::Result<PeerIdentityResult> {
    if !config.proxy.trusts(context) {
        return untrusted();
    }
    let values = (
        context.header(&config.spiffe_id_header),
        context.header(&config.present_header),
        context.header(&config.chain_verified_header),
        context.header(&config.error_header),
    );
    let (Ok(id), Ok(present), Ok(verified), Ok(failure)) = values else {
        return invalid();
    };
    if present == Some("false") && verified.is_none_or(|value| value == "false") && id.is_none() {
        return no_match();
    }
    if present != Some("true")
        || verified != Some("true")
        || failure.is_some_and(|value| !value.is_empty())
        || id.is_none_or(str::is_empty)
    {
        return invalid();
    }
    let id = id.expect("checked above");
    if id.len() > config.proxy.max_header_bytes {
        return invalid();
    }
    let trust_domain = match validate_spiffe_id(id, &config.proxy.trust_domains) {
        Ok(domain) => domain,
        Err(_) => return invalid(),
    };
    workload_identity(
        context,
        id,
        trust_domain,
        "gcp_load_balancer_mtls",
        BTreeMap::from([
            ("client_certificate_present".into(), Value::Bool(true)),
            (
                "client_certificate_chain_verified".into(),
                Value::Bool(true),
            ),
        ]),
    )
}

#[cfg(feature = "mtls-pem")]
/// Generic verified client-certificate header configuration.
#[derive(Clone, Debug)]
pub struct SpiffeCertificateHeaderConfig {
    pub proxy: SpiffeProxyConfig,
    pub certificate_header: String,
    pub verification_header: String,
    pub verification_value: String,
    pub evidence_source: String,
}

#[cfg(feature = "mtls-pem")]
impl SpiffeCertificateHeaderConfig {
    pub fn new(proxy: SpiffeProxyConfig, verification_header: impl Into<String>) -> Self {
        Self {
            proxy,
            certificate_header: "X-SSL-Client-Cert".into(),
            verification_header: verification_header.into(),
            verification_value: "true".into(),
            evidence_source: "verified_certificate_header".into(),
        }
    }

    pub fn with_profile(
        mut self,
        certificate_header: impl Into<String>,
        verification_value: impl Into<String>,
        evidence_source: impl Into<String>,
    ) -> crate::Result<Self> {
        self.certificate_header = certificate_header.into();
        self.verification_value = verification_value.into();
        self.evidence_source = evidence_source.into();
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> crate::Result<()> {
        self.proxy.validate()?;
        if !is_http_field_name(&self.certificate_header)
            || !is_http_field_name(&self.verification_header)
            || self
                .certificate_header
                .eq_ignore_ascii_case(&self.verification_header)
            || self.verification_value.len() > 64
            || contains_control(&self.verification_value)
            || self.evidence_source.is_empty()
            || contains_control(&self.evidence_source)
        {
            return Err(RpcError::value_error(
                "invalid or ambiguous verified-certificate header profile",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "mtls-pem")]
pub fn spiffe_certificate_header_provider(
    config: SpiffeCertificateHeaderConfig,
) -> crate::Result<PeerIdentityProvider> {
    config.validate()?;
    certificate_provider(config, true)
}

#[cfg(feature = "mtls-pem")]
pub fn nginx_spiffe_provider(proxy: SpiffeProxyConfig) -> crate::Result<PeerIdentityProvider> {
    let config = SpiffeCertificateHeaderConfig::new(proxy, "X-SSL-Client-Verify").with_profile(
        "X-SSL-Client-Cert",
        "SUCCESS",
        "nginx_mtls",
    )?;
    certificate_provider(config, true)
}

#[cfg(feature = "mtls-pem")]
pub fn azure_application_gateway_spiffe_provider(
    proxy: SpiffeProxyConfig,
) -> crate::Result<PeerIdentityProvider> {
    let config = SpiffeCertificateHeaderConfig::new(proxy, "X-Client-Certificate-Verification")
        .with_profile(
            "X-Client-Certificate",
            "SUCCESS",
            "azure_application_gateway_mtls_strict",
        )?;
    certificate_provider(config, true)
}

#[cfg(feature = "mtls-pem")]
/// Consume ALB's leaf header under the operator's explicit declaration that
/// the adjacent listener is configured in mTLS verify mode, never passthrough.
pub fn aws_alb_spiffe_provider(proxy: SpiffeProxyConfig) -> crate::Result<PeerIdentityProvider> {
    let config = SpiffeCertificateHeaderConfig {
        proxy,
        certificate_header: "X-Amzn-Mtls-Clientcert-Leaf".into(),
        verification_header: "X-VGI-Unused".into(),
        verification_value: String::new(),
        evidence_source: "aws_alb_mtls_verify".into(),
    };
    config.proxy.validate()?;
    certificate_provider(config, false)
}

#[cfg(feature = "mtls-pem")]
fn certificate_provider(
    config: SpiffeCertificateHeaderConfig,
    require_verification: bool,
) -> crate::Result<PeerIdentityProvider> {
    PeerIdentityProvider::new(PROVIDER, move |context| {
        resolve_certificate(&config, require_verification, context)
    })
}

#[cfg(feature = "mtls-pem")]
fn resolve_certificate(
    config: &SpiffeCertificateHeaderConfig,
    require_verification: bool,
    context: &PeerResolutionContext,
) -> crate::Result<PeerIdentityResult> {
    if !config.proxy.trusts(context) {
        return untrusted();
    }
    let raw = match context.header(&config.certificate_header) {
        Ok(Some(raw)) if !raw.is_empty() => raw,
        Ok(_) => return no_match(),
        Err(_) => return invalid(),
    };
    if require_verification {
        match context.header(&config.verification_header) {
            Ok(Some(value))
                if value.len() <= 64
                    && value.as_bytes() == config.verification_value.as_bytes() => {}
            _ => return invalid(),
        }
    }
    let (id, trust_domain) = match certificate_spiffe_id(raw, &config.proxy) {
        Ok(value) => value,
        Err(()) => return invalid(),
    };
    workload_identity(
        context,
        &id,
        &trust_domain,
        &config.evidence_source,
        BTreeMap::new(),
    )
}

#[cfg(feature = "mtls-pem")]
fn certificate_spiffe_id(raw: &str, proxy: &SpiffeProxyConfig) -> Result<(String, String), ()> {
    use x509_parser::pem::parse_x509_pem;

    if raw.len() > proxy.max_header_bytes || !raw.is_ascii() || contains_control(raw) {
        return Err(());
    }
    let decoded = strict_percent_decode(raw, true)?;
    if decoded.len() > proxy.max_header_bytes || !decoded.starts_with("-----BEGIN CERTIFICATE-----")
    {
        return Err(());
    }
    let (trailing, pem) = parse_x509_pem(decoded.as_bytes()).map_err(|_| ())?;
    if pem.label != "CERTIFICATE" || trailing.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(());
    }
    crate::auth::spiffe_x509::x509_svid_from_der(&pem.contents, &proxy.trust_domains)
}

fn strict_percent_decode(value: &str, certificate: bool) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(());
            }
            index += 2;
            (hex(bytes[index - 1])? << 4) | hex(bytes[index])?
        } else {
            bytes[index]
        };
        if certificate {
            if !byte.is_ascii() || byte == 0x7f || (byte < 0x20 && !matches!(byte, b'\r' | b'\n')) {
                return Err(());
            }
        } else if byte < 0x20 || byte == 0x7f {
            return Err(());
        }
        decoded.push(byte);
        index += 1;
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn hex(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(feature = "mtls-pem")]
fn contains_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character <= '\u{1f}' || character == '\u{7f}')
}

fn is_http_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn proxy() -> SpiffeProxyConfig {
        SpiffeProxyConfig::new(["example.org"], ["127.0.0.1"]).unwrap()
    }

    fn context(headers: BTreeMap<String, Vec<String>>) -> PeerResolutionContext {
        PeerResolutionContext::new("http")
            .unwrap()
            .with_peers(Some("127.0.0.1"), Some("10.0.0.7:1234"))
            .with_headers(headers)
            .unwrap()
    }

    fn headers(values: &BTreeMap<String, String>) -> BTreeMap<String, Vec<String>> {
        values
            .iter()
            .map(|(name, value)| (name.clone(), vec![value.clone()]))
            .collect()
    }

    #[derive(Deserialize)]
    struct Vectors {
        version: u32,
        spiffe_id_cases: Vec<ValueCase>,
        envoy_xfcc_cases: Vec<ValueCase>,
        gcp_cases: Vec<HeaderCase>,
    }

    #[derive(Deserialize)]
    struct ValueCase {
        #[allow(dead_code)]
        name: String,
        value: String,
        expected: String,
    }

    #[derive(Deserialize)]
    struct HeaderCase {
        #[allow(dead_code)]
        name: String,
        headers: BTreeMap<String, String>,
        expected: String,
    }

    fn expected(value: &str) -> PeerIdentityStatus {
        match value {
            "available" => PeerIdentityStatus::Available,
            "invalid" => PeerIdentityStatus::Invalid,
            "no_match" => PeerIdentityStatus::NoMatch,
            other => panic!("unexpected vector status {other}"),
        }
    }

    #[test]
    fn canonical_transport_identity_vectors() {
        let vectors: Vectors = serde_json::from_str(include_str!(
            "../../tests/data/transport_identity_vectors.json"
        ))
        .unwrap();
        assert_eq!(vectors.version, 1);
        for case in vectors.spiffe_id_cases {
            assert_eq!(
                validate_spiffe_id(&case.value, &proxy().trust_domains).is_ok(),
                case.expected == "valid",
                "{}",
                case.name
            );
        }
        let envoy = envoy_xfcc_spiffe_provider(EnvoyXfccSpiffeConfig::new(proxy())).unwrap();
        for case in vectors.envoy_xfcc_cases {
            let result = envoy(&context(BTreeMap::from([(
                "X-Forwarded-Client-Cert".into(),
                vec![case.value],
            )])))
            .unwrap();
            assert_eq!(result.status(), expected(&case.expected), "{}", case.name);
        }
        let gcp = gcp_load_balancer_spiffe_provider(GcpSpiffeConfig::new(proxy())).unwrap();
        for case in vectors.gcp_cases {
            let result = gcp(&context(headers(&case.headers))).unwrap();
            assert_eq!(result.status(), expected(&case.expected), "{}", case.name);
        }
    }

    #[test]
    fn exact_proxy_and_raw_header_ambiguity_fail_closed() {
        let provider = envoy_xfcc_spiffe_provider(EnvoyXfccSpiffeConfig::new(proxy())).unwrap();
        let untrusted = PeerResolutionContext::new("http")
            .unwrap()
            .with_peers(Some("127.0.0.2"), None::<String>);
        assert_eq!(
            provider(&untrusted).unwrap().status(),
            PeerIdentityStatus::UntrustedProxy
        );
        let duplicate = context(BTreeMap::from([(
            "X-Forwarded-Client-Cert".into(),
            vec!["one".into(), "two".into()],
        )]));
        assert_eq!(
            provider(&duplicate).unwrap().status(),
            PeerIdentityStatus::Invalid
        );
        assert!(SpiffeProxyConfig::new(["example.org"], ["localhost"]).is_err());
        assert!(SpiffeProxyConfig::new(["Example.org"], ["127.0.0.1"]).is_err());
    }

    #[test]
    fn envoy_identity_is_stable_configured_proxy_evidence() {
        let provider = envoy_xfcc_spiffe_provider(EnvoyXfccSpiffeConfig::new(proxy())).unwrap();
        let raw = format!(
            "By=spiffe%3A%2F%2Fmesh.example%2Fproxy;Hash={};URI=spiffe%3A%2F%2Fexample.org%2Fworkload",
            "a".repeat(64)
        );
        let result = provider(&context(BTreeMap::from([(
            "X-Forwarded-Client-Cert".into(),
            vec![raw],
        )])))
        .unwrap();
        let identity = &result.identities()[0];
        assert_eq!(identity.assurance(), IdentityAssurance::ConfiguredProxy);
        assert_eq!(identity.subject_kind(), SubjectKind::Workload);
        assert_eq!(identity.subject_stability(), SubjectStability::Stable);
        assert_eq!(
            identity.subject_key(),
            Some("spiffe://example.org/workload")
        );
        assert_eq!(identity.source_address(), Some("10.0.0.7:1234"));
        assert_ne!(identity.subject_key(), identity.source_address());
    }

    #[test]
    fn gcp_requires_every_verified_chain_signal() {
        let provider = gcp_load_balancer_spiffe_provider(GcpSpiffeConfig::new(proxy())).unwrap();
        let invalid = context(BTreeMap::from([
            ("X-Client-Cert-Present".into(), vec!["true".into()]),
            (
                "X-Client-Cert-Spiffe-Id".into(),
                vec!["spiffe://example.org/workload".into()],
            ),
        ]));
        assert_eq!(
            provider(&invalid).unwrap().status(),
            PeerIdentityStatus::Invalid
        );
        let duplicate = context(BTreeMap::from([
            (
                "X-Client-Cert-Present".into(),
                vec!["true".into(), "true".into()],
            ),
            ("X-Client-Cert-Chain-Verified".into(), vec!["true".into()]),
            (
                "X-Client-Cert-Spiffe-Id".into(),
                vec!["spiffe://example.org/workload".into()],
            ),
        ]));
        assert_eq!(
            provider(&duplicate).unwrap().status(),
            PeerIdentityStatus::Invalid
        );
    }

    #[cfg(feature = "mtls-pem")]
    fn encoded_certificate() -> String {
        include_str!("../../tests/data/spiffe-test-cert.pem")
            .bytes()
            .flat_map(|byte| {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                    vec![char::from(byte)].into_iter()
                } else {
                    format!("%{byte:02X}")
                        .chars()
                        .collect::<Vec<_>>()
                        .into_iter()
                }
            })
            .collect()
    }

    #[cfg(feature = "mtls-pem")]
    #[test]
    fn named_certificate_profiles_require_their_trust_signals() {
        let certificate = encoded_certificate();
        for (provider, certificate_header, verification_header, source) in [
            (
                nginx_spiffe_provider(proxy()).unwrap(),
                "X-SSL-Client-Cert",
                "X-SSL-Client-Verify",
                "nginx_mtls",
            ),
            (
                azure_application_gateway_spiffe_provider(proxy()).unwrap(),
                "X-Client-Certificate",
                "X-Client-Certificate-Verification",
                "azure_application_gateway_mtls_strict",
            ),
        ] {
            let missing = context(BTreeMap::from([(
                certificate_header.into(),
                vec![certificate.clone()],
            )]));
            assert_eq!(
                provider(&missing).unwrap().status(),
                PeerIdentityStatus::Invalid
            );
            let available = context(BTreeMap::from([
                (certificate_header.into(), vec![certificate.clone()]),
                (verification_header.into(), vec!["SUCCESS".into()]),
            ]));
            let result = provider(&available).unwrap();
            assert_eq!(result.status(), PeerIdentityStatus::Available);
            assert_eq!(result.identities()[0].evidence_source(), source);
        }

        let aws = aws_alb_spiffe_provider(proxy()).unwrap();
        let duplicate = context(BTreeMap::from([(
            "X-Amzn-Mtls-Clientcert-Leaf".into(),
            vec![certificate.clone(), certificate.clone()],
        )]));
        assert_eq!(
            aws(&duplicate).unwrap().status(),
            PeerIdentityStatus::Invalid
        );
        let result = aws(&context(BTreeMap::from([(
            "X-Amzn-Mtls-Clientcert-Leaf".into(),
            vec![certificate],
        )])))
        .unwrap();
        assert_eq!(result.status(), PeerIdentityStatus::Available);
        assert_eq!(
            result.identities()[0].assurance(),
            IdentityAssurance::ConfiguredProxy
        );
        assert_eq!(
            result.identities()[0].evidence_source(),
            "aws_alb_mtls_verify"
        );
    }

    #[cfg(feature = "mtls-pem")]
    #[test]
    fn certificate_profiles_reject_wrong_domain_malformed_and_duplicate_pem() {
        let aws = aws_alb_spiffe_provider(proxy()).unwrap();
        for certificate in [
            "%ZZ".to_owned(),
            encoded_certificate() + &encoded_certificate(),
        ] {
            let result = aws(&context(BTreeMap::from([(
                "X-Amzn-Mtls-Clientcert-Leaf".into(),
                vec![certificate],
            )])))
            .unwrap();
            assert_eq!(result.status(), PeerIdentityStatus::Invalid);
        }
        let wrong_domain = SpiffeProxyConfig::new(["other.org"], ["127.0.0.1"]).unwrap();
        let aws = aws_alb_spiffe_provider(wrong_domain).unwrap();
        let result = aws(&context(BTreeMap::from([(
            "X-Amzn-Mtls-Clientcert-Leaf".into(),
            vec![encoded_certificate()],
        )])))
        .unwrap();
        assert_eq!(result.status(), PeerIdentityStatus::Invalid);
    }
}
