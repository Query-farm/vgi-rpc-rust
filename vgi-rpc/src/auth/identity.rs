//! Transport-neutral peer identity evidence and authentication policies.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::unauthorized::AuthReason;
use crate::{AuthContext, RpcError};

const EVIDENCE_BINDING_CLAIM: &str = "peer_evidence_binding";
const MAX_JSON_BYTES: usize = 65_536;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_VALUES: usize = 4_096;
const MAX_HEADER_COUNT: usize = 128;
const MAX_HEADER_VALUES: usize = 16;
const MAX_HEADER_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerIdentityStatus {
    Off,
    NotApplicable,
    Available,
    Unavailable,
    PermissionDenied,
    NoMatch,
    Invalid,
    UntrustedProxy,
}

impl PeerIdentityStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::NotApplicable => "not_applicable",
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::PermissionDenied => "permission_denied",
            Self::NoMatch => "no_match",
            Self::Invalid => "invalid",
            Self::UntrustedProxy => "untrusted_proxy",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAssurance {
    CryptographicPeer,
    LocalDaemon,
    ConfiguredProxy,
}

impl IdentityAssurance {
    fn as_str(self) -> &'static str {
        match self {
            Self::CryptographicPeer => "cryptographic_peer",
            Self::LocalDaemon => "local_daemon",
            Self::ConfiguredProxy => "configured_proxy",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKind {
    User,
    TaggedNode,
    Workload,
    Endpoint,
    Unknown,
}

impl SubjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::TaggedNode => "tagged_node",
            Self::Workload => "workload",
            Self::Endpoint => "endpoint",
            Self::Unknown => "unknown",
        }
    }
}

impl SubjectStability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Login => "login",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectStability {
    Stable,
    Login,
    None,
}

/// Provider-neutral, immutable snapshot of one transport peer and destination.
#[derive(Clone, Debug)]
pub struct PeerResolutionContext {
    transport: Arc<str>,
    immediate_peer: Option<Arc<str>>,
    asserted_peer: Option<Arc<str>>,
    source_endpoint: Option<Arc<str>>,
    destination_address: Option<Arc<str>>,
    authority: Option<Arc<str>>,
    service_name: Option<Arc<str>>,
    headers: Arc<BTreeMap<String, Arc<[String]>>>,
    metadata: Arc<BTreeMap<String, Value>>,
    deadline: Option<Instant>,
}

impl PeerResolutionContext {
    pub fn new(transport: impl Into<String>) -> crate::Result<Self> {
        let transport = transport.into();
        if transport.is_empty() {
            return Err(RpcError::value_error("peer transport must not be empty"));
        }
        Ok(Self {
            transport: Arc::from(transport),
            immediate_peer: None,
            asserted_peer: None,
            source_endpoint: None,
            destination_address: None,
            authority: None,
            service_name: None,
            headers: Arc::new(BTreeMap::new()),
            metadata: Arc::new(BTreeMap::new()),
            deadline: None,
        })
    }

    pub fn with_peers(
        mut self,
        immediate_peer: Option<impl Into<String>>,
        asserted_peer: Option<impl Into<String>>,
    ) -> Self {
        self.immediate_peer = immediate_peer.map(|value| Arc::from(value.into()));
        self.asserted_peer = asserted_peer.map(|value| Arc::from(value.into()));
        self
    }

    /// Preserve the raw transport source endpoint for providers that must
    /// query an adjacent identity authority (for example LocalAPI WhoIs).
    /// Header-based proxy adapters must continue to use `immediate_peer` as
    /// their exact trust boundary and must not promote this value to identity.
    pub fn with_source_endpoint(mut self, endpoint: Option<impl Into<String>>) -> Self {
        self.source_endpoint = endpoint.map(|value| Arc::from(value.into()));
        self
    }

    pub fn with_destination(
        mut self,
        destination_address: Option<impl Into<String>>,
        service_name: Option<impl Into<String>>,
    ) -> Self {
        self.destination_address = destination_address.map(|value| Arc::from(value.into()));
        self.service_name = service_name.map(|value| Arc::from(value.into()));
        self
    }

    pub fn with_authority(mut self, authority: Option<impl Into<String>>) -> Self {
        self.authority = authority.map(|value| Arc::from(value.into()));
        self
    }

    pub fn with_headers(
        mut self,
        headers: impl IntoIterator<Item = (String, Vec<String>)>,
    ) -> crate::Result<Self> {
        let mut normalized = BTreeMap::new();
        let mut header_bytes = 0usize;
        for (name, values) in headers {
            if normalized.len() >= MAX_HEADER_COUNT {
                return Err(RpcError::permission_error("too many peer identity headers"));
            }
            if !is_http_field_name(&name) {
                return Err(RpcError::value_error("invalid peer-resolution header name"));
            }
            if values.len() > MAX_HEADER_VALUES {
                return Err(RpcError::permission_error(format!(
                    "too many values for peer identity header: {name}"
                )));
            }
            if values.iter().any(|value| contains_control(value)) {
                return Err(RpcError::value_error(format!(
                    "invalid peer-resolution header value: {name}"
                )));
            }
            header_bytes = header_bytes
                .saturating_add(name.len())
                .saturating_add(values.iter().map(String::len).sum::<usize>());
            if header_bytes > MAX_HEADER_BYTES {
                return Err(RpcError::permission_error(
                    "peer identity headers are too large",
                ));
            }
            let key = name.to_ascii_lowercase();
            if normalized.insert(key, Arc::from(values)).is_some() {
                return Err(RpcError::permission_error(
                    "case-varied duplicate peer identity header",
                ));
            }
        }
        self.headers = Arc::new(normalized);
        Ok(self)
    }

    pub fn with_metadata(mut self, metadata: BTreeMap<String, Value>) -> crate::Result<Self> {
        validate_json_object(&metadata, "peer metadata")?;
        self.metadata = Arc::new(metadata);
        Ok(self)
    }

    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn transport(&self) -> &str {
        &self.transport
    }

    pub fn immediate_peer(&self) -> Option<&str> {
        self.immediate_peer.as_deref()
    }

    pub fn asserted_peer(&self) -> Option<&str> {
        self.asserted_peer.as_deref()
    }

    pub fn source_endpoint(&self) -> Option<&str> {
        self.source_endpoint.as_deref()
    }

    pub fn destination_address(&self) -> Option<&str> {
        self.destination_address.as_deref()
    }

    pub fn authority(&self) -> Option<&str> {
        self.authority.as_deref()
    }

    pub fn service_name(&self) -> Option<&str> {
        self.service_name.as_deref()
    }

    pub fn header(&self, name: &str) -> crate::Result<Option<&str>> {
        let Some(values) = self.headers.get(&name.to_ascii_lowercase()) else {
            return Ok(None);
        };
        match values.as_ref() {
            [] => Ok(None),
            [value] => Ok(Some(value)),
            _ => Err(RpcError::permission_error(format!(
                "duplicate peer identity header: {name}"
            ))),
        }
    }

    pub fn metadata(&self) -> &BTreeMap<String, Value> {
        &self.metadata
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Remaining total provider budget measured exclusively with Rust's
    /// monotonic [`Instant`] clock.
    pub fn remaining_time(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }
}

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

/// Immutable peer identity with structured JSON attributes and capabilities.
#[derive(Clone, Debug)]
pub struct PeerIdentity {
    provider: Arc<str>,
    evidence_source: Arc<str>,
    assurance: IdentityAssurance,
    issuer: Arc<str>,
    transport: Arc<str>,
    subject_kind: SubjectKind,
    subject_key: Option<Arc<str>>,
    subject_stability: SubjectStability,
    subject_verified: bool,
    attributes: Arc<BTreeMap<String, Value>>,
    capabilities: Arc<BTreeMap<String, Value>>,
    capabilities_verified: bool,
    source_address: Option<Arc<str>>,
    proxy_address: Option<Arc<str>>,
}

impl PeerIdentity {
    pub fn new(
        provider: impl Into<String>,
        evidence_source: impl Into<String>,
        assurance: IdentityAssurance,
        issuer: impl Into<String>,
        transport: impl Into<String>,
    ) -> crate::Result<Self> {
        let provider = provider.into();
        let evidence_source = evidence_source.into();
        let issuer = issuer.into();
        let transport = transport.into();
        if provider.is_empty()
            || evidence_source.is_empty()
            || issuer.is_empty()
            || transport.is_empty()
        {
            return Err(RpcError::value_error(
                "provider, evidence_source, issuer, and transport are required",
            ));
        }
        Ok(Self {
            provider: Arc::from(provider),
            evidence_source: Arc::from(evidence_source),
            assurance,
            issuer: Arc::from(issuer),
            transport: Arc::from(transport),
            subject_kind: SubjectKind::Unknown,
            subject_key: None,
            subject_stability: SubjectStability::None,
            subject_verified: false,
            attributes: Arc::new(BTreeMap::new()),
            capabilities: Arc::new(BTreeMap::new()),
            capabilities_verified: false,
            source_address: None,
            proxy_address: None,
        })
    }

    pub fn with_subject(
        mut self,
        kind: SubjectKind,
        key: impl Into<String>,
        stability: SubjectStability,
        verified: bool,
    ) -> crate::Result<Self> {
        let key = key.into();
        if key.is_empty() {
            return Err(RpcError::value_error("peer subject key must not be empty"));
        }
        self.subject_kind = kind;
        self.subject_key = Some(Arc::from(key));
        self.subject_stability = stability;
        self.subject_verified = verified;
        Ok(self)
    }

    pub fn with_attributes(mut self, attributes: BTreeMap<String, Value>) -> crate::Result<Self> {
        validate_json_object(&attributes, "peer attributes")?;
        self.attributes = Arc::new(attributes);
        Ok(self)
    }

    pub fn with_capabilities(
        mut self,
        capabilities: BTreeMap<String, Value>,
        verified: bool,
    ) -> crate::Result<Self> {
        validate_json_object(&capabilities, "peer capabilities")?;
        self.capabilities = Arc::new(capabilities);
        self.capabilities_verified = verified;
        Ok(self)
    }

    pub fn with_addresses(
        mut self,
        source_address: Option<impl Into<String>>,
        proxy_address: Option<impl Into<String>>,
    ) -> Self {
        self.source_address = source_address.map(|value| Arc::from(value.into()));
        self.proxy_address = proxy_address.map(|value| Arc::from(value.into()));
        self
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn evidence_source(&self) -> &str {
        &self.evidence_source
    }
    pub fn assurance(&self) -> IdentityAssurance {
        self.assurance
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn transport(&self) -> &str {
        &self.transport
    }
    pub fn subject_kind(&self) -> SubjectKind {
        self.subject_kind
    }
    pub fn subject_key(&self) -> Option<&str> {
        self.subject_key.as_deref()
    }
    pub fn subject_stability(&self) -> SubjectStability {
        self.subject_stability
    }
    pub fn subject_verified(&self) -> bool {
        self.subject_verified
    }
    pub fn attributes(&self) -> &BTreeMap<String, Value> {
        &self.attributes
    }
    pub fn capabilities(&self) -> &BTreeMap<String, Value> {
        &self.capabilities
    }
    pub fn capabilities_verified(&self) -> bool {
        self.capabilities_verified
    }
    pub fn source_address(&self) -> Option<&str> {
        self.source_address.as_deref()
    }
    pub fn proxy_address(&self) -> Option<&str> {
        self.proxy_address.as_deref()
    }

    pub fn canonical_principal(&self) -> crate::Result<String> {
        let subject = self.subject_key().ok_or_else(|| {
            RpcError::value_error("subjectless evidence has no canonical principal")
        })?;
        Ok(format!(
            "peer/{}/{}/{}",
            percent_encode(self.provider()),
            percent_encode(self.issuer()),
            percent_encode(subject)
        ))
    }
}

fn validate_json_object(value: &BTreeMap<String, Value>, path: &str) -> crate::Result<()> {
    let mut values = 1usize;
    let mut source_bytes = value.keys().map(String::len).sum::<usize>();
    for item in value.values() {
        validate_json_value(item, path, 1, &mut values, &mut source_bytes)?;
    }
    let encoded = serde_json::to_vec(value)
        .map_err(|_| RpcError::value_error(format!("{path} is not valid JSON")))?;
    if encoded.len() > MAX_JSON_BYTES {
        return Err(RpcError::value_error(format!(
            "{path} exceeds maximum JSON byte size"
        )));
    }
    Ok(())
}

fn validate_json_value(
    value: &Value,
    path: &str,
    depth: usize,
    values: &mut usize,
    source_bytes: &mut usize,
) -> crate::Result<()> {
    if depth > MAX_JSON_DEPTH {
        return Err(RpcError::value_error(format!(
            "{path} exceeds maximum JSON depth"
        )));
    }
    *values = values.saturating_add(1);
    if *values > MAX_JSON_VALUES {
        return Err(RpcError::value_error(format!(
            "{path} exceeds maximum JSON value count"
        )));
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::String(text) => {
            *source_bytes = source_bytes.saturating_add(text.len());
        }
        Value::Array(items) => {
            for item in items {
                validate_json_value(item, path, depth + 1, values, source_bytes)?;
            }
        }
        Value::Object(items) => {
            *source_bytes =
                source_bytes.saturating_add(items.keys().map(String::len).sum::<usize>());
            for item in items.values() {
                validate_json_value(item, path, depth + 1, values, source_bytes)?;
            }
        }
    }
    if *source_bytes > MAX_JSON_BYTES {
        return Err(RpcError::value_error(format!(
            "{path} exceeds maximum JSON byte size"
        )));
    }
    Ok(())
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

#[derive(Clone, Debug)]
pub struct PeerIdentityResult {
    provider: Arc<str>,
    status: PeerIdentityStatus,
    identities: Arc<[PeerIdentity]>,
}

impl PeerIdentityResult {
    pub fn available(identity: PeerIdentity) -> Self {
        Self {
            provider: Arc::clone(&identity.provider),
            status: PeerIdentityStatus::Available,
            identities: Arc::from([identity]),
        }
    }

    pub fn without_identity(
        provider: impl Into<String>,
        status: PeerIdentityStatus,
    ) -> crate::Result<Self> {
        if status == PeerIdentityStatus::Available {
            return Err(RpcError::value_error(
                "available peer identity result requires an identity",
            ));
        }
        let provider = provider.into();
        if provider.is_empty()
            || !provider
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(RpcError::value_error(
                "peer identity provider must be a non-empty safe identifier",
            ));
        }
        Ok(Self {
            provider: Arc::from(provider),
            status,
            identities: Arc::from([]),
        })
    }

    pub fn available_many(
        provider: impl Into<String>,
        identities: impl IntoIterator<Item = PeerIdentity>,
    ) -> crate::Result<Self> {
        let provider = provider.into();
        let identities: Vec<_> = identities.into_iter().collect();
        if provider.is_empty() || identities.is_empty() {
            return Err(RpcError::value_error(
                "available peer identity result requires provider and identities",
            ));
        }
        if identities
            .iter()
            .any(|identity| identity.provider() != provider)
        {
            return Err(RpcError::value_error("peer identity provider mismatch"));
        }
        Ok(Self {
            provider: Arc::from(provider),
            status: PeerIdentityStatus::Available,
            identities: Arc::from(identities),
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn status(&self) -> PeerIdentityStatus {
        self.status
    }
    pub fn identities(&self) -> &[PeerIdentity] {
        &self.identities
    }
}

#[derive(Clone, Debug, Default)]
pub struct PeerEvidenceSet {
    identities: Arc<[PeerIdentity]>,
    provider_status: Arc<BTreeMap<String, PeerIdentityStatus>>,
}

impl PeerEvidenceSet {
    pub fn from_results(
        results: impl IntoIterator<Item = PeerIdentityResult>,
    ) -> crate::Result<Self> {
        let mut identities = Vec::new();
        let mut provider_status = BTreeMap::new();
        for result in results {
            if provider_status.contains_key(result.provider()) {
                return Err(RpcError::value_error("duplicate peer identity provider"));
            }
            if (result.status() == PeerIdentityStatus::Available) != !result.identities().is_empty()
            {
                return Err(RpcError::value_error(
                    "invalid peer identity provider result",
                ));
            }
            if result
                .identities()
                .iter()
                .any(|identity| identity.provider() != result.provider())
            {
                return Err(RpcError::value_error("peer identity provider mismatch"));
            }
            provider_status.insert(result.provider().to_owned(), result.status());
            identities.extend(result.identities().iter().cloned());
        }
        Ok(Self {
            identities: Arc::from(identities),
            provider_status: Arc::new(provider_status),
        })
    }

    pub fn identities(&self) -> &[PeerIdentity] {
        &self.identities
    }
    pub fn provider_status(&self) -> &BTreeMap<String, PeerIdentityStatus> {
        &self.provider_status
    }

    pub fn status(&self, provider: &str) -> PeerIdentityStatus {
        self.provider_status
            .get(provider)
            .copied()
            .unwrap_or(PeerIdentityStatus::Off)
    }

    pub fn for_provider<'a>(
        &'a self,
        provider: &str,
    ) -> impl Iterator<Item = &'a PeerIdentity> + 'a {
        let provider = provider.to_owned();
        self.identities
            .iter()
            .filter(move |identity| identity.provider() == provider)
    }

    pub fn unique_verified_subject(&self, provider: &str) -> crate::Result<&PeerIdentity> {
        let mut matches = self.for_provider(provider).filter(|identity| {
            identity.subject_verified()
                && identity.subject_key().is_some()
                && identity.subject_stability() == SubjectStability::Stable
        });
        let Some(identity) = matches.next() else {
            return Err(RpcError::permission_error(format!(
                "provider {provider:?} did not produce one verified stable subject"
            )));
        };
        if matches.next().is_some() {
            return Err(RpcError::permission_error(format!(
                "provider {provider:?} produced multiple verified stable subjects"
            )));
        }
        Ok(identity)
    }

    pub fn reject_ambiguous_provider(&self, provider: &str) -> crate::Result<()> {
        let count = self
            .for_provider(provider)
            .filter(|identity| {
                identity.subject_verified()
                    && identity.subject_key().is_some()
                    && identity.subject_stability() == SubjectStability::Stable
            })
            .take(2)
            .count();
        if count > 1 {
            return Err(RpcError::auth_failure(
                AuthReason::InvalidCredential,
                format!("provider {provider:?} produced ambiguous verified subjects"),
            ));
        }
        Ok(())
    }

    pub fn require_usable_provider(&self, provider: &str) -> crate::Result<&PeerIdentity> {
        match self.status(provider) {
            PeerIdentityStatus::Unavailable | PeerIdentityStatus::PermissionDenied => {
                return Err(RpcError::auth_unavailable(format!(
                    "peer identity provider {provider:?} is unavailable"
                )));
            }
            PeerIdentityStatus::Invalid => {
                return Err(RpcError::auth_failure(
                    AuthReason::InvalidCredential,
                    format!("peer identity provider {provider:?} rejected evidence"),
                ));
            }
            PeerIdentityStatus::UntrustedProxy => {
                return Err(RpcError::auth_failure(
                    AuthReason::ProxyRequired,
                    format!("peer identity provider {provider:?} rejected its proxy boundary"),
                ));
            }
            _ => {}
        }
        self.unique_verified_subject(provider)
    }

    /// Require verified evidence from a provider without requiring it to name
    /// a unique stable subject. This is the capability-only authorization
    /// path; primary authentication remains stricter via
    /// [`Self::require_usable_provider`].
    pub fn require_available_provider(&self, provider: &str) -> crate::Result<&[PeerIdentity]> {
        match self.status(provider) {
            PeerIdentityStatus::Unavailable | PeerIdentityStatus::PermissionDenied => {
                return Err(RpcError::auth_unavailable(format!(
                    "peer identity provider {provider:?} is unavailable"
                )));
            }
            PeerIdentityStatus::Invalid => {
                return Err(RpcError::auth_failure(
                    AuthReason::InvalidCredential,
                    format!("peer identity provider {provider:?} rejected evidence"),
                ));
            }
            PeerIdentityStatus::UntrustedProxy => {
                return Err(RpcError::auth_failure(
                    AuthReason::ProxyRequired,
                    format!("peer identity provider {provider:?} rejected its proxy boundary"),
                ));
            }
            PeerIdentityStatus::Available => {}
            _ => {
                return Err(RpcError::permission_error(format!(
                    "peer identity provider {provider:?} did not produce evidence"
                )));
            }
        }
        let start = self
            .identities
            .iter()
            .position(|identity| identity.provider() == provider);
        let Some(start) = start else {
            return Err(RpcError::permission_error(format!(
                "peer identity provider {provider:?} did not produce evidence"
            )));
        };
        // `from_results` appends each unique provider's block contiguously, so
        // expose the original immutable slice without allocating references.
        let len = self.identities[start..]
            .iter()
            .take_while(|identity| identity.provider() == provider)
            .count();
        Ok(&self.identities[start..start + len])
    }

    pub fn binding_digest<'a>(&self, providers: impl IntoIterator<Item = &'a str>) -> String {
        self.binding_digest_inner(providers.into_iter().collect(), None)
    }

    pub fn application_binding_digest<'a>(
        &self,
        providers: impl IntoIterator<Item = &'a str>,
        application_auth: &AuthContext,
    ) -> String {
        self.binding_digest_inner(providers.into_iter().collect(), Some(application_auth))
    }

    fn binding_digest_inner(
        &self,
        mut providers: Vec<&str>,
        application_auth: Option<&AuthContext>,
    ) -> String {
        providers.sort_unstable();
        providers.dedup();
        let mut hasher = Sha256::new();
        for provider in providers {
            hash_field(&mut hasher, provider);
            hash_field(&mut hasher, self.status(provider).as_str());
            let mut identities: Vec<_> = self
                .for_provider(provider)
                .map(|identity| {
                    vec![
                        identity.provider().to_owned(),
                        identity.issuer().to_owned(),
                        identity.subject_key().unwrap_or("").to_owned(),
                        identity.assurance().as_str().to_owned(),
                        identity.evidence_source().to_owned(),
                        identity.transport().to_owned(),
                        identity.subject_kind().as_str().to_owned(),
                        identity.subject_stability().as_str().to_owned(),
                        (if identity.subject_verified() {
                            "true"
                        } else {
                            "false"
                        })
                        .to_owned(),
                        (if identity.capabilities_verified() {
                            "true"
                        } else {
                            "false"
                        })
                        .to_owned(),
                        // Addresses are audit/routing observations. NAT source
                        // ports and proxy replicas must not invalidate sticky
                        // state for the same authenticated evidence. Keep the
                        // two empty framed fields for digest compatibility
                        // with the historical no-address vector.
                        String::new(),
                        String::new(),
                        serde_json::to_string(identity.attributes())
                            .expect("peer attributes are JSON"),
                        serde_json::to_string(identity.capabilities())
                            .expect("peer capabilities are JSON"),
                    ]
                })
                .collect();
            identities.sort_unstable();
            for identity in identities {
                for field in identity {
                    hash_field(&mut hasher, &field);
                }
            }
        }
        if let Some(application_auth) = application_auth {
            hash_field(&mut hasher, "application_auth");
            hash_field(&mut hasher, &application_auth.domain);
            hash_field(&mut hasher, &application_auth.principal);
        }
        format!("{:x}", hasher.finalize())
    }
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

/// A named resolver for one provider's evidence from a request snapshot.
///
/// The provider name is part of the adapter rather than only its successful
/// result. This lets orchestration record a timeout, capacity rejection, or
/// typed authority outage as *that provider's* `Unavailable` result without
/// losing valid application authentication or evidence from other providers.
///
/// HTTP and raw-TCP integrations run resolvers on blocking threads and bound
/// how long a request or connection waits. Providers that perform I/O must
/// also honor [`PeerResolutionContext::deadline`], because a timed-out blocking
/// call retains its concurrency permit until it actually exits.
#[derive(Clone)]
pub struct PeerIdentityProvider {
    provider: Arc<str>,
    resolver: Arc<PeerIdentityResolver>,
}

type PeerIdentityResolver =
    dyn Fn(&PeerResolutionContext) -> crate::Result<PeerIdentityResult> + Send + Sync;

impl PeerIdentityProvider {
    pub fn new<F>(provider: impl Into<String>, resolver: F) -> crate::Result<Self>
    where
        F: Fn(&PeerResolutionContext) -> crate::Result<PeerIdentityResult> + Send + Sync + 'static,
    {
        let provider = provider.into();
        if provider.is_empty() {
            return Err(RpcError::value_error("peer identity provider is required"));
        }
        Ok(Self {
            provider: Arc::from(provider),
            resolver: Arc::new(resolver),
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn resolve(&self, context: &PeerResolutionContext) -> crate::Result<PeerIdentityResult> {
        (self.resolver)(context)
    }
}

impl std::ops::Deref for PeerIdentityProvider {
    type Target = PeerIdentityResolver;

    fn deref(&self) -> &Self::Target {
        self.resolver.as_ref()
    }
}

pub type PeerIdentityLinker =
    Arc<dyn Fn(&AuthContext, &BTreeMap<String, PeerIdentity>) -> crate::Result<()> + Send + Sync>;

pub type PeerAuthenticationPolicy =
    Arc<dyn Fn(&PeerEvidenceSet, &AuthContext) -> crate::Result<AuthContext> + Send + Sync>;

pub fn observe_peer_identity() -> PeerAuthenticationPolicy {
    Arc::new(|_, auth| Ok(auth.clone()))
}

pub fn require_peer_identity(provider: impl Into<String>) -> PeerAuthenticationPolicy {
    let provider = provider.into();
    Arc::new(move |evidence, auth| {
        evidence.require_available_provider(&provider)?;
        Ok(with_evidence_binding(auth, evidence, [&provider]))
    })
}

pub fn peer_identity_primary(provider: impl Into<String>) -> PeerAuthenticationPolicy {
    let provider = provider.into();
    Arc::new(move |evidence, _| {
        let identity = evidence.require_usable_provider(&provider)?;
        let mut auth = AuthContext::for_principal(&provider, identity.canonical_principal()?);
        auth.claims
            .insert("issuer".into(), identity.issuer().into());
        auth.claims.insert(
            "subject_kind".into(),
            identity.subject_kind().as_str().into(),
        );
        auth.claims
            .insert("assurance".into(), identity.assurance().as_str().into());
        auth.claims
            .insert("evidence_source".into(), identity.evidence_source().into());
        auth.claims.insert(
            "subject".into(),
            identity
                .subject_key()
                .expect("verified subject has a key")
                .into(),
        );
        auth.claims.insert(
            EVIDENCE_BINDING_CLAIM.into(),
            evidence.binding_digest([provider.as_str()]),
        );
        Ok(auth)
    })
}

/// Accept existing application authentication or the first usable peer
/// identity. When application authentication wins, peer evidence remains
/// observation-only and is not bound into that principal. Use
/// [`require_peer_identity`], [`all_of_peer_identities`], or a custom policy
/// when state must be bound to both factors.
pub fn any_of_peer_identities(
    providers: impl IntoIterator<Item = impl Into<String>>,
) -> crate::Result<PeerAuthenticationPolicy> {
    let providers: Arc<[String]> = Arc::from(
        providers
            .into_iter()
            .map(Into::into)
            .collect::<Vec<String>>(),
    );
    if providers.is_empty() {
        return Err(RpcError::value_error("at least one provider is required"));
    }
    Ok(Arc::new(move |evidence, existing_auth| {
        for provider in providers.iter() {
            match evidence.status(provider) {
                PeerIdentityStatus::Invalid | PeerIdentityStatus::UntrustedProxy => {
                    evidence.require_usable_provider(provider)?;
                }
                _ => {}
            }
            if evidence.status(provider) == PeerIdentityStatus::Available {
                evidence.reject_ambiguous_provider(provider)?;
            }
        }
        if existing_auth.authenticated {
            return Ok(existing_auth.clone());
        }
        for provider in providers.iter() {
            if evidence.unique_verified_subject(provider).is_ok() {
                return peer_identity_primary(provider)(evidence, existing_auth);
            }
        }
        if providers.iter().any(|provider| {
            matches!(
                evidence.status(provider),
                PeerIdentityStatus::Unavailable | PeerIdentityStatus::PermissionDenied
            )
        }) {
            return Err(RpcError::auth_unavailable(
                "no usable authentication factor; a peer provider is unavailable",
            ));
        }
        Err(RpcError::permission_error(
            "no configured provider produced a verified subject",
        ))
    }))
}

pub fn all_of_peer_identities(
    providers: impl IntoIterator<Item = impl Into<String>>,
    principal_provider: Option<impl Into<String>>,
    identity_linker: Option<PeerIdentityLinker>,
) -> crate::Result<PeerAuthenticationPolicy> {
    let providers: Arc<[String]> = Arc::from(
        providers
            .into_iter()
            .map(Into::into)
            .collect::<Vec<String>>(),
    );
    if providers.is_empty() {
        return Err(RpcError::value_error("at least one provider is required"));
    }
    let selected = principal_provider
        .map(Into::into)
        .unwrap_or_else(|| providers[0].clone());
    if !providers.iter().any(|provider| provider == &selected) {
        return Err(RpcError::value_error(
            "principal_provider must be one of providers",
        ));
    }
    let identity_linker = identity_linker.ok_or_else(|| {
        RpcError::value_error("all_of requires identity_linker to reject conflicting identities")
    })?;
    Ok(Arc::new(move |evidence, existing_auth| {
        if !existing_auth.authenticated {
            return Err(RpcError::auth_failure(
                AuthReason::MissingCredential,
                "all_of requires existing application authentication",
            ));
        }
        let identities = providers
            .iter()
            .map(|provider| {
                Ok((
                    provider.clone(),
                    evidence.require_usable_provider(provider)?.clone(),
                ))
            })
            .collect::<crate::Result<BTreeMap<_, _>>>()?;
        identity_linker(existing_auth, &identities)?;
        let primary = evidence.require_usable_provider(&selected)?;
        let mut auth = AuthContext::for_principal(&selected, primary.canonical_principal()?);
        auth.claims.insert("issuer".into(), primary.issuer().into());
        auth.claims.insert(
            "application_principal".into(),
            existing_auth.principal.clone(),
        );
        auth.claims.insert(
            EVIDENCE_BINDING_CLAIM.into(),
            evidence
                .application_binding_digest(providers.iter().map(String::as_str), existing_auth),
        );
        auth.claims
            .insert("application_domain".into(), existing_auth.domain.clone());
        Ok(auth)
    }))
}

fn with_evidence_binding<'a>(
    auth: &AuthContext,
    evidence: &PeerEvidenceSet,
    providers: impl IntoIterator<Item = &'a String>,
) -> AuthContext {
    let mut auth = auth.clone();
    auth.claims.insert(
        EVIDENCE_BINDING_CLAIM.into(),
        evidence.binding_digest(providers.into_iter().map(String::as_str)),
    );
    auth
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> PeerIdentity {
        identity_for("spiffe://example.org/workload")
    }

    fn identity_for(subject: &str) -> PeerIdentity {
        PeerIdentity::new(
            "spiffe",
            "test",
            IdentityAssurance::CryptographicPeer,
            "spiffe://example.org",
            "tcp",
        )
        .unwrap()
        .with_subject(
            SubjectKind::Workload,
            subject,
            SubjectStability::Stable,
            true,
        )
        .unwrap()
    }

    #[test]
    fn primary_policy_authenticates_issuer_namespaced_subject() {
        let evidence =
            PeerEvidenceSet::from_results([PeerIdentityResult::available(identity())]).unwrap();
        let auth = peer_identity_primary("spiffe")(&evidence, &AuthContext::anonymous()).unwrap();
        assert_eq!(
            auth.principal,
            "peer/spiffe/spiffe%3A%2F%2Fexample.org/spiffe%3A%2F%2Fexample.org%2Fworkload"
        );
        assert_eq!(
            auth.claims[EVIDENCE_BINDING_CLAIM],
            "948ce118ddd5f212e7bfd62e13ffdba0675397c56a43060e98656965389e5367"
        );
    }

    #[test]
    fn duplicate_provider_is_rejected() {
        let result = PeerIdentityResult::available(identity());
        assert!(PeerEvidenceSet::from_results([result.clone(), result]).is_err());
    }

    #[test]
    fn capability_only_evidence_satisfies_require_but_not_primary() {
        let capability_only = PeerIdentity::new(
            "tailscale",
            "serve",
            IdentityAssurance::ConfiguredProxy,
            "tailnet:test",
            "http",
        )
        .unwrap()
        .with_capabilities(
            BTreeMap::from([(
                "query.farm/can-run".into(),
                serde_json::json!([{ "worker": "analytics" }]),
            )]),
            true,
        )
        .unwrap();
        let evidence =
            PeerEvidenceSet::from_results([PeerIdentityResult::available(capability_only)])
                .unwrap();
        let application = AuthContext::for_principal("bearer", "alice");
        let accepted = require_peer_identity("tailscale")(&evidence, &application).unwrap();
        assert_eq!(accepted.principal, "alice");
        assert!(accepted.claims.contains_key(EVIDENCE_BINDING_CLAIM));
        assert!(peer_identity_primary("tailscale")(&evidence, &AuthContext::anonymous()).is_err());
    }

    #[test]
    fn structured_json_evidence_is_bounded() {
        let base = || {
            PeerIdentity::new(
                "test",
                "test",
                IdentityAssurance::LocalDaemon,
                "test://issuer",
                "tcp",
            )
            .unwrap()
        };
        assert!(base()
            .with_attributes(BTreeMap::from([(
                "value".into(),
                Value::String("x".repeat(MAX_JSON_BYTES + 1)),
            )]))
            .is_err());

        let mut nested = serde_json::json!({});
        for _ in 0..=MAX_JSON_DEPTH {
            nested = serde_json::json!({ "child": nested });
        }
        assert!(base()
            .with_attributes(BTreeMap::from([("nested".into(), nested)]))
            .is_err());

        assert!(base()
            .with_attributes(BTreeMap::from([(
                "values".into(),
                Value::Array(vec![Value::Null; MAX_JSON_VALUES]),
            )]))
            .is_err());

        // `serde_json::Value` cannot represent a non-finite number, so the
        // public type enforces the finite-value invariant before validation.
        assert!(serde_json::Number::from_f64(f64::NAN).is_none());
    }

    #[test]
    fn resolution_context_budget_is_monotonic() {
        let context = PeerResolutionContext::new("http")
            .unwrap()
            .with_deadline(Instant::now() + std::time::Duration::from_millis(100));
        let before = context.remaining_time().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(context.remaining_time().unwrap() < before);
    }

    #[test]
    fn unavailable_provider_cannot_downgrade_any_of() {
        let evidence = PeerEvidenceSet::from_results([PeerIdentityResult::without_identity(
            "spiffe",
            PeerIdentityStatus::Unavailable,
        )
        .unwrap()])
        .unwrap();
        let policy = any_of_peer_identities(["spiffe"]).unwrap();
        let error = policy(&evidence, &AuthContext::anonymous()).unwrap_err();
        assert!(error.is_auth_unavailable());
        let bearer = AuthContext::for_principal("bearer", "alice");
        assert_eq!(policy(&evidence, &bearer).unwrap().principal, "alice");
    }

    #[test]
    fn ambiguous_available_provider_cannot_downgrade_any_of() {
        let evidence = PeerEvidenceSet::from_results([PeerIdentityResult::available_many(
            "spiffe",
            [
                identity_for("spiffe://example.org/alice"),
                identity_for("spiffe://example.org/bob"),
            ],
        )
        .unwrap()])
        .unwrap();
        let policy = any_of_peer_identities(["spiffe"]).unwrap();
        let bearer = AuthContext::for_principal("bearer", "alice");
        assert!(policy(&evidence, &bearer).is_err());
    }

    #[test]
    fn all_of_requires_application_auth_and_binds_all_factors() {
        let evidence =
            PeerEvidenceSet::from_results([PeerIdentityResult::available(identity())]).unwrap();
        let linker: PeerIdentityLinker = Arc::new(|_, _| Ok(()));
        let policy = all_of_peer_identities(["spiffe"], None::<String>, Some(linker)).unwrap();
        assert!(policy(&evidence, &AuthContext::anonymous()).is_err());
        let auth = policy(&evidence, &AuthContext::for_principal("bearer", "alice")).unwrap();
        assert_eq!(auth.claims["application_principal"], "alice");
        assert_eq!(auth.claims[EVIDENCE_BINDING_CLAIM].len(), 64);
    }

    #[test]
    fn all_of_binding_includes_application_domain_and_principal() {
        let evidence =
            PeerEvidenceSet::from_results([PeerIdentityResult::available(identity())]).unwrap();
        let linker: PeerIdentityLinker = Arc::new(|_, _| Ok(()));
        let policy = all_of_peer_identities(["spiffe"], None::<String>, Some(linker)).unwrap();
        let alice = policy(&evidence, &AuthContext::for_principal("bearer", "alice")).unwrap();
        let bob = policy(&evidence, &AuthContext::for_principal("bearer", "bob")).unwrap();
        let other_domain =
            policy(&evidence, &AuthContext::for_principal("oauth", "alice")).unwrap();
        assert_ne!(
            alice.claims[EVIDENCE_BINDING_CLAIM],
            bob.claims[EVIDENCE_BINDING_CLAIM]
        );
        assert_ne!(
            alice.claims[EVIDENCE_BINDING_CLAIM],
            other_domain.claims[EVIDENCE_BINDING_CLAIM]
        );
    }

    #[test]
    fn evidence_binding_ignores_network_path_but_not_capabilities() {
        let evidence = |source: &str, proxy: &str, capability: &str| {
            let identity = identity()
                .with_capabilities(
                    BTreeMap::from([(
                        "query.farm/can-run".into(),
                        serde_json::json!([{ "worker": capability }]),
                    )]),
                    true,
                )
                .unwrap()
                .with_addresses(Some(source), Some(proxy));
            PeerEvidenceSet::from_results([PeerIdentityResult::available(identity)]).unwrap()
        };
        let first = evidence("192.0.2.10:41000", "127.0.0.1:8443", "analytics");
        let moved = evidence("192.0.2.10:52000", "127.0.0.2:8443", "analytics");
        let changed = evidence("192.0.2.10:52000", "127.0.0.2:8443", "billing");
        assert_eq!(
            first.binding_digest(["spiffe"]),
            moved.binding_digest(["spiffe"])
        );
        assert_ne!(
            first.binding_digest(["spiffe"]),
            changed.binding_digest(["spiffe"])
        );
    }

    #[test]
    fn all_of_requires_an_identity_linker() {
        assert!(all_of_peer_identities(["spiffe"], None::<String>, None).is_err());
    }

    #[test]
    fn resolution_context_rejects_duplicate_headers() {
        let context = PeerResolutionContext::new("http")
            .unwrap()
            .with_headers([("X-ID".into(), vec!["one".into(), "two".into()])])
            .unwrap();
        assert!(context.header("x-id").is_err());
        assert!(PeerResolutionContext::new("http")
            .unwrap()
            .with_headers([
                ("X-ID".into(), vec!["one".into()]),
                ("x-id".into(), vec!["two".into()]),
            ])
            .is_err());
        assert!(PeerResolutionContext::new("http")
            .unwrap()
            .with_headers([("not a field".into(), vec!["value".into()])])
            .is_err());
        assert!(PeerResolutionContext::new("http")
            .unwrap()
            .with_headers([("x-peer".into(), vec!["bad\tvalue".into()])])
            .is_err());
        assert!(PeerResolutionContext::new("http")
            .unwrap()
            .with_headers([("x-peer".into(), vec!["value".into(); MAX_HEADER_VALUES + 1],)])
            .is_err());
    }
}
