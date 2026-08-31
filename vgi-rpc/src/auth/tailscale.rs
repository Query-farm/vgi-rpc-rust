//! Tailscale Serve and LocalAPI peer-identity evidence providers.
//!
//! These adapters resolve evidence only. Applications select an authorization
//! policy independently through the provider-neutral identity APIs.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use super::identity::{
    IdentityAssurance, PeerIdentity, PeerIdentityProvider, PeerIdentityResult, PeerIdentityStatus,
    PeerResolutionContext, SubjectKind, SubjectStability,
};
use crate::RpcError;

const PROVIDER: &str = "tailscale";
const LOCALAPI_HOST: &str = "local-tailscaled.sock";
const SERVE_LOGIN: &str = "tailscale-user-login";
const SERVE_NAME: &str = "tailscale-user-name";
const SERVE_PROFILE: &str = "tailscale-user-profile-pic";
const SERVE_CAPABILITIES: &str = "tailscale-app-capabilities";
const FUNNEL_REQUEST: &str = "tailscale-funnel-request";
const MAX_LOCALAPI_HEADER_BYTES: usize = 32_768;
const MAX_LOCALAPI_CHUNK_LINE_BYTES: usize = 8_192;
const MAX_SOURCE_BYTES: usize = 4_096;
const MAX_JSON_BYTES: usize = 65_536;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_VALUES: usize = 4_096;

/// Configuration for strict Tailscale Serve headers.
#[derive(Clone, Debug)]
pub struct TailscaleServeConfig {
    pub issuer: String,
    pub trusted_proxy_addresses: BTreeSet<IpAddr>,
    pub max_header_bytes: usize,
}

impl TailscaleServeConfig {
    pub fn new<I, S>(issuer: impl Into<String>, trusted_proxy_addresses: I) -> crate::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let trusted_proxy_addresses = trusted_proxy_addresses
            .into_iter()
            .map(|address| {
                address
                    .into()
                    .parse::<IpAddr>()
                    .map(normalize_ip)
                    .map_err(|_| {
                        RpcError::value_error("trusted proxy addresses must be exact IP addresses")
                    })
            })
            .collect::<crate::Result<BTreeSet<_>>>()?;
        let config = Self {
            issuer: issuer.into(),
            trusted_proxy_addresses,
            max_header_bytes: 16_384,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_max_header_bytes(mut self, max_header_bytes: usize) -> crate::Result<Self> {
        self.max_header_bytes = max_header_bytes;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> crate::Result<()> {
        if self.issuer.is_empty()
            || self
                .issuer
                .chars()
                .any(|character| character <= '\u{1f}' || character == '\u{7f}')
            || self.trusted_proxy_addresses.is_empty()
            || self.max_header_bytes == 0
        {
            return Err(RpcError::value_error(
                "issuer, trusted proxy addresses, and a positive header limit are required",
            ));
        }
        Ok(())
    }
}

/// Build a provider that trusts Serve headers only from exact configured
/// immediate peers.
pub fn tailscale_serve_header_provider(
    config: TailscaleServeConfig,
) -> crate::Result<PeerIdentityProvider> {
    config.validate()?;
    PeerIdentityProvider::new(PROVIDER, move |context| resolve_serve(&config, context))
}

fn resolve_serve(
    config: &TailscaleServeConfig,
    context: &PeerResolutionContext,
) -> crate::Result<PeerIdentityResult> {
    let immediate_ip = context.immediate_peer().and_then(peer_ip);
    if !immediate_ip.is_some_and(|peer| {
        config
            .trusted_proxy_addresses
            .iter()
            .any(|trusted| normalize_ip(*trusted) == peer)
    }) {
        return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::UntrustedProxy);
    }
    let values = match (
        context.header(FUNNEL_REQUEST),
        context.header(SERVE_LOGIN),
        context.header(SERVE_NAME),
        context.header(SERVE_PROFILE),
        context.header(SERVE_CAPABILITIES),
    ) {
        (Ok(funnel), Ok(login), Ok(name), Ok(profile), Ok(capabilities)) => {
            (funnel, login, name, profile, capabilities)
        }
        _ => {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
        }
    };
    let (funnel, login_raw, name_raw, profile_raw, capabilities_raw) = values;
    if let Some(funnel) = funnel {
        return PeerIdentityResult::without_identity(
            PROVIDER,
            if funnel == "?1" {
                PeerIdentityStatus::NotApplicable
            } else {
                PeerIdentityStatus::Invalid
            },
        );
    }

    let decoded = (|| {
        let login = login_raw
            .map(|value| decode_serve_value(value, config.max_header_bytes))
            .transpose()?;
        let display_name = name_raw
            .map(|value| decode_serve_value(value, config.max_header_bytes))
            .transpose()?;
        if let Some(profile) = profile_raw {
            decode_serve_value(profile, config.max_header_bytes)?;
        }
        let capabilities = capabilities_raw
            .map(|value| parse_serve_capabilities(value, config.max_header_bytes))
            .transpose()?
            .unwrap_or_default();
        Ok::<_, ()>((login, display_name, capabilities))
    })();
    let Ok((login, display_name, capabilities)) = decoded else {
        return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
    };
    if login_raw.is_some() && login.as_deref().is_none_or(str::is_empty)
        || (name_raw.is_some() || profile_raw.is_some())
            && login.as_deref().is_none_or(str::is_empty)
    {
        return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
    }
    if login.is_none() && capabilities.is_empty() {
        return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::NoMatch);
    }

    let mut attributes = BTreeMap::new();
    if let Some(login) = login.as_ref() {
        attributes.insert("user_login".into(), Value::String(login.clone()));
    }
    if let Some(display_name) = display_name.filter(|value| !value.is_empty()) {
        attributes.insert("user_display_name".into(), Value::String(display_name));
    }
    let mut identity = PeerIdentity::new(
        PROVIDER,
        "serve_proxy",
        IdentityAssurance::ConfiguredProxy,
        &config.issuer,
        "http",
    )?
    .with_attributes(attributes)?
    .with_capabilities(capabilities, capabilities_raw.is_some())?
    .with_addresses(
        context.asserted_peer().map(str::to_owned),
        context.immediate_peer().map(str::to_owned),
    );
    if let Some(login) = login {
        identity = identity.with_subject(
            SubjectKind::User,
            format!("login:{login}"),
            SubjectStability::Login,
            true,
        )?;
    }
    Ok(PeerIdentityResult::available(identity))
}

fn decode_serve_value(value: &str, maximum_bytes: usize) -> Result<String, ()> {
    if !value.is_ascii()
        || value.len() > maximum_bytes
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(());
    }
    if !value.starts_with("=?") {
        return Ok(value.to_owned());
    }

    let mut rest = value;
    let mut decoded = Vec::new();
    loop {
        if rest.len() < 12 || !rest[..10].eq_ignore_ascii_case("=?utf-8?q?") {
            return Err(());
        }
        let encoded = &rest[10..];
        let end = encoded.find("?=").ok_or(())?;
        decode_q_word(&encoded[..end], &mut decoded)?;
        rest = &encoded[end + 2..];
        if rest.is_empty() {
            break;
        }
        let trimmed = rest.trim_start_matches([' ', '\t']);
        if trimmed.len() == rest.len() || !trimmed.starts_with("=?") {
            return Err(());
        }
        rest = trimmed;
    }
    if decoded.len() > maximum_bytes {
        return Err(());
    }
    let decoded = String::from_utf8(decoded).map_err(|_| ())?;
    if decoded
        .chars()
        .any(|character| character <= '\u{1f}' || character == '\u{7f}')
    {
        return Err(());
    }
    Ok(decoded)
}

fn decode_q_word(encoded: &str, output: &mut Vec<u8>) -> Result<(), ()> {
    let bytes = encoded.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'_' => output.push(b' '),
            b'=' => {
                if index + 2 >= bytes.len() {
                    return Err(());
                }
                output.push((hex(bytes[index + 1])? << 4) | hex(bytes[index + 2])?);
                index += 2;
            }
            byte if byte.is_ascii_graphic() && byte != b'?' => output.push(byte),
            _ => return Err(()),
        }
        index += 1;
    }
    Ok(())
}

fn hex(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

fn parse_serve_capabilities(
    value: &str,
    maximum_bytes: usize,
) -> Result<BTreeMap<String, Value>, ()> {
    let decoded = decode_serve_value(value, maximum_bytes)?;
    let Value::Object(capabilities) = strict_json(decoded.as_bytes())? else {
        return Err(());
    };
    let mut result = BTreeMap::new();
    for (name, entries) in capabilities {
        if name.is_empty()
            || name.len() > 512
            || !name.contains('/')
            || name
                .chars()
                .any(|character| character <= '\u{1f}' || character == '\u{7f}')
        {
            return Err(());
        }
        let Value::Array(entries) = &entries else {
            return Err(());
        };
        if entries.iter().any(|entry| !entry.is_object()) {
            return Err(());
        }
        result.insert(name, Value::Array(entries.clone()));
    }
    Ok(result)
}

/// LocalAPI socket selection. HTTP is direct and intentionally ignores proxy
/// environment variables.
#[derive(Clone, Debug)]
pub enum TailscaleLocalApiEndpoint {
    Unix(PathBuf),
    Http { host: String, port: u16 },
}

/// No-cache LocalAPI WhoIs provider configuration.
#[derive(Clone, Debug)]
pub struct TailscaleLocalApiConfig {
    pub issuer: String,
    pub endpoint: TailscaleLocalApiEndpoint,
    pub password: Option<String>,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

impl TailscaleLocalApiConfig {
    pub fn new(issuer: impl Into<String>) -> crate::Result<Self> {
        let config = Self {
            issuer: issuer.into(),
            endpoint: TailscaleLocalApiEndpoint::Unix("/var/run/tailscale/tailscaled.sock".into()),
            password: None,
            timeout: Duration::from_secs(5),
            max_response_bytes: 65_536,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_unix_socket(mut self, path: impl Into<PathBuf>) -> crate::Result<Self> {
        self.endpoint = TailscaleLocalApiEndpoint::Unix(path.into());
        self.password = None;
        self.validate()?;
        Ok(self)
    }

    pub fn with_http_endpoint(mut self, endpoint: &str) -> crate::Result<Self> {
        let parsed = url::Url::parse(endpoint)
            .map_err(|_| RpcError::value_error("LocalAPI endpoint must be a valid HTTP origin"))?;
        if parsed.scheme() != "http"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(RpcError::value_error(
                "LocalAPI endpoint must be an HTTP origin without userinfo, path, query, or fragment",
            ));
        }
        self.endpoint = TailscaleLocalApiEndpoint::Http {
            host: parsed.host_str().expect("validated host").to_owned(),
            port: parsed.port().unwrap_or(80),
        };
        self.validate()?;
        Ok(self)
    }

    pub fn with_password(mut self, password: impl Into<String>) -> crate::Result<Self> {
        self.password = Some(password.into());
        self.validate()?;
        Ok(self)
    }

    pub fn with_timeout(mut self, timeout: Duration) -> crate::Result<Self> {
        self.timeout = timeout;
        self.validate()?;
        Ok(self)
    }

    pub fn with_max_response_bytes(mut self, maximum: usize) -> crate::Result<Self> {
        self.max_response_bytes = maximum;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> crate::Result<()> {
        if self.issuer.is_empty()
            || self
                .issuer
                .chars()
                .any(|character| character <= '\u{1f}' || character == '\u{7f}')
            || self.timeout.is_zero()
            || self.max_response_bytes == 0
        {
            return Err(RpcError::value_error(
                "issuer, a positive timeout, and a positive response limit are required",
            ));
        }
        match &self.endpoint {
            TailscaleLocalApiEndpoint::Unix(path) => {
                if path.as_os_str().is_empty() {
                    return Err(RpcError::value_error(
                        "LocalAPI Unix socket path is required",
                    ));
                }
                if self.password.is_some() {
                    return Err(RpcError::value_error(
                        "LocalAPI password is valid only for an HTTP endpoint",
                    ));
                }
            }
            TailscaleLocalApiEndpoint::Http { host, port } => {
                if host.is_empty() || *port == 0 {
                    return Err(RpcError::value_error("invalid LocalAPI HTTP endpoint"));
                }
            }
        }
        if self.password.as_ref().is_some_and(|password| {
            password
                .chars()
                .any(|character| matches!(character, '\r' | '\n' | '\0'))
        }) {
            return Err(RpcError::value_error(
                "LocalAPI password contains a control character",
            ));
        }
        Ok(())
    }
}

pub fn tailscale_localapi_provider(
    config: TailscaleLocalApiConfig,
) -> crate::Result<PeerIdentityProvider> {
    config.validate()?;
    PeerIdentityProvider::new(PROVIDER, move |context| resolve_localapi(&config, context))
}

fn resolve_localapi(
    config: &TailscaleLocalApiConfig,
    context: &PeerResolutionContext,
) -> crate::Result<PeerIdentityResult> {
    let Some(source) = context
        .asserted_peer()
        .or(context.source_endpoint())
        .or(context.immediate_peer())
    else {
        return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::NotApplicable);
    };
    if source.len() > MAX_SOURCE_BYTES
        || source
            .chars()
            .any(|character| matches!(character, '\r' | '\n' | '\0'))
    {
        return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
    }

    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("addr", source)
        .append_pair("proto", "tcp");
    let target = if let Some(service) = context.service_name() {
        if !valid_service_name(service) {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
        }
        query.append_pair("svc_name", service);
        capability_target("service", Some(service))
    } else if let Some(destination) = context.destination_address() {
        let Some(destination) = destination_ip(destination) else {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
        };
        query.append_pair("dst_ip", &destination.to_string());
        capability_target("destination_ip", Some(&destination.to_string()))
    } else {
        capability_target("node", None)
    };
    let path = format!("/localapi/v0/whois?{}", query.finish());
    let local_deadline = Instant::now()
        .checked_add(config.timeout)
        .unwrap_or_else(Instant::now);
    let deadline = context
        .deadline()
        .map_or(local_deadline, |request| request.min(local_deadline));
    let response = localapi_request(config, &path, deadline);
    let (status, headers, body) = match response {
        Ok(response) => response,
        Err(LocalApiError::Io | LocalApiError::Timeout) => {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Unavailable);
        }
        Err(LocalApiError::Protocol) => {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
        }
    };
    match status {
        401 | 403 => {
            return PeerIdentityResult::without_identity(
                PROVIDER,
                PeerIdentityStatus::PermissionDenied,
            );
        }
        404 => {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::NoMatch);
        }
        500..=599 => {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Unavailable);
        }
        200 => {}
        _ => {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
        }
    }
    let content_types = headers
        .get("content-type")
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if content_types.len() != 1
        || !content_types[0]
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
    }
    let identity = match localapi_identity(&body, context, target, &config.issuer) {
        Ok(identity) => identity,
        Err(()) => {
            return PeerIdentityResult::without_identity(PROVIDER, PeerIdentityStatus::Invalid);
        }
    };
    Ok(PeerIdentityResult::available(identity))
}

fn valid_service_name(service: &str) -> bool {
    let Some(label) = service.strip_prefix("svc:") else {
        return false;
    };
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn destination_ip(value: &str) -> Option<IpAddr> {
    value
        .parse()
        .ok()
        .or_else(|| {
            value
                .parse::<SocketAddr>()
                .ok()
                .map(|address| normalize_ip(address.ip()))
        })
        .or_else(|| {
            let bracketed = value.strip_prefix('[')?;
            let close = bracketed.find(']')?;
            let (address, suffix) = bracketed.split_at(close);
            if !matches!(suffix, "]") {
                return None;
            }
            address.parse().ok().map(normalize_ip)
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

fn peer_ip(value: &str) -> Option<IpAddr> {
    value
        .parse()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|peer| peer.ip()))
        .map(normalize_ip)
}

fn capability_target(kind: &str, value: Option<&str>) -> Value {
    let mut target = serde_json::Map::new();
    target.insert("kind".into(), Value::String(kind.into()));
    if let Some(value) = value {
        target.insert("value".into(), Value::String(value.into()));
    }
    Value::Object(target)
}

fn localapi_identity(
    body: &[u8],
    context: &PeerResolutionContext,
    target: Value,
    issuer: &str,
) -> Result<PeerIdentity, ()> {
    let Value::Object(mut payload) = strict_json(body)? else {
        return Err(());
    };
    let Value::Object(node) = payload.remove("Node").ok_or(())? else {
        return Err(());
    };
    let profile = payload.remove("UserProfile");
    let capabilities = match payload.remove("CapMap") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(Value::Object(values)) => values.into_iter().collect(),
        _ => return Err(()),
    };
    if capabilities.values().any(|entries| !entries.is_array()) {
        return Err(());
    }
    let tags = match node.get("Tags") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(tags)) => tags
            .iter()
            .map(|tag| tag.as_str().filter(|tag| tag.starts_with("tag:")))
            .collect::<Option<Vec<_>>>()
            .ok_or(())?,
        _ => return Err(()),
    };
    let stable_id = optional_string(node.get("StableID"))?;
    let node_name = optional_string(node.get("Name"))?;
    let mut attributes = BTreeMap::from([
        (
            "node_id".into(),
            stable_id.map_or(Value::Null, |value| Value::String(value.into())),
        ),
        (
            "node_name".into(),
            node_name.map_or(Value::Null, |value| Value::String(value.into())),
        ),
        (
            "tags".into(),
            Value::Array(
                tags.iter()
                    .map(|tag| Value::String((*tag).into()))
                    .collect(),
            ),
        ),
        ("capability_target".into(), target),
    ]);
    let (kind, subject) = if tags.is_empty() {
        let Value::Object(profile) = profile.ok_or(())? else {
            return Err(());
        };
        let user_id = profile
            .get("ID")
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or(())?;
        attributes.insert("user_id".into(), Value::String(user_id.to_string()));
        for (source, target) in [
            ("LoginName", "user_login"),
            ("DisplayName", "user_display_name"),
        ] {
            if let Some(value) =
                optional_string(profile.get(source))?.filter(|value| !value.is_empty())
            {
                attributes.insert(target.into(), Value::String(value.into()));
            }
        }
        (SubjectKind::User, format!("user:{user_id}"))
    } else {
        let stable_id = stable_id.filter(|value| !value.is_empty()).ok_or(())?;
        (SubjectKind::TaggedNode, format!("node:{stable_id}"))
    };
    PeerIdentity::new(
        PROVIDER,
        "localapi",
        IdentityAssurance::LocalDaemon,
        issuer,
        context.transport(),
    )
    .map_err(|_| ())?
    .with_subject(kind, subject, SubjectStability::Stable, true)
    .map_err(|_| ())?
    .with_attributes(attributes)
    .map_err(|_| ())?
    .with_capabilities(capabilities, true)
    .map_err(|_| ())
    .map(|identity| {
        identity.with_addresses(
            context
                .asserted_peer()
                .or(context.source_endpoint())
                .or(context.immediate_peer())
                .and_then(normalized_endpoint_ip),
            None::<String>,
        )
    })
}

fn normalized_endpoint_ip(value: &str) -> Option<String> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .map(normalize_ip)
        .map(|address| address.to_string())
}

fn optional_string(value: Option<&Value>) -> Result<Option<&str>, ()> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(()),
    }
}

#[derive(Clone, Copy, Debug)]
enum LocalApiError {
    Io,
    Timeout,
    Protocol,
}

type LocalApiResponse = (u16, BTreeMap<String, Vec<String>>, Vec<u8>);

trait LocalApiStream: Read + Write {
    fn set_timeouts(&self, duration: Duration) -> io::Result<()>;
}

impl LocalApiStream for TcpStream {
    fn set_timeouts(&self, duration: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(duration))?;
        self.set_write_timeout(Some(duration))
    }
}

#[cfg(unix)]
impl LocalApiStream for std::os::unix::net::UnixStream {
    fn set_timeouts(&self, duration: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(duration))?;
        self.set_write_timeout(Some(duration))
    }
}

fn localapi_request(
    config: &TailscaleLocalApiConfig,
    path: &str,
    deadline: Instant,
) -> Result<LocalApiResponse, LocalApiError> {
    let mut stream: Box<dyn LocalApiStream> = match &config.endpoint {
        TailscaleLocalApiEndpoint::Http { host, port } => {
            Box::new(connect_tcp(host, *port, deadline)?)
        }
        #[cfg(unix)]
        TailscaleLocalApiEndpoint::Unix(path) => {
            Box::new(std::os::unix::net::UnixStream::connect(path).map_err(|_| LocalApiError::Io)?)
        }
        #[cfg(not(unix))]
        TailscaleLocalApiEndpoint::Unix(_) => return Err(LocalApiError::Io),
    };
    stream
        .set_timeouts(remaining(deadline)?)
        .map_err(|_| LocalApiError::Io)?;
    let mut request =
        format!("GET {path} HTTP/1.1\r\nHost: {LOCALAPI_HOST}\r\nConnection: close\r\n");
    if let Some(password) = config.password.as_ref() {
        request.push_str("Authorization: Basic ");
        request.push_str(&base64(&format!(":{password}")));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .set_timeouts(remaining(deadline)?)
        .map_err(|_| LocalApiError::Io)?;
    stream.write_all(request.as_bytes()).map_err(classify_io)?;
    read_http_response(&mut *stream, deadline, config.max_response_bytes)
}

fn connect_tcp(host: &str, port: u16, deadline: Instant) -> Result<TcpStream, LocalApiError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| LocalApiError::Io)?;
    let mut last = LocalApiError::Io;
    for address in addresses {
        match TcpStream::connect_timeout(&address, remaining(deadline)?) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = classify_io(error),
        }
    }
    Err(last)
}

fn remaining(deadline: Instant) -> Result<Duration, LocalApiError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(LocalApiError::Timeout)
    } else {
        Ok(remaining)
    }
}

fn classify_io(error: io::Error) -> LocalApiError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        LocalApiError::Timeout
    } else {
        LocalApiError::Io
    }
}

fn read_http_response(
    stream: &mut dyn LocalApiStream,
    deadline: Instant,
    maximum_body_bytes: usize,
) -> Result<LocalApiResponse, LocalApiError> {
    let mut pending = Vec::new();
    let header_end = loop {
        if let Some(offset) = find_bytes(&pending, b"\r\n\r\n") {
            break offset;
        }
        if pending.len() > MAX_LOCALAPI_HEADER_BYTES {
            return Err(LocalApiError::Protocol);
        }
        read_more(stream, deadline, &mut pending)?;
    };
    if header_end > MAX_LOCALAPI_HEADER_BYTES {
        return Err(LocalApiError::Protocol);
    }
    let body_start = header_end + 4;
    let raw_headers = &pending[..header_end];
    let split_lines: Vec<_> = raw_headers.split(|byte| *byte == b'\n').collect();
    if split_lines.is_empty()
        || split_lines[..split_lines.len() - 1]
            .iter()
            .any(|line| !line.ends_with(b"\r"))
        || split_lines[split_lines.len() - 1].contains(&b'\r')
    {
        return Err(LocalApiError::Protocol);
    }
    let mut lines = split_lines.iter().enumerate().map(|(index, line)| {
        if index + 1 == split_lines.len() {
            *line
        } else {
            &line[..line.len() - 1]
        }
    });
    let status_line = lines.next().ok_or(LocalApiError::Protocol)?;
    let status_text = std::str::from_utf8(status_line).map_err(|_| LocalApiError::Protocol)?;
    let mut status_parts = status_text.splitn(3, ' ');
    let protocol = status_parts.next().ok_or(LocalApiError::Protocol)?;
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|status| (100..=599).contains(status))
        .ok_or(LocalApiError::Protocol)?;
    if !matches!(protocol, "HTTP/1.0" | "HTTP/1.1") || status_parts.next().is_none() {
        return Err(LocalApiError::Protocol);
    }
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    for line in lines {
        if line.is_empty() || matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(LocalApiError::Protocol);
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(LocalApiError::Protocol)?;
        let (name, value) = line.split_at(colon);
        if name.is_empty() || !name.iter().copied().all(is_http_token) || !value.is_ascii() {
            return Err(LocalApiError::Protocol);
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| LocalApiError::Protocol)?
            .to_ascii_lowercase();
        let value = std::str::from_utf8(&value[1..])
            .map_err(|_| LocalApiError::Protocol)?
            .trim()
            .to_owned();
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(LocalApiError::Protocol);
        }
        headers.entry(name).or_default().push(value);
    }
    let mut body = pending.split_off(body_start);
    let lengths = headers
        .get("content-length")
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let encodings = headers
        .get("transfer-encoding")
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if !lengths.is_empty() && !encodings.is_empty() {
        return Err(LocalApiError::Protocol);
    }
    if !lengths.is_empty() {
        if lengths.len() != 1 {
            return Err(LocalApiError::Protocol);
        }
        let length = lengths[0]
            .parse::<usize>()
            .ok()
            .filter(|length| *length <= maximum_body_bytes)
            .ok_or(LocalApiError::Protocol)?;
        while body.len() < length {
            read_more(stream, deadline, &mut body)?;
        }
        body.truncate(length);
    } else if !encodings.is_empty() {
        if encodings.len() != 1 || !encodings[0].eq_ignore_ascii_case("chunked") {
            return Err(LocalApiError::Protocol);
        }
        body = decode_chunked(stream, deadline, body, maximum_body_bytes)?;
    } else {
        loop {
            if body.len() > maximum_body_bytes {
                return Err(LocalApiError::Protocol);
            }
            match read_more_allow_eof(stream, deadline, &mut body)? {
                true => {}
                false => break,
            }
        }
    }
    if body.len() > maximum_body_bytes {
        return Err(LocalApiError::Protocol);
    }
    Ok((status, headers, body))
}

fn decode_chunked(
    stream: &mut dyn LocalApiStream,
    deadline: Instant,
    mut pending: Vec<u8>,
    maximum_body_bytes: usize,
) -> Result<Vec<u8>, LocalApiError> {
    let mut decoded = Vec::new();
    loop {
        let line = read_line(stream, deadline, &mut pending)?;
        let size_text = line
            .split(|byte| *byte == b';')
            .next()
            .ok_or(LocalApiError::Protocol)?;
        let size = usize::from_str_radix(
            std::str::from_utf8(size_text).map_err(|_| LocalApiError::Protocol)?,
            16,
        )
        .map_err(|_| LocalApiError::Protocol)?;
        if decoded.len().saturating_add(size) > maximum_body_bytes {
            return Err(LocalApiError::Protocol);
        }
        if size == 0 {
            while !read_line(stream, deadline, &mut pending)?.is_empty() {}
            return Ok(decoded);
        }
        while pending.len() < size + 2 {
            read_more(stream, deadline, &mut pending)?;
        }
        if &pending[size..size + 2] != b"\r\n" {
            return Err(LocalApiError::Protocol);
        }
        decoded.extend_from_slice(&pending[..size]);
        pending.drain(..size + 2);
    }
}

fn read_line(
    stream: &mut dyn LocalApiStream,
    deadline: Instant,
    pending: &mut Vec<u8>,
) -> Result<Vec<u8>, LocalApiError> {
    loop {
        if let Some(offset) = find_bytes(pending, b"\r\n") {
            let line = pending[..offset].to_vec();
            pending.drain(..offset + 2);
            return Ok(line);
        }
        if pending.len() > MAX_LOCALAPI_CHUNK_LINE_BYTES {
            return Err(LocalApiError::Protocol);
        }
        read_more(stream, deadline, pending)?;
    }
}

fn read_more(
    stream: &mut dyn LocalApiStream,
    deadline: Instant,
    output: &mut Vec<u8>,
) -> Result<(), LocalApiError> {
    if read_more_allow_eof(stream, deadline, output)? {
        Ok(())
    } else {
        Err(LocalApiError::Protocol)
    }
}

fn read_more_allow_eof(
    stream: &mut dyn LocalApiStream,
    deadline: Instant,
    output: &mut Vec<u8>,
) -> Result<bool, LocalApiError> {
    stream
        .set_timeouts(remaining(deadline)?)
        .map_err(classify_io)?;
    let mut buffer = [0u8; 8_192];
    let read = stream.read(&mut buffer).map_err(classify_io)?;
    output.extend_from_slice(&buffer[..read]);
    Ok(read != 0)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_http_token(byte: u8) -> bool {
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
}

fn base64(value: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(ALPHABET[((bits >> 18) & 63) as usize]));
        output.push(char::from(ALPHABET[((bits >> 12) & 63) as usize]));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[((bits >> 6) & 63) as usize])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[(bits & 63) as usize])
        } else {
            '='
        });
    }
    output
}

fn strict_json(input: &[u8]) -> Result<Value, ()> {
    if input.len() > MAX_JSON_BYTES {
        return Err(());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|_| ())?
        .0;
    deserializer.end().map_err(|_| ())?;
    let mut count = 0usize;
    validate_strict_value(&value, 1, &mut count)?;
    Ok(value)
}

fn validate_strict_value(value: &Value, depth: usize, count: &mut usize) -> Result<(), ()> {
    if depth > MAX_JSON_DEPTH {
        return Err(());
    }
    *count = count.checked_add(1).ok_or(())?;
    if *count > MAX_JSON_VALUES {
        return Err(());
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_strict_value(value, depth + 1, count)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_strict_value(value, depth + 1, count)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.into())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(A::Error::custom("duplicate JSON key"));
            }
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn serve_context(headers: Vec<(String, Vec<String>)>) -> PeerResolutionContext {
        PeerResolutionContext::new("http")
            .unwrap()
            .with_peers(Some("127.0.0.1"), None::<String>)
            .with_headers(headers)
            .unwrap()
    }

    fn serve_provider() -> PeerIdentityProvider {
        tailscale_serve_header_provider(
            TailscaleServeConfig::new("tailnet:test", ["127.0.0.1"]).unwrap(),
        )
        .unwrap()
    }

    fn header(name: &str, value: &str) -> (String, Vec<String>) {
        (name.to_owned(), vec![value.to_owned()])
    }

    #[test]
    fn serve_user_and_capabilities_are_strict_verified_evidence() {
        let context = serve_context(vec![
            header(SERVE_LOGIN, "alice@example.com"),
            header(SERVE_NAME, "=?UTF-8?Q?Alice_=E2=98=83?="),
            header(
                SERVE_CAPABILITIES,
                r#"{"example.com/cap":[{"role":"reader"}]}"#,
            ),
        ]);
        let result = serve_provider()(&context).unwrap();
        assert_eq!(result.status(), PeerIdentityStatus::Available);
        let identity = &result.identities()[0];
        assert_eq!(identity.subject_key(), Some("login:alice@example.com"));
        assert_eq!(identity.subject_stability(), SubjectStability::Login);
        assert!(identity.subject_verified());
        assert_eq!(identity.assurance(), IdentityAssurance::ConfiguredProxy);
        assert_eq!(
            identity.attributes().get("user_display_name"),
            Some(&Value::String("Alice ☃".into()))
        );
        assert!(identity.capabilities_verified());
    }

    #[test]
    fn serve_capability_only_is_available_but_subjectless() {
        let context = serve_context(vec![header(
            SERVE_CAPABILITIES,
            r#"{"example.com/cap":[{}]}"#,
        )]);
        let result = serve_provider()(&context).unwrap();
        assert_eq!(result.status(), PeerIdentityStatus::Available);
        assert_eq!(result.identities()[0].subject_key(), None);
        assert_eq!(result.identities()[0].subject_kind(), SubjectKind::Unknown);
    }

    #[test]
    fn serve_rejects_untrusted_funnel_duplicate_and_malformed_headers() {
        let provider = serve_provider();
        let untrusted = PeerResolutionContext::new("http")
            .unwrap()
            .with_peers(Some("127.0.0.2"), None::<String>);
        assert_eq!(
            provider(&untrusted).unwrap().status(),
            PeerIdentityStatus::UntrustedProxy
        );
        assert_eq!(
            provider(&serve_context(vec![header(FUNNEL_REQUEST, "?1")]))
                .unwrap()
                .status(),
            PeerIdentityStatus::NotApplicable
        );

        let invalid = [
            vec![(
                SERVE_LOGIN.to_owned(),
                vec!["alice@example.com".into(), "mallory@example.com".into()],
            )],
            vec![header(SERVE_NAME, "orphan")],
            vec![header(SERVE_LOGIN, "=?UTF-8?B?YWxpY2U=?=")],
            vec![header(SERVE_LOGIN, "=?UTF-8?Q?bad=0Avalue?=")],
            vec![header(
                SERVE_CAPABILITIES,
                r#"{"example.com/cap":[],"example.com/cap":[]}"#,
            )],
            vec![header(SERVE_CAPABILITIES, r#"{"missing-slash":[]}"#)],
            vec![header(SERVE_CAPABILITIES, r#"{"example.com/cap":[1]}"#)],
            vec![header(
                SERVE_CAPABILITIES,
                r#"{"example.com/cap":[{"bad":"\uD800"}]}"#,
            )],
        ];
        for headers in invalid {
            assert_eq!(
                provider(&serve_context(headers)).unwrap().status(),
                PeerIdentityStatus::Invalid
            );
        }

        assert!(TailscaleServeConfig::new("tailnet:test", ["localhost"]).is_err());
        let mapped = tailscale_serve_header_provider(
            TailscaleServeConfig::new("tailnet:test", ["::ffff:127.0.0.1"]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            mapped(&serve_context(vec![header(
                SERVE_LOGIN,
                "alice@example.com"
            )]))
            .unwrap()
            .status(),
            PeerIdentityStatus::Available
        );
    }

    #[test]
    fn strict_json_enforces_depth_count_and_byte_limits() {
        let mut deep = Value::Null;
        for _ in 0..16 {
            deep = serde_json::json!({"x": deep});
        }
        assert!(strict_json(&serde_json::to_vec(&deep).unwrap()).is_err());
        let wide = serde_json::to_vec(&vec![Value::Null; MAX_JSON_VALUES]).unwrap();
        assert!(strict_json(&wide).is_err());
        assert!(strict_json(&vec![b' '; MAX_JSON_BYTES + 1]).is_err());
        assert!(strict_json(br#"{"a":1,"a":2}"#).is_err());
        assert_eq!(
            destination_ip("[::1]"),
            Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            destination_ip("[::1]:9400"),
            Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
        );
        assert!(destination_ip("worker.example:9400").is_none());
    }

    fn spawn_localapi_response(
        response: Vec<u8>,
        delay: Option<Duration>,
    ) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 512];
            while find_bytes(&request, b"\r\n\r\n").is_none() {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let _ = sender.send(String::from_utf8(request).unwrap());
            if let Some(delay) = delay {
                thread::sleep(delay);
            }
            let _ = stream.write_all(&response);
        });
        (format!("http://{address}"), receiver)
    }

    fn response(status: u16, body: &str, extra_headers: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra_headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn localapi_context() -> PeerResolutionContext {
        PeerResolutionContext::new("tcp")
            .unwrap()
            .with_peers(Some("127.0.0.1:9999"), Some("100.64.0.8:12345"))
            .with_destination(Some("100.64.0.9:9400"), Some("svc:worker"))
            .with_deadline(Instant::now() + Duration::from_secs(2))
    }

    fn local_provider(endpoint: &str) -> PeerIdentityProvider {
        tailscale_localapi_provider(
            TailscaleLocalApiConfig::new("tailnet:test")
                .unwrap()
                .with_http_endpoint(endpoint)
                .unwrap()
                .with_password("secret")
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn localapi_queries_each_request_with_service_scope_and_builds_stable_user() {
        let body = r#"{"Node":{"StableID":"node-1","Name":"host","Tags":[]},"UserProfile":{"ID":42,"LoginName":"alice@example.com","DisplayName":"Alice"},"CapMap":{"example.com/cap":[{"role":"reader"}]}}"#;
        assert!(localapi_identity(
            body.as_bytes(),
            &localapi_context(),
            capability_target("service", Some("svc:worker")),
            "tailnet:test"
        )
        .is_ok());
        let (endpoint, request) = spawn_localapi_response(response(200, body, ""), None);
        let result = local_provider(&endpoint)(&localapi_context()).unwrap();
        assert_eq!(result.status(), PeerIdentityStatus::Available);
        let identity = &result.identities()[0];
        assert_eq!(identity.subject_key(), Some("user:42"));
        assert_eq!(identity.subject_stability(), SubjectStability::Stable);
        assert_eq!(identity.source_address(), Some("100.64.0.8"));
        assert_eq!(identity.proxy_address(), None);
        assert_eq!(
            identity.attributes()["capability_target"]["kind"],
            "service"
        );
        assert_eq!(
            identity.attributes()["capability_target"]["value"],
            "svc:worker"
        );

        let request = request.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.starts_with(
            "GET /localapi/v0/whois?addr=100.64.0.8%3A12345&proto=tcp&svc_name=svc%3Aworker HTTP/1.1\r\n"
        ));
        assert!(request.contains("\r\nHost: local-tailscaled.sock\r\n"));
        assert!(request.contains("\r\nAuthorization: Basic OnNlY3JldA==\r\n"));
    }

    #[test]
    fn localapi_http_lookup_uses_raw_source_endpoint_but_records_only_ip() {
        let body = r#"{"Node":{"StableID":"node-1","Name":"host","Tags":[]},"UserProfile":{"ID":42},"CapMap":{}}"#;
        let (endpoint, request) = spawn_localapi_response(response(200, body, ""), None);
        let context = PeerResolutionContext::new("http")
            .unwrap()
            .with_peers(Some("127.0.0.1"), None::<String>)
            .with_source_endpoint(Some("100.64.0.8:54321"))
            .with_destination(None::<String>, Some("svc:worker"))
            .with_deadline(Instant::now() + Duration::from_secs(2));
        let result = local_provider(&endpoint)(&context).unwrap();
        assert_eq!(result.status(), PeerIdentityStatus::Available);
        assert_eq!(result.identities()[0].source_address(), Some("100.64.0.8"));
        let request = request.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.starts_with(
            "GET /localapi/v0/whois?addr=100.64.0.8%3A54321&proto=tcp&svc_name=svc%3Aworker HTTP/1.1\r\n"
        ));
    }

    #[test]
    fn localapi_tagged_node_ignores_user_profile() {
        let body = r#"{"Node":{"StableID":"node-stable","Name":"svc","Tags":["tag:worker"]},"UserProfile":{"ID":999,"LoginName":"ignored"},"CapMap":{}}"#;
        let (endpoint, _) = spawn_localapi_response(response(200, body, ""), None);
        let result = local_provider(&endpoint)(&localapi_context()).unwrap();
        let identity = &result.identities()[0];
        assert_eq!(identity.subject_kind(), SubjectKind::TaggedNode);
        assert_eq!(identity.subject_key(), Some("node:node-stable"));
        assert!(!identity.attributes().contains_key("user_id"));
    }

    #[test]
    fn localapi_maps_status_protocol_and_timeout_fail_closed() {
        for (status, expected) in [
            (401, PeerIdentityStatus::PermissionDenied),
            (403, PeerIdentityStatus::PermissionDenied),
            (404, PeerIdentityStatus::NoMatch),
            (500, PeerIdentityStatus::Unavailable),
            (302, PeerIdentityStatus::Invalid),
        ] {
            let (endpoint, _) = spawn_localapi_response(response(status, "{}", ""), None);
            assert_eq!(
                local_provider(&endpoint)(&localapi_context())
                    .unwrap()
                    .status(),
                expected
            );
        }

        let body = r#"{"Node":{"Tags":[]},"UserProfile":{"ID":1}}"#;
        let duplicate_type = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (endpoint, _) = spawn_localapi_response(duplicate_type.into_bytes(), None);
        assert_eq!(
            local_provider(&endpoint)(&localapi_context())
                .unwrap()
                .status(),
            PeerIdentityStatus::Invalid
        );

        let (endpoint, _) =
            spawn_localapi_response(response(200, body, ""), Some(Duration::from_millis(100)));
        let provider = tailscale_localapi_provider(
            TailscaleLocalApiConfig::new("tailnet:test")
                .unwrap()
                .with_http_endpoint(&endpoint)
                .unwrap()
                .with_timeout(Duration::from_millis(20))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            provider(&localapi_context()).unwrap().status(),
            PeerIdentityStatus::Unavailable
        );
    }

    #[test]
    fn localapi_accepts_bounded_chunked_response_and_rejects_duplicate_json() {
        let body = r#"{"Node":{"StableID":"node-1","Tags":[]},"UserProfile":{"ID":7}}"#;
        let split = body.len() / 2;
        let chunked = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            split,
            &body[..split],
            body.len() - split,
            &body[split..]
        );
        let (endpoint, _) = spawn_localapi_response(chunked.into_bytes(), None);
        assert_eq!(
            local_provider(&endpoint)(&localapi_context())
                .unwrap()
                .status(),
            PeerIdentityStatus::Available
        );

        let duplicate = r#"{"Node":{"Tags":[],"Tags":[]},"UserProfile":{"ID":7}}"#;
        let (endpoint, _) = spawn_localapi_response(response(200, duplicate, ""), None);
        assert_eq!(
            local_provider(&endpoint)(&localapi_context())
                .unwrap()
                .status(),
            PeerIdentityStatus::Invalid
        );
    }
}
