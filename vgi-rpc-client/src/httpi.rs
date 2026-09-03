//! Native blocking VGI HTTP client over authenticated Iroh QUIC.
//!
//! This module supplies only the HTTP executor. Arrow serialization,
//! continuations, capabilities, authentication headers, compression, sticky
//! sessions, and external locations remain implemented by [`crate::HttpClient`].

use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::blocking::Client as ReqwestClient;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use vgi_iroh_transport::{
    process_secret_key, ClientEndpoint, DispatchCertainty, EndpointConfig, ErrorCategory,
    ErrorStage, HttpRequest, HttpResponse, RelayConfig, RemoteAddr, TransportError,
};
use vgi_rpc::external::UrlValidator;
use vgi_rpc::retry::RetryConfig;
use vgi_rpc::{Result, RpcError};

use crate::client::OnLog;
use crate::http::{HttpClient, HttpClientBuilder};

const HTTP_PREFIX: &str = "httpi://";
const ENDPOINT_ID_LEN: usize = 64;

/// Canonical components of a native `httpi://` location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpiTarget {
    endpoint_id: String,
    base_path: String,
}

impl HttpiTarget {
    /// Parse `httpi://<64-lowercase-hex-endpoint-id>[/base-path]` without URL
    /// normalization. Rejecting non-canonical paths ensures every SDK sends
    /// the same HTTP request target.
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
            return Err(invalid_target(
                "httpi target must be non-empty ASCII text without whitespace or controls",
            ));
        }
        let rest = value.strip_prefix(HTTP_PREFIX).ok_or_else(|| {
            invalid_target("Iroh HTTP target scheme must be exactly lowercase 'httpi'")
        })?;
        if rest.contains(['?', '#', '@']) {
            return Err(invalid_target(
                "httpi target must not contain user information, a query, or a fragment",
            ));
        }
        let (endpoint_id, raw_path) = rest
            .split_once('/')
            .map_or((rest, ""), |(endpoint, path)| (endpoint, path));
        if endpoint_id.len() != ENDPOINT_ID_LEN
            || !endpoint_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid_target(
                "httpi EndpointId must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        // Validate that the bytes are also accepted by the pinned Iroh API.
        RemoteAddr::parse(endpoint_id, None, &[]).map_err(transport_rpc_error)?;

        let base_path = if raw_path.is_empty() {
            String::new()
        } else {
            validate_base_path(raw_path)?;
            format!("/{raw_path}")
        };
        Ok(Self {
            endpoint_id: endpoint_id.to_owned(),
            base_path,
        })
    }

    pub fn endpoint_id(&self) -> &str {
        &self.endpoint_id
    }

    pub fn base_path(&self) -> &str {
        &self.base_path
    }
}

fn validate_base_path(path: &str) -> Result<()> {
    // A single slash is the canonical empty base path.
    if path.is_empty() {
        return Ok(());
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(invalid_target(
                "httpi base path must contain no empty or dot segments",
            ));
        }
        let decoded = percent_decode_segment(segment)?;
        if decoded == b"." || decoded == b".." {
            return Err(invalid_target(
                "httpi base path must contain no encoded dot segments",
            ));
        }
        if decoded
            .iter()
            .any(|byte| *byte == b'/' || *byte == b'\\' || *byte <= b' ' || *byte == 0x7f)
        {
            return Err(invalid_target(
                "httpi base path contains an encoded separator, whitespace, or control",
            ));
        }
    }
    Ok(())
}

fn percent_decode_segment(segment: &str) -> Result<Vec<u8>> {
    let bytes = segment.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            if bytes[index] == b'\\' {
                return Err(invalid_target(
                    "httpi base path must not contain backslashes",
                ));
            }
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(invalid_target(
                "httpi base path contains an invalid percent escape",
            ));
        }
        let high = hex_value(bytes[index + 1]);
        let low = hex_value(bytes[index + 2]);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(invalid_target(
                "httpi base path contains an invalid percent escape",
            ));
        };
        output.push((high << 4) | low);
        index += 3;
    }
    Ok(output)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_target(message: impl Into<String>) -> RpcError {
    RpcError::new(
        "IrohTransportError",
        format!(
            "stage=parse category=invalid_input dispatch=not_sent: {}",
            message.into()
        ),
    )
}

/// Builder for the blocking typed HTTP client over `iroh-http/2`.
pub struct HttpiClientBuilder {
    target: HttpiTarget,
    http: HttpClientBuilder,
    endpoint: EndpointConfig,
    relay_urls: Option<Vec<String>>,
    no_relay: bool,
    remote_relay_url: Option<String>,
    direct_addresses: Vec<String>,
}

impl HttpiClientBuilder {
    pub fn connect(target: &str) -> Result<Self> {
        let target = HttpiTarget::parse(target)?;
        let http = HttpClient::connect("").prefix(target.base_path.clone());
        Ok(Self {
            target,
            http,
            endpoint: EndpointConfig::default(),
            relay_urls: None,
            no_relay: false,
            remote_relay_url: None,
            direct_addresses: Vec::new(),
        })
    }

    /// Use a persistent Iroh identity. The value may be Iroh's textual secret
    /// key encoding; it is never included in errors or logs.
    pub fn secret_key(mut self, value: &str) -> Result<Self> {
        self.endpoint.secret_key =
            Some(EndpointConfig::parse_secret_key(value).map_err(transport_rpc_error)?);
        Ok(self)
    }

    /// Use an already assembled endpoint configuration. When its secret key
    /// is absent, build still installs the process-stable ephemeral key.
    pub fn endpoint_config(mut self, config: EndpointConfig) -> Self {
        self.endpoint = config;
        self
    }

    pub fn relay_urls(mut self, urls: impl IntoIterator<Item = String>) -> Self {
        self.relay_urls = Some(urls.into_iter().collect());
        self
    }

    pub fn no_relay(mut self, value: bool) -> Self {
        self.no_relay = value;
        self
    }

    pub fn remote_relay_url(mut self, url: impl Into<String>) -> Self {
        self.remote_relay_url = Some(url.into());
        self
    }

    pub fn direct_addresses(mut self, addresses: impl IntoIterator<Item = String>) -> Self {
        self.direct_addresses = addresses.into_iter().collect();
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.endpoint.connect_timeout = timeout;
        self
    }

    pub fn io_timeout(mut self, timeout: Duration) -> Self {
        self.endpoint.io_timeout = timeout;
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Result<Self> {
        self.http = self.http.header(name, value)?;
        Ok(self)
    }

    pub fn external_http_client(mut self, client: ReqwestClient) -> Self {
        self.http = self.http.client(client);
        self
    }

    pub fn on_log(mut self, callback: OnLog) -> Self {
        self.http = self.http.on_log(callback);
        self
    }

    pub fn relax_nullability(mut self, value: bool) -> Self {
        self.http = self.http.relax_nullability(value);
        self
    }

    pub fn protocol_version(mut self, version: impl Into<String>) -> Self {
        self.http = self.http.protocol_version(version);
        self
    }

    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.http = self.http.timeout(timeout);
        if let Some(timeout) = timeout {
            self.endpoint.io_timeout = timeout;
        }
        self
    }

    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.http = self.http.retry(retry);
        self
    }

    pub fn compression_level(mut self, level: Option<i32>) -> Self {
        self.http = self.http.compression_level(level);
        self
    }

    pub fn max_encoded_response_bytes(mut self, bytes: usize) -> Self {
        self.http = self.http.max_encoded_response_bytes(bytes);
        self
    }

    pub fn max_decoded_response_bytes(mut self, bytes: usize) -> Self {
        self.http = self.http.max_decoded_response_bytes(bytes);
        self
    }

    pub fn accepted_max_response_bytes(mut self, bytes: usize) -> Self {
        self.http = self.http.accepted_max_response_bytes(bytes);
        self
    }

    pub fn external_resolution(mut self, validator: UrlValidator) -> Self {
        self.http = self.http.external_resolution(validator);
        self
    }

    pub fn external_resolution_any(mut self) -> Self {
        self.http = self.http.external_resolution_any();
        self
    }

    pub fn build(mut self) -> Result<HttpClient> {
        if self.no_relay && self.relay_urls.is_some() {
            return Err(invalid_target(
                "custom relay URLs and no_relay are mutually exclusive",
            ));
        }
        self.endpoint.relays = if self.no_relay {
            RelayConfig::Disabled
        } else if let Some(urls) = self.relay_urls {
            RelayConfig::Custom(EndpointConfig::parse_relays(&urls).map_err(transport_rpc_error)?)
        } else {
            self.endpoint.relays.clone()
        };
        if self.endpoint.secret_key.is_none() {
            self.endpoint.secret_key = Some(process_secret_key());
        }
        let remote = RemoteAddr::parse(
            self.target.endpoint_id(),
            self.remote_relay_url.as_deref(),
            &self.direct_addresses,
        )
        .map_err(transport_rpc_error)?;
        let executor = HttpiExecutor::bind(self.endpoint, remote)?;
        self.http.build_httpi(executor)
    }
}

struct RuntimeOwner(Option<Runtime>);

impl RuntimeOwner {
    fn runtime(&self) -> &Runtime {
        self.0.as_ref().expect("Iroh runtime remains alive")
    }
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            // This is non-blocking and is safe even if a client is dropped
            // from another Tokio runtime's worker thread.
            runtime.shutdown_background();
        }
    }
}

pub(crate) struct HttpiExecutor {
    endpoint: ClientEndpoint,
    runtime: Arc<RuntimeOwner>,
    remote: RemoteAddr,
}

pub(crate) struct HttpiResponseParts {
    pub status: u16,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: HttpiBody,
}

impl HttpiExecutor {
    fn bind(config: EndpointConfig, remote: RemoteAddr) -> Result<Self> {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("vgi-httpi")
            .build()
            .map_err(|error| {
                RpcError::new(
                    "IrohTransportError",
                    format!(
                        "stage=bind category=internal dispatch=not_sent: create runtime: {error}"
                    ),
                )
            })?;
        let endpoint = runtime
            .block_on(ClientEndpoint::bind(config))
            .map_err(transport_rpc_error)?;
        Ok(Self {
            endpoint,
            runtime: Arc::new(RuntimeOwner(Some(runtime))),
            remote,
        })
    }

    pub(crate) fn endpoint_id(&self) -> String {
        vgi_iroh_transport::endpoint_id_hex(self.endpoint.id())
    }

    pub(crate) fn execute(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        body: Vec<u8>,
    ) -> std::result::Result<HttpiResponseParts, TransportError> {
        let response = self.runtime.runtime().block_on(self.endpoint.request(
            &self.remote,
            HttpRequest {
                method: method.to_owned(),
                path: path.to_owned(),
                headers,
                body: Bytes::from(body),
            },
        ))?;
        let status = response.status();
        let headers = response.headers().to_vec();
        Ok(HttpiResponseParts {
            status,
            headers,
            body: HttpiBody {
                response,
                runtime: Arc::clone(&self.runtime),
            },
        })
    }
}

impl Drop for HttpiExecutor {
    fn drop(&mut self) {
        // Cancellation wakes any core operation before the owned runtime is
        // shut down. Dropping Endpoint then closes its sockets and tasks.
        self.endpoint.cancel();
    }
}

pub(crate) struct HttpiBody {
    response: HttpResponse,
    runtime: Arc<RuntimeOwner>,
}

impl Read for HttpiBody {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.runtime
            .runtime()
            .block_on(self.response.read(output))
            .map_err(io::Error::other)
    }
}

pub(crate) fn transport_rpc_error(error: TransportError) -> RpcError {
    let error_type = match error.category {
        ErrorCategory::InvalidInput => "IrohInvalidInputError",
        ErrorCategory::Unsupported => "IrohUnsupportedError",
        ErrorCategory::Unavailable => "IrohUnavailableError",
        ErrorCategory::Timeout => "IrohTimeoutError",
        ErrorCategory::Protocol => "IrohProtocolError",
        ErrorCategory::ConnectionReset => "IrohConnectionResetError",
        ErrorCategory::Cancelled => "IrohCancelledError",
        ErrorCategory::Authentication => "IrohAuthenticationError",
        ErrorCategory::ResourceExhausted => "IrohResourceExhaustedError",
        ErrorCategory::Internal => "IrohInternalError",
    };
    RpcError::new(error_type, format_transport_error(&error))
}

fn format_transport_error(error: &TransportError) -> String {
    format!(
        "stage={} category={} dispatch={}: {}",
        stage_name(error.stage),
        category_name(error.category),
        dispatch_name(error.dispatch),
        error.message
    )
}

fn stage_name(stage: ErrorStage) -> &'static str {
    match stage {
        ErrorStage::Parse => "parse",
        ErrorStage::Bind => "bind",
        ErrorStage::Resolve => "resolve",
        ErrorStage::Connect => "connect",
        ErrorStage::Alpn => "alpn",
        ErrorStage::OpenStream => "open_stream",
        ErrorStage::Write => "write",
        ErrorStage::Read => "read",
        ErrorStage::Cancel => "cancel",
        ErrorStage::Close => "close",
        ErrorStage::Internal => "internal",
    }
}

fn category_name(category: ErrorCategory) -> &'static str {
    match category {
        ErrorCategory::InvalidInput => "invalid_input",
        ErrorCategory::Unsupported => "unsupported",
        ErrorCategory::Unavailable => "unavailable",
        ErrorCategory::Timeout => "timeout",
        ErrorCategory::Protocol => "protocol",
        ErrorCategory::ConnectionReset => "connection_reset",
        ErrorCategory::Cancelled => "cancelled",
        ErrorCategory::Authentication => "authentication",
        ErrorCategory::ResourceExhausted => "resource_exhausted",
        ErrorCategory::Internal => "internal",
    }
}

fn dispatch_name(dispatch: DispatchCertainty) -> &'static str {
    match dispatch {
        DispatchCertainty::NotSent => "not_sent",
        DispatchCertainty::Unknown => "unknown",
        DispatchCertainty::Sent => "sent",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_canonical_httpi_targets() {
        let root = HttpiTarget::parse(&format!("httpi://{ID}/")).unwrap();
        assert_eq!(root.endpoint_id(), ID);
        assert_eq!(root.base_path(), "");
        let nested = HttpiTarget::parse(&format!("httpi://{ID}/api/v1")).unwrap();
        assert_eq!(nested.base_path(), "/api/v1");
    }

    #[test]
    fn rejects_noncanonical_httpi_targets() {
        for value in [
            format!("HTTPI://{ID}"),
            format!("httpi://{ID}:443"),
            format!("httpi://user@{ID}"),
            format!("httpi://{ID}/vgi/"),
            format!("httpi://{ID}/a//b"),
            format!("httpi://{ID}/a/../b"),
            format!("httpi://{ID}/a/%2e%2e/b"),
            format!("httpi://{ID}/a%2fb"),
            format!("httpi://{ID}/a%5cb"),
            format!("httpi://{ID}/vgi?x=1"),
            format!("httpi://{ID}/vgi#x"),
        ] {
            assert!(HttpiTarget::parse(&value).is_err(), "accepted {value}");
        }
    }
}
