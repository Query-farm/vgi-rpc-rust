//! Arrow-free native Iroh transport primitives shared by VGI adapters.
//!
//! This crate deliberately knows nothing about Arrow or the VGI RPC client.
//! It owns one authenticated endpoint, pooled ALPN connections, raw QUIC
//! streams, and HTTP/1.1 exchanges carried on `iroh-http/2` streams.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

pub const VGI_IROH_ALPN: &[u8] = b"vgi-rpc/arrow-mux/1";
pub const IROH_HTTP_ALPN: &[u8] = b"iroh-http/2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ErrorStage {
    Parse = 1,
    Bind = 2,
    Resolve = 3,
    Connect = 4,
    Alpn = 5,
    OpenStream = 6,
    Write = 7,
    Read = 8,
    Cancel = 9,
    Close = 10,
    Internal = 11,
}

#[allow(non_upper_case_globals)]
impl ErrorStage {
    pub const Config: Self = Self::Parse;
    pub const Endpoint: Self = Self::Bind;
    pub const WriteRequest: Self = Self::Write;
    pub const ReadResponse: Self = Self::Read;
    pub const Finish: Self = Self::Write;
    pub const Shutdown: Self = Self::Close;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ErrorCategory {
    InvalidInput = 1,
    Unsupported = 2,
    Unavailable = 3,
    Timeout = 4,
    Protocol = 5,
    ConnectionReset = 6,
    Cancelled = 7,
    Authentication = 8,
    ResourceExhausted = 9,
    Internal = 10,
}

#[allow(non_upper_case_globals)]
impl ErrorCategory {
    pub const InvalidArgument: Self = Self::InvalidInput;
    pub const Io: Self = Self::ConnectionReset;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DispatchCertainty {
    NotSent = 0,
    Unknown = 1,
    Sent = 2,
}

#[allow(non_upper_case_globals)]
impl DispatchCertainty {
    pub const NotApplicable: Self = Self::NotSent;
    pub const NotDispatched: Self = Self::NotSent;
    pub const PossiblyDispatched: Self = Self::Unknown;
    pub const Dispatched: Self = Self::Sent;
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct TransportError {
    pub stage: ErrorStage,
    pub category: ErrorCategory,
    pub dispatch: DispatchCertainty,
    pub message: String,
}

impl TransportError {
    pub fn new(
        stage: ErrorStage,
        category: ErrorCategory,
        dispatch: DispatchCertainty,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            category,
            dispatch,
            message: message.into(),
        }
    }

    fn timeout(stage: ErrorStage, dispatch: DispatchCertainty) -> Self {
        Self::new(
            stage,
            ErrorCategory::Timeout,
            dispatch,
            "Iroh operation timed out",
        )
    }

    fn cancelled(_stage: ErrorStage, dispatch: DispatchCertainty) -> Self {
        Self::new(
            ErrorStage::Cancel,
            ErrorCategory::Cancelled,
            dispatch,
            "Iroh operation cancelled",
        )
    }
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Clone, Debug)]
pub enum RelayConfig {
    Default,
    Disabled,
    Custom(Vec<RelayUrl>),
}

#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub secret_key: Option<SecretKey>,
    pub relays: RelayConfig,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            secret_key: None,
            relays: RelayConfig::Default,
            connect_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(300),
        }
    }
}

impl EndpointConfig {
    pub fn parse_secret_key(value: &str) -> Result<SecretKey> {
        SecretKey::from_str(value.trim()).map_err(|error| {
            TransportError::new(
                ErrorStage::Config,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotApplicable,
                format!("invalid Iroh secret key: {error}"),
            )
        })
    }

    pub fn parse_relays(values: &[String]) -> Result<Vec<RelayUrl>> {
        values
            .iter()
            .map(|value| {
                RelayUrl::from_str(value).map_err(|error| {
                    TransportError::new(
                        ErrorStage::Config,
                        ErrorCategory::InvalidArgument,
                        DispatchCertainty::NotApplicable,
                        format!("invalid Iroh relay URL: {error}"),
                    )
                })
            })
            .collect()
    }

    fn validate(&self) -> Result<()> {
        if self.connect_timeout.is_zero() || self.io_timeout.is_zero() {
            return Err(TransportError::new(
                ErrorStage::Config,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotApplicable,
                "Iroh timeouts must be positive",
            ));
        }
        if matches!(&self.relays, RelayConfig::Custom(values) if values.is_empty()) {
            return Err(TransportError::new(
                ErrorStage::Config,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotApplicable,
                "custom Iroh relay configuration must not be empty",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RemoteAddr {
    pub id: EndpointId,
    pub relay_url: Option<RelayUrl>,
    pub direct_addresses: Vec<SocketAddr>,
}

impl RemoteAddr {
    pub fn from_id(id: EndpointId) -> Self {
        Self {
            id,
            relay_url: None,
            direct_addresses: Vec::new(),
        }
    }

    pub fn parse(id: &str, relay_url: Option<&str>, direct: &[String]) -> Result<Self> {
        let id = EndpointId::from_str(id.trim()).map_err(|error| {
            TransportError::new(
                ErrorStage::Config,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotApplicable,
                format!("invalid Iroh endpoint ID: {error}"),
            )
        })?;
        let relay_url = relay_url
            .map(RelayUrl::from_str)
            .transpose()
            .map_err(|error| {
                TransportError::new(
                    ErrorStage::Config,
                    ErrorCategory::InvalidArgument,
                    DispatchCertainty::NotApplicable,
                    format!("invalid remote Iroh relay URL: {error}"),
                )
            })?;
        let direct_addresses = direct
            .iter()
            .map(|value| {
                value.parse::<SocketAddr>().map_err(|error| {
                    TransportError::new(
                        ErrorStage::Config,
                        ErrorCategory::InvalidArgument,
                        DispatchCertainty::NotApplicable,
                        format!("invalid remote Iroh direct address: {error}"),
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            id,
            relay_url,
            direct_addresses,
        })
    }

    fn endpoint_addr(&self) -> EndpointAddr {
        let mut addr = EndpointAddr::new(self.id);
        if let Some(relay) = self.relay_url.clone() {
            addr = addr.with_relay_url(relay);
        }
        for direct in &self.direct_addresses {
            addr = addr.with_ip_addr(*direct);
        }
        addr
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Protocol {
    Raw,
    Http,
}

impl Protocol {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::Raw => VGI_IROH_ALPN,
            Self::Http => IROH_HTTP_ALPN,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    remote: EndpointId,
    protocol: Protocol,
}

#[derive(Clone)]
pub struct ClientEndpoint {
    endpoint: Endpoint,
    connect_timeout: Duration,
    io_timeout: Duration,
    connections: Arc<Mutex<HashMap<ConnectionKey, Connection>>>,
    cancellation: CancellationToken,
}

impl ClientEndpoint {
    pub async fn bind(config: EndpointConfig) -> Result<Self> {
        config.validate()?;
        let mut builder = Endpoint::builder(presets::N0);
        if let Some(secret_key) = config.secret_key {
            builder = builder.secret_key(secret_key);
        }
        builder = match config.relays {
            RelayConfig::Default => builder,
            RelayConfig::Disabled => builder.relay_mode(RelayMode::Disabled),
            RelayConfig::Custom(relays) => builder.relay_mode(RelayMode::custom(relays)),
        };
        let endpoint = builder.bind().await.map_err(|error| {
            TransportError::new(
                ErrorStage::Endpoint,
                ErrorCategory::Unavailable,
                DispatchCertainty::NotApplicable,
                format!("failed to bind Iroh endpoint: {error}"),
            )
        })?;
        Ok(Self {
            endpoint,
            connect_timeout: config.connect_timeout,
            io_timeout: config.io_timeout,
            connections: Arc::new(Mutex::new(HashMap::new())),
            cancellation: CancellationToken::new(),
        })
    }

    pub fn from_endpoint(
        endpoint: Endpoint,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self> {
        if connect_timeout.is_zero() || io_timeout.is_zero() {
            return Err(TransportError::new(
                ErrorStage::Config,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotApplicable,
                "Iroh timeouts must be positive",
            ));
        }
        Ok(Self {
            endpoint,
            connect_timeout,
            io_timeout,
            connections: Arc::new(Mutex::new(HashMap::new())),
            cancellation: CancellationToken::new(),
        })
    }

    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }
    pub fn raw_endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    async fn connection(&self, remote: &RemoteAddr, protocol: Protocol) -> Result<Connection> {
        let key = ConnectionKey {
            remote: remote.id,
            protocol,
        };
        {
            let connections = self.connections.lock().await;
            if let Some(connection) = connections.get(&key) {
                if connection.close_reason().is_none() {
                    return Ok(connection.clone());
                }
            }
        }
        let connect = self
            .endpoint
            .connect(remote.endpoint_addr(), protocol.alpn());
        let connection = cancellable(
            &self.cancellation,
            self.connect_timeout,
            ErrorStage::Connect,
            DispatchCertainty::NotDispatched,
            connect,
        )
        .await?
        .map_err(|error| {
            TransportError::new(
                ErrorStage::Connect,
                ErrorCategory::Unavailable,
                DispatchCertainty::NotDispatched,
                format!("Iroh connect failed: {error}"),
            )
        })?;
        self.connections
            .lock()
            .await
            .insert(key, connection.clone());
        Ok(connection)
    }

    async fn open(
        &self,
        remote: &RemoteAddr,
        protocol: Protocol,
    ) -> Result<(SendStream, RecvStream, CancellationToken)> {
        let connection = self.connection(remote, protocol).await?;
        let cancellation = self.cancellation.child_token();
        let opened = cancellable(
            &cancellation,
            self.connect_timeout,
            ErrorStage::OpenStream,
            DispatchCertainty::NotDispatched,
            connection.open_bi(),
        )
        .await?;
        match opened {
            Ok((send, recv)) => Ok((send, recv, cancellation)),
            Err(first_error) => {
                self.connections.lock().await.remove(&ConnectionKey {
                    remote: remote.id,
                    protocol,
                });
                Err(TransportError::new(
                    ErrorStage::OpenStream,
                    ErrorCategory::Unavailable,
                    DispatchCertainty::NotDispatched,
                    format!("opening Iroh stream failed: {first_error}"),
                ))
            }
        }
    }

    pub async fn open_raw(&self, remote: &RemoteAddr) -> Result<RawStream> {
        let (send, recv, cancellation) = self.open(remote, Protocol::Raw).await?;
        Ok(RawStream {
            send,
            recv,
            remote_id: remote.id,
            io_timeout: self.io_timeout,
            cancellation,
        })
    }

    pub async fn open_raw_with_timeout(
        &self,
        remote: &RemoteAddr,
        duration: Duration,
    ) -> Result<RawStream> {
        if duration.is_zero() {
            return Err(TransportError::new(
                ErrorStage::OpenStream,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotDispatched,
                "stream-open timeout must be positive",
            ));
        }
        timeout(duration, self.open_raw(remote))
            .await
            .map_err(|_| {
                TransportError::timeout(ErrorStage::OpenStream, DispatchCertainty::NotDispatched)
            })?
    }

    pub async fn request(&self, remote: &RemoteAddr, request: HttpRequest) -> Result<HttpResponse> {
        self.request_with_timeout(remote, request, self.io_timeout)
            .await
    }

    pub async fn request_with_timeout(
        &self,
        remote: &RemoteAddr,
        request: HttpRequest,
        response_head_timeout: Duration,
    ) -> Result<HttpResponse> {
        if response_head_timeout.is_zero() {
            return Err(TransportError::new(
                ErrorStage::ReadResponse,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotDispatched,
                "HTTP response-head timeout must be positive",
            ));
        }
        let (send, recv, cancellation) = self.open(remote, Protocol::Http).await?;
        let io = TokioIo::new(IrohIo { send, recv });
        let (mut sender, driver) = cancellable(
            &cancellation,
            self.connect_timeout,
            ErrorStage::OpenStream,
            DispatchCertainty::NotDispatched,
            hyper::client::conn::http1::Builder::new().handshake::<_, Full<Bytes>>(io),
        )
        .await?
        .map_err(|error| {
            TransportError::new(
                ErrorStage::OpenStream,
                ErrorCategory::Protocol,
                DispatchCertainty::NotDispatched,
                format!("Iroh HTTP handshake failed: {error}"),
            )
        })?;
        let mut driver = AbortOnDrop(Some(tokio::spawn(async move {
            let _ = driver.await;
        })));
        let hyper_request = request.into_hyper(remote.id)?;
        let response = cancellable(
            &cancellation,
            response_head_timeout,
            ErrorStage::ReadResponse,
            DispatchCertainty::PossiblyDispatched,
            sender.send_request(hyper_request),
        )
        .await
        .and_then(|result| {
            result.map_err(|error| {
                TransportError::new(
                    ErrorStage::ReadResponse,
                    ErrorCategory::Protocol,
                    DispatchCertainty::PossiblyDispatched,
                    format!("Iroh HTTP request failed: {error}"),
                )
            })
        });
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                cancellation.cancel();
                return Err(error);
            }
        };
        driver.detach();
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()))
            .collect();
        Ok(HttpResponse {
            status,
            headers,
            body: response.into_body(),
            buffered: Bytes::new(),
            remote_id: remote.id,
            io_timeout: self.io_timeout,
            cancellation,
        })
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub async fn close(&self) {
        self.cancellation.cancel();
        let mut connections = self.connections.lock().await;
        for connection in connections.values() {
            connection.close(0_u32.into(), b"VGI endpoint closed");
        }
        connections.clear();
        self.endpoint.close().await;
    }
}

pub struct RawStream {
    send: SendStream,
    recv: RecvStream,
    remote_id: EndpointId,
    io_timeout: Duration,
    cancellation: CancellationToken,
}

impl RawStream {
    pub fn remote_id(&self) -> EndpointId {
        self.remote_id
    }
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.read_with_timeout(buffer, self.io_timeout).await
    }

    /// Read with a caller-selected polling deadline. A timeout does not cancel
    /// or poison the stream, so synchronous consumers can periodically check
    /// their own cancellation source.
    pub async fn read_with_timeout(
        &mut self,
        buffer: &mut [u8],
        duration: Duration,
    ) -> Result<usize> {
        if duration.is_zero() {
            return Err(TransportError::new(
                ErrorStage::Read,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::Dispatched,
                "read timeout must be positive",
            ));
        }
        cancellable(
            &self.cancellation,
            duration,
            ErrorStage::Read,
            DispatchCertainty::Dispatched,
            self.recv.read(buffer),
        )
        .await?
        .map_err(|error| {
            TransportError::new(
                ErrorStage::Read,
                ErrorCategory::Io,
                DispatchCertainty::Dispatched,
                format!("Iroh stream read failed: {error}"),
            )
        })
        .map(Option::unwrap_or_default)
    }

    pub async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        self.write_all_with_timeout(buffer, self.io_timeout).await
    }

    pub async fn write_all_with_timeout(
        &mut self,
        buffer: &[u8],
        duration: Duration,
    ) -> Result<()> {
        if duration.is_zero() {
            return Err(TransportError::new(
                ErrorStage::Write,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::PossiblyDispatched,
                "write timeout must be positive",
            ));
        }
        let result = cancellable(
            &self.cancellation,
            duration,
            ErrorStage::Write,
            DispatchCertainty::PossiblyDispatched,
            self.send.write_all(buffer),
        )
        .await
        .and_then(|result| {
            result.map_err(|error| {
                TransportError::new(
                    ErrorStage::Write,
                    ErrorCategory::Io,
                    DispatchCertainty::PossiblyDispatched,
                    format!("Iroh stream write failed: {error}"),
                )
            })
        });
        if result.is_err() {
            self.cancellation.cancel();
        }
        result
    }

    pub async fn finish(&mut self) -> Result<()> {
        cancellable(
            &self.cancellation,
            self.io_timeout,
            ErrorStage::Finish,
            DispatchCertainty::Dispatched,
            async { self.send.finish() },
        )
        .await?
        .map_err(|error| {
            TransportError::new(
                ErrorStage::Finish,
                ErrorCategory::Io,
                DispatchCertainty::Dispatched,
                format!("finishing Iroh stream failed: {error}"),
            )
        })
    }
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Bytes,
}

impl HttpRequest {
    fn into_hyper(self, remote_id: EndpointId) -> Result<hyper::Request<Full<Bytes>>> {
        let mut builder = hyper::Request::builder()
            .method(self.method.as_str())
            .uri(self.path.as_str());
        let headers = builder.headers_mut().ok_or_else(|| {
            TransportError::new(
                ErrorStage::WriteRequest,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotDispatched,
                "invalid HTTP request",
            )
        })?;
        for (name, value) in self.headers {
            let name = hyper::header::HeaderName::from_bytes(&name).map_err(|error| {
                TransportError::new(
                    ErrorStage::WriteRequest,
                    ErrorCategory::InvalidArgument,
                    DispatchCertainty::NotDispatched,
                    format!("invalid HTTP header name: {error}"),
                )
            })?;
            let value = hyper::header::HeaderValue::from_bytes(&value).map_err(|error| {
                TransportError::new(
                    ErrorStage::WriteRequest,
                    ErrorCategory::InvalidArgument,
                    DispatchCertainty::NotDispatched,
                    format!("invalid HTTP header value: {error}"),
                )
            })?;
            headers.append(name, value);
        }
        if !headers.contains_key(hyper::header::HOST) {
            headers.insert(
                hyper::header::HOST,
                hyper::header::HeaderValue::from_str(&endpoint_id_hex(remote_id)).map_err(
                    |error| {
                        TransportError::new(
                            ErrorStage::WriteRequest,
                            ErrorCategory::InvalidArgument,
                            DispatchCertainty::NotDispatched,
                            format!("invalid Iroh endpoint ID for HTTP Host: {error}"),
                        )
                    },
                )?,
            );
        }
        builder.body(Full::new(self.body)).map_err(|error| {
            TransportError::new(
                ErrorStage::WriteRequest,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::NotDispatched,
                format!("invalid HTTP request: {error}"),
            )
        })
    }
}

pub struct HttpResponse {
    status: u16,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: hyper::body::Incoming,
    buffered: Bytes,
    remote_id: EndpointId,
    io_timeout: Duration,
    cancellation: CancellationToken,
}

impl HttpResponse {
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn headers(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.headers
    }
    pub fn remote_id(&self) -> EndpointId {
        self.remote_id
    }
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub async fn read(&mut self, output: &mut [u8]) -> Result<usize> {
        self.read_with_timeout(output, self.io_timeout).await
    }

    /// Read body bytes with a non-poisoning polling deadline.
    pub async fn read_with_timeout(
        &mut self,
        output: &mut [u8],
        duration: Duration,
    ) -> Result<usize> {
        if duration.is_zero() {
            return Err(TransportError::new(
                ErrorStage::Read,
                ErrorCategory::InvalidArgument,
                DispatchCertainty::Dispatched,
                "HTTP read timeout must be positive",
            ));
        }
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.buffered.is_empty() {
                let len = output.len().min(self.buffered.len());
                output[..len].copy_from_slice(&self.buffered.split_to(len));
                return Ok(len);
            }
            let frame = cancellable(
                &self.cancellation,
                duration,
                ErrorStage::Read,
                DispatchCertainty::Dispatched,
                self.body.frame(),
            )
            .await?;
            match frame {
                None => return Ok(0),
                Some(Err(error)) => {
                    return Err(TransportError::new(
                        ErrorStage::Read,
                        ErrorCategory::Protocol,
                        DispatchCertainty::Dispatched,
                        format!("Iroh HTTP body read failed: {error}"),
                    ))
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.buffered = data;
                    }
                }
            }
        }
    }
}

async fn cancellable<T, F>(
    cancellation: &CancellationToken,
    duration: Duration,
    stage: ErrorStage,
    dispatch: DispatchCertainty,
    future: F,
) -> Result<T>
where
    F: Future<Output = T>,
{
    tokio::select! {
        _ = cancellation.cancelled() => Err(TransportError::cancelled(stage, dispatch)),
        result = timeout(duration, future) => result.map_err(|_| TransportError::timeout(stage, dispatch)),
    }
}

struct IrohIo {
    send: SendStream,
    recv: RecvStream,
}

struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);

impl AbortOnDrop {
    fn detach(&mut self) {
        self.0.take();
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

impl AsyncRead for IrohIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for IrohIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buffer)
            .map(|result| result.map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error)))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// Stable lowercase hexadecimal form used by VGI endpoint URIs and the C ABI.
pub fn endpoint_id_hex(id: EndpointId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in id.as_bytes() {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    use iroh_http_core::{serve, Body, IrohEndpoint, NetworkingOptions, NodeOptions, ServeOptions};

    #[test]
    fn parses_both_key_encodings_and_stable_ids() {
        let secret = SecretKey::generate();
        let hex = hex_string(&secret.to_bytes());
        assert_eq!(
            EndpointConfig::parse_secret_key(&hex).unwrap().public(),
            secret.public()
        );
        assert_eq!(endpoint_id_hex(secret.public()).len(), 64);
        assert_eq!(
            RemoteAddr::parse(&endpoint_id_hex(secret.public()), None, &[])
                .unwrap()
                .id,
            secret.public()
        );
    }

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn raw_loopback_reuses_one_authenticated_connection() {
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![VGI_IROH_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let remote = RemoteAddr {
            id: server.id(),
            relay_url: None,
            direct_addresses: server.addr().ip_addrs().copied().collect(),
        };
        let client = ClientEndpoint::bind(EndpointConfig {
            relays: RelayConfig::Disabled,
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            ..EndpointConfig::default()
        })
        .await
        .unwrap();
        let expected_client = client.id();
        let (responses_read_tx, responses_read_rx) = tokio::sync::oneshot::channel();

        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            assert_eq!(connection.remote_id(), expected_client);
            for expected in [b"one".as_slice(), b"two".as_slice()] {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let mut input = vec![0_u8; expected.len()];
                recv.read_exact(&mut input).await.unwrap();
                assert_eq!(input, expected);
                send.write_all(expected).await.unwrap();
                send.finish().unwrap();
            }
            responses_read_rx.await.unwrap();
        });

        for payload in [b"one".as_slice(), b"two".as_slice()] {
            let mut stream = client.open_raw(&remote).await.unwrap();
            stream.write_all(payload).await.unwrap();
            stream.finish().await.unwrap();
            let mut received = vec![0; payload.len()];
            let mut offset = 0;
            while offset < received.len() {
                let count = stream.read(&mut received[offset..]).await.unwrap();
                assert!(count > 0, "unexpected EOF");
                offset += count;
            }
            assert_eq!(received, payload);
        }
        responses_read_tx.send(()).unwrap();
        server_task.await.unwrap();
        client.close().await;
    }

    fn local_http_options() -> NodeOptions {
        NodeOptions {
            networking: NetworkingOptions {
                disabled: true,
                bind_addrs: vec!["127.0.0.1:0".into()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn http_loopback_streams_status_headers_and_body() {
        let server = IrohEndpoint::bind(local_http_options()).await.unwrap();
        let client = IrohEndpoint::bind(local_http_options()).await.unwrap();
        let _guard = serve(
            server.clone(),
            ServeOptions::default(),
            tower::service_fn(|request: hyper::Request<Body>| async move {
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let host = request
                    .headers()
                    .get(hyper::header::HOST)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();
                if path == "/slow-head" {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let request = request.into_body().collect().await.unwrap().to_bytes();
                let text = Bytes::from(format!("{method} host={host} received={}", request.len()));
                let frames = futures_util::stream::once(async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok::<_, Infallible>(hyper::body::Frame::data(text))
                });
                let mut response =
                    hyper::Response::new(Body::new(http_body_util::StreamBody::new(frames)));
                response
                    .headers_mut()
                    .append("x-vgi-test", "first".parse().unwrap());
                response
                    .headers_mut()
                    .append("x-vgi-test", "second".parse().unwrap());
                Ok::<_, Infallible>(response)
            }),
        );
        let core = ClientEndpoint::from_endpoint(
            client.raw().clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        let remote = RemoteAddr {
            id: server.raw().id(),
            relay_url: None,
            direct_addresses: server.raw().addr().ip_addrs().copied().collect(),
        };
        let mut response = core
            .request(
                &remote,
                HttpRequest {
                    method: "POST".into(),
                    path: "/vgi".into(),
                    headers: vec![],
                    body: Bytes::from_static(b"arrow-ipc"),
                },
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .iter()
                .filter(|(name, _)| name == b"x-vgi-test")
                .count(),
            2
        );
        let mut body = Vec::new();
        let mut chunk = [0_u8; 4];
        let timeout = response
            .read_with_timeout(&mut chunk, Duration::from_millis(1))
            .await
            .unwrap_err();
        assert_eq!(timeout.category, ErrorCategory::Timeout);
        loop {
            let count = response.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(
            body,
            format!(
                "POST host={} received=9",
                endpoint_id_hex(server.raw().id())
            )
            .as_bytes()
        );

        let head_timeout = match core
            .request_with_timeout(
                &remote,
                HttpRequest {
                    method: "GET".into(),
                    path: "/slow-head".into(),
                    headers: vec![],
                    body: Bytes::new(),
                },
                Duration::from_millis(1),
            )
            .await
        {
            Ok(_) => panic!("slow response headers unexpectedly completed"),
            Err(error) => error,
        };
        assert_eq!(head_timeout.category, ErrorCategory::Timeout);
        assert_eq!(head_timeout.dispatch, DispatchCertainty::Unknown);

        let mut options = core
            .request(
                &remote,
                HttpRequest {
                    method: "OPTIONS".into(),
                    path: "/vgi".into(),
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .unwrap();
        let mut options_body = Vec::new();
        loop {
            let count = options.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            options_body.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(
            options_body,
            format!(
                "OPTIONS host={} received=0",
                endpoint_id_hex(server.raw().id())
            )
            .as_bytes()
        );
        core.close().await;
    }
}
