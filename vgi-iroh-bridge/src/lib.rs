//! Narrow ingress bridge from authenticated Iroh connections to ordinary VGI
//! worker listeners.
//!
//! This crate is intentionally not a load balancer.  For the raw
//! `vgi-rpc/arrow-mux/1` protocol, every accepted QUIC bidirectional stream is
//! pinned to exactly one new TCP or Unix-domain upstream connection for its
//! lifetime.  The upstream receives a fixed, versioned PROXY-v2 TLV containing
//! the cryptographically authenticated Iroh EndpointId.  The worker chooses a
//! local issuer and authorization policy; the bridge cannot assert either.
//!
//! For `iroh-http/2`, [`HttpBridgeProtocol`] streams requests through one
//! shared iroh-http connection runtime and a pooled Hyper client to one fixed
//! HTTP(S) origin. It overwrites forwarded identity from the typed raw
//! EndpointId and applies reverse-proxy header boundary rules in both
//! directions. Neither protocol chooses among upstream workers.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::header::{CONNECTION, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use hyper::{Request, Response, StatusCode};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointId;
use iroh_http_core::{
    Body as IrohHttpBody, ConnectionServeOptions, ConnectionServeRuntime, RemoteEndpointId,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tower::Service;

pub use vgi_rpc_iroh::VGI_IROH_ALPN;

/// Iroh HTTP ALPN accepted by [`HttpBridgeProtocol`].
pub const IROH_HTTP_ALPN: &[u8] = iroh_http_core::ALPN;
/// Verified identity header injected into every upstream HTTP request.
pub const IROH_FORWARDED_ENDPOINT_HEADER: &str = "vgi-forwarded-iroh-endpoint";

/// Private-use PROXY-v2 TLV assigned by the VGI transport identity contract.
pub const IROH_ENDPOINT_TLV: u8 = 0xe0;
/// Current fixed payload version of [`IROH_ENDPOINT_TLV`].
pub const IROH_ENDPOINT_TLV_VERSION: u8 = 1;

const PROXY_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const PROXY_V2_VERSION_COMMAND: u8 = 0x21;
const PROXY_V2_UNSPEC: u8 = 0x00;
const IDENTITY_PAYLOAD_LEN: usize = 33;
const IDENTITY_TLV_LEN: usize = 1 + 2 + IDENTITY_PAYLOAD_LEN;
const CLOSE_CODE: u32 = 0;

type PooledHttpClient = Client<HttpsConnector<HttpConnector>, IrohHttpBody>;

/// HTTP serving limits and lifecycle policy for [`HttpBridgeProtocol`].
#[derive(Clone, Debug)]
pub struct HttpBridgeOptions {
    /// Shared HTTP connection runtime settings.
    pub connection: ConnectionServeOptions,
}

impl Default for HttpBridgeOptions {
    fn default() -> Self {
        let mut connection = ConnectionServeOptions::default();
        // A transparent bridge must preserve Content-Encoding and the exact
        // wire body. Operators may opt into decoding when the upstream is an
        // application handler rather than another HTTP hop.
        connection.decompression = false;
        Self { connection }
    }
}

/// A non-balancing HTTP bridge protocol suitable for an `iroh::protocol::Router`.
///
/// Every request is streamed to one fixed HTTP(S) origin and base path. The
/// pooled Hyper client may reuse connections to that origin, but this type
/// never selects among worker destinations, follows redirects, or retries a
/// request.
#[derive(Clone)]
pub struct HttpBridgeProtocol {
    upstream: FixedHttpUpstream,
    runtime: ConnectionServeRuntime,
}

impl std::fmt::Debug for HttpBridgeProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpBridgeProtocol")
            .field("upstream", &self.upstream)
            .finish_non_exhaustive()
    }
}

impl HttpBridgeProtocol {
    /// Configure one fixed HTTP(S) upstream, including an optional base path.
    ///
    /// For example, an incoming `/catalog?limit=1` request sent through an
    /// upstream base of `https://worker.example/vgi` reaches
    /// `https://worker.example/vgi/catalog?limit=1`.
    pub fn new(upstream_base: &str, options: HttpBridgeOptions) -> Result<Self> {
        let upstream = FixedHttpUpstream::parse(upstream_base)?;
        let service = HttpProxyService::new(upstream.clone());
        let runtime =
            ConnectionServeRuntime::new(options.connection, service).map_err(|error| {
                BridgeError::HttpRuntime {
                    message: error.to_string(),
                }
            })?;
        Ok(Self { upstream, runtime })
    }

    /// Gracefully stop all shared HTTP connection handlers and drain response
    /// delivery within the configured runtime deadline.
    pub async fn shutdown(&self) -> bool {
        self.runtime.shutdown().await
    }

    async fn serve_connection(&self, connection: Connection) -> Result<()> {
        self.runtime
            .serve_connection(connection)
            .await
            .map(|_| ())
            .map_err(|error| BridgeError::HttpRuntime {
                message: error.to_string(),
            })
    }
}

impl ProtocolHandler for HttpBridgeProtocol {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        self.serve_connection(connection).await.map_err(|error| {
            tracing::warn!(%error, "HTTP VGI bridge connection failed");
            AcceptError::from_err(io::Error::other("HTTP bridge connection failed"))
        })
    }

    async fn shutdown(&self) {
        if !HttpBridgeProtocol::shutdown(self).await {
            tracing::warn!("HTTP VGI bridge response drain timed out");
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixedHttpUpstream {
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    base_path: String,
}

impl FixedHttpUpstream {
    fn parse(value: &str) -> Result<Self> {
        let uri = value
            .parse::<Uri>()
            .map_err(|_| BridgeError::InvalidHttpUpstream {
                reason: "must be an absolute HTTP(S) URI",
            })?;
        let scheme = uri
            .scheme()
            .filter(|scheme| {
                *scheme == &http::uri::Scheme::HTTP || *scheme == &http::uri::Scheme::HTTPS
            })
            .cloned()
            .ok_or(BridgeError::InvalidHttpUpstream {
                reason: "scheme must be http or https",
            })?;
        let authority = uri
            .authority()
            .cloned()
            .ok_or(BridgeError::InvalidHttpUpstream {
                reason: "authority is required",
            })?;
        if authority.as_str().contains('@') {
            return Err(BridgeError::InvalidHttpUpstream {
                reason: "userinfo is forbidden",
            });
        }
        if uri.query().is_some() {
            return Err(BridgeError::InvalidHttpUpstream {
                reason: "base URI must not contain a query",
            });
        }
        let path = uri.path();
        let base_path = if path == "/" {
            String::new()
        } else {
            path.trim_end_matches('/').to_owned()
        };
        Ok(Self {
            scheme,
            authority,
            base_path,
        })
    }

    fn rewrite_uri(&self, incoming: &Uri) -> Result<Uri> {
        let incoming_path = incoming.path();
        let mut path_and_query = String::with_capacity(
            self.base_path
                .len()
                .saturating_add(incoming_path.len())
                .saturating_add(
                    incoming
                        .query()
                        .map_or(0, |query| query.len().saturating_add(1)),
                ),
        );
        path_and_query.push_str(&self.base_path);
        if incoming_path.starts_with('/') {
            path_and_query.push_str(incoming_path);
        } else {
            path_and_query.push('/');
            path_and_query.push_str(incoming_path);
        }
        if path_and_query.is_empty() {
            path_and_query.push('/');
        }
        if let Some(query) = incoming.query() {
            path_and_query.push('?');
            path_and_query.push_str(query);
        }
        Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(path_and_query)
            .build()
            .map_err(|_| BridgeError::InvalidHttpRequest)
    }

    fn host_header(&self) -> Result<HeaderValue> {
        HeaderValue::from_str(self.authority.as_str()).map_err(|_| BridgeError::InvalidHttpRequest)
    }
}

#[derive(Clone)]
struct HttpProxyService {
    upstream: FixedHttpUpstream,
    client: PooledHttpClient,
}

impl HttpProxyService {
    fn new(upstream: FixedHttpUpstream) -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let mut builder = Client::builder(TokioExecutor::new());
        builder.retry_canceled_requests(false);
        let client = builder.build(connector);
        Self { upstream, client }
    }

    async fn proxy(&self, request: Request<IrohHttpBody>) -> Response<IrohHttpBody> {
        let endpoint_id = match request.extensions().get::<RemoteEndpointId>() {
            Some(identity) => identity.0,
            None => {
                tracing::error!("HTTP bridge request missing authenticated Iroh identity");
                return bad_gateway();
            }
        };
        let (mut parts, body) = request.into_parts();
        let rewritten_uri = match self.upstream.rewrite_uri(&parts.uri) {
            Ok(uri) => uri,
            Err(error) => {
                tracing::warn!(%error, "HTTP bridge rejected request target");
                return bad_gateway();
            }
        };
        let mut headers = sanitize_request_headers(&parts.headers);
        let host = match self.upstream.host_header() {
            Ok(host) => host,
            Err(error) => {
                tracing::warn!(%error, "HTTP bridge could not construct upstream Host header");
                return bad_gateway();
            }
        };
        let identity = match HeaderValue::from_str(&hex::encode(endpoint_id.as_bytes())) {
            Ok(identity) => identity,
            Err(_) => return bad_gateway(),
        };
        headers.insert(HOST, host);
        headers.insert(
            HeaderName::from_static(IROH_FORWARDED_ENDPOINT_HEADER),
            identity,
        );
        parts.uri = rewritten_uri;
        parts.headers = headers;

        let response = match self.client.request(Request::from_parts(parts, body)).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%error, "HTTP VGI upstream request failed");
                return bad_gateway();
            }
        };
        let (mut parts, body) = response.into_parts();
        parts.headers = sanitize_response_headers(&parts.headers);
        Response::from_parts(parts, IrohHttpBody::new(body))
    }
}

impl Service<Request<IrohHttpBody>> for HttpProxyService {
    type Response = Response<IrohHttpBody>;
    type Error = std::convert::Infallible;
    type Future = Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<Self::Response, Self::Error>>
                + Send,
        >,
    >;

    fn poll_ready(
        &mut self,
        _context: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<IrohHttpBody>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move { Ok(service.proxy(request).await) })
    }
}

fn strip_hop_by_hop(headers: &HeaderMap) -> HeaderMap {
    let nominated = connection_nominated_headers(headers);
    let mut clean = HeaderMap::with_capacity(headers.len());
    for name in headers.keys() {
        if is_hop_by_hop(name) || nominated.contains(name) {
            continue;
        }
        for value in headers.get_all(name) {
            clean.append(name.clone(), value.clone());
        }
    }
    clean
}

fn sanitize_request_headers(headers: &HeaderMap) -> HeaderMap {
    let mut clean = strip_hop_by_hop(headers);
    clean.remove(HOST);
    clean.remove(IROH_FORWARDED_ENDPOINT_HEADER);
    clean
}

fn sanitize_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut clean = strip_hop_by_hop(headers);
    clean.remove(IROH_FORWARDED_ENDPOINT_HEADER);
    clean
}

fn connection_nominated_headers(headers: &HeaderMap) -> std::collections::HashSet<HeaderName> {
    let mut nominated = std::collections::HashSet::new();
    for value in headers.get_all(CONNECTION) {
        for token in value.as_bytes().split(|byte| *byte == b',') {
            let token = trim_optional_whitespace(token);
            if let Ok(name) = HeaderName::from_bytes(token) {
                nominated.insert(name);
            }
        }
    }
    nominated
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len().saturating_sub(1)];
    }
    value
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn bad_gateway() -> Response<IrohHttpBody> {
    let mut response = Response::new(IrohHttpBody::full("Bad Gateway"));
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response
}

/// One non-balancing raw-worker destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawUpstream {
    Tcp(std::net::SocketAddr),
    /// DNS name or IP authority in `host:port` form. Resolution is included in
    /// the configured connect deadline, so this can target an internal load
    /// balancer without introducing bridge-side balancing.
    TcpAuthority(String),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

/// Admission and lifecycle bounds for the raw bridge.
#[derive(Clone, Debug)]
pub struct RawBridgeOptions {
    pub connect_timeout: Duration,
    pub first_stream_timeout: Duration,
    /// Maximum wait for another mux stream after the first stream is accepted.
    pub connection_idle_timeout: Duration,
    pub max_connections: usize,
    pub max_connections_per_peer: usize,
    pub max_streams: usize,
    pub max_streams_per_connection: usize,
    pub drain_timeout: Duration,
}

impl Default for RawBridgeOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            first_stream_timeout: Duration::from_secs(15),
            connection_idle_timeout: Duration::from_secs(60),
            max_connections: 256,
            max_connections_per_peer: 8,
            max_streams: 1024,
            max_streams_per_connection: 32,
            drain_timeout: Duration::from_secs(10),
        }
    }
}

impl RawBridgeOptions {
    fn validate(&self) -> Result<()> {
        if self.connect_timeout.is_zero()
            || self.first_stream_timeout.is_zero()
            || self.connection_idle_timeout.is_zero()
            || self.drain_timeout.is_zero()
            || self.max_connections == 0
            || self.max_connections_per_peer == 0
            || self.max_streams == 0
            || self.max_streams_per_connection == 0
            || self.max_connections > Semaphore::MAX_PERMITS
            || self.max_connections_per_peer > Semaphore::MAX_PERMITS
            || self.max_streams > Semaphore::MAX_PERMITS
            || self.max_streams_per_connection > Semaphore::MAX_PERMITS
            || self.max_connections_per_peer > self.max_connections
            || self.max_streams_per_connection > self.max_streams
        {
            return Err(BridgeError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("bridge timeouts and admission limits are invalid or out of range")]
    InvalidConfiguration,
    #[error("invalid HTTP upstream: {reason}")]
    InvalidHttpUpstream { reason: &'static str },
    #[error("invalid HTTP request target")]
    InvalidHttpRequest,
    #[error("HTTP connection runtime: {message}")]
    HttpRuntime { message: String },
    #[error("{operation} timed out")]
    Timeout { operation: &'static str },
    #[error("{operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{operation}: {message}")]
    Iroh {
        operation: &'static str,
        message: String,
    },
}

type Result<T> = std::result::Result<T, BridgeError>;

fn iroh_error(operation: &'static str, error: impl std::fmt::Display) -> BridgeError {
    BridgeError::Iroh {
        operation,
        message: error.to_string(),
    }
}

/// Build the entire fixed-size PROXY-v2 identity preamble.
///
/// The command is PROXY and the address family/protocol is UNSPEC.  Ordinary
/// PROXY-v2 parsers must continue rejecting that combination unless the worker
/// has explicitly enabled VGI Iroh identity forwarding.
pub fn encode_iroh_proxy_v2(endpoint_id: EndpointId) -> [u8; 16 + IDENTITY_TLV_LEN] {
    let mut output = [0_u8; 16 + IDENTITY_TLV_LEN];
    output[..12].copy_from_slice(PROXY_V2_SIGNATURE);
    output[12] = PROXY_V2_VERSION_COMMAND;
    output[13] = PROXY_V2_UNSPEC;
    output[14..16].copy_from_slice(&(IDENTITY_TLV_LEN as u16).to_be_bytes());
    output[16] = IROH_ENDPOINT_TLV;
    output[17..19].copy_from_slice(&(IDENTITY_PAYLOAD_LEN as u16).to_be_bytes());
    output[19] = IROH_ENDPOINT_TLV_VERSION;
    output[20..52].copy_from_slice(endpoint_id.as_bytes());
    output
}

/// Raw bridge protocol suitable for an `iroh::protocol::Router`.
#[derive(Clone)]
pub struct RawBridgeProtocol {
    upstream: RawUpstream,
    options: RawBridgeOptions,
    connections: Arc<Semaphore>,
    peer_connections: Arc<PeerConnectionAdmission>,
    streams: Arc<Semaphore>,
    shutdown: CancellationToken,
}

impl std::fmt::Debug for RawBridgeProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawBridgeProtocol")
            .field("upstream", &self.upstream)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl RawBridgeProtocol {
    pub fn new(upstream: RawUpstream, options: RawBridgeOptions) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            upstream,
            connections: Arc::new(Semaphore::new(options.max_connections)),
            peer_connections: Arc::new(PeerConnectionAdmission::new(
                options.max_connections_per_peer,
            )),
            streams: Arc::new(Semaphore::new(options.max_streams)),
            options,
            shutdown: CancellationToken::new(),
        })
    }

    async fn serve_connection(&self, connection: Connection) -> Result<()> {
        if connection.alpn() != VGI_IROH_ALPN {
            connection.close(CLOSE_CODE.into(), b"unexpected ALPN");
            return Err(iroh_error("validate ALPN", "unexpected protocol"));
        }
        let remote = connection.remote_id();
        let _peer_permit = self.peer_connections.acquire(remote).ok_or_else(|| {
            connection.close(CLOSE_CODE.into(), b"peer connection limit reached");
            iroh_error("connection admission", "peer at capacity")
        })?;
        let _connection_permit =
            Arc::clone(&self.connections)
                .try_acquire_owned()
                .map_err(|_| {
                    connection.close(CLOSE_CODE.into(), b"bridge connection limit reached");
                    iroh_error("connection admission", "bridge at capacity")
                })?;
        let local_streams = Arc::new(Semaphore::new(self.options.max_streams_per_connection));
        let mut tasks = JoinSet::new();

        let first = match timeout(self.options.first_stream_timeout, connection.accept_bi()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(iroh_error("accept first Iroh stream", error)),
            Err(_) => {
                connection.close(CLOSE_CODE.into(), b"first raw stream timeout");
                return Err(BridgeError::Timeout {
                    operation: "first Iroh stream",
                });
            }
        };
        self.admit_stream(first, remote, Arc::clone(&local_streams), &mut tasks);

        loop {
            let idle = tokio::time::sleep(self.options.connection_idle_timeout);
            tokio::pin!(idle);
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                accepted = connection.accept_bi() => match accepted {
                    Ok(stream) => self.admit_stream(stream, remote, Arc::clone(&local_streams), &mut tasks),
                    Err(_) => break,
                },
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    report_stream(completed);
                },
                _ = &mut idle, if tasks.is_empty() => {
                    connection.close(CLOSE_CODE.into(), b"raw connection idle timeout");
                    break;
                }
            }
        }

        let draining = async {
            while let Some(completed) = tasks.join_next().await {
                report_stream(Some(completed));
            }
        };
        if timeout(self.options.drain_timeout, draining).await.is_err() {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        connection.close(CLOSE_CODE.into(), b"bridge drained");
        Ok(())
    }

    fn admit_stream(
        &self,
        (mut send, mut recv): (SendStream, RecvStream),
        remote: EndpointId,
        local_streams: Arc<Semaphore>,
        tasks: &mut JoinSet<Result<()>>,
    ) {
        let global = Arc::clone(&self.streams).try_acquire_owned();
        let local = local_streams.try_acquire_owned();
        let permits = match (global, local) {
            (Ok(global), Ok(local)) => StreamPermits {
                _global: global,
                _local: local,
            },
            _ => {
                let _ = send.reset(CLOSE_CODE.into());
                let _ = recv.stop(CLOSE_CODE.into());
                return;
            }
        };
        let upstream = self.upstream.clone();
        let connect_timeout = self.options.connect_timeout;
        tasks.spawn(async move {
            bridge_stream(upstream, connect_timeout, remote, send, recv, permits).await
        });
    }
}

struct PeerConnectionAdmission {
    max_per_peer: usize,
    counts: Mutex<HashMap<EndpointId, usize>>,
}

impl PeerConnectionAdmission {
    fn new(max_per_peer: usize) -> Self {
        Self {
            max_per_peer,
            counts: Mutex::new(HashMap::new()),
        }
    }

    fn acquire(self: &Arc<Self>, peer: EndpointId) -> Option<PeerConnectionPermit> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = counts.entry(peer).or_insert(0);
        if *count >= self.max_per_peer {
            return None;
        }
        *count += 1;
        Some(PeerConnectionPermit {
            admission: Arc::clone(self),
            peer,
        })
    }
}

struct PeerConnectionPermit {
    admission: Arc<PeerConnectionAdmission>,
    peer: EndpointId,
}

impl Drop for PeerConnectionPermit {
    fn drop(&mut self) {
        let mut counts = self
            .admission
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(count) = counts.get_mut(&self.peer) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&self.peer);
        }
    }
}

impl ProtocolHandler for RawBridgeProtocol {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        self.serve_connection(connection)
            .await
            .map_err(|error| AcceptError::from_err(io::Error::other(error.to_string())))
    }

    async fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

struct StreamPermits {
    _global: OwnedSemaphorePermit,
    _local: OwnedSemaphorePermit,
}

async fn bridge_stream(
    upstream: RawUpstream,
    connect_timeout: Duration,
    remote: EndpointId,
    send: SendStream,
    recv: RecvStream,
    _permits: StreamPermits,
) -> Result<()> {
    let mut upstream = timeout(connect_timeout, connect_upstream(upstream))
        .await
        .map_err(|_| BridgeError::Timeout {
            operation: "raw upstream connect",
        })??;
    upstream
        .write_all(&encode_iroh_proxy_v2(remote))
        .await
        .map_err(|source| BridgeError::Io {
            operation: "write Iroh identity preamble",
            source,
        })?;
    let mut downstream = IrohStream { send, recv };
    tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
        .await
        .map_err(|source| BridgeError::Io {
            operation: "proxy VGI stream",
            source,
        })?;
    downstream
        .shutdown()
        .await
        .map_err(|source| BridgeError::Io {
            operation: "finish Iroh stream",
            source,
        })?;
    Ok(())
}

enum UpstreamIo {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

async fn connect_upstream(upstream: RawUpstream) -> Result<UpstreamIo> {
    match upstream {
        RawUpstream::Tcp(address) => tokio::net::TcpStream::connect(address)
            .await
            .map(UpstreamIo::Tcp)
            .map_err(|source| BridgeError::Io {
                operation: "connect TCP upstream",
                source,
            }),
        RawUpstream::TcpAuthority(authority) => tokio::net::TcpStream::connect(authority)
            .await
            .map(UpstreamIo::Tcp)
            .map_err(|source| BridgeError::Io {
                operation: "resolve or connect TCP upstream",
                source,
            }),
        #[cfg(unix)]
        RawUpstream::Unix(path) => tokio::net::UnixStream::connect(path)
            .await
            .map(UpstreamIo::Unix)
            .map_err(|source| BridgeError::Io {
                operation: "connect Unix upstream",
                source,
            }),
    }
}

impl AsyncRead for UpstreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for UpstreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, buffer),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

struct IrohStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for IrohStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for IrohStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(context, buffer)
            .map(|result| result.map_err(io::Error::other))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(context)
    }
}

fn report_stream(completed: Option<std::result::Result<Result<()>, tokio::task::JoinError>>) {
    match completed {
        Some(Ok(Err(error))) => tracing::warn!(%error, "raw VGI bridge stream failed"),
        Some(Err(error)) => tracing::warn!(%error, "raw VGI bridge stream task failed"),
        Some(Ok(Ok(()))) | None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use iroh::{endpoint::presets, Endpoint, RelayMode};
    use iroh_http_core::{
        fetch_request, IrohEndpoint, NetworkingOptions, NodeOptions, StackConfig,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn loopback_http_endpoint() -> IrohEndpoint {
        IrohEndpoint::bind(NodeOptions {
            networking: NetworkingOptions {
                disabled: true,
                bind_addrs: vec!["127.0.0.1:0".into()],
                ..NetworkingOptions::default()
            },
            ..NodeOptions::default()
        })
        .await
        .expect("bind HTTP endpoint")
    }

    fn endpoint_address(endpoint: &IrohEndpoint) -> iroh::EndpointAddr {
        let mut address = iroh::EndpointAddr::new(endpoint.raw().id());
        for socket in endpoint.raw().addr().ip_addrs() {
            address = address.with_ip_addr(*socket);
        }
        address
    }

    fn values(headers: &HeaderMap, name: &str) -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().expect("test header is text").to_owned())
            .collect()
    }

    #[test]
    fn proxy_preamble_matches_canonical_vector() {
        let endpoint =
            EndpointId::from_bytes(&(0_u8..32).collect::<Vec<_>>().try_into().expect("32 bytes"))
                .expect("valid endpoint key");
        assert_eq!(
            hex::encode(encode_iroh_proxy_v2(endpoint)),
            concat!(
                "0d0a0d0a000d0a515549540a", // signature
                "21",                       // v2 + PROXY
                "00",                       // UNSPEC
                "0024",                     // one 36-byte TLV
                "e0",                       // VGI Iroh identity
                "0021",                     // 33-byte value
                "01",                       // payload version
                "000102030405060708090a0b0c0d0e0f",
                "101112131415161718191a1b1c1d1e1f"
            )
        );
    }

    #[test]
    fn rejects_zero_limits_and_timeouts() {
        let options = RawBridgeOptions {
            max_streams: 0,
            ..RawBridgeOptions::default()
        };
        assert!(matches!(
            RawBridgeProtocol::new(
                RawUpstream::Tcp("127.0.0.1:9400".parse().expect("address")),
                options
            ),
            Err(BridgeError::InvalidConfiguration)
        ));

        let options = RawBridgeOptions {
            max_connections: Semaphore::MAX_PERMITS + 1,
            ..RawBridgeOptions::default()
        };
        assert!(matches!(
            RawBridgeProtocol::new(
                RawUpstream::Tcp("127.0.0.1:9400".parse().expect("address")),
                options
            ),
            Err(BridgeError::InvalidConfiguration)
        ));
    }

    #[test]
    fn raw_peer_connection_admission_is_shared_and_released() {
        let peer =
            EndpointId::from_bytes(&(0_u8..32).collect::<Vec<_>>().try_into().expect("32 bytes"))
                .expect("endpoint ID");
        let admission = Arc::new(PeerConnectionAdmission::new(1));
        let permit = admission.acquire(peer).expect("first connection");
        assert!(admission.acquire(peer).is_none());
        drop(permit);
        assert!(admission.acquire(peer).is_some());
    }

    #[test]
    fn fixed_http_upstream_rejects_unsafe_forms_and_joins_paths() {
        let upstream = FixedHttpUpstream::parse("https://worker.example/vgi/base/")
            .expect("valid HTTPS upstream");
        assert_eq!(upstream.scheme, http::uri::Scheme::HTTPS);
        assert_eq!(
            upstream
                .rewrite_uri(&"/method?first=1&second=two".parse().expect("request URI"))
                .expect("rewrite"),
            "https://worker.example/vgi/base/method?first=1&second=two"
                .parse::<Uri>()
                .expect("expected URI")
        );
        assert!(matches!(
            FixedHttpUpstream::parse("http://user:password@worker.example/vgi"),
            Err(BridgeError::InvalidHttpUpstream {
                reason: "userinfo is forbidden"
            })
        ));
        assert!(matches!(
            FixedHttpUpstream::parse("http://worker.example/vgi?tenant=unsafe"),
            Err(BridgeError::InvalidHttpUpstream {
                reason: "base URI must not contain a query"
            })
        ));
        assert!(FixedHttpUpstream::parse("ftp://worker.example/vgi").is_err());
    }

    #[test]
    fn http_bridge_defaults_to_transparent_request_bodies() {
        assert!(!HttpBridgeOptions::default().connection.decompression);
    }

    #[test]
    fn header_sanitizers_strip_spoofs_hops_and_nominated_headers() {
        let mut request = HeaderMap::new();
        request.append(
            HeaderName::from_static(IROH_FORWARDED_ENDPOINT_HEADER),
            HeaderValue::from_static("spoof-one"),
        );
        request.append(
            HeaderName::from_static(IROH_FORWARDED_ENDPOINT_HEADER),
            HeaderValue::from_static("spoof-two"),
        );
        request.insert(HOST, HeaderValue::from_static("attacker.invalid"));
        request.insert(
            CONNECTION,
            HeaderValue::from_static("x-client-hop, VGI-Forwarded-Iroh-Endpoint, content-length"),
        );
        request.insert("x-client-hop", HeaderValue::from_static("secret"));
        request.insert("content-length", HeaderValue::from_static("123"));
        request.append("x-end-to-end", HeaderValue::from_static("one"));
        request.append("x-end-to-end", HeaderValue::from_static("two"));
        let clean = sanitize_request_headers(&request);
        assert!(!clean.contains_key(IROH_FORWARDED_ENDPOINT_HEADER));
        assert!(!clean.contains_key(HOST));
        assert!(!clean.contains_key(CONNECTION));
        assert!(!clean.contains_key("x-client-hop"));
        assert!(!clean.contains_key("content-length"));
        assert_eq!(values(&clean, "x-end-to-end"), ["one", "two"]);

        let mut response = HeaderMap::new();
        response.insert(
            CONNECTION,
            HeaderValue::from_static("x-upstream-hop, set-cookie-shadow"),
        );
        response.insert("x-upstream-hop", HeaderValue::from_static("secret"));
        response.insert(
            HeaderName::from_static(IROH_FORWARDED_ENDPOINT_HEADER),
            HeaderValue::from_static("must-not-reflect"),
        );
        response.append("set-cookie", HeaderValue::from_static("a=1; Path=/"));
        response.append("set-cookie", HeaderValue::from_static("b=2; Path=/"));
        let clean = sanitize_response_headers(&response);
        assert!(!clean.contains_key(CONNECTION));
        assert!(!clean.contains_key("x-upstream-hop"));
        assert!(!clean.contains_key(IROH_FORWARDED_ENDPOINT_HEADER));
        assert_eq!(values(&clean, "set-cookie"), ["a=1; Path=/", "b=2; Path=/"]);
    }

    #[tokio::test]
    async fn upstream_failure_returns_generic_502_without_identity() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve address");
        let address = listener.local_addr().expect("reserved address");
        drop(listener);
        let service = HttpProxyService::new(
            FixedHttpUpstream::parse(&format!("http://{address}/vgi")).expect("valid upstream"),
        );
        let endpoint_id = iroh::SecretKey::generate().public();
        let mut request = Request::builder()
            .uri("/method")
            .body(IrohHttpBody::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(RemoteEndpointId(endpoint_id));
        let response = service.proxy(request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(!response
            .headers()
            .contains_key(IROH_FORWARDED_ENDPOINT_HEADER));
        let body = response
            .into_body()
            .collect()
            .await
            .expect("error body")
            .to_bytes();
        assert_eq!(body.as_ref(), b"Bad Gateway");
        assert!(!String::from_utf8_lossy(&body).contains(&hex::encode(endpoint_id.as_bytes())));
    }

    #[derive(Debug)]
    struct HttpObservation {
        uri: String,
        host: String,
        identities: Vec<String>,
        duplicate_headers: Vec<String>,
        client_hop_present: bool,
        content_encoding: Option<String>,
        body: Bytes,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_http_bridge_preserves_semantics_and_verified_identity() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP upstream");
        let upstream_address = listener.local_addr().expect("upstream address");
        let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
        let upstream_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept HTTP upstream");
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let observation_tx = observation_tx.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let body = body
                        .collect()
                        .await
                        .expect("upstream request body")
                        .to_bytes();
                    observation_tx
                        .send(HttpObservation {
                            uri: parts.uri.to_string(),
                            host: parts
                                .headers
                                .get(HOST)
                                .expect("rewritten Host")
                                .to_str()
                                .expect("text Host")
                                .to_owned(),
                            identities: values(&parts.headers, IROH_FORWARDED_ENDPOINT_HEADER),
                            duplicate_headers: values(&parts.headers, "x-end-to-end"),
                            client_hop_present: parts.headers.contains_key("x-client-hop"),
                            content_encoding: parts.headers.get("content-encoding").map(|value| {
                                value.to_str().expect("content encoding is text").to_owned()
                            }),
                            body,
                        })
                        .expect("test observation receiver");

                    let mut response =
                        Response::new(Full::new(Bytes::from_static(b"streamed upstream response")));
                    *response.status_mut() = StatusCode::MULTI_STATUS;
                    response
                        .headers_mut()
                        .append("set-cookie", HeaderValue::from_static("a=1; Path=/"));
                    response
                        .headers_mut()
                        .append("set-cookie", HeaderValue::from_static("b=2; Path=/"));
                    response
                        .headers_mut()
                        .append("x-end-to-end-response", HeaderValue::from_static("one"));
                    response
                        .headers_mut()
                        .append("x-end-to-end-response", HeaderValue::from_static("two"));
                    response
                        .headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("x-upstream-hop"));
                    response
                        .headers_mut()
                        .insert("x-upstream-hop", HeaderValue::from_static("secret"));
                    response.headers_mut().insert(
                        HeaderName::from_static(IROH_FORWARDED_ENDPOINT_HEADER),
                        HeaderValue::from_static("must-not-reflect"),
                    );
                    Ok::<_, std::convert::Infallible>(response)
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await;
        });

        let server_endpoint = loopback_http_endpoint().await;
        let client_endpoint = loopback_http_endpoint().await;
        let expected_identity = hex::encode(client_endpoint.raw().id().as_bytes());
        let protocol = HttpBridgeProtocol::new(
            &format!("http://{upstream_address}/fixed/base/"),
            HttpBridgeOptions::default(),
        )
        .expect("HTTP bridge configuration");
        let router = iroh::protocol::Router::builder(server_endpoint.raw().clone())
            .accept(IROH_HTTP_ALPN, protocol.clone())
            .spawn();

        let mut request = Request::builder()
            .method("POST")
            .uri("/method?first=1&second=two")
            .header(HOST, "attacker.invalid")
            .header(CONNECTION, "x-client-hop, vgi-forwarded-iroh-endpoint")
            .header("x-client-hop", "must-not-forward")
            .header("content-encoding", "zstd")
            .body(IrohHttpBody::full("opaque encoded request body"))
            .expect("client request");
        request.headers_mut().append(
            HeaderName::from_static(IROH_FORWARDED_ENDPOINT_HEADER),
            HeaderValue::from_static("spoof-one"),
        );
        request.headers_mut().append(
            HeaderName::from_static(IROH_FORWARDED_ENDPOINT_HEADER),
            HeaderValue::from_static("spoof-two"),
        );
        request
            .headers_mut()
            .append("x-end-to-end", HeaderValue::from_static("one"));
        request
            .headers_mut()
            .append("x-end-to-end", HeaderValue::from_static("two"));

        let response = fetch_request(
            &client_endpoint,
            &endpoint_address(&server_endpoint),
            request,
            &StackConfig::default(),
        )
        .await
        .expect("Iroh HTTP bridge response");
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        assert_eq!(
            values(response.headers(), "set-cookie"),
            ["a=1; Path=/", "b=2; Path=/"]
        );
        assert_eq!(
            values(response.headers(), "x-end-to-end-response"),
            ["one", "two"]
        );
        // iroh-http may add its own hop-local `connection: close` framing
        // after the proxy service returns. The upstream's nominated header
        // must still be gone.
        assert!(!response.headers().contains_key("x-upstream-hop"));
        assert!(!response
            .headers()
            .contains_key(IROH_FORWARDED_ENDPOINT_HEADER));
        let response_body = response
            .into_body()
            .collect()
            .await
            .expect("bridged response body")
            .to_bytes();
        assert_eq!(response_body.as_ref(), b"streamed upstream response");

        let observation = tokio::time::timeout(Duration::from_secs(5), observation_rx.recv())
            .await
            .expect("upstream observation deadline")
            .expect("upstream observation");
        assert_eq!(observation.uri, "/fixed/base/method?first=1&second=two");
        assert_eq!(observation.host, upstream_address.to_string());
        assert_eq!(observation.identities, [expected_identity]);
        assert_eq!(observation.duplicate_headers, ["one", "two"]);
        assert!(!observation.client_hop_present);
        assert_eq!(observation.content_encoding.as_deref(), Some("zstd"));
        assert_eq!(observation.body.as_ref(), b"opaque encoded request body");

        tokio::time::timeout(Duration::from_secs(5), router.shutdown())
            .await
            .expect("router shutdown deadline")
            .expect("router shutdown");
        assert!(protocol.shutdown().await, "shutdown remains idempotent");
        upstream_task.abort();
        let _ = upstream_task.await;
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn active_raw_stream_survives_connection_idle_timeout_and_echoes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_address = listener.local_addr().expect("upstream address");
        let (stream_active_tx, stream_active_rx) = tokio::sync::oneshot::channel();
        let (release_upstream_tx, release_upstream_rx) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept upstream");
            let mut preamble = [0_u8; 52];
            socket
                .read_exact(&mut preamble)
                .await
                .expect("read identity preamble");
            let mut payload = [0_u8; 4];
            socket
                .read_exact(&mut payload)
                .await
                .expect("read bridged payload");
            stream_active_tx.send(()).expect("signal active stream");
            release_upstream_rx.await.expect("release active stream");
            socket.write_all(&payload).await.expect("echo payload");
            (preamble, payload)
        });

        let server_endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![VGI_IROH_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind bridge endpoint");
        let server_address = server_endpoint.addr();
        let client_endpoint = Endpoint::builder(presets::N0)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind client endpoint");
        let client_id = client_endpoint.id();
        let protocol = RawBridgeProtocol::new(
            RawUpstream::Tcp(upstream_address),
            RawBridgeOptions {
                connection_idle_timeout: Duration::from_millis(100),
                ..RawBridgeOptions::default()
            },
        )
        .expect("bridge config");
        let bridge = tokio::spawn({
            let protocol = protocol.clone();
            async move {
                let incoming = server_endpoint.accept().await.expect("incoming");
                let connection = incoming.await.expect("handshake");
                protocol.serve_connection(connection).await
            }
        });

        let connection = client_endpoint
            .connect(server_address, VGI_IROH_ALPN)
            .await
            .expect("connect bridge");
        let (mut send, mut recv) = connection.open_bi().await.expect("open stream");
        send.write_all(b"ping").await.expect("write payload");
        stream_active_rx.await.expect("upstream observed payload");

        // The connection has no newly accepted streams for more than three
        // idle-timeout periods, but this stream is active and must survive.
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(connection.close_reason(), None);
        release_upstream_tx.send(()).expect("release upstream echo");
        send.finish().expect("finish payload");
        let mut echoed = [0_u8; 4];
        recv.read_exact(&mut echoed).await.expect("read echo");
        assert_eq!(&echoed, b"ping");
        let (preamble, payload) = upstream.await.expect("upstream task");
        assert_eq!(preamble, encode_iroh_proxy_v2(client_id));
        assert_eq!(&payload, b"ping");
        tokio::time::timeout(Duration::from_secs(2), bridge)
            .await
            .expect("post-stream connection idle timeout")
            .expect("bridge task")
            .expect("bridge result");
        connection.close(CLOSE_CODE.into(), b"test complete");
        client_endpoint.close().await;
    }
}
