//! Narrow ingress bridge from authenticated Iroh connections to ordinary VGI
//! worker listeners.
//!
//! This crate is intentionally not a load balancer.  For the raw
//! `vgi-rpc/arrow-mux/1` protocol, every accepted QUIC bidirectional stream is
//! pinned to exactly one new TCP or Unix-domain upstream connection for its
//! lifetime.  The upstream receives a fixed, versioned PROXY-v2 TLV containing
//! the cryptographically authenticated Iroh EndpointId.  The worker chooses a
//! local issuer and authorization policy; the bridge cannot assert either.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointId;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

pub use vgi_rpc_iroh::VGI_IROH_ALPN;

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

/// One non-balancing raw-worker destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawUpstream {
    Tcp(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

/// Admission and lifecycle bounds for the raw bridge.
#[derive(Clone, Debug)]
pub struct RawBridgeOptions {
    pub connect_timeout: Duration,
    pub first_stream_timeout: Duration,
    pub max_connections: usize,
    pub max_streams: usize,
    pub max_streams_per_connection: usize,
    pub drain_timeout: Duration,
}

impl Default for RawBridgeOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            first_stream_timeout: Duration::from_secs(15),
            max_connections: 256,
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
            || self.drain_timeout.is_zero()
            || self.max_connections == 0
            || self.max_streams == 0
            || self.max_streams_per_connection == 0
        {
            return Err(BridgeError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("bridge timeouts and admission limits must be positive")]
    InvalidConfiguration,
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
        let _connection_permit = Arc::clone(&self.connections)
            .try_acquire_owned()
            .map_err(|_| iroh_error("connection admission", "bridge at capacity"))?;
        let remote = connection.remote_id();
        let local_streams = Arc::new(Semaphore::new(self.options.max_streams_per_connection));
        let mut tasks = JoinSet::new();

        let first = timeout(self.options.first_stream_timeout, connection.accept_bi())
            .await
            .map_err(|_| BridgeError::Timeout {
                operation: "first Iroh stream",
            })?
            .map_err(|error| iroh_error("accept first Iroh stream", error))?;
        self.admit_stream(first, remote, Arc::clone(&local_streams), &mut tasks);

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                accepted = connection.accept_bi() => match accepted {
                    Ok(stream) => self.admit_stream(stream, remote, Arc::clone(&local_streams), &mut tasks),
                    Err(_) => break,
                },
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    report_stream(completed);
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
    use iroh::{endpoint::presets, Endpoint, RelayMode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_forwards_identity_before_bytes_and_echoes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_address = listener.local_addr().expect("upstream address");
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
            RawBridgeOptions::default(),
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
        send.finish().expect("finish payload");
        let mut echoed = [0_u8; 4];
        recv.read_exact(&mut echoed).await.expect("read echo");
        assert_eq!(&echoed, b"ping");
        connection.close(CLOSE_CODE.into(), b"test complete");

        let (preamble, payload) = upstream.await.expect("upstream task");
        assert_eq!(preamble, encode_iroh_proxy_v2(client_id));
        assert_eq!(&payload, b"ping");
        bridge.await.expect("bridge task").expect("bridge result");
        client_endpoint.close().await;
    }
}
