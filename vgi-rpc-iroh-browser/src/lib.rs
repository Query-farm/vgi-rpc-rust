//! Browser-capable, client-only HTTP over Iroh.
//!
//! This crate deliberately owns neither Iroh endpoint construction nor VGI
//! request serialization. It accepts a clone of an application-owned
//! [`iroh::Endpoint`], so the same authenticated endpoint identity can be
//! shared with other Iroh protocols. Each request uses the `iroh-http/2` ALPN,
//! opens one QUIC bidirectional stream, and delegates HTTP/1.1 framing to
//! Hyper. The ALPN name is inherited from iroh-http; it is a protocol version,
//! not an HTTP/2 claim.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use iroh::{Endpoint, EndpointAddr, EndpointId};

/// ALPN used by the iroh-http version-2 wire protocol.
pub const IROH_HTTP_ALPN: &[u8] = b"iroh-http/2";

/// Fully materialized request body supported by the initial browser client.
pub type RequestBody = Full<Bytes>;

/// Errors while dialing or sending one HTTP request over Iroh.
#[derive(Debug, thiserror::Error)]
pub enum IrohHttpError {
    #[error("Iroh connect failed: {0}")]
    Connect(String),
    #[error("opening an Iroh bidirectional stream failed: {0}")]
    OpenStream(String),
    #[error("Hyper client handshake failed: {0}")]
    Handshake(#[source] hyper::Error),
    #[error("Hyper request failed: {0}")]
    Request(#[source] hyper::Error),
}

/// A client view over an application-owned Iroh endpoint.
///
/// `Endpoint` is a cheap cloneable handle. Keeping it outside this crate lets
/// an application use one endpoint identity for this HTTP path and for other
/// Iroh protocols without creating competing sockets or identities.
#[derive(Clone, Debug)]
pub struct IrohHttpEndpoint {
    endpoint: Endpoint,
}

impl IrohHttpEndpoint {
    /// Use an existing Iroh endpoint for outbound HTTP requests.
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Return the shared raw endpoint handle.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Return the cryptographic identity of the shared endpoint.
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Negotiate an authenticated `iroh-http/2` connection.
    pub async fn connect(&self, remote: EndpointAddr) -> Result<Connection, IrohHttpError> {
        self.endpoint
            .connect(remote, IROH_HTTP_ALPN)
            .await
            .map_err(|error| IrohHttpError::Connect(error.to_string()))
    }

    /// Send one Hyper HTTP/1.1 request on a fresh Iroh bidirectional stream.
    ///
    /// The returned body remains streaming. A target-appropriate background
    /// task continues driving Hyper: `spawn_local` in a browser and
    /// `tokio::spawn` on native targets.
    pub async fn request(
        &self,
        remote: EndpointAddr,
        request: hyper::Request<RequestBody>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, IrohHttpError> {
        let connection = self.connect(remote).await?;
        self.request_on_connection(&connection, request).await
    }

    /// Send one request over an already-negotiated Iroh connection.
    ///
    /// This is the endpoint-sharing seam needed by clients that pool or
    /// otherwise manage authenticated connections outside this crate.
    pub async fn request_on_connection(
        &self,
        connection: &Connection,
        request: hyper::Request<RequestBody>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, IrohHttpError> {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|error| IrohHttpError::OpenStream(error.to_string()))?;
        let io = TokioIo::new(IrohStream::new(send, recv));
        let (mut sender, driver) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, RequestBody>(io)
            .await
            .map_err(IrohHttpError::Handshake)?;
        spawn_connection_driver(driver);
        sender
            .send_request(request)
            .await
            .map_err(IrohHttpError::Request)
    }
}

impl From<Endpoint> for IrohHttpEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        Self::new(endpoint)
    }
}

struct IrohStream {
    send: SendStream,
    recv: RecvStream,
}

impl IrohStream {
    fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for IrohStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for IrohStream {
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

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn spawn_connection_driver<F>(driver: F)
where
    F: Future<Output = Result<(), hyper::Error>> + Send + 'static,
{
    tokio::spawn(async move {
        let _ = driver.await;
    });
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn spawn_connection_driver<F>(driver: F)
where
    F: Future<Output = Result<(), hyper::Error>> + 'static,
{
    wasm_bindgen_futures::spawn_local(async move {
        let _ = driver.await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_name_is_versioned_and_stable() {
        assert_eq!(IROH_HTTP_ALPN, b"iroh-http/2");
    }
}
