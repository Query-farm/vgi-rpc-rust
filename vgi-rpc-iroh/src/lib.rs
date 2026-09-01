//! Stateful VGI Arrow framing over authenticated Iroh QUIC connections.
//!
//! Iroh is intentionally isolated in this adapter crate. The base `vgi-rpc`
//! and `vgi-rpc-client` dependency graphs do not include it.

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Handle;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{timeout, Instant};
pub use tokio_util::sync::CancellationToken;
use vgi_rpc::{
    AuthContext, ConnectionContext, IdentityAssurance, PeerAuthenticationPolicy, PeerEvidenceSet,
    PeerIdentity, PeerIdentityResult, RpcError, RpcServer, SubjectKind, SubjectStability,
};
use vgi_rpc_client::transport::RpcDeadline;
use vgi_rpc_client::{RpcClient, Transport};

/// ALPN used by the multiplexed, stateful VGI-over-Iroh protocol.
pub const VGI_IROH_ALPN: &[u8] = b"vgi-rpc/arrow-mux/1";

const CLOSE_CODE: u32 = 0;
const CLOSE_REASON: &[u8] = b"vgi-rpc transport closed";

/// Errors produced while establishing or serving an Iroh VGI connection.
#[derive(Debug, thiserror::Error)]
pub enum IrohAdapterError {
    #[error("{operation} timed out")]
    Timeout { operation: &'static str },
    #[error("{operation} cancelled")]
    Cancelled { operation: &'static str },
    #[error("{operation} rejected because the server is at capacity")]
    Saturated { operation: &'static str },
    #[error("{operation}: {message}")]
    Iroh {
        operation: &'static str,
        message: String,
    },
    #[error("peer authentication failed: {0}")]
    Authentication(#[from] RpcError),
    #[error("blocking VGI serve task failed: {0}")]
    Join(#[from] JoinError),
}

pub type Result<T> = std::result::Result<T, IrohAdapterError>;

fn iroh_error(operation: &'static str, error: impl std::fmt::Display) -> IrohAdapterError {
    IrohAdapterError::Iroh {
        operation,
        message: error.to_string(),
    }
}

fn redacted_policy_error(error: RpcError) -> RpcError {
    if error.is_auth_unavailable() {
        let retry_after = error.retry_after_seconds;
        let mut redacted = RpcError::auth_unavailable("peer identity authentication unavailable");
        if let Some(seconds) = retry_after {
            redacted = redacted.with_retry_after(seconds);
        }
        redacted
    } else {
        RpcError::auth_failure(
            vgi_rpc::unauthorized::AuthReason::InvalidCredential,
            "peer identity authentication rejected",
        )
    }
}

fn endpoint_subject(endpoint: EndpointId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut subject = String::with_capacity(64);
    for byte in endpoint.as_bytes() {
        subject.push(HEX[usize::from(byte >> 4)] as char);
        subject.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    subject
}

fn adapter_error_class(error: &IrohAdapterError) -> &'static str {
    match error {
        IrohAdapterError::Timeout { .. } => "timeout",
        IrohAdapterError::Cancelled { .. } => "cancelled",
        IrohAdapterError::Saturated { .. } => "saturated",
        IrohAdapterError::Iroh { .. } => "iroh",
        IrohAdapterError::Authentication(_) => "authentication",
        IrohAdapterError::Join(_) => "join",
    }
}

async fn cancellable_timeout<T, F>(
    cancellation: &CancellationToken,
    duration: Duration,
    operation: &'static str,
    future: F,
) -> Result<T>
where
    F: Future<Output = T>,
{
    tokio::select! {
        _ = cancellation.cancelled() => Err(IrohAdapterError::Cancelled { operation }),
        result = timeout(duration, future) => result.map_err(|_| IrohAdapterError::Timeout { operation }),
    }
}

/// Server-side connection and identity policy.
#[derive(Clone)]
pub struct IrohServerOptions {
    /// Namespace for endpoint identities. Set this to a stable, unique name
    /// for the operator's Iroh trust domain.
    pub issuer: String,
    /// Optional policy applied once to endpoint evidence. Endpoint possession
    /// proves a cryptographic peer key, not membership or authorization, so no
    /// authentication is granted unless an operator configures a policy.
    pub policy: Option<PeerAuthenticationPolicy>,
    /// Authentication established outside Iroh, composed by `policy`.
    pub application_auth: AuthContext,
    /// Maximum time allowed for an incoming cryptographic handshake.
    pub handshake_timeout: Duration,
    /// Maximum time allowed for the client to open its VGI stream.
    pub stream_open_timeout: Duration,
    /// Maximum idle duration of each blocking read or write after stream open.
    pub connection_io_timeout: Duration,
    /// Absolute budget for receiving the first complete VGI request. Unlike
    /// `connection_io_timeout`, successful partial reads do not restart it.
    pub first_request_timeout: Duration,
    /// Maximum concurrent cryptographic handshakes admitted by this server.
    pub max_pending_handshakes: usize,
    /// Maximum concurrent established VGI connections admitted by this server.
    pub max_active_connections: usize,
    /// Optional concurrent connection limit for each authenticated endpoint
    /// ID. This is enforced in addition to `max_active_connections`.
    pub max_active_connections_per_endpoint: Option<usize>,
    /// Maximum number of logical VGI streams dispatched across all Iroh
    /// connections. Admission is acquired before blocking worker dispatch.
    pub max_active_streams: usize,
    /// Maximum number of concurrent logical VGI streams on one Iroh
    /// connection. Excess streams are rejected without closing the connection.
    pub max_active_streams_per_connection: usize,
    /// Maximum graceful drain for active logical streams after shutdown.
    pub shutdown_timeout: Duration,
}

impl Default for IrohServerOptions {
    fn default() -> Self {
        Self {
            issuer: "iroh".into(),
            policy: None,
            application_auth: AuthContext::anonymous(),
            handshake_timeout: Duration::from_secs(15),
            stream_open_timeout: Duration::from_secs(15),
            connection_io_timeout: Duration::from_secs(30),
            first_request_timeout: Duration::from_secs(30),
            max_pending_handshakes: 64,
            max_active_connections: 256,
            max_active_connections_per_endpoint: None,
            max_active_streams: 1024,
            max_active_streams_per_connection: 32,
            shutdown_timeout: Duration::from_secs(10),
        }
    }
}

impl IrohServerOptions {
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    pub fn with_policy(mut self, policy: PeerAuthenticationPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_application_auth(mut self, auth: AuthContext) -> Self {
        self.application_auth = auth;
        self
    }

    pub fn with_first_request_timeout(mut self, timeout: Duration) -> Self {
        self.first_request_timeout = timeout;
        self
    }

    pub fn with_max_active_connections_per_endpoint(mut self, limit: usize) -> Self {
        self.max_active_connections_per_endpoint = Some(limit);
        self
    }

    pub fn with_max_active_streams(mut self, limit: usize) -> Self {
        self.max_active_streams = limit;
        self
    }

    pub fn with_max_active_streams_per_connection(mut self, limit: usize) -> Self {
        self.max_active_streams_per_connection = limit;
        self
    }

    fn validate(&self) -> Result<()> {
        if self.issuer.is_empty()
            || self.handshake_timeout.is_zero()
            || self.stream_open_timeout.is_zero()
            || self.connection_io_timeout.is_zero()
            || self.first_request_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
            || self.max_pending_handshakes == 0
            || self.max_active_connections == 0
            || self.max_active_connections_per_endpoint == Some(0)
            || self.max_active_streams == 0
            || self.max_active_streams_per_connection == 0
        {
            return Err(IrohAdapterError::Authentication(RpcError::value_error(
                "Iroh issuer, timeouts, and admission limits must be positive",
            )));
        }
        Ok(())
    }
}

struct IrohAdmission {
    pending: Arc<Semaphore>,
    active: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    endpoint_active: Arc<Mutex<HashMap<String, usize>>>,
    max_active_per_endpoint: Option<usize>,
}

impl IrohAdmission {
    fn new(options: &IrohServerOptions) -> Self {
        Self {
            pending: Arc::new(Semaphore::new(options.max_pending_handshakes)),
            active: Arc::new(Semaphore::new(options.max_active_connections)),
            streams: Arc::new(Semaphore::new(options.max_active_streams)),
            endpoint_active: Arc::new(Mutex::new(HashMap::new())),
            max_active_per_endpoint: options.max_active_connections_per_endpoint,
        }
    }

    fn try_pending(&self) -> Result<OwnedSemaphorePermit> {
        Arc::clone(&self.pending)
            .try_acquire_owned()
            .map_err(|_| IrohAdapterError::Saturated {
                operation: "Iroh handshake admission",
            })
    }

    fn try_active(&self) -> Result<OwnedSemaphorePermit> {
        Arc::clone(&self.active)
            .try_acquire_owned()
            .map_err(|_| IrohAdapterError::Saturated {
                operation: "Iroh connection admission",
            })
    }

    fn try_stream(&self) -> Result<OwnedSemaphorePermit> {
        Arc::clone(&self.streams)
            .try_acquire_owned()
            .map_err(|_| IrohAdapterError::Saturated {
                operation: "Iroh stream admission",
            })
    }

    fn try_endpoint(&self, endpoint: &impl std::fmt::Display) -> Result<Option<EndpointPermit>> {
        let Some(limit) = self.max_active_per_endpoint else {
            return Ok(None);
        };
        let endpoint = endpoint.to_string();
        let mut active = self
            .endpoint_active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = active.entry(endpoint.clone()).or_default();
        if *count >= limit {
            return Err(IrohAdapterError::Saturated {
                operation: "Iroh per-endpoint connection admission",
            });
        }
        *count += 1;
        Ok(Some(EndpointPermit {
            endpoint,
            active: Arc::clone(&self.endpoint_active),
        }))
    }
}

struct EndpointPermit {
    endpoint: String,
    active: Arc<Mutex<HashMap<String, usize>>>,
}

struct StreamPermits {
    _global: OwnedSemaphorePermit,
    _local: OwnedSemaphorePermit,
}

impl Drop for EndpointPermit {
    fn drop(&mut self) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = active.get_mut(&self.endpoint) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.endpoint);
            }
        }
    }
}

/// A stateful VGI worker endpoint over Iroh.
#[derive(Clone)]
pub struct IrohServer {
    rpc: Arc<RpcServer>,
    options: IrohServerOptions,
    admission: Arc<IrohAdmission>,
}

impl IrohServer {
    pub fn new(rpc: Arc<RpcServer>) -> Self {
        let options = IrohServerOptions::default();
        Self {
            rpc,
            admission: Arc::new(IrohAdmission::new(&options)),
            options,
        }
    }

    pub fn with_options(rpc: Arc<RpcServer>, options: IrohServerOptions) -> Self {
        Self {
            rpc,
            admission: Arc::new(IrohAdmission::new(&options)),
            options,
        }
    }

    /// Build an official Iroh router protocol handler for
    /// [`VGI_IROH_ALPN`]. This is the preferred API when an endpoint serves
    /// multiple ALPN protocols.
    pub fn protocol_handler(&self) -> IrohProtocol {
        IrohProtocol {
            server: self.clone(),
            shutdown: CancellationToken::new(),
            handlers: Arc::new(HandlerDrain::new()),
        }
    }

    /// Accept Iroh connections until `shutdown` is cancelled.
    ///
    /// The endpoint must advertise [`VGI_IROH_ALPN`]. The endpoint remains
    /// owned by the caller and is not globally closed on shutdown. Use
    /// [`Self::protocol_handler`] and Iroh's `Router` when sharing an endpoint
    /// with additional ALPN protocols.
    pub async fn serve(&self, endpoint: Endpoint, shutdown: CancellationToken) -> Result<()> {
        self.options.validate()?;
        let mut connections = JoinSet::new();
        let connections_shutdown = shutdown.child_token();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let pending = match self.admission.try_pending() {
                        Ok(permit) => permit,
                        Err(error) => {
                            tracing::warn!(
                                target: "vgi_rpc_iroh.server",
                                error_class = adapter_error_class(&error),
                                "Iroh handshake rejected at admission boundary"
                            );
                            continue;
                        }
                    };
                    let server = self.clone();
                    let connection_shutdown = connections_shutdown.child_token();
                    connections.spawn(async move {
                        let accepting = incoming
                            .accept()
                            .map_err(|error| iroh_error("accept Iroh handshake", error))?;
                        let connection = cancellable_timeout(
                            &connection_shutdown,
                            server.options.handshake_timeout,
                            "Iroh handshake",
                            accepting,
                        )
                        .await?
                        .map_err(|error| iroh_error("complete Iroh handshake", error))?;
                        drop(pending);
                        server.serve_connection(connection, connection_shutdown).await
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    report_connection_result(completed);
                }
            }
        }

        connections_shutdown.cancel();
        while let Some(completed) = connections.join_next().await {
            report_connection_result(Some(completed));
        }
        Ok(())
    }

    /// Serve one already-authenticated Iroh connection.
    ///
    /// Each accepted bidirectional QUIC stream is one stateful logical VGI
    /// transport. Streams are dispatched independently, while the
    /// cryptographic peer identity is snapshotted once for this connection.
    pub async fn serve_connection(
        &self,
        connection: Connection,
        shutdown: CancellationToken,
    ) -> Result<()> {
        self.options.validate()?;
        let active = self.admission.try_active()?;
        let endpoint = self.admission.try_endpoint(&connection.remote_id())?;
        self.serve_admitted_connection(connection, shutdown, active, endpoint)
            .await
    }

    async fn serve_admitted_connection(
        &self,
        connection: Connection,
        shutdown: CancellationToken,
        _active: OwnedSemaphorePermit,
        _endpoint: Option<EndpointPermit>,
    ) -> Result<()> {
        let remote_id = connection.remote_id();
        let context = self.connection_context(remote_id)?;
        let per_connection = Arc::new(Semaphore::new(
            self.options.max_active_streams_per_connection,
        ));
        let hard_cancel = CancellationToken::new();
        let mut streams = JoinSet::new();

        // A peer cannot occupy a connection slot forever without opening its
        // first logical transport. Once multiplexing is active, an idle gap
        // between later streams is harmless and is governed by QUIC itself.
        let first = cancellable_timeout(
            &shutdown,
            self.options.stream_open_timeout,
            "first Iroh VGI stream open",
            connection.accept_bi(),
        )
        .await?
        .map_err(|error| iroh_error("accept first Iroh bidirectional stream", error))?;
        self.admit_stream(
            first,
            &mut streams,
            Arc::clone(&per_connection),
            context.clone(),
            shutdown.clone(),
            hard_cancel.child_token(),
        );

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = connection.accept_bi() => {
                    let accepted = match accepted {
                        Ok(stream) => stream,
                        Err(_) => {
                            hard_cancel.cancel();
                            break;
                        }
                    };
                    self.admit_stream(
                        accepted,
                        &mut streams,
                        Arc::clone(&per_connection),
                        context.clone(),
                        shutdown.clone(),
                        hard_cancel.child_token(),
                    );
                }
                completed = streams.join_next(), if !streams.is_empty() => {
                    report_stream_result(completed);
                }
            }
        }

        let drain = async {
            while let Some(completed) = streams.join_next().await {
                report_stream_result(Some(completed));
            }
        };
        if timeout(self.options.shutdown_timeout, drain).await.is_err() {
            hard_cancel.cancel();
            connection.close(CLOSE_CODE.into(), CLOSE_REASON);
            streams.abort_all();
            while streams.join_next().await.is_some() {}
        }
        connection.close(CLOSE_CODE.into(), CLOSE_REASON);
        Ok(())
    }

    fn admit_stream(
        &self,
        (mut send, mut recv): (SendStream, RecvStream),
        streams: &mut JoinSet<Result<()>>,
        per_connection: Arc<Semaphore>,
        context: ConnectionContext,
        shutdown: CancellationToken,
        cancellation: CancellationToken,
    ) {
        let global = self.admission.try_stream();
        let local = per_connection
            .try_acquire_owned()
            .map_err(|_| IrohAdapterError::Saturated {
                operation: "Iroh per-connection stream admission",
            });
        let (global, local) = match (global, local) {
            (Ok(global), Ok(local)) => (global, local),
            (global, local) => {
                let error = global.err().or_else(|| local.err()).expect("one error");
                tracing::warn!(
                    target: "vgi_rpc_iroh.server",
                    error_class = adapter_error_class(&error),
                    "Iroh VGI stream rejected at admission boundary"
                );
                let _ = send.reset(CLOSE_CODE.into());
                let _ = recv.stop(CLOSE_CODE.into());
                return;
            }
        };

        let server = self.clone();
        let permits = StreamPermits {
            _global: global,
            _local: local,
        };
        streams.spawn(async move {
            server
                .serve_stream(send, recv, context, shutdown, cancellation, permits)
                .await
        });
    }

    async fn serve_stream(
        &self,
        send: SendStream,
        recv: RecvStream,
        context: ConnectionContext,
        shutdown: CancellationToken,
        cancellation: CancellationToken,
        _permits: StreamPermits,
    ) -> Result<()> {
        let handle = Handle::current();
        let first_request = Arc::new(FirstRequestBudget::new(self.options.first_request_timeout));
        let mut reader = BlockingRecv {
            stream: recv,
            handle: handle.clone(),
            cancellation: cancellation.clone(),
            deadline: None,
            io_timeout: Some(self.options.connection_io_timeout),
            first_request: Some(Arc::clone(&first_request)),
        };
        let mut writer = BlockingSend {
            stream: send,
            handle,
            cancellation,
            deadline: None,
            io_timeout: Some(self.options.connection_io_timeout),
            first_request: Some(first_request),
        };
        let rpc = Arc::clone(&self.rpc);
        tokio::task::spawn_blocking(move || {
            rpc.serve_with_context_and_shutdown(&mut reader, &mut writer, context, || {
                shutdown.is_cancelled()
            });
            let _ = writer.stream.finish();
            let _ = reader.stream.stop(CLOSE_CODE.into());
        })
        .await
        .map_err(IrohAdapterError::Join)
    }

    fn connection_context(&self, remote_id: EndpointId) -> Result<ConnectionContext> {
        self.options.validate()?;
        // The portable identity contract uses the complete raw endpoint key,
        // not Iroh's human-oriented z-base-32 Display representation.
        let subject = endpoint_subject(remote_id);
        let identity = PeerIdentity::new(
            "iroh",
            "iroh_quic_handshake",
            IdentityAssurance::CryptographicPeer,
            &self.options.issuer,
            "iroh",
        )?
        .with_subject(
            SubjectKind::Endpoint,
            subject,
            SubjectStability::Stable,
            true,
        )?;
        let evidence = Arc::new(PeerEvidenceSet::from_results([
            PeerIdentityResult::available(identity),
        ])?);
        let auth = match &self.options.policy {
            Some(policy) => {
                policy(&evidence, &self.options.application_auth).map_err(redacted_policy_error)?
            }
            None => self.options.application_auth.clone(),
        };
        Ok(ConnectionContext::new(auth, evidence))
    }
}

/// Iroh [`ProtocolHandler`] for mounting VGI on a shared endpoint/router.
#[derive(Clone)]
pub struct IrohProtocol {
    server: IrohServer,
    shutdown: CancellationToken,
    handlers: Arc<HandlerDrain>,
}

#[derive(Default)]
struct HandlerDrainState {
    closed: bool,
    active: usize,
}

struct HandlerDrain {
    state: Mutex<HandlerDrainState>,
    active: watch::Sender<usize>,
}

impl HandlerDrain {
    fn new() -> Self {
        let (active, _) = watch::channel(0);
        Self {
            state: Mutex::new(HandlerDrainState::default()),
            active,
        }
    }

    fn try_enter(self: &Arc<Self>) -> Option<HandlerPermit> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return None;
        }
        state.active += 1;
        self.active.send_replace(state.active);
        Some(HandlerPermit {
            drain: Arc::clone(self),
        })
    }

    fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed = true;
    }

    async fn wait(&self) {
        let mut active = self.active.subscribe();
        while *active.borrow_and_update() != 0 {
            if active.changed().await.is_err() {
                break;
            }
        }
    }
}

struct HandlerPermit {
    drain: Arc<HandlerDrain>,
}

impl Drop for HandlerPermit {
    fn drop(&mut self) {
        let mut state = self
            .drain
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = state.active.saturating_sub(1);
        self.drain.active.send_replace(state.active);
    }
}

impl std::fmt::Debug for IrohProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IrohProtocol")
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for IrohProtocol {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        let Some(_handler) = self.handlers.try_enter() else {
            connection.close(CLOSE_CODE.into(), CLOSE_REASON);
            return Err(AcceptError::from_err(io::Error::other(
                "Iroh VGI protocol is shutting down",
            )));
        };
        self.server
            .serve_connection(connection, self.shutdown.child_token())
            .await
            .map_err(|error| {
                AcceptError::from_err(io::Error::other(format!(
                    "Iroh VGI protocol failure ({})",
                    adapter_error_class(&error)
                )))
            })
    }

    async fn shutdown(&self) {
        self.handlers.close();
        self.shutdown.cancel();
        if timeout(self.server.options.shutdown_timeout, self.handlers.wait())
            .await
            .is_err()
        {
            tracing::warn!("Iroh VGI connection drain timed out");
        }
    }
}

fn report_connection_result(completed: Option<std::result::Result<Result<()>, JoinError>>) {
    match completed {
        Some(Ok(Ok(()))) | None => {}
        Some(Ok(Err(error))) => tracing::warn!(
            target: "vgi_rpc_iroh.server",
            error_class = adapter_error_class(&error),
            "Iroh VGI connection ended with an error"
        ),
        Some(Err(_error)) => tracing::warn!(
            target: "vgi_rpc_iroh.server",
            error_class = "join",
            "Iroh VGI connection task failed"
        ),
    }
}

fn report_stream_result(completed: Option<std::result::Result<Result<()>, JoinError>>) {
    match completed {
        Some(Ok(Ok(()))) | None => {}
        Some(Ok(Err(error))) => tracing::warn!(
            target: "vgi_rpc_iroh.server",
            error_class = adapter_error_class(&error),
            "Iroh VGI logical stream ended with an error"
        ),
        Some(Err(_error)) => tracing::warn!(
            target: "vgi_rpc_iroh.server",
            error_class = "join",
            "Iroh VGI logical stream task failed"
        ),
    }
}

/// Client connection, cancellation, and per-RPC deadline settings.
#[derive(Clone)]
pub struct IrohClientOptions {
    pub connect_timeout: Duration,
    pub stream_open_timeout: Duration,
    pub rpc_timeout: Option<Duration>,
    pub cancellation: CancellationToken,
}

impl Default for IrohClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            stream_open_timeout: Duration::from_secs(15),
            rpc_timeout: None,
            cancellation: CancellationToken::new(),
        }
    }
}

impl IrohClientOptions {
    pub fn with_rpc_timeout(mut self, timeout: Duration) -> Self {
        self.rpc_timeout = Some(timeout);
        self
    }

    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }
}

/// A reusable Iroh connection that opens one independent VGI transport per
/// bidirectional QUIC stream.
#[derive(Clone)]
pub struct IrohConnection {
    inner: Arc<IrohConnectionInner>,
}

struct IrohConnectionInner {
    connection: Connection,
    remote_id: EndpointId,
    stream_open_timeout: Duration,
    rpc_timeout: Option<Duration>,
    cancellation: CancellationToken,
}

impl Drop for IrohConnectionInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.connection.close(CLOSE_CODE.into(), CLOSE_REASON);
    }
}

impl IrohConnection {
    /// Connect using endpoint-ID address lookup configured on `endpoint`.
    pub async fn connect_id(
        endpoint: Endpoint,
        remote_id: EndpointId,
        options: IrohClientOptions,
    ) -> Result<Self> {
        Self::connect_addr(endpoint, EndpointAddr::from(remote_id), options).await
    }

    /// Connect using an address that may include direct and relay hints.
    pub async fn connect_addr(
        endpoint: Endpoint,
        remote: EndpointAddr,
        options: IrohClientOptions,
    ) -> Result<Self> {
        let cancellation = options.cancellation.child_token();
        let connection = cancellable_timeout(
            &cancellation,
            options.connect_timeout,
            "Iroh connect",
            endpoint.connect(remote, VGI_IROH_ALPN),
        )
        .await?
        .map_err(|error| iroh_error("connect Iroh endpoint", error))?;
        let remote_id = connection.remote_id();
        Ok(Self {
            inner: Arc::new(IrohConnectionInner {
                connection,
                remote_id,
                stream_open_timeout: options.stream_open_timeout,
                rpc_timeout: options.rpc_timeout,
                cancellation,
            }),
        })
    }

    /// Open a new logical VGI byte transport on this pooled connection.
    pub async fn open_transport(&self) -> Result<IrohTransport> {
        let cancellation = self.inner.cancellation.child_token();
        let (send, recv) = cancellable_timeout(
            &cancellation,
            self.inner.stream_open_timeout,
            "Iroh VGI stream open",
            self.inner.connection.open_bi(),
        )
        .await?
        .map_err(|error| iroh_error("open Iroh bidirectional stream", error))?;
        let deadline = self.inner.rpc_timeout.map(RpcDeadline::new);
        let handle = Handle::current();
        Ok(IrohTransport {
            reader: BlockingRecv {
                stream: recv,
                handle: handle.clone(),
                cancellation: cancellation.clone(),
                deadline: deadline.clone(),
                io_timeout: None,
                first_request: None,
            },
            writer: BlockingSend {
                stream: send,
                handle,
                cancellation: cancellation.clone(),
                deadline: deadline.clone(),
                io_timeout: None,
                first_request: None,
            },
            connection: Arc::clone(&self.inner),
            deadline,
            cancellation,
            closed: false,
        })
    }

    pub fn remote_id(&self) -> EndpointId {
        self.inner.remote_id
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    /// Close the shared QUIC connection and cancel all of its logical streams.
    pub fn close(&self) {
        self.inner.cancellation.cancel();
        self.inner.connection.close(CLOSE_CODE.into(), CLOSE_REASON);
    }

    /// Open a logical transport and wrap it in a blocking [`RpcClient`].
    pub async fn open_client(&self) -> Result<RpcClient> {
        Ok(self.open_transport().await?.into_client())
    }
}

/// Blocking VGI client transport backed by one bidirectional QUIC stream.
///
/// Construct it asynchronously, then use the resulting `RpcClient` only from
/// a blocking thread (for example `tokio::task::spawn_blocking`). Dropping one
/// transport does not close the pooled [`IrohConnection`] or sibling streams.
pub struct IrohTransport {
    reader: BlockingRecv,
    writer: BlockingSend,
    connection: Arc<IrohConnectionInner>,
    deadline: Option<RpcDeadline>,
    cancellation: CancellationToken,
    closed: bool,
}

impl IrohTransport {
    /// Convenience constructor that opens a new connection and one stream.
    pub async fn connect_id(
        endpoint: Endpoint,
        remote_id: EndpointId,
        options: IrohClientOptions,
    ) -> Result<Self> {
        IrohConnection::connect_id(endpoint, remote_id, options)
            .await?
            .open_transport()
            .await
    }

    /// Convenience constructor that opens a new connection and one stream.
    pub async fn connect_addr(
        endpoint: Endpoint,
        remote: EndpointAddr,
        options: IrohClientOptions,
    ) -> Result<Self> {
        IrohConnection::connect_addr(endpoint, remote, options)
            .await?
            .open_transport()
            .await
    }

    pub fn remote_id(&self) -> EndpointId {
        self.connection.remote_id
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn into_client(self) -> RpcClient {
        RpcClient::from_transport(Box::new(self))
    }
}

impl Transport for IrohTransport {
    fn split(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        (&mut self.reader, &mut self.writer)
    }

    fn rpc_deadline(&self) -> Option<RpcDeadline> {
        self.deadline.clone()
    }

    fn is_reusable(&self) -> bool {
        !self.cancellation.is_cancelled() && self.connection.connection.close_reason().is_none()
    }

    fn close(&mut self) -> vgi_rpc_client::Result<()> {
        let finish = self.writer.stream.finish().map_err(|error| {
            RpcError::new(
                "TransportError",
                format!("finish Iroh send stream: {error}"),
            )
        });
        let _ = self.reader.stream.stop(CLOSE_CODE.into());
        self.closed = true;
        self.cancellation.cancel();
        finish
    }
}

impl Drop for IrohTransport {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.writer.stream.reset(CLOSE_CODE.into());
            let _ = self.reader.stream.stop(CLOSE_CODE.into());
        }
        self.cancellation.cancel();
    }
}

struct BlockingRecv {
    stream: RecvStream,
    handle: Handle,
    cancellation: CancellationToken,
    deadline: Option<RpcDeadline>,
    io_timeout: Option<Duration>,
    first_request: Option<Arc<FirstRequestBudget>>,
}

impl Read for BlockingRecv {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let cancellation = self.cancellation.clone();
        let budget = minimum_budget(
            minimum_budget(
                active_budget(self.deadline.as_ref(), &cancellation)?,
                first_request_budget(self.first_request.as_deref(), &cancellation)?,
            ),
            self.io_timeout,
        );
        let stream = &mut self.stream;
        self.handle
            .block_on(cancellable_io(cancellation, budget, stream.read(buffer)))
            .map(|read| read.unwrap_or(0))
    }
}

struct BlockingSend {
    stream: SendStream,
    handle: Handle,
    cancellation: CancellationToken,
    deadline: Option<RpcDeadline>,
    io_timeout: Option<Duration>,
    first_request: Option<Arc<FirstRequestBudget>>,
}

impl Write for BlockingSend {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if !buffer.is_empty() {
            complete_first_request(self.first_request.as_deref());
        }
        let cancellation = self.cancellation.clone();
        let budget = minimum_budget(
            active_budget(self.deadline.as_ref(), &cancellation)?,
            self.io_timeout,
        );
        let stream = &mut self.stream;
        self.handle
            .block_on(cancellable_io(cancellation, budget, stream.write(buffer)))
    }

    fn write_all(&mut self, buffer: &[u8]) -> io::Result<()> {
        if !buffer.is_empty() {
            complete_first_request(self.first_request.as_deref());
        }
        let cancellation = self.cancellation.clone();
        let budget = minimum_budget(
            active_budget(self.deadline.as_ref(), &cancellation)?,
            self.io_timeout,
        );
        let stream = &mut self.stream;
        self.handle.block_on(cancellable_io(
            cancellation,
            budget,
            stream.write_all(buffer),
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        let cancellation = self.cancellation.clone();
        let budget = minimum_budget(
            active_budget(self.deadline.as_ref(), &cancellation)?,
            self.io_timeout,
        );
        let stream = &mut self.stream;
        self.handle
            .block_on(cancellable_io(cancellation, budget, stream.flush()))
    }
}

struct FirstRequestBudget {
    deadline: Instant,
    complete: AtomicBool,
}

impl FirstRequestBudget {
    fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            complete: AtomicBool::new(false),
        }
    }

    fn complete(&self) {
        self.complete.store(true, Ordering::Release);
    }

    fn remaining(&self) -> Option<Duration> {
        if self.complete.load(Ordering::Acquire) {
            None
        } else {
            Some(
                self.deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::ZERO),
            )
        }
    }
}

fn complete_first_request(first_request: Option<&FirstRequestBudget>) {
    if let Some(first_request) = first_request {
        first_request.complete();
    }
}

fn first_request_budget(
    first_request: Option<&FirstRequestBudget>,
    cancellation: &CancellationToken,
) -> io::Result<Option<Duration>> {
    let remaining = first_request.and_then(FirstRequestBudget::remaining);
    if remaining == Some(Duration::ZERO) {
        cancellation.cancel();
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "VGI Iroh first request deadline elapsed",
        ))
    } else {
        Ok(remaining)
    }
}

fn minimum_budget(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn active_budget(
    deadline: Option<&RpcDeadline>,
    cancellation: &CancellationToken,
) -> io::Result<Option<Duration>> {
    let remaining = deadline.and_then(RpcDeadline::remaining);
    if remaining == Some(Duration::ZERO) {
        cancellation.cancel();
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "VGI Iroh RPC deadline elapsed",
        ))
    } else {
        Ok(remaining)
    }
}

async fn cancellable_io<T, E>(
    cancellation: CancellationToken,
    budget: Option<Duration>,
    operation: impl Future<Output = std::result::Result<T, E>>,
) -> io::Result<T>
where
    E: std::fmt::Display,
{
    if let Some(budget) = budget {
        let timeout_cancellation = cancellation.clone();
        tokio::select! {
            _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "VGI Iroh transport cancelled")),
            result = timeout_at(Instant::now() + budget, operation) => {
                match result {
                    Ok(result) => result.map_err(|error| io::Error::other(error.to_string())),
                    Err(_) => {
                        timeout_cancellation.cancel();
                        Err(io::Error::new(io::ErrorKind::TimedOut, "VGI Iroh RPC deadline elapsed"))
                    }
                }
            }
        }
    } else {
        tokio::select! {
            _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "VGI Iroh transport cancelled")),
            result = operation => result.map_err(|error| io::Error::other(error.to_string())),
        }
    }
}

async fn timeout_at<T>(
    deadline: Instant,
    future: impl Future<Output = T>,
) -> std::result::Result<T, tokio::time::error::Elapsed> {
    tokio::time::timeout_at(deadline, future).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handler_shutdown_closes_admission_and_waits_for_active_accepts() {
        let handlers = Arc::new(HandlerDrain::new());
        let permit = handlers.try_enter().expect("first handler admitted");
        handlers.close();
        assert!(handlers.try_enter().is_none(), "shutdown closes admission");
        assert!(
            timeout(Duration::from_millis(20), handlers.wait())
                .await
                .is_err(),
            "shutdown must wait for the active handler"
        );

        drop(permit);
        timeout(Duration::from_secs(1), handlers.wait())
            .await
            .expect("released handler drains");
    }

    #[tokio::test]
    async fn an_io_deadline_poison_cancels_the_connection_token() {
        let cancellation = CancellationToken::new();
        let result = cancellable_io(
            cancellation.clone(),
            Some(Duration::from_millis(1)),
            std::future::pending::<io::Result<()>>(),
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn defaults_do_not_authenticate_arbitrary_endpoint_keys() {
        assert!(IrohServerOptions::default().policy.is_none());
        assert_eq!(VGI_IROH_ALPN, b"vgi-rpc/arrow-mux/1");
    }

    #[test]
    fn custom_policy_error_details_are_redacted_before_logging() {
        let secret = "raw-capability-policy-secret";
        let rejected = redacted_policy_error(RpcError::auth_failure(
            vgi_rpc::unauthorized::AuthReason::InvalidCredential,
            secret,
        ));
        assert_eq!(rejected.message, "peer identity authentication rejected");
        assert!(!rejected.to_string().contains(secret));

        let unavailable =
            redacted_policy_error(RpcError::auth_unavailable(secret).with_retry_after(17));
        assert_eq!(
            unavailable.message,
            "peer identity authentication unavailable"
        );
        assert_eq!(unavailable.retry_after_seconds, Some(17));
        assert!(!unavailable.to_string().contains(secret));
        assert_eq!(
            adapter_error_class(&IrohAdapterError::Authentication(unavailable)),
            "authentication"
        );
    }

    #[tokio::test]
    async fn panic_payload_is_reduced_to_a_fixed_log_class() {
        let join = tokio::spawn(async { panic!("join-panic-secret") })
            .await
            .unwrap_err();
        let error = IrohAdapterError::Join(join);
        assert_eq!(adapter_error_class(&error), "join");
        assert!(!adapter_error_class(&error).contains("join-panic-secret"));
    }

    #[test]
    fn admission_is_bounded_and_permits_are_released_for_drain() {
        let options = IrohServerOptions {
            max_pending_handshakes: 1,
            max_active_connections: 1,
            max_active_connections_per_endpoint: Some(1),
            max_active_streams: 1,
            ..IrohServerOptions::default()
        };
        let admission = IrohAdmission::new(&options);
        let pending = admission.try_pending().unwrap();
        assert!(matches!(
            admission.try_pending(),
            Err(IrohAdapterError::Saturated { .. })
        ));
        drop(pending);
        assert!(admission.try_pending().is_ok());

        let active = admission.try_active().unwrap();
        assert!(matches!(
            admission.try_active(),
            Err(IrohAdapterError::Saturated { .. })
        ));
        drop(active);
        assert!(admission.try_active().is_ok());

        let stream = admission.try_stream().unwrap();
        assert!(matches!(
            admission.try_stream(),
            Err(IrohAdapterError::Saturated { .. })
        ));
        drop(stream);
        assert!(admission.try_stream().is_ok());

        let endpoint_a = admission.try_endpoint(&"endpoint-a").unwrap().unwrap();
        assert!(matches!(
            admission.try_endpoint(&"endpoint-a"),
            Err(IrohAdapterError::Saturated { .. })
        ));

        // One endpoint cannot consume another endpoint's allocation.
        let endpoint_b = admission.try_endpoint(&"endpoint-b").unwrap().unwrap();
        drop(endpoint_b);

        // The RAII permit releases the endpoint slot on every return path.
        drop(endpoint_a);
        assert!(admission.try_endpoint(&"endpoint-a").unwrap().is_some());
    }

    #[tokio::test]
    async fn first_request_budget_is_absolute_and_response_disarms_it() {
        let cancellation = CancellationToken::new();
        let budget = FirstRequestBudget::new(Duration::from_millis(100));

        tokio::time::sleep(Duration::from_millis(60)).await;
        let first = first_request_budget(Some(&budget), &cancellation)
            .unwrap()
            .unwrap();
        assert!(first < Duration::from_millis(60));

        // Observing progress does not reset the original deadline.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let error = first_request_budget(Some(&budget), &cancellation).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(cancellation.is_cancelled());

        let completed = FirstRequestBudget::new(Duration::from_millis(1));
        completed.complete();
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(
            first_request_budget(Some(&completed), &CancellationToken::new()).unwrap(),
            None
        );
    }
}
