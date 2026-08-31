//! AF_INET (TCP) accept loop with optional idle self-termination.
//!
//! This is the network analog of the [`crate::unix`] serve path: it speaks the
//! exact same raw Arrow-IPC framing protocol, only the listening socket differs
//! (`TcpListener`/`TcpStream` bound to `host:port`). A worker serves RPC over a
//! bare TCP socket, prints `TCP:<host>:<port>` once it is listening, and
//! self-terminates after a quiet period so abandoned workers don't leak.
//!
//! Plain [`serve_tcp`] carries **no authentication and no TLS**. Bind it to a
//! trusted network only — the default host is loopback-only (`127.0.0.1`).
//! [`serve_tcp_with_identity`] can instead consume a strictly trusted PROXY v2
//! boundary and resolve provider-neutral peer evidence (for example through
//! Tailscale LocalAPI). With the `tcp-mtls` feature,
//! [`serve_tcp_with_mtls_identity`] adds mandatory rustls client-chain
//! verification and strict direct X.509-SVID evidence.
//!
//! [`serve_tcp`] binds `(host, port)` (with `port = 0` letting the OS choose a
//! free port), fires `on_bound` with `(host, actual_port)` (the caller prints
//! the `TCP:<host>:<port>` line there), then accepts connections — each served
//! on its own thread. With `idle_timeout` set it mirrors the Unix semantics
//! exactly:
//!
//! * A **startup grace** timer of `max(idle_timeout, 60s)` is armed at bind so a
//!   launcher has time to connect its first client.
//! * Every accepted connection **cancels** the idle timer; when the *last*
//!   connection closes the timer is **re-armed** for `idle_timeout`.
//! * When the timer elapses with zero active connections the accept loop stops
//!   and the listener is dropped.
//!
//! The `shutdown` flag lets a caller's signal handler (SIGTERM/SIGINT) tear the
//! loop down the same way.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Read};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::auth::identity::{
    PeerAuthenticationPolicy, PeerEvidenceSet, PeerIdentityProvider, PeerIdentityResult,
    PeerResolutionContext,
};
use crate::unauthorized::AuthReason;
use crate::{AuthContext, ConnectionContext, RpcError, RpcServer};

#[cfg(feature = "tcp-mtls")]
use crate::auth::identity::{IdentityAssurance, PeerIdentity, SubjectKind, SubjectStability};

/// Off-wire identity options for a stateful raw TCP connection.
///
/// Existing [`serve_tcp`] callers remain anonymous. This configuration is
/// consumed only by [`serve_tcp_with_identity`].
#[derive(Clone)]
pub struct TcpIdentityOptions {
    pub proxy_protocol_v2_required: bool,
    /// Exact normalized proxy IPs. Loopback is never trusted implicitly.
    pub trusted_proxy_addresses: BTreeSet<IpAddr>,
    pub proxy_preamble_timeout: Duration,
    pub maximum_proxy_preamble_bytes: usize,
    pub service_name: Option<String>,
    pub identity_resolution_timeout: Duration,
    pub identity_resolver_concurrency: usize,
    pub providers: Arc<[PeerIdentityProvider]>,
    pub policy: Option<PeerAuthenticationPolicy>,
    pub application_auth: AuthContext,
}

impl Default for TcpIdentityOptions {
    fn default() -> Self {
        Self {
            proxy_protocol_v2_required: false,
            trusted_proxy_addresses: BTreeSet::new(),
            proxy_preamble_timeout: Duration::from_secs(1),
            maximum_proxy_preamble_bytes: crate::proxy_protocol::DEFAULT_MAX_PROXY_V2_BYTES,
            service_name: None,
            identity_resolution_timeout: Duration::from_secs(5),
            identity_resolver_concurrency: 64,
            providers: Arc::from([]),
            policy: None,
            application_auth: AuthContext::anonymous(),
        }
    }
}

impl TcpIdentityOptions {
    fn validate(&self) -> io::Result<()> {
        if self.proxy_preamble_timeout.is_zero()
            || self.maximum_proxy_preamble_bytes < 16
            || self.identity_resolution_timeout.is_zero()
            || self.identity_resolver_concurrency == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP proxy and identity limits must be positive",
            ));
        }
        if self.proxy_protocol_v2_required && self.trusted_proxy_addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXY v2 requires at least one exact trusted proxy address",
            ));
        }
        Ok(())
    }
}

/// Mandatory mutual-TLS configuration for direct raw-TCP X.509-SVID identity.
///
/// Construction installs rustls' WebPKI client verifier with the supplied
/// trust roots. Callers cannot replace it with an optional or permissive
/// verifier. The verified leaf is then checked against the strict X.509-SVID
/// profile and allowed SPIFFE trust domains before any VGI framing is read.
#[cfg(feature = "tcp-mtls")]
#[derive(Clone)]
pub struct TcpMutualTlsConfig {
    server_config: Arc<rustls::ServerConfig>,
    trust_domains: BTreeSet<String>,
    handshake_timeout: Duration,
}

#[cfg(feature = "tcp-mtls")]
impl TcpMutualTlsConfig {
    pub fn new<D, S>(
        server_certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        server_private_key: rustls::pki_types::PrivateKeyDer<'static>,
        client_roots: rustls::RootCertStore,
        trust_domains: D,
    ) -> crate::Result<Self>
    where
        D: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if server_certificate_chain.is_empty() || client_roots.is_empty() {
            return Err(RpcError::value_error(
                "direct TCP mTLS requires a server certificate and client trust roots",
            ));
        }
        let mut domains = BTreeSet::new();
        for value in trust_domains {
            let value = value.into();
            if !crate::auth::spiffe_proxy::valid_trust_domain(&value) || !domains.insert(value) {
                return Err(RpcError::value_error(
                    "direct TCP mTLS trust domains must be valid and unique",
                ));
            }
        }
        if domains.is_empty() {
            return Err(RpcError::value_error(
                "direct TCP mTLS requires an allowed SPIFFE trust domain",
            ));
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|error| RpcError::value_error(format!("invalid client trust roots: {error}")))?;
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| RpcError::value_error(format!("invalid TLS versions: {error}")))?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certificate_chain, server_private_key)
            .map_err(|error| {
                RpcError::value_error(format!("invalid TLS server certificate or key: {error}"))
            })?;
        Ok(Self {
            server_config: Arc::new(server_config),
            trust_domains: domains,
            handshake_timeout: Duration::from_secs(5),
        })
    }

    pub fn with_handshake_timeout(mut self, timeout: Duration) -> crate::Result<Self> {
        if timeout.is_zero() {
            return Err(RpcError::value_error(
                "direct TCP mTLS handshake timeout must be positive",
            ));
        }
        self.handshake_timeout = timeout;
        Ok(self)
    }
}

#[derive(Clone, Default)]
enum TcpTransportSecurity {
    #[default]
    Plain,
    #[cfg(feature = "tcp-mtls")]
    MutualTls(TcpMutualTlsConfig),
}

#[derive(Clone, Default)]
struct TcpConnectionOptions {
    identity: Option<TcpIdentityOptions>,
    security: TcpTransportSecurity,
}

/// Identity and TLS settings for [`serve_tcp_with_mtls_identity`].
#[cfg(feature = "tcp-mtls")]
#[derive(Clone)]
pub struct TcpMutualTlsOptions {
    pub identity: TcpIdentityOptions,
    pub tls: TcpMutualTlsConfig,
}

#[cfg(feature = "tcp-mtls")]
impl TcpMutualTlsOptions {
    pub fn new(tls: TcpMutualTlsConfig) -> Self {
        Self {
            identity: TcpIdentityOptions::default(),
            tls,
        }
    }

    pub fn with_identity(mut self, identity: TcpIdentityOptions) -> Self {
        self.identity = identity;
        self
    }
}

struct ResolverSlots {
    active: AtomicUsize,
    maximum: usize,
}

impl ResolverSlots {
    fn try_acquire(self: &Arc<Self>) -> Option<ResolverPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.maximum {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ResolverPermit(Arc::clone(self))),
                Err(observed) => current = observed,
            }
        }
    }
}

struct ResolverPermit(Arc<ResolverSlots>);

impl Drop for ResolverPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Shared idle bookkeeping: how many connections are live, and — when zero —
/// the instant at which the worker should self-terminate.
struct IdleState {
    conn_count: usize,
    /// `Some(deadline)` while idle (or in startup grace); `None` while at least
    /// one connection is active. Always `None` when `idle_timeout` is unset.
    deadline: Option<Instant>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn reap_finished(threads: &mut Vec<thread::JoinHandle<()>>) {
    let mut index = 0;
    while index < threads.len() {
        if threads[index].is_finished() {
            let handle = threads.swap_remove(index);
            let _ = handle.join();
        } else {
            index += 1;
        }
    }
}

fn join_until(threads: &mut Vec<thread::JoinHandle<()>>, deadline: Instant) {
    loop {
        reap_finished(threads);
        if threads.is_empty() || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Serve `server` on a TCP socket bound to `(host, port)`, one thread per
/// connection.
///
/// Binds and listens, invokes `on_bound` with `(host, actual_port)` once
/// listening succeeds — the caller typically prints `TCP:{host}:{port}` and
/// flushes stdout there. `port = 0` lets the OS pick a free port, which is read
/// back from `local_addr()` and reported to `on_bound`. Nagle's algorithm is
/// disabled (`TCP_NODELAY`) on each accepted connection so the lockstep
/// request/response framing is not delayed waiting to coalesce writes.
///
/// The accept loop runs until either `shutdown` is set or, when `idle_timeout`
/// is `Some`, the worker has been idle past its deadline. On exit the listener
/// is dropped.
///
/// Returns the bind/listen error if the socket cannot be created; the accept
/// loop itself never returns an error (transient accept failures are retried,
/// terminal ones end the loop).
pub fn serve_tcp<F: FnOnce(&str, u16)>(
    server: Arc<RpcServer>,
    host: &str,
    port: u16,
    idle_timeout: Option<Duration>,
    shutdown: Arc<AtomicBool>,
    on_bound: F,
) -> io::Result<()> {
    serve_tcp_inner(
        server,
        host,
        port,
        idle_timeout,
        shutdown,
        TcpConnectionOptions::default(),
        on_bound,
    )
}

/// Serve raw VGI over TCP with an immutable, connection-scoped peer identity
/// snapshot. When PROXY v2 is required, the accepted socket's immediate IP is
/// checked against the exact trust set before one preamble byte is read.
pub fn serve_tcp_with_identity<F: FnOnce(&str, u16)>(
    server: Arc<RpcServer>,
    host: &str,
    port: u16,
    idle_timeout: Option<Duration>,
    shutdown: Arc<AtomicBool>,
    identity: TcpIdentityOptions,
    on_bound: F,
) -> io::Result<()> {
    identity.validate()?;
    serve_tcp_inner(
        server,
        host,
        port,
        idle_timeout,
        shutdown,
        TcpConnectionOptions {
            identity: Some(identity),
            security: TcpTransportSecurity::Plain,
        },
        on_bound,
    )
}

/// Serve raw VGI over mandatory mutual TLS with a strict direct X.509-SVID
/// connection snapshot.
///
/// If PROXY v2 is enabled in `options.identity`, its preamble is consumed and trusted
/// before TLS begins. One monotonic handshake deadline covers both phases.
/// The resulting `spiffe` evidence does not authenticate implicitly: configure
/// `options.identity.policy` (normally `peer_identity_primary("spiffe")`) when
/// the SPIFFE workload should become the application principal.
#[cfg(feature = "tcp-mtls")]
pub fn serve_tcp_with_mtls_identity<F: FnOnce(&str, u16)>(
    server: Arc<RpcServer>,
    host: &str,
    port: u16,
    idle_timeout: Option<Duration>,
    shutdown: Arc<AtomicBool>,
    options: TcpMutualTlsOptions,
    on_bound: F,
) -> io::Result<()> {
    options.identity.validate()?;
    serve_tcp_inner(
        server,
        host,
        port,
        idle_timeout,
        shutdown,
        TcpConnectionOptions {
            identity: Some(options.identity),
            security: TcpTransportSecurity::MutualTls(options.tls),
        },
        on_bound,
    )
}

fn serve_tcp_inner<F: FnOnce(&str, u16)>(
    server: Arc<RpcServer>,
    host: &str,
    port: u16,
    idle_timeout: Option<Duration>,
    shutdown: Arc<AtomicBool>,
    connection_options: TcpConnectionOptions,
    on_bound: F,
) -> io::Result<()> {
    #[cfg(not(feature = "tcp-mtls"))]
    let _ = &connection_options.security;
    let listener = TcpListener::bind((host, port))?;
    let bound_port = listener.local_addr()?.port();
    listener.set_nonblocking(true).ok();
    on_bound(host, bound_port);

    // Startup grace: max(idle_timeout, 60s) before the first client connects,
    // matching the Unix launcher's `_arm_timer_locked(max(idle_timeout, 60))`.
    let startup_deadline = idle_timeout.map(|t| Instant::now() + t.max(Duration::from_secs(60)));
    let state = Arc::new(Mutex::new(IdleState {
        conn_count: 0,
        deadline: startup_deadline,
    }));

    let mut threads: Vec<thread::JoinHandle<()>> = Vec::new();
    let active = Arc::new(Mutex::new(HashMap::<u64, TcpStream>::new()));
    let next_connection_id = AtomicU64::new(1);
    let resolver_slots = connection_options.identity.as_ref().map(|options| {
        Arc::new(ResolverSlots {
            active: AtomicUsize::new(0),
            maximum: options.identity_resolver_concurrency,
        })
    });
    loop {
        reap_finished(&mut threads);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        // Idle self-termination: only when nothing is in flight and the
        // (startup or re-armed) deadline has elapsed.
        if idle_timeout.is_some() {
            let st = lock(&state);
            if st.conn_count == 0 {
                if let Some(dl) = st.deadline {
                    if Instant::now() >= dl {
                        break;
                    }
                }
            }
        }

        match listener.accept() {
            Ok((mut conn, peer)) => {
                conn.set_nonblocking(false).ok();
                // Disable Nagle so lockstep framing isn't delayed.
                conn.set_nodelay(true).ok();
                // Both clones are prerequisites: the worker needs one reader
                // and the accept loop needs an independent handle that can
                // interrupt a stalled read during shutdown. Never account or
                // spawn a connection that cannot be interrupted.
                let mut reader = match conn.try_clone() {
                    Ok(reader) => reader,
                    Err(_) => continue,
                };
                let interrupter = match conn.try_clone() {
                    Ok(interrupter) => interrupter,
                    Err(_) => continue,
                };
                {
                    let mut st = lock(&state);
                    st.conn_count += 1;
                    st.deadline = None; // cancel idle timer while active
                }
                let srv = server.clone();
                let state2 = state.clone();
                let active2 = active.clone();
                let identity = connection_options.identity.clone();
                #[cfg(feature = "tcp-mtls")]
                let security = connection_options.security.clone();
                let resolver_slots = resolver_slots.clone();
                let connection_id = next_connection_id.fetch_add(1, Ordering::Relaxed);
                lock(&active).insert(connection_id, interrupter);
                threads.push(thread::spawn(move || {
                    #[cfg(feature = "tcp-mtls")]
                    if let TcpTransportSecurity::MutualTls(tls) = security {
                        match identity.as_ref() {
                            Some(options) => serve_mtls_connection(
                                &srv,
                                reader,
                                conn,
                                peer,
                                options,
                                resolver_slots.as_ref().expect("identity slots configured"),
                                &tls,
                            ),
                            None => unreachable!("mTLS identity options are always configured"),
                        }
                    } else {
                        serve_plain_connection(
                            &srv,
                            &mut reader,
                            &mut conn,
                            peer,
                            identity.as_ref(),
                            resolver_slots.as_ref(),
                        );
                    }
                    #[cfg(not(feature = "tcp-mtls"))]
                    serve_plain_connection(
                        &srv,
                        &mut reader,
                        &mut conn,
                        peer,
                        identity.as_ref(),
                        resolver_slots.as_ref(),
                    );
                    let mut st = lock(&state2);
                    st.conn_count -= 1;
                    // Re-arm the idle timer once the last connection drains.
                    if st.conn_count == 0 {
                        if let Some(t) = idle_timeout {
                            st.deadline = Some(Instant::now() + t);
                        }
                    }
                    drop(st);
                    lock(&active2).remove(&connection_id);
                }));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    drop(listener);
    for connection in lock(&active).values() {
        let _ = connection.shutdown(Shutdown::Both);
    }
    // Poll only completed handles. Calling `join` on an unfinished handle
    // would make the nominal deadline unbounded.
    let deadline = Instant::now() + Duration::from_secs(2);
    join_until(&mut threads, deadline);
    Ok(())
}

fn serve_plain_connection(
    server: &RpcServer,
    reader: &mut TcpStream,
    connection: &mut TcpStream,
    immediate: SocketAddr,
    options: Option<&TcpIdentityOptions>,
    resolver_slots: Option<&Arc<ResolverSlots>>,
) {
    let snapshot = match options {
        Some(options) => prepare_tcp_identity(
            reader,
            connection,
            immediate,
            options,
            resolver_slots.expect("identity slots configured"),
        ),
        None => Ok(ConnectionContext::default()),
    };
    match snapshot {
        Ok(snapshot) => server.serve_with_context(reader, connection, snapshot),
        Err(error) => tracing::warn!(
            target: "vgi_rpc.tcp",
            error_kind = ?error.kind(),
            "TCP connection identity rejected"
        ),
    }
}

#[derive(Clone, Debug)]
struct PreparedTcpPeer {
    immediate: SocketAddr,
    asserted: Option<String>,
    destination: String,
}

fn prepare_tcp_peer(
    reader: &mut TcpStream,
    connection: &TcpStream,
    immediate: SocketAddr,
    options: &TcpIdentityOptions,
    handshake_deadline: Option<Instant>,
) -> io::Result<PreparedTcpPeer> {
    let immediate = SocketAddr::new(normalize_ip(immediate.ip()), immediate.port());
    let mut asserted = None;
    let mut destination = connection.local_addr()?.to_string();
    if options.proxy_protocol_v2_required {
        let immediate_ip = immediate.ip();
        if !options
            .trusted_proxy_addresses
            .iter()
            .any(|trusted| normalize_ip(*trusted) == immediate_ip)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "immediate peer is not a trusted PROXY v2 sender",
            ));
        }
        let proxy = read_proxy_until(
            reader,
            handshake_deadline.unwrap_or_else(|| {
                Instant::now()
                    .checked_add(options.proxy_preamble_timeout)
                    .unwrap_or_else(Instant::now)
            }),
            options.maximum_proxy_preamble_bytes,
        )?;
        asserted = Some(proxy.source.to_string());
        destination = proxy.destination.to_string();
    }
    Ok(PreparedTcpPeer {
        immediate,
        asserted,
        destination,
    })
}

fn prepare_tcp_identity(
    reader: &mut TcpStream,
    connection: &TcpStream,
    immediate: SocketAddr,
    options: &TcpIdentityOptions,
    resolver_slots: &Arc<ResolverSlots>,
) -> io::Result<ConnectionContext> {
    let peer = prepare_tcp_peer(reader, connection, immediate, options, None)?;
    resolve_tcp_identity(peer, options, resolver_slots, None)
}

fn resolve_tcp_identity(
    peer: PreparedTcpPeer,
    options: &TcpIdentityOptions,
    resolver_slots: &Arc<ResolverSlots>,
    direct_identity: Option<PeerIdentityResult>,
) -> io::Result<ConnectionContext> {
    if options.providers.is_empty() && options.policy.is_none() && direct_identity.is_none() {
        return Ok(ConnectionContext::new(
            options.application_auth.clone(),
            Arc::new(PeerEvidenceSet::default()),
        ));
    }
    let deadline = Instant::now()
        .checked_add(options.identity_resolution_timeout)
        .unwrap_or_else(Instant::now);
    let has_direct_tls = direct_identity.is_some();
    let has_proxy_protocol = peer.asserted.is_some();
    let context = PeerResolutionContext::new("tcp")
        .map_err(io::Error::other)?
        .with_peers(Some(peer.immediate.to_string()), peer.asserted.clone())
        .with_source_endpoint(Some(peer.immediate.to_string()))
        .with_destination(
            Some(peer.destination),
            options.service_name.as_ref().map(ToOwned::to_owned),
        )
        .with_metadata(BTreeMap::from([
            (
                "remote_addr".into(),
                serde_json::Value::String(peer.immediate.to_string()),
            ),
            (
                "proxy_protocol_v2".into(),
                serde_json::Value::Bool(has_proxy_protocol),
            ),
            ("direct_tls".into(), serde_json::Value::Bool(has_direct_tls)),
        ]))
        .map_err(io::Error::other)?
        .with_deadline(deadline);
    let mut configured = BTreeSet::new();
    for provider in options.providers.iter() {
        if !configured.insert(provider.provider().to_owned()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate peer identity provider",
            ));
        }
    }
    let (sender, receiver) = mpsc::channel();
    let mut pending = BTreeSet::new();
    let mut results =
        Vec::with_capacity(options.providers.len() + usize::from(direct_identity.is_some()));
    for provider in options.providers.iter() {
        let name = provider.provider().to_owned();
        let Some(permit) = resolver_slots.try_acquire() else {
            results.push(
                PeerIdentityResult::without_identity(name, crate::PeerIdentityStatus::Unavailable)
                    .map_err(io::Error::other)?,
            );
            continue;
        };
        pending.insert(name.clone());
        let provider = provider.clone();
        let context = context.clone();
        let sender = sender.clone();
        thread::Builder::new()
            .name(format!("vgi-tcp-identity-{name}"))
            .spawn(move || {
                let _permit = permit;
                let _ = sender.send((name, provider.resolve(&context)));
            })
            .map_err(|_| io::Error::other("failed to spawn peer identity provider task"))?;
    }
    drop(sender);

    while !pending.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok((provider, result)) => {
                record_tcp_peer_provider_result(&mut results, &mut pending, provider, result)
                    .map_err(peer_provider_error_to_io)?
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other(
                    "peer identity provider tasks terminated without results",
                ));
            }
        }
    }
    while let Ok((provider, result)) = receiver.try_recv() {
        record_tcp_peer_provider_result(&mut results, &mut pending, provider, result)
            .map_err(peer_provider_error_to_io)?;
    }
    for provider in pending {
        results.push(
            PeerIdentityResult::without_identity(provider, crate::PeerIdentityStatus::Unavailable)
                .map_err(io::Error::other)?,
        );
    }
    if let Some(direct_identity) = direct_identity {
        results.push(direct_identity);
    }
    let evidence =
        Arc::new(PeerEvidenceSet::from_results(results).map_err(peer_provider_error_to_io)?);
    let auth = match options.policy.as_ref() {
        Some(policy) => {
            policy(&evidence, &options.application_auth).map_err(peer_policy_error_to_io)?
        }
        None => options.application_auth.clone(),
    };
    Ok(ConnectionContext::new(auth, evidence))
}

fn record_tcp_peer_provider_result(
    results: &mut Vec<PeerIdentityResult>,
    pending: &mut BTreeSet<String>,
    provider: String,
    result: crate::Result<PeerIdentityResult>,
) -> crate::Result<()> {
    if !pending.remove(&provider) {
        return Err(RpcError::runtime_error(
            "peer identity provider task attribution mismatch",
        ));
    }
    match result {
        Ok(result) if result.provider() == provider => {
            results.push(result);
            Ok(())
        }
        Ok(_) => Err(RpcError::runtime_error(
            "peer identity provider result attribution mismatch",
        )),
        Err(error) if error.is_auth_unavailable() => {
            results.push(PeerIdentityResult::without_identity(
                provider,
                crate::PeerIdentityStatus::Unavailable,
            )?);
            Ok(())
        }
        Err(error)
            if error.auth_reason.is_some()
                || matches!(error.error_type.as_str(), "PermissionError" | "ValueError") =>
        {
            Err(RpcError::auth_failure(
                AuthReason::InvalidCredential,
                format!("peer identity provider {provider} rejected evidence"),
            ))
        }
        Err(_) => Err(RpcError::runtime_error(format!(
            "peer identity provider {provider} failed"
        ))),
    }
}

fn peer_provider_error_to_io(error: RpcError) -> io::Error {
    if error.is_auth_unavailable() {
        io::Error::new(io::ErrorKind::TimedOut, error)
    } else if error.auth_reason.is_some()
        || matches!(error.error_type.as_str(), "PermissionError" | "ValueError")
    {
        io::Error::new(io::ErrorKind::PermissionDenied, error)
    } else {
        io::Error::other(error)
    }
}

fn peer_policy_error_to_io(error: RpcError) -> io::Error {
    if error.is_auth_unavailable() {
        let retry_after = error.retry_after_seconds;
        let mut redacted = RpcError::auth_unavailable("peer identity authentication unavailable");
        if let Some(seconds) = retry_after {
            redacted = redacted.with_retry_after(seconds);
        }
        io::Error::new(io::ErrorKind::TimedOut, redacted)
    } else {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            RpcError::auth_failure(
                error.auth_reason.unwrap_or(AuthReason::InvalidCredential),
                "peer identity authentication rejected",
            ),
        )
    }
}

#[cfg(feature = "tcp-mtls")]
type ServerTlsStream = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

#[cfg(feature = "tcp-mtls")]
struct TlsReader(Arc<Mutex<ServerTlsStream>>);

#[cfg(feature = "tcp-mtls")]
struct TlsWriter(Arc<Mutex<ServerTlsStream>>);

#[cfg(feature = "tcp-mtls")]
impl Read for TlsReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        lock(&self.0).read(output)
    }
}

#[cfg(feature = "tcp-mtls")]
impl io::Write for TlsWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut *lock(&self.0), input)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut *lock(&self.0))
    }
}

#[cfg(feature = "tcp-mtls")]
fn serve_mtls_connection(
    server: &RpcServer,
    mut proxy_reader: TcpStream,
    connection: TcpStream,
    immediate: SocketAddr,
    options: &TcpIdentityOptions,
    resolver_slots: &Arc<ResolverSlots>,
    tls: &TcpMutualTlsConfig,
) {
    let prepared = (|| {
        let deadline = Instant::now()
            .checked_add(tls.handshake_timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS timeout overflow"))?;
        let peer = prepare_tcp_peer(
            &mut proxy_reader,
            &connection,
            immediate,
            options,
            Some(deadline),
        )?;
        let (stream, direct_identity) = accept_direct_spiffe_tls(connection, &peer, tls, deadline)?;
        let snapshot = resolve_tcp_identity(peer, options, resolver_slots, Some(direct_identity))?;
        Ok::<_, io::Error>((stream, snapshot))
    })();
    match prepared {
        Ok((stream, snapshot)) => {
            let stream = Arc::new(Mutex::new(stream));
            server.serve_with_context(TlsReader(Arc::clone(&stream)), TlsWriter(stream), snapshot);
        }
        Err(error) => tracing::warn!(
            target: "vgi_rpc.tcp",
            error_kind = ?error.kind(),
            "TCP mutual-TLS identity rejected"
        ),
    }
}

#[cfg(feature = "tcp-mtls")]
fn accept_direct_spiffe_tls(
    mut socket: TcpStream,
    peer: &PreparedTcpPeer,
    tls: &TcpMutualTlsConfig,
    deadline: Instant,
) -> io::Result<(ServerTlsStream, PeerIdentityResult)> {
    let mut connection = rustls::ServerConnection::new(Arc::clone(&tls.server_config))
        .map_err(|error| io::Error::other(format!("create TLS server connection: {error}")))?;
    while connection.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "direct TCP mutual-TLS handshake timed out",
            ));
        }
        socket.set_read_timeout(Some(remaining))?;
        socket.set_write_timeout(Some(remaining))?;
        connection
            .complete_io(&mut socket)
            .map_err(|error| io::Error::other(format!("mutual-TLS handshake: {error}")))?;
    }
    socket.set_read_timeout(None)?;
    socket.set_write_timeout(None)?;
    let certificates = connection.peer_certificates().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mutual TLS did not provide a verified client certificate",
        )
    })?;
    let leaf = certificates.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mutual TLS did not provide a verified client certificate",
        )
    })?;
    let (spiffe_id, trust_domain) =
        crate::auth::spiffe_x509::x509_svid_from_der(leaf.as_ref(), &tls.trust_domains).map_err(
            |()| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "verified client certificate is not an allowed X.509-SVID",
                )
            },
        )?;
    let immediate = peer.immediate.to_string();
    let source = peer.asserted.clone().unwrap_or_else(|| immediate.clone());
    let proxy = peer.asserted.as_ref().map(|_| immediate);
    let identity = PeerIdentity::new(
        "spiffe",
        "direct_tls",
        IdentityAssurance::CryptographicPeer,
        format!("spiffe://{trust_domain}"),
        "tcp",
    )
    .map_err(io::Error::other)?
    .with_subject(
        SubjectKind::Workload,
        spiffe_id,
        SubjectStability::Stable,
        true,
    )
    .map_err(io::Error::other)?
    .with_addresses(Some(source), proxy);
    let result = PeerIdentityResult::available(identity);
    Ok((rustls::StreamOwned::new(connection, socket), result))
}

fn read_proxy_until(
    stream: &mut TcpStream,
    deadline: Instant,
    maximum_bytes: usize,
) -> io::Result<crate::proxy_protocol::ProxyProtocolV2Address> {
    if maximum_bytes < 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "maximum PROXY v2 bytes must be at least 16",
        ));
    }
    let mut fixed = [0u8; 16];
    read_exact_until(stream, &mut fixed, deadline)?;
    let total = 16 + usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if total > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY v2 preamble exceeds configured limit",
        ));
    }
    let mut preamble = vec![0; total];
    preamble[..16].copy_from_slice(&fixed);
    read_exact_until(stream, &mut preamble[16..], deadline)?;
    stream.set_read_timeout(None)?;
    crate::proxy_protocol::parse_proxy_protocol_v2(&preamble, maximum_bytes)
}

fn read_exact_until(
    stream: &mut TcpStream,
    mut output: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !output.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PROXY v2 preamble timed out",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(output) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated PROXY v2 preamble",
                ));
            }
            Ok(read) => output = &mut output[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
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
mod identity_tests {
    use super::*;
    use crate::auth::identity::{
        any_of_peer_identities, peer_identity_primary, require_peer_identity, IdentityAssurance,
        PeerIdentity, PeerIdentityResult, PeerIdentityStatus, SubjectKind, SubjectStability,
    };
    use std::io::Write;
    use std::net::Ipv4Addr;
    use std::sync::Barrier;

    #[cfg(feature = "tcp-mtls")]
    use base64::Engine;

    fn tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        (client, server, peer)
    }

    fn proxy_v4(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut value = vec![
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0,
            12,
        ];
        value.extend_from_slice(&source);
        value.extend_from_slice(&destination);
        value.extend_from_slice(&12345u16.to_be_bytes());
        value.extend_from_slice(&9400u16.to_be_bytes());
        value
    }

    #[cfg(feature = "tcp-mtls")]
    fn pem_der(value: &str, label: &str) -> Vec<u8> {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let body = value
            .split_once(&begin)
            .unwrap()
            .1
            .split_once(&end)
            .unwrap()
            .0
            .lines()
            .map(str::trim)
            .collect::<String>();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap()
    }

    #[cfg(feature = "tcp-mtls")]
    fn certificate(value: &str) -> rustls::pki_types::CertificateDer<'static> {
        rustls::pki_types::CertificateDer::from(pem_der(value, "CERTIFICATE"))
    }

    #[cfg(feature = "tcp-mtls")]
    fn private_key(value: &str) -> rustls::pki_types::PrivateKeyDer<'static> {
        rustls::pki_types::PrivatePkcs8KeyDer::from(pem_der(value, "PRIVATE KEY")).into()
    }

    #[cfg(feature = "tcp-mtls")]
    fn server_tls(domains: &[&str], timeout: Duration) -> TcpMutualTlsConfig {
        let client = certificate(include_str!("../tests/data/tcp-mtls-client-cert.pem"));
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(client).unwrap();
        TcpMutualTlsConfig::new(
            vec![certificate(include_str!(
                "../tests/data/tcp-mtls-server-cert.pem"
            ))],
            private_key(include_str!("../tests/data/tcp-mtls-server-key.pem")),
            client_roots,
            domains.iter().copied(),
        )
        .unwrap()
        .with_handshake_timeout(timeout)
        .unwrap()
    }

    #[cfg(feature = "tcp-mtls")]
    fn client_tls(with_certificate: bool) -> Arc<rustls::ClientConfig> {
        let mut server_roots = rustls::RootCertStore::empty();
        server_roots
            .add(certificate(include_str!(
                "../tests/data/tcp-mtls-server-cert.pem"
            )))
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(server_roots);
        let config = if with_certificate {
            builder
                .with_client_auth_cert(
                    vec![certificate(include_str!(
                        "../tests/data/tcp-mtls-client-cert.pem"
                    ))],
                    private_key(include_str!("../tests/data/tcp-mtls-client-key.pem")),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        Arc::new(config)
    }

    #[cfg(feature = "tcp-mtls")]
    fn spawn_tls_client(
        mut socket: TcpStream,
        proxy: Option<Vec<u8>>,
        with_certificate: bool,
    ) -> thread::JoinHandle<io::Result<()>> {
        thread::spawn(move || {
            if let Some(proxy) = proxy {
                socket.write_all(&proxy)?;
            }
            let name = rustls::pki_types::ServerName::try_from("localhost")
                .expect("static server name")
                .to_owned();
            let connection = rustls::ClientConnection::new(client_tls(with_certificate), name)
                .map_err(io::Error::other)?;
            let mut stream = rustls::StreamOwned::new(connection, socket);
            stream.write_all(&[0xaa])?;
            stream.flush()
        })
    }

    fn test_identity(context: &PeerResolutionContext) -> crate::Result<PeerIdentityResult> {
        assert_eq!(context.transport(), "tcp");
        assert_eq!(context.asserted_peer(), Some("100.64.0.8:12345"));
        assert_eq!(context.destination_address(), Some("100.64.0.9:9400"));
        assert_eq!(context.service_name(), Some("svc:worker"));
        let identity = PeerIdentity::new(
            "tailscale",
            "localapi",
            IdentityAssurance::LocalDaemon,
            "tailnet:test",
            "tcp",
        )?
        .with_subject(
            SubjectKind::TaggedNode,
            "node:stable",
            SubjectStability::Stable,
            true,
        )?;
        Ok(PeerIdentityResult::available(identity))
    }

    #[test]
    fn proxy_identity_is_snapshotted_and_following_vgi_bytes_are_preserved() {
        let (mut client, connection, peer) = tcp_pair();
        let mut wire = proxy_v4([100, 64, 0, 8], [100, 64, 0, 9]);
        wire.push(0xaa);
        client.write_all(&wire).unwrap();
        let mut reader = connection.try_clone().unwrap();
        let options = TcpIdentityOptions {
            proxy_protocol_v2_required: true,
            trusted_proxy_addresses: BTreeSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            service_name: Some("svc:worker".into()),
            providers: Arc::from([PeerIdentityProvider::new("tailscale", test_identity).unwrap()]),
            policy: Some(peer_identity_primary("tailscale")),
            ..TcpIdentityOptions::default()
        };
        let slots = Arc::new(ResolverSlots {
            active: AtomicUsize::new(0),
            maximum: 1,
        });
        let mapped_peer = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
            peer.port(),
        );
        let snapshot =
            prepare_tcp_identity(&mut reader, &connection, mapped_peer, &options, &slots).unwrap();
        assert!(snapshot.auth.authenticated);
        assert_eq!(snapshot.auth.domain, "tailscale");
        assert_eq!(
            snapshot
                .peer_evidence
                .unique_verified_subject("tailscale")
                .unwrap()
                .subject_key(),
            Some("node:stable")
        );
        let mut following = [0];
        reader.read_exact(&mut following).unwrap();
        assert_eq!(following, [0xaa]);
    }

    #[test]
    fn untrusted_proxy_is_rejected_before_waiting_for_a_preamble() {
        let (_client, connection, peer) = tcp_pair();
        let mut reader = connection.try_clone().unwrap();
        let options = TcpIdentityOptions {
            proxy_protocol_v2_required: true,
            trusted_proxy_addresses: BTreeSet::from(["192.0.2.1".parse().unwrap()]),
            ..TcpIdentityOptions::default()
        };
        let slots = Arc::new(ResolverSlots {
            active: AtomicUsize::new(0),
            maximum: 1,
        });
        let started = Instant::now();
        let error =
            prepare_tcp_identity(&mut reader, &connection, peer, &options, &slots).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn proxy_preamble_uses_one_total_monotonic_deadline() {
        let (mut client, connection, peer) = tcp_pair();
        let mut reader = connection.try_clone().unwrap();
        let options = TcpIdentityOptions {
            proxy_protocol_v2_required: true,
            trusted_proxy_addresses: BTreeSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            proxy_preamble_timeout: Duration::from_millis(30),
            ..TcpIdentityOptions::default()
        };
        let slots = Arc::new(ResolverSlots {
            active: AtomicUsize::new(0),
            maximum: 1,
        });
        let barrier = Arc::new(Barrier::new(2));
        let writer_barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let wire = proxy_v4([100, 64, 0, 8], [100, 64, 0, 9]);
            writer_barrier.wait();
            for byte in wire {
                if client.write_all(&[byte]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(8));
            }
        });
        barrier.wait();
        let started = Instant::now();
        let error =
            prepare_tcp_identity(&mut reader, &connection, peer, &options, &slots).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(120));
    }

    #[test]
    fn timed_out_provider_keeps_its_global_capacity_until_it_exits() {
        let provider = PeerIdentityProvider::new("slow", |_| {
            thread::sleep(Duration::from_millis(150));
            PeerIdentityResult::without_identity("slow", PeerIdentityStatus::NoMatch)
        })
        .unwrap();
        let options = TcpIdentityOptions {
            identity_resolution_timeout: Duration::from_millis(20),
            identity_resolver_concurrency: 1,
            providers: Arc::from([provider]),
            ..TcpIdentityOptions::default()
        };
        let slots = Arc::new(ResolverSlots {
            active: AtomicUsize::new(0),
            maximum: 1,
        });
        let (_client, connection, peer) = tcp_pair();
        let mut reader = connection.try_clone().unwrap();
        let first = prepare_tcp_identity(&mut reader, &connection, peer, &options, &slots).unwrap();
        assert_eq!(
            first.peer_evidence.status("slow"),
            PeerIdentityStatus::Unavailable
        );
        assert_eq!(slots.active.load(Ordering::Acquire), 1);

        let (_client, connection, peer) = tcp_pair();
        let mut reader = connection.try_clone().unwrap();
        let second =
            prepare_tcp_identity(&mut reader, &connection, peer, &options, &slots).unwrap();
        assert_eq!(
            second.peer_evidence.status("slow"),
            PeerIdentityStatus::Unavailable
        );
    }

    #[test]
    fn raw_tcp_any_of_preserves_valid_application_auth_during_provider_outage() {
        let provider = PeerIdentityProvider::new("slow", |_| {
            thread::sleep(Duration::from_millis(100));
            PeerIdentityResult::without_identity("slow", PeerIdentityStatus::NoMatch)
        })
        .unwrap();
        let options = TcpIdentityOptions {
            identity_resolution_timeout: Duration::from_millis(10),
            providers: Arc::from([provider]),
            policy: Some(any_of_peer_identities(["slow"]).unwrap()),
            application_auth: AuthContext::for_principal("bearer", "alice"),
            ..TcpIdentityOptions::default()
        };
        let slots = Arc::new(ResolverSlots {
            active: AtomicUsize::new(0),
            maximum: 1,
        });
        let (_client, connection, peer) = tcp_pair();
        let mut reader = connection.try_clone().unwrap();
        let snapshot =
            prepare_tcp_identity(&mut reader, &connection, peer, &options, &slots).unwrap();
        assert!(snapshot.auth.authenticated);
        assert_eq!(snapshot.auth.principal, "alice");
        assert_eq!(
            snapshot.peer_evidence.status("slow"),
            PeerIdentityStatus::Unavailable
        );
    }

    #[test]
    fn raw_tcp_unavailable_provider_fails_required_policies() {
        for policy in [require_peer_identity("slow"), peer_identity_primary("slow")] {
            let provider = PeerIdentityProvider::new("slow", |_| {
                Err(RpcError::auth_unavailable("secret authority detail"))
            })
            .unwrap();
            let options = TcpIdentityOptions {
                providers: Arc::from([provider]),
                policy: Some(policy),
                ..TcpIdentityOptions::default()
            };
            let slots = Arc::new(ResolverSlots {
                active: AtomicUsize::new(0),
                maximum: 1,
            });
            let (_client, connection, peer) = tcp_pair();
            let mut reader = connection.try_clone().unwrap();
            let error =
                prepare_tcp_identity(&mut reader, &connection, peer, &options, &slots).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(!error.to_string().contains("secret authority detail"));
        }
    }

    #[test]
    fn raw_tcp_custom_policy_details_are_redacted() {
        for (policy, expected_kind, expected_text) in [
            (
                Arc::new(|_: &PeerEvidenceSet, _: &AuthContext| {
                    Err(RpcError::auth_failure(
                        AuthReason::InvalidCredential,
                        "raw-capability-policy-secret",
                    ))
                }) as PeerAuthenticationPolicy,
                io::ErrorKind::PermissionDenied,
                "peer identity authentication rejected",
            ),
            (
                Arc::new(|_: &PeerEvidenceSet, _: &AuthContext| {
                    Err(RpcError::auth_unavailable("raw-capability-policy-secret")
                        .with_retry_after(17))
                }) as PeerAuthenticationPolicy,
                io::ErrorKind::TimedOut,
                "peer identity authentication unavailable",
            ),
        ] {
            let options = TcpIdentityOptions {
                policy: Some(policy),
                ..TcpIdentityOptions::default()
            };
            let slots = Arc::new(ResolverSlots {
                active: AtomicUsize::new(0),
                maximum: 1,
            });
            let (_client, connection, peer) = tcp_pair();
            let mut reader = connection.try_clone().unwrap();
            let error =
                prepare_tcp_identity(&mut reader, &connection, peer, &options, &slots).unwrap_err();
            assert_eq!(error.kind(), expected_kind);
            assert!(error.to_string().contains(expected_text));
            assert!(!error.to_string().contains("raw-capability-policy-secret"));
        }
    }

    #[test]
    fn raw_tcp_invalid_peer_evidence_never_falls_back_to_application_auth() {
        let provider = PeerIdentityProvider::new("peer", |_| {
            PeerIdentityResult::without_identity("peer", PeerIdentityStatus::Invalid)
        })
        .unwrap();
        let options = TcpIdentityOptions {
            providers: Arc::from([provider]),
            policy: Some(any_of_peer_identities(["peer"]).unwrap()),
            application_auth: AuthContext::for_principal("bearer", "alice"),
            ..TcpIdentityOptions::default()
        };
        let slots = Arc::new(ResolverSlots {
            active: AtomicUsize::new(0),
            maximum: 1,
        });
        let (_client, connection, peer) = tcp_pair();
        let mut reader = connection.try_clone().unwrap();
        assert_eq!(
            prepare_tcp_identity(&mut reader, &connection, peer, &options, &slots)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(feature = "tcp-mtls")]
    #[test]
    fn direct_mtls_verifies_and_snapshots_spiffe_after_proxy_v2() {
        let (client, connection, immediate) = tcp_pair();
        let proxy = proxy_v4([100, 64, 0, 8], [100, 64, 0, 9]);
        let client = spawn_tls_client(client, Some(proxy), true);
        let options = TcpIdentityOptions {
            proxy_protocol_v2_required: true,
            trusted_proxy_addresses: BTreeSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            policy: Some(peer_identity_primary("spiffe")),
            ..TcpIdentityOptions::default()
        };
        let tls = server_tls(&["example.org"], Duration::from_secs(2));
        let deadline = Instant::now() + tls.handshake_timeout;
        let mut proxy_reader = connection.try_clone().unwrap();
        let peer = prepare_tcp_peer(
            &mut proxy_reader,
            &connection,
            immediate,
            &options,
            Some(deadline),
        )
        .unwrap();
        assert_eq!(peer.asserted.as_deref(), Some("100.64.0.8:12345"));
        let (mut stream, direct) =
            accept_direct_spiffe_tls(connection, &peer, &tls, deadline).unwrap();
        let slots = Arc::new(ResolverSlots {
            active: AtomicUsize::new(0),
            maximum: 1,
        });
        let snapshot = resolve_tcp_identity(peer, &options, &slots, Some(direct.clone())).unwrap();
        let identity = snapshot
            .peer_evidence
            .unique_verified_subject("spiffe")
            .unwrap();
        assert_eq!(identity.evidence_source(), "direct_tls");
        assert_eq!(identity.assurance(), IdentityAssurance::CryptographicPeer);
        assert_eq!(identity.transport(), "tcp");
        assert_eq!(identity.subject_kind(), SubjectKind::Workload);
        assert_eq!(
            identity.subject_key(),
            Some("spiffe://example.org/workload")
        );
        assert_eq!(identity.source_address(), Some("100.64.0.8:12345"));
        let immediate_text = immediate.to_string();
        assert_eq!(identity.proxy_address(), Some(immediate_text.as_str()));
        assert!(snapshot.auth.authenticated);
        assert_eq!(snapshot.auth.domain, "spiffe");
        let mut following = [0];
        stream.read_exact(&mut following).unwrap();
        assert_eq!(following, [0xaa]);
        client.join().unwrap().unwrap();

        let provider_result = direct.clone();
        let duplicate_options = TcpIdentityOptions {
            providers: Arc::from([PeerIdentityProvider::new(
                "spiffe",
                move |_: &PeerResolutionContext| Ok(provider_result.clone()),
            )
            .unwrap()]),
            ..TcpIdentityOptions::default()
        };
        let peer = PreparedTcpPeer {
            immediate,
            asserted: None,
            destination: "127.0.0.1:9400".into(),
        };
        assert_eq!(
            resolve_tcp_identity(peer, &duplicate_options, &slots, Some(direct))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(feature = "tcp-mtls")]
    #[test]
    fn direct_mtls_rejects_missing_client_certificate_and_wrong_spiffe_domain() {
        for (with_certificate, domains) in [(false, vec!["example.org"]), (true, vec!["other.org"])]
        {
            let (client, connection, immediate) = tcp_pair();
            let client = spawn_tls_client(client, None, with_certificate);
            let options = TcpIdentityOptions::default();
            let tls = server_tls(&domains, Duration::from_secs(2));
            let deadline = Instant::now() + tls.handshake_timeout;
            let mut reader = connection.try_clone().unwrap();
            let peer = prepare_tcp_peer(
                &mut reader,
                &connection,
                immediate,
                &options,
                Some(deadline),
            )
            .unwrap();
            assert!(accept_direct_spiffe_tls(connection, &peer, &tls, deadline).is_err());
            let _ = client.join().unwrap();
        }
    }

    #[cfg(feature = "tcp-mtls")]
    #[test]
    fn direct_mtls_handshake_has_one_bounded_deadline() {
        let (_client, connection, immediate) = tcp_pair();
        let options = TcpIdentityOptions::default();
        let tls = server_tls(&["example.org"], Duration::from_millis(30));
        let deadline = Instant::now() + tls.handshake_timeout;
        let mut reader = connection.try_clone().unwrap();
        let peer = prepare_tcp_peer(
            &mut reader,
            &connection,
            immediate,
            &options,
            Some(deadline),
        )
        .unwrap();
        let started = Instant::now();
        let error = match accept_direct_spiffe_tls(connection, &peer, &tls, deadline) {
            Ok(_) => panic!("stalled TLS handshake unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Other
        ));
        assert!(started.elapsed() < Duration::from_millis(150));
    }
}
