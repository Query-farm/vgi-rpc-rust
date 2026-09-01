# vgi-rpc-iroh

`vgi-rpc-iroh` carries the existing stateful VGI Arrow-IPC byte-stream protocol
over an authenticated Iroh QUIC connection. Iroh remains an optional workspace
crate: neither `vgi-rpc` nor `vgi-rpc-client` depends on it.

The `vgi-rpc/arrow-mux/1` protocol carries many independent logical VGI
transports on one Iroh QUIC connection. Each logical transport is one
long-lived bidirectional QUIC stream. Unary calls and producer/exchange turns
on that transport stay on the same stream, so worker state stays in memory
exactly as it does over pipe, Unix sockets, or raw TCP. It does not convert
Arrow batches to HTTP bodies or serialize continuation state.

The server snapshots `Connection::remote_id()` once after Iroh's cryptographic
handshake and shares that immutable evidence with every accepted logical
stream. Possession of an
Internet-reachable endpoint key proves the peer key; it does **not** prove
deployment membership or authorization. The default therefore observes this
evidence without authenticating it. An operator must configure an explicit
VGI peer-authentication policy or an application-authenticated allowlist.

Connection, policy, and task-join failures are reduced to fixed classes in
adapter and router logs so caller evidence and panic payloads are not emitted.
Rust's process-global panic hook runs before a task becomes a `JoinError`;
applications that execute untrusted extension code must install a production
panic hook that also redacts panic payloads.

## Server

Configure the accepting endpoint with [`VGI_IROH_ALPN`](https://docs.rs/vgi-rpc-iroh/latest/vgi_rpc_iroh/constant.VGI_IROH_ALPN.html):

```rust,no_run
use std::sync::Arc;
use iroh::{Endpoint, endpoint::presets};
use tokio_util::sync::CancellationToken;
use vgi_rpc::{peer_identity_primary, RpcServer};
use vgi_rpc_iroh::{IrohServer, IrohServerOptions, VGI_IROH_ALPN};

# async fn run(rpc: RpcServer) -> Result<(), Box<dyn std::error::Error>> {
let endpoint = Endpoint::builder(presets::N0)
    .alpns(vec![VGI_IROH_ALPN.to_vec()])
    .bind()
    .await?;
let shutdown = CancellationToken::new();
let options = IrohServerOptions::default()
    .with_issuer("my-deployment")
    // Safe only when endpoint membership is constrained separately. Most
    // Internet deployments should use an operator allowlist policy instead.
    .with_policy(peer_identity_primary("iroh"));
IrohServer::with_options(Arc::new(rpc), options)
    .serve(endpoint, shutdown)
    .await?;
# Ok(()) }
```

`IrohServer::serve` owns the endpoint accept loop and therefore expects a
dedicated endpoint. To share an endpoint with other Iroh protocols, mount
`IrohServer::protocol_handler()` on the official Iroh `Router` under
`VGI_IROH_ALPN`; router shutdown cancels active VGI connections cleanly.

There is no permissive default authentication policy. Use
`IrohServerOptions::with_policy` to apply an operator allowlist, compose with
application authentication, or deliberately select primary identity in a
network where membership is enforced independently. `issuer` must uniquely
name the deployment so endpoint IDs from separate trust domains cannot collide.

The server bounds pending handshakes, established connections, global logical
streams, and streams per connection before allocating blocking framing work.
The first-stream-open budget prevents a peer from occupying an unused
connection slot. Per-read/write idle budgets apply independently to each
logical stream, so a timed-out or malformed stream is reset without poisoning
healthy sibling streams. An absolute `first_request_timeout` also bounds each
stream's first VGI frame even when a peer keeps drip-feeding bytes inside the
idle timeout. The budget stops applying when the server begins that stream's
first response, after its first request framing has been consumed.

Configure `max_pending_handshakes`, `max_active_connections`,
`max_active_streams`, `max_active_streams_per_connection`, and
`connection_io_timeout` for the deployment's capacity. Internet-facing workers
can additionally set `max_active_connections_per_endpoint` (or use
`with_max_active_connections_per_endpoint`) so one authenticated endpoint key
cannot occupy every global connection slot. Connection and stream permits are
released automatically on rejection, timeout, shutdown, or normal completion.
Shutdown stops accepting new streams, lets active streams finish until
`shutdown_timeout`, and then cancels only the remaining work.

## Client

```rust,no_run
use std::time::Duration;
use iroh::{Endpoint, EndpointId, endpoint::presets};
use vgi_rpc_client::RpcClient;
use vgi_rpc_iroh::{IrohClientOptions, IrohConnection};

# async fn connect(remote: EndpointId) -> Result<(), Box<dyn std::error::Error>> {
let endpoint = Endpoint::bind(presets::N0).await?;
let connection = IrohConnection::connect_id(
    endpoint,
    remote,
    IrohClientOptions::default().with_rpc_timeout(Duration::from_secs(30)),
).await?;
let transport = connection.open_transport().await?;

// RpcClient is blocking. Run calls on a blocking thread, outside Tokio's
// async worker threads.
let mut client = RpcClient::from_transport(Box::new(transport));
# drop(client);

// Open another independent logical VGI transport without another Iroh
// handshake. It can be used concurrently on another blocking thread.
let second_client = connection.open_client().await?;
# drop(second_client);
# Ok(()) }
```

Connecting with only an endpoint ID requires the supplied Iroh endpoint to
have a suitable address-lookup service. `connect_addr` also accepts an
`EndpointAddr` containing direct or relay addresses.

Dropping or closing an `IrohTransport` finishes/resets only its QUIC stream.
Dropping the last `IrohConnection`/transport handle or explicitly calling
`IrohConnection::close` closes the pooled connection. Cancelling the
connection token interrupts all blocked stream work; call `close` as well when
the peer must observe immediate connection closure. Connect, stream-open,
handshake, and shutdown budgets use Tokio's monotonic timeouts. The optional
client RPC timeout is a single monotonic budget across all reads and writes in
a VGI call or stream turn. `IrohTransport::connect_id` and `connect_addr`
remain as one-connection/one-stream convenience constructors.

Iroh 1.1.0 has MSRV 1.91; this workspace tests the adapter with Rust 1.97.
