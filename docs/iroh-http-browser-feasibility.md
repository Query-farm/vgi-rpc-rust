# Browser Iroh HTTP feasibility

Validated 2026-09-01 against:

- `vgi-rpc-rust` `e2b53f43866cb696142cf5fe872c3a07c127a250`
- `iroh` `1.1.0`
- `iroh-http-core` `0.6.2` / upstream commit
  `f6ec4d23064dfc9d2d1239be837b14afd1429644`
- Rust `1.97.1`, target `wasm32-unknown-unknown`

## Result

A client-only browser path is feasible with the versions already used by
VGI. The `vgi-rpc-iroh-browser` proof builds Iroh 1.1.0 plus Hyper for
`wasm32-unknown-unknown`, shares an application-owned `iroh::Endpoint`,
negotiates `iroh-http/2`, opens a QUIC bidirectional stream, and sends a typed
Hyper request.

The `iroh-http/2` suffix is iroh-http's wire-protocol version. HTTP framing on
each QUIC bidirectional stream is HTTP/1.1, not HTTP/2.

The native interoperability test uses the released `iroh-http-core` server.
It proves request delivery and proves that the server observes the same
cryptographic endpoint identity exposed by the shared client endpoint.

## Browser build

The target graph contains 9 direct and 220 unique transitive Rust packages.
An isolated cold check took 86 seconds on the development Mac; the workspace
check took 46 seconds after partial cache warm-up. This is feasible, but the
dependency and final bundle-size cost must be measured in a real wasm-bindgen
application before calling it production-ready.

Iroh's `tls-ring` build requires a clang with a WebAssembly backend. Apple
clang 17 fails with `No available targets are compatible with triple
wasm32-unknown-unknown`; Homebrew LLVM clang 22 succeeds. This is a build-host
toolchain requirement, not an Iroh source incompatibility.

The published `iroh-http-core 0.6.2` crate itself does not compile for the
browser target. It unconditionally enables Tokio's `rt-multi-thread` feature,
which Tokio rejects on `wasm32-unknown-unknown`, and it includes native server,
pool, compression, and FFI machinery that a browser client does not need. The
small client crate therefore reuses the protocol and Hyper/Iroh transport
shape without depending on `iroh-http-core` in its production graph.

## Upstream already-negotiated connection blocker

Upstream exposes two whole-endpoint pure-Rust APIs:

- `fetch_request(&IrohEndpoint, &EndpointAddr, Request<Body>, &StackConfig)`
- `serve(IrohEndpoint, ServeOptions, Service)`

It does not expose a server entrypoint for an `iroh::endpoint::Connection`
that was already negotiated by another protocol router. The reusable pieces
are private:

- `http::server::accept::accept_loop` accepts from the raw endpoint.
- The connection stream loop is inline in `accept_loop`.
- `http::server::pipeline::serve_bistream` and the `IrohStream` adapter are
  crate-private.

This cannot safely be fixed by changing one visibility modifier. The inline
connection loop also owns ALPN enforcement, authenticated `RemoteNodeId`
injection, the Tower stack, header limits, slowloris timeout, request and
transport-delivery tracking, graceful-drain gates, and connection close
signals. A separate implementation would drift from those security and
lifecycle invariants.

The smallest reusable upstream change is to extract the existing per-
connection block from `accept.rs` into one internal `serve_connection_inner`
used by `accept_loop`, then expose a wrapper resembling:

```rust,ignore
pub async fn serve_connection<S>(
    connection: iroh::endpoint::Connection,
    options: ConnectionServeOptions,
    service: S,
) -> Result<(), ServeConnectionError>
```

The public options must define whether endpoint-global concurrency, per-peer
limits, statistics, connection events, and graceful-drain ownership are
available or deliberately absent. Until upstream makes that semantic choice,
VGI should use upstream's whole-endpoint `serve` API for HTTP servers and must
not copy its private connection loop into `vgi-rpc-iroh`.

The native VGI mux confirms the required ownership model: snapshot
`Connection::remote_id()` once, then accept one bidirectional stream per
logical request. Admission happens before dispatch. Resetting or cancelling
one stream must not close the shared connection; connection shutdown first
drains active streams and only then hard-cancels them. An upstream extraction
should therefore expose the per-connection loop (or a stream-dispatch hook),
not merely endpoint/ALPN registration.

## Remaining VGI work

The initial transport implementation now includes:

- wasm-bindgen node construction with ephemeral or persisted identity and
  default or custom relays;
- one application-owned endpoint shared across mux and HTTP;
- protocol-specific pooling with single-flight connection establishment;
- raw mux stream operations plus a WHATWG duplex-stream wrapper;
- streaming HTTP response bodies, duplicate header retention, an explicit raw
  representation flag, AbortSignal integration, and an optional application
  target resolver/authorizer;
- wasm-target Clippy and TypeScript wrapper checks in CI;
- generated wasm-bindgen runtime smoke coverage in system Chrome, Playwright
  Firefox, and Playwright WebKit.

A complete browser VGI release still needs:

- VGI HTTP request construction and Arrow IPC serialization/decoding.
- Response-body byte limits and explicit request deadlines/cancellation.
- VGI-aware stale-connection retry rules for provably idempotent calls. The
  transport itself never replays an ambiguous request.
- generated wasm-bindgen package publication and DuckDB/Haybarn integration.
- real release-Chrome, release-Firefox, and Apple Safari relay qualification
  against a deployed worker. The current cross-engine gate exercises generated
  bindings without relay traffic, and Playwright WebKit is not Apple Safari.
- Bundle-size, startup-time, and memory measurements.

Browser operation is client-only. A browser does not become a general
internet-facing Iroh HTTP server through this crate.
