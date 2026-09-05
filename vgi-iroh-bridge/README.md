# vgi-iroh-bridge

This is a narrow transport bridge, not a service load balancer.

For `vgi-rpc/arrow-mux/1`, each authenticated Iroh bidirectional stream opens
one TCP or Unix-domain connection to one configured upstream VGI worker. The
bridge writes the canonical VGI Iroh PROXY-v2 identity preamble before copying
bytes in both directions. Stream failure cannot migrate or replay state on a
different worker.

The upstream listener must require PROXY v2, explicitly enable Iroh forwarding,
trust only the bridge's exact immediate address, and choose its own stable
issuer. The bridge forwards the raw cryptographic EndpointId but never forwards
an issuer or authorization decision.

HTTP support is intentionally added only through iroh-http's shared
already-negotiated connection loop. VGI will not carry a forked copy of that
loop because doing so would duplicate its peer identity, header/body bounds,
slowloris, middleware, request tracking, and drain invariants.

## HTTP bridge

`HttpBridgeProtocol` accepts `iroh-http/2` and streams each HTTP request through
a pooled Hyper client to one fixed HTTP or HTTPS origin and optional base path:

```rust,ignore
use vgi_iroh_bridge::{
    HttpBridgeOptions, HttpBridgeProtocol, RawBridgeOptions, RawBridgeProtocol,
    RawUpstream, IROH_HTTP_ALPN, VGI_IROH_ALPN,
};

let raw = RawBridgeProtocol::new(raw_upstream, RawBridgeOptions::default())?;
let http = HttpBridgeProtocol::new(
    "https://worker.internal.example/vgi",
    HttpBridgeOptions::default(),
)?;

let router = iroh::protocol::Router::builder(endpoint)
    .accept(VGI_IROH_ALPN, raw)
    .accept(IROH_HTTP_ALPN, http)
    .spawn();
```

The crate also installs a `vgi-iroh-bridge` executable for the common
standalone deployment:

```sh
vgi-iroh-bridge \
  --secret-key-file /run/secrets/vgi-iroh-key \
  --raw-upstream tcp://worker.internal:9400 \
  --http-upstream https://workers.internal.example/vgi
```

Tagged releases provide executable archives for Linux (x86-64 and ARM64),
macOS (x86-64 and Apple Silicon), and Windows x86-64. Production containers
are published for Linux x86-64 and ARM64 as
`ghcr.io/query-farm/vgi-iroh-bridge:<version>` and
`ghcr.io/query-farm/vgi-iroh-bridge:latest`. For example:

```sh
docker run --rm --network host \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD/vgi-iroh-key",dst=/run/secrets/vgi-iroh-key,readonly \
  ghcr.io/query-farm/vgi-iroh-bridge:0.24.3 \
  --secret-key-file /run/secrets/vgi-iroh-key \
  --http-upstream http://127.0.0.1:9400
```

The container runs as numeric user/group `65532:65532`; the mounted key must
be readable by that identity. Host networking is only an example for a worker
bound to host loopback. In an orchestrated deployment, place the bridge and
worker on a private network and use the worker service name instead.

The first stdout line is the bridge EndpointId. A persistent key is required
from `--secret-key-file` or `VGI_IROH_SECRET_KEY`; `--ephemeral` is an explicit
development-only alternative. The key itself is never accepted as a command
line argument. Repeated `--relay-url` values replace the default relay set,
and `--no-relay` selects direct paths only. `SIGINT` and, on Unix, `SIGTERM`
stop the Router, which in turn drains both protocol handlers within their
configured bounds.

Raw and HTTP connection admission, concurrency, request-head progress,
request-body progress, headers, idle connections, and graceful drain have safe
defaults. The executable exposes scoped `--raw-*` and `--http-*` overrides
(see `--help`); an override is rejected unless its corresponding upstream is
enabled, and zero is never accepted. HTTP remains a transparent hop: request
decompression is disabled even when other limits are customized.
Raw connections default to 8 per EndpointId and 256 total; after their first
stream they are closed after 60 seconds with no active logical streams and no
new stream. An active stream is intentionally never expired by this
connection-level idle timer. It remains open until the peer or upstream
completes it, admission rejects it, or the bridge's drain deadline expires
during shutdown. These limits prevent one authenticated but unauthorized peer
from occupying the bridge before worker-level policy can inspect a forwarded
request.

Raw `tcp://` destinations accept IP literals or DNS names, so the one fixed
destination may be an internal Envoy/nginx stream listener or cloud network
load-balancer name. DNS resolution is part of the upstream connect deadline;
it does not make the bridge a load balancer.

For an upstream base ending in `/vgi`, an incoming `/catalog?limit=1` target
becomes `/vgi/catalog?limit=1`. The configured authority always replaces the
incoming URI authority and `Host`. HTTPS validates the configured hostname
against the public WebPKI root set.

This remains a bridge, not a load balancer: it has one configured origin, does
not follow redirects, and does not replay a request. Hyper connection pooling
only reuses transport connections to that origin. The shared iroh-http runtime
owns connection-wide admission, request-head and body-progress slowloris
defense, optional coarse body ceilings, delivery tracking, and graceful drain.
Request and response bodies remain streaming and are never collected by the
bridge.

`HttpBridgeOptions::default()` disables request decompression. Consequently
`Content-Encoding` and the encoded body pass to the fixed upstream unchanged,
which is the safe transparent-proxy behavior. An embedding application may
explicitly enable decompression when the upstream expects decoded application
bodies rather than HTTP forwarding semantics.

There is no implicit request-size ceiling in the transparent bridge. The VGI
worker owns its semantic request limit and advertises it via `OPTIONS`.
Operators that need an independent transport ceiling can set
`--http-max-request-body-bytes`; they should keep it at or above the worker's
advertised value. The bridge counts bytes while forwarding and does not buffer
the complete body. `--http-request-head-timeout` and
`--http-body-idle-timeout` tune progress protection independently of the
optional `--http-request-timeout` application deadline.

### Identity and header boundary

The bridge obtains `RemoteEndpointId` directly from the authenticated Iroh
connection and encodes its raw 32 bytes as exactly 64 lowercase hexadecimal
characters. It never decodes the compatible RFC 4648 display identity. Before
dispatch it removes every client-provided `VGI-Forwarded-Iroh-Endpoint` value
and injects exactly one verified value.

On requests and responses the bridge removes standard hop-by-hop headers and
every header nominated by `Connection`. It rewrites `Host` and preserves all
duplicate end-to-end fields, including `Set-Cookie`. Upstream failures return a
generic `502 Bad Gateway`; the response never contains the caller identity or
the upstream error. The header is identity evidence, not an authorization
decision: the worker still selects an issuer, trusted immediate proxy, and
authorization policy.

The safest deployment connects the bridge directly to a loopback or private
worker listener that trusts only the bridge's exact address. If Envoy, nginx,
an AWS/GCP/Azure load balancer, or another intermediary sits between them:

- isolate its bridge-facing listener so untrusted traffic cannot reach it;
- authenticate or exact-address allowlist the bridge-to-intermediary hop;
- preserve exactly one bridge identity value while clearing this header on
  every other listener/route;
- apply ordinary hop-by-hop and `Connection`-nominated header sanitization;
- configure the worker to trust only that intermediary's exact immediate
  address, not the wider network or client-supplied forwarding headers.

Do not share a public listener that blindly forwards
`VGI-Forwarded-Iroh-Endpoint`. A generic cloud load balancer does not turn this
header into cryptographic evidence by itself.

## Upstream dependency

The bridge consumes the released `query-farm-iroh-http-core` crate under the
conventional Rust alias `iroh-http-core`. `Cargo.lock` fixes the exact release
used by bridge binaries and containers; update the declared version and lock
together after the fork's CI and this bridge's compatibility tests pass.
