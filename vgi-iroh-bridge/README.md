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

The first stdout line is the bridge EndpointId. A persistent key is required
from `--secret-key-file` or `VGI_IROH_SECRET_KEY`; `--ephemeral` is an explicit
development-only alternative. The key itself is never accepted as a command
line argument. Repeated `--relay-url` values replace the default relay set,
and `--no-relay` selects direct paths only. `SIGINT` stops the Router, which in
turn drains both protocol handlers within their configured bounds.

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
owns connection-wide admission, request/header/body limits, slowloris defense,
delivery tracking, and graceful drain.

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

## Temporary upstream dependency

Development currently points `iroh-http-core` at the local
`projects/iroh-http-upstream-feasibility` checkout so the negotiated-connection
API can be tested before upstream publication. This local path is a merge and
release blocker. Replace it with the pushed immutable Git commit SHA (and
update `Cargo.lock`) before merging or releasing this workspace.
