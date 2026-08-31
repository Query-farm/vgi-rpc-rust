# Tailscale identity evidence

`vgi-rpc` keeps connectivity, identity evidence, and authorization separate.
The adapters in this crate ask Tailscale for evidence; they do not join a
Tailnet, manage keys, invoke the `tailscale` CLI, cache identities, or define an
authorization language.

## HTTP behind Tailscale Serve

Build a strict header provider and add it to the existing HTTP identity
pipeline:

```rust,ignore
use vgi_rpc::{
    require_peer_identity, tailscale_serve_header_provider,
    TailscaleServeConfig,
};

let tailscale = tailscale_serve_header_provider(
    TailscaleServeConfig::new("tailnet:production", ["127.0.0.1"])?
)?;
let state = vgi_rpc::http::HttpState::builder()
    .server(server)
    .peer_identity_providers([tailscale])
    .peer_authentication_policy(require_peer_identity("tailscale"))
    .build();
```

The address list is an exact immediate-peer trust boundary. A request from any
other address is `untrusted_proxy`; VGI never accepts `Tailscale-*` headers from
it. Keep the worker backend unreachable except through that proxy. Trusting
loopback also trusts any local process able to connect to the backend, so it is
an operator decision, not an implicit default.

The provider rejects duplicate headers, Funnel, malformed or control-bearing
RFC 2047 values, duplicate JSON keys, malformed capabilities, non-finite
numbers, JSON over 64 KiB, depth over 16, and more than 4096 JSON values.
Serve's user login has `configured_proxy` assurance and login stability; it is
not accepted by the built-in stable-subject primary authenticator. Capability-
only evidence is available but subjectless. An application that deliberately
uses a Serve login as its primary identity must express that opt-in in its own
authentication policy.

## Direct Tailscale LocalAPI WhoIs

The LocalAPI provider defaults to the tailscaled Unix socket:

```rust,ignore
use vgi_rpc::{
    peer_identity_primary, tailscale_localapi_provider,
    TailscaleLocalApiConfig,
};

let tailscale = tailscale_localapi_provider(
    TailscaleLocalApiConfig::new("tailnet:production")?
)?;
let state = vgi_rpc::http::HttpState::builder()
    .server(server)
    .peer_identity_providers([tailscale])
    .peer_authentication_policy(peer_identity_primary("tailscale"))
    .peer_service_name("svc:vgi-workers")
    .build();
```

For containers or a supported macOS LocalAPI endpoint, configure a direct HTTP
origin with `with_http_endpoint` and, when required, `with_password`. The
adapter uses direct sockets and ignores process proxy variables. It sends
`Host: local-tailscaled.sock`, scopes WhoIs with `svc_name` when configured or
`dst_ip` otherwise, applies one monotonic provider/request deadline, bounds
headers and bodies, and performs a fresh lookup for every request.

Untagged peers use `user:<numeric-user-id>` as the stable subject. Tagged peers
ignore `UserProfile` and use `node:<StableNodeID>`. Tags and node names remain
attributes. Permission, no-match, unavailable, and malformed-response outcomes
remain distinct provider statuses. WhoIs uses the full source endpoint for its
fresh lookup, but evidence retains at most its normalized IP for audit; source
ports are never part of a principal or state-binding digest.

`any_of_peer_identities` leaves peer evidence observation-only when existing
application authentication wins. Use `require_peer_identity`, `all_of`, or a
custom policy when both factors must be present and bound into resumable state.

Provider timeout, capacity exhaustion, and a typed authority-unavailable error
become that named provider's `unavailable` result. Observation and a valid
application factor in `any_of` may continue; invalid/untrusted evidence still
rejects, while required and peer-primary policies return HTTP 503. Provider
exception detail is replaced with fixed class/provider text before normal
logging so daemon tokens, capabilities, and certificate text cannot leak.

The current HTTP integration does not receive the listener's local socket
address from Axum's per-request connection metadata. Configure
`peer_service_name` for destination-scoped LocalAPI capabilities. Without it,
HTTP WhoIs is deliberately node-scoped; the untrusted HTTP `Host` authority is
never promoted to `dst_ip`. Raw TCP does capture its actual or PROXY-asserted
destination endpoint.

## Raw TCP behind a Tailscale Service or load balancer

Use the additive identity-aware entry point; existing `serve_tcp` callers stay
source-compatible and anonymous:

```rust,ignore
use std::{collections::BTreeSet, sync::Arc};
use vgi_rpc::{peer_identity_primary, tailscale_localapi_provider};
use vgi_rpc::tcp::{serve_tcp_with_identity, TcpIdentityOptions};

let options = TcpIdentityOptions {
    proxy_protocol_v2_required: true,
    trusted_proxy_addresses: BTreeSet::from(["127.0.0.1".parse()?]),
    service_name: Some("svc:vgi-workers".into()),
    providers: Arc::from([tailscale_localapi_provider(localapi_config)?]),
    policy: Some(peer_identity_primary("tailscale")),
    ..TcpIdentityOptions::default()
};
serve_tcp_with_identity(server, "127.0.0.1", 9400, None, shutdown, options,
    |host, port| println!("TCP:{host}:{port}"))?;
```

Before reading one PROXY byte, VGI compares the accepted socket's normalized
immediate IP with the exact trust set. Only PROXY v2 `PROXY` commands carrying
TCP over IPv4 or IPv6 are accepted; `LOCAL`, `UNSPEC`, UDP, Unix addresses,
truncation, malformed TLVs, and oversized preambles fail closed. Unknown TLVs
are bounded and skipped. IPv4-mapped IPv6 is normalized, and bytes following
the declared header remain untouched for the VGI Arrow framing reader.

The preamble has its own short total deadline. Identity resolution has a
separate total monotonic deadline and globally bounded lingering-task capacity.
Each raw provider is named, so timeout, capacity, and a typed authority outage
become that provider's `unavailable` result just as they do for HTTP. This lets
observation or a prevalidated `application_auth` factor in `any_of` continue;
required/primary policies still fail connection setup. Invalid or untrusted
peer evidence is evaluated before application fallback and always rejects.
The resulting `ConnectionContext` is immutable and reused for every VGI call on
that byte stream. This is a connection identity snapshot, not a per-call WhoIs
lookup.

Raw TCP accepts an already-resolved `application_auth` snapshot; it does not
run an application credential callback during connection setup. The owner of
that snapshot must reject invalid credentials before calling VGI. Consequently
there is no internal raw-TCP "invalid application credential" branch to fall
back from, unlike the HTTP authentication pipeline.
