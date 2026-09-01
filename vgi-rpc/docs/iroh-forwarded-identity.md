# Forwarded Iroh identity

An Iroh bridge authenticates the remote EndpointId cryptographically and then
forwards that evidence to an ordinary VGI worker. The worker owns the issuer
namespace and authorization policy; neither is accepted from the bridge.

Forwarded evidence has `ConfiguredProxy` assurance because the worker directly
authenticates only its adjacent bridge hop. The attribute
`original_assurance=cryptographic_peer` preserves that the bridge verified the
Iroh peer. The stable subject is exactly the raw EndpointId rendered as 64
lowercase hexadecimal characters.

## Raw TCP bridge

Configure the ordinary identity-aware TCP worker:

```rust,ignore
use std::{collections::BTreeSet, sync::Arc};
use vgi_rpc::peer_identity_primary;
use vgi_rpc::tcp::{serve_tcp_with_identity, TcpIdentityOptions};

let options = TcpIdentityOptions {
    proxy_protocol_v2_required: true,
    trusted_proxy_addresses: BTreeSet::from(["127.0.0.1".parse()?]),
    iroh_proxy_issuer: Some("iroh:production".into()),
    policy: Some(peer_identity_primary("iroh")),
    ..TcpIdentityOptions::default()
};
serve_tcp_with_identity(server, "127.0.0.1", 9400, None, shutdown, options,
    |host, port| println!("TCP:{host}:{port}"))?;
```

`iroh_proxy_issuer` is an explicit opt-in and requires required PROXY v2 plus
at least one exact trusted immediate IP. Before consuming any preamble byte,
the listener checks that immediate peer. Keep the worker unreachable except
through the trusted bridge.

The canonical preamble is PROXY v2 command `PROXY`, family/protocol `UNSPEC`,
and exactly one identity TLV of type `0xE0`. Its fixed 33-byte value is version
byte `1` followed by the 32 raw EndpointId bytes. Missing, duplicate,
wrong-version, wrong-size, and IP-family identity TLVs fail closed. Other
bounded structurally valid TLVs remain extensions and never become identity.

The ordinary `parse_proxy_protocol_v2` and `read_proxy_protocol_v2` functions
remain strict TCP-over-IPv4/IPv6 parsers. Only the dedicated
`*_with_options` functions with `allow_iroh_identity=true` accept the Iroh
`PROXY/UNSPEC` form. No synthetic source IP is created, and bytes following
the declared preamble remain available to the VGI Arrow reader.

## HTTP bridge

For an HTTP bridge, register the strict header provider in the existing worker
identity pipeline:

```rust,ignore
use vgi_rpc::{
    iroh_forwarded_header_provider, peer_identity_primary,
    IrohForwardedHeaderConfig,
};

let iroh = iroh_forwarded_header_provider(
    IrohForwardedHeaderConfig::new("iroh:production", ["127.0.0.1"])?
)?;
let state = vgi_rpc::http::HttpState::builder()
    .server(server)
    .peer_identity_providers([iroh])
    .peer_authentication_policy(peer_identity_primary("iroh"))
    .build();
```

The provider consumes one `VGI-Forwarded-Iroh-Endpoint` header only after the
exact immediate-peer IP check. The bridge must replace or strip any
client-supplied copy before setting its own. Missing evidence is `no_match`;
an untrusted peer is `untrusted_proxy`; uppercase, non-64-hex, duplicate,
case-varied duplicate, or control-bearing values fail closed as invalid input.
