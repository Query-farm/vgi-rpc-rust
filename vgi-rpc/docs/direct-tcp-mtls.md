# Direct TCP mutual-TLS SPIFFE identity

Enable `tcp-mtls` to serve the raw stateful VGI protocol with mandatory client
certificates. `TcpMutualTlsConfig::new` accepts the server DER chain/key,
dedicated client trust roots, and explicit SPIFFE trust domains. It constructs
the rustls verifier internally, so an optional-client-auth or accept-any
verifier cannot be substituted accidentally.

Use `serve_tcp_with_mtls_identity`. The TLS handshake verifies the client chain
and proof of private-key possession before VGI reads a frame. The leaf must
also satisfy the strict current X.509-SVID profile: exactly one canonical URI
SAN in an allowed trust domain, non-CA basic constraints, critical digital
signature usage without CA signing bits, and both client/server authentication
when extended key usage is present.

```rust,ignore
use std::{sync::Arc, time::Duration};
use vgi_rpc::{peer_identity_primary, tcp::{
    serve_tcp_with_mtls_identity, TcpIdentityOptions, TcpMutualTlsConfig,
    TcpMutualTlsOptions,
}};

// Load these rustls DER types from the deployment's secret/certificate store.
let tls = TcpMutualTlsConfig::new(
    server_certificate_chain,
    server_private_key,
    client_root_store,
    ["prod.example.org"],
)?.with_handshake_timeout(Duration::from_secs(5))?;
let identity = TcpIdentityOptions {
    policy: Some(peer_identity_primary("spiffe")),
    ..TcpIdentityOptions::default()
};
serve_tcp_with_mtls_identity(
    server, "127.0.0.1", 9400, None, shutdown,
    TcpMutualTlsOptions::new(tls).with_identity(identity),
    |host, port| println!("TCP:{host}:{port}"),
)?;
```

The handshake creates provider `spiffe`, evidence source `direct_tls`,
`cryptographic_peer` assurance, and a stable workload subject. Evidence alone
does not authenticate an RPC. Configure `peer_identity_primary("spiffe")`,
`require_peer_identity`, `all_of`, or a custom policy explicitly.

When PROXY v2 is required, the exact configured immediate proxy is checked and
the bounded preamble is consumed before the first TLS byte. One monotonic TLS
handshake deadline covers both phases. TLS and additional provider evidence
are combined into one immutable connection snapshot; another provider named
`spiffe` is rejected as a duplicate. Network addresses are audit/routing data,
never principals or state-binding inputs.

The existing blocking raw-TCP client stores independent concrete socket read
and write halves, while rustls requires shared connection state. This change
does not silently retrofit that client or invent a new transport abstraction;
use a TLS-capable custom `Transport` until an explicit client-side API is
introduced.
