# Cloud and trusted-proxy SPIFFE identity

The adapters in `auth::spiffe_proxy` produce transport identity evidence, not
authorization decisions. Every adapter requires an explicit set of allowed
SPIFFE trust domains and exact immediate-proxy IP addresses. Hostnames, CIDRs,
and source ranges are rejected. Keep the backend unreachable around the proxy,
and configure the proxy to replace or strip every identity header.

Evidence from these adapters has `ConfiguredProxy` assurance. A source address
is retained only as an attribute of the transport snapshot; it never becomes a
principal. Available identities always have one stable, verified workload
subject containing a canonical SPIFFE ID.

## Envoy

`envoy_xfcc_spiffe_provider` requires an adjacent Envoy that validates client
mTLS and uses `forward_client_cert_details: SANITIZE_SET` with URI details in
text XFCC format. The adapter requires one XFCC element, one allowed URI, and
one 64-hex SHA-256 `Hash`. Forwarded/append chains, unknown fields, duplicate
singletons, malformed escaping, and malformed percent encoding fail closed.

## nginx

With the `mtls-pem` Cargo feature, `nginx_spiffe_provider` consumes
`X-SSL-Client-Cert` from `$ssl_client_escaped_cert` and requires the exact
per-request signal `X-SSL-Client-Verify: SUCCESS`.

## AWS Application Load Balancer

With `mtls-pem`, `aws_alb_spiffe_provider` consumes
`X-Amzn-Mtls-Clientcert-Leaf`. Construct this provider only when the adjacent
ALB listener is configured in mTLS **verify** mode. ALB provides no independent
per-request verification boolean in that mode, so the selected provider,
exact proxy allowlist, and unreachable backend together are the configured
trust boundary. Passthrough mode is not supported.

## Google Cloud Application Load Balancer

`gcp_load_balancer_spiffe_provider` consumes custom headers mapped from
`client_cert_present`, `client_cert_chain_verified`,
`client_cert_spiffe_id`, and `client_cert_error`. It requires present and
chain-verified to equal `true`, an empty error, and one allowed canonical
SPIFFE ID. Header names are configurable but must be valid and
case-insensitively distinct.

## Azure

With `mtls-pem`, `azure_application_gateway_spiffe_provider` models Application
Gateway mTLS strict mode. Rewrite `client_certificate` and
`client_certificate_verification` into the adapter's default headers; the
verification value must be exactly `SUCCESS`.

Azure App Service's `X-ARR-ClientCert` is intentionally not an evidence
adapter. App Service forwards the certificate but leaves chain validation to
the application, so it cannot satisfy this provider's verified-proxy contract.
Use Application Gateway strict mode or an adjacent Envoy/nginx tier instead.

## Authentication diagnostics

Normal HTTP logs record only a fixed authentication failure class, never an
authenticator, provider, or peer-policy error message. A classified
`RpcError::auth_failure` detail is intentionally a public 401 wire message for
compatibility; application callbacks must therefore keep credentials,
certificate material, capability JSON, and library diagnostics out of it.
Unclassified and unavailable callback details are neither returned nor logged.
Rust's global panic hook runs before a provider task's join failure can be
redacted; deployments that execute untrusted extension callbacks must install
a production panic hook that does not print panic payloads.

## Certificate profile

Certificate-header adapters decode exactly one bounded URL-escaped PEM leaf
and validate its X.509-SVID profile: current validity, exactly one allowed URI
SAN, non-CA basic constraints, critical digital-signature key usage without CA
signing bits, and both client/server authentication when extended key usage is
present. This leaf validation complements rather than replaces the proxy's
certificate-chain validation.
