<div align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi-rpc-rust/main/assets/vgi-logo.png" alt="Vector Gateway Interface" width="320">
</div>

# vgi-rpc

[![crates.io](https://img.shields.io/crates/v/vgi-rpc.svg)](https://crates.io/crates/vgi-rpc)
[![docs.rs](https://docs.rs/vgi-rpc/badge.svg)](https://docs.rs/vgi-rpc)

Rust library for the
[`vgi-rpc`](https://github.com/Query-farm/vgi-rpc) transport-agnostic
RPC framework built on Apache Arrow IPC. Byte-for-byte wire-compatible
with the Python canonical implementation and the Go port — this crate
passes the **complete 868-test Python conformance suite** across
pipe, subprocess, HTTP, Unix-socket, externalised-upload, and
shared-memory pipe transports.

Stock `arrow-rs` 59.x dependency tree, MSRV 1.97, no
`[patch.crates-io]` required.

## Highlights

- **Server-side dispatch** for unary, producer, and exchange stream
  methods over stdio / Unix socket / HTTP / shared memory.
- **Introspection** via the built-in `__describe__` method
  (`DESCRIBE_VERSION = "4"`, slim wire format plus `protocol_hash`).
- **HTTP surface** — axum-backed server with HMAC-signed stateless
  stream-state tokens, CORS + preflight, zstd request/response
  compression, configurable URL prefix, landing / describe / health
  pages, RFC 9728 Protected Resource Metadata, configurable response
  / externalised-response caps.
- **Auth** — bearer (constant-time compare), mTLS via RFC 8705
  `x-forwarded-client-cert`, OAuth 2 Protected Resource Metadata;
  JWKS-backed JWT (single-flight refresh) and OAuth 2 PKCE
  primitives behind Cargo features.
- **Observability** — `DispatchHook` + `CallStatistics`,
  schema-validated structured access logs, real `tracing::Span`
  emission for `tracing-opentelemetry`, two-tier Sentry integration
  (tracing-only or full SDK).
- **Lifecycle** — `TransportKind` + `on_serve_start` hook so workers
  can tailor startup work to the bound transport (pipe / HTTP / unix
  / shared-memory).
- **External locations** — transparent upload of oversized batches to
  pluggable `ExternalStorage` backends (`vgi-rpc-s3` /
  `vgi-rpc-gcs`), SHA-256 integrity, optional zstd, post-decompression
  size cap.
- **DoS-resilience by construction** — wire reader rejects
  oversized IPC schema length prefixes (`MAX_IPC_SCHEMA_BYTES = 16 MiB`)
  and per-message flatbuffer `bodyLength` (`MAX_IPC_MESSAGE_BYTES =
  256 MiB`) **before** allocating, blocking the trivial 4-byte and
  50-byte OOM payloads `fuzz/wire_stream_reader` discovered.
- **Graceful shutdown** on SIGTERM / SIGINT for both HTTP and Unix
  listeners.

## Cargo features

| feature | default | enables |
|---------|:-:|---------|
| `http`  | ✅ | Axum HTTP server + external-location helpers + stream-state tokens. |
| `macros` | ✅ | `#[service]`, `#[unary]`, `#[producer]`, `#[exchange]`, `#[derive(VgiArrow)]`, `#[derive(StreamState)]`. |
| `jwt` |  | `JwtConfig` / `Jwks` types only — bring your own verifier. |
| `jwt-jsonwebtoken` |  | Bundled JWT verifier (`jsonwebtoken` + `reqwest` JWKS fetcher). |
| `oauth-pkce` |  | `auth::pkce` cookie + verifier crypto primitives. |
| `oauth-pkce-server` |  | OAuth 2 PKCE server-side redirect / token-exchange (`reqwest`). |
| `mtls-pem` |  | PEM-cert parsing helpers (`x509-parser`). XFCC parsing is always on. |
| — |  | `auth::proof` (proxy proof) ships with `http`; no extra dependency. See `docs/proxy-proof-spec.md` in vgi-rpc. |
| `otel` |  | `OtelHook` — real `tracing::Span` per RPC for `tracing-opentelemetry`. |
| `sentry-tracing` |  | `TracingSentryHook` — lightweight, no extra deps. |
| `sentry-sdk` |  | `SentrySdkHook` — full Sentry SDK integration (`sentry` 0.46). |
| `shm` |  | POSIX shared-memory transport (zero-copy producer / exchange). |
| `test-utils` |  | `external::InMemoryStorage` fixture for downstream tests. |

## Minimal example

```rust,no_run
use std::sync::Arc;
use arrow_schema::{DataType, Field, Schema};
use arrow_array::{RecordBatch, StringArray};
use vgi_rpc::{MethodInfo, RpcServer};
use vgi_rpc::http::HttpState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params_schema: Arc<Schema> =
        Arc::new(Schema::new(vec![Field::new("value", DataType::Utf8, false)]));
    let result_schema: Arc<Schema> =
        Arc::new(Schema::new(vec![Field::new("result", DataType::Utf8, false)]));

    let mut srv = RpcServer::builder()
        .protocol_name("Echo")
        .enable_describe(true)
        .build();

    let rs = result_schema.clone();
    srv.register(
        MethodInfo::unary("echo", params_schema, result_schema.clone(), move |req, _ctx| {
            let col = req.column("value").unwrap()
                .as_any().downcast_ref::<StringArray>().unwrap();
            Ok(Some(RecordBatch::try_new(
                rs.clone(),
                vec![Arc::new(StringArray::from(vec![col.value(0).to_string()]))],
            )?))
        })
        .doc("Echo a string")
        .param_type("value", "str"),
    );

    let state = HttpState::builder()
        .server(Arc::new(srv))
        .cors_origins("*")
        .response_compression_level(3)
        .build();
    let app = vgi_rpc::http::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Public surface cheat sheet

```rust
use vgi_rpc::{
    // Core
    RpcServer, RpcServerBuilder, MethodInfo, MethodType, CallContext, Request,
    AuthContext, AuthRequest, Authenticate, chain_authenticate, chain_all,
    OAuthResourceMetadata,
    DispatchHook, DispatchInfo, CallStatistics, ChainHook, SharedHook,
    AccessLogHook, RetryConfig,
    LogLevel, LogMessage, RpcError, Result,
    DESCRIBE_METHOD_NAME, DESCRIBE_VERSION,
    // Transport lifecycle
    TransportKind, TransportCapabilities, ServeStartHook,
    // Stream state (for hand-written stream handlers; macros generate these for you)
    ExchangeState, OutputCollector, ProducerState, StreamResult,
};

// Feature-gated:
use vgi_rpc::auth::bearer::bearer_authenticate_static;      // always on
use vgi_rpc::auth::mtls::mtls_authenticate_fingerprint;     // always on
use vgi_rpc::auth::proof::proof_authenticate;               // feature `http`
use vgi_rpc::http::{HttpState, HttpStateBuilder};            // "http"
use vgi_rpc::external::{ExternalLocationConfig, Compression}; // "http"
// use vgi_rpc::auth::jwt::jwt_authenticate;                 // "jwt"
// use vgi_rpc::auth::pkce::generate_pkce_pair;               // "oauth-pkce"
// use vgi_rpc::{OtelConfig, OtelHook, OtelMetrics};         // "otel"
// use vgi_rpc::{TracingSentryConfig, TracingSentryHook};    // "sentry-tracing"
// use vgi_rpc::{SentrySdkConfig, SentrySdkHook};            // "sentry-sdk"
```

## Macros (default-on `macros` feature)

```rust,ignore
use std::sync::Arc;
use vgi_rpc::{service, unary, RpcServer, Result};

pub struct Calc;

#[service]
impl Calc {
    /// Echo a string back, prefixed.
    #[unary]
    fn echo(&self, value: String) -> Result<String> {
        Ok(format!("echo: {value}"))
    }
}

let mut srv = RpcServer::builder().protocol_name("Calc").build();
Calc::register_with(&mut srv, Arc::new(Calc));
```

`#[derive(VgiArrow)]` derives a struct's Arrow `Struct<fields>` data
type for any field that itself implements `VgiArrow` (mirroring
Python's `ArrowSerializableDataclass`). `#[derive(StreamState)]`
auto-impls `StreamStateCodec` (bincode) on stream-state types.

## Interoperability notes

The wire protocol matches Python's `vgi_rpc` canonical:

- Pointer-batch schema is empty; location metadata is the payload.
- `__describe__` version is `"4"`; `method_type` collapses Producer /
  Exchange / Dynamic into `"stream"`. The describe response carries a
  `protocol_hash` SHA-256 digest computed identically to Python's
  algorithm.
- Access log records carry `logger: "vgi_rpc.access"` and validate
  cleanly against Python's `vgi_rpc.access_log_conformance` JSON
  Schema. `request_data` is truncated at INFO level (replaced with
  `original_request_bytes` + `truncated: true`) — opt in via
  `AccessLogHook::with_verbose(true)` to get full payloads.
- HTTP stream-state tokens are HMAC-SHA256-signed (token format v3,
  identical byte layout to Python's `_state_token.py`); set an
  explicit signing key with `HttpStateBuilder::signing_key_*` so
  tokens survive across worker restarts and load balancing.
- Pyarrow's default nullability (`list` inner / `map` values / dynamic
  schema fields = `nullable=true`) is honored.

## License

Apache-2.0.
