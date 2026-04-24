# vgi-rpc

[![crates.io](https://img.shields.io/crates/v/vgi-rpc.svg)](https://crates.io/crates/vgi-rpc)
[![docs.rs](https://docs.rs/vgi-rpc/badge.svg)](https://docs.rs/vgi-rpc)

Rust library for the [`vgi-rpc`](https://github.com/Query-farm/vgi-rpc)
transport-agnostic RPC framework built on Apache Arrow IPC. Compatible
byte-for-byte with the Python canonical implementation and the Go port
— this crate passes the complete Python conformance suite across pipe,
subprocess, HTTP, and unix-socket transports.

## Highlights

- **Server-side dispatch** for unary, producer, and exchange stream
  methods over stdio / Unix socket / HTTP.
- **Introspection** via the built-in `__describe__` method
  (`DESCRIBE_VERSION = "3"`).
- **HTTP surface** — axum-backed server with HMAC-signed stream state
  tokens, CORS + preflight, zstd request/response compression,
  configurable URL prefix, landing / describe / health pages, session
  TTL + reaper, RFC 9728 Protected Resource Metadata.
- **Auth** — bearer, mTLS via RFC 8705 `x-forwarded-client-cert`,
  OAuth 2 Protected Resource Metadata; JWKS-backed JWT and OAuth2 PKCE
  primitives behind Cargo features.
- **Observability** — `DispatchHook` + `CallStatistics`, structured
  access logs, OTel-style spans + metrics, Sentry-compatible
  `tracing::error!` events.
- **External locations** — transparent upload of oversized batches to
  pluggable `ExternalStorage` backends (`vgi-rpc-s3` /
  `vgi-rpc-gcs`) with SHA-256 integrity + optional zstd.
- **Graceful shutdown** on SIGTERM / SIGINT for both HTTP and Unix
  listeners.

## Cargo features

| feature | default | enables |
|---------|:-:|---------|
| `http`  | ✅ | Axum HTTP server + external-location helpers. |
| `jwt`   |   | `auth::jwt::jwt_authenticate_with` with JWKS cache + pluggable verifier. |
| `oauth-pkce` |   | `auth::pkce` crypto primitives. |
| `mtls-pem`   |   | Reserved for PEM-based mTLS helpers. |
| `otel`  |   | `otel::OtelHook` — `tracing` spans + in-memory counters. |
| `sentry` |  | `sentry::SentryHook` — structured `tracing::error!` events. |

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
    RpcServer, RpcServerBuilder, MethodInfo, MethodType, CallContext,
    AuthContext, AuthRequest, Authenticate, chain_authenticate,
    DispatchHook, DispatchInfo, CallStatistics, ChainHook,
    AccessLogHook, RetryConfig,
    LogLevel, LogMessage, RpcError, Result,
    DESCRIBE_METHOD_NAME, DESCRIBE_VERSION,
};

// Feature-gated modules:
use vgi_rpc::auth::bearer::bearer_authenticate;            // always on
use vgi_rpc::auth::mtls::mtls_authenticate_fingerprint;    // always on
use vgi_rpc::auth::oauth::OAuthResourceMetadata;            // always on
use vgi_rpc::http::{HttpState, HttpStateBuilder, build_router};  // "http"
use vgi_rpc::external::{ExternalLocationConfig, Compression};    // "http"
// use vgi_rpc::auth::jwt::jwt_authenticate_with;          // "jwt"
// use vgi_rpc::auth::pkce::generate_pkce_pair;             // "oauth-pkce"
// use vgi_rpc::otel::OtelHook;                             // "otel"
// use vgi_rpc::sentry::SentryHook;                         // "sentry"
```

## Interoperability notes

The wire protocol matches Python's `vgi_rpc` canonical:

- Pointer-batch schema is empty; location metadata is the payload.
- `__describe__` version is `"3"`; `method_type` collapses Producer /
  Exchange / Dynamic into `"stream"`.
- Access log records carry `logger: "vgi_rpc.access"` and validate
  cleanly against Python's `vgi_rpc.access_log_conformance` tool.
- Pyarrow's default nullability (`list` inner / `map` values / dynamic
  schema fields = `nullable=true`) is honored.

## License

Apache-2.0.
