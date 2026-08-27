<p align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi-rpc-rust/main/assets/vgi-logo.png" alt="Vector Gateway Interface logo" width="320">
</p>

<h1 align="center">vgi-rpc (Rust)</h1>

<p align="center">
  Transport-agnostic RPC framework built on <a href="https://arrow.apache.org/">Apache Arrow</a> IPC serialization — the Rust port of <a href="https://github.com/Query-farm/vgi-rpc-python">vgi-rpc</a>.<br>
  Built by <a href="https://query.farm">🚜 Query.Farm</a>
</p>

<p align="center">
  <a href="https://github.com/Query-farm/vgi-rpc-rust/actions/workflows/ci.yml"><img src="https://github.com/Query-farm/vgi-rpc-rust/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/vgi-rpc"><img src="https://img.shields.io/crates/v/vgi-rpc" alt="crates.io"></a>
  <a href="https://crates.io/crates/vgi-rpc"><img src="https://img.shields.io/crates/d/vgi-rpc" alt="crates.io downloads"></a>
  <a href="https://docs.rs/vgi-rpc"><img src="https://img.shields.io/docsrs/vgi-rpc" alt="docs.rs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
</p>

Transport-agnostic RPC framework built on Apache Arrow IPC. The Rust
implementation tracks the Python canonical
[`vgi-rpc`](https://github.com/Query-farm/vgi-rpc) byte-for-byte on
the wire, so Python / Go / Rust clients and servers all interoperate.

```
┌────────────────────────┐  stdio │ unix │ http                 ┌────────────────────────┐
│  any vgi-rpc client    │◀───────────────────────────────────▶│  vgi-rpc Rust server   │
│ (Python / Go / Rust)   │    Arrow IPC + signed state tokens   │   (this repo)          │
└────────────────────────┘                                      └────────────────────────┘
```

**Status.** 901 / 901 Python conformance tests pass across pipe,
subprocess, http, and unix transports. 250 Rust-native unit +
integration tests pass with all features enabled. Workspace-wide
`cargo clippy --all-features -- -D warnings` is clean.

---

## Workspace layout

| crate | summary |
|-------|---------|
| `vgi-rpc/` | Library. Wire protocol, server dispatch, HTTP, auth, observability, external locations, introspection. |
| `conformance-worker/` | Binary `vgi-rpc-conformance-rust` — registers the full Python `ConformanceService` and serves stdio / `--http` / `--unix`. Drives the conformance test harness. |
| `vgi-rpc-s3/` | `PresignedS3Storage` + shared `HttpFetcher` for the external-location flow. |
| `vgi-rpc-gcs/` | `SignedGcsStorage` for Google Cloud Storage V4 signed URLs. |
| `scripts/conf.py` | Python test-runner wrapper around the conformance suite. |

## Feature matrix

The main `vgi-rpc` crate exposes these Cargo features:

| feature | default | what it turns on |
|---------|:-:|------------------|
| `http`  | ✅ | `axum` HTTP server, zstd, HMAC stream tokens, external-location helpers. |
| `jwt`   |   | `auth::jwt::jwt_authenticate_with` — JWKS caching + verifier hook. |
| `oauth-pkce` |   | `auth::pkce::{generate_pkce_pair, new_state_cookie, verify_state_cookie}`. |
| `mtls-pem`   |   | Reserved for PEM-based mTLS helpers. |
| `otel`  |   | `otel::OtelHook` tracing+metrics `DispatchHook`. |
| `sentry` |  | `sentry::SentryHook` adapter that emits tagged `tracing::error!` events. |

## Quick start (server)

```rust
use std::sync::Arc;
use arrow_schema::{DataType, Field, Schema};
use vgi_rpc::{MethodInfo, RpcServer};
use vgi_rpc::http::HttpState;

#[tokio::main]
async fn main() {
    let mut srv = RpcServer::builder()
        .server_id("my-server-1")
        .protocol_name("MyService")
        .server_version(env!("CARGO_PKG_VERSION"))
        .enable_describe(true)
        .build();

    let result_schema: Arc<Schema> = Arc::new(Schema::new(vec![
        Field::new("result", DataType::Utf8, false),
    ]));
    let params_schema: Arc<Schema> = Arc::new(Schema::new(vec![
        Field::new("value", DataType::Utf8, false),
    ]));

    srv.register(
        MethodInfo::unary("echo", params_schema, result_schema.clone(),
            |req, _ctx| {
                use arrow_array::StringArray;
                let arr = req.column("value").unwrap()
                    .as_any().downcast_ref::<StringArray>().unwrap();
                Ok(Some(arrow_array::RecordBatch::try_new(
                    result_schema.clone(),
                    vec![Arc::new(StringArray::from(vec![arr.value(0).to_string()]))],
                )?))
            },
        )
        .doc("Echo a string")
        .param_type("value", "str"),
    );

    // zstd response compression is on by default (level 1); override with
    // `.response_compression_level(n)` or turn it off with
    // `.disable_response_compression()`.
    let state = HttpState::builder()
        .server(Arc::new(srv))
        .cors_origins("*")
        .build();
    let app = vgi_rpc::http::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## Running conformance tests

Requires the Python `vgi-rpc` package. By default `scripts/conf.py`
looks for it at `~/Development/vgi-rpc/.venv`; override with
`PYTHON=/path/to/python`.

```bash
# Build the worker and run the whole suite over all transports.
./scripts/conf.py run --transport all

# One class on one transport.
./scripts/conf.py run --transport pipe --class TestProducer

# Query previous run's JUnit XML without re-running.
./scripts/conf.py summary
./scripts/conf.py failures
./scripts/conf.py show TestProducer::test_produce_n
```

Results land in `.test-run/junit.xml` and `.test-run/pytest.log`.

## Worker binary

```bash
# Default: stdio (launched as a subprocess by a pipe client).
./target/release/vgi-rpc-conformance-rust

# HTTP: prints PORT:<n> then serves.
./target/release/vgi-rpc-conformance-rust --http

# Unix socket: prints UNIX:<path> then accepts connections.
./target/release/vgi-rpc-conformance-rust --unix /tmp/my.sock
```

`SIGTERM` / `SIGINT` triggers a graceful shutdown. `VGI_ACCESS_LOG=path`
writes one JSON-per-call record compatible with Python's
`vgi_rpc.access_log_conformance` validator.

## Related projects

- [`vgi-rpc`](https://github.com/Query-farm/vgi-rpc) — Python canonical
  implementation and conformance suite (installed via PyPI).
- [`vgi-rpc-go`](https://github.com/Query-farm/vgi-rpc-go) — Go port,
  structural reference for HTTP state tokens and describe format.

## License

Apache-2.0 — see [LICENSE.md](LICENSE.md).
