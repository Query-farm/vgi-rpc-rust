# vgi-rpc-client

A blocking, synchronous client for the [`vgi-rpc`](https://crates.io/crates/vgi-rpc)
Arrow-IPC RPC framework. It speaks the canonical `vgi_rpc` wire protocol and is
validated against the Python reference implementation's full conformance suite
(unary, producer/exchange streaming, cancellation, logs, errors, `__describe__`,
and `__transport_options__`) across every transport, driving the Rust, Python,
and Go conformance servers.

The client is **dynamic and schema-first**, mirroring the server's model and the
canonical Python client: you build the request parameters as a one-row Arrow
`RecordBatch` and receive the result batch — no generated stubs.

## Transports

- **subprocess / stdio** — spawn a worker and talk over its stdin/stdout.
- **AF_UNIX** — connect to a worker on a unix socket (with an optional read
  timeout for untrusted peers). *(feature `unix`)*
- **HTTP** — `reqwest`-blocking, with the full production surface:
  external-location resolution, sticky sessions, 413 request-externalization,
  415/zstd codec negotiation, a request timeout, and connection-level retry on
  idempotent calls. *(feature `http`, default)*
- **POSIX shared memory** — the `shm` side-channel for large batches.
  *(feature `shm`)*

## Example

```rust
use vgi_rpc_client::RpcClient;
use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use std::sync::Arc;

# fn main() -> vgi_rpc_client::Result<()> {
// Spawn a worker subprocess and call a unary method.
let mut client = RpcClient::connect(&["my-worker"])?;

let schema = Arc::new(Schema::new(vec![Field::new("value", DataType::Utf8, false)]));
let params = RecordBatch::try_new(schema, vec![Arc::new(StringArray::from(vec!["hello"]))])?;
let (result, _md) = client.call_unary("echo_string", &params, None)?;
# Ok(())
# }
```

Streaming uses `open_producer` / `open_exchange`, which return a
`StreamSession` (`tick` for producers, `exchange` for bidirectional streams,
plus `cancel`/`close`). HTTP connections use `HttpClient::connect(url)`.

## Features

| feature | default | what it adds |
|---------|:-:|--------------|
| `http`  | ✅ | `HttpClient` + the HTTP production features above |
| `unix`  | — | AF_UNIX transport |
| `shm`   | — | POSIX shared-memory side-channel |

## License

Apache-2.0
