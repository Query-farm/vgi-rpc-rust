<div align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi-rpc-rust/main/assets/vgi-logo.png" alt="Vector Gateway Interface" width="320">
</div>

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

- **subprocess / stdio** — spawn a worker and talk over its stdin/stdout. An
  optional monotonic response deadline terminates, reaps, and poisons a timed-out
  child, preventing late bytes from desynchronizing the next call. Unix workers
  run in a private process group which is killed in full. On other platforms,
  `std::process` can kill only the direct child; reader shutdown is bounded and
  detaches if a descendant retained stdout. Anonymous pipe writes are not
  interruptible by `std`, so subprocess request sizes and workers remain a
  trusted-peer boundary.
- **AF_UNIX** — connect to a worker on a unix socket (with an optional read
  timeout for untrusted peers). *(feature `unix`)*
- **TCP / SOCKS5h** — persistent raw Arrow framing over TCP. `Socks5hProxy`
  supports credential-free userspace Tailscale sidecars with proxy-side IDNA
  hostname resolution, one setup deadline, and no direct fallback. The proxy
  URI intentionally requires an IP literal so local proxy DNS cannot escape
  that deadline. Raw TCP provides neither encryption nor authentication.
- **HTTP** — `reqwest`-blocking, with the full production surface:
  external-location resolution, sticky sessions, 413 request-externalization,
  415/zstd codec negotiation, a request timeout, and opt-in connection-level
  retries. *(feature `http`, default)*
- **HTTP over Iroh** — the same typed, stateless HTTP state machine carried on
  authenticated `iroh-http/2` streams. A canonical
  `httpi://<endpoint-id>[/base-path]` target selects the peer; direct and relay
  address hints are optional. Ambiguously dispatched requests are never
  retried. *(feature `iroh`, optional)*
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

Native HTTP-over-Iroh uses the same `HttpClient` type and methods:

```rust,no_run
use std::time::Duration;
use vgi_rpc_client::HttpClient;

# fn main() -> vgi_rpc_client::Result<()> {
let mut client = HttpClient::connect_httpi(
    "httpi://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/vgi",
)?
.connect_timeout(Duration::from_secs(15))
.io_timeout(Duration::from_secs(30))
.build()?;
let description = client.describe()?;
# let _ = description;
# Ok(()) }
```

The default key is generated once and remains stable for this process. Use
`secret_key`, `endpoint_config`, `relay_urls`, `no_relay`,
`remote_relay_url`, and `direct_addresses` when a deployment needs persistent
identity or explicit routing. Construction and calls are blocking; use them on
a blocking thread rather than a Tokio worker. Externalized payload URLs remain
ordinary HTTP(S) and use the independently configurable external HTTP client.

## Features

| feature | default | what it adds |
|---------|:-:|--------------|
| `http`  | ✅ | `HttpClient` + the HTTP production features above |
| `iroh`  | — | Native `httpi://` execution through `vgi-iroh-transport`; implies `http` |
| `unix`  | — | AF_UNIX transport |
| `shm`   | — | POSIX shared-memory side-channel |

## License

Apache-2.0
