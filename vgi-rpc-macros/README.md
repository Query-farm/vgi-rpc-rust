# vgi-rpc-macros

Proc-macros for [`vgi-rpc`](https://crates.io/crates/vgi-rpc). Re-exported
from `vgi-rpc` (default-on `macros` feature) so you only depend on
`vgi-rpc` directly.

## What you get

- **`#[vgi_rpc::service]`** — attribute on an `impl` block. Generates a
  `Self::register_with(server, instance)` that wires every annotated
  method into an `RpcServer`.
- **`#[unary]`**, **`#[producer]`**, **`#[exchange]`** — method markers
  consumed by `#[service]`.
- **`#[param]`** — per-parameter metadata (`name`, `doc`, `default`,
  `rename`).
- **`#[derive(VgiArrow)]`** — auto-impl `VgiArrow` for plain structs;
  the wire format mirrors the Python `ArrowSerializableDataclass`
  layout (`Struct<fields>` with each field's Arrow data type).
- **`#[derive(StreamState)]`** — auto-impl `StreamStateCodec` (bincode)
  on a state type. Container `#[stream_state(rebuild = "fn_path")]`
  re-derives non-serializable fields after decode (e.g. dynamic
  schemas).

## Quick start

```rust
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vgi_rpc::stream::{ExchangeState, OutputCollector, ProducerState};
use vgi_rpc::{service, CallContext, Result, RpcServer, StreamState, VgiArrow};

struct Calc;

#[derive(VgiArrow, Debug)]
struct Point { x: f64, y: f64 }

#[derive(StreamState, Serialize, Deserialize)]
struct CountTo { total: i64, cur: i64 }

impl ProducerState for CountTo {
    fn produce(&mut self, out: &mut OutputCollector, _: &CallContext) -> Result<()> {
        if self.cur >= self.total { out.finish(); return Ok(()); }
        // ... emit batch ...
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[service]
impl Calc {
    /// Echo a string back, prefixed.
    #[unary]
    fn echo(&self, value: String) -> Result<String> {
        Ok(format!("echo: {value}"))
    }

    /// Add two integers, with default values surfaced via __describe__.
    #[unary]
    #[param(name = "a", default = 0)]
    #[param(name = "b", default = 0)]
    fn add(&self, a: i64, b: i64) -> Result<i64> {
        Ok(a + b)
    }

    /// Async unary — bridged via `tokio::task::block_in_place +
    /// Handle::current().block_on(...)`. Requires the multi-thread tokio
    /// runtime (which `axum::serve` uses by default).
    #[unary]
    async fn fetch(&self, url: String) -> Result<String> {
        // tokio::time::sleep(...).await;
        Ok(url)
    }

    /// Stateful producer.
    #[producer(state = CountTo, output = i64)]
    fn count_to(&self, total: i64) -> Result<CountTo> {
        Ok(CountTo { total, cur: 0 })
    }
}

let mut server = RpcServer::builder().protocol_name("Calc").build();
Calc::register_with(&mut server, Arc::new(Calc));
```

## Method-attribute reference

```rust
#[unary]                                  // sync; result schema from return type
#[unary]
async fn slow(...) -> Result<T>           // async unary
#[producer(state = S, output = T)]        // single-column "value" output
#[producer(state = S, output_schema = my_schema_fn)] // custom output schema fn
#[producer(state = S, output = T,
           header = H, header_fn = build_header)]    // with typed header
#[producer(state = S, dynamic, schema_fn = build_schema)] // dynamic schema
#[exchange(state = S, input = T, output = U)]
#[exchange(state = S, input_schema = ..., output_schema = ...)]
#[param(name = "n", doc = "the count", default = 10)]
#[param(name = "n", rename = "wireName")] // method param `n`, wire name `wireName`
```

`header_fn` / `schema_fn` paths must point to free functions taking
`&vgi_rpc::server::Request` and returning `Result<HeaderType>` /
`Result<SchemaRef>` respectively.

## Built-in `VgiArrow` types

| Rust          | Arrow `DataType`           |
| ------------- | -------------------------- |
| `String`      | `Utf8`                     |
| `i64`, `i32`  | `Int64` / `Int32`          |
| `f64`, `f32`  | `Float64` / `Float32`      |
| `bool`        | `Boolean`                  |
| `vgi_rpc::Bytes(Vec<u8>)` | `Binary`       |
| `Vec<T>`      | `List<T>`                  |
| `Vec<Vec<T>>` | `List<List<T>>`            |
| `Vec<(String, V)>` | `Map<Utf8, V>`        |
| `Option<T>`   | inner T with `nullable=true` |
| `#[derive(VgiArrow)] struct` | `Struct<fields>` |

`Vec<u8>` is treated as `List<UInt8>`, **not** `Binary`. Use the
`vgi_rpc::Bytes` newtype when you want Arrow `Binary`.

## Compile-fail behavior

The macro emits typed `compile_error!` for misuse:

- `#[producer]` without `state =`
- `#[unary]` returning a non-`Result<T>` type
- `#[derive(VgiArrow)]` on a struct with a non-`VgiArrow` field
- `header = T` without `header_fn = path` (or vice versa)
- `dynamic` without `schema_fn = path`
- `dynamic` on `#[exchange]`

Fixtures live in `vgi-rpc/tests/macro_compile_fail/`.
