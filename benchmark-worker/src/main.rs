//! Rust benchmark worker mirroring the Go ``benchmark/cmd/vgi-rpc-benchmark-go``
//! and Python ``serve_benchmark_fixture.py`` workers — exposes the same
//! six methods (``noop``, ``add``, ``greet``, ``generate``, ``transform``,
//! and ``roundtrip_types`` — though ``roundtrip_types`` is omitted here
//! because the Rust crate has no dict/set param support).
//!
//! Apples-to-apples benchmark target for the cross-language comparison.

use std::io::{self, Write};
use std::sync::Arc;

use arrow_array::{ArrayRef, Float64Array, Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use serde::{Deserialize, Serialize};
use vgi_rpc::{
    service,
    stream::{ExchangeState, OutputCollector, ProducerState},
    stream_codec::{bincode_decode, bincode_encode, StreamStateCodec},
    CallContext, Result, RpcServer,
};

fn generate_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("i", DataType::Int64, false),
        Field::new("value", DataType::Int64, false),
    ]))
}

fn transform_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Float64,
        false,
    )]))
}

#[derive(Serialize, Deserialize)]
struct GenerateState {
    count: i64,
    cur: i64,
}

impl StreamStateCodec for GenerateState {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        bincode_decode(bytes)
    }
}

impl ProducerState for GenerateState {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.count {
            out.finish();
            return Ok(());
        }
        let i = self.cur;
        let arrs: Vec<ArrayRef> = vec![
            Arc::new(Int64Array::from(vec![i])),
            Arc::new(Int64Array::from(vec![i * 10])),
        ];
        out.emit(RecordBatch::try_new(generate_schema(), arrs)?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct TransformState {
    factor: f64,
}

impl StreamStateCodec for TransformState {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        bincode_decode(bytes)
    }
}

impl ExchangeState for TransformState {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        let col = input
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("transform: expected float64 input column");
        let vals: Vec<f64> = (0..col.len()).map(|i| col.value(i) * self.factor).collect();
        let arrs: Vec<ArrayRef> = vec![Arc::new(Float64Array::from(vals))];
        out.emit(RecordBatch::try_new(out.schema(), arrs)?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

pub struct BenchSvc;

#[service]
impl BenchSvc {
    /// Minimum framework overhead — accept and return nothing.
    #[unary]
    fn noop(&self) -> Result<()> {
        Ok(())
    }

    /// Add two floats.
    #[unary]
    fn add(&self, a: f64, b: f64) -> Result<f64> {
        Ok(a + b)
    }

    /// Greet by name.
    #[unary]
    fn greet(&self, name: String) -> Result<String> {
        Ok(format!("Hello, {name}!"))
    }

    /// Produce ``count`` batches with ``{i, value=i*10}``.
    #[producer(state = GenerateState, output_schema = generate_schema)]
    fn generate(&self, count: i64) -> Result<GenerateState> {
        Ok(GenerateState { count, cur: 0 })
    }

    /// Multiply input float64 values by ``factor``.
    #[exchange(
        state = TransformState,
        input_schema = transform_schema,
        output_schema = transform_schema
    )]
    fn transform(&self, factor: f64) -> Result<TransformState> {
        Ok(TransformState { factor })
    }
}

fn main() {
    let mut server = RpcServer::new("benchmark");
    BenchSvc::register_with(&mut server, Arc::new(BenchSvc));
    let server = Arc::new(server);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut r = io::BufReader::with_capacity(1024 * 1024, stdin.lock());
    let mut w = io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
    server.serve(&mut r, &mut w);
    let _ = w.flush();
}
