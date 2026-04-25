//! Streaming RPC example: a producer (`count_to`) and an exchange
//! (`scale`).
//!
//! Run with:
//!
//! ```sh
//! cargo run --example hello_stream
//! ```

use std::sync::Arc;

use arrow_array::{Float64Array, RecordBatch};
use serde::{Deserialize, Serialize};
use vgi_rpc::http::{serve_with_shutdown, HttpState};
use vgi_rpc::stream::{ExchangeState, OutputCollector, ProducerState};
use vgi_rpc::{service, CallContext, Result, RpcServer, StreamState, VgiArrow};

struct StreamingSvc;

#[derive(StreamState, Serialize, Deserialize)]
struct CountTo {
    total: i64,
    cur: i64,
}

impl ProducerState for CountTo {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        let arr = i64::build_singleton(self.cur)?;
        out.emit(RecordBatch::try_new(out.schema(), vec![arr])?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[derive(StreamState, Serialize, Deserialize)]
struct Scale {
    factor: f64,
}

impl ExchangeState for Scale {
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
            .expect("Float64 input");
        let scaled: Vec<f64> = (0..col.len()).map(|i| col.value(i) * self.factor).collect();
        let arr = std::sync::Arc::new(Float64Array::from(scaled)) as arrow_array::ArrayRef;
        out.emit(RecordBatch::try_new(out.schema(), vec![arr])?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[service]
impl StreamingSvc {
    /// Emit each integer 0..total, one per HTTP round-trip.
    #[producer(state = CountTo, output = i64)]
    fn count_to(&self, total: i64) -> Result<CountTo> {
        Ok(CountTo { total, cur: 0 })
    }

    /// Multiply each input float by a factor.
    #[exchange(state = Scale, input = f64, output = f64)]
    fn scale(&self, factor: f64) -> Result<Scale> {
        Ok(Scale { factor })
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let mut server = RpcServer::builder()
        .server_id("hello-stream")
        .protocol_name("StreamingSvc")
        .enable_describe(true)
        .build();
    StreamingSvc::register_with(&mut server, Arc::new(StreamingSvc));

    let state = HttpState::builder()
        .server(Arc::new(server))
        .signing_key(&[0xau8; 32])
        .cors_origins("*")
        .build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8081").await?;
    println!("listening on http://127.0.0.1:8081");
    serve_with_shutdown(state, listener).await
}
