//! End-to-end smoke test for `#[vgi_rpc::service]` + `#[unary]`.
//!
//! Defines a small service via the macro, registers it against an
//! `RpcServer`, and drives both methods through the in-process axum
//! router. Asserts the response decodes back to the expected values.

use std::sync::Arc;

use arrow_array::{Int64Array, RecordBatch, StringArray};
use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use bytes::Bytes;
use tower::ServiceExt;

use serde::{Deserialize, Serialize};
use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY};
use vgi_rpc::stream::{ExchangeState, OutputCollector, ProducerState};
use vgi_rpc::wire::{StreamReader, StreamWriter};
use vgi_rpc::{service, CallContext, Result, RpcServer, StreamState, VgiArrow};

struct Calc;

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
        let batch = RecordBatch::try_new(out.schema(), vec![arr])?;
        out.emit(batch)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[derive(StreamState, Serialize, Deserialize)]
struct Doubler;

impl ExchangeState for Doubler {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        let v = i64::read(input.column(0).as_ref(), 0)?;
        let arr = i64::build_singleton(v * 2)?;
        out.emit(RecordBatch::try_new(out.schema(), vec![arr])?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[service]
impl Calc {
    /// Echo a string back, prefixed.
    #[unary]
    fn echo_string(&self, value: String) -> Result<String> {
        Ok(format!("echo: {value}"))
    }

    /// Add two integers.
    #[unary]
    #[param(name = "a", doc = "first addend", default = 0)]
    #[param(name = "b", doc = "second addend", default = 0)]
    fn add(&self, a: i64, b: i64) -> Result<i64> {
        Ok(a + b)
    }

    /// Method returning Result<()> — should produce an empty unary result.
    #[unary]
    fn ping(&self) -> Result<()> {
        Ok(())
    }

    /// Produce a counter from 0..total.
    #[producer(state = CountTo, output = i64)]
    fn count_to(&self, total: i64) -> Result<CountTo> {
        Ok(CountTo { total, cur: 0 })
    }

    /// Echo each input doubled.
    #[exchange(state = Doubler, input = i64, output = i64)]
    fn double_each(&self) -> Result<Doubler> {
        Ok(Doubler)
    }

    /// Producer with a typed header.
    #[producer(state = CountTo, output = i64, header = i64, header_fn = build_header)]
    fn count_with_header(&self, total: i64) -> Result<CountTo> {
        Ok(CountTo { total, cur: 0 })
    }

    /// Producer with a dynamic schema.
    #[producer(state = DynState, dynamic, schema_fn = build_dyn_schema)]
    fn count_dynamic(&self, total: i64, with_label: bool) -> Result<DynState> {
        Ok(DynState {
            total,
            cur: 0,
            with_label,
        })
    }
}

fn build_header(req: &vgi_rpc::server::Request) -> Result<i64> {
    Ok(i64::read(req.column("total").expect("total param"), 0)? * 2)
}

#[derive(StreamState, Serialize, Deserialize)]
struct DynState {
    total: i64,
    cur: i64,
    with_label: bool,
}

impl ProducerState for DynState {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        let mut arrs: Vec<arrow_array::ArrayRef> = vec![i64::build_singleton(self.cur)?];
        if self.with_label {
            arrs.push(String::build_singleton(format!("row-{}", self.cur))?);
        }
        out.emit(RecordBatch::try_new(out.schema(), arrs)?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

fn build_dyn_schema(req: &vgi_rpc::server::Request) -> Result<arrow_schema::SchemaRef> {
    let with_label = bool::read(req.column("with_label").expect("with_label param"), 0)?;
    let mut fields = vec![arrow_schema::Field::new(
        "value",
        arrow_schema::DataType::Int64,
        false,
    )];
    if with_label {
        fields.push(arrow_schema::Field::new(
            "label",
            arrow_schema::DataType::Utf8,
            false,
        ));
    }
    Ok(Arc::new(arrow_schema::Schema::new(fields)))
}

fn build_app() -> axum::Router {
    let mut srv = RpcServer::builder()
        .server_id("test")
        .protocol_name("Calc")
        .enable_describe(true)
        .build();
    Calc::register_with(&mut srv, Arc::new(Calc));
    let state = HttpState::builder()
        .server(Arc::new(srv))
        .signing_key(&[7u8; 32])
        .build();
    vgi_rpc::http::build_router(state)
}

fn build_unary_body<T: VgiArrow>(method: &str, params: Vec<(&str, T)>) -> Vec<u8> {
    use std::sync::Arc as Ar;
    let len = params.len();
    let (names, values): (Vec<&str>, Vec<T>) = params.into_iter().unzip();

    let arrays: Vec<arrow_array::ArrayRef> = values
        .into_iter()
        .map(|v| T::build_singleton(v).unwrap())
        .collect();

    let fields: Vec<arrow_schema::Field> = names
        .iter()
        .map(|n| arrow_schema::Field::new(*n, T::arrow_data_type(), T::nullable()))
        .collect();
    let _ = len;

    let schema = Ar::new(arrow_schema::Schema::new(fields));
    let batch = RecordBatch::try_new(schema.clone(), arrays).unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Build the empty-params body for `ping` (zero columns, one row).
fn build_empty_params_body(method: &str) -> Vec<u8> {
    use arrow_array::RecordBatchOptions;
    use std::sync::Arc as Ar;
    let schema = Ar::new(arrow_schema::Schema::empty());
    let batch = RecordBatch::try_new_with_options(
        schema.clone(),
        vec![],
        &RecordBatchOptions::new().with_row_count(Some(1)),
    )
    .unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

async fn post_arrow(app: axum::Router, path: &str, body: Vec<u8>) -> Bytes {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(path)
                .method("POST")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status: {}", resp.status());
    to_bytes(resp.into_body(), usize::MAX).await.unwrap()
}

#[tokio::test]
async fn unary_echo_string_round_trips() {
    let app = build_app();
    let body = build_unary_body("echo_string", vec![("value", "hello".to_string())]);
    let resp = post_arrow(app, "/echo_string", body).await;

    let mut r = StreamReader::new(resp.as_ref()).unwrap();
    let (rb, _md) = r.read_next().unwrap().expect("response batch");
    let col = rb
        .column_by_name("result")
        .expect("result column")
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("Utf8 result");
    assert_eq!(col.value(0), "echo: hello");
}

#[tokio::test]
async fn unary_add_returns_sum() {
    let app = build_app();
    // Two-column body for add(a, b).
    use std::sync::Arc as Ar;
    let schema = Ar::new(arrow_schema::Schema::new(vec![
        arrow_schema::Field::new("a", arrow_schema::DataType::Int64, false),
        arrow_schema::Field::new("b", arrow_schema::DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Ar::new(Int64Array::from(vec![3i64])) as arrow_array::ArrayRef,
            Ar::new(Int64Array::from(vec![4i64])),
        ],
    )
    .unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), "add".to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    let resp = post_arrow(app, "/add", buf).await;

    let mut r = StreamReader::new(resp.as_ref()).unwrap();
    let (rb, _md) = r.read_next().unwrap().expect("response batch");
    let col = rb
        .column_by_name("result")
        .expect("result column")
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Int64 result");
    assert_eq!(col.value(0), 7);
}

#[tokio::test]
async fn unary_ping_returns_empty_result() {
    let app = build_app();
    let body = build_empty_params_body("ping");
    let resp = post_arrow(app, "/ping", body).await;

    // Response is an empty-schema stream.
    let r = StreamReader::new(resp.as_ref()).unwrap();
    assert_eq!(r.schema().fields().len(), 0);
}

#[tokio::test]
async fn producer_emits_first_batch_and_state_token() {
    let app = build_app();
    // count_to(total=3) — producer with batch_limit=1 emits 1 batch + token.
    let body = build_unary_body("count_to", vec![("total", 3i64)]);
    let resp = post_arrow(app, "/count_to/init", body).await;

    let mut r = StreamReader::new(resp.as_ref()).unwrap();
    let mut data_values: Vec<i64> = Vec::new();
    let mut got_token = false;
    while let Some((rb, md)) = r.read_next().unwrap() {
        if rb.num_rows() == 0 {
            for k in md.keys() {
                if k == "vgi_rpc.stream_state#b64" {
                    got_token = true;
                }
            }
        } else {
            let col = rb.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
            for i in 0..col.len() {
                data_values.push(col.value(i));
            }
        }
    }
    assert_eq!(data_values, vec![0]);
    assert!(got_token, "init must emit a continuation token");
}

#[tokio::test]
async fn producer_with_header_emits_header_then_data() {
    let app = build_app();
    let body = build_unary_body("count_with_header", vec![("total", 5i64)]);
    let resp = post_arrow(app, "/count_with_header/init", body).await;

    // Two IPC streams concatenated: header stream then output stream.
    let mut cursor = resp.as_ref();

    // Header stream: a single i64 column "value".
    let mut hr = StreamReader::new(&mut cursor).unwrap();
    let mut got_header_value: Option<i64> = None;
    while let Some((rb, _md)) = hr.read_next().unwrap() {
        if rb.num_rows() > 0 {
            let col = rb
                .column_by_name("value")
                .unwrap()
                .as_any()
                .downcast_ref::<Int64Array>()
                .unwrap();
            got_header_value = Some(col.value(0));
        }
    }
    assert_eq!(got_header_value, Some(10), "header_fn returns total*2");

    // Output stream: first data batch + state token.
    let mut or_ = StreamReader::new(cursor).unwrap();
    let mut data: Vec<i64> = Vec::new();
    while let Some((rb, _md)) = or_.read_next().unwrap() {
        if rb.num_rows() > 0 {
            let col = rb.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
            for i in 0..col.len() {
                data.push(col.value(i));
            }
        }
    }
    assert_eq!(data, vec![0]);
}

#[tokio::test]
async fn dynamic_producer_uses_runtime_schema() {
    let app = build_app();
    // count_dynamic(total=2, with_label=true) — output schema has 2 cols.
    use std::sync::Arc as Ar;
    let schema = Ar::new(arrow_schema::Schema::new(vec![
        arrow_schema::Field::new("total", arrow_schema::DataType::Int64, false),
        arrow_schema::Field::new("with_label", arrow_schema::DataType::Boolean, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Ar::new(Int64Array::from(vec![2i64])) as arrow_array::ArrayRef,
            Ar::new(arrow_array::BooleanArray::from(vec![true])),
        ],
    )
    .unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), "count_dynamic".to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    let resp = post_arrow(app, "/count_dynamic/init", buf).await;
    let r = StreamReader::new(resp.as_ref()).unwrap();
    // Schema should have 2 fields when with_label=true.
    assert_eq!(r.schema().fields().len(), 2);
    assert_eq!(r.schema().fields()[0].name(), "value");
    assert_eq!(r.schema().fields()[1].name(), "label");
}

#[tokio::test]
async fn exchange_init_returns_token() {
    let app = build_app();
    let body = build_empty_params_body("double_each");
    let resp = post_arrow(app, "/double_each/init", body).await;

    let mut r = StreamReader::new(resp.as_ref()).unwrap();
    let mut got_token = false;
    while let Some((_rb, md)) = r.read_next().unwrap() {
        for k in md.keys() {
            if k == "vgi_rpc.stream_state#b64" {
                got_token = true;
            }
        }
    }
    assert!(got_token, "exchange init must emit a continuation token");
}
