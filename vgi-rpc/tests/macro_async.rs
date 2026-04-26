//! Smoke test for `async fn` handlers via `#[service]`.
//!
//! Demonstrates that the macro bridges `async fn` bodies through
//! `tokio::runtime::Handle::current().block_on(...)` so user code can
//! `.await` from inside an RPC handler. Requires a tokio runtime to be
//! present, which the HTTP transport always provides.

use std::sync::Arc;

use arrow_array::{Int64Array, RecordBatch, StringArray};
use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY};
use vgi_rpc::stream::{OutputCollector, ProducerState};
use vgi_rpc::wire::{StreamReader, StreamWriter};
use vgi_rpc::{service, CallContext, Result, RpcServer, StreamState, VgiArrow};

struct SlowSvc;

#[derive(StreamState, Serialize, Deserialize)]
struct OneShot {
    value: i64,
    sent: bool,
}

impl ProducerState for OneShot {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.sent {
            out.finish();
            return Ok(());
        }
        self.sent = true;
        let arr = i64::build_singleton(self.value)?;
        out.emit(RecordBatch::try_new(out.schema(), vec![arr])?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[service]
impl SlowSvc {
    /// Async unary that yields once before returning.
    #[unary]
    async fn slow_echo(&self, value: String) -> Result<String> {
        tokio::task::yield_now().await;
        Ok(format!("slow: {value}"))
    }

    /// Async producer init.
    #[producer(state = OneShot, output = i64)]
    async fn async_producer(&self, value: i64) -> Result<OneShot> {
        tokio::task::yield_now().await;
        Ok(OneShot { value, sent: false })
    }
}

fn build_app() -> axum::Router {
    let mut srv = RpcServer::builder().server_id("t").build();
    SlowSvc::register_with(&mut srv, Arc::new(SlowSvc));
    let state = HttpState::builder()
        .server(Arc::new(srv))
        .signing_key(&[7u8; 32])
        .build();
    vgi_rpc::http::build_router(state)
}

fn body_one<T: VgiArrow>(method: &str, name: &str, value: T) -> Vec<u8> {
    let arr = T::build_singleton(value).unwrap();
    let schema = Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new(
        name,
        T::arrow_data_type(),
        T::nullable(),
    )]));
    let batch = RecordBatch::try_new(schema.clone(), vec![arr]).unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref()).unwrap();
        w.write(&batch.clone().with_custom_metadata(md.clone()))
            .unwrap();
        w.finish().unwrap();
    }
    buf
}

async fn post(app: axum::Router, path: &str, body: Vec<u8>) -> Bytes {
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

#[tokio::test(flavor = "multi_thread")]
async fn async_unary_round_trips() {
    let app = build_app();
    let body = body_one("slow_echo", "value", "hello".to_string());
    let resp = post(app, "/slow_echo", body).await;
    let mut r = StreamReader::new(resp.as_ref()).unwrap();
    let rb = r.read_next().unwrap().expect("response batch");
    let col = rb
        .column_by_name("result")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(col.value(0), "slow: hello");
}

#[tokio::test(flavor = "multi_thread")]
async fn async_producer_emits_first_batch() {
    let app = build_app();
    let body = body_one("async_producer", "value", 42i64);
    let resp = post(app, "/async_producer/init", body).await;
    let mut r = StreamReader::new(resp.as_ref()).unwrap();
    let mut data: Vec<i64> = Vec::new();
    while let Some(rb) = r.read_next().unwrap() {
        if rb.num_rows() > 0 {
            let col = rb.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
            for i in 0..col.len() {
                data.push(col.value(i));
            }
        }
    }
    assert_eq!(data, vec![42]);
}
