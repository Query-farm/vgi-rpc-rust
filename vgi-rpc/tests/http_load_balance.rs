//! Integration test: prove that a continuation request served by a
//! *different* `HttpState` instance (with the same signing key) can
//! resume a stream started against the first instance.
//!
//! This is the load-balancer scenario: two workers sharing a signing
//! key, no shared session map.

use std::sync::Arc;

use arrow_array::{Array, Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{
    REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY, STATE_KEY,
};
use vgi_rpc::server::{MethodType, StateDecoder};
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult, StreamStateKind};
use vgi_rpc::stream_codec::{bincode_decode, bincode_encode, StreamStateCodec};
use vgi_rpc::wire::{empty_batch, md_get, write_one_batch, StreamReader, StreamWriter};
use vgi_rpc::{CallContext, MethodInfo, Result, RpcServer};

#[derive(Serialize, Deserialize)]
struct Counter {
    total: i64,
    cur: i64,
}

impl StreamStateCodec for Counter {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        bincode_decode(bytes)
    }
}

impl ProducerState for Counter {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        let arr: arrow_array::ArrayRef = Arc::new(Int64Array::from(vec![self.cur]));
        out.emit(RecordBatch::try_new(counter_schema(), vec![arr])?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

fn counter_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]))
}

fn params_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "count",
        DataType::Int64,
        false,
    )]))
}

fn producer_decoder() -> StateDecoder {
    Arc::new(|bytes: &[u8]| Ok(StreamStateKind::Producer(Box::new(Counter::decode(bytes)?))))
}

fn build_server() -> Arc<RpcServer> {
    let mut srv = RpcServer::builder().server_id("lb").build();
    srv.register(
        MethodInfo::stream(
            "counter",
            MethodType::Producer,
            params_schema(),
            |req, _ctx| {
                let a = req
                    .column("count")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .unwrap();
                let total = a.value(0);
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(Counter { total, cur: 0 }),
                ))
            },
        )
        .with_state_decoder(producer_decoder()),
    );
    Arc::new(srv)
}

fn state_with_shared_key(key: &[u8; 32], server: Arc<RpcServer>) -> Arc<HttpState> {
    HttpState::builder()
        .server(server)
        .signing_key(key)
        .producer_batch_limit(1)
        .build()
}

/// Build an Arrow IPC request body invoking `counter(count=total)`.
fn init_body(total: i64) -> Vec<u8> {
    let batch = RecordBatch::try_new(
        params_schema(),
        vec![Arc::new(Int64Array::from(vec![total]))],
    )
    .unwrap();
    let md = vec![
        (RPC_METHOD_KEY.to_string(), "counter".to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "lb-req".to_string()),
    ];
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, params_schema().as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Build a producer-continuation body: empty batch carrying the state token.
fn exchange_body(token: &str) -> Vec<u8> {
    let empty = empty_batch(&Schema::empty()).unwrap();
    let md = vec![
        (STATE_KEY.to_string(), token.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "lb-cont".to_string()),
    ];
    write_one_batch(&empty, Some(&md)).unwrap()
}

/// Extract (data_values, state_token_or_none) from an arrow response body.
fn parse_response(body: &[u8]) -> (Vec<i64>, Option<String>) {
    let mut r = StreamReader::new(body).unwrap();
    let mut values = Vec::new();
    let mut token: Option<String> = None;
    while let Some(rb) = r.read_next().unwrap() {
        if rb.batch.num_rows() == 0 {
            if let Some(t) = md_get(&rb.metadata, STATE_KEY) {
                token = Some(t.to_string());
            }
        } else if let Some(col) = rb.batch.column(0).as_any().downcast_ref::<Int64Array>() {
            for i in 0..col.len() {
                values.push(col.value(i));
            }
        }
    }
    (values, token)
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
async fn second_worker_can_resume_stream_from_first() {
    let key = [0x5au8; 32];
    let server = build_server();

    // Worker A serves the init request.
    let worker_a = state_with_shared_key(&key, server.clone());
    let app_a = vgi_rpc::http::build_router(worker_a);
    let body_a = post_arrow(app_a, "/counter/init", init_body(3)).await;
    let (values_a, token_a) = parse_response(&body_a);
    assert_eq!(values_a, vec![0], "worker A should emit exactly one batch");
    let token_a = token_a.expect("worker A must emit a continuation token");

    // Worker B (independent HttpState, same key, same server) serves the
    // continuation — this is the load-balance-across-workers scenario.
    let worker_b = state_with_shared_key(&key, server.clone());
    let app_b = vgi_rpc::http::build_router(worker_b);
    let body_b = post_arrow(app_b, "/counter/exchange", exchange_body(&token_a)).await;
    let (values_b, token_b) = parse_response(&body_b);
    assert_eq!(values_b, vec![1], "worker B should continue at cur=1");
    let token_b = token_b.expect("worker B must emit a refreshed token");

    // And a third hop back to worker A (proving the token is freshly
    // valid after B's mutation).
    let worker_a2 = state_with_shared_key(&key, server.clone());
    let app_a2 = vgi_rpc::http::build_router(worker_a2);
    let body_c = post_arrow(app_a2, "/counter/exchange", exchange_body(&token_b)).await;
    let (values_c, _token_c) = parse_response(&body_c);
    assert_eq!(values_c, vec![2], "round-trip C should see cur=2");
}

#[tokio::test]
async fn worker_with_different_key_rejects_peer_token() {
    let server = build_server();
    let worker_a = state_with_shared_key(&[1u8; 32], server.clone());
    let app_a = vgi_rpc::http::build_router(worker_a);
    let body_a = post_arrow(app_a, "/counter/init", init_body(3)).await;
    let (_vals, token_a) = parse_response(&body_a);
    let token_a = token_a.expect("init token");

    // Worker with a *different* signing key must reject the token.
    let hostile = state_with_shared_key(&[2u8; 32], server);
    let app_h = vgi_rpc::http::build_router(hostile);
    let resp = app_h
        .oneshot(
            Request::builder()
                .uri("/counter/exchange")
                .method("POST")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(exchange_body(&token_a)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "hostile worker should reject a token signed with a different key"
    );
}
