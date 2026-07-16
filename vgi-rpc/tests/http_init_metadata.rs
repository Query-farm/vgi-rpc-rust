//! Integration test: the /init request's custom metadata must reach a
//! producer's FIRST tick — and only the first.
//!
//! On the pipe transports a producer's first turn is a distinct tick batch,
//! so custom metadata the client attached to it reaches the worker through
//! `CallContext::tick_metadata`. Over HTTP that turn folds into the /init
//! request; without delivery the VGI result cache's conditional
//! revalidation (`vgi.cache.if_none_match` / `if_modified_since` on /init)
//! is dropped and the worker recomputes instead of answering not_modified.
//! Mirrors Go a32b08b / Java 823dca2 / TS 2ed4c35.

use std::sync::Arc;

use arrow_array::{Array, RecordBatch, StringArray};
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

const REVALIDATOR_KEY: &str = "vgi.cache.if_none_match";

/// Emits, on every tick, the revalidator value visible via
/// `ctx.tick_metadata` — empty string when absent.
#[derive(Serialize, Deserialize)]
struct MetaEcho {
    remaining: i64,
}

impl StreamStateCodec for MetaEcho {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        bincode_decode(bytes)
    }
}

impl ProducerState for MetaEcho {
    fn produce(&mut self, out: &mut OutputCollector, ctx: &CallContext) -> Result<()> {
        if self.remaining <= 0 {
            out.finish();
            return Ok(());
        }
        self.remaining -= 1;
        let seen = ctx.tick_metadata(REVALIDATOR_KEY).unwrap_or_default();
        let arr: arrow_array::ArrayRef = Arc::new(StringArray::from(vec![seen]));
        out.emit(RecordBatch::try_new(output_schema(), vec![arr])?)?;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new("seen", DataType::Utf8, false)]))
}

fn producer_decoder() -> StateDecoder {
    Arc::new(|bytes: &[u8]| {
        Ok(StreamStateKind::Producer(Box::new(MetaEcho::decode(
            bytes,
        )?)))
    })
}

fn build_state(producer_batch_limit: usize) -> Arc<HttpState> {
    let mut srv = RpcServer::builder().server_id("meta").build();
    srv.register(
        MethodInfo::stream(
            "meta_echo",
            MethodType::Producer,
            Arc::new(Schema::empty()),
            |_req, _ctx| {
                Ok(StreamResult::producer(
                    output_schema(),
                    Box::new(MetaEcho { remaining: 3 }),
                ))
            },
        )
        .with_state_decoder(producer_decoder()),
    );
    HttpState::builder()
        .server(Arc::new(srv))
        .producer_batch_limit(producer_batch_limit)
        .build()
}

/// Frame the /init request, attaching the revalidator to its metadata the
/// way the DuckDB extension does.
fn init_body(revalidator: &str) -> Vec<u8> {
    let schema = Schema::empty();
    let batch = empty_batch(&schema).unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), "meta_echo".to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "meta-req".to_string()),
        (REVALIDATOR_KEY.to_string(), revalidator.to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Build a producer-continuation body: empty batch carrying the state token.
fn exchange_body(token: &str) -> Vec<u8> {
    let empty = empty_batch(&Schema::empty()).unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (STATE_KEY.to_string(), token.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "meta-cont".to_string()),
    ]);
    write_one_batch(&empty, Some(&md)).unwrap()
}

/// Extract (seen_values, state_token_or_none) from an arrow response body.
fn parse_response(body: &[u8]) -> (Vec<String>, Option<String>) {
    let mut r = StreamReader::new(body).unwrap();
    let mut values = Vec::new();
    let mut token: Option<String> = None;
    while let Some((rb, md)) = r.read_next().unwrap() {
        if rb.num_rows() == 0 {
            if let Some(t) = md_get(&md, STATE_KEY) {
                token = Some(t.to_string());
            }
        } else if let Some(col) = rb.column(0).as_any().downcast_ref::<StringArray>() {
            for i in 0..col.len() {
                values.push(col.value(i).to_string());
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

/// Within one /init response, the init request's metadata is visible to the
/// first produce call only.
#[tokio::test]
async fn init_metadata_reaches_first_tick_only() {
    let state = build_state(0); // drain the whole producer in /init
    let app = vgi_rpc::http::build_router(state);
    let body = post_arrow(app, "/meta_echo/init", init_body("etag-1")).await;
    let (values, token) = parse_response(&body);
    assert_eq!(
        values,
        vec!["etag-1".to_string(), String::new(), String::new()],
        "first tick sees the /init metadata; later ticks do not"
    );
    assert!(token.is_none(), "drained producer emits no token");
}

/// A continuation turn is not the producer's first tick — it must not see
/// the (already-consumed) init metadata, nor its own request's metadata.
#[tokio::test]
async fn continuation_turn_carries_no_first_tick_metadata() {
    let state = build_state(1); // one batch per response + continuation token
    let app = vgi_rpc::http::build_router(state.clone());
    let body = post_arrow(app, "/meta_echo/init", init_body("etag-2")).await;
    let (values, token) = parse_response(&body);
    assert_eq!(values, vec!["etag-2".to_string()]);
    let token = token.expect("continuation token");

    let app = vgi_rpc::http::build_router(state);
    let body = post_arrow(app, "/meta_echo/exchange", exchange_body(&token)).await;
    let (values, _token) = parse_response(&body);
    assert_eq!(
        values,
        vec![String::new()],
        "continuation produce call must see empty tick metadata"
    );
}
