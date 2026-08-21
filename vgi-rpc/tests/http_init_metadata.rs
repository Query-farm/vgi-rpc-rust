//! Integration test: an HTTP request's custom metadata must reach the FIRST
//! produce call of that turn — and only the first.
//!
//! On the pipe transports EVERY producer turn is a distinct tick batch, so
//! custom metadata the client attached to it reaches the worker through
//! `CallContext::tick_metadata`. Over HTTP the first turn folds into the
//! /init request and later turns are continuation POSTs, so both have to be
//! forwarded:
//!
//!   * /init — without it the VGI result cache's conditional revalidation
//!     (`vgi.cache.if_none_match` / `if_modified_since`) is dropped and the
//!     worker recomputes instead of answering not_modified.
//!   * /exchange continuations — without it DuckDB's *between-tick*
//!     dynamic-filter updates (`vgi_pushdown_filters`: Top-N boundary
//!     tightening, join-key IN sets) never reach the worker over HTTP, though
//!     the client re-sends a tightened value on every tick.
//!
//! The framework's own transport keys (stream-state cursor, call-state,
//! cancel) must NOT be visible to user code: the pipe transports never put
//! them on a tick, and the stream-state value is a sealed cursor token.
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
    CALL_STATE_KEY, CANCEL_KEY, REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY,
    RPC_METHOD_KEY, STATE_KEY,
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
        // Any framework transport key visible here is a leak: user code must
        // never see the sealed cursor token or the cancel flag on a tick.
        let leaked = [STATE_KEY, CALL_STATE_KEY, CANCEL_KEY]
            .into_iter()
            .filter(|k| ctx.tick_metadata(k).is_some())
            .collect::<Vec<_>>()
            .join(";");
        let seen_arr: arrow_array::ArrayRef = Arc::new(StringArray::from(vec![seen]));
        let leaked_arr: arrow_array::ArrayRef = Arc::new(StringArray::from(vec![leaked]));
        out.emit(RecordBatch::try_new(
            output_schema(),
            vec![seen_arr, leaked_arr],
        )?)?;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("seen", DataType::Utf8, false),
        Field::new("leaked", DataType::Utf8, false),
    ]))
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

/// Build a producer-continuation body: empty batch carrying the state token
/// plus whatever per-tick metadata the client wants to refresh (the DuckDB
/// extension re-sends a tightened `vgi_pushdown_filters` on every tick).
fn exchange_body(token: &str, revalidator: Option<&str>) -> Vec<u8> {
    let empty = empty_batch(&Schema::empty()).unwrap();
    let mut md = std::collections::HashMap::<String, String>::from([
        (STATE_KEY.to_string(), token.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "meta-cont".to_string()),
    ]);
    if let Some(v) = revalidator {
        md.insert(REVALIDATOR_KEY.to_string(), v.to_string());
    }
    write_one_batch(&empty, Some(&md)).unwrap()
}

/// Extract (seen_values, leaked_framework_keys, state_token_or_none) from an
/// arrow response body.
fn parse_response(body: &[u8]) -> (Vec<String>, Vec<String>, Option<String>) {
    let mut r = StreamReader::new(body).unwrap();
    let mut values = Vec::new();
    let mut leaked = Vec::new();
    let mut token: Option<String> = None;
    while let Some((rb, md)) = r.read_next().unwrap() {
        if rb.num_rows() == 0 {
            if let Some(t) = md_get(&md, STATE_KEY) {
                token = Some(t.to_string());
            }
        } else {
            if let Some(col) = rb.column(0).as_any().downcast_ref::<StringArray>() {
                for i in 0..col.len() {
                    values.push(col.value(i).to_string());
                }
            }
            if let Some(col) = rb.column(1).as_any().downcast_ref::<StringArray>() {
                for i in 0..col.len() {
                    leaked.push(col.value(i).to_string());
                }
            }
        }
    }
    (values, leaked, token)
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
    let (values, leaked, token) = parse_response(&body);
    assert_eq!(
        values,
        vec!["etag-1".to_string(), String::new(), String::new()],
        "first tick sees the /init metadata; later ticks do not"
    );
    assert!(
        leaked.iter().all(String::is_empty),
        "framework transport keys leaked into user-visible tick metadata: {leaked:?}"
    );
    assert!(token.is_none(), "drained producer emits no token");
}

/// A continuation turn's own request metadata must reach the first produce
/// call of that turn. This is the transport-parity property the pipe
/// transports get for free (every tick is a batch), and it is what carries
/// DuckDB's between-tick dynamic-filter updates over HTTP. The framework's
/// transport keys must not come along for the ride.
#[tokio::test]
async fn continuation_turn_carries_its_own_request_metadata() {
    let state = build_state(1); // one batch per response + continuation token
    let app = vgi_rpc::http::build_router(state.clone());
    let body = post_arrow(app, "/meta_echo/init", init_body("etag-2")).await;
    let (values, leaked, token) = parse_response(&body);
    assert_eq!(values, vec!["etag-2".to_string()]);
    assert_eq!(leaked, vec![String::new()]);
    let token = token.expect("continuation token");

    // The client refreshes the value on the continuation tick — the worker
    // must see the NEW one, not the /init one and not an empty metadata map.
    let app = vgi_rpc::http::build_router(state.clone());
    let body = post_arrow(
        app,
        "/meta_echo/exchange",
        exchange_body(&token, Some("etag-3")),
    )
    .await;
    let (values, leaked, token2) = parse_response(&body);
    assert_eq!(
        values,
        vec!["etag-3".to_string()],
        "continuation produce call must see its own request's tick metadata"
    );
    assert_eq!(
        leaked,
        vec![String::new()],
        "framework transport keys (stream-state cursor, call-state, cancel) \
         must be stripped before the request metadata reaches user code"
    );

    // A continuation that attaches nothing still sees an empty map, so the
    // previous turn's value is not sticky.
    let token2 = token2.expect("second continuation token");
    let app = vgi_rpc::http::build_router(state);
    let body = post_arrow(app, "/meta_echo/exchange", exchange_body(&token2, None)).await;
    let (values, _leaked, _token) = parse_response(&body);
    assert_eq!(
        values,
        vec![String::new()],
        "a continuation with no user metadata must see an empty tick metadata map"
    );
}
