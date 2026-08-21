//! Integration test: an HTTP *exchange* turn's request metadata must reach the
//! handler as `CallContext::tick_metadata` — with the framework's own
//! transport keys stripped.
//!
//! On the pipe transports the exchange loop sets `ctx.tick_metadata` from each
//! input batch's own custom metadata (`server.rs`, the `'lockstep` loop), and
//! that state never carries framework plumbing: the stream cursor and call
//! state live in the CONNECTION, not on a batch. Over HTTP each exchange turn
//! is a continuation POST whose metadata carries BOTH — the client's
//! application metadata (e.g. the result cache's `vgi.cache.if_none_match`
//! validators) and the framework's sealed cursor / call-state tokens.
//!
//! So the HTTP exchange path owes user code two things at once:
//!
//!   * deliver the request's application metadata, or an identical worker
//!     sees its validators over subprocess and nothing over HTTP;
//!   * strip `STATE_KEY` / `CALL_STATE_KEY` / `CANCEL_KEY` first — the cursor
//!     is an AEAD-sealed token that application code has no business seeing
//!     (and may log or persist).
//!
//! Mirrors the producer-side guarantee in `http_init_metadata.rs`.

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
use vgi_rpc::stream::{ExchangeState, OutputCollector, StreamResult, StreamStateKind};
use vgi_rpc::stream_codec::{bincode_decode, bincode_encode, StreamStateCodec};
use vgi_rpc::wire::{empty_batch, md_get, write_one_batch, StreamReader, StreamWriter};
use vgi_rpc::{CallContext, MethodInfo, Result, RpcServer};

const REVALIDATOR_KEY: &str = "vgi.cache.if_none_match";

/// Echoes, per exchange turn, the revalidator value visible through
/// `ctx.tick_metadata` plus any framework transport key that leaked into it.
#[derive(Serialize, Deserialize)]
struct MetaEchoExchange {
    turns: i64,
}

impl StreamStateCodec for MetaEchoExchange {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        bincode_decode(bytes)
    }
}

impl ExchangeState for MetaEchoExchange {
    fn exchange(
        &mut self,
        _input: &RecordBatch,
        out: &mut OutputCollector,
        ctx: &CallContext,
    ) -> Result<()> {
        self.turns += 1;
        let seen = ctx.tick_metadata(REVALIDATOR_KEY).unwrap_or_default();
        // Any framework transport key visible here is a leak: user code must
        // never see the sealed cursor token, the call state, or the cancel flag.
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

fn input_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Utf8,
        false,
    )]))
}

fn exchange_decoder() -> StateDecoder {
    Arc::new(|bytes: &[u8]| {
        Ok(StreamStateKind::Exchange(Box::new(
            MetaEchoExchange::decode(bytes)?,
        )))
    })
}

fn build_state() -> Arc<HttpState> {
    let mut srv = RpcServer::builder().server_id("meta-ex").build();
    srv.register(
        MethodInfo::stream(
            "meta_exchange",
            MethodType::Exchange,
            Arc::new(Schema::empty()),
            |_req, _ctx| {
                Ok(StreamResult::exchange(
                    output_schema(),
                    input_schema(),
                    Box::new(MetaEchoExchange { turns: 0 }),
                ))
            },
        )
        .with_state_decoder(exchange_decoder()),
    );
    HttpState::builder().server(Arc::new(srv)).build()
}

/// Frame the /init request for the exchange stream.
fn init_body() -> Vec<u8> {
    let schema = Schema::empty();
    let batch = empty_batch(&schema).unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), "meta_exchange".to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "meta-ex-req".to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Build an exchange-continuation body: a real input batch whose custom
/// metadata carries BOTH framework tokens (as a conformant client echoes
/// them) and the client's own application metadata.
fn exchange_body(token: &str, call_token: &str, revalidator: Option<&str>) -> Vec<u8> {
    let arr: arrow_array::ArrayRef = Arc::new(StringArray::from(vec!["payload"]));
    let batch = RecordBatch::try_new(input_schema(), vec![arr]).unwrap();
    let mut md = std::collections::HashMap::<String, String>::from([
        (STATE_KEY.to_string(), token.to_string()),
        (CALL_STATE_KEY.to_string(), call_token.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "meta-ex-cont".to_string()),
    ]);
    if let Some(v) = revalidator {
        md.insert(REVALIDATOR_KEY.to_string(), v.to_string());
    }
    write_one_batch(&batch, Some(&md)).unwrap()
}

/// Extract (seen_values, leaked_framework_keys, cursor, call_token).
fn parse_response(body: &[u8]) -> (Vec<String>, Vec<String>, Option<String>, Option<String>) {
    let mut r = StreamReader::new(body).unwrap();
    let mut values = Vec::new();
    let mut leaked = Vec::new();
    let mut token: Option<String> = None;
    let mut call_token: Option<String> = None;
    while let Some((rb, md)) = r.read_next().unwrap() {
        if let Some(t) = md_get(&md, STATE_KEY) {
            token = Some(t.to_string());
        }
        if let Some(t) = md_get(&md, CALL_STATE_KEY) {
            call_token = Some(t.to_string());
        }
        if rb.num_rows() > 0 {
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
    (values, leaked, token, call_token)
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

/// An exchange turn's own request metadata must reach the handler, and the
/// framework's transport keys must not come along for the ride.
#[tokio::test]
async fn exchange_turn_carries_user_metadata_without_framework_keys() {
    let state = build_state();
    let app = vgi_rpc::http::build_router(state.clone());
    let body = post_arrow(app, "/meta_exchange/init", init_body()).await;
    let (_values, _leaked, token, call_token) = parse_response(&body);
    let token = token.expect("/init must hand over a cursor");
    let call_token = call_token.expect("/init must hand over a call token");

    let app = vgi_rpc::http::build_router(state.clone());
    let body = post_arrow(
        app,
        "/meta_exchange/exchange",
        exchange_body(&token, &call_token, Some("etag-xyz")),
    )
    .await;
    let (values, leaked, token2, _) = parse_response(&body);

    assert_eq!(
        values,
        vec!["etag-xyz".to_string()],
        "the exchange handler must see its own request's application metadata \
         (the pipe transports deliver it from the input batch)"
    );
    assert_eq!(
        leaked,
        vec![String::new()],
        "framework transport keys (stream-state cursor, call-state, cancel) \
         must be stripped before the request metadata reaches user code"
    );

    // A turn that attaches no application metadata sees an empty map — the
    // previous turn's value is not sticky.
    let token2 = token2.expect("exchange turn re-mints a cursor");
    let app = vgi_rpc::http::build_router(state);
    let body = post_arrow(
        app,
        "/meta_exchange/exchange",
        exchange_body(&token2, &call_token, None),
    )
    .await;
    let (values, leaked, _, _) = parse_response(&body);
    assert_eq!(
        values,
        vec![String::new()],
        "an exchange turn with no user metadata must see an empty tick metadata map"
    );
    assert_eq!(leaked, vec![String::new()]);
}
