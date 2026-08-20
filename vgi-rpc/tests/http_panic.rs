//! Integration test: a handler panic over the HTTP transport must be isolated
//! into the structured Arrow error envelope (HTTP 200 + an `EXCEPTION` metadata
//! batch), matching the stdio/unix serve loop — NOT bubble up to the
//! `CatchPanicLayer` as a bare 500 the DuckDB client can't parse as a VGI error.

use std::sync::Arc;

use arrow_schema::Schema;
use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{
    CALL_STATE_KEY, CANCEL_KEY, LOG_LEVEL_KEY, REQUEST_ID_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY, STATE_KEY,
};
use vgi_rpc::server::{MethodType, StateDecoder};
use vgi_rpc::stream::{
    ExchangeState, OutputCollector, ProducerState, StreamResult, StreamStateKind,
};
use vgi_rpc::wire::{empty_batch, md_get, write_one_batch, StreamReader};
use vgi_rpc::{CallContext, MethodInfo, Result, RpcServer};

/// Build a minimal arrow request body addressed to `method` (empty input batch).
fn request_body(method: &str) -> Vec<u8> {
    let empty = empty_batch(&Schema::empty()).unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "panic-req".to_string()),
    ]);
    write_one_batch(&empty, Some(&md)).unwrap()
}

fn server_with_panicking(method: &str, kind: MethodType) -> Arc<RpcServer> {
    let mut srv = RpcServer::builder().server_id("it").build();
    match kind {
        MethodType::Unary => srv.register(MethodInfo::unary(
            method,
            Schema::empty().into(),
            Schema::empty().into(),
            |_req, _ctx| panic!("unary handler exploded"),
        )),
        _ => srv.register(MethodInfo::stream(
            method,
            kind,
            Schema::empty().into(),
            |_req, _ctx| panic!("stream handler exploded"),
        )),
    }
    Arc::new(srv)
}

struct PanickingProducer;

impl ProducerState for PanickingProducer {
    fn produce(&mut self, _out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        panic!("producer turn exploded")
    }
}

fn server_with_panicking_producer() -> Arc<RpcServer> {
    let mut server = RpcServer::builder().server_id("it").build();
    server.register(MethodInfo::stream(
        "producer_boom",
        MethodType::Producer,
        Schema::empty().into(),
        |_req, _ctx| {
            Ok(StreamResult::producer(
                Schema::empty().into(),
                Box::new(PanickingProducer),
            ))
        },
    ));
    Arc::new(server)
}

struct PanickingExchange;

impl ExchangeState for PanickingExchange {
    fn exchange(
        &mut self,
        _input: &arrow_array::RecordBatch,
        _out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        panic!("exchange turn exploded")
    }

    fn on_cancel(&mut self, _ctx: &CallContext) {
        panic!("cancel callback exploded")
    }

    fn encode_state(&self) -> Result<Vec<u8>> {
        Ok(vec![1])
    }
}

fn exchange_decoder() -> StateDecoder {
    Arc::new(|bytes: &[u8]| {
        assert_eq!(bytes, [1]);
        Ok(StreamStateKind::Exchange(Box::new(PanickingExchange)))
    })
}

fn server_with_panicking_exchange() -> Arc<RpcServer> {
    let mut server = RpcServer::builder().server_id("it").build();
    server.register(
        MethodInfo::stream(
            "exchange_boom",
            MethodType::Exchange,
            Schema::empty().into(),
            |_req, _ctx| {
                Ok(StreamResult::exchange(
                    Schema::empty().into(),
                    Schema::empty().into(),
                    Box::new(PanickingExchange),
                ))
            },
        )
        .with_state_decoder(exchange_decoder()),
    );
    Arc::new(server)
}

fn continuation_body(token: &str, call_token: &str, cancel: bool) -> Vec<u8> {
    let empty = empty_batch(&Schema::empty()).unwrap();
    let mut md = std::collections::HashMap::<String, String>::from([
        (STATE_KEY.to_string(), token.to_string()),
        (CALL_STATE_KEY.to_string(), call_token.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "panic-cont".to_string()),
    ]);
    if cancel {
        md.insert(CANCEL_KEY.to_string(), "1".to_string());
    }
    write_one_batch(&empty, Some(&md)).unwrap()
}

fn continuation_tokens(body: &[u8]) -> (String, String) {
    let mut reader = StreamReader::new(body).unwrap();
    while let Some((_batch, md)) = reader.read_next().unwrap() {
        if let (Some(token), Some(call_token)) =
            (md_get(&md, STATE_KEY), md_get(&md, CALL_STATE_KEY))
        {
            return (token.to_string(), call_token.to_string());
        }
    }
    panic!("stream init did not return continuation tokens")
}

async fn post(app: axum::Router, path: &str, body: Vec<u8>) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn open_panicking_exchange(app: axum::Router) -> (String, String) {
    let response = post(app, "/exchange_boom/init", request_body("exchange_boom")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    continuation_tokens(&body)
}

/// Assert the body is a structured error envelope (an EXCEPTION metadata batch),
/// proving the panic was converted to an `RpcError`, not dropped as a raw 500.
fn assert_error_envelope(body: &[u8]) {
    let mut r = StreamReader::new(body).expect("response is a valid arrow stream");
    let mut saw_exception = false;
    while let Some((_batch, md)) = r.read_next().expect("readable batch") {
        if md_get(&md, LOG_LEVEL_KEY) == Some("EXCEPTION") {
            saw_exception = true;
        }
    }
    assert!(
        saw_exception,
        "expected an EXCEPTION error envelope from the panicking handler"
    );
}

#[tokio::test]
async fn unary_handler_panic_yields_structured_error_not_500() {
    let state = HttpState::builder()
        .server(server_with_panicking("boom", MethodType::Unary))
        .build();
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/boom")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(request_body("boom")))
                .unwrap(),
        )
        .await
        .unwrap();

    // The panic is surfaced as a structured envelope at HTTP 200, NOT a
    // CatchPanicLayer 500.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "panic should be an arrow error envelope, not a bare 500"
    );
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_error_envelope(&body);
}

#[tokio::test]
async fn stream_init_handler_panic_yields_structured_error_not_500() {
    let state = HttpState::builder()
        .server(server_with_panicking("flow", MethodType::Dynamic))
        .build();
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/flow/init")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(request_body("flow")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "stream-init panic should be an arrow error envelope, not a bare 500"
    );
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_error_envelope(&body);
}

#[tokio::test]
async fn producer_turn_panic_yields_structured_error_not_500() {
    let state = HttpState::builder()
        .server(server_with_panicking_producer())
        .build();
    let response = post(
        vgi_rpc::http::build_router(state),
        "/producer_boom/init",
        request_body("producer_boom"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_error_envelope(&body);
}

#[tokio::test]
async fn exchange_turn_panic_yields_structured_error_not_500() {
    let state = HttpState::builder()
        .server(server_with_panicking_exchange())
        .build();
    let app = vgi_rpc::http::build_router(state);
    let (token, call_token) = open_panicking_exchange(app.clone()).await;
    let response = post(
        app,
        "/exchange_boom/exchange",
        continuation_body(&token, &call_token, false),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_error_envelope(&body);
}

#[tokio::test]
async fn cancellation_panic_yields_structured_error_not_500() {
    let state = HttpState::builder()
        .server(server_with_panicking_exchange())
        .build();
    let app = vgi_rpc::http::build_router(state);
    let (token, call_token) = open_panicking_exchange(app.clone()).await;
    let response = post(
        app,
        "/exchange_boom/exchange",
        continuation_body(&token, &call_token, true),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_error_envelope(&body);
}
