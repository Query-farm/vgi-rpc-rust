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
    LOG_LEVEL_KEY, REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::server::MethodType;
use vgi_rpc::wire::{empty_batch, md_get, write_one_batch, StreamReader};
use vgi_rpc::{MethodInfo, RpcServer};

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
