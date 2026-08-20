//! HTTP dispatch must enforce the same application protocol-version boundary
//! as the pipe and unix transports.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use arrow_schema::Schema;
use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{
    LOG_EXTRA_KEY, LOG_LEVEL_KEY, PROTOCOL_VERSION_KEY, REQUEST_ID_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::server::MethodType;
use vgi_rpc::wire::{empty_batch, md_get, write_one_batch, StreamReader};
use vgi_rpc::{MethodInfo, RpcServer};

fn request_body(method: &str, protocol_version: &str) -> Vec<u8> {
    let batch = empty_batch(&Schema::empty()).unwrap();
    let md = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "version-req".to_string()),
        (
            PROTOCOL_VERSION_KEY.to_string(),
            protocol_version.to_string(),
        ),
    ]);
    write_one_batch(&batch, Some(&md)).unwrap()
}

fn assert_version_error(body: &[u8]) {
    let mut reader = StreamReader::new(body).expect("response is an Arrow stream");
    let mut saw_version_error = false;
    while let Some((_batch, md)) = reader.read_next().expect("readable response") {
        if md_get(&md, LOG_LEVEL_KEY) == Some("EXCEPTION") {
            let extra: serde_json::Value = serde_json::from_str(
                md_get(&md, LOG_EXTRA_KEY).expect("exception metadata has details"),
            )
            .unwrap();
            saw_version_error = extra["exception_type"] == "VersionError";
        }
    }
    assert!(saw_version_error, "expected a structured VersionError");
}

fn versioned_server(
    unary_called: Arc<AtomicBool>,
    stream_called: Arc<AtomicBool>,
) -> Arc<RpcServer> {
    let mut server = RpcServer::builder()
        .server_id("versioned")
        .protocol_version("2.4")
        .build();
    server.register(MethodInfo::unary(
        "unary",
        Schema::empty().into(),
        Schema::empty().into(),
        move |_req, _ctx| {
            unary_called.store(true, Ordering::SeqCst);
            Ok(None)
        },
    ));
    server.register(MethodInfo::stream(
        "stream",
        MethodType::Producer,
        Schema::empty().into(),
        move |_req, _ctx| {
            stream_called.store(true, Ordering::SeqCst);
            panic!("version validation should run before stream init")
        },
    ));
    Arc::new(server)
}

async fn post(state: Arc<HttpState>, path: &str, body: Vec<u8>) -> axum::response::Response {
    vgi_rpc::http::build_router(state)
        .oneshot(
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

#[tokio::test]
async fn incompatible_major_is_rejected_before_unary_dispatch() {
    let unary_called = Arc::new(AtomicBool::new(false));
    let stream_called = Arc::new(AtomicBool::new(false));
    let state = HttpState::builder()
        .server(versioned_server(unary_called.clone(), stream_called))
        .build();

    let response = post(state, "/unary", request_body("unary", "1.9")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!unary_called.load(Ordering::SeqCst));
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_version_error(&body);
}

#[tokio::test]
async fn incompatible_major_is_rejected_before_stream_init() {
    let unary_called = Arc::new(AtomicBool::new(false));
    let stream_called = Arc::new(AtomicBool::new(false));
    let state = HttpState::builder()
        .server(versioned_server(unary_called, stream_called.clone()))
        .build();

    let response = post(state, "/stream/init", request_body("stream", "3.0")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!stream_called.load(Ordering::SeqCst));
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_version_error(&body);
}

#[tokio::test]
async fn compatible_major_reaches_http_dispatch() {
    let unary_called = Arc::new(AtomicBool::new(false));
    let stream_called = Arc::new(AtomicBool::new(false));
    let state = HttpState::builder()
        .server(versioned_server(unary_called.clone(), stream_called))
        .build();

    let response = post(state, "/unary", request_body("unary", "2.99")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(unary_called.load(Ordering::SeqCst));
}
