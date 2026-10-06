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
        .protocol_version("2.4.0")
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
                .uri(format!("/Service{path}"))
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

    let response = post(state, "/unary", request_body("unary", "1.9.0")).await;
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

    let response = post(state, "/stream/init", request_body("stream", "3.0.0")).await;
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

    // Patch is ignored: major and minor are what must match.
    let response = post(state, "/unary", request_body("unary", "2.4.99")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(unary_called.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_minor_mismatch_is_rejected_too() {
    let unary_called = Arc::new(AtomicBool::new(false));
    let stream_called = Arc::new(AtomicBool::new(false));
    let state = HttpState::builder()
        .server(versioned_server(unary_called.clone(), stream_called))
        .build();

    let response = post(state, "/unary", request_body("unary", "2.5.0")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!unary_called.load(Ordering::SeqCst));
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_version_error(&body);
}

/// No protocol in the path is no route (WIRE_PROTOCOL.md §3.1): a flat
/// `/{method}` POST is refused with `protocol_not_specified` /
/// `INVALID_ARGUMENT` and never reaches the handler -- even though the method
/// exists on the primary and the version is right. The flat stream routes are
/// gone too: `/{method}/init` is a unary call to `init` on protocol `{method}`.
#[tokio::test]
async fn an_unrouted_request_is_refused_with_protocol_not_specified() {
    use vgi_rpc::metadata::{ERROR_CODE_KEY, ERROR_KIND_KEY};
    let unary_called = Arc::new(AtomicBool::new(false));
    let stream_called = Arc::new(AtomicBool::new(false));
    let state = HttpState::builder()
        .server(versioned_server(
            unary_called.clone(),
            stream_called.clone(),
        ))
        .build();
    let error_of = |body: &[u8]| {
        let mut reader = StreamReader::new(body).expect("response is an Arrow stream");
        let mut found = None;
        while let Some((_b, md)) = reader.read_next().unwrap() {
            if md_get(&md, LOG_LEVEL_KEY) == Some("EXCEPTION") {
                found = Some((
                    md_get(&md, ERROR_KIND_KEY).unwrap_or("").to_string(),
                    md_get(&md, ERROR_CODE_KEY).unwrap_or("").to_string(),
                ));
            }
        }
        found.expect("an EXCEPTION batch")
    };

    let response = vgi_rpc::http::build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/unary")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(request_body("unary", "2.4.0")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        error_of(&body),
        (
            "protocol_not_specified".to_string(),
            "INVALID_ARGUMENT".to_string()
        )
    );
    assert!(
        !unary_called.load(Ordering::SeqCst),
        "an unrouted request reached the handler"
    );

    // The path is the routing carrier a proxy or WAF sees: a flat path is
    // refused even when the request's metadata names a hosted protocol.
    let keyed = std::collections::HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), "unary".to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (PROTOCOL_VERSION_KEY.to_string(), "2.4.0".to_string()),
        (
            vgi_rpc::metadata::PROTOCOL_KEY.to_string(),
            "Service".to_string(),
        ),
    ]);
    let keyed_body =
        write_one_batch(&empty_batch(&Schema::empty()).unwrap(), Some(&keyed)).unwrap();
    let response = vgi_rpc::http::build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/unary")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(keyed_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(error_of(&body).0, "protocol_not_specified");
    assert!(
        !unary_called.load(Ordering::SeqCst),
        "a flat path reached the handler"
    );

    let response = vgi_rpc::http::build_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/stream/init")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(request_body("init", "2.4.0")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(!stream_called.load(Ordering::SeqCst));
}
