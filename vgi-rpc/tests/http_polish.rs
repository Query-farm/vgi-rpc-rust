//! Integration tests: CORS, health endpoint, landing/describe pages,
//! URL prefix mounting, and zstd response compression.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::{MethodInfo, RpcServer};

fn state_with(
    cors: Option<&str>,
    prefix: Option<&str>,
    compression: Option<i32>,
) -> Arc<HttpState> {
    let mut srv = RpcServer::builder()
        .server_id("it")
        .protocol_name("Test")
        .enable_describe(true)
        .build();
    srv.register(
        MethodInfo::unary(
            "echo_string",
            arrow_schema::Schema::new(vec![arrow_schema::Field::new(
                "value",
                arrow_schema::DataType::Utf8,
                false,
            )])
            .into(),
            arrow_schema::Schema::new(vec![arrow_schema::Field::new(
                "result",
                arrow_schema::DataType::Utf8,
                false,
            )])
            .into(),
            |_req, _| Ok(None),
        )
        .doc("stub echo")
        .param_type("value", "str"),
    );
    let mut b = HttpState::builder().server(Arc::new(srv));
    if let Some(o) = cors {
        b = b.cors_origins(o);
    }
    if let Some(p) = prefix {
        b = b.prefix(p);
    }
    if let Some(l) = compression {
        b = b.response_compression_level(l);
    }
    b.build()
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let state = state_with(None, None, None);
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn preflight_includes_cors_headers() {
    let state = state_with(Some("https://app.example.com"), None, None);
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/echo_string")
                .header(header::ORIGIN, "https://app.example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let allow = resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .unwrap();
    assert_eq!(allow, "https://app.example.com");
    assert!(resp.headers().contains_key(header::ACCESS_CONTROL_MAX_AGE));
}

#[tokio::test]
async fn prefix_mounts_routes_under_path() {
    let state = state_with(None, Some("/v1"), None);
    let app = vgi_rpc::http::build_router(state);
    // /health is always at the absolute root regardless of API prefix —
    // load balancers and orchestrators should never have to know which
    // prefix the API is under, and the conformance suite enforces this.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // The prefixed path does NOT serve /health (the route lives at root).
    // The prefix path may match the API router pattern `:method` and
    // return 405 (Method Not Allowed for GET) rather than 404 — either
    // is correct as long as it isn't 200.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() != StatusCode::OK,
        "/v1/health must NOT be the health endpoint when prefix=/v1"
    );
}

#[tokio::test]
async fn describe_html_page_served() {
    let state = state_with(None, None, None);
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/describe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
    assert!(ct.to_str().unwrap().starts_with("text/html"));
}

#[tokio::test]
async fn compression_emits_zstd_encoded_response_on_error() {
    let state = state_with(None, None, Some(3));
    let app = vgi_rpc::http::build_router(state);
    // Send a request missing Content-Type to force an error body; the
    // response is an Arrow error stream which exercises the compression path.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/echo_string")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .header(header::ACCEPT_ENCODING, "zstd")
                .body(Body::from(vec![]))
                .unwrap(),
        )
        .await
        .unwrap();
    // Empty body parses as an error — we expect a 400 with arrow content.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let ce = resp.headers().get(header::CONTENT_ENCODING);
    assert_eq!(ce.map(|v| v.to_str().unwrap()), Some("zstd"));
}
