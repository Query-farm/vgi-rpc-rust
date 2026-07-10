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

/// `/health` is the mandatory capability-discovery endpoint, and the C++ client
/// probes it with `HEAD`. It must not 405 (which carries no Content-Length and
/// would silently degrade discovery to defaults), and must expose the same
/// capability headers as GET so discovery is verb-independent.
#[tokio::test]
async fn health_head_returns_200_with_capabilities() {
    let caps = |resp: &axum::response::Response| -> Vec<(String, String)> {
        let mut v: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str().starts_with("vgi-"))
            .map(|(k, val)| (k.as_str().to_string(), val.to_str().unwrap().to_string()))
            .collect();
        v.sort();
        v
    };
    let request = |method: &str| {
        Request::builder()
            .method(method)
            .uri("/health")
            .body(Body::empty())
            .unwrap()
    };

    let get_resp = vgi_rpc::http::build_router(state_with(None, None, None))
        .oneshot(request("GET"))
        .await
        .unwrap();
    let head_resp = vgi_rpc::http::build_router(state_with(None, None, None))
        .oneshot(request("HEAD"))
        .await
        .unwrap();

    assert_eq!(head_resp.status(), StatusCode::OK);
    assert!(head_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("application/json"));
    assert_eq!(caps(&head_resp), caps(&get_resp));
    assert!(
        !caps(&get_resp).is_empty(),
        "GET should expose capabilities"
    );

    let get_body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let head_len = head_resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|v| v.to_str().unwrap().to_string());
    let head_body = axum::body::to_bytes(head_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(head_body.is_empty(), "HEAD carries no body");
    assert_eq!(
        head_len.as_deref(),
        Some(get_body.len().to_string().as_str())
    );
}

/// The `__upload_url__` wire contract is public, so an intermediary that
/// terminates or serves the flow needn't copy the method name or schemas.
#[test]
fn upload_url_contract_is_exported() {
    assert_eq!(vgi_rpc::UPLOAD_URL_METHOD, "__upload_url__");
    assert_eq!(vgi_rpc::MAX_UPLOAD_URL_COUNT, 100);
    let params = vgi_rpc::upload_url_params_schema();
    assert_eq!(
        params
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .collect::<Vec<_>>(),
        ["count"]
    );
    let response = vgi_rpc::upload_url_response_schema();
    assert_eq!(
        response
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .collect::<Vec<_>>(),
        ["upload_url", "download_url", "expires_at"]
    );
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

/// Minimal `HttpState` with a one-method server, configured by `f`.
fn state_configured(
    f: impl FnOnce(vgi_rpc::http::HttpStateBuilder) -> vgi_rpc::http::HttpStateBuilder,
) -> Arc<HttpState> {
    let mut srv = RpcServer::builder().server_id("it").build();
    srv.register(MethodInfo::unary(
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
    ));
    f(HttpState::builder().server(Arc::new(srv))).build()
}

#[tokio::test]
async fn oversize_request_body_is_rejected_by_body_limit() {
    // The body-limit layer enforces `max_body_size` on the raw bytes,
    // independent of `Content-Length` — a 4 KiB body against a 16-byte
    // limit must be refused before the handler runs.
    let state = state_configured(|b| b.max_body_size(16));
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/echo_string")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(vec![0u8; 4096]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn small_response_under_soft_cap_is_not_rejected() {
    // `max_response_bytes` is a *soft* producer-side cap — a normal
    // response (here, a small Arrow error stream) that happens to be
    // larger than the soft cap must NOT be turned into a 500 by the
    // post-processing middleware. The middleware's hard ceiling is
    // separate and far higher; see `response_buffer_ceiling`.
    let state = state_configured(|b| b.max_response_bytes(8));
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/echo_string")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(vec![]))
                .unwrap(),
        )
        .await
        .unwrap();
    // Empty body → request parse error → 400 (NOT a 500 from the
    // middleware buffer cap).
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
