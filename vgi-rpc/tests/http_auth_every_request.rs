//! `HttpStateBuilder::authenticate_every_request`: every path needs a
//! credential except `HEAD /health` and CORS preflights, and authentication
//! runs before the body is size-checked.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt; // for oneshot

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::unauthorized::AuthReason;
use vgi_rpc::{AuthContext, RpcError, RpcServer};

const CHALLENGE: &str = "Bearer error=\"invalid_token\"";

/// `good` authenticates, `down` is an outage, anything else is rejected and
/// no header leaves the caller anonymous.
fn state() -> Arc<HttpState> {
    let server = Arc::new(
        RpcServer::builder()
            .server_id("gate")
            .protocol_name("Test")
            .build(),
    );
    HttpState::builder()
        .server(server)
        .authenticate(Arc::new(|req| match req.header("authorization") {
            None => Ok(AuthContext::anonymous()),
            Some("Bearer good") => Ok(AuthContext::for_principal("test", "alice")),
            Some("Bearer down") => Err(RpcError::auth_unavailable("keys unavailable")),
            Some(_) => Err(RpcError::auth_failure(
                AuthReason::InvalidCredential,
                "bad token",
            )),
        }))
        .authenticate_every_request(true)
        .www_authenticate(CHALLENGE)
        .cors_origins("*")
        .cors_credentials(false)
        .max_request_bytes(16)
        .build()
}

async fn send(req: Request<Body>) -> axum::response::Response {
    vgi_rpc::http::build_router(state())
        .oneshot(req)
        .await
        .unwrap()
}

fn get(method: &str, uri: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::ORIGIN, "https://shell.example.com");
    if let Some(token) = auth {
        b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    b.body(Body::empty()).unwrap()
}

fn assert_401(resp: &axum::response::Response, reason: &str) {
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let h = resp.headers();
    assert_eq!(h.get(header::WWW_AUTHENTICATE).unwrap(), CHALLENGE);
    assert_eq!(h.get("vgi-auth-reason").unwrap(), reason);
    assert!(h.contains_key("vgi-supported-encodings"), "{h:?}");
    assert_eq!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
    assert!(!h.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
}

#[tokio::test]
async fn every_path_needs_a_credential() {
    for (method, uri) in [
        ("GET", "/health"),
        ("GET", "/"),
        ("GET", "/describe"),
        ("GET", "/no/such/path"),
        ("POST", "/Test/echo"),
        // OPTIONS without Access-Control-Request-Method is not a preflight.
        ("OPTIONS", "/health"),
    ] {
        let resp = send(get(method, uri, None)).await;
        assert_401(&resp, "missing_credential");
    }
}

#[tokio::test]
async fn head_health_is_anonymous() {
    let resp = send(get("HEAD", "/health", None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("vgi-supported-encodings"));
}

#[tokio::test]
async fn preflight_needs_no_credential_on_any_path() {
    for uri in ["/Test/echo", "/", "/no/such/path"] {
        let req = Request::builder()
            .method("OPTIONS")
            .uri(uri)
            .header(header::ORIGIN, "https://shell.example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
            .body(Body::empty())
            .unwrap();
        let resp = send(req).await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let h = resp.headers();
        assert_eq!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
            "authorization"
        );
    }
}

#[tokio::test]
async fn rejected_credential_is_401_invalid() {
    let resp = send(get("GET", "/health", Some("forged"))).await;
    assert_401(&resp, "invalid_credential");
}

#[tokio::test]
async fn outage_is_503_with_retry_after() {
    let resp = send(get("GET", "/health", Some("down"))).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "*"
    );
}

#[tokio::test]
async fn valid_credential_reaches_routes() {
    let resp = send(get("GET", "/health", Some("good"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn authentication_runs_before_the_size_check() {
    // Over max_request_bytes (16): without a credential the answer is 401,
    // not 413; with one, the size check applies as usual.
    let oversized = |auth: Option<&str>| {
        let mut b = Request::builder()
            .method("POST")
            .uri("/Test/echo")
            .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
            .header(header::CONTENT_LENGTH, "1024");
        if let Some(token) = auth {
            b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        b.body(Body::from(vec![0u8; 1024])).unwrap()
    };
    let resp = send(oversized(None)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = send(oversized(Some("good"))).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
#[should_panic(expected = "cors_origins")]
fn wildcard_cors_with_credentials_still_refused() {
    let server = Arc::new(RpcServer::builder().server_id("gate").build());
    HttpState::builder()
        .server(server)
        .authenticate(Arc::new(|_| Ok(AuthContext::anonymous())))
        .cors_origins("*")
        .build();
}
