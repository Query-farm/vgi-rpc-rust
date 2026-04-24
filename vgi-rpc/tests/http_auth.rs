//! Integration test: HTTP server with bearer auth + RFC 9728 metadata.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt; // for oneshot

use vgi_rpc::auth::bearer::bearer_authenticate_static;
use vgi_rpc::auth::oauth::OAuthResourceMetadata;
use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::{AuthContext, RpcServer};

fn make_state(with_auth: bool) -> Arc<HttpState> {
    let server = Arc::new(
        RpcServer::builder()
            .server_id("it")
            .protocol_name("Test")
            .build(),
    );
    let mut b = HttpState::builder().server(server);
    if with_auth {
        let mut tokens = HashMap::new();
        tokens.insert("good".into(), AuthContext::for_principal("bearer", "alice"));
        b = b.authenticate(bearer_authenticate_static(tokens));
        b = b.oauth_resource_metadata(
            OAuthResourceMetadata::new("https://api.example.com")
                .with_authorization_server("https://issuer.example/")
                .with_scope("rpc"),
        );
    }
    b.build()
}

#[tokio::test]
async fn anonymous_request_hits_unknown_method_404() {
    let state = make_state(false);
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
    // Empty body → decompress ok, request parse fails → 400.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bearer_auth_rejects_missing_header() {
    // Install an authenticate callback that *errors* when no token is
    // present, so we can observe the 401 path.
    let server = Arc::new(RpcServer::builder().server_id("it").build());
    let state = HttpState::builder()
        .server(server)
        .authenticate(Arc::new(|req| {
            if req.header("authorization").is_some() {
                Ok(AuthContext::for_principal("bearer", "alice"))
            } else {
                Err(vgi_rpc::RpcError::new("PermissionError", "token required"))
            }
        }))
        .oauth_resource_metadata(OAuthResourceMetadata::new("https://api.example.com"))
        .build();

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
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www_auth = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(www_auth.contains("resource_metadata="));
}

#[tokio::test]
async fn oauth_well_known_served_when_configured() {
    let state = make_state(true);
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(OAuthResourceMetadata::well_known_path())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
    assert_eq!(ct, "application/json");
}

#[tokio::test]
async fn oauth_well_known_returns_404_without_metadata() {
    let state = make_state(false);
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(OAuthResourceMetadata::well_known_path())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
