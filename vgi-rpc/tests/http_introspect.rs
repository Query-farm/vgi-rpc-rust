//! Integration test: `POST {prefix}/__introspect_token__`.
//!
//! The shared conformance group (`TestTokenIntrospection` /
//! `TestTokenIntrospectionOffMode`) covers the wire contract. What is asserted
//! here is what a black-box HTTP group structurally cannot see: that the route
//! stays definitive with no resolver configured, that the capability advert
//! reaches the CORS expose list, and — the one that matters most — that a
//! transient failure surfaces as `503` rather than being flattened into the
//! `401`/`404` a caller is entitled to negative-cache.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt; // for oneshot

use vgi_rpc::auth::introspect::{TokenIdentity, INTROSPECT_ENABLED_HEADER};
use vgi_rpc::http::HttpState;
use vgi_rpc::{AuthContext, RpcError, RpcServer};

const INTROSPECTOR: &str = "proxy@example";
const SUBJECT_TOKEN: &str = "opaque-subject-token";
const PRINCIPAL_HEADER: &str = "x-conformance-principal";

fn server() -> Arc<RpcServer> {
    Arc::new(
        RpcServer::builder()
            .server_id("it")
            .protocol_name("Test")
            .build(),
    )
}

/// Resolve the caller from a header. Not authentication — just two
/// distinguishable identities, which is all the allowlist needs to be checked.
fn principal_from_header(req: &vgi_rpc::AuthRequest) -> vgi_rpc::AuthResult {
    Ok(match req.header(PRINCIPAL_HEADER) {
        Some(p) if !p.is_empty() => AuthContext::for_principal("test", p),
        _ => AuthContext::anonymous(),
    })
}

fn enabled_state(resolver: vgi_rpc::auth::introspect::TokenResolver) -> Arc<HttpState> {
    HttpState::builder()
        .server(server())
        .authenticate(Arc::new(principal_from_header))
        .introspect_resolver(resolver)
        .introspect_principals([INTROSPECTOR])
        .build()
}

fn resolving_state() -> Arc<HttpState> {
    enabled_state(Arc::new(|token: &str| {
        Ok((token == SUBJECT_TOKEN)
            .then(|| TokenIdentity::new("subject@example").with_token_name("laptop")))
    }))
}

async fn post_as(state: Arc<HttpState>, caller: Option<&str>, token: &str) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/__introspect_token__")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(c) = caller {
        req = req.header(PRINCIPAL_HEADER, c);
    }
    let body = serde_json::json!({ "token": token }).to_string();
    let resp = vgi_rpc::http::build_router(state)
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn a_worker_without_a_resolver_refuses_definitively() {
    // Tier-one requirement, and the reason the route is mounted at all: a
    // caller classifying 401/403/404 as final and everything else as transient
    // would retry the generic route's 415 forever against a worker that is
    // never going to support the feature.
    let state = HttpState::builder().server(server()).build();
    let (status, body) = post_as(state, Some(INTROSPECTOR), SUBJECT_TOKEN).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("not_enabled"), "{body}");
}

#[tokio::test]
async fn the_capability_is_advertised_and_exposed_only_when_enabled() {
    // The Rust expose list is derived from the live capability map, so this
    // also proves the advert reaches a browser rather than only a curl — the
    // header may as well not exist to a `fetch()` client that cannot read it.
    // Both workers grant an origin, since the expose list only rides a CORS
    // response at all.
    let origin = "https://proxy.example";
    let on = HttpState::builder()
        .server(server())
        .authenticate(Arc::new(principal_from_header))
        .cors_origins(origin)
        .introspect_resolver(Arc::new(|_: &str| Ok(None)))
        .introspect_principals([INTROSPECTOR])
        .build();
    let off = HttpState::builder()
        .server(server())
        .cors_origins(origin)
        .build();
    for (state, want) in [(on, true), (off, false)] {
        let resp = vgi_rpc::http::build_router(state)
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let advertised = resp.headers().get(INTROSPECT_ENABLED_HEADER);
        let exposed = resp
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains(INTROSPECT_ENABLED_HEADER);
        if want {
            assert_eq!(advertised.and_then(|v| v.to_str().ok()), Some("true"));
            assert!(exposed, "capability advertised but not CORS-exposed");
        } else {
            assert!(advertised.is_none(), "advertised without a resolver");
            assert!(!exposed);
        }
    }
}

#[tokio::test]
async fn a_resolver_outage_is_503_not_a_cacheable_rejection() {
    // The whole definitive/transient split: 404 here would have the caller
    // negative-cache an outage, so a worker restart takes the fleet down for
    // the cache's lifetime.
    let state = enabled_state(Arc::new(|_: &str| {
        Err(RpcError::auth_unavailable("token store unreachable").with_retry_after(11))
    }));
    let router = vgi_rpc::http::build_router(state);
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/__introspect_token__")
                .header(header::CONTENT_TYPE, "application/json")
                .header(PRINCIPAL_HEADER, INTROSPECTOR)
                .body(Body::from(
                    serde_json::json!({ "token": SUBJECT_TOKEN }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers().get(header::RETRY_AFTER).unwrap(),
        "11",
        "without Retry-After a caller has no basis for when to try again"
    );
}

#[tokio::test]
async fn a_transient_authenticator_failure_is_not_a_401() {
    // The failure mode the reference's `AuthUnavailableError` exists to stop:
    // an authority that is merely down reaching the caller as "your credential
    // is bad", which makes every client re-authenticate at once. Driven
    // through the chain combinator, since that is where the reference's
    // equivalent used to lose the distinction.
    let down: vgi_rpc::Authenticate = Arc::new(|_| Err(RpcError::auth_unavailable("jwks down")));
    let fallback: vgi_rpc::Authenticate =
        Arc::new(|_| Ok(AuthContext::for_principal("test", INTROSPECTOR)));
    let state = HttpState::builder()
        .server(server())
        .authenticate(vgi_rpc::chain_all([down, fallback]).unwrap())
        .build();
    let resp = vgi_rpc::http::build_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/echo_string")
                .header(header::CONTENT_TYPE, vgi_rpc::http::ARROW_CONTENT_TYPE)
                .body(Body::from(vec![]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an outage was reported as a credential rejection"
    );
    assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "5");
}

#[tokio::test]
async fn the_response_is_a_closed_set_of_three_keys() {
    let (status, body) = post_as(resolving_state(), Some(INTROSPECTOR), SUBJECT_TOKEN).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let keys: Vec<&str> = parsed
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    assert_eq!(keys, ["principal", "token_name", "ttl_seconds"]);
    assert_eq!(parsed["principal"], "subject@example");
    assert_eq!(parsed["ttl_seconds"], 300);
}

#[tokio::test]
async fn rejections_are_byte_identical_and_never_echo_the_credential() {
    let state = resolving_state();
    let (unknown_status, unknown_body) =
        post_as(state.clone(), Some(INTROSPECTOR), "no-such-credential").await;
    for probe in ["expired-credential", "!!malformed!!", "a.b.c"] {
        let (status, body) = post_as(state.clone(), Some(INTROSPECTOR), probe).await;
        assert_eq!(status, unknown_status);
        assert_eq!(
            body, unknown_body,
            "rejection for {probe} is distinguishable"
        );
        assert!(!body.contains(probe));
    }
    // The caller check runs before anything reads the subject, so a
    // non-introspector cannot even learn whether the credential resolves.
    for caller in [None, Some("someone-else")] {
        let (status, body) = post_as(state.clone(), caller, SUBJECT_TOKEN).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!body.contains("subject@example"));
    }
}

#[test]
#[should_panic(expected = "at least one principal")]
fn enabling_the_route_without_an_allowlist_fails_at_construction() {
    // No permissive default: "any authenticated caller" is the configuration
    // that turns this into an open oracle, so it must not be reachable by
    // omission — and a misconfiguration must fail at boot, not at the first
    // proxy preflight.
    let _ = HttpState::builder()
        .server(server())
        .introspect_resolver(Arc::new(|_: &str| Ok(None)))
        .build();
}

#[test]
#[should_panic(expected = "without introspect_resolver")]
fn an_allowlist_without_a_resolver_is_a_configuration_error() {
    let _ = HttpState::builder()
        .server(server())
        .introspect_principals([INTROSPECTOR])
        .build();
}
