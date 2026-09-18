//! `vgi_rpc.Identity.v1` over HTTP.
//!
//! HTTP is the transport the protocol exists for -- a reverse proxy that
//! terminates the only public listener and has to resolve an opaque credential
//! before it can authorize anything. The byte-stream path is covered in
//! `identity_protocol.rs`; what is asserted here is that the same binding is
//! reachable over HTTP, that it is addressed by the *routing key* rather than
//! by the URL path (so an application method named `introspect_token` is a
//! different method), that a worker that configured no hook grows no route, and
//! that the retired `__introspect_token__` JSON route is gone -- `Identity.v1`
//! is the only introspection surface (cross-port spec §8).

use std::io::Cursor;
use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt; // for oneshot

use vgi_rpc::http::HttpState;
use vgi_rpc::metadata::{
    ERROR_KIND_KEY, LOG_LEVEL_KEY, PROTOCOL_KEY, REQUEST_ID_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::token_identity::{
    IdentityImpl, TokenIdentity, IDENTITY_PROTOCOL_NAME, INTROSPECT_TOKEN_METHOD,
};
use vgi_rpc::wire::{Metadata, StreamReader, StreamWriter};
use vgi_rpc::{AuthContext, RpcServer};

const INTROSPECTOR: &str = "proxy@example";
const SUBJECT: &str = "opaque-subject-token";
const PRINCIPAL_HEADER: &str = "x-conformance-principal";

fn principal_from_header(req: &vgi_rpc::AuthRequest) -> vgi_rpc::AuthResult {
    Ok(match req.header(PRINCIPAL_HEADER) {
        Some(p) if !p.is_empty() => AuthContext::for_principal("test", p),
        _ => AuthContext::anonymous(),
    })
}

fn resolver() -> vgi_rpc::token_identity::TokenResolver {
    Arc::new(|token: &str| {
        Ok((token == SUBJECT)
            .then(|| TokenIdentity::new("subject@example").with_token_name("laptop")))
    })
}

fn state(identity: Option<IdentityImpl>) -> Arc<HttpState> {
    let mut builder = RpcServer::builder().server_id("it").protocol_name("Test");
    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }
    HttpState::builder()
        .server(Arc::new(builder.build()))
        .authenticate(Arc::new(principal_from_header))
        .build()
}

fn introspecting_state() -> Arc<HttpState> {
    state(Some(
        IdentityImpl::builder()
            .resolve_token(resolver())
            .introspect_principals([INTROSPECTOR])
            .build(),
    ))
}

/// A framed `introspect_token` request body.
fn request_body(protocol: &str, token: &str) -> Vec<u8> {
    let batch = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new(
            "token",
            DataType::Utf8,
            false,
        )])),
        vec![Arc::new(StringArray::from(vec![token])) as ArrayRef],
    )
    .unwrap();
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, batch.schema_ref()).unwrap();
        let mut md = Metadata::new();
        md.insert(RPC_METHOD_KEY.into(), INTROSPECT_TOKEN_METHOD.into());
        md.insert(PROTOCOL_KEY.into(), protocol.into());
        md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
        md.insert(REQUEST_ID_KEY.into(), "req-1".into());
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

async fn post(
    state: Arc<HttpState>,
    caller: Option<&str>,
    protocol: &str,
) -> (
    StatusCode,
    Vec<(RecordBatch, std::collections::HashMap<String, String>)>,
) {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/{INTROSPECT_TOKEN_METHOD}"))
        .header(header::CONTENT_TYPE, "application/vnd.apache.arrow.stream");
    if let Some(c) = caller {
        req = req.header(PRINCIPAL_HEADER, c);
    }
    let resp = vgi_rpc::http::build_router(state)
        .oneshot(
            req.body(Body::from(request_body(protocol, SUBJECT)))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let mut frames = Vec::new();
    if let Ok(mut reader) = StreamReader::new(&mut Cursor::new(bytes.to_vec())) {
        while let Ok(Some(frame)) = reader.read_next() {
            frames.push(frame);
        }
    }
    (status, frames)
}

fn payload(frames: &[(RecordBatch, std::collections::HashMap<String, String>)]) -> RecordBatch {
    let batch = frames
        .iter()
        .map(|(b, _)| b)
        .find(|b| b.num_rows() > 0)
        .expect("a result batch");
    let col = batch
        .column_by_name("result")
        .expect("the result column")
        .as_any()
        .downcast_ref::<arrow_array::BinaryArray>()
        .unwrap();
    let mut cursor = Cursor::new(col.value(0).to_vec());
    let mut reader = StreamReader::new(&mut cursor).unwrap();
    reader.read_next().unwrap().unwrap().0
}

fn error_kind(
    frames: &[(RecordBatch, std::collections::HashMap<String, String>)],
) -> Option<String> {
    frames
        .iter()
        .find(|(_, md)| md.get(LOG_LEVEL_KEY).map(String::as_str) == Some("EXCEPTION"))
        .and_then(|(_, md)| md.get(ERROR_KIND_KEY).cloned())
}

/// The case the protocol exists for: a fronting proxy resolving a credential
/// it holds no local copy of.
#[tokio::test]
async fn an_allowlisted_proxy_resolves_over_http() {
    let (status, frames) = post(
        introspecting_state(),
        Some(INTROSPECTOR),
        IDENTITY_PROTOCOL_NAME,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(error_kind(&frames), None, "{frames:?}");
    let payload = payload(&frames);
    let principal = payload
        .column_by_name("principal")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .value(0);
    assert_eq!(principal, "subject@example");
}

/// Authentication is not introspection: a caller the worker authenticated but
/// did not allowlist learns nothing about the subject.
#[tokio::test]
async fn a_caller_off_the_allowlist_is_refused_over_http() {
    let (_status, frames) = post(
        introspecting_state(),
        Some("someone-else"),
        IDENTITY_PROTOCOL_NAME,
    )
    .await;
    assert_eq!(
        error_kind(&frames).as_deref(),
        Some("introspection_refused")
    );
}

/// The protocol is addressed by the routing key, not the URL path. A request
/// that names the *application* protocol is asking for an application method
/// called `introspect_token`, which does not exist -- so identity cannot be
/// reached by accident, nor shadowed by an application that declares the name.
#[tokio::test]
async fn the_routing_key_selects_the_protocol_not_the_path() {
    let (status, _frames) = post(introspecting_state(), Some(INTROSPECTOR), "Test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A worker that configured no hook grows no route: upgrading a dependency
/// must not add a credential-to-identity oracle to an existing deployment.
#[tokio::test]
async fn an_unconfigured_worker_hosts_nothing() {
    let (status, _frames) = post(state(None), Some(INTROSPECTOR), IDENTITY_PROTOCOL_NAME).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The pre-0.46 JSON route is retired, not merely unadvertised: a worker that
/// *does* resolve credentials must not answer it, and must not consult its
/// resolver for it. Two surfaces meant two sets of guards to keep identical,
/// and the second had already drifted -- it kept a rate limiter after the
/// protocol dropped one.
///
/// The resolver here resolves everything and counts its calls, so a route that
/// quietly survived would show up as a resolution or as a call, not hide
/// behind a rejection that reads the same either way.
#[tokio::test]
async fn the_retired_json_route_is_not_served() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let state = state(Some(
        IdentityImpl::builder()
            .resolve_token(Arc::new(move |_: &str| {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Some(TokenIdentity::new("subject@example")))
            }))
            .introspect_principals([INTROSPECTOR])
            .build(),
    ));
    let resp = vgi_rpc::http::build_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/__introspect_token__")
                .header(header::CONTENT_TYPE, "application/json")
                .header(PRINCIPAL_HEADER, INTROSPECTOR)
                .body(Body::from(
                    serde_json::json!({ "token": SUBJECT }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        status.is_client_error(),
        "POST /__introspect_token__ answered {status}: {body}"
    );
    assert!(
        !body.contains("subject@example") && !body.contains("ttl_seconds"),
        "the retired route answered with an identity: {body}"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the retired route consulted the resolver"
    );
}

/// Its capability header went with it. A client learns whether a worker
/// introspects from reflection (`vgi_rpc.Identity.v1` hosted), which is what
/// the reference and the conformance group use; a stale advert would send a
/// proxy's preflight to a route that no longer exists.
#[tokio::test]
async fn health_does_not_advertise_the_retired_route() {
    let state = HttpState::builder()
        .server(Arc::new(
            RpcServer::builder()
                .server_id("it")
                .protocol_name("Test")
                .identity(
                    IdentityImpl::builder()
                        .resolve_token(resolver())
                        .introspect_principals([INTROSPECTOR])
                        .build(),
                )
                .build(),
        ))
        .authenticate(Arc::new(principal_from_header))
        .cors_origins("https://proxy.example")
        .build();
    for method in ["OPTIONS", "GET"] {
        let resp = vgi_rpc::http::build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/health")
                    .header(header::ORIGIN, "https://proxy.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.headers().get("vgi-token-introspection").is_none(),
            "{method} /health still advertises the retired route"
        );
        let exposed = resp
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            !exposed.contains("vgi-token-introspection"),
            "{method} /health still exposes the retired header: {exposed}"
        );
    }
}
