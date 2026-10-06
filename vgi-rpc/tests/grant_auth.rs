//! Sealed grants close the `vgi_rpc.Identity.v1` loop over HTTP
//! (IDENTITY_V1_SPEC §9): `issue_grant` mints, and the minted token then
//! authenticates an ordinary call as its owner. Also pins the configuration
//! rules: grant keys host `issue_grant` alone, and keys beside an identity
//! built without them refuse to start.

use std::io::Cursor;
use std::sync::Arc;

use arrow_array::{ArrayRef, BinaryArray, Int64Array, RecordBatch, StringArray};
use arrow_schema::Schema;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use vgi_rpc::conformance_identity::{whoami_protocol, WHOAMI_PROTOCOL_NAME};
use vgi_rpc::grants::GrantKeys;
use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{
    ERROR_KIND_KEY, LOG_LEVEL_KEY, PROTOCOL_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY,
    RPC_METHOD_KEY,
};
use vgi_rpc::server::GrantKeysSetting;
use vgi_rpc::token_identity::{issue_grant_params_schema, IdentityImpl, IDENTITY_PROTOCOL_NAME};
use vgi_rpc::wire::{Metadata, StreamReader, StreamWriter};
use vgi_rpc::{AuthContext, RpcServer};

const PRINCIPAL_HEADER: &str = "x-test-principal";

fn keys() -> GrantKeys {
    GrantKeys::new([vec![0x42; 32]], "test", 3600, 60).unwrap()
}

/// A deployment authenticator that knows only fresh logins (header-named
/// principals with an `auth_time`), and passes everything else through.
fn fresh_login(req: &vgi_rpc::AuthRequest) -> vgi_rpc::AuthResult {
    Ok(match req.header(PRINCIPAL_HEADER) {
        Some(p) if !p.is_empty() => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            AuthContext::for_principal("login", p).with_claim("auth_time", now.to_string())
        }
        _ => AuthContext::anonymous(),
    })
}

fn state() -> Arc<HttpState> {
    let server = RpcServer::builder()
        .protocol_name("App")
        .grant_keys(GrantKeysSetting::Keys(keys()))
        .add_protocol(whoami_protocol())
        .build();
    HttpState::builder()
        .server(Arc::new(server))
        .authenticate(Arc::new(fresh_login))
        .build()
}

fn body(protocol: &str, method: &str, batch: &RecordBatch) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut md = Metadata::new();
    md.insert(RPC_METHOD_KEY.into(), method.into());
    md.insert(PROTOCOL_KEY.into(), protocol.into());
    md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
    {
        let mut w = StreamWriter::new(&mut buf, batch.schema_ref()).unwrap();
        w.write(batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

async fn post(
    state: Arc<HttpState>,
    protocol: &str,
    method: &str,
    batch: &RecordBatch,
    headers: &[(&str, String)],
) -> (
    StatusCode,
    Vec<(RecordBatch, std::collections::HashMap<String, String>)>,
) {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/{protocol}/{method}"))
        .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let resp = vgi_rpc::http::build_router(state)
        .oneshot(req.body(Body::from(body(protocol, method, batch))).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let mut frames = Vec::new();
    if let Ok(mut r) = StreamReader::new(&mut Cursor::new(bytes.to_vec())) {
        while let Ok(Some(f)) = r.read_next() {
            frames.push(f);
        }
    }
    (status, frames)
}

fn error_kind(
    frames: &[(RecordBatch, std::collections::HashMap<String, String>)],
) -> Option<String> {
    frames
        .iter()
        .find(|(_, md)| md.get(LOG_LEVEL_KEY).map(String::as_str) == Some("EXCEPTION"))
        .and_then(|(_, md)| md.get(ERROR_KIND_KEY).cloned())
}

fn grant_request(purpose: &str) -> RecordBatch {
    let mut scopes =
        arrow_array::builder::ListBuilder::new(arrow_array::builder::StringBuilder::new());
    scopes.values().append_value("read");
    scopes.append(true);
    RecordBatch::try_new(
        issue_grant_params_schema(),
        vec![
            Arc::new(StringArray::from(vec![purpose])) as ArrayRef,
            Arc::new(scopes.finish()) as ArrayRef,
            Arc::new(Int64Array::from(vec![600])) as ArrayRef,
        ],
    )
    .unwrap()
}

/// The token out of an `issue_grant` response (`result` binary -> nested
/// IssuedGrant batch).
fn minted_token(frames: &[(RecordBatch, std::collections::HashMap<String, String>)]) -> String {
    let (batch, _) = frames
        .iter()
        .find(|(b, _)| b.num_rows() == 1)
        .expect("a result");
    let nested = batch
        .column(0)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .unwrap()
        .value(0)
        .to_vec();
    let mut cursor = Cursor::new(nested);
    let mut r = StreamReader::new(&mut cursor).unwrap();
    let (grant, _) = r.read_next().unwrap().unwrap();
    grant
        .column_by_name("token")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .value(0)
        .to_string()
}

fn whoami(
    frames: &[(RecordBatch, std::collections::HashMap<String, String>)],
) -> serde_json::Value {
    let (batch, _) = frames
        .iter()
        .find(|(b, _)| b.num_rows() == 1)
        .expect("a result");
    let text = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .value(0);
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn a_minted_grant_authenticates_as_its_owner_and_cannot_mint() {
    let state = state();
    let empty = RecordBatch::new_empty(Arc::new(Schema::empty()));

    // 1. Mint as a freshly logged-in caller.
    let (status, frames) = post(
        state.clone(),
        IDENTITY_PROTOCOL_NAME,
        "issue_grant",
        &grant_request("nightly"),
        &[(PRINCIPAL_HEADER, "alice@example".into())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(error_kind(&frames), None, "{frames:?}");
    let token = minted_token(&frames);
    assert!(token.starts_with("vgig1."));

    // 2. Present it as an ordinary bearer: authenticated as the owner.
    let (status, frames) = post(
        state.clone(),
        WHOAMI_PROTOCOL_NAME,
        "whoami",
        &empty,
        &[("authorization", format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let who = whoami(&frames);
    assert_eq!(who["domain"], "grant");
    assert_eq!(who["principal"], "alice@example");
    assert_eq!(who["claims"]["scopes"], serde_json::json!(["read"]));
    assert_eq!(who["claims"]["purpose"], "nightly");

    // 3. A grant cannot mint a grant: no auth_time.
    let (_, frames) = post(
        state.clone(),
        IDENTITY_PROTOCOL_NAME,
        "issue_grant",
        &grant_request("child"),
        &[("authorization", format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(error_kind(&frames).as_deref(), Some("stale_auth"));

    // 4. Tampered: 401, invalid_credential.
    let tampered = format!(
        "{}{}",
        &token[..token.len() - 2],
        if token.ends_with("AA") { "BB" } else { "AA" }
    );
    let (status, _) = post(
        state,
        WHOAMI_PROTOCOL_NAME,
        "whoami",
        &empty,
        &[("authorization", format!("Bearer {tampered}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn no_credential_stays_anonymous_and_an_unknown_bearer_is_401() {
    let empty = RecordBatch::new_empty(Arc::new(Schema::empty()));
    let (status, frames) = post(state(), WHOAMI_PROTOCOL_NAME, "whoami", &empty, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(whoami(&frames)["authenticated"], false);
    let (status, _) = post(
        state(),
        WHOAMI_PROTOCOL_NAME,
        "whoami",
        &empty,
        &[("authorization", "Bearer something-else".into())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[test]
fn grant_keys_host_issue_grant_alone_and_must_match_the_identity() {
    let server = RpcServer::builder()
        .protocol_name("App")
        .grant_keys(GrantKeysSetting::Keys(keys()))
        .build();
    assert!(server
        .hosted_protocol_names()
        .contains(&IDENTITY_PROTOCOL_NAME));

    let without_keys = IdentityImpl::builder()
        .mint_grant(Arc::new(|_p: &str, _u: &str, _s: &[String], _t: i64| {
            Err(vgi_rpc::token_identity::grant_refused("no"))
        }))
        .build();
    let refused = RpcServer::builder()
        .protocol_name("App")
        .grant_keys(GrantKeysSetting::Keys(keys()))
        .identity(without_keys)
        .try_build();
    assert!(refused.is_err());

    let off = RpcServer::builder()
        .protocol_name("App")
        .grant_keys(GrantKeysSetting::Off)
        .build();
    assert!(!off
        .hosted_protocol_names()
        .contains(&IDENTITY_PROTOCOL_NAME));
}

/// Accepting identity bearers beside a proxy-evidence gate would OR around
/// it: refuse to start.
#[test]
#[should_panic(expected = "proxy-injected evidence")]
fn identity_bearers_beside_a_proxy_gate_refuse_to_start() {
    let server = RpcServer::builder()
        .protocol_name("App")
        .grant_keys(GrantKeysSetting::Keys(keys()))
        .build();
    let _ = HttpState::builder()
        .server(Arc::new(server))
        .authenticate(Arc::new(fresh_login))
        .proxy_auth_headers(["x-forwarded-client-cert"])
        .build();
}
