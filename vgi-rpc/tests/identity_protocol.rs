//! `vgi_rpc.Identity.v1` end to end: registration, routing, and what a client
//! discovers about a worker that hosts only half of it.
//!
//! The guards themselves are unit-tested beside the implementation. What can
//! only be checked here is the *wiring*: that the protocol is absent until
//! configured, that it routes as an ordinary co-hosted protocol rather than a
//! special case, that reflection reports what the deployment can actually
//! answer, and that the `error_kind` a caller branches on survives the trip to
//! the wire.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

use arrow_array::{Array, ArrayRef, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};

use vgi_rpc::auth::AuthContext;
use vgi_rpc::metadata::{
    ERROR_KIND_KEY, LOG_LEVEL_KEY, PROTOCOL_KEY, REQUEST_ID_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::server::ConnectionContext;
use vgi_rpc::token_identity::{
    IdentityImpl, IssuedGrant, TokenIdentity, IDENTITY_PROTOCOL_NAME, INTROSPECT_TOKEN_METHOD,
    ISSUE_GRANT_METHOD,
};
use vgi_rpc::wire::{Metadata, StreamReader, StreamWriter};
use vgi_rpc::{MethodInfo, RpcServer};

const INTROSPECTOR: &str = "proxy";
const SUBJECT: &str = "opaque-subject-token";

fn resolver() -> vgi_rpc::token_identity::TokenResolver {
    Arc::new(|token: &str| {
        Ok((token == SUBJECT)
            .then(|| TokenIdentity::new("subject@example").with_token_name("laptop")))
    })
}

fn minter() -> vgi_rpc::token_identity::GrantMinter {
    Arc::new(
        |principal: &str, purpose: &str, scopes: &[String], ttl: i64| {
            Ok(IssuedGrant::new(
                format!("grant/{principal}/{purpose}/{}", scopes.join("+")),
                1_000_000.0 + ttl as f64,
            )
            .with_grant_id("g1"))
        },
    )
}

/// A server with an ordinary application method, so the identity protocol is
/// co-hosted rather than alone.
fn app_server() -> RpcServer {
    let mut server = RpcServer::builder()
        .server_id("srv")
        .protocol_name("Service")
        .build();
    server.register(MethodInfo::unary(
        "noop",
        Arc::new(Schema::empty()),
        Arc::new(Schema::empty()),
        |_req, _ctx| Ok(None),
    ));
    server
}

fn server_with(identity: IdentityImpl) -> RpcServer {
    let mut server = RpcServer::builder()
        .server_id("srv")
        .protocol_name("Service")
        .identity(identity)
        .build();
    server.register(MethodInfo::unary(
        "noop",
        Arc::new(Schema::empty()),
        Arc::new(Schema::empty()),
        |_req, _ctx| Ok(None),
    ));
    server
}

/// Frame one request as a self-contained IPC stream.
fn request_bytes(protocol: &str, method: &str, batch: &RecordBatch) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, batch.schema_ref()).unwrap();
        let mut md = Metadata::new();
        md.insert(RPC_METHOD_KEY.into(), method.into());
        md.insert(PROTOCOL_KEY.into(), protocol.into());
        md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
        md.insert(REQUEST_ID_KEY.into(), format!("req-{method}"));
        w.write(batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

fn empty_batch() -> RecordBatch {
    RecordBatch::new_empty(Arc::new(Schema::empty()))
}

fn token_batch(token: &str) -> RecordBatch {
    RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new(
            "token",
            DataType::Utf8,
            false,
        )])),
        vec![Arc::new(StringArray::from(vec![token])) as ArrayRef],
    )
    .unwrap()
}

fn grant_batch(purpose: &str, scopes: &[&str], ttl: i64) -> RecordBatch {
    let schema = vgi_rpc::token_identity::issue_grant_params_schema();
    let mut list =
        arrow_array::builder::ListBuilder::new(arrow_array::builder::StringBuilder::new());
    for s in scopes {
        list.values().append_value(s);
    }
    list.append(true);
    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(vec![purpose])) as ArrayRef,
            Arc::new(list.finish()) as ArrayRef,
            Arc::new(Int64Array::from(vec![ttl])) as ArrayRef,
        ],
    )
    .unwrap()
}

/// Dispatch one request and return every (batch, metadata) frame written back.
fn call(
    server: &RpcServer,
    auth: AuthContext,
    protocol: &str,
    method: &str,
    batch: &RecordBatch,
) -> Vec<(RecordBatch, HashMap<String, String>)> {
    let bytes = request_bytes(protocol, method, batch);
    let mut input = Cursor::new(bytes);
    let mut output: Vec<u8> = Vec::new();
    let connection = ConnectionContext::new(auth, Default::default());
    server
        .serve_one_with_context(&mut input, &mut output, &connection)
        .unwrap();
    let mut cursor = Cursor::new(output);
    let mut reader = StreamReader::new(&mut cursor).unwrap();
    let mut frames = Vec::new();
    while let Some((batch, md)) = reader.read_next().unwrap() {
        frames.push((batch, md));
    }
    frames
}

/// The error envelope's metadata, if the response was an error.
fn error_metadata(
    frames: &[(RecordBatch, HashMap<String, String>)],
) -> Option<&HashMap<String, String>> {
    frames
        .iter()
        .find(|(_, md)| md.get(LOG_LEVEL_KEY).map(String::as_str) == Some("EXCEPTION"))
        .map(|(_, md)| md)
}

/// Decode the nested payload out of the single `result` binary column.
fn payload(frames: &[(RecordBatch, HashMap<String, String>)]) -> RecordBatch {
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
        .expect("result is binary");
    let mut cursor = Cursor::new(col.value(0).to_vec());
    let mut reader = StreamReader::new(&mut cursor).unwrap();
    reader.read_next().unwrap().unwrap().0
}

/// Read one string field out of every element of a `list<struct<...>>`
/// column -- how a reflection listing is inspected without a prettyprinter.
fn list_struct_field(batch: &RecordBatch, column: &str, field: &str) -> Vec<String> {
    let list = batch
        .column_by_name(column)
        .unwrap()
        .as_any()
        .downcast_ref::<arrow_array::ListArray>()
        .unwrap();
    let values = list.value(0);
    let structs = values
        .as_any()
        .downcast_ref::<arrow_array::StructArray>()
        .unwrap();
    let col = structs
        .column_by_name(field)
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    (0..col.len()).map(|i| col.value(i).to_string()).collect()
}

fn string_at(batch: &RecordBatch, column: &str) -> String {
    batch
        .column_by_name(column)
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .value(0)
        .to_string()
}

/// A dependency upgrade must not grow a credential-to-identity oracle on every
/// existing worker: the protocol is not hosted until someone configures a hook.
#[test]
fn absent_until_configured() {
    let server = app_server();
    assert!(!server
        .hosted_protocol_names()
        .contains(&IDENTITY_PROTOCOL_NAME));
    let frames = call(
        &server,
        AuthContext::for_principal("test", INTROSPECTOR),
        IDENTITY_PROTOCOL_NAME,
        INTROSPECT_TOKEN_METHOD,
        &token_batch(SUBJECT),
    );
    let md = error_metadata(&frames).expect("an error");
    // "This server does not host that protocol" -- a routing answer, not a
    // method-level refusal, because the surface genuinely is not here.
    assert!(
        md.values().any(|v| v.contains("does not host protocol")),
        "{md:?}"
    );
}

/// The happy path, for the reverse proxy the method exists for.
#[test]
fn an_allowlisted_caller_resolves_a_credential() {
    let server = server_with(
        IdentityImpl::builder()
            .resolve_token(resolver())
            .introspect_principals([INTROSPECTOR])
            .build(),
    );
    let frames = call(
        &server,
        AuthContext::for_principal("test", INTROSPECTOR),
        IDENTITY_PROTOCOL_NAME,
        INTROSPECT_TOKEN_METHOD,
        &token_batch(SUBJECT),
    );
    assert!(error_metadata(&frames).is_none(), "{frames:?}");
    let payload = payload(&frames);
    assert_eq!(string_at(&payload, "principal"), "subject@example");
    assert_eq!(string_at(&payload, "token_name"), "laptop");
    let ttl = payload
        .column_by_name("ttl_seconds")
        .unwrap()
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap()
        .value(0);
    assert_eq!(ttl, 300, "a resolution naming no TTL takes the default");
}

/// The subject is the caller, never a request parameter, so the minted grant
/// names whoever actually authenticated.
#[test]
fn a_fresh_caller_mints_a_grant_for_themselves() {
    let server = server_with(IdentityImpl::builder().mint_grant(minter()).build());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let caller =
        AuthContext::for_principal("test", "alice").with_claim("auth_time", format!("{now}"));
    let frames = call(
        &server,
        caller,
        IDENTITY_PROTOCOL_NAME,
        ISSUE_GRANT_METHOD,
        &grant_batch("reports", &["read", "list"], 3600),
    );
    assert!(error_metadata(&frames).is_none(), "{frames:?}");
    let payload = payload(&frames);
    assert_eq!(
        string_at(&payload, "token"),
        "grant/alice/reports/read+list"
    );
    assert_eq!(string_at(&payload, "grant_id"), "g1");
}

/// An unauthenticated transport -- subprocess, unix -- carries no principal at
/// all, so minting fails closed for free, and the caller is told *why* because
/// the answer is about them.
#[test]
fn an_unauthenticated_caller_is_told_to_reauthenticate() {
    let server = server_with(IdentityImpl::builder().mint_grant(minter()).build());
    let frames = call(
        &server,
        AuthContext::anonymous(),
        IDENTITY_PROTOCOL_NAME,
        ISSUE_GRANT_METHOD,
        &grant_batch("reports", &[], 60),
    );
    let md = error_metadata(&frames).expect("an error");
    assert_eq!(
        md.get(ERROR_KIND_KEY).map(String::as_str),
        Some("stale_auth")
    );
}

/// The `error_kind` reaches the wire as its own metadata key.
///
/// It is the only definitive-vs-transient signal a caller has now that these
/// are protocol methods rather than an HTTP route with a status code, so a
/// caller must not have to parse a JSON blob -- or worse, a message -- to find
/// it.
#[test]
fn error_kind_rides_on_the_wire() {
    let server = server_with(
        IdentityImpl::builder()
            .resolve_token(resolver())
            .introspect_principals([INTROSPECTOR])
            .build(),
    );
    // Off the allowlist: refused before the subject is looked at.
    let frames = call(
        &server,
        AuthContext::for_principal("test", "mallory"),
        IDENTITY_PROTOCOL_NAME,
        INTROSPECT_TOKEN_METHOD,
        &token_batch(SUBJECT),
    );
    let md = error_metadata(&frames).expect("an error");
    assert_eq!(
        md.get(ERROR_KIND_KEY).map(String::as_str),
        Some("introspection_refused")
    );
    // And the credential never reaches the envelope.
    assert!(
        !md.values().any(|v| v.contains(SUBJECT)),
        "the credential reached an error envelope: {md:?}"
    );

    // An allowlisted caller presenting an unknown credential gets the uniform
    // rejection, with the kind that says "definitive, do not retry".
    let frames = call(
        &server,
        AuthContext::for_principal("test", INTROSPECTOR),
        IDENTITY_PROTOCOL_NAME,
        INTROSPECT_TOKEN_METHOD,
        &token_batch("no-such-credential"),
    );
    let md = error_metadata(&frames).expect("an error");
    assert_eq!(
        md.get(ERROR_KIND_KEY).map(String::as_str),
        Some("token_unresolved")
    );
}

/// A newline-padded JWS is refused on the wire, not routed onward.
///
/// This port's shape matcher is hand-rolled, so `"aaa.bbb.ccc\n"` has a
/// non-base64url third segment and is not JWS-shaped unless the guard trims
/// first -- which meant the one credential this guard exists to stop reached
/// the resolver. The resolver here resolves everything, so a missing trim
/// surfaces as a resolution rather than as a rejection for the wrong reason.
#[test]
fn a_padded_jws_is_refused_on_the_wire() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let spy = seen.clone();
    let server = server_with(
        IdentityImpl::builder()
            .resolve_token(Arc::new(move |token: &str| {
                spy.lock().unwrap().push(token.to_string());
                Ok(Some(TokenIdentity::new("anyone@example")))
            }))
            .introspect_principals([INTROSPECTOR])
            .build(),
    );
    for padded in ["aaa.bbb.ccc\n", "  aaa.bbb.ccc  ", "aaa.bbb.ccc\u{00A0}"] {
        let frames = call(
            &server,
            AuthContext::for_principal("test", INTROSPECTOR),
            IDENTITY_PROTOCOL_NAME,
            INTROSPECT_TOKEN_METHOD,
            &token_batch(padded),
        );
        let md = error_metadata(&frames).unwrap_or_else(|| panic!("{padded:?} was resolved"));
        assert_eq!(
            md.get(ERROR_KIND_KEY).map(String::as_str),
            Some("token_unresolved")
        );
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "the resolver was handed a padded JWS: {:?}",
        seen.lock().unwrap()
    );
}

/// Trimming is for the shape test only: the hook is handed the credential
/// exactly as it arrived, because rewriting it would make the worker answer
/// about a string the caller never sent.
#[test]
fn the_resolver_receives_the_credential_unmodified_on_the_wire() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let spy = seen.clone();
    let server = server_with(
        IdentityImpl::builder()
            .resolve_token(Arc::new(move |token: &str| {
                spy.lock().unwrap().push(token.to_string());
                Ok(Some(TokenIdentity::new("subject@example")))
            }))
            .introspect_principals([INTROSPECTOR])
            .build(),
    );
    let frames = call(
        &server,
        AuthContext::for_principal("test", INTROSPECTOR),
        IDENTITY_PROTOCOL_NAME,
        INTROSPECT_TOKEN_METHOD,
        &token_batch("  padded-opaque-token  "),
    );
    assert!(error_metadata(&frames).is_none(), "{frames:?}");
    assert_eq!(*seen.lock().unwrap(), vec!["  padded-opaque-token  "]);
}

/// A method whose hook the deployment did not configure is *absent*, not
/// routed-and-refusing -- so a caller gets the "no such method" answer it would
/// get for any method this protocol does not have here.
#[test]
fn an_unconfigured_method_is_not_hosted() {
    let server = server_with(IdentityImpl::builder().mint_grant(minter()).build());
    let frames = call(
        &server,
        AuthContext::for_principal("test", INTROSPECTOR),
        IDENTITY_PROTOCOL_NAME,
        INTROSPECT_TOKEN_METHOD,
        &token_batch(SUBJECT),
    );
    let md = error_metadata(&frames).expect("an error");
    let rendered = format!("{md:?}");
    assert!(rendered.contains("has no method"), "{rendered}");
    // And the diagnostic names what *is* hosted, which is how a client probing
    // for an optional method learns the difference.
    assert!(rendered.contains(ISSUE_GRANT_METHOD), "{rendered}");
}

/// Identity is registered *after* reflection, so it appears in reflection's
/// output: a client learns which methods this deployment can answer by
/// looking, rather than by calling and reading an error.
#[test]
fn reflection_reports_the_narrowed_identity_protocol() {
    let server = server_with(IdentityImpl::builder().mint_grant(minter()).build());
    let frames = call(
        &server,
        AuthContext::anonymous(),
        "vgi_rpc.Reflection.v1",
        "list_protocols",
        &empty_batch(),
    );
    let listing = payload(&frames);
    let names = list_struct_field(&listing, "protocols", "protocol");
    assert!(
        names.contains(&IDENTITY_PROTOCOL_NAME.to_string()),
        "{names:?}"
    );
    // The narrowed hash, not the whole protocol's: a server offering half the
    // methods is not offering the same surface.
    let hashes = list_struct_field(&listing, "protocols", "protocol_hash");
    let index = names
        .iter()
        .position(|n| n == IDENTITY_PROTOCOL_NAME)
        .unwrap();
    assert_eq!(
        hashes[index], "c71b12f453310139b6b6a445378064661c52711d03ae1e4fba29b8f7976ef4d8",
        "the listed hash must be the issue_grant-only one"
    );

    // And `describe` lists only the method whose hook exists.
    let described = call(
        &server,
        AuthContext::anonymous(),
        "vgi_rpc.Reflection.v1",
        "describe",
        &RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new(
                "protocol",
                DataType::Utf8,
                false,
            )])),
            vec![Arc::new(StringArray::from(vec![IDENTITY_PROTOCOL_NAME])) as ArrayRef],
        )
        .unwrap(),
    );
    let description = payload(&described);
    let methods = list_struct_field(&description, "methods", "name");
    assert_eq!(methods, vec![ISSUE_GRANT_METHOD.to_string()]);
}

/// Hosting identity must not perturb the application protocol's own
/// fingerprint: they are separate surfaces, and a conformance hash that moved
/// because an unrelated protocol was co-hosted would be worthless.
#[test]
fn co_hosting_identity_does_not_move_the_application_hash() {
    let plain = app_server();
    let with_identity = server_with(
        IdentityImpl::builder()
            .resolve_token(resolver())
            .mint_grant(minter())
            .introspect_principals([INTROSPECTOR])
            .build(),
    );
    assert_eq!(plain.protocol_hash(), with_identity.protocol_hash());
}

/// An application may not claim the framework's name, and a request naming a
/// protocol this server does not host is told so rather than landing on
/// whichever protocol happened to be first.
#[test]
fn the_reserved_prefix_is_the_frameworks() {
    assert!(vgi_rpc::binding::validate_protocol_name(IDENTITY_PROTOCOL_NAME, false).is_err());
    assert!(vgi_rpc::binding::validate_protocol_name(IDENTITY_PROTOCOL_NAME, true).is_ok());
}
