//! Hosting several application protocols, and the error model on the wire.
//!
//! WIRE_PROTOCOL.md §3.1 ("Hosting several application protocols"), §8 ("Error
//! model", "Tracebacks") and §16 (the identity retry hint and translation),
//! driven through the pipe transport's real serve loop.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use arrow_array::{ArrayRef, Float64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use serde_json::Value;

use vgi_rpc::auth::AuthContext;
use vgi_rpc::conformance_secondary::{
    conformance_secondary_protocol, SECONDARY_PROTOCOL_HASH, SECONDARY_PROTOCOL_NAME,
};
use vgi_rpc::metadata::{
    ERROR_CODE_KEY, ERROR_DETAILS_KEY, ERROR_KIND_KEY, LOG_EXTRA_KEY, LOG_LEVEL_KEY, PROTOCOL_KEY,
    PROTOCOL_VERSION_KEY, REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::server::{ConnectionContext, HostedProtocol};
use vgi_rpc::token_identity::{IdentityImpl, IssuedGrant, IDENTITY_PROTOCOL_NAME};
use vgi_rpc::wire::{Metadata, StreamReader, StreamWriter};
use vgi_rpc::{MethodInfo, RpcError, RpcServer, TransportCapabilities, TransportKind};

type Frames = Vec<(RecordBatch, HashMap<String, String>)>;

fn utf8_schema(name: &str) -> Arc<Schema> {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Utf8, false)]))
}

/// The primary: `echo_string` with the same signature as the secondary's, so
/// routing by bare method name would answer one with the other.
fn primary_server(builder: vgi_rpc::RpcServerBuilder) -> RpcServer {
    let mut server = builder
        .server_id("srv")
        .protocol_name("Primary")
        .protocol_version("2.0.0")
        .add_protocol(conformance_secondary_protocol())
        .build();
    server.register(MethodInfo::unary(
        "echo_string",
        utf8_schema("value"),
        utf8_schema("result"),
        |req, _ctx| {
            let v = req.column("value").unwrap();
            let v = v.as_any().downcast_ref::<StringArray>().unwrap().value(0);
            Ok(Some(RecordBatch::try_new(
                utf8_schema("result"),
                vec![Arc::new(StringArray::from(vec![format!("primary:{v}")])) as ArrayRef],
            )?))
        },
    ));
    server
}

fn request(protocol: &str, method: &str, batch: &RecordBatch, version: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, batch.schema_ref()).unwrap();
        let mut md = Metadata::new();
        md.insert(RPC_METHOD_KEY.into(), method.into());
        if !protocol.is_empty() {
            md.insert(PROTOCOL_KEY.into(), protocol.into());
        }
        if let Some(v) = version {
            md.insert(PROTOCOL_VERSION_KEY.into(), v.into());
        }
        md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
        md.insert(REQUEST_ID_KEY.into(), "r1".into());
        w.write(batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

fn call_with(server: &RpcServer, auth: AuthContext, bytes: Vec<u8>) -> Frames {
    let mut input = Cursor::new(bytes);
    let mut output = Vec::new();
    server
        .serve_one_with_context(
            &mut input,
            &mut output,
            &ConnectionContext::new(auth, Default::default()),
        )
        .unwrap();
    let mut reader = StreamReader::new(Cursor::new(output)).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.read_next().unwrap() {
        frames.push(frame);
    }
    frames
}

fn call(server: &RpcServer, protocol: &str, method: &str, batch: &RecordBatch) -> Frames {
    // The primary declares 2.0.0, so a conforming client sends it (patch
    // ignored); bindings that declare none ignore it.
    call_with(
        server,
        AuthContext::anonymous(),
        request(protocol, method, batch, Some("2.0.7")),
    )
}

fn error_md(frames: &Frames) -> &HashMap<String, String> {
    frames
        .iter()
        .map(|(_, md)| md)
        .find(|md| md.get(LOG_LEVEL_KEY).map(String::as_str) == Some("EXCEPTION"))
        .expect("an EXCEPTION batch")
}

fn extra(md: &HashMap<String, String>) -> serde_json::Map<String, Value> {
    match serde_json::from_str(md.get(LOG_EXTRA_KEY).unwrap()).unwrap() {
        Value::Object(m) => m,
        _ => panic!("log_extra is not an object"),
    }
}

fn echo_batch(value: &str) -> RecordBatch {
    RecordBatch::try_new(
        utf8_schema("value"),
        vec![Arc::new(StringArray::from(vec![value])) as ArrayRef],
    )
    .unwrap()
}

fn fail_batch(code: &str, kind: &str, delay: f64) -> RecordBatch {
    RecordBatch::try_new(
        Arc::new(Schema::new(vec![
            Field::new("code", DataType::Utf8, false),
            Field::new("kind", DataType::Utf8, false),
            Field::new("retry_delay_seconds", DataType::Float64, false),
        ])),
        vec![
            Arc::new(StringArray::from(vec![code])) as ArrayRef,
            Arc::new(StringArray::from(vec![kind])) as ArrayRef,
            Arc::new(Float64Array::from(vec![delay])) as ArrayRef,
        ],
    )
    .unwrap()
}

fn result_string(frames: &Frames) -> String {
    let (batch, _) = frames.iter().find(|(b, _)| b.num_rows() == 1).unwrap();
    batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .value(0)
        .to_string()
}

#[test]
fn the_secondary_hashes_to_the_pin_and_is_listed_after_the_primary() {
    let server = primary_server(RpcServer::builder());
    assert_eq!(
        server.protocol_identity(SECONDARY_PROTOCOL_NAME).hash,
        SECONDARY_PROTOCOL_HASH
    );
    let names = server.hosted_protocol_names();
    let apps: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| !n.starts_with("vgi_rpc."))
        .collect();
    assert_eq!(apps, ["Primary", SECONDARY_PROTOCOL_NAME]);
}

#[test]
fn routing_is_by_protocol_and_method_together() {
    let server = primary_server(RpcServer::builder());
    let b = echo_batch("x");
    assert_eq!(
        result_string(&call(&server, "Primary", "echo_string", &b)),
        "primary:x"
    );
    assert_eq!(
        result_string(&call(&server, SECONDARY_PROTOCOL_NAME, "echo_string", &b)),
        "secondary:x"
    );
}

/// The secondary declares no version, so a client of the primary's major-2
/// version -- or of a mismatched one -- still reaches it; the primary gates.
#[test]
fn the_version_gate_is_per_binding() {
    let server = primary_server(RpcServer::builder());
    let b = echo_batch("x");
    let frames = call_with(
        &server,
        AuthContext::anonymous(),
        request(SECONDARY_PROTOCOL_NAME, "echo_string", &b, Some("1.0.0")),
    );
    assert_eq!(result_string(&frames), "secondary:x");
    let frames = call_with(
        &server,
        AuthContext::anonymous(),
        request("Primary", "echo_string", &b, Some("1.0.0")),
    );
    let md = error_md(&frames);
    assert_eq!(md[ERROR_CODE_KEY], "FAILED_PRECONDITION");
    assert_eq!(md[ERROR_KIND_KEY], "protocol_version_mismatch");
    assert!(md[ERROR_DETAILS_KEY].contains("\"subject\":\"Primary\""));
    assert!(md[ERROR_DETAILS_KEY].contains("major and minor must match"));
}

/// Major **and minor** must match; patch is ignored; an absent or malformed
/// client version is refused with the same kind.
#[test]
fn the_gate_compares_major_and_minor() {
    let server = primary_server(RpcServer::builder());
    let b = echo_batch("x");
    let outcome = |version: Option<&str>| {
        let frames = call_with(
            &server,
            AuthContext::anonymous(),
            request("Primary", "echo_string", &b, version),
        );
        frames
            .iter()
            .find(|(_, md)| md.get(LOG_LEVEL_KEY).map(String::as_str) == Some("EXCEPTION"))
            .map(|(_, md)| md[ERROR_KIND_KEY].clone())
    };
    assert_eq!(outcome(Some("2.0.0")), None);
    assert_eq!(outcome(Some("2.0.99")), None);
    for refused in [
        None,
        Some("2.1.0"),
        Some("2.0"),
        Some("02.0.0"),
        Some("2.0.0-rc1"),
        Some("3.0.0"),
    ] {
        assert_eq!(
            outcome(refused).as_deref(),
            Some("protocol_version_mismatch"),
            "{refused:?}"
        );
    }
}

#[test]
fn routing_errors_carry_their_codes() {
    let server = primary_server(RpcServer::builder());
    let b = echo_batch("x");
    for (protocol, method, code, kind) in [
        (
            "",
            "echo_string",
            "INVALID_ARGUMENT",
            "protocol_not_specified",
        ),
        (
            "Nope.v1",
            "echo_string",
            "UNIMPLEMENTED",
            "protocol_not_supported",
        ),
        (
            SECONDARY_PROTOCOL_NAME,
            "absent",
            "UNIMPLEMENTED",
            "method_not_implemented",
        ),
    ] {
        let frames = call(&server, protocol, method, &b);
        let md = error_md(&frames);
        assert_eq!(md[ERROR_CODE_KEY], code, "{protocol}/{method}");
        assert_eq!(md[ERROR_KIND_KEY], kind, "{protocol}/{method}");
        assert_eq!(extra(md)["error_code"], code);
    }
}

/// V1 on the wire: code, kind and details, mirrored into `log_extra`.
#[test]
fn fail_round_trips_the_three_layers() {
    let server = primary_server(RpcServer::builder());
    let frames = call(
        &server,
        SECONDARY_PROTOCOL_NAME,
        "fail",
        &fail_batch("UNAVAILABLE", "backend_down", 7.0),
    );
    let md = error_md(&frames);
    assert_eq!(md[ERROR_CODE_KEY], "UNAVAILABLE");
    assert_eq!(md[ERROR_KIND_KEY], "backend_down");
    let details: Value = serde_json::from_str(&md[ERROR_DETAILS_KEY]).unwrap();
    let x = extra(md);
    assert_eq!(x["error_details"], details, "log_extra mirrors the array");
    assert_eq!(x["error_kind"], "backend_down");
    assert_eq!(details.as_array().unwrap().len(), 3);
    assert_eq!(details[1]["retry_delay_seconds"], 7);

    // V2: no kind key at all when the kind is empty.
    let frames = call(
        &server,
        SECONDARY_PROTOCOL_NAME,
        "fail",
        &fail_batch("ABORTED", "", 0.0),
    );
    let md = error_md(&frames);
    assert_eq!(md[ERROR_CODE_KEY], "ABORTED");
    assert!(!md.contains_key(ERROR_KIND_KEY));
    assert!(!extra(md).contains_key("error_kind"));
}

/// V4: the whole array is dropped -- from both places -- and the code and kind
/// still go.
#[test]
fn oversized_details_are_dropped_whole() {
    let server = primary_server(RpcServer::builder());
    let frames = call(
        &server,
        SECONDARY_PROTOCOL_NAME,
        "fail_oversized",
        &RecordBatch::new_empty(Arc::new(Schema::empty())),
    );
    let md = error_md(&frames);
    assert_eq!(md[ERROR_CODE_KEY], "RESOURCE_EXHAUSTED");
    assert_eq!(md[ERROR_KIND_KEY], "details_oversized");
    assert!(!md.contains_key(ERROR_DETAILS_KEY));
    assert!(!extra(md).contains_key("error_details"));
}

#[test]
fn an_unclassified_error_is_unknown() {
    let mut server = RpcServer::builder().protocol_name("P").build();
    server.register(MethodInfo::unary(
        "boom",
        Arc::new(Schema::empty()),
        Arc::new(Schema::empty()),
        |_req, _ctx| Err(RpcError::value_error("boom")),
    ));
    let frames = call(
        &server,
        "P",
        "boom",
        &RecordBatch::new_empty(Arc::new(Schema::empty())),
    );
    let md = error_md(&frames);
    assert_eq!(md[ERROR_CODE_KEY], "UNKNOWN");
    assert!(!md.contains_key(ERROR_KIND_KEY));
}

/// Tracebacks: included by default on every transport, synthesized (type,
/// message, `<protocol>/<method>`) for a stackless error; one per-server
/// switch omits them everywhere.
#[test]
fn tracebacks_are_on_everywhere_by_default_and_one_switch_turns_them_off() {
    let fail = || fail_batch("INTERNAL", "", 0.0);
    let traceback_of = |server: &RpcServer| {
        let frames = call(server, SECONDARY_PROTOCOL_NAME, "fail", &fail());
        extra(error_md(&frames))
            .get("traceback")
            .map(|t| t.as_str().unwrap().to_string())
    };
    for kind in [
        None,
        Some(TransportKind::Pipe),
        Some(TransportKind::Unix),
        Some(TransportKind::Tcp),
        Some(TransportKind::Http),
    ] {
        let server = primary_server(RpcServer::builder());
        if let Some(kind) = kind {
            server.notify_transport(kind, TransportCapabilities::none());
        }
        let tb = traceback_of(&server).expect("traceback present");
        assert!(tb.contains("StatusError"), "{tb}");
        assert!(tb.contains("conformance.Secondary.v1/fail"), "{tb}");

        let server = primary_server(RpcServer::builder().include_tracebacks(false));
        if let Some(kind) = kind {
            server.notify_transport(kind, TransportCapabilities::none());
        }
        assert_eq!(traceback_of(&server), None, "{kind:?}");
    }
}

#[test]
fn the_reserved_prefix_is_refused_for_every_application_protocol() {
    let primary = RpcServer::builder()
        .protocol_name("vgi_rpc.Reflection.v1")
        .try_build();
    assert!(primary.is_err());
    let extra = RpcServer::builder()
        .protocol_name("App")
        .add_protocol(HostedProtocol::new("vgi_rpc.Identity.v1"))
        .try_build();
    assert!(extra.err().unwrap().message.contains("reserved"));
    let dup = RpcServer::builder()
        .protocol_name("App")
        .add_protocol(HostedProtocol::new("App"))
        .try_build();
    assert!(dup.err().unwrap().message.contains("more than once"));
    let malformed = RpcServer::builder()
        .protocol_name("App")
        .add_protocol(HostedProtocol::new("has space"))
        .try_build();
    assert!(malformed.is_err());
}

/// A reserved-name registration is refused at construction -- it never gets
/// far enough to shadow the framework's protocol, and its handler is never
/// reached.
#[test]
fn a_refused_registration_never_serves() {
    let reached = Arc::new(AtomicBool::new(false));
    let flag = reached.clone();
    let shadow = HostedProtocol::new("vgi_rpc.Reflection.v1").with_method(MethodInfo::unary(
        "list_protocols",
        Arc::new(Schema::empty()),
        Arc::new(Schema::empty()),
        move |_req, _ctx| {
            flag.store(true, Ordering::SeqCst);
            Ok(None)
        },
    ));
    let result = RpcServer::builder()
        .protocol_name("App")
        .add_protocol(shadow)
        .try_build();
    assert!(result.is_err());
    assert!(!reached.load(Ordering::SeqCst));
}

fn auth_unavailable_identity() -> IdentityImpl {
    IdentityImpl::builder()
        .resolve_token(Arc::new(|_token: &str| {
            Err(RpcError::auth_unavailable("store down").with_retry_after(7))
        }))
        .mint_grant(Arc::new(
            |_p: &str, _purpose: &str, _s: &[String], _t: i64| {
                Err::<IssuedGrant, _>(RpcError::auth_unavailable("store down").with_retry_after(7))
            },
        ))
        .introspect_principals(["proxy"])
        .build()
}

fn assert_identity_unavailable_with_7(frames: &Frames) {
    let md = error_md(frames);
    assert_eq!(md[ERROR_KIND_KEY], "identity_unavailable");
    assert_eq!(md[ERROR_CODE_KEY], "UNAVAILABLE");
    let details: Value = serde_json::from_str(&md[ERROR_DETAILS_KEY]).unwrap();
    let retry = details
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["@type"] == "vgi_rpc.RetryInfo")
        .expect("RetryInfo");
    assert_eq!(retry["retry_delay_seconds"], 7);
}

/// §16: the transport-auth "unavailable" error from either hook reaches the
/// wire as `identity_unavailable`, keeping the hook's own hint.
#[test]
fn auth_unavailable_from_either_hook_is_translated_with_its_hint() {
    let server = RpcServer::builder()
        .protocol_name("App")
        .identity(auth_unavailable_identity())
        .build();
    let token = RecordBatch::try_new(
        utf8_schema("token"),
        vec![Arc::new(StringArray::from(vec!["t"])) as ArrayRef],
    )
    .unwrap();
    let frames = call_with(
        &server,
        AuthContext::for_principal("test", "proxy"),
        request(IDENTITY_PROTOCOL_NAME, "introspect_token", &token, None),
    );
    assert_identity_unavailable_with_7(&frames);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let schema = vgi_rpc::token_identity::issue_grant_params_schema();
    let mut list =
        arrow_array::builder::ListBuilder::new(arrow_array::builder::StringBuilder::new());
    list.append(true);
    let grant = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(vec!["p"])) as ArrayRef,
            Arc::new(list.finish()) as ArrayRef,
            Arc::new(arrow_array::Int64Array::from(vec![60])) as ArrayRef,
        ],
    )
    .unwrap();
    let frames = call_with(
        &server,
        AuthContext::for_principal("test", "minter").with_claim("auth_time", now.to_string()),
        request(IDENTITY_PROTOCOL_NAME, "issue_grant", &grant, None),
    );
    assert_identity_unavailable_with_7(&frames);
}

/// The client side of the model, through the client decode point's shape: a
/// server-built error carries what the accessors and `is_retryable` read.
#[test]
fn rpc_error_accessors_and_retryability() {
    let err = vgi_rpc::conformance_secondary::fail_error("UNAVAILABLE", "backend_down", 7.0);
    assert_eq!(err.error_code(), "UNAVAILABLE");
    assert_eq!(err.error_kind(), "backend_down");
    assert_eq!(err.error_details().len(), 3, "unknown types are kept raw");
    assert_eq!(err.details().len(), 2, "typed access skips the probe");
    assert_eq!(err.retry_info(), Some(7.0));
    assert_eq!(
        err.error_info().unwrap().get("fixture").map(String::as_str),
        Some(SECONDARY_PROTOCOL_NAME)
    );
    assert!(err.is_retryable());
    assert!(!vgi_rpc::conformance_secondary::oversized_error()
        .with_code(vgi_rpc::Code::Aborted)
        .is_retryable());
}

/// The hosted surface is sealed once serving starts: a registration after a
/// transport is bound (or after the hash was published) fails and changes
/// nothing.
#[test]
fn registration_after_serving_starts_fails() {
    let noop = || {
        MethodInfo::unary(
            "late",
            Arc::new(Schema::empty()),
            Arc::new(Schema::empty()),
            |_req, _ctx| Ok(None),
        )
    };
    let mut server = primary_server(RpcServer::builder());
    server.try_register(noop()).expect("before serving");
    server.notify_transport(TransportKind::Pipe, TransportCapabilities::none());
    assert!(server
        .try_register(MethodInfo::unary(
            "later",
            Arc::new(Schema::empty()),
            Arc::new(Schema::empty()),
            |_req, _ctx| Ok(None),
        ))
        .is_err());
    assert!(server.method("later").is_none());

    let mut hashed = primary_server(RpcServer::builder());
    let _ = hashed.protocol_hash();
    assert!(hashed.try_register(noop()).is_err());
}
