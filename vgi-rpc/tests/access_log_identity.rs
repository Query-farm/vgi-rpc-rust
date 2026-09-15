//! An access record names the protocol that *owns* the dispatched method --
//! and carries that protocol's digest.
//!
//! `access-log-spec.md` §3 makes `protocol` "the wire name of the protocol that
//! owns the dispatched method … not a server-wide default", and `protocol_hash`
//! that protocol's canonical digest -- "the registry key when decoding archived
//! records".
//!
//! This is the one failure in the multi-service change that is silent. A
//! mislabelled record is well-formed, passes the schema, and feeds a plausible
//! dashboard while a consumer keying on `protocol_hash` decodes it against the
//! wrong description. And it is invisible to every test that does not call a
//! *secondary* protocol, because for an application method the primary **is**
//! the owning binding -- which is why the checks below drive reflection rather
//! than the application surface.
//!
//! Two independent ways to get the digest wrong are covered, because this port
//! had both:
//!
//! 1. the *wrong protocol's* digest -- the primary's, stamped on a reflection
//!    record; and
//! 2. the right protocol's digest *computed the wrong way* -- the retired
//!    `__describe__` payload hashed serialized Arrow IPC bytes, which each
//!    language may legitimately spell differently for the same logical schema,
//!    so an archived record could not be keyed against the canonical registry
//!    at all.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

use arrow_array::RecordBatch;
use arrow_schema::Schema;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt; // for oneshot

use vgi_rpc::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};
use vgi_rpc::metadata::{
    LOG_LEVEL_KEY, LOG_MESSAGE_KEY, PROTOCOL_KEY, REQUEST_ID_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::reflection::{describe_retired, REFLECTION_PROTOCOL_NAME, RETIRED_DESCRIBE_METHOD};
use vgi_rpc::server::ConnectionContext;
use vgi_rpc::wire::{Metadata, StreamReader, StreamWriter};
use vgi_rpc::{MethodInfo, RpcServer};

/// What one access record carries about protocol identity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    method: String,
    protocol: String,
    protocol_hash: String,
}

#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<Record>>,
}

impl Recorder {
    fn records(&self) -> Vec<Record> {
        self.seen.lock().unwrap().clone()
    }
    fn one(&self, method: &str) -> Record {
        self.records()
            .into_iter()
            .find(|r| r.method == method)
            .unwrap_or_else(|| {
                panic!(
                    "no access record for {method:?}; saw {:?}",
                    self.records()
                        .iter()
                        .map(|r| r.method.clone())
                        .collect::<Vec<_>>()
                )
            })
    }
}

impl DispatchHook for Recorder {
    fn on_dispatch_start(&self, _info: &DispatchInfo) -> HookToken {
        0
    }
    fn on_dispatch_end(
        &self,
        _token: HookToken,
        info: &DispatchInfo,
        _error: Option<&vgi_rpc::RpcError>,
        _stats: &CallStatistics,
    ) {
        self.seen.lock().unwrap().push(Record {
            method: info.method.clone(),
            protocol: info.protocol.clone(),
            protocol_hash: info.protocol_hash.clone(),
        });
    }
}

fn server_with(hook: Arc<Recorder>) -> RpcServer {
    let mut server = RpcServer::builder()
        .server_id("srv")
        .protocol_name("Service")
        .protocol_version("2.0.0")
        .with_hook(hook)
        .build();
    server.register(MethodInfo::unary(
        "noop",
        Arc::new(Schema::empty()),
        Arc::new(Schema::empty()),
        |_req, _ctx| Ok(None),
    ));
    server
}

fn empty_batch() -> RecordBatch {
    RecordBatch::new_empty(Arc::new(Schema::empty()))
}

fn request_bytes(protocol: &str, method: &str) -> Vec<u8> {
    let batch = empty_batch();
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, batch.schema_ref()).unwrap();
        let mut md = Metadata::new();
        md.insert(RPC_METHOD_KEY.into(), method.into());
        if !protocol.is_empty() {
            md.insert(PROTOCOL_KEY.into(), protocol.into());
        }
        md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
        md.insert(REQUEST_ID_KEY.into(), format!("req-{method}"));
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Dispatch one request over the byte-stream path; return the response frames.
fn call(server: &RpcServer, protocol: &str, method: &str) -> Vec<(RecordBatch, Metadata)> {
    let mut input = Cursor::new(request_bytes(protocol, method));
    let mut output: Vec<u8> = Vec::new();
    server
        .serve_one_with_context(&mut input, &mut output, &ConnectionContext::default())
        .unwrap();
    let mut cursor = Cursor::new(output);
    let mut reader = StreamReader::new(&mut cursor).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.read_next().unwrap() {
        frames.push(frame);
    }
    frames
}

fn error_message(frames: &[(RecordBatch, HashMap<String, String>)]) -> String {
    frames
        .iter()
        .find(|(_, md)| md.get(LOG_LEVEL_KEY).map(String::as_str) == Some("EXCEPTION"))
        .map(|(_, md)| md.get(LOG_MESSAGE_KEY).cloned().unwrap_or_default())
        .unwrap_or_else(|| panic!("expected an error envelope"))
}

// ---------------------------------------------------------------------------
// The accessor
// ---------------------------------------------------------------------------

/// The precondition that makes every other check here meaningful.
///
/// If reflection and the application hashed alike, stamping the primary
/// everywhere would be both invisible and harmless, and none of these tests
/// would prove anything.
#[test]
fn the_two_bindings_do_not_share_a_digest() {
    let server = server_with(Arc::new(Recorder::default()));
    assert_ne!(
        server.protocol_identity(REFLECTION_PROTOCOL_NAME).hash,
        server.protocol_hash()
    );
}

#[test]
fn the_accessor_returns_the_owning_bindings_identity() {
    let server = server_with(Arc::new(Recorder::default()));

    let app = server.protocol_identity("Service");
    assert_eq!(app.name, "Service");
    assert_eq!(app.hash, server.protocol_hash());
    assert_eq!(app.version, "2.0.0");

    let refl = server.protocol_identity(REFLECTION_PROTOCOL_NAME);
    assert_eq!(refl.name, REFLECTION_PROTOCOL_NAME);
    assert_ne!(refl.hash, server.protocol_hash());
    // The framework's own protocols declare no contract version of their own,
    // and borrowing the application's would claim one they do not have.
    assert_eq!(refl.version, "");
}

/// `__transport_options__` and `__upload_url__` belong to no protocol. The
/// spec prescribes the server's primary for those, so the fallback is the
/// specified behaviour rather than a gap in it.
#[test]
fn an_unowned_framework_endpoint_falls_back_to_the_primary() {
    let server = server_with(Arc::new(Recorder::default()));
    let unowned = server.protocol_identity("");
    assert_eq!(unowned.name, "Service");
    assert_eq!(unowned.hash, server.protocol_hash());
}

/// The digest is the canonical one, not the digest the retired `__describe__`
/// payload carried.
///
/// Those differ by construction -- different domain separator, different
/// preimage -- so this pins the *definition* rather than a value: a port
/// logging the legacy digest publishes a registry key no other port can
/// resolve, and nothing about the resulting record looks wrong.
#[test]
fn the_logged_digest_is_the_canonical_one() {
    let server = server_with(Arc::new(Recorder::default()));
    let canonical = vgi_rpc::protocol_hash::compute_protocol_hash(
        "Service",
        &vgi_rpc::reflection::hash_methods(server.methods()),
    )
    .unwrap();
    assert_eq!(server.protocol_hash(), canonical);
}

// ---------------------------------------------------------------------------
// Every emit site
// ---------------------------------------------------------------------------

#[test]
fn a_byte_stream_reflection_call_is_logged_as_reflection() {
    let hook = Arc::new(Recorder::default());
    let server = server_with(hook.clone());

    call(&server, "Service", "noop");
    call(&server, REFLECTION_PROTOCOL_NAME, "list_protocols");

    let app = hook.one("noop");
    assert_eq!(app.protocol, "Service");
    assert_eq!(app.protocol_hash, server.protocol_hash());

    let refl = hook.one("list_protocols");
    assert_eq!(
        refl.protocol, REFLECTION_PROTOCOL_NAME,
        "a record must name the protocol that owns the dispatched method"
    );
    assert_ne!(
        refl.protocol_hash, app.protocol_hash,
        "a reflection record carrying the application's digest decodes against \
         the wrong description, and nothing about it looks wrong"
    );
    assert_eq!(
        refl.protocol_hash,
        server.protocol_identity(REFLECTION_PROTOCOL_NAME).hash
    );
}

#[tokio::test]
async fn an_http_reflection_call_is_logged_as_reflection() {
    let hook = Arc::new(Recorder::default());
    let server = Arc::new(server_with(hook.clone()));
    let app_hash = server.protocol_hash().to_string();
    let state = vgi_rpc::http::HttpState::builder().server(server).build();

    for (protocol, method) in [
        ("Service", "noop"),
        (REFLECTION_PROTOCOL_NAME, "list_protocols"),
    ] {
        let resp = vgi_rpc::http::build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{protocol}/{method}"))
                    .header(header::CONTENT_TYPE, "application/vnd.apache.arrow.stream")
                    .body(Body::from(request_bytes(protocol, method)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{protocol}/{method}");
    }

    let app = hook.one("noop");
    assert_eq!(app.protocol, "Service");
    assert_eq!(app.protocol_hash, app_hash);

    let refl = hook.one("list_protocols");
    assert_eq!(refl.protocol, REFLECTION_PROTOCOL_NAME);
    assert_ne!(refl.protocol_hash, app_hash);
}

// ---------------------------------------------------------------------------
// A structural guard, because the failure mode is "someone adds an emit site"
// ---------------------------------------------------------------------------

/// Both identity fields must be filled from the shared accessor, at the one
/// place they are filled.
///
/// End-to-end tests cannot catch the real failure here, which is a *future*
/// emit site that stamps the server's primary: the suite stays green and the
/// records stay wrong. So this asserts the shape of the source instead --
/// `DispatchInfo::from_request` is the only place the three identity fields are
/// set, and it sets them from `RpcServer::protocol_identity`.
///
/// The whole `src` tree is walked rather than a fixed list of files, because
/// the thing being guarded against is a site that does not exist yet.
///
/// This catches a site that stamps the *wrong* identity. It does not catch one
/// that stamps *none* -- a hand-built `DispatchInfo` has nothing to assign, so
/// this scan sees nothing to object to. That half is
/// `a_dispatch_record_may_only_be_built_by_the_one_constructor` below; neither
/// test is sufficient alone.
#[test]
fn no_emit_site_may_stamp_the_protocol_identity_itself() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let hooks = std::fs::read_to_string(src.join("hooks.rs")).unwrap();
    assert!(
        hooks.contains("let identity = server.protocol_identity(&req.protocol);"),
        "DispatchInfo::from_request must read the identity off the resolved binding"
    );
    for field in ["protocol", "protocol_hash", "protocol_version"] {
        assert!(
            hooks.contains(&format!("{field}: identity.")),
            "from_request must fill {field} from the accessor's result"
        );
    }

    // A dispatch record is only ever bound to one of these names in this
    // crate; an assignment through any of them is an emit site overriding what
    // the accessor produced.
    const RECEIVERS: [&str; 3] = ["di.", "info.", "dispatch_info."];
    const FIELDS: [&str; 3] = ["protocol =", "protocol_hash =", "protocol_version ="];

    let mut checked = 0usize;
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            checked += 1;
            for (n, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.starts_with("//") {
                    continue;
                }
                for receiver in RECEIVERS {
                    for field in FIELDS {
                        assert!(
                            !line.contains(&format!("{receiver}{field}")),
                            "{}:{} assigns {receiver}{field} on a dispatch record. Every emit \
                             site must take the name and the hash together from \
                             RpcServer::protocol_identity -- setting either of them here is how \
                             a record ends up naming one protocol and carrying another's digest, \
                             which is well-formed, passes the schema, and decodes against the \
                             wrong description.",
                            path.file_name().unwrap().to_string_lossy(),
                            n + 1
                        );
                    }
                }
            }
        }
    }
    assert!(checked > 10, "the source walk found only {checked} files");
}

/// The blind spot the scan above does not cover: a site that fills the identity
/// fields with *nothing*.
///
/// `no_emit_site_may_stamp_the_protocol_identity_itself` looks for
/// *assignments*, so it catches a site that stamps the wrong protocol. It does
/// not catch one that stamps none -- and forgetting is the likelier mistake.
/// Mutation-checked in both directions: pointing `info.protocol` at the
/// server's primary fails that test, while adding a `DispatchInfo { .. }`
/// literal that never mentions the three fields passed it. Those records carry
/// `protocol: ""` and `protocol_hash: ""`, which is not a milder failure than
/// the wrong digest -- it is an unfilterable, undecodable record.
///
/// So this pins the stronger property: outside `hooks.rs`, a `DispatchInfo`
/// may only come into existence through `DispatchInfo::from_request`. Fields
/// you cannot skip are fields you cannot forget.
#[test]
fn a_dispatch_record_may_only_be_built_by_the_one_constructor() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // Production code only. Every module in this crate keeps its unit tests in
    // a single trailing `#[cfg(test)] mod tests`, and those legitimately build
    // `DispatchInfo` literals as fixtures for the *consumer* side (the access
    // log, otel, sentry) -- which is a different thing from an emit site.
    // The `saw_emit_sites` assertion at the end is what stops this heuristic
    // from silently swallowing a whole file and passing vacuously.
    fn production_code(text: &str) -> &str {
        match text.find("#[cfg(test)]") {
            Some(at) => &text[..at],
            None => text,
        }
    }

    let mut saw_emit_sites: Vec<String> = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            // `hooks.rs` defines the struct and the constructor; it is the one
            // place a `DispatchInfo` is allowed to be assembled field by field.
            if name == "hooks.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let code = production_code(&text);
            for (n, line) in code.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                for forbidden in ["DispatchInfo {", "DispatchInfo::default()"] {
                    assert!(
                        !trimmed.contains(forbidden),
                        "{name}:{} builds a DispatchInfo itself ({forbidden}). Every record \
                         must come from DispatchInfo::from_request, which reads protocol, \
                         protocol_hash and protocol_version off RpcServer::protocol_identity. \
                         A hand-built record silently leaves them empty -- a record that names \
                         no protocol and carries no digest cannot be filtered or decoded at \
                         all, and nothing about it looks wrong.",
                        n + 1
                    );
                }
            }
            if (code.contains(".on_dispatch_start(") || code.contains(".on_dispatch_end("))
                && code.contains("DispatchInfo::from_request(")
            {
                // A site that fires a hook either builds its record with the
                // constructor or was handed one (ChainHook forwards).
                saw_emit_sites.push(name);
            }
        }
    }

    saw_emit_sites.sort();
    // The emit sites that exist today. Not a closed list -- a new one is
    // welcome -- but if the walk stops finding these, the scan above has
    // stopped looking at production code and every assertion in it is vacuous.
    for expected in ["http.rs", "reflection.rs", "server.rs"] {
        assert!(
            saw_emit_sites.iter().any(|f| f == expected),
            "the source walk found no hook-firing code in {expected}; it saw \
             {saw_emit_sites:?}. Either an emit site moved or this scan is \
             reading the wrong half of the files."
        );
    }
}

// ---------------------------------------------------------------------------
// `__describe__` is retired, not merely absent
// ---------------------------------------------------------------------------

/// A stale caller is told where introspection went.
///
/// "Retired" and "this server was built without introspection" are
/// indistinguishable from the caller's side and need opposite fixes: one is a
/// client to update, the other a server to reconfigure.
/// The properties a stale caller needs, asserted on the message itself.
///
/// Spelled out at each site rather than compared against
/// `describe_retired()`: a test that only checks the wire carries whatever
/// that function returns still passes when the function is gutted back to
/// "unknown method", which is the regression this whole group exists to catch.
fn assert_names_the_replacement(message: &str) {
    assert!(message.to_lowercase().contains("retired"), "{message}");
    assert!(message.contains(REFLECTION_PROTOCOL_NAME), "{message}");
    assert!(message.contains("list_protocols"), "{message}");
    assert!(message.contains("describe"), "{message}");
}

#[test]
fn the_refusal_names_the_replacement() {
    assert_names_the_replacement(&describe_retired().message);
}

#[test]
fn a_byte_stream_describe_call_is_refused_with_the_replacement() {
    let server = server_with(Arc::new(Recorder::default()));
    // No routing key: a client stale enough to call `__describe__` predates it,
    // and telling such a caller only that it failed to route is not its problem.
    assert_names_the_replacement(&error_message(&call(&server, "", RETIRED_DESCRIBE_METHOD)));
}

/// Only `__describe__` is special-cased. Every other reserved name keeps the
/// plain "no such method" answer, which is what a client probing for an
/// optional method needs.
#[test]
fn another_reserved_name_keeps_the_generic_answer() {
    let server = server_with(Arc::new(Recorder::default()));
    let message = error_message(&call(&server, "Service", "__not_a_thing__"));
    assert!(!message.to_lowercase().contains("retired"), "{message}");
}

#[tokio::test]
async fn an_http_describe_call_is_refused_with_the_replacement() {
    let state = vgi_rpc::http::HttpState::builder()
        .server(Arc::new(server_with(Arc::new(Recorder::default()))))
        .build();
    let resp = vgi_rpc::http::build_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/{RETIRED_DESCRIBE_METHOD}"))
                .header(header::CONTENT_TYPE, "application/vnd.apache.arrow.stream")
                .body(Body::from(request_bytes("", RETIRED_DESCRIBE_METHOD)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let mut cursor = Cursor::new(bytes.to_vec());
    let mut reader = StreamReader::new(&mut cursor).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.read_next().unwrap() {
        frames.push(frame);
    }
    assert_names_the_replacement(&error_message(&frames));
}
