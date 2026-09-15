//! `vgi_rpc.Reflection.v1` describes itself, end to end.
//!
//! The unit tests beside the implementation pin the digest and the method
//! table it is computed from. What can only be checked here is that the table
//! actually reaches a client: that a caller doing the documented discovery
//! sequence -- `list_protocols`, then `describe` for each name it cares about
//! -- is told reflection's two methods rather than told it has none.
//!
//! This port shipped the empty answer for a while, and nothing local could see
//! it: `list_protocols` advertised the same digest this port's own `describe`
//! returned, so every internal consistency check passed. Only a port-to-port
//! comparison caught it. Hence the pinned digest below -- a local statement of
//! the cross-port contract, so a regression fails here rather than in a
//! six-port diff nobody runs on a feature branch.

use std::io::Cursor;
use std::sync::Arc;

use arrow_array::{Array, ArrayRef, BooleanArray, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};

use vgi_rpc::auth::AuthContext;
use vgi_rpc::metadata::{
    PROTOCOL_KEY, REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::reflection::{
    DESCRIBE_METHOD, LIST_PROTOCOLS_METHOD, REFLECTION_PROTOCOL_NAME as REFLECTION,
};
use vgi_rpc::server::ConnectionContext;
use vgi_rpc::wire::{Metadata, StreamReader, StreamWriter};
use vgi_rpc::{MethodInfo, RpcServer};

/// The digest every port must produce for reflection. Moving it means this
/// port and the reference disagree about whether they speak the same protocol.
const REFLECTION_HASH: &str = "3c7db4cae8cdfc93dc4a76e73b8b759e18e45e6a5811adba4e520366344b919a";

/// A server with an ordinary application method, so reflection is co-hosted
/// rather than alone -- which is the only configuration that ships.
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

/// Dispatch one request and return every (batch, metadata) frame written back.
fn call(server: &RpcServer, method: &str, batch: &RecordBatch) -> Vec<(RecordBatch, Metadata)> {
    let bytes = request_bytes(REFLECTION, method, batch);
    let mut input = Cursor::new(bytes);
    let mut output: Vec<u8> = Vec::new();
    let connection = ConnectionContext::new(AuthContext::anonymous(), Default::default());
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

fn describe(server: &RpcServer, protocol: &str) -> RecordBatch {
    let batch = RecordBatch::try_new(
        vgi_rpc::reflection::describe_params_schema(),
        vec![Arc::new(StringArray::from(vec![protocol])) as ArrayRef],
    )
    .unwrap();
    payload(&call(server, DESCRIBE_METHOD, &batch))
}

fn list_protocols(server: &RpcServer) -> RecordBatch {
    let empty = RecordBatch::new_empty(Arc::new(Schema::empty()));
    payload(&call(server, LIST_PROTOCOLS_METHOD, &empty))
}

/// Decode the nested payload out of the single `result` binary column.
fn payload(frames: &[(RecordBatch, Metadata)]) -> RecordBatch {
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

/// The struct elements of a `list<struct<...>>` column's single row.
fn list_structs(batch: &RecordBatch, column: &str) -> arrow_array::StructArray {
    let list = batch
        .column_by_name(column)
        .unwrap()
        .as_any()
        .downcast_ref::<arrow_array::ListArray>()
        .unwrap();
    list.value(0)
        .as_any()
        .downcast_ref::<arrow_array::StructArray>()
        .unwrap()
        .clone()
}

fn strings(structs: &arrow_array::StructArray, field: &str) -> Vec<String> {
    let col = structs
        .column_by_name(field)
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    (0..col.len()).map(|i| col.value(i).to_string()).collect()
}

fn bools(structs: &arrow_array::StructArray, field: &str) -> Vec<bool> {
    let col = structs
        .column_by_name(field)
        .unwrap()
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();
    (0..col.len()).map(|i| col.value(i)).collect()
}

/// Decode one method's `*_schema_ipc` column back into a schema.
fn schema_at(structs: &arrow_array::StructArray, field: &str, row: usize) -> Schema {
    let col = structs
        .column_by_name(field)
        .unwrap()
        .as_any()
        .downcast_ref::<arrow_array::BinaryArray>()
        .unwrap();
    let mut cursor = Cursor::new(col.value(row).to_vec());
    let reader = arrow_ipc::reader::StreamReader::try_new(&mut cursor, None).unwrap();
    reader.schema().as_ref().clone()
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

/// The finding itself: describing reflection returns both of its methods.
#[test]
fn describe_returns_both_reflection_methods() {
    let description = describe(&app_server(), REFLECTION);
    let methods = list_structs(&description, "methods");
    assert_eq!(
        strings(&methods, "name"),
        vec![
            DESCRIBE_METHOD.to_string(),
            LIST_PROTOCOLS_METHOD.to_string()
        ],
        "sorted by name, as the canonical description is"
    );
    assert_eq!(strings(&methods, "method_type"), vec!["unary", "unary"]);
    assert_eq!(bools(&methods, "has_return"), vec![true, true]);
    assert_eq!(bools(&methods, "has_header"), vec![false, false]);
    // A unary method's stream kind is empty rather than "unknown".
    assert_eq!(strings(&methods, "stream_kind"), vec!["", ""]);

    // Both return the framework's structured-return envelope.
    let result = Schema::new(vec![Field::new("result", DataType::Binary, false)]);
    assert_eq!(schema_at(&methods, "result_schema_ipc", 0), result);
    assert_eq!(schema_at(&methods, "result_schema_ipc", 1), result);

    // `describe` takes the wire name to describe; `list_protocols` takes
    // nothing. Getting either wrong moves the digest.
    assert_eq!(
        schema_at(&methods, "params_schema_ipc", 0),
        Schema::new(vec![Field::new("protocol", DataType::Utf8, false)])
    );
    assert!(schema_at(&methods, "params_schema_ipc", 1)
        .fields()
        .is_empty());
}

/// The cross-port digest, stated locally so a regression fails this suite.
#[test]
fn the_described_hash_is_the_reference_one() {
    let description = describe(&app_server(), REFLECTION);
    assert_eq!(string_at(&description, "protocol"), REFLECTION);
    assert_eq!(string_at(&description, "protocol_hash"), REFLECTION_HASH);
}

/// `list_protocols` and `describe` must agree -- they did before, on the wrong
/// value, which is exactly why this alone is not the test.
#[test]
fn the_listing_advertises_the_same_hash() {
    let server = app_server();
    let listing = list_protocols(&server);
    let protocols = list_structs(&listing, "protocols");
    let names = strings(&protocols, "protocol");
    let index = names
        .iter()
        .position(|n| n == REFLECTION)
        .expect("reflection lists itself");
    assert_eq!(strings(&protocols, "protocol_hash")[index], REFLECTION_HASH);
    assert_eq!(
        string_at(&describe(&server, REFLECTION), "protocol_hash"),
        REFLECTION_HASH
    );
}

/// Reflection's own methods are not the application's: registering them into
/// reflection's table must not reach the application's surface, whose digest
/// is a conformance contract of its own.
#[test]
fn the_application_surface_is_untouched() {
    let server = app_server();
    let description = describe(&server, "Service");
    assert_eq!(
        strings(&list_structs(&description, "methods"), "name"),
        vec!["noop".to_string()]
    );
    assert_eq!(
        string_at(&description, "protocol_hash"),
        server.protocol_hash()
    );
    assert_ne!(server.protocol_hash(), REFLECTION_HASH);
}

/// Reflection answers the two methods it describes -- the point of describing
/// them. A name it does not host is refused with the ones it does.
#[test]
fn it_answers_what_it_describes() {
    let server = app_server();
    let described: Vec<String> = strings(
        &list_structs(&describe(&server, REFLECTION), "methods"),
        "name",
    );
    for method in &described {
        let batch = RecordBatch::try_new(
            vgi_rpc::reflection::describe_params_schema(),
            vec![Arc::new(StringArray::from(vec![REFLECTION])) as ArrayRef],
        )
        .unwrap();
        let frames = call(&server, method, &batch);
        assert!(
            error_metadata(&frames).is_none(),
            "{method} answered with an error: {frames:?}"
        );
    }
    let frames = call(
        &server,
        "no_such_method",
        &RecordBatch::new_empty(Arc::new(Schema::empty())),
    );
    let rendered = format!("{:?}", error_metadata(&frames).expect("an error"));
    for method in &described {
        assert!(rendered.contains(method.as_str()), "{rendered}");
    }
}

fn error_metadata(frames: &[(RecordBatch, Metadata)]) -> Option<&Metadata> {
    frames
        .iter()
        .find(|(_, md)| {
            md.get(vgi_rpc::metadata::LOG_LEVEL_KEY).map(String::as_str) == Some("EXCEPTION")
        })
        .map(|(_, md)| md)
}
