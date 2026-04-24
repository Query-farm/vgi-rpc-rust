//! `__describe__` introspection.
//!
//! Builds a pre-cached Arrow RecordBatch at server construction time that
//! describes every registered method. `RpcServer` serves this directly when
//! it receives a `__describe__` request; the wire format matches the Python
//! canonical (`vgi_rpc/introspect.py`, DESCRIBE_VERSION = "3").

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, BooleanBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use crate::errors::{Result, RpcError};
use crate::metadata::{
    DESCRIBE_VERSION_KEY, PROTOCOL_NAME_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY, SERVER_ID_KEY,
};
use crate::server::{MethodInfo, MethodType};
use crate::wire::{Metadata, StreamWriter};

pub const DESCRIBE_METHOD_NAME: &str = "__describe__";
pub const DESCRIBE_VERSION: &str = "3";

/// Schema of the describe response batch. Matches the Python
/// `_DESCRIBE_FIELDS` exactly.
pub fn describe_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("method_type", DataType::Utf8, false),
        Field::new("doc", DataType::Utf8, true),
        Field::new("has_return", DataType::Boolean, false),
        Field::new("params_schema_ipc", DataType::Binary, false),
        Field::new("result_schema_ipc", DataType::Binary, false),
        Field::new("param_types_json", DataType::Utf8, true),
        Field::new("param_defaults_json", DataType::Utf8, true),
        Field::new("has_header", DataType::Boolean, false),
        Field::new("header_schema_ipc", DataType::Binary, true),
        Field::new("is_exchange", DataType::Boolean, true),
        Field::new("param_docs_json", DataType::Utf8, true),
    ]))
}

/// Build the describe batch + custom metadata for a set of methods.
pub fn build_describe(
    protocol_name: &str,
    methods: &HashMap<String, MethodInfo>,
    server_id: &str,
) -> Result<(RecordBatch, Metadata)> {
    let schema = describe_schema();

    // Sorted by name for deterministic output (matches Python).
    let mut names: Vec<&String> = methods.keys().collect();
    names.sort();

    let mut name_b = StringBuilder::new();
    let mut mtype_b = StringBuilder::new();
    let mut doc_b = StringBuilder::new();
    let mut has_return_b = BooleanBuilder::new();
    let mut params_schema_b = BinaryBuilder::new();
    let mut result_schema_b = BinaryBuilder::new();
    let mut param_types_b = StringBuilder::new();
    let mut param_defaults_b = StringBuilder::new();
    let mut has_header_b = BooleanBuilder::new();
    let mut header_schema_b = BinaryBuilder::new();
    let mut is_exchange_b = BooleanBuilder::new();
    let mut param_docs_b = StringBuilder::new();

    for name in names {
        let m = &methods[name];
        name_b.append_value(&m.name);

        // Python's MethodType is just UNARY/STREAM — collapse Producer/Exchange/Dynamic to "stream".
        let mtype_str = match m.method_type {
            MethodType::Unary => "unary",
            MethodType::Producer | MethodType::Exchange | MethodType::Dynamic => "stream",
        };
        mtype_b.append_value(mtype_str);

        match &m.doc {
            Some(d) => doc_b.append_value(d),
            None => doc_b.append_null(),
        }

        has_return_b.append_value(m.has_return);
        params_schema_b.append_value(schema_to_ipc(&m.params_schema)?);
        result_schema_b.append_value(schema_to_ipc(&m.result_schema)?);

        if m.param_types.is_empty() {
            param_types_b.append_null();
        } else {
            let mut map = serde_json::Map::new();
            for (k, v) in &m.param_types {
                map.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
            param_types_b.append_value(serde_json::Value::Object(map).to_string());
        }

        if m.param_defaults.is_empty() {
            param_defaults_b.append_null();
        } else {
            let mut map = serde_json::Map::new();
            for (k, v) in &m.param_defaults {
                map.insert(k.clone(), v.clone());
            }
            param_defaults_b.append_value(serde_json::Value::Object(map).to_string());
        }

        has_header_b.append_value(m.header_schema.is_some());
        match &m.header_schema {
            Some(hs) => header_schema_b.append_value(schema_to_ipc(hs)?),
            None => header_schema_b.append_null(),
        }

        // Python's MethodType has no Producer/Exchange distinction — Python
        // always emits None here for STREAM methods. Match that.
        is_exchange_b.append_null();

        if m.param_docs.is_empty() {
            param_docs_b.append_null();
        } else {
            let mut map = serde_json::Map::new();
            for (k, v) in &m.param_docs {
                map.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
            param_docs_b.append_value(serde_json::Value::Object(map).to_string());
        }
    }

    let arrs: Vec<ArrayRef> = vec![
        Arc::new(name_b.finish()),
        Arc::new(mtype_b.finish()),
        Arc::new(doc_b.finish()),
        Arc::new(has_return_b.finish()),
        Arc::new(params_schema_b.finish()),
        Arc::new(result_schema_b.finish()),
        Arc::new(param_types_b.finish()),
        Arc::new(param_defaults_b.finish()),
        Arc::new(has_header_b.finish()),
        Arc::new(header_schema_b.finish()),
        Arc::new(is_exchange_b.finish()),
        Arc::new(param_docs_b.finish()),
    ];

    let batch = RecordBatch::try_new(schema, arrs)?;

    let md: Metadata = vec![
        (PROTOCOL_NAME_KEY.to_string(), protocol_name.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (
            DESCRIBE_VERSION_KEY.to_string(),
            DESCRIBE_VERSION.to_string(),
        ),
        (SERVER_ID_KEY.to_string(), server_id.to_string()),
    ];

    Ok((batch, md))
}

/// Serialize a `Schema` as an IPC stream (schema-only, empty body) — matches
/// pyarrow's `Schema.serialize()`.
fn schema_to_ipc(schema: &Schema) -> Result<Vec<u8>> {
    // An IPC stream with just the schema message followed by the EOS marker.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema)?;
        w.finish()?;
    }
    Ok(buf)
}

/// Convenience: write the describe batch as a complete response IPC stream
/// to `w`. Used by both pipe/unix dispatch and HTTP unary.
pub fn write_describe_response<W: std::io::Write>(
    w: &mut W,
    batch: &RecordBatch,
    metadata: &Metadata,
) -> Result<()> {
    let mut sw = StreamWriter::new(w, batch.schema().as_ref())?;
    sw.write(batch, Some(metadata))?;
    sw.finish()?;
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn describe_err() -> RpcError {
    RpcError::new(
        "AttributeError",
        "Server does not support __describe__ (enable with RpcServer::builder().enable_describe(true))",
    )
}
