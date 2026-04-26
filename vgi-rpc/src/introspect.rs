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
use sha2::{Digest, Sha256};

use crate::errors::{Result, RpcError};
use crate::metadata::{
    DESCRIBE_VERSION_KEY, PROTOCOL_HASH_KEY, PROTOCOL_NAME_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, SERVER_ID_KEY,
};
use crate::server::{MethodInfo, MethodType};
use crate::wire::{Metadata, StreamWriter};

pub const DESCRIBE_METHOD_NAME: &str = "__describe__";
pub const DESCRIBE_VERSION: &str = "4";

/// Schema of the describe response batch. Matches the Python
/// slim `_DESCRIBE_FIELDS` for DESCRIBE_VERSION 4 — Python-flavoured
/// columns (doc, param_types_json, param_defaults_json, param_docs_json)
/// are not on the wire.
pub fn describe_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("method_type", DataType::Utf8, false),
        Field::new("has_return", DataType::Boolean, false),
        Field::new("params_schema_ipc", DataType::Binary, false),
        Field::new("result_schema_ipc", DataType::Binary, false),
        Field::new("has_header", DataType::Boolean, false),
        Field::new("header_schema_ipc", DataType::Binary, true),
        Field::new("is_exchange", DataType::Boolean, true),
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
    let mut has_return_b = BooleanBuilder::new();
    let mut params_schema_b = BinaryBuilder::new();
    let mut result_schema_b = BinaryBuilder::new();
    let mut has_header_b = BooleanBuilder::new();
    let mut header_schema_b = BinaryBuilder::new();
    let mut is_exchange_b = BooleanBuilder::new();

    // Per-row canonical inputs for the protocol_hash.
    let mut hash_rows: Vec<HashRow> = Vec::with_capacity(names.len());

    for name in names {
        let m = &methods[name];
        name_b.append_value(&m.name);

        let mtype_str = match m.method_type {
            MethodType::Unary => "unary",
            MethodType::Producer | MethodType::Exchange | MethodType::Dynamic => "stream",
        };
        mtype_b.append_value(mtype_str);

        has_return_b.append_value(m.has_return);
        let params_ipc = schema_to_ipc(&m.params_schema)?;
        let result_ipc = schema_to_ipc(&m.result_schema)?;
        params_schema_b.append_value(&params_ipc);
        result_schema_b.append_value(&result_ipc);

        let has_header = m.header_schema.is_some();
        has_header_b.append_value(has_header);
        let header_ipc = match &m.header_schema {
            Some(hs) => {
                let bytes = schema_to_ipc(hs)?;
                header_schema_b.append_value(&bytes);
                Some(bytes)
            }
            None => {
                header_schema_b.append_null();
                None
            }
        };

        // Rust's MethodInfo doesn't carry the producer/exchange split for
        // dynamic streams; Python emits None for the same set. Mirror that
        // and feed `-` into the hash.
        is_exchange_b.append_null();

        hash_rows.push(HashRow {
            name: m.name.clone(),
            method_type: mtype_str.to_string(),
            has_return: m.has_return,
            has_header,
            is_exchange: None,
            params_ipc,
            result_ipc,
            header_ipc,
        });
    }

    let arrs: Vec<ArrayRef> = vec![
        Arc::new(name_b.finish()),
        Arc::new(mtype_b.finish()),
        Arc::new(has_return_b.finish()),
        Arc::new(params_schema_b.finish()),
        Arc::new(result_schema_b.finish()),
        Arc::new(has_header_b.finish()),
        Arc::new(header_schema_b.finish()),
        Arc::new(is_exchange_b.finish()),
    ];

    let batch = RecordBatch::try_new(schema, arrs)?;

    let protocol_hash = compute_protocol_hash(protocol_name, &hash_rows);

    let mut md = Metadata::new();
    md.insert(PROTOCOL_NAME_KEY.to_string(), protocol_name.to_string());
    md.insert(REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string());
    md.insert(DESCRIBE_VERSION_KEY.to_string(), DESCRIBE_VERSION.to_string());
    md.insert(PROTOCOL_HASH_KEY.to_string(), protocol_hash);
    md.insert(SERVER_ID_KEY.to_string(), server_id.to_string());

    Ok((batch, md))
}

struct HashRow {
    name: String,
    method_type: String,
    has_return: bool,
    has_header: bool,
    is_exchange: Option<bool>,
    params_ipc: Vec<u8>,
    result_ipc: Vec<u8>,
    header_ipc: Option<Vec<u8>>,
}

/// SHA-256 hex digest of the canonical describe payload. Mirrors Python's
/// `vgi_rpc.introspect.compute_protocol_hash` byte-for-byte.
fn compute_protocol_hash(protocol_name: &str, rows: &[HashRow]) -> String {
    let mut h = Sha256::new();
    h.update(b"vgi_rpc.describe.v");
    h.update(DESCRIBE_VERSION.as_bytes());
    h.update(b"|");
    h.update(REQUEST_VERSION.as_bytes());
    h.update(b"|");
    h.update(protocol_name.as_bytes());
    h.update(b"|");
    for r in rows {
        h.update([0x1f]);
        h.update(r.name.as_bytes());
        h.update([0x1e]);
        h.update(r.method_type.as_bytes());
        h.update([0x1e]);
        h.update(if r.has_return { b"1" } else { b"0" });
        h.update([0x1e]);
        h.update(if r.has_header { b"1" } else { b"0" });
        h.update([0x1e]);
        match r.is_exchange {
            Some(true) => h.update(b"1"),
            Some(false) => h.update(b"0"),
            None => h.update(b"-"),
        }
        h.update([0x1e]);
        h.update(&r.params_ipc);
        h.update([0x1e]);
        h.update(&r.result_ipc);
        h.update([0x1e]);
        if let Some(hi) = &r.header_ipc {
            h.update(hi);
        }
    }
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
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
    sw.write(&batch.clone().with_custom_metadata(metadata.clone()))?;
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
