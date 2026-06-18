//! Client-side `__describe__` decoding.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::{Array, RecordBatch};
use arrow_schema::{Schema, SchemaRef};

use vgi_rpc::errors::{Result, RpcError};
use vgi_rpc::metadata::{
    DESCRIBE_VERSION_KEY, PROTOCOL_HASH_KEY, PROTOCOL_NAME_KEY, PROTOCOL_VERSION_KEY,
    REQUEST_VERSION_KEY, SERVER_ID_KEY,
};
use vgi_rpc::wire::{md_get, Metadata, StreamReader};

/// One method's introspected shape.
#[derive(Debug, Clone)]
pub struct MethodDescription {
    pub name: String,
    /// `"unary"` or `"stream"` (Python's `MethodType`).
    pub method_type: String,
    pub has_return: bool,
    pub params_schema: SchemaRef,
    pub result_schema: SchemaRef,
    pub has_header: bool,
    pub header_schema: Option<SchemaRef>,
    pub is_exchange: Option<bool>,
}

/// The full service description returned by `__describe__`.
#[derive(Debug, Clone)]
pub struct ServiceDescription {
    pub protocol_name: String,
    pub request_version: String,
    pub describe_version: String,
    pub protocol_hash: String,
    pub server_id: String,
    pub protocol_version: String,
    pub methods: HashMap<String, MethodDescription>,
}

impl ServiceDescription {
    pub fn method(&self, name: &str) -> Option<&MethodDescription> {
        self.methods.get(name)
    }
}

/// Decode an IPC schema-only stream (as produced by pyarrow's
/// `Schema.serialize()` / vgi-rpc's `schema_to_ipc`).
fn schema_from_ipc(bytes: &[u8]) -> Result<SchemaRef> {
    let reader = StreamReader::new(bytes)?;
    Ok(reader.schema())
}

/// Parse a `__describe__` response batch + metadata into a [`ServiceDescription`].
pub fn parse_describe_batch(batch: &RecordBatch, md: &Metadata) -> Result<ServiceDescription> {
    let names = batch
        .column_by_name("name")
        .ok_or_else(|| RpcError::new("ProtocolError", "describe batch missing 'name'"))?
        .as_string::<i32>();
    let mtypes = batch
        .column_by_name("method_type")
        .ok_or_else(|| RpcError::new("ProtocolError", "describe batch missing 'method_type'"))?
        .as_string::<i32>();
    let has_returns = batch
        .column_by_name("has_return")
        .ok_or_else(|| RpcError::new("ProtocolError", "describe batch missing 'has_return'"))?
        .as_boolean();
    let params_ipc = batch
        .column_by_name("params_schema_ipc")
        .ok_or_else(|| {
            RpcError::new(
                "ProtocolError",
                "describe batch missing 'params_schema_ipc'",
            )
        })?
        .as_binary::<i32>();
    let result_ipc = batch
        .column_by_name("result_schema_ipc")
        .ok_or_else(|| {
            RpcError::new(
                "ProtocolError",
                "describe batch missing 'result_schema_ipc'",
            )
        })?
        .as_binary::<i32>();
    let has_headers = batch
        .column_by_name("has_header")
        .ok_or_else(|| RpcError::new("ProtocolError", "describe batch missing 'has_header'"))?
        .as_boolean();
    let header_ipc = batch
        .column_by_name("header_schema_ipc")
        .ok_or_else(|| {
            RpcError::new(
                "ProtocolError",
                "describe batch missing 'header_schema_ipc'",
            )
        })?
        .as_binary::<i32>();
    let is_exchange = batch
        .column_by_name("is_exchange")
        .ok_or_else(|| RpcError::new("ProtocolError", "describe batch missing 'is_exchange'"))?
        .as_boolean();

    let mut methods = HashMap::with_capacity(batch.num_rows());
    for i in 0..batch.num_rows() {
        let name = names.value(i).to_string();
        let params_schema = schema_from_ipc(params_ipc.value(i))?;
        let result_schema = schema_from_ipc(result_ipc.value(i))?;
        let has_header = has_headers.value(i);
        let header_schema = if has_header && !header_ipc.is_null(i) {
            Some(schema_from_ipc(header_ipc.value(i))?)
        } else {
            None
        };
        let is_exchange = if is_exchange.is_null(i) {
            None
        } else {
            Some(is_exchange.value(i))
        };
        methods.insert(
            name.clone(),
            MethodDescription {
                name,
                method_type: mtypes.value(i).to_string(),
                has_return: has_returns.value(i),
                params_schema,
                result_schema,
                has_header,
                header_schema,
                is_exchange,
            },
        );
    }

    Ok(ServiceDescription {
        protocol_name: md_get(md, PROTOCOL_NAME_KEY).unwrap_or("").to_string(),
        request_version: md_get(md, REQUEST_VERSION_KEY).unwrap_or("").to_string(),
        describe_version: md_get(md, DESCRIBE_VERSION_KEY).unwrap_or("").to_string(),
        protocol_hash: md_get(md, PROTOCOL_HASH_KEY).unwrap_or("").to_string(),
        server_id: md_get(md, SERVER_ID_KEY).unwrap_or("").to_string(),
        protocol_version: md_get(md, PROTOCOL_VERSION_KEY).unwrap_or("").to_string(),
        methods,
    })
}

/// Convenience: an empty schema (for no-argument framework requests).
pub(crate) fn empty_schema() -> SchemaRef {
    Arc::new(Schema::empty())
}
