//! Client-side introspection over `vgi_rpc.Reflection.v1`.
//!
//! Introspection used to be `__describe__`: a hardcoded method name answered
//! from a pre-built batch in a bespoke format that every port hand-wrote, which
//! is how the ports drifted. It is now an ordinary co-hosted protocol, reached
//! by the same routing key as everything else.
//!
//! What survives here is the *client-side view*. [`ServiceDescription`] and
//! [`MethodDescription`] are convenience shapes for Rust callers, not a wire
//! format -- they were only ever the latter by accident of there having been a
//! single encoding. [`RpcClient::describe`](crate::RpcClient::describe) speaks
//! reflection and presents the reply in this shape, so callers did not have to
//! change.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::{Array, RecordBatch, StructArray};
use arrow_schema::{Schema, SchemaRef};

use vgi_rpc::errors::{Result, RpcError};
use vgi_rpc::wire::StreamReader;

/// Introspection format version, reported for readers who still look for it.
///
/// Vestigial: introspection is `vgi_rpc.Reflection.v1` now, a protocol whose
/// major version is part of its own name, so there is no separate format
/// number to negotiate and this will not move again.
pub const DESCRIBE_VERSION: &str = "5";

/// One method's introspected shape.
#[derive(Debug, Clone)]
pub struct MethodDescription {
    pub name: String,
    /// `"unary"` or `"stream"`.
    pub method_type: String,
    pub has_return: bool,
    pub params_schema: SchemaRef,
    pub result_schema: SchemaRef,
    pub has_header: bool,
    pub header_schema: Option<SchemaRef>,
    /// For streams: `Some(true)` for exchange, `Some(false)` for producer,
    /// `None` when the server cannot say. Always `None` for unary.
    pub is_exchange: Option<bool>,
}

/// One protocol as it appears in a `list_protocols` reply.
#[derive(Debug, Clone)]
pub struct ProtocolSummary {
    pub protocol: String,
    pub protocol_version: String,
    /// The canonical protocol hash -- the cheap answer to "has it changed",
    /// which is why `list_protocols` is the call a warm client makes.
    pub protocol_hash: String,
    pub deprecated: bool,
    pub deprecation_message: String,
    /// Additive capabilities, which announce here rather than consuming
    /// version numbers.
    pub features: Vec<String>,
}

/// What a server hosts, as returned by `list_protocols`.
#[derive(Debug, Clone)]
pub struct ProtocolList {
    pub server_id: String,
    pub server_version: String,
    pub request_version: String,
    pub protocols: Vec<ProtocolSummary>,
}

impl ProtocolList {
    /// The first hosted protocol that is not framework-owned -- the server's
    /// application surface, and the one [`describe`] asks about by default.
    ///
    /// [`describe`]: crate::RpcClient::describe
    pub fn primary(&self) -> Option<&ProtocolSummary> {
        self.protocols.iter().find(|p| {
            !p.protocol
                .starts_with(vgi_rpc::binding::RESERVED_PROTOCOL_PREFIX)
        })
    }
}

/// One protocol's full description.
#[derive(Debug, Clone)]
pub struct ServiceDescription {
    pub protocol_name: String,
    /// From the `list_protocols` hop. Empty when the caller named a protocol
    /// explicitly and that hop was skipped: it is a property of the server,
    /// and a description deliberately carries no server identity -- two
    /// processes serving the same protocol must describe it identically.
    pub request_version: String,
    pub describe_version: String,
    pub protocol_hash: String,
    /// From the `list_protocols` hop; see [`Self::request_version`].
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

/// An empty schema: what an absent one decodes to.
///
/// Absent is spelled as empty bytes rather than null on the wire, so that a
/// port need not null-check a value it will only ever treat as absent.
fn schema_or_empty(bytes: &[u8]) -> Result<SchemaRef> {
    if bytes.is_empty() {
        return Ok(empty_schema());
    }
    schema_from_ipc(bytes)
}

fn missing(what: &str, field: &str) -> RpcError {
    RpcError::new(
        "ProtocolError",
        format!("reflection {what} payload missing {field:?}"),
    )
}

/// Unwrap the single `result` column of a reflection reply into the nested
/// payload batch.
///
/// A structured return rides as serialized bytes in one binary column -- the
/// framework's ordinary unary convention. Reflection is an ordinary protocol,
/// so it is subject to it like everything else.
pub fn reflection_payload(batch: &RecordBatch) -> Result<RecordBatch> {
    let col = batch
        .column_by_name("result")
        .ok_or_else(|| missing("reply", "result"))?;
    let bytes = col.as_binary::<i32>();
    if bytes.len() == 0 || bytes.is_null(0) {
        return Err(missing("reply", "result"));
    }
    let mut reader = StreamReader::new(bytes.value(0))?;
    reader
        .read_next()?
        .map(|(b, _)| b)
        .ok_or_else(|| RpcError::new("ProtocolError", "reflection payload carried no batch"))
}

fn struct_string(sa: &StructArray, field: &str, row: usize) -> Result<String> {
    let col = sa
        .column_by_name(field)
        .ok_or_else(|| missing("struct", field))?;
    Ok(col.as_string::<i32>().value(row).to_string())
}

fn struct_bool(sa: &StructArray, field: &str, row: usize) -> Result<bool> {
    let col = sa
        .column_by_name(field)
        .ok_or_else(|| missing("struct", field))?;
    Ok(col.as_boolean().value(row))
}

fn struct_binary<'a>(sa: &'a StructArray, field: &str, row: usize) -> Result<&'a [u8]> {
    let col = sa
        .column_by_name(field)
        .ok_or_else(|| missing("struct", field))?;
    Ok(col.as_binary::<i32>().value(row))
}

/// Read the single-row list column `field` as its struct element array.
fn row0_struct_list(batch: &RecordBatch, field: &str) -> Result<(StructArray, usize, usize)> {
    let col = batch
        .column_by_name(field)
        .ok_or_else(|| missing("payload", field))?;
    let list = col.as_list::<i32>();
    if list.len() == 0 || list.is_null(0) {
        return Err(missing("payload", field));
    }
    let offsets = list.value_offsets();
    let start = offsets[0] as usize;
    let end = offsets[1] as usize;
    let values = list
        .values()
        .as_any()
        .downcast_ref::<StructArray>()
        .ok_or_else(|| missing("payload", field))?
        .clone();
    Ok((values, start, end))
}

fn row0_string(batch: &RecordBatch, field: &str) -> Result<String> {
    let col = batch
        .column_by_name(field)
        .ok_or_else(|| missing("payload", field))?;
    Ok(col.as_string::<i32>().value(0).to_string())
}

/// Parse a `list_protocols` payload batch.
pub fn parse_protocol_list(batch: &RecordBatch) -> Result<ProtocolList> {
    let (values, start, end) = row0_struct_list(batch, "protocols")?;
    let mut protocols = Vec::with_capacity(end - start);
    for i in start..end {
        let features = match values.column_by_name("features") {
            Some(col) => {
                let list = col.as_list::<i32>();
                if list.is_null(i) {
                    Vec::new()
                } else {
                    let items = list.value(i);
                    let strings = items.as_string::<i32>();
                    (0..strings.len())
                        .map(|j| strings.value(j).to_string())
                        .collect()
                }
            }
            None => Vec::new(),
        };
        protocols.push(ProtocolSummary {
            protocol: struct_string(&values, "protocol", i)?,
            protocol_version: struct_string(&values, "protocol_version", i)?,
            protocol_hash: struct_string(&values, "protocol_hash", i)?,
            deprecated: struct_bool(&values, "deprecated", i)?,
            deprecation_message: struct_string(&values, "deprecation_message", i)?,
            features,
        });
    }
    Ok(ProtocolList {
        server_id: row0_string(batch, "server_id")?,
        server_version: row0_string(batch, "server_version")?,
        request_version: row0_string(batch, "request_version")?,
        protocols,
    })
}

/// Parse a `describe` payload batch into this module's client-side shape.
///
/// `listing` supplies the two server-identity fields the description itself
/// does not carry; pass `None` when the `list_protocols` hop was skipped.
pub fn parse_service_description(
    batch: &RecordBatch,
    listing: Option<&ProtocolList>,
) -> Result<ServiceDescription> {
    let (values, start, end) = row0_struct_list(batch, "methods")?;
    let mut methods = HashMap::with_capacity(end - start);
    for i in start..end {
        let name = struct_string(&values, "name", i)?;
        let has_return = struct_bool(&values, "has_return", i)?;
        let has_header = struct_bool(&values, "has_header", i)?;
        let header_schema = if has_header {
            Some(schema_or_empty(struct_binary(
                &values,
                "header_schema_ipc",
                i,
            )?)?)
        } else {
            None
        };
        methods.insert(
            name.clone(),
            MethodDescription {
                name,
                method_type: struct_string(&values, "method_type", i)?,
                has_return,
                params_schema: schema_or_empty(struct_binary(&values, "params_schema_ipc", i)?)?,
                result_schema: schema_or_empty(struct_binary(&values, "result_schema_ipc", i)?)?,
                has_header,
                header_schema,
                is_exchange: is_exchange(&struct_string(&values, "stream_kind", i)?),
            },
        );
    }
    Ok(ServiceDescription {
        protocol_name: row0_string(batch, "protocol")?,
        request_version: listing
            .map(|l| l.request_version.clone())
            .unwrap_or_default(),
        describe_version: DESCRIBE_VERSION.to_string(),
        protocol_hash: row0_string(batch, "protocol_hash")?,
        server_id: listing.map(|l| l.server_id.clone()).unwrap_or_default(),
        protocol_version: row0_string(batch, "protocol_version")?,
        methods,
    })
}

/// Map a reflection stream kind back to this module's tri-state bool.
///
/// `""` (unary) and `"unknown"` both become `None`: a server describing its
/// own surface often genuinely cannot say whether a stream accepts input, and
/// "unknown" is the honest answer rather than a missing one.
fn is_exchange(stream_kind: &str) -> Option<bool> {
    match stream_kind {
        "exchange" => Some(true),
        "producer" => Some(false),
        _ => None,
    }
}

/// Convenience: an empty schema (for no-argument framework requests).
pub(crate) fn empty_schema() -> SchemaRef {
    Arc::new(Schema::empty())
}

/// The params schema of `vgi_rpc.Reflection.v1`'s `describe`.
pub(crate) fn describe_params_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![arrow_schema::Field::new(
        "protocol",
        arrow_schema::DataType::Utf8,
        false,
    )]))
}

/// A one-row `describe` request batch naming `protocol`.
pub(crate) fn describe_params(protocol: &str) -> Result<RecordBatch> {
    let schema = describe_params_schema();
    RecordBatch::try_new(
        schema,
        vec![Arc::new(arrow_array::StringArray::from(vec![protocol])) as arrow_array::ArrayRef],
    )
    .map_err(|e| RpcError::protocol_error(format!("building describe params: {e}")))
}

/// The error for a server that hosts nothing to describe.
pub(crate) fn no_application_protocol(listing: &ProtocolList) -> RpcError {
    RpcError::protocol_error(format!(
        "Server {:?} hosts no application protocol; it lists only {:?}.",
        listing.server_id,
        listing
            .protocols
            .iter()
            .map(|p| p.protocol.as_str())
            .collect::<Vec<_>>()
    ))
}
