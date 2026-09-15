//! `vgi_rpc.Reflection.v1` -- discovery as an ordinary co-hosted protocol.
//!
//! Introspection used to be a hardcoded method name, `__describe__`, answered
//! from a pre-built batch before dispatch. That made it a thing every port had
//! to hand-implement, in a bespoke format, outside the machinery that serves
//! every other method -- which is how the ports drifted. Here it is a protocol
//! like any other, addressed by the same routing key as everything else.
//!
//! Following gRPC's reflection service and D-Bus's `org.freedesktop.DBus`, it
//! is co-hosted rather than special-cased. Its own major version sits in its
//! name, so an incompatible reflection is a routing failure a client can act on
//! rather than a mis-parse.
//!
//! Exempt from the `protocol_version` gate: this is the protocol a
//! version-mismatched client calls to learn *what* mismatched, and gating it
//! would deny the client the diagnosis it came for.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::builder::{
    ArrayBuilder, BinaryBuilder, BooleanBuilder, ListBuilder, StringBuilder, StructBuilder,
};
use arrow_array::{Array, ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Fields, Schema};

use crate::errors::{Result, RpcError};
use crate::introspect::schema_to_ipc;
use crate::protocol_hash::{compute_protocol_hash, HashMethod};
use crate::server::{MethodInfo, MethodType};
use crate::stream::empty_schema;

/// The wire name of the reflection protocol.
///
/// Fixed, and the one protocol name a client may know a priori: it is the
/// bootstrap, so there is nothing to discover it with.
pub const REFLECTION_PROTOCOL_NAME: &str = "vgi_rpc.Reflection.v1";

/// Values a method's `idempotency` may take, borrowed from gRPC.
///
/// With an HTTP transport and a policy proxy in the path, retries *will*
/// happen; without this nothing on the wire said what was safe to retry.
/// `unknown` is the default and means a caller must assume the worst.
pub const IDEMPOTENCY_LEVELS: [&str; 3] = ["unknown", "no_side_effects", "idempotent"];

/// What a stream method does, when that is knowable.
///
/// Whether a stream is an exchange is decided by the implementation, not by the
/// protocol definition, so a server describing its own surface often cannot say
/// -- `unknown` is the honest answer and is spelled rather than left null.
pub const STREAM_KINDS: [&str; 3] = ["unknown", "producer", "exchange"];

/// The `ProtocolSummary` struct fields, mirroring the reference field for field.
fn protocol_summary_fields() -> Fields {
    Fields::from(vec![
        Field::new("protocol", DataType::Utf8, false),
        Field::new("protocol_version", DataType::Utf8, false),
        Field::new("protocol_hash", DataType::Utf8, false),
        Field::new("deprecated", DataType::Boolean, false),
        Field::new("deprecation_message", DataType::Utf8, false),
        Field::new(
            "features",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
    ])
}

/// The `MethodInfo` struct fields.
fn method_info_fields() -> Fields {
    Fields::from(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("method_type", DataType::Utf8, false),
        Field::new("has_return", DataType::Boolean, false),
        Field::new("has_header", DataType::Boolean, false),
        Field::new("stream_kind", DataType::Utf8, false),
        Field::new("params_schema_ipc", DataType::Binary, false),
        Field::new("result_schema_ipc", DataType::Binary, false),
        Field::new("header_schema_ipc", DataType::Binary, false),
        Field::new("idempotency", DataType::Utf8, false),
        Field::new("deprecated", DataType::Boolean, false),
        Field::new("deprecation_message", DataType::Utf8, false),
    ])
}

/// The `ProtocolList` payload schema.
pub fn protocol_list_schema() -> Schema {
    Schema::new(vec![
        Field::new("server_id", DataType::Utf8, false),
        Field::new("server_version", DataType::Utf8, false),
        Field::new("request_version", DataType::Utf8, false),
        Field::new(
            "protocols",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::Struct(protocol_summary_fields()),
                true,
            ))),
            false,
        ),
    ])
}

/// The `ServiceDescription` payload schema.
///
/// Carries no server identity: two processes serving the same protocol must
/// describe it identically, or the description is not a property of the
/// protocol. Server identity lives on `ProtocolList`, which is a statement
/// about a server.
pub fn service_description_schema() -> Schema {
    let mut fields: Vec<Field> = protocol_summary_fields()
        .iter()
        .map(|f| (**f).clone())
        .collect();
    fields.push(Field::new(
        "methods",
        DataType::List(Arc::new(Field::new(
            "item",
            DataType::Struct(method_info_fields()),
            true,
        ))),
        false,
    ));
    Schema::new(fields)
}

/// Whether a method returns a value to its caller.
///
/// A stream's `result_schema` is the (empty) protocol-level return, not
/// something the caller receives, and a void unary method carries a zero-field
/// schema rather than an absent one -- so neither the emptiness check nor the
/// method type alone is the question being asked.
fn unary_has_return(info: &MethodInfo) -> bool {
    matches!(info.method_type, MethodType::Unary) && !info.result_schema.fields().is_empty()
}

/// The stream kind, or `""` for a unary method.
fn stream_kind_for(info: &MethodInfo) -> &'static str {
    match info.method_type {
        MethodType::Unary => "",
        MethodType::Producer => "producer",
        MethodType::Exchange => "exchange",
        // The state type is decided at runtime by the handler, so the protocol
        // definition genuinely cannot say -- and "unknown" is sayable, which is
        // why this is a string rather than a nullable bool.
        MethodType::Dynamic => "unknown",
    }
}

/// One protocol's canonical fingerprint.
pub fn binding_hash(name: &str, methods: &HashMap<String, MethodInfo>) -> Result<String> {
    let entries: Vec<HashMethod<'_>> = methods
        .values()
        .map(|info| HashMethod {
            name: &info.name,
            method_type: match info.method_type {
                MethodType::Unary => "unary",
                _ => "stream",
            },
            has_return: unary_has_return(info),
            has_header: info.header_schema.is_some(),
            params_schema: Some(info.params_schema.as_ref()),
            result_schema: Some(info.result_schema.as_ref()),
            header_schema: info.header_schema.as_deref(),
        })
        .collect();
    compute_protocol_hash(name, &entries)
        .map_err(|e| RpcError::protocol_error(format!("computing protocol hash for {name:?}: {e}")))
}

/// Build the single-row `ProtocolList` batch.
pub fn build_protocol_list(
    server_id: &str,
    server_version: &str,
    request_version: &str,
    protocols: &[(String, String, String)],
) -> Result<RecordBatch> {
    let schema = protocol_list_schema();
    let mut list_b = ListBuilder::new(StructBuilder::from_fields(protocol_summary_fields(), 0));
    {
        let sb = list_b.values();
        for (name, version, hash) in protocols {
            append_string(sb, 0, name);
            append_string(sb, 1, version);
            append_string(sb, 2, hash);
            sb.field_builder::<BooleanBuilder>(3)
                .unwrap()
                .append_value(false);
            append_string(sb, 4, "");
            // An empty but present feature list: additive capabilities announce
            // here rather than consuming version numbers.
            //
            // StructBuilder::from_fields boxes its child builders, so the list
            // child is ListBuilder<Box<dyn ArrayBuilder>> -- downcasting to the
            // concrete element builder returns None and panics.
            sb.field_builder::<ListBuilder<Box<dyn arrow_array::builder::ArrayBuilder>>>(5)
                .unwrap()
                .append(true);
            sb.append(true);
        }
    }
    list_b.append(true);

    let cols: Vec<ArrayRef> = vec![
        Arc::new(arrow_array::StringArray::from(vec![server_id])),
        Arc::new(arrow_array::StringArray::from(vec![server_version])),
        Arc::new(arrow_array::StringArray::from(vec![request_version])),
        Arc::new(list_b.finish()),
    ];
    RecordBatch::try_new(Arc::new(schema), cols)
        .map_err(|e| RpcError::protocol_error(format!("building ProtocolList batch: {e}")))
}

/// Build the single-row `ServiceDescription` batch.
pub fn build_service_description(
    protocol: &str,
    protocol_version: &str,
    protocol_hash: &str,
    methods: &HashMap<String, MethodInfo>,
) -> Result<RecordBatch> {
    let schema = service_description_schema();

    // Sorted so two ports iterating differently-ordered maps still agree.
    let mut names: Vec<&String> = methods.keys().collect();
    names.sort();

    let mut list_b = ListBuilder::new(StructBuilder::from_fields(method_info_fields(), 0));
    {
        let sb = list_b.values();
        for name in &names {
            let info = &methods[*name];
            append_string(sb, 0, &info.name);
            append_string(
                sb,
                1,
                match info.method_type {
                    MethodType::Unary => "unary",
                    _ => "stream",
                },
            );
            sb.field_builder::<BooleanBuilder>(2)
                .unwrap()
                .append_value(unary_has_return(info));
            sb.field_builder::<BooleanBuilder>(3)
                .unwrap()
                .append_value(info.header_schema.is_some());
            append_string(sb, 4, stream_kind_for(info));
            append_binary(sb, 5, &schema_to_ipc(&info.params_schema)?);
            // Empty rather than null when absent: a nullable column costs every
            // port a null check on a value it will only ever treat as absent.
            let result_ipc = if unary_has_return(info) {
                schema_to_ipc(&info.result_schema)?
            } else {
                Vec::new()
            };
            append_binary(sb, 6, &result_ipc);
            let header_ipc = match &info.header_schema {
                Some(h) => schema_to_ipc(h)?,
                None => Vec::new(),
            };
            append_binary(sb, 7, &header_ipc);
            append_string(sb, 8, IDEMPOTENCY_LEVELS[0]);
            sb.field_builder::<BooleanBuilder>(9)
                .unwrap()
                .append_value(false);
            append_string(sb, 10, "");
            sb.append(true);
        }
    }
    list_b.append(true);

    let empty_features = {
        let mut b = ListBuilder::new(StringBuilder::new());
        b.append(true);
        b.finish()
    };
    let cols: Vec<ArrayRef> = vec![
        Arc::new(arrow_array::StringArray::from(vec![protocol])),
        Arc::new(arrow_array::StringArray::from(vec![protocol_version])),
        Arc::new(arrow_array::StringArray::from(vec![protocol_hash])),
        Arc::new(arrow_array::BooleanArray::from(vec![false])),
        Arc::new(arrow_array::StringArray::from(vec![""])),
        Arc::new(empty_features),
        Arc::new(list_b.finish()),
    ];
    RecordBatch::try_new(Arc::new(schema), cols)
        .map_err(|e| RpcError::protocol_error(format!("building ServiceDescription batch: {e}")))
}

fn append_string(sb: &mut StructBuilder, idx: usize, value: &str) {
    sb.field_builder::<StringBuilder>(idx)
        .unwrap()
        .append_value(value);
}

fn append_binary(sb: &mut StructBuilder, idx: usize, value: &[u8]) {
    sb.field_builder::<BinaryBuilder>(idx)
        .unwrap()
        .append_value(value);
}

impl crate::server::RpcServer {
    /// Serve one call to `vgi_rpc.Reflection.v1`.
    ///
    /// Two methods, deliberately. `list_protocols` is the cheap question --
    /// what is here, and has it changed -- and the only one a client needs on a
    /// warm path, because `protocol_hash` answers "has it changed" without
    /// transferring any schema. `describe` is the expensive one, asked once.
    ///
    /// Self-description is not special-cased: reflection appears in its own
    /// output, so a client discovers it the same way it discovers everything
    /// else rather than having to know a priori what to ask.
    pub(crate) fn serve_reflection<W: std::io::Write>(
        &self,
        w: &mut W,
        req: &crate::server::Request,
    ) -> Result<bool> {
        let app_hash = binding_hash(&self.protocol_name, &self.methods)?;
        // Reflection describes itself with no methods of its own in the table:
        // they are framework-owned rather than registered, so the honest hash
        // is over an empty method set.
        let refl_methods: HashMap<String, MethodInfo> = HashMap::new();
        let refl_hash = binding_hash(REFLECTION_PROTOCOL_NAME, &refl_methods)?;

        let batch = match req.method.as_str() {
            "list_protocols" => build_protocol_list(
                &self.server_id,
                "",
                crate::metadata::REQUEST_VERSION,
                &[
                    (
                        self.protocol_name.clone(),
                        self.protocol_version.clone(),
                        app_hash,
                    ),
                    (
                        REFLECTION_PROTOCOL_NAME.to_string(),
                        String::new(),
                        refl_hash,
                    ),
                ],
            )?,
            "describe" => {
                let requested = reflection_describe_argument(&req.batch);
                if requested == self.protocol_name {
                    build_service_description(
                        &self.protocol_name,
                        &self.protocol_version,
                        &app_hash,
                        &self.methods,
                    )?
                } else if requested == REFLECTION_PROTOCOL_NAME {
                    build_service_description(
                        REFLECTION_PROTOCOL_NAME,
                        "",
                        &refl_hash,
                        &refl_methods,
                    )?
                } else {
                    // Named, not silently empty: an empty description reads as
                    // "this protocol has no methods".
                    let hosted = [self.protocol_name.as_str(), REFLECTION_PROTOCOL_NAME];
                    crate::server::write_error_stream(
                        w,
                        &empty_schema(),
                        &crate::binding::protocol_not_supported(&requested, &hosted),
                        &self.server_id,
                        &req.request_id,
                    )?;
                    return Ok(true);
                }
            }
            other => {
                crate::server::write_error_stream(
                    w,
                    &empty_schema(),
                    &RpcError::attribute_error(format!(
                        "Protocol '{REFLECTION_PROTOCOL_NAME}' has no method '{other}'. \
                         Available: [\"describe\", \"list_protocols\"]"
                    )),
                    &self.server_id,
                    &req.request_id,
                )?;
                return Ok(true);
            }
        };

        // The framework's ordinary convention for a structured return: the
        // payload rides as serialized bytes in a single `result` binary column.
        // Reflection is an ordinary protocol, so it is subject to it like
        // everything else.
        let nested = batch_to_ipc(&batch)?;
        let schema = Schema::new(vec![Field::new("result", DataType::Binary, false)]);
        let out = RecordBatch::try_new(
            Arc::new(schema),
            vec![Arc::new(arrow_array::BinaryArray::from(vec![nested.as_slice()])) as ArrayRef],
        )
        .map_err(|e| RpcError::protocol_error(format!("building reflection result: {e}")))?;
        let md = crate::server::build_envelope_metadata(&self.server_id, &req.request_id);
        crate::introspect::write_describe_response(w, &out, &md)?;
        Ok(true)
    }
}

/// Read the `protocol` argument off a `describe` request batch.
fn reflection_describe_argument(batch: &RecordBatch) -> String {
    let Some(col) = batch.column_by_name("protocol") else {
        return String::new();
    };
    let Some(arr) = col.as_any().downcast_ref::<arrow_array::StringArray>() else {
        return String::new();
    };
    if arr.len() == 0 || arr.is_null(0) {
        return String::new();
    }
    arr.value(0).to_string()
}

/// Serialize one batch as a complete IPC stream.
pub(crate) fn batch_to_ipc(batch: &RecordBatch) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut w = arrow_ipc::writer::StreamWriter::try_new(&mut buf, &batch.schema())
            .map_err(|e| RpcError::protocol_error(format!("opening IPC writer: {e}")))?;
        w.write(batch)
            .map_err(|e| RpcError::protocol_error(format!("writing batch: {e}")))?;
        w.finish()
            .map_err(|e| RpcError::protocol_error(format!("finishing IPC stream: {e}")))?;
    }
    Ok(buf)
}
