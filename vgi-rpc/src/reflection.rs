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
use std::sync::{Arc, OnceLock};

use arrow_array::builder::{
    ArrayBuilder, BinaryBuilder, BooleanBuilder, ListBuilder, StringBuilder, StructBuilder,
};
use arrow_array::{Array, ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef};

use crate::errors::{Result, RpcError};
use crate::protocol_hash::{compute_protocol_hash, HashMethod};
use crate::server::{MethodInfo, MethodType};
use crate::stream::empty_schema;

/// The wire name of the reflection protocol.
///
/// Fixed, and the one protocol name a client may know a priori: it is the
/// bootstrap, so there is nothing to discover it with.
pub const REFLECTION_PROTOCOL_NAME: &str = "vgi_rpc.Reflection.v1";

/// The method that returns one protocol's full description.
pub const DESCRIBE_METHOD: &str = "describe";

/// The method that lists every protocol a server hosts.
pub const LIST_PROTOCOLS_METHOD: &str = "list_protocols";

/// The method introspection used to be, kept only so the refusal can name its
/// replacement.
///
/// No server answers it. It is spelled here because "retired" and "this server
/// was built without introspection" are indistinguishable from the caller's
/// side, and they need opposite fixes: one is a client to update, the other a
/// server to reconfigure. A stale caller told merely "no such method" reads the
/// second while suffering the first.
pub const RETIRED_DESCRIBE_METHOD: &str = "__describe__";

/// The answer to a stale `__describe__` caller: where introspection went.
///
/// Only `__describe__` is special-cased. Every other reserved name keeps the
/// plain "no such method" answer, which is what a client probing for an
/// optional method needs.
///
/// Unlike the Python reference -- where `_reflection` imports the server module,
/// so the protocol name has to be spelled a second time and pinned by a test --
/// the name is used directly here and cannot drift from the protocol it points
/// at.
pub fn describe_retired() -> RpcError {
    RpcError::attribute_error(format!(
        "'{RETIRED_DESCRIBE_METHOD}' was retired. Introspection is now the \
         '{REFLECTION_PROTOCOL_NAME}' protocol: call 'list_protocols' for what this \
         server hosts, then 'describe' for one protocol's methods."
    ))
}

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

/// The params schema of [`DESCRIBE_METHOD`]: the wire name to describe.
pub fn describe_params_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "protocol",
        DataType::Utf8,
        false,
    )]))
}

/// The result schema both reflection methods share.
///
/// Reflection returns its payload the way every structured return travels
/// here: serialized into a single non-null `result` binary column. It is an
/// ordinary protocol, so the convention applies to it too.
pub fn reflection_result_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "result",
        DataType::Binary,
        false,
    )]))
}

/// Reflection's own method table -- the two methods it answers.
///
/// Registered rather than left empty. An earlier reading had it that the table
/// is "honestly empty" because reflection's methods are framework-owned rather
/// than registered; that inverts the contract. The table is what `describe`
/// reports and what [`binding_hash`] is computed over, so an empty one is not
/// honesty about an empty protocol -- it is a protocol lying about itself. A
/// client discovering a server the documented way -- `list_protocols`, then
/// `describe` for each name it cares about -- would be told reflection exists
/// and then told it has no methods, leaving it unable to learn how to call the
/// protocol it is already calling.
///
/// The entries carry schemas and an unreachable handler: reflection dispatches
/// from `RpcServer::serve_reflection`, which matches the method name itself,
/// and this table is never inserted into a server's registered methods. The
/// handler is spelled anyway, returning an error, so that a future caller which
/// *does* register these gets a diagnosis rather than the `unwrap` panic a
/// handler-less registration would earn.
pub fn reflection_methods() -> &'static HashMap<String, MethodInfo> {
    static METHODS: OnceLock<HashMap<String, MethodInfo>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let mut methods: HashMap<String, MethodInfo> = HashMap::new();
        methods.insert(
            DESCRIBE_METHOD.to_string(),
            MethodInfo::unary(
                DESCRIBE_METHOD,
                describe_params_schema(),
                reflection_result_schema(),
                |_req, _ctx| Err(served_by_the_framework(DESCRIBE_METHOD)),
            )
            .doc("Return one protocol's full description.")
            .param_type("protocol", "str"),
        );
        methods.insert(
            LIST_PROTOCOLS_METHOD.to_string(),
            MethodInfo::unary(
                LIST_PROTOCOLS_METHOD,
                empty_schema(),
                reflection_result_schema(),
                |_req, _ctx| Err(served_by_the_framework(LIST_PROTOCOLS_METHOD)),
            )
            .doc("Return every protocol this server hosts, with versions and hashes."),
        );
        methods
    })
}

/// Reflection's method names, sorted -- for the "no such method" diagnostic.
pub fn sorted_reflection_method_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = reflection_methods().keys().map(String::as_str).collect();
    names.sort_unstable();
    names
}

/// The error a reflection registration's handler would return if one were ever
/// reached. See [`reflection_methods`].
fn served_by_the_framework(method: &str) -> RpcError {
    RpcError::protocol_error(format!(
        "'{REFLECTION_PROTOCOL_NAME}.{method}' is served by the framework's own dispatcher, \
         not from a registered handler."
    ))
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
fn stream_kind_for(info: &MethodInfo) -> String {
    match info.method_type {
        MethodType::Unary => String::new(),
        MethodType::Producer => "producer".to_string(),
        MethodType::Exchange => "exchange".to_string(),
        // A runtime output schema does not make the kind unknowable: the
        // declaration states it separately. "unknown" remains sayable for a
        // registration that genuinely does not.
        MethodType::Dynamic if !info.declared_stream_kind.is_empty() => {
            info.declared_stream_kind.clone()
        }
        MethodType::Dynamic => "unknown".to_string(),
    }
}

/// The hash inputs for one method table.
///
/// Split out from [`binding_hash`] so a failing digest can be diffed rather
/// than guessed at: feed these to
/// [`canonical_description`](crate::protocol_hash::canonical_description) and
/// compare the JSON against the reference's.
pub fn hash_methods(methods: &HashMap<String, MethodInfo>) -> Vec<HashMethod<'_>> {
    methods
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
        .collect()
}

/// One protocol's canonical fingerprint.
pub fn binding_hash(name: &str, methods: &HashMap<String, MethodInfo>) -> Result<String> {
    let entries = hash_methods(methods);
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
            sb.field_builder::<ListBuilder<Box<dyn ArrayBuilder>>>(5)
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
            append_string(sb, 4, &stream_kind_for(info));
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
    /// [`serve_reflection`](Self::serve_reflection) with an access record
    /// around it.
    ///
    /// Reflection is dispatched outside the registered method table, so it
    /// would otherwise produce no record at all -- and "no record" is how a
    /// port ends up unable to tell whether its labelling is right, because the
    /// one call that can prove it never reaches the log. The record's
    /// `protocol` and `protocol_hash` come from
    /// [`protocol_identity`](crate::server::RpcServer::protocol_identity) like
    /// every other site's, so reflection is labelled as itself rather than as
    /// the application.
    pub(crate) fn serve_reflection_logged<W: std::io::Write>(
        &self,
        w: &mut W,
        req: &crate::server::Request,
        ctx: &crate::server::CallContext,
    ) -> Result<bool> {
        let Some(hook) = self.dispatch_hook.as_ref() else {
            return self.serve_reflection(w, req);
        };
        let mut info = crate::hooks::DispatchInfo::from_request(self, req, "unary", &ctx.auth);
        if let Ok(bytes) = crate::server::serialize_request_batch(&req.batch) {
            info.request_data = bytes;
        }
        let token = hook.on_dispatch_start(&info);
        let outcome = self.serve_reflection(w, req);
        let stats = crate::hooks::CallStatistics {
            input_batches: 1,
            input_rows: req.batch.num_rows() as u64,
            output_batches: 1,
            output_rows: 1,
            ..Default::default()
        };
        let err = outcome.as_ref().err().cloned();
        hook.on_dispatch_end(token, &info, err.as_ref(), &stats);
        outcome
    }

    pub(crate) fn serve_reflection<W: std::io::Write>(
        &self,
        w: &mut W,
        req: &crate::server::Request,
    ) -> Result<bool> {
        let app_hash = binding_hash(&self.protocol_name, &self.methods)?;
        // Reflection describes itself out of the same table it answers from,
        // so its hash covers the two methods it really has. Self-description is
        // not special-cased: the protocol appears in its own output, methods
        // and all, or a client cannot learn to call what it is already calling.
        let refl_methods = reflection_methods();
        let refl_hash = binding_hash(REFLECTION_PROTOCOL_NAME, refl_methods)?;
        // Identity is registered *after* reflection, so it appears in
        // reflection's output -- which is the whole point of hosting it as an
        // ordinary protocol: a client learns which of its methods this
        // deployment can answer by looking, rather than by calling and reading
        // an error.
        let identity = self.identity_binding();

        let batch = match req.method.as_str() {
            LIST_PROTOCOLS_METHOD => {
                let mut protocols = vec![
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
                ];
                if let Some(binding) = identity {
                    protocols.push((
                        crate::token_identity::IDENTITY_PROTOCOL_NAME.to_string(),
                        String::new(),
                        binding.protocol_hash.clone(),
                    ));
                }
                build_protocol_list(
                    &self.server_id,
                    "",
                    crate::metadata::REQUEST_VERSION,
                    &protocols,
                )?
            }
            DESCRIBE_METHOD => {
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
                        refl_methods,
                    )?
                } else if let Some(binding) =
                    identity.filter(|_| requested == crate::token_identity::IDENTITY_PROTOCOL_NAME)
                {
                    // Only the methods whose hooks the deployment supplied: a
                    // description that listed `issue_grant` on a worker that
                    // cannot mint would be a promise the worker does not keep.
                    build_service_description(
                        crate::token_identity::IDENTITY_PROTOCOL_NAME,
                        "",
                        &binding.protocol_hash,
                        &binding.methods,
                    )?
                } else {
                    // Named, not silently empty: an empty description reads as
                    // "this protocol has no methods".
                    let hosted = self.hosted_protocol_names();
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
                         Available: {:?}",
                        sorted_reflection_method_names()
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
        write_unary_response(w, &out, &md)?;
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

/// Serialize a `Schema` as an IPC stream (schema-only, empty body) — matches
/// pyarrow's `Schema.serialize()`, which is how every port carries a schema
/// inside a description.
pub(crate) fn schema_to_ipc(schema: &Schema) -> Result<Vec<u8>> {
    // An IPC stream with just the schema message followed by the EOS marker.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = arrow_ipc::writer::StreamWriter::try_new(&mut buf, schema)
            .map_err(|e| RpcError::protocol_error(format!("opening IPC writer: {e}")))?;
        w.finish()
            .map_err(|e| RpcError::protocol_error(format!("finishing IPC stream: {e}")))?;
    }
    Ok(buf)
}

/// Write one batch as a complete unary response stream.
///
/// Outlived `__describe__`, which is what it was written for: reflection and
/// `vgi_rpc.Identity.v1` are ordinary unary methods served outside the
/// registered method table, and both frame their replies this way.
pub fn write_unary_response<W: std::io::Write>(
    w: &mut W,
    batch: &RecordBatch,
    metadata: &crate::wire::Metadata,
) -> Result<()> {
    let mut sw = crate::wire::StreamWriter::new(w, batch.schema().as_ref())?;
    sw.write(batch, Some(metadata))?;
    sw.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cross-port contract. A mismatch means this port and the reference
    /// would disagree about whether they speak the same reflection.
    ///
    /// A failure is a JSON diff, not a guess: print
    /// [`crate::protocol_hash::canonical_description`] and compare it against
    /// the preimage pinned in `canonical_preimage_matches_the_reference`.
    #[test]
    fn matches_the_reference_hash() {
        assert_eq!(
            binding_hash(REFLECTION_PROTOCOL_NAME, reflection_methods()).unwrap(),
            "3c7db4cae8cdfc93dc4a76e73b8b759e18e45e6a5811adba4e520366344b919a",
        );
    }

    /// Pinned so a digest mismatch is diffable rather than a mystery.
    #[test]
    fn canonical_preimage_matches_the_reference() {
        let entries = hash_methods(reflection_methods());
        let preimage =
            crate::protocol_hash::canonical_description(REFLECTION_PROTOCOL_NAME, &entries)
                .unwrap();
        assert_eq!(
            preimage,
            r#"{"methods":[{"has_header":false,"has_return":true,"name":"describe","params":[{"name":"protocol","nullable":false,"type":"utf8"}],"result":[{"name":"result","nullable":false,"type":"binary"}],"type":"unary"},{"has_header":false,"has_return":true,"name":"list_protocols","params":[],"result":[{"name":"result","nullable":false,"type":"binary"}],"type":"unary"}],"protocol":"vgi_rpc.Reflection.v1"}"#
        );
    }

    /// The digest is a consequence of the shape, so the shape is pinned too: a
    /// digest alone would let a future edit satisfy the vector by accident
    /// while describing something else.
    #[test]
    fn hosts_exactly_its_two_methods() {
        assert_eq!(
            sorted_reflection_method_names(),
            vec![DESCRIBE_METHOD, LIST_PROTOCOLS_METHOD]
        );
        for info in reflection_methods().values() {
            assert!(
                matches!(info.method_type, MethodType::Unary),
                "{}",
                info.name
            );
            assert!(unary_has_return(info), "{}", info.name);
            assert!(info.header_schema.is_none(), "{}", info.name);
            assert_eq!(
                info.result_schema.as_ref(),
                reflection_result_schema().as_ref(),
                "{}",
                info.name
            );
        }
        let describe = &reflection_methods()[DESCRIBE_METHOD];
        assert_eq!(
            describe.params_schema.as_ref(),
            describe_params_schema().as_ref()
        );
        // The one argument, non-null: a nullable `protocol` would hash
        // differently and describe a method that can be asked about nothing.
        let field = describe.params_schema.field_with_name("protocol").unwrap();
        assert_eq!(field.data_type(), &DataType::Utf8);
        assert!(!field.is_nullable());
        assert!(reflection_methods()[LIST_PROTOCOLS_METHOD]
            .params_schema
            .fields()
            .is_empty());
    }

    /// The table is a description, not a dispatch path: reflection is served
    /// from `serve_reflection`, which matches names itself. If one of these
    /// handlers is ever reached it means the table was registered as a
    /// server's methods, and an error says so where a panic would not.
    #[test]
    fn the_registrations_are_descriptions_only() {
        for info in reflection_methods().values() {
            assert!(info.stream.is_none(), "{}", info.name);
            assert!(info.unary.is_some(), "a handler, so a misuse cannot panic");
        }
    }
}
