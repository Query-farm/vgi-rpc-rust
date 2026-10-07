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
//!
//! [`list_protocols`] and [`describe_protocol`] are the connection-reusing
//! entry points: they take a client the caller already holds -- an
//! [`RpcClient`](crate::RpcClient) on any byte-stream transport (subprocess,
//! pipe, shm, unix, TCP, TLS, Iroh) or an `HttpClient` (HTTP, HTTP over Iroh),
//! bound to any protocol -- and ask reflection over that same connection.
//! Nothing is opened and nothing is closed.

use std::collections::HashMap;
use std::fmt;
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

/// One protocol a server hosts, as `vgi_rpc.Reflection.v1` lists it.
///
/// A client-side view of the wire `ProtocolSummary`, returned by
/// [`list_protocols`] in the server's order: application protocols in
/// registration order (the primary first), then the framework's own
/// (`vgi_rpc.Reflection.v1`, and `vgi_rpc.Identity.v1` on an HTTP server that
/// hosts it).
///
/// A value, not a handle: it owns its fields and nothing reads them back
/// from the server, so a copy kept across calls stays exactly what was listed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct HostedProtocol {
    /// The protocol's wire name -- its routing key, carrying its major
    /// version, e.g. `"vgi_rpc.Reflection.v1"`.
    pub name: String,
    /// Its declared semver, or `""` when it declares none.
    pub version: String,
    /// SHA-256 of its canonical description, as 64 lowercase hex characters.
    /// Equal hashes mean an identical wire surface, in any port, so a caller
    /// holding a cached description for this hash can skip
    /// [`describe_protocol`].
    pub hash: String,
    /// Whether callers should migrate off this protocol. Default `false`.
    pub deprecated: bool,
    /// What to migrate to; empty unless [`Self::deprecated`].
    pub deprecation_message: String,
    /// Capability tokens the protocol announces, which announce here rather
    /// than consuming version numbers. Default empty.
    pub features: Vec<String>,
}

/// What a server hosts, as `list_protocols` returns it: the protocols plus the
/// server identity a [`ServiceDescription`] borrows.
#[derive(Debug, Clone)]
pub(crate) struct ProtocolList {
    pub(crate) server_id: String,
    pub(crate) request_version: String,
    pub(crate) protocols: Vec<HostedProtocol>,
}

impl ProtocolList {
    /// The first hosted protocol that is not framework-owned -- the server's
    /// application surface, and the one [`describe`] asks about by default.
    ///
    /// [`describe`]: crate::RpcClient::describe
    pub(crate) fn primary(&self) -> Option<&HostedProtocol> {
        self.protocols.iter().find(|p| {
            !p.name
                .starts_with(vgi_rpc::binding::RESERVED_PROTOCOL_PREFIX)
        })
    }
}

/// One protocol's full description.
#[derive(Debug, Clone)]
pub struct ServiceDescription {
    pub protocol_name: String,
    /// From the `list_protocols` hop: a property of the server, not of the
    /// protocol. A description deliberately carries no server identity --
    /// two processes serving the same protocol must describe it identically.
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
pub(crate) fn reflection_payload(batch: &RecordBatch) -> Result<RecordBatch> {
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
pub(crate) fn parse_protocol_list(batch: &RecordBatch) -> Result<ProtocolList> {
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
        protocols.push(HostedProtocol {
            name: struct_string(&values, "protocol", i)?,
            version: struct_string(&values, "protocol_version", i)?,
            hash: struct_string(&values, "protocol_hash", i)?,
            deprecated: struct_bool(&values, "deprecated", i)?,
            deprecation_message: struct_string(&values, "deprecation_message", i)?,
            features,
        });
    }
    Ok(ProtocolList {
        server_id: row0_string(batch, "server_id")?,
        request_version: row0_string(batch, "request_version")?,
        protocols,
    })
}

/// Parse a `describe` payload batch into this module's client-side shape.
///
/// `listing` supplies the two server-identity fields the description itself
/// does not carry; pass `None` when the `list_protocols` hop was skipped.
pub(crate) fn parse_service_description(
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

/// A one-row `describe` request batch naming `protocol`.
pub(crate) fn describe_params(protocol: &str) -> Result<RecordBatch> {
    let schema = vgi_rpc::reflection::describe_params_schema();
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
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
    ))
}

// ---------------------------------------------------------------------------
// Public reflection client: list_protocols / describe_protocol
// ---------------------------------------------------------------------------

/// The server does not host `vgi_rpc.Reflection.v1`.
///
/// Returned (inside [`ReflectionError::NotSupported`]) by [`list_protocols`]
/// and [`describe_protocol`] when the server answers the reflection call with
/// "not hosted" rather than with a listing: a server that opts out of
/// reflection (the Python reference's `enable_describe` defaults to off), or
/// one that predates it. Such a server still serves its own protocol, so this
/// is a statement about discovery, not about the connection -- the connection
/// remains usable.
///
/// Carries the server's original error unchanged; it derefs to that
/// [`RpcError`], so `err.error_kind`, `err.error_code()` and the rest read the
/// server's fields.
#[derive(Debug, Clone)]
pub struct ReflectionNotSupportedError {
    error: RpcError,
}

impl ReflectionNotSupportedError {
    /// The server's answer, every field as it sent it.
    pub fn rpc_error(&self) -> &RpcError {
        &self.error
    }

    /// Unwrap into the server's answer.
    pub fn into_rpc_error(self) -> RpcError {
        self.error
    }
}

impl std::ops::Deref for ReflectionNotSupportedError {
    type Target = RpcError;

    fn deref(&self) -> &RpcError {
        &self.error
    }
}

impl fmt::Display for ReflectionNotSupportedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "server does not host {}: {}",
            vgi_rpc::reflection::REFLECTION_PROTOCOL_NAME,
            self.error
        )
    }
}

impl std::error::Error for ReflectionNotSupportedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Why [`list_protocols`] or [`describe_protocol`] failed.
///
/// Two cases a caller treats differently: the server cannot be asked at all
/// ([`Self::NotSupported`]), or it was asked and answered with an error --
/// including `error_kind = "protocol_not_supported"` from `describe` for a
/// name it does not host -- or the transport failed ([`Self::Rpc`]).
/// Converts into [`RpcError`] so `?` works in code that returns one.
#[derive(Debug, Clone)]
pub enum ReflectionError {
    /// The server does not host reflection. The connection is still usable.
    NotSupported(ReflectionNotSupportedError),
    /// Any other failure, as the server or transport reported it.
    Rpc(RpcError),
}

impl ReflectionError {
    /// The underlying error in either case.
    pub fn rpc_error(&self) -> &RpcError {
        match self {
            Self::NotSupported(e) => e.rpc_error(),
            Self::Rpc(e) => e,
        }
    }

    /// Whether this is "the server does not host reflection".
    pub fn is_not_supported(&self) -> bool {
        matches!(self, Self::NotSupported(_))
    }
}

impl fmt::Display for ReflectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported(e) => e.fmt(f),
            Self::Rpc(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ReflectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotSupported(e) => Some(e),
            Self::Rpc(e) => Some(e),
        }
    }
}

impl From<RpcError> for ReflectionError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

impl From<ReflectionError> for RpcError {
    fn from(error: ReflectionError) -> Self {
        match error {
            ReflectionError::NotSupported(e) => e.into_rpc_error(),
            ReflectionError::Rpc(e) => e,
        }
    }
}

/// `error_kind` values meaning "this server does not answer reflection".
const NOT_HOSTED_KINDS: [&str; 2] = [
    vgi_rpc::errors::ERROR_KIND_PROTOCOL_NOT_SUPPORTED,
    vgi_rpc::errors::ERROR_KIND_METHOD_NOT_IMPLEMENTED,
];

/// Remote exception names for the same, from servers that send no kind.
const NOT_HOSTED_TYPES: [&str; 2] = ["ProtocolNotSupportedError", "MethodNotImplementedError"];

/// Whether `error` says the server does not host reflection at all.
///
/// Only meaningful for `list_protocols`, which is always hosted when
/// reflection is: a "not supported" answer to it can only be about the
/// protocol. (`describe` answers `protocol_not_supported` for an unknown
/// *argument*, which is why [`describe_protocol`] lists first.)
///
/// A current server without reflection answers `protocol_not_supported`; one
/// older than multi-protocol hosting ignores the protocol key and answers an
/// unknown method; both carry `UNIMPLEMENTED` when the server sends a code at
/// all. An HTTP server older than protocol-scoped routes answers a bare 404,
/// which the HTTP client reports as a non-Arrow `HttpError`.
pub(crate) fn reflection_not_hosted(error: &RpcError) -> bool {
    if error
        .error_kind
        .as_deref()
        .is_some_and(|k| NOT_HOSTED_KINDS.contains(&k))
        || error.error_code() == "UNIMPLEMENTED"
    {
        return true;
    }
    if NOT_HOSTED_TYPES.contains(&error.error_type.as_str()) {
        return true;
    }
    error.error_type == "HttpError" && error.message.starts_with("HTTP 404")
}

mod sealed {
    use arrow_array::RecordBatch;
    use vgi_rpc::errors::Result;

    /// The non-public hook a reflection target implements: one unary call to
    /// `vgi_rpc.Reflection.v1` over the target's own connection, returning
    /// the unwrapped payload batch.
    pub trait ReflectionCall {
        fn reflection_call(&mut self, method: &str, params: &RecordBatch) -> Result<RecordBatch>;
    }
}

pub(crate) use sealed::ReflectionCall;

/// A held connection that [`list_protocols`] and [`describe_protocol`] can ask
/// over: every client this crate hands out.
///
/// Implemented for [`RpcClient`](crate::RpcClient) -- subprocess, pipe, shm,
/// unix, TCP, TLS-TCP, and raw Iroh (`vgi-rpc-iroh` hands out an
/// `RpcClient`) -- and for `HttpClient`, plain or over Iroh. The client's own
/// bound protocol does not matter: the reflection request names
/// `vgi_rpc.Reflection.v1` in its routing key. Sealed; the hook it needs is
/// not public.
pub trait ReflectionTarget: sealed::ReflectionCall {}

impl<T: sealed::ReflectionCall + ?Sized> ReflectionTarget for T {}

fn list_raw<T: ReflectionTarget + ?Sized>(
    target: &mut T,
) -> std::result::Result<ProtocolList, ReflectionError> {
    let params = vgi_rpc::wire::empty_batch(empty_schema().as_ref())?;
    match target.reflection_call(vgi_rpc::reflection::LIST_PROTOCOLS_METHOD, &params) {
        Ok(payload) => Ok(parse_protocol_list(&payload)?),
        Err(e) if reflection_not_hosted(&e) => {
            Err(ReflectionError::NotSupported(ReflectionNotSupportedError {
                error: e,
            }))
        }
        Err(e) => Err(ReflectionError::Rpc(e)),
    }
}

/// List the protocols a server hosts, over a connection the caller holds.
///
/// One round trip -- `vgi_rpc.Reflection.v1.list_protocols` -- on `target`'s
/// own connection; nothing new is opened and nothing is closed. Over HTTP the
/// call goes through the client's own backend (or executor), prefix, headers,
/// retry and response budget; over every other transport it shares the
/// client's byte stream, which the server demultiplexes by each request's
/// protocol key. `&mut` borrowing already rules out calling it while a stream
/// is open on the same client.
///
/// Returns one [`HostedProtocol`] per hosted protocol, in the server's order:
/// application protocols first, primary leading, then the framework's own.
///
/// # Errors
///
/// [`ReflectionError::NotSupported`] when the server does not host reflection
/// (built without it, or older than it); the connection is still usable.
/// [`ReflectionError::Rpc`] for any other error or a transport failure. A
/// listing is never inferred.
///
/// A Rust [`vgi_rpc`] server always hosts reflection; the Python reference
/// hosts it only when built with `enable_describe=True`.
pub fn list_protocols<T: ReflectionTarget + ?Sized>(
    target: &mut T,
) -> std::result::Result<Vec<HostedProtocol>, ReflectionError> {
    Ok(list_raw(target)?.protocols)
}

/// Describe one hosted protocol, over a connection the caller holds.
///
/// Two round trips on `target`'s connection: `list_protocols` (for the server
/// identity the description carries, and to tell "no reflection" apart from
/// "no such protocol"), then `describe(name)`. The connection rules are those
/// of [`list_protocols`].
///
/// # Errors
///
/// [`ReflectionError::NotSupported`] when the server does not host
/// reflection. [`ReflectionError::Rpc`] when the server does not host `name`
/// (`error_kind` `"protocol_not_supported"`), answered with another error, or
/// the transport failed.
pub fn describe_protocol<T: ReflectionTarget + ?Sized>(
    target: &mut T,
    name: &str,
) -> std::result::Result<ServiceDescription, ReflectionError> {
    let listing = list_raw(target)?;
    let params = describe_params(name)?;
    let payload = target.reflection_call(vgi_rpc::reflection::DESCRIBE_METHOD, &params)?;
    Ok(parse_service_description(&payload, Some(&listing))?)
}

/// Describe the server's application protocol (the primary): `list_protocols`,
/// then `describe` on the first non-framework protocol listed.
pub(crate) fn describe_primary<T: ReflectionTarget + ?Sized>(
    target: &mut T,
) -> Result<ServiceDescription> {
    let listing = list_raw(target)?;
    let protocol = listing
        .primary()
        .ok_or_else(|| no_application_protocol(&listing))?
        .name
        .clone();
    let params = describe_params(&protocol)?;
    let payload = target.reflection_call(vgi_rpc::reflection::DESCRIBE_METHOD, &params)?;
    parse_service_description(&payload, Some(&listing))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(error_type: &str, message: &str) -> RpcError {
        RpcError::new(error_type, message)
    }

    #[test]
    fn older_servers_are_classified_as_not_hosted() {
        let cases = [
            err("MethodNotImplementedError", "no list_protocols"),
            err("AttributeError", "x").with_error_kind("method_not_implemented"),
            err("ProtocolNotSupportedError", "x"),
            err("Whatever", "x").with_error_kind("protocol_not_supported"),
            err("Whatever", "x").with_code(vgi_rpc::errors::Code::Unimplemented),
            err(
                "HttpError",
                "HTTP 404: response is not a valid Arrow IPC stream",
            ),
        ];
        for case in &cases {
            assert!(reflection_not_hosted(case), "{case:?}");
        }
    }

    #[test]
    fn other_errors_are_not_classified() {
        let cases = [
            err("ValueError", "boom"),
            err(
                "HttpError",
                "HTTP 500: response is not a valid Arrow IPC stream",
            ),
            err("TransportError", "pipe closed").with_code(vgi_rpc::errors::Code::Unavailable),
        ];
        for case in &cases {
            assert!(!reflection_not_hosted(case), "{case:?}");
        }
    }

    #[test]
    fn not_supported_keeps_the_server_fields() {
        let server = err("ProtocolNotSupportedError", "not here")
            .with_error_kind("protocol_not_supported")
            .with_code(vgi_rpc::errors::Code::Unimplemented);
        let wrapped = ReflectionNotSupportedError {
            error: server.clone(),
        };
        assert_eq!(wrapped.error_type, "ProtocolNotSupportedError");
        assert_eq!(
            wrapped.error_kind.as_deref(),
            Some("protocol_not_supported")
        );
        assert_eq!(wrapped.error_code(), "UNIMPLEMENTED");
        let back: RpcError = ReflectionError::NotSupported(wrapped).into();
        assert_eq!(back.message, server.message);
    }

    #[test]
    fn hosted_protocol_defaults() {
        let p = HostedProtocol {
            name: "a.v1".into(),
            version: String::new(),
            hash: "0".repeat(64),
            ..Default::default()
        };
        assert!(!p.deprecated);
        assert!(p.deprecation_message.is_empty());
        assert!(p.features.is_empty());
    }
}
