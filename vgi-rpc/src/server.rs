//! RPC server dispatch — reads requests, invokes handlers, writes responses.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use arrow_array::RecordBatch;
use arrow_cast::cast_with_options;
use arrow_schema::{Schema, SchemaRef};

use crate::errors::{Result, RpcError};
use crate::log::{LogLevel, LogMessage};
#[cfg(feature = "shm")]
use crate::metadata::SHM_SEGMENT_SIZE_KEY;
use crate::metadata::{
    CANCEL_KEY, LOG_EXTRA_KEY, LOG_LEVEL_KEY, LOG_MESSAGE_KEY, REQUEST_ID_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY, SERVER_ID_KEY, SHM_OFFSET_KEY, SHM_SEGMENT_NAME_KEY,
};
#[cfg(feature = "shm")]
use crate::shm::{is_shm_pointer_batch, maybe_write_to_shm, resolve_shm_batch, ShmSegment};

/// Feature-off stand-in so dispatch signatures stay uniform.
#[cfg(not(feature = "shm"))]
pub(crate) struct ShmSegment;

/// Attach to a client-advertised SHM segment named in request metadata.
/// `track = false` since the client owns the lifecycle.
#[cfg(feature = "shm")]
fn maybe_attach_shm(req_md: &Metadata) -> Option<ShmSegment> {
    let name = req_md.get(SHM_SEGMENT_NAME_KEY)?;
    let size: usize = req_md.get(SHM_SEGMENT_SIZE_KEY)?.parse().ok()?;
    match ShmSegment::attach(name, size, false) {
        Ok(seg) => Some(seg),
        Err(e) => {
            tracing::warn!(target: "vgi_rpc.shm", "ignoring malformed SHM metadata ({e})");
            None
        }
    }
}

#[cfg(not(feature = "shm"))]
#[inline]
fn maybe_attach_shm(_req_md: &Metadata) -> Option<ShmSegment> {
    None
}

/// Per-connection cache of a client-advertised SHM segment.
///
/// A client names its segment once — in an early request's metadata — then
/// routes later batches (request *and* data) through it carrying only an
/// offset/length, no name (the C++ extension does this; the Python client
/// happens to re-advertise the name on every request, so it never needed
/// the cache). The worker attaches on first sight and reuses the
/// attachment for the connection's lifetime; [`RpcServer::serve`] owns the
/// cache, and dropping it detaches without unlinking (the client owns the
/// OS object). Without this, a later offset-only pointer request can't be
/// resolved and trips the "Expected 1 row in request batch" guard.
///
/// Mirrors Python `vgi_rpc.rpc._server._ConnectionShm`.
#[derive(Default)]
pub(crate) struct ConnectionShm {
    #[cfg(feature = "shm")]
    name: Option<String>,
    #[cfg(feature = "shm")]
    segment: Option<ShmSegment>,
}

#[cfg(feature = "shm")]
impl ConnectionShm {
    /// Attach and cache the segment named in `req_md` when it first
    /// appears or changes.
    fn refresh(&mut self, req_md: &Metadata) {
        let Some(name) = req_md.get(SHM_SEGMENT_NAME_KEY) else {
            return;
        };
        if self.name.as_deref() == Some(name.as_str()) {
            return;
        }
        let Some(new) = maybe_attach_shm(req_md) else {
            return;
        };
        self.segment = Some(new);
        self.name = Some(name.clone());
    }

    fn segment(&self) -> Option<&ShmSegment> {
        self.segment.as_ref()
    }
}

#[cfg(not(feature = "shm"))]
impl ConnectionShm {
    #[inline]
    fn refresh(&mut self, _req_md: &Metadata) {}

    #[inline]
    fn segment(&self) -> Option<&ShmSegment> {
        None
    }
}
use crate::stream::{empty_schema, Emitted, OutputCollector, StreamResult, StreamStateKind};
use crate::wire::{empty_batch, md_get, Metadata, StreamReader, StreamWriter};

/// Serialize a parsed request batch back to a self-contained Arrow IPC
/// stream (one schema message + one record batch + EOS) for inclusion in
/// access-log `request_data`.
fn serialize_request_batch(batch: &RecordBatch) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut w = arrow_ipc::writer::StreamWriter::try_new(&mut buf, batch.schema_ref())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        w.write(batch)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        w.finish()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }
    Ok(buf)
}

/// Lock a mutex, recovering the guard even if a previous holder
/// panicked. Handler code is arbitrary and *will* panic eventually; a
/// poisoned lock must not turn that into a process abort on the next
/// `.lock()`. The panic itself is surfaced to the client as an
/// `RpcError` by the `catch_unwind` wrappers in the dispatch path.
fn lock_ok<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Invoke a handler closure, converting a panic into an `RpcError`
/// instead of unwinding through the serve loop (which on stdio/pipe
/// would kill the whole process). The panic message is intentionally
/// not echoed to the client.
pub(crate) fn call_guard<T>(f: impl FnOnce() -> T) -> Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .map_err(|_| RpcError::new("RuntimeError", "handler panicked"))
}

/// Context supplied to each handler invocation.
#[derive(Clone)]
pub struct CallContext {
    pub server_id: String,
    pub method: String,
    pub request_id: String,
    pub transport_metadata: Arc<Metadata>,
    /// Authentication state, or [`crate::AuthContext::anonymous`] when
    /// no authenticator is configured (e.g. pipe/unix transports).
    pub auth: crate::auth::AuthContext,
    /// HTTP request cookies (empty for pipe/unix). Name → value.
    pub cookies: std::collections::BTreeMap<String, String>,
    /// Coarse identifier of the bound transport. `None` until the
    /// framework has observed the transport (i.e. before the first
    /// [`RpcServer::notify_transport`] call).
    pub kind: Option<crate::transport::TransportKind>,
    pub(crate) log_sink: Arc<Mutex<Vec<LogMessage>>>,
    /// Per-tick input-batch custom metadata (updated each producer/exchange
    /// iteration). Carries e.g. `vgi_pushdown_filters` for dynamic filters.
    pub(crate) tick_metadata: Arc<Mutex<Metadata>>,
    /// Sticky-session bridge, installed by the HTTP transport when the
    /// server is sticky-enabled. `None` on pipe/unix/subprocess and on
    /// HTTP servers without sticky support — [`CallContext::open_session`]
    /// then raises a clear "not available on this transport" error.
    pub(crate) sticky: Option<Arc<dyn StickySink>>,
}

/// Bridge between [`CallContext`]'s sticky-session API and the HTTP
/// transport's per-worker session registry. Implemented by the HTTP layer
/// (see `crate::sticky`); the trait lives here so [`CallContext`] carries
/// no compile-time dependency on the `http` feature.
pub trait StickySink: Send + Sync {
    /// Whether the client opted in via `VGI-Session-Accept: true`.
    fn accept_opens(&self) -> bool;
    /// The live session state bound to this request, if any.
    fn current_state(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>>;
    /// The opaque hex session id bound to this request, if any.
    fn current_session_id(&self) -> Option<String>;
    /// Register a session holding `state`; mints + stashes the response token.
    fn open(
        &self,
        state: Arc<dyn std::any::Any + Send + Sync>,
        ttl: Option<std::time::Duration>,
    ) -> Result<()>;
    /// Close the session bound to this request. Returns whether one was live.
    fn close(&self) -> Result<bool>;
}

impl CallContext {
    pub fn client_log(&self, level: LogLevel, message: impl Into<String>) {
        lock_ok(&self.log_sink).push(LogMessage::new(level, message));
    }

    pub fn client_log_with(&self, msg: LogMessage) {
        lock_ok(&self.log_sink).push(msg);
    }

    pub(crate) fn drain_logs(&self) -> Vec<LogMessage> {
        std::mem::take(&mut *lock_ok(&self.log_sink))
    }

    /// Per-tick input-batch custom metadata value (e.g. `vgi_pushdown_filters`),
    /// set by the producer/exchange loop for the current iteration.
    pub fn tick_metadata(&self, key: &str) -> Option<String> {
        lock_ok(&self.tick_metadata).get(key).cloned()
    }

    /// Replace the per-tick input-batch metadata for the current iteration.
    /// Used by the HTTP transport, where a producer's first turn folds into
    /// the `/init` request (see `run_producer`). HTTP-only, so gated to
    /// avoid a dead-code `-D warnings` failure in non-`http` builds.
    #[cfg(feature = "http")]
    pub(crate) fn set_tick_metadata(&self, md: Metadata) {
        *lock_ok(&self.tick_metadata) = md;
    }

    /// Build a call context for `server` serving `req`. Defaults to
    /// anonymous auth with no cookies — callers on authenticated
    /// transports (HTTP) override the two after construction or use
    /// [`CallContext::with_auth_cookies`].
    pub(crate) fn for_request(server: &RpcServer, req: &Request) -> Self {
        Self {
            server_id: server.server_id.clone(),
            method: req.method.clone(),
            request_id: req.request_id.clone(),
            transport_metadata: req.metadata.clone(),
            auth: crate::auth::AuthContext::anonymous(),
            cookies: std::collections::BTreeMap::new(),
            kind: server.transport_kind(),
            log_sink: Arc::new(Mutex::new(Vec::new())),
            tick_metadata: Arc::new(Mutex::new(Metadata::default())),
            sticky: None,
        }
    }

    /// Build a call context with an explicit auth context + cookie map.
    /// Only the HTTP transport constructs contexts this way; gated so the
    /// method isn't dead code (a `-D warnings` build failure) when `vgi-rpc`
    /// is compiled without the `http` feature (e.g. from `vgi-rpc-client`).
    #[cfg(feature = "http")]
    pub(crate) fn with_auth_cookies(
        server: &RpcServer,
        req: &Request,
        auth: crate::auth::AuthContext,
        cookies: std::collections::BTreeMap<String, String>,
    ) -> Self {
        Self {
            server_id: server.server_id.clone(),
            method: req.method.clone(),
            request_id: req.request_id.clone(),
            transport_metadata: req.metadata.clone(),
            auth,
            cookies,
            kind: server.transport_kind(),
            log_sink: Arc::new(Mutex::new(Vec::new())),
            tick_metadata: Arc::new(Mutex::new(Metadata::default())),
            sticky: None,
        }
    }

    /// Attach a sticky-session sink (HTTP transport only). No-op semantics
    /// for callers: the session API simply reports "not available" when
    /// this is never set. HTTP-only, so gated to avoid a dead-code
    /// `-D warnings` failure in non-`http` builds.
    #[cfg(feature = "http")]
    pub(crate) fn set_sticky(&mut self, sink: Arc<dyn StickySink>) {
        self.sticky = Some(sink);
    }

    // --- Sticky sessions (HTTP-only) -----------------------------------

    /// The live session state object, downcast to `T`, or `None` when no
    /// session is bound to this request (or it is not a `T`).
    ///
    /// Sticky sessions are HTTP-only; on other transports this is always
    /// `None`. Mirrors Python's `ctx.session`.
    pub fn session<T: std::any::Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let state = self.sticky.as_ref()?.current_state()?;
        state.downcast::<T>().ok()
    }

    /// The opaque hex session id bound to this request, or `None`.
    /// Survives [`CallContext::close_session`] within the same request.
    pub fn session_id(&self) -> Option<String> {
        self.sticky.as_ref()?.current_session_id()
    }

    /// Register a sticky session holding `state` for subsequent requests.
    ///
    /// The framework mints a signed `VGI-Session` token and attaches it to
    /// the response; a client inside a `with_session_token()` block echoes
    /// it on subsequent requests, and the framework restores `state` as
    /// [`CallContext::session`]. `ttl` overrides the server default.
    ///
    /// Mirrors Python's `ctx.open_session`. Errors when sticky is
    /// unavailable on this transport, the client did not opt in, or a
    /// session is already bound to this request.
    pub fn open_session(
        &self,
        state: Arc<dyn std::any::Any + Send + Sync>,
        ttl: Option<std::time::Duration>,
    ) -> Result<()> {
        let sink = self.sticky.as_ref().ok_or_else(|| {
            RpcError::runtime_error("sticky sessions not available on this transport")
        })?;
        if !sink.accept_opens() {
            return Err(RpcError::runtime_error(
                "client did not opt in to sticky sessions \
                 (missing VGI-Session-Accept: true header — open the call inside \
                 an HttpConnection.with_session_token() block)",
            ));
        }
        if sink.current_state().is_some() {
            return Err(RpcError::runtime_error(
                "a sticky session is already active for this request",
            ));
        }
        sink.open(state, ttl)
    }

    /// Invalidate the sticky session bound to this request. Idempotent;
    /// mirrors Python's `ctx.close_session`.
    pub fn close_session(&self) -> Result<()> {
        let sink = self.sticky.as_ref().ok_or_else(|| {
            RpcError::runtime_error("sticky sessions not available on this transport")
        })?;
        sink.close()?;
        Ok(())
    }
}

/// A request batch parsed from the wire.
pub struct Request {
    pub method: String,
    pub request_id: String,
    pub batch: RecordBatch,
    /// Request-level custom metadata. Held behind an `Arc` so the dispatch
    /// path can hand a shared, cheap-to-clone reference to the `CallContext`
    /// and (when enabled) the `DispatchInfo` without deep-copying the map.
    pub metadata: Arc<Metadata>,
}

impl Request {
    pub fn column(&self, name: &str) -> Option<&dyn arrow_array::Array> {
        let idx = self.batch.schema().index_of(name).ok()?;
        Some(self.batch.column(idx).as_ref())
    }

    /// Build a `Request` from a record batch carrying its own
    /// `custom_metadata`, validating the `vgi_rpc.method` /
    /// `vgi_rpc.request_version` metadata.
    ///
    /// `require_method` controls whether a missing `vgi_rpc.method` key is
    /// an error (pipe/unix transports require it; HTTP already derives the
    /// method from the URL path and may leave the key absent).
    pub(crate) fn from_read_batch(
        batch: RecordBatch,
        metadata: Metadata,
        require_method: bool,
    ) -> Result<Self> {
        let method = if require_method {
            md_get(&metadata, RPC_METHOD_KEY)
                .ok_or_else(|| {
                    RpcError::protocol_error(
                        "Missing 'vgi_rpc.method' in request batch custom_metadata.",
                    )
                })?
                .to_string()
        } else {
            md_get(&metadata, RPC_METHOD_KEY).unwrap_or("").to_string()
        };
        let version = md_get(&metadata, REQUEST_VERSION_KEY).ok_or_else(|| {
            RpcError::version_error(format!(
                "Missing 'vgi_rpc.request_version' in request batch custom_metadata. Set it to {:?}.",
                REQUEST_VERSION
            ))
        })?;
        if version != REQUEST_VERSION {
            return Err(RpcError::version_error(format!(
                "Unsupported request version {:?}, expected {:?}.",
                version, REQUEST_VERSION
            )));
        }
        if require_method && !batch.schema().fields().is_empty() && batch.num_rows() != 1 {
            return Err(RpcError::protocol_error(format!(
                "Expected 1 row in request batch, got {}",
                batch.num_rows()
            )));
        }
        let request_id = md_get(&metadata, REQUEST_ID_KEY).unwrap_or("").to_string();
        Ok(Request {
            method,
            request_id,
            batch,
            metadata: Arc::new(metadata),
        })
    }
}

/// Identifies the dispatch kind of a registered method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodType {
    Unary,
    Producer,
    Exchange,
    /// State kind determined at runtime by handler return value.
    Dynamic,
}

/// A handler function for a unary RPC method.
pub type UnaryHandler =
    Arc<dyn Fn(&Request, &CallContext) -> Result<Option<RecordBatch>> + Send + Sync>;

/// A handler function for a streaming RPC method.
pub type StreamHandler = Arc<dyn Fn(&Request, &CallContext) -> Result<StreamResult> + Send + Sync>;

/// Fluent builder for [`RpcServer`] with describe/identity/version knobs.
#[derive(Default)]
pub struct RpcServerBuilder {
    server_id: Option<String>,
    server_version: Option<String>,
    protocol_name: Option<String>,
    protocol_version: Option<String>,
    enable_describe: bool,
    dispatch_hook: Option<Arc<dyn crate::hooks::DispatchHook>>,
    on_serve_start: Option<crate::transport::ServeStartHook>,
    #[cfg(feature = "http")]
    external_config: Option<Arc<crate::external::ExternalLocationConfig>>,
}

impl RpcServerBuilder {
    pub fn server_id(mut self, id: impl Into<String>) -> Self {
        self.server_id = Some(id.into());
        self
    }

    pub fn server_version(mut self, v: impl Into<String>) -> Self {
        self.server_version = Some(v.into());
        self
    }

    pub fn protocol_name(mut self, name: impl Into<String>) -> Self {
        self.protocol_name = Some(name.into());
        self
    }

    /// Operator-supplied free-form protocol-contract version label, reported
    /// in access-log records as ``protocol_version``. Complementary to
    /// (build) ``server_version``.
    pub fn protocol_version(mut self, v: impl Into<String>) -> Self {
        self.protocol_version = Some(v.into());
        self
    }

    pub fn enable_describe(mut self, enabled: bool) -> Self {
        self.enable_describe = enabled;
        self
    }

    pub fn with_hook(mut self, hook: Arc<dyn crate::hooks::DispatchHook>) -> Self {
        self.dispatch_hook = Some(hook);
        self
    }

    /// Register a one-shot lifecycle hook fired before the first
    /// request is dispatched on each (kind, capabilities) combination.
    /// Mirrors Python's `on_serve_start` duck-typed protocol.
    ///
    /// The hook runs synchronously on the thread that first observes
    /// the transport binding. Subsequent calls to
    /// [`RpcServer::notify_transport`] with the same `(kind, caps)`
    /// are no-ops; calls with a different combination re-fire the hook
    /// (matches Python's behaviour for test paths that re-bind).
    pub fn on_serve_start(mut self, hook: crate::transport::ServeStartHook) -> Self {
        self.on_serve_start = Some(hook);
        self
    }

    /// Enable automatic externalization of large unary results and stream
    /// output batches. Feature-gated on `http` (where the compression +
    /// fetcher deps already live).
    #[cfg(feature = "http")]
    pub fn with_external_location(mut self, cfg: crate::external::ExternalLocationConfig) -> Self {
        self.external_config = Some(Arc::new(cfg));
        self
    }

    pub fn build(self) -> RpcServer {
        RpcServer {
            methods: HashMap::new(),
            server_id: self.server_id.unwrap_or_else(crate::util::short_random_id),
            server_version: self.server_version.unwrap_or_default(),
            protocol_name: self.protocol_name.unwrap_or_default(),
            protocol_version: self.protocol_version.unwrap_or_default(),
            protocol_hash: std::sync::OnceLock::new(),
            describe_enabled: self.enable_describe,
            dispatch_hook: self.dispatch_hook,
            on_serve_start: self.on_serve_start,
            transport_state: Mutex::new(None),
            #[cfg(feature = "http")]
            external_config: self.external_config,
        }
    }
}

/// Describes one RPC method — the metadata required both for dispatch and
/// introspection via `__describe__`.
///
/// Build via [`MethodInfo::unary`] / [`MethodInfo::stream`] and attach
/// additional describe-time metadata through the builder helpers
/// (`.doc`, `.param_type`, `.param_default`, `.param_doc`, `.header_schema`).
pub struct MethodInfo {
    pub name: String,
    pub method_type: MethodType,
    /// Schema of the request parameters (one row).
    pub params_schema: SchemaRef,
    /// Schema of the unary result; empty for streams.
    pub result_schema: SchemaRef,
    /// For streams that emit a typed header, the header batch schema.
    pub header_schema: Option<SchemaRef>,
    /// Method-level docstring (the first line of Python's docstring).
    pub doc: Option<String>,
    /// Parameter type names in source order, matching the Python describe
    /// wire format ("str", "int", "list[str]", "Point", "str | None").
    pub param_types: Vec<(String, String)>,
    /// Parameter defaults; values are anything JSON-serializable.
    pub param_defaults: Vec<(String, serde_json::Value)>,
    /// Per-parameter documentation (matches the Python `param_docs_json`).
    pub param_docs: Vec<(String, String)>,
    /// Whether the method has a non-void return. `false` for streams/void.
    pub has_return: bool,
    pub unary: Option<UnaryHandler>,
    pub stream: Option<StreamHandler>,
    /// Decoder that reconstructs the method's `StreamStateKind` from a byte
    /// slice produced by `ProducerState::encode_state` /
    /// `ExchangeState::encode_state`. Required for HTTP streaming (the
    /// stateless-worker model); `None` for unary methods and for streams
    /// that will only ever run over pipe/unix.
    pub state_decoder: Option<StateDecoder>,
}

/// Decoder that reconstructs a concrete streaming state from its
/// serialized bytes, used by the HTTP transport on continuation requests.
pub type StateDecoder = Arc<dyn Fn(&[u8]) -> Result<crate::stream::StreamStateKind> + Send + Sync>;

impl MethodInfo {
    /// Start building a unary method registration.
    pub fn unary(
        name: impl Into<String>,
        params_schema: SchemaRef,
        result_schema: SchemaRef,
        handler: impl Fn(&Request, &CallContext) -> Result<Option<RecordBatch>> + Send + Sync + 'static,
    ) -> Self {
        let has_return = !result_schema.fields().is_empty();
        Self {
            name: name.into(),
            method_type: MethodType::Unary,
            params_schema,
            result_schema,
            header_schema: None,
            doc: None,
            param_types: Vec::new(),
            param_defaults: Vec::new(),
            param_docs: Vec::new(),
            has_return,
            unary: Some(Arc::new(handler)),
            stream: None,
            state_decoder: None,
        }
    }

    /// Start building a streaming method registration.
    ///
    /// **Note:** this form registers the method without a state decoder,
    /// so it will work for pipe/unix transports but HTTP continuation
    /// requests will fail. Attach a decoder via
    /// [`MethodInfo::with_state_decoder`] with
    /// [`producer_decoder`](crate::stream::producer_decoder) /
    /// [`exchange_decoder`](crate::stream::exchange_decoder) when HTTP is
    /// enabled.
    pub fn stream(
        name: impl Into<String>,
        method_type: MethodType,
        params_schema: SchemaRef,
        handler: impl Fn(&Request, &CallContext) -> Result<StreamResult> + Send + Sync + 'static,
    ) -> Self {
        assert!(
            matches!(
                method_type,
                MethodType::Producer | MethodType::Exchange | MethodType::Dynamic
            ),
            "stream methods must be Producer / Exchange / Dynamic"
        );
        Self {
            name: name.into(),
            method_type,
            params_schema,
            result_schema: empty_schema(),
            header_schema: None,
            doc: None,
            param_types: Vec::new(),
            param_defaults: Vec::new(),
            param_docs: Vec::new(),
            has_return: false,
            unary: None,
            stream: Some(Arc::new(handler)),
            state_decoder: None,
        }
    }

    /// Attach a state decoder function. See [`StateDecoder`].
    pub fn with_state_decoder(mut self, decoder: StateDecoder) -> Self {
        self.state_decoder = Some(decoder);
        self
    }

    pub fn doc(mut self, s: impl Into<String>) -> Self {
        self.doc = Some(s.into());
        self
    }

    pub fn param_type(mut self, param: impl Into<String>, ty: impl Into<String>) -> Self {
        self.param_types.push((param.into(), ty.into()));
        self
    }

    pub fn param_default(mut self, param: impl Into<String>, value: serde_json::Value) -> Self {
        self.param_defaults.push((param.into(), value));
        self
    }

    pub fn param_doc(mut self, param: impl Into<String>, doc: impl Into<String>) -> Self {
        self.param_docs.push((param.into(), doc.into()));
        self
    }

    pub fn header_schema(mut self, schema: SchemaRef) -> Self {
        self.header_schema = Some(schema);
        self
    }
}

/// The RPC server — holds method registrations and dispatches requests.
pub struct RpcServer {
    methods: HashMap<String, MethodInfo>,
    pub server_id: String,
    pub(crate) server_version: String,
    pub(crate) protocol_name: String,
    pub(crate) protocol_version: String,
    pub(crate) protocol_hash: std::sync::OnceLock<String>,
    pub(crate) describe_enabled: bool,
    pub(crate) dispatch_hook: Option<Arc<dyn crate::hooks::DispatchHook>>,
    /// Optional one-shot lifecycle hook fired on the first
    /// [`notify_transport`](Self::notify_transport) per (kind, caps).
    on_serve_start: Option<crate::transport::ServeStartHook>,
    /// Coarse identifier of the bound transport, populated by
    /// [`notify_transport`](Self::notify_transport).
    transport_state: Mutex<
        Option<(
            crate::transport::TransportKind,
            crate::transport::TransportCapabilities,
        )>,
    >,
    #[cfg(feature = "http")]
    pub(crate) external_config: Option<Arc<crate::external::ExternalLocationConfig>>,
}

impl RpcServer {
    /// Create a new `RpcServer`. For richer configuration, use [`RpcServer::builder`].
    pub fn new(server_id: impl Into<String>) -> Self {
        Self::builder().server_id(server_id).build()
    }

    /// Create a new builder.
    pub fn builder() -> RpcServerBuilder {
        RpcServerBuilder::default()
    }

    pub fn protocol_name(&self) -> &str {
        &self.protocol_name
    }

    pub fn describe_enabled(&self) -> bool {
        self.describe_enabled
    }

    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    /// SHA-256 hex digest of the canonical __describe__ payload. Computed
    /// lazily on first call and cached.
    pub fn protocol_hash(&self) -> &str {
        self.protocol_hash.get_or_init(|| {
            match crate::introspect::build_describe(
                &self.protocol_name,
                &self.methods,
                &self.server_id,
                &self.protocol_version,
            ) {
                Ok((_, md)) => md
                    .get(crate::metadata::PROTOCOL_HASH_KEY)
                    .cloned()
                    .unwrap_or_default(),
                Err(_) => String::new(),
            }
        })
    }

    #[cfg(feature = "http")]
    pub fn external_config(&self) -> Option<&Arc<crate::external::ExternalLocationConfig>> {
        self.external_config.as_ref()
    }

    /// Currently-bound [`TransportKind`](crate::transport::TransportKind),
    /// or `None` before the framework has observed a transport. Set by
    /// [`notify_transport`](Self::notify_transport).
    pub fn transport_kind(&self) -> Option<crate::transport::TransportKind> {
        lock_ok(&self.transport_state).as_ref().map(|(k, _)| *k)
    }

    /// Currently-advertised [`TransportCapabilities`](crate::transport::TransportCapabilities).
    /// Empty (all-false) before a transport is bound and for transports
    /// without extra capabilities.
    pub fn transport_capabilities(&self) -> crate::transport::TransportCapabilities {
        lock_ok(&self.transport_state)
            .as_ref()
            .map(|(_, c)| *c)
            .unwrap_or_default()
    }

    /// Bind the server to a transport, firing `on_serve_start` once per
    /// `(kind, caps)` combination. Subsequent calls with the same
    /// combination are cheap no-ops (the common case where transport
    /// glue invokes this on every request). A different combination
    /// updates the bound state and re-fires the hook — matches the
    /// Python `_notify_transport` contract.
    ///
    /// Call this from each transport entry point:
    /// - stdio / pipe `main`: once before [`serve`](Self::serve)
    /// - Unix accept loop: once per process
    /// - HTTP request handler: every request (idempotent)
    pub fn notify_transport(
        &self,
        kind: crate::transport::TransportKind,
        caps: crate::transport::TransportCapabilities,
    ) {
        let hook = {
            let mut guard = lock_ok(&self.transport_state);
            if let Some((cur_kind, cur_caps)) = guard.as_ref() {
                if *cur_kind == kind && *cur_caps == caps {
                    return;
                }
            }
            *guard = Some((kind, caps));
            self.on_serve_start.clone()
        };
        if let Some(h) = hook {
            h(kind, &caps);
        }
    }

    /// Register a method described by a [`MethodInfo`].
    pub fn register(&mut self, info: MethodInfo) {
        self.methods.insert(info.name.clone(), info);
    }

    /// Convenience wrapper for the old positional API — equivalent to
    /// `register(MethodInfo::unary(name, empty_schema(), result_schema, handler))`.
    /// Prefer [`MethodInfo::unary`] + [`RpcServer::register`] for new code.
    pub fn register_unary(
        &mut self,
        name: impl Into<String>,
        result_schema: SchemaRef,
        handler: impl Fn(&Request, &CallContext) -> Result<Option<RecordBatch>> + Send + Sync + 'static,
    ) {
        self.register(MethodInfo::unary(
            name,
            empty_schema(),
            result_schema,
            handler,
        ));
    }

    /// Convenience wrapper for the old positional API — equivalent to
    /// `register(MethodInfo::stream(name, method_type, empty_schema(), handler))`.
    /// Prefer [`MethodInfo::stream`] + [`RpcServer::register`] for new code.
    pub fn register_stream(
        &mut self,
        name: impl Into<String>,
        method_type: MethodType,
        handler: impl Fn(&Request, &CallContext) -> Result<StreamResult> + Send + Sync + 'static,
    ) {
        self.register(MethodInfo::stream(
            name,
            method_type,
            empty_schema(),
            handler,
        ));
    }

    pub fn method(&self, name: &str) -> Option<&MethodInfo> {
        self.methods.get(name)
    }

    pub fn methods(&self) -> &HashMap<String, MethodInfo> {
        &self.methods
    }

    pub fn method_names(&self) -> Vec<&str> {
        self.sorted_method_names()
    }

    /// Method names sorted alphabetically. Preferred over `methods().keys()`
    /// when order matters (introspection / describe / HTML rendering).
    pub fn sorted_method_names(&self) -> Vec<&str> {
        let mut names: Vec<_> = self.methods.keys().map(String::as_str).collect();
        names.sort();
        names
    }

    /// Run the serve loop over a single reader/writer pair (pipe or socket).
    ///
    /// Reads are **blocking with no timeout** — a peer that opens the
    /// connection and then stalls pins this thread until it sends data,
    /// EOFs, or resets. stdio/pipe has no timeout API, so that transport
    /// is trusted-peer-only (see also the SHM module docs). On a socket
    /// transport, the caller owns the stream and **should** set a read
    /// timeout (e.g. `UnixStream::set_read_timeout`) before handing it
    /// here; a `TimedOut`/`WouldBlock` error then cleanly ends the
    /// connection via the error path below.
    pub fn serve<R: Read, W: Write>(&self, mut r: R, mut w: W) {
        // Cache the client's dynamically-advertised SHM segment for the
        // life of the connection so later offset-only request/data batches
        // resolve against it (see [`ConnectionShm`]).
        let mut conn_shm = ConnectionShm::default();
        loop {
            match self.serve_one_conn(&mut r, &mut w, Some(&mut conn_shm)) {
                Ok(keep_going) => {
                    if !keep_going {
                        return;
                    }
                }
                Err(e) => {
                    // A frame-level error (malformed request, IO error,
                    // peer reset) ends the connection. Log it so a
                    // daemonized listener has diagnostics — silently
                    // returning made transient and hostile-input
                    // failures indistinguishable from a clean EOF.
                    tracing::warn!(
                        target: "vgi_rpc.server",
                        error = %e,
                        "serve loop terminating connection on error"
                    );
                    return;
                }
            }
        }
    }

    /// Like [`Self::serve`], but checks `shutdown` between requests and exits
    /// cleanly when it returns `true`. Useful for daemonized pipe/unix
    /// listeners that want to drain the in-flight request before exiting
    /// on SIGTERM. Blocking reads still must terminate via EOF/peer-close
    /// — this is an *advisory* signal checked at request boundaries.
    pub fn serve_with_shutdown<R, W, F>(&self, mut r: R, mut w: W, shutdown: F)
    where
        R: Read,
        W: Write,
        F: Fn() -> bool,
    {
        let mut conn_shm = ConnectionShm::default();
        loop {
            if shutdown() {
                return;
            }
            match self.serve_one_conn(&mut r, &mut w, Some(&mut conn_shm)) {
                Ok(true) => {}
                _ => return,
            }
        }
    }

    /// Handle one request. Returns `Ok(true)` to continue, `Ok(false)` on EOS/EOF.
    ///
    /// With no per-connection SHM cache wired (direct `serve_one` calls), a
    /// client-advertised segment is attached and detached per call instead
    /// of being cached across requests (the [`serve`](Self::serve) loop
    /// supplies the cache).
    pub fn serve_one<R: Read, W: Write>(&self, r: &mut R, w: &mut W) -> Result<bool> {
        self.serve_one_conn(r, w, None)
    }

    fn serve_one_conn<R: Read, W: Write>(
        &self,
        r: &mut R,
        w: &mut W,
        shm_cache: Option<&mut ConnectionShm>,
    ) -> Result<bool> {
        let result = self._serve_one(r, w, shm_cache);
        let _ = w.flush();
        result
    }

    fn _serve_one<R: Read, W: Write>(
        &self,
        r: &mut R,
        w: &mut W,
        mut shm_cache: Option<&mut ConnectionShm>,
    ) -> Result<bool> {
        let (req, request_used_shm) = match self.read_request(r, shm_cache.as_deref_mut())? {
            Some(rq) => rq,
            None => return Ok(false),
        };

        // __transport_options__ — framework transport-capability handshake,
        // handled before method dispatch (not a registered method, so it never
        // appears in `methods` / `__describe__`, and doesn't perturb the
        // protocol hash). Capabilities ride as response metadata; the response
        // batch is empty. Always available, including to version-mismatched
        // clients, since it is the negotiation they perform before `init`.
        if req.method == crate::transport_options::TRANSPORT_OPTIONS_METHOD_NAME {
            let mut md = crate::transport_options::worker_transport_metadata();
            md.insert(REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string());
            md.insert(SERVER_ID_KEY.to_string(), self.server_id.clone());
            let schema = empty_schema();
            let batch = empty_batch(&schema)?;
            let mut sw = StreamWriter::new(w, &schema)?;
            sw.write(&batch, Some(&md))?;
            sw.finish()?;
            return Ok(true);
        }

        // Enforce application protocol-version compatibility: the client sends
        // its `vgi_rpc.protocol_version`; if its MAJOR differs from the
        // server's enforced version, reject (mirrors the Python framework).
        if !self.protocol_version.is_empty() {
            if let Some(client_v) = md_get(&req.metadata, crate::metadata::PROTOCOL_VERSION_KEY) {
                let major = |v: &str| v.split('.').next().unwrap_or("").to_string();
                if major(client_v) != major(&self.protocol_version) {
                    let err = RpcError::version_error(format!(
                        "protocol_version mismatch: client {:?} is incompatible with server {:?}",
                        client_v, self.protocol_version
                    ));
                    write_error_stream(w, &empty_schema(), &err, &self.server_id, &req.request_id)?;
                    return Ok(true);
                }
            }
        }

        let ctx = CallContext::for_request(self, &req);

        let stats = Arc::new(Mutex::new(crate::hooks::CallStatistics::default()));
        // Record the unary request batch as input stats (one row).
        {
            let mut s = lock_ok(&stats);
            s.input_batches = 1;
            s.input_rows = req.batch.num_rows() as u64;
        }

        // Built-in __describe__ introspection.
        if self.describe_enabled && req.method == crate::introspect::DESCRIBE_METHOD_NAME {
            match crate::introspect::build_describe(
                &self.protocol_name,
                &self.methods,
                &self.server_id,
                &self.protocol_version,
            ) {
                Ok((batch, md)) => {
                    crate::introspect::write_describe_response(w, &batch, &md)?;
                }
                Err(err) => {
                    write_error_stream(w, &empty_schema(), &err, &self.server_id, &req.request_id)?;
                }
            }
            return Ok(true);
        }

        let Some(info) = self.methods.get(&req.method) else {
            let names = self.sorted_method_names();
            let msg = format!(
                "Unknown method: '{}'. Available methods: {:?}",
                req.method, names
            );
            write_error_stream(
                w,
                &empty_schema(),
                &RpcError::attribute_error(msg),
                &self.server_id,
                &req.request_id,
            )?;
            return Ok(true);
        };

        let method_type = match info.method_type {
            MethodType::Unary => "unary",
            _ => "stream",
        };
        // The `DispatchInfo` — a large struct with many owned clones — plus
        // the request re-serialization below are needed *only* when a
        // dispatch hook is registered. Build nothing on the hookless path.
        let dispatch_info = self.dispatch_hook.as_ref().map(|_| {
            let mut di =
                crate::hooks::DispatchInfo::from_request(self, &req, method_type, &ctx.auth);
            // Best-effort capture of self-contained Arrow IPC bytes of the
            // request batch for access-log `request_data`. Failures here must
            // not abort dispatch — observability is non-essential.
            if let Ok(bytes) = serialize_request_batch(&req.batch) {
                di.request_data = bytes;
            }
            if method_type == "stream" {
                di.stream_id = crate::access_log::random_stream_id();
            }
            di
        });
        let hook_token = match (self.dispatch_hook.as_ref(), dispatch_info.as_ref()) {
            (Some(h), Some(di)) => Some(h.on_dispatch_start(di)),
            _ => None,
        };

        let mut app_err: Option<RpcError> = None;
        // Determine the SHM segment for this call's data plane (resolving
        // input batches, routing output/response batches). Crucially, only
        // route the *response* through shm when the client signalled shm for
        // THIS exchange — it sent the request via a shm pointer
        // (SHM_OFFSET_KEY) or advertised the segment (SHM_SEGMENT_NAME_KEY).
        // The C++ client resolves shm responses only for those methods; for
        // plain inline requests (bind, catalog_*, transaction_*) it expects
        // an inline response and reports a shm-routed one as empty. With no
        // cache wired (a direct `serve_one` call) fall back to the original
        // per-call attach, which only succeeds when this request names the
        // segment.
        let dynamic_shm: Option<ShmSegment>;
        let shm_ref: Option<&ShmSegment> = match shm_cache {
            Some(cache) => {
                if request_used_shm {
                    cache.segment()
                } else {
                    None
                }
            }
            None => {
                dynamic_shm = maybe_attach_shm(&req.metadata);
                dynamic_shm.as_ref()
            }
        };
        match info.method_type {
            MethodType::Unary => {
                self.serve_unary(w, &req, info, &ctx, &stats, &mut app_err, shm_ref)?
            }
            MethodType::Producer | MethodType::Exchange | MethodType::Dynamic => {
                self.serve_stream(r, w, &req, info, &ctx, &stats, &mut app_err, shm_ref)?
            }
        }
        // A per-call `dynamic_shm` (if any) is dropped here, releasing our
        // mmap of the client-owned segment without unlinking it; a cached
        // segment lives until the connection ends.

        if let (Some(hook), Some(di)) = (self.dispatch_hook.as_ref(), dispatch_info.as_ref()) {
            let token = hook_token.unwrap_or(0);
            let final_stats = lock_ok(&stats).clone();
            hook.on_dispatch_end(token, di, app_err.as_ref(), &final_stats);
        }
        Ok(true)
    }

    /// Read one request off the wire. Returns the parsed request plus
    /// whether the client signalled SHM for this exchange (the request was
    /// a shm pointer, or advertised a segment) — which gates whether the
    /// response/data plane may route through shm.
    fn read_request<R: Read>(
        &self,
        r: &mut R,
        shm_cache: Option<&mut ConnectionShm>,
    ) -> Result<Option<(Request, bool)>> {
        let mut reader = match StreamReader::new(r) {
            Ok(r) => r,
            Err(e) => {
                // EOF at request boundary is normal
                let msg = e.message.to_lowercase();
                if msg.contains("empty ipc stream") || msg.contains("eof") {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let (batch, metadata) = match reader.read_next()? {
            Some(b) => b,
            None => return Ok(None),
        };
        reader.drain()?;
        // Computed on the wire metadata, before pointer resolution strips
        // the offset key.
        let request_used_shm =
            metadata.contains_key(SHM_OFFSET_KEY) || metadata.contains_key(SHM_SEGMENT_NAME_KEY);
        // A client (e.g. the C++ extension) may route the single-row request
        // batch through the shm side channel above a size threshold, so the
        // inline batch arrives as a 0-row pointer; resolve it back to its
        // real columns before the single-row guard in `from_read_batch`.
        // The segment comes from the connection cache — refreshed from any
        // name this request's own metadata advertises — or, with no cache
        // wired, a one-shot attach released before returning.
        #[cfg(feature = "shm")]
        let (batch, metadata) = if is_shm_pointer_batch(&batch, &metadata) {
            let one_shot: Option<ShmSegment>;
            let seg: Option<&ShmSegment> = match shm_cache {
                Some(cache) => {
                    cache.refresh(&metadata);
                    cache.segment()
                }
                None => {
                    one_shot = maybe_attach_shm(&metadata);
                    one_shot.as_ref()
                }
            };
            let resolved = resolve_shm_batch(batch, metadata, seg)?;
            // The resolved batch copies the region bytes out, so the slot
            // is dead once materialized — free it for the client.
            if let (Some(off), Some(seg)) = (resolved.release_offset, seg) {
                let _ = seg.free(off);
            }
            (resolved.batch, resolved.metadata)
        } else {
            if let Some(cache) = shm_cache {
                cache.refresh(&metadata);
            }
            (batch, metadata)
        };
        #[cfg(not(feature = "shm"))]
        let _ = shm_cache;
        Ok(Some((
            Request::from_read_batch(batch, metadata, true)?,
            request_used_shm,
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn serve_unary<W: Write>(
        &self,
        w: &mut W,
        req: &Request,
        info: &MethodInfo,
        ctx: &CallContext,
        stats: &Arc<Mutex<crate::hooks::CallStatistics>>,
        app_err: &mut Option<RpcError>,
        #[cfg_attr(not(feature = "shm"), allow(unused_variables))] shm: Option<&ShmSegment>,
    ) -> Result<()> {
        // A panic in handler code is converted to an `RpcError` and
        // flows into the error-envelope path below, rather than
        // unwinding through the serve loop.
        let result = call_guard(|| (info.unary.as_ref().unwrap())(req, ctx)).and_then(|r| r);
        let logs = ctx.drain_logs();
        let mut envelope = EnvelopeMeta::new(&self.server_id, &req.request_id);
        match result {
            Ok(maybe_batch) => {
                let mut sw = StreamWriter::new(w, &info.result_schema)?;
                for log in logs {
                    let md = envelope.log(&log);
                    sw.write(&empty_batch(&info.result_schema)?, Some(md))?;
                }
                let out_batch = match maybe_batch {
                    Some(b) => b,
                    None => empty_batch(&info.result_schema)?,
                };
                {
                    let mut s = lock_ok(stats);
                    s.output_batches = 1;
                    s.output_rows = out_batch.num_rows() as u64;
                }
                #[cfg(feature = "shm")]
                if let Some(seg) = shm {
                    let (written, written_md) =
                        maybe_write_to_shm(out_batch.clone(), Metadata::new(), Some(seg))?;
                    if written_md.contains_key(crate::metadata::SHM_OFFSET_KEY) {
                        sw.write(&written, Some(&written_md))?;
                        sw.finish()?;
                        return Ok(());
                    }
                }
                #[cfg(feature = "http")]
                if let Some(cfg) = self.external_config.as_ref() {
                    if let Ok(Some((ptr, md))) =
                        crate::external::maybe_externalize_batch(&out_batch, None, cfg)
                    {
                        sw.write(&ptr, Some(&md))?;
                        sw.finish()?;
                        return Ok(());
                    }
                }
                #[cfg(not(feature = "shm"))]
                let _ = shm;
                sw.write(&out_batch, None)?;
                sw.finish()?;
            }
            Err(err) => {
                let mut sw = StreamWriter::new(w, &info.result_schema)?;
                for log in logs {
                    let md = envelope.log(&log);
                    sw.write(&empty_batch(&info.result_schema)?, Some(md))?;
                }
                let md = envelope.error(&err);
                sw.write(&empty_batch(&info.result_schema)?, Some(md))?;
                sw.finish()?;
                *app_err = Some(err);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn serve_stream<R: Read, W: Write>(
        &self,
        r: &mut R,
        w: &mut W,
        req: &Request,
        info: &MethodInfo,
        ctx: &CallContext,
        stats: &Arc<Mutex<crate::hooks::CallStatistics>>,
        app_err: &mut Option<RpcError>,
        #[cfg_attr(not(feature = "shm"), allow(unused_variables))] shm: Option<&ShmSegment>,
    ) -> Result<()> {
        let init_result = call_guard(|| (info.stream.as_ref().unwrap())(req, ctx)).and_then(|r| r);
        let init_logs = ctx.drain_logs();
        let stream = match init_result {
            Ok(s) => s,
            Err(err) => {
                // Init error: write as unary-style error stream.
                let output_schema = info.result_schema.clone();
                let mut sw = StreamWriter::new(w, &output_schema)?;
                let mut envelope = EnvelopeMeta::new(&self.server_id, &req.request_id);
                for log in init_logs {
                    let md = envelope.log(&log);
                    sw.write(&empty_batch(&output_schema)?, Some(md))?;
                }
                let md = envelope.error(&err);
                sw.write(&empty_batch(&output_schema)?, Some(md))?;
                sw.finish()?;
                // Drain any client input (ticks / exchange batches) so the transport
                // is clean for the next request.
                let _ = drain_input(r);
                *app_err = Some(err);
                return Ok(());
            }
        };

        let StreamResult {
            output_schema,
            input_schema,
            state,
            header,
            header_metadata,
        } = stream;

        // Reused across every log/error envelope in this stream: the stable
        // server_id/request_id entries are allocated once and each envelope
        // only overwrites the transient level/message/extra values.
        let mut envelope = EnvelopeMeta::new(&self.server_id, &req.request_id);

        // Write header as its own IPC stream if present.
        let wrote_header = header.is_some();
        if let Some(header_batch) = header {
            let mut hw = StreamWriter::new(&mut *w, header_batch.schema().as_ref())?;
            for log in &init_logs {
                let md = envelope.log(log);
                hw.write(&empty_batch(header_batch.schema().as_ref())?, Some(md))?;
            }
            hw.write(&header_batch, header_metadata.as_ref())?;
            hw.finish()?;
        }
        let _ = w.flush();

        // Open the output stream first — the client opens the output reader
        // before the next tick is read back here, so we must make the schema
        // available without waiting on input.
        let mut out_writer = StreamWriter::new(&mut *w, output_schema.as_ref())?;
        out_writer.flush()?;

        // Open the input stream (ticks for producer, real batches for exchange).
        let mut input_reader = StreamReader::new(&mut *r)?;

        // A zero-row batch on the output schema, reused for every log/error
        // envelope in this stream (it's immutable and identical each time)
        // instead of rebuilding it per log line / per tick.
        let empty_out = empty_batch(output_schema.as_ref())?;

        // If we didn't already write init logs into a header stream, write them now.
        if !wrote_header {
            for log in &init_logs {
                let md = envelope.log(log);
                out_writer.write(&empty_out, Some(md))?;
            }
        }
        let _ = header_metadata;

        let mut state = state;
        let mut cancelled = false;

        'lockstep: loop {
            let read = match input_reader.read_next() {
                Ok(x) => x,
                Err(_) => break,
            };
            let Some((input_batch, input_md)) = read else {
                break;
            };

            // Resolve SHM pointer batches before anything else — the
            // schema cast / cancel check / handler all expect the real
            // batch. Free the region as soon as it's been deserialized
            // (we copy on read, so no live borrow remains).
            #[cfg(feature = "shm")]
            let (input_batch, input_md) = {
                let resolved = resolve_shm_batch(input_batch, input_md, shm)?;
                if let (Some(off), Some(seg)) = (resolved.release_offset, shm) {
                    let _ = seg.free(off);
                }
                (resolved.batch, resolved.metadata)
            };

            {
                let mut s = lock_ok(stats);
                s.input_batches += 1;
                s.input_rows += input_batch.num_rows() as u64;
            }

            // Read the cancel flag before moving `input_md` into the context.
            let is_cancel = md_get(&input_md, CANCEL_KEY).is_some();

            // Surface this tick's input metadata (e.g. dynamic pushdown
            // filters) to the producer/exchange handler via the context.
            // `input_md` is not used past this point, so move it in rather
            // than deep-clone the map every tick.
            *lock_ok(&ctx.tick_metadata) = input_md;

            // Cancellation signal.
            if is_cancel {
                cancelled = true;
                match &mut state {
                    StreamStateKind::Producer(p) => p.on_cancel(ctx),
                    StreamStateKind::Exchange(e) => e.on_cancel(ctx),
                }
                break;
            }

            // Cast input schema to expected schema when required.
            let casted = match &input_schema {
                Some(expected) if input_batch.schema() != *expected => {
                    match cast_batch(&input_batch, expected) {
                        Ok(b) => b,
                        Err(e) => {
                            let md = envelope.error(&e);
                            out_writer.write(&empty_out, Some(md))?;
                            break 'lockstep;
                        }
                    }
                }
                _ => input_batch,
            };

            let mut out = OutputCollector::new(output_schema.clone(), input_schema.is_none());

            let iter_result = call_guard(|| match &mut state {
                StreamStateKind::Producer(p) => p.produce(&mut out, ctx),
                StreamStateKind::Exchange(e) => e.exchange(&casted, &mut out, ctx),
            })
            .and_then(|r| r);

            // Flush any iteration-level logs first (logs appended during produce/exchange).
            let iter_logs = ctx.drain_logs();
            for log in iter_logs {
                let md = envelope.log(&log);
                out_writer.write(&empty_out, Some(md))?;
            }

            if let Err(err) = iter_result {
                let md = envelope.error(&err);
                out_writer.write(&empty_out, Some(md))?;
                *app_err = Some(err);
                break;
            }

            let finished = out.finished();

            // Flush collected emitted items (logs added via OutputCollector, then batches).
            for item in out.items.drain(..) {
                match item {
                    Emitted::Log(log) => {
                        let md = envelope.log(&log);
                        out_writer.write(&empty_out, Some(md))?;
                    }
                    Emitted::Batch { batch, metadata } => {
                        {
                            let mut s = lock_ok(stats);
                            s.output_batches += 1;
                            s.output_rows += batch.num_rows() as u64;
                        }
                        #[cfg(feature = "shm")]
                        if let Some(seg) = shm {
                            let md_in = metadata.clone().unwrap_or_default();
                            let (written, written_md) =
                                maybe_write_to_shm(batch.clone(), md_in, Some(seg))?;
                            if written_md.contains_key(crate::metadata::SHM_OFFSET_KEY) {
                                out_writer.write(&written, Some(&written_md))?;
                                continue;
                            }
                        }
                        #[cfg(feature = "http")]
                        if let Some(cfg) = self.external_config.as_ref() {
                            match crate::external::maybe_externalize_batch(
                                &batch,
                                metadata.as_ref(),
                                cfg,
                            ) {
                                Ok(Some((ptr, md))) => {
                                    out_writer.write(&ptr, Some(&md))?;
                                    continue;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    // Externalization failed — fall through to inline write,
                                    // but record the error on the access log via app_err.
                                    *app_err = Some(e);
                                }
                            }
                        }
                        out_writer.write(&batch, metadata.as_ref())?;
                    }
                }
            }
            // The client writes a tick and then blocks reading our response;
            // we must flush after every lockstep iteration.
            out_writer.flush()?;

            if finished {
                break;
            }
        }
        let _ = cancelled;
        out_writer.finish()?;

        // Drain remaining input.
        let _ = input_reader.drain();
        Ok(())
    }
}

fn drain_input<R: Read>(r: &mut R) -> Result<()> {
    let mut rdr = StreamReader::new(r)?;
    rdr.drain()?;
    Ok(())
}

pub(crate) fn cast_batch(batch: &RecordBatch, target: &SchemaRef) -> Result<RecordBatch> {
    if batch.num_columns() != target.fields().len() {
        return Err(RpcError::type_error(format!(
            "Input schema mismatch: expected {} fields, got {}",
            target.fields().len(),
            batch.num_columns()
        )));
    }
    let src_schema = batch.schema();
    for (i, field) in target.fields().iter().enumerate() {
        let src_name = src_schema.field(i).name();
        if src_name != field.name() {
            return Err(RpcError::type_error(format!(
                "Input schema mismatch: expected field {:?}, got {:?}",
                field.name(),
                src_name
            )));
        }
    }
    let opts = arrow_cast::CastOptions::default();
    let mut cols = Vec::with_capacity(batch.num_columns());
    for (i, field) in target.fields().iter().enumerate() {
        let src = batch.column(i);
        if src.data_type() == field.data_type() {
            cols.push(src.clone());
            continue;
        }
        let c = cast_with_options(src.as_ref(), field.data_type(), &opts)
            .map_err(|e| RpcError::type_error(format!("cast field {}: {}", field.name(), e)))?;
        cols.push(c);
    }
    // Reuse the caller's `SchemaRef` (Arc bump) instead of deep-cloning the
    // Schema on every casting tick.
    RecordBatch::try_new(target.clone(), cols).map_err(RpcError::from)
}

/// Reusable builder for per-message log / error envelope metadata.
///
/// The `server_id` / `request_id` entries are stable for the lifetime of a
/// call, so they are allocated once at construction and kept in the map.
/// Each subsequent envelope only overwrites the transient
/// level/message/extra values in place (`get_mut`, reusing the existing key
/// and slot allocations) instead of building a fresh `HashMap` and
/// re-stringifying the ids on every log line — the per-tick allocation cost
/// under streaming logging. The on-wire bytes are unchanged (metadata key
/// order is already unspecified).
pub(crate) struct EnvelopeMeta<'a> {
    server_id: &'a str,
    request_id: &'a str,
    /// Allocated lazily on the first log/error so a call that never logs
    /// (the common case) pays nothing.
    md: Option<Metadata>,
}

impl<'a> EnvelopeMeta<'a> {
    pub(crate) fn new(server_id: &'a str, request_id: &'a str) -> Self {
        Self {
            server_id,
            request_id,
            md: None,
        }
    }

    /// The metadata map, allocating it (with the stable id entries) on first
    /// use.
    fn map(&mut self) -> &mut Metadata {
        if self.md.is_none() {
            let mut md = Metadata::with_capacity(5);
            if !self.server_id.is_empty() {
                md.insert(SERVER_ID_KEY.to_string(), self.server_id.to_string());
            }
            if !self.request_id.is_empty() {
                md.insert(REQUEST_ID_KEY.to_string(), self.request_id.to_string());
            }
            self.md = Some(md);
        }
        self.md.as_mut().unwrap()
    }

    /// Overwrite `key`'s value in place when present (reusing the key + slot
    /// allocation), else insert it.
    fn set(&mut self, key: &'static str, val: String) {
        let md = self.map();
        if let Some(slot) = md.get_mut(key) {
            *slot = val;
        } else {
            md.insert(key.to_string(), val);
        }
    }

    /// Populate for a log message and return the reused metadata map.
    pub(crate) fn log(&mut self, msg: &LogMessage) -> &Metadata {
        self.set(LOG_LEVEL_KEY, msg.level.as_str().to_string());
        self.set(LOG_MESSAGE_KEY, msg.message.clone());
        if !msg.extras.is_empty() {
            self.set(LOG_EXTRA_KEY, msg.extras_json());
        } else {
            // Clear any extra left by a previous error/log envelope.
            self.map().remove(LOG_EXTRA_KEY);
        }
        self.md.as_ref().unwrap()
    }

    /// Populate for an error (EXCEPTION level) and return the reused map.
    pub(crate) fn error(&mut self, err: &RpcError) -> &Metadata {
        let extra = serde_json::json!({
            "exception_type": err.error_type,
            "exception_message": err.message,
            "traceback": err.traceback,
        })
        .to_string();
        self.set(LOG_LEVEL_KEY, "EXCEPTION".to_string());
        self.set(LOG_MESSAGE_KEY, err.message.clone());
        self.set(LOG_EXTRA_KEY, extra);
        self.md.as_ref().unwrap()
    }
}

// Only the HTTP transport still calls the standalone builder — the pipe/unix
// serve loops use a reused `EnvelopeMeta` directly. Gate it so a no-`http`
// build (e.g. the conformance client-driver) doesn't flag it as dead code.
#[cfg(feature = "http")]
pub(crate) fn build_log_metadata(msg: &LogMessage, server_id: &str, request_id: &str) -> Metadata {
    let mut e = EnvelopeMeta::new(server_id, request_id);
    e.log(msg);
    e.md.unwrap()
}

pub(crate) fn build_error_metadata(err: &RpcError, server_id: &str, request_id: &str) -> Metadata {
    let mut e = EnvelopeMeta::new(server_id, request_id);
    e.error(err);
    e.md.unwrap()
}

/// Write an error as a complete single-batch IPC stream.
pub(crate) fn write_error_stream<W: Write>(
    w: &mut W,
    schema: &Schema,
    err: &RpcError,
    server_id: &str,
    request_id: &str,
) -> Result<()> {
    let mut sw = StreamWriter::new(w, schema)?;
    let md = build_error_metadata(err, server_id, request_id);
    sw.write(&empty_batch(schema)?, Some(&md))?;
    sw.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Frame a no-argument request for `method` as a self-contained IPC
    /// stream the pipe-transport serve loop can read.
    fn request_bytes(method: &str) -> Vec<u8> {
        let schema = empty_schema();
        let batch = empty_batch(&schema).unwrap();
        let mut buf = Vec::new();
        {
            let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
            let mut md = Metadata::new();
            md.insert(RPC_METHOD_KEY.into(), method.into());
            md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
            md.insert(REQUEST_ID_KEY.into(), format!("req-{method}"));
            w.write(&batch, Some(&md)).unwrap();
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn panicking_handler_yields_error_envelope_and_loop_survives() {
        let mut server = RpcServer::new("test-srv");
        server.register(MethodInfo::unary(
            "boom",
            empty_schema(),
            empty_schema(),
            |_req, _ctx| panic!("handler exploded"),
        ));
        let ran_second = Arc::new(AtomicBool::new(false));
        let flag = ran_second.clone();
        server.register(MethodInfo::unary(
            "ok",
            empty_schema(),
            empty_schema(),
            move |_req, _ctx| {
                flag.store(true, Ordering::SeqCst);
                Ok(None)
            },
        ));

        // Two back-to-back requests: the first handler panics, the
        // second must still run — the serve loop must not abort.
        let mut input = request_bytes("boom");
        input.extend(request_bytes("ok"));
        let mut output: Vec<u8> = Vec::new();
        server.serve(Cursor::new(input), &mut output);

        assert!(
            ran_second.load(Ordering::SeqCst),
            "serve loop aborted after a handler panic"
        );

        // The panic was surfaced to the client as an error envelope,
        // not a silent connection drop.
        let mut r = StreamReader::new(output.as_slice()).unwrap();
        let (_b, md) = r.read_next().unwrap().expect("error batch");
        assert_eq!(md_get(&md, LOG_LEVEL_KEY), Some("EXCEPTION"));
    }

    #[test]
    fn transport_options_reports_shm_capability_unregistered() {
        use crate::metadata::TRANSPORT_SHM_KEY;
        use crate::transport_options::{shm_available, TRANSPORT_OPTIONS_METHOD_NAME};

        let mut server = RpcServer::new("test-srv");
        server.register(MethodInfo::unary(
            "noop",
            empty_schema(),
            empty_schema(),
            |_req, _ctx| Ok(None),
        ));
        // Not a registered method — handled by pre-dispatch interception.
        assert!(!server.methods.contains_key(TRANSPORT_OPTIONS_METHOD_NAME));

        let input = request_bytes(TRANSPORT_OPTIONS_METHOD_NAME);
        let mut output: Vec<u8> = Vec::new();
        server.serve(Cursor::new(input), &mut output);

        let mut r = StreamReader::new(output.as_slice()).unwrap();
        let (_b, md) = r.read_next().unwrap().expect("transport options batch");
        let expected = if shm_available() { "true" } else { "false" };
        assert_eq!(md_get(&md, TRANSPORT_SHM_KEY), Some(expected));
        assert_eq!(md_get(&md, REQUEST_VERSION_KEY), Some(REQUEST_VERSION));
        assert_eq!(md_get(&md, SERVER_ID_KEY), Some("test-srv"));
    }

    /// SHM-routed *request* batches (vgi-rpc Python 42701df).
    ///
    /// Cross-language regression: the C++ client routes a large single-row
    /// request batch through the shm side channel (sending a 0-row pointer
    /// inline), whereas the Python and Rust clients keep requests inline —
    /// so no end-to-end conformance lane exercised this path. Before the
    /// fix, a shm-routed request tripped the ``Expected 1 row in request
    /// batch`` guard (seen on accumulate / table_buffering over the shm
    /// transport).
    #[cfg(feature = "shm")]
    mod shm_requests {
        use super::*;
        use crate::metadata::{SHM_OFFSET_KEY, SHM_SEGMENT_NAME_KEY, SHM_SEGMENT_SIZE_KEY};
        use crate::shm::{
            is_shm_pointer_batch, make_shm_pointer_batch, maybe_write_to_shm, ShmSegment,
        };
        use arrow_array::{BinaryArray, Int64Array};
        use arrow_schema::{DataType, Field};

        fn params_schema() -> SchemaRef {
            Arc::new(Schema::new(vec![Field::new(
                "request",
                DataType::Binary,
                false,
            )]))
        }

        fn result_schema() -> SchemaRef {
            Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]))
        }

        fn request_batch(payload: &[u8]) -> RecordBatch {
            RecordBatch::try_new(
                params_schema(),
                vec![Arc::new(BinaryArray::from(vec![Some(payload)]))],
            )
            .unwrap()
        }

        /// Dispatch metadata the way the C++ client stamps it: method +
        /// version, plus (optionally) the client-owned segment's name/size.
        fn dispatch_md(seg: Option<&ShmSegment>) -> Metadata {
            let mut md = Metadata::new();
            md.insert(RPC_METHOD_KEY.into(), "do_thing".into());
            md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
            if let Some(seg) = seg {
                md.insert(SHM_SEGMENT_NAME_KEY.into(), seg.name().to_string());
                md.insert(SHM_SEGMENT_SIZE_KEY.into(), seg.size().to_string());
            }
            md
        }

        /// Frame one request stream whose parameter batch rides through shm
        /// (`maybe_write_to_shm`, the way the C++ client builds it). Fresh
        /// allocation each call: resolving frees the region, so a reused
        /// pointer would dangle.
        fn pointer_request(seg: &ShmSegment, payload: &[u8], advertise: bool) -> Vec<u8> {
            let md = dispatch_md(advertise.then_some(seg));
            let (ptr, ptr_md) = maybe_write_to_shm(request_batch(payload), md, Some(seg)).unwrap();
            assert!(
                is_shm_pointer_batch(&ptr, &ptr_md),
                "request batch should have routed through shm"
            );
            let mut buf = Vec::new();
            {
                let mut w = StreamWriter::new(&mut buf, ptr.schema().as_ref()).unwrap();
                w.write(&ptr, Some(&ptr_md)).unwrap();
                w.finish().unwrap();
            }
            buf
        }

        /// Frame one inline request stream (optionally advertising the segment).
        fn inline_request(payload: &[u8], seg: Option<&ShmSegment>) -> Vec<u8> {
            let batch = request_batch(payload);
            let md = dispatch_md(seg);
            let mut buf = Vec::new();
            {
                let mut w = StreamWriter::new(&mut buf, batch.schema().as_ref()).unwrap();
                w.write(&batch, Some(&md)).unwrap();
                w.finish().unwrap();
            }
            buf
        }

        /// Server whose single unary method records each request payload and
        /// answers with a 1-row batch (so the response data plane has
        /// something to route).
        fn payload_server(seen: Arc<Mutex<Vec<Vec<u8>>>>) -> RpcServer {
            let mut server = RpcServer::new("shm-srv");
            let rs = result_schema();
            server.register(MethodInfo::unary(
                "do_thing",
                params_schema(),
                result_schema(),
                move |req, _ctx| {
                    let col = req
                        .column("request")
                        .expect("request column")
                        .as_any()
                        .downcast_ref::<BinaryArray>()
                        .unwrap();
                    lock_ok(&seen).push(col.value(0).to_vec());
                    Ok(Some(RecordBatch::try_new(
                        rs.clone(),
                        vec![Arc::new(Int64Array::from(vec![1i64]))],
                    )?))
                },
            ));
            server
        }

        /// Collect every response batch's metadata across the concatenated
        /// response streams in `output`.
        fn response_metadata(output: &[u8]) -> Vec<Metadata> {
            let mut out = Vec::new();
            let mut cursor = Cursor::new(output);
            while (cursor.position() as usize) < output.len() {
                let mut reader = StreamReader::new(&mut cursor).unwrap();
                while let Some((_b, md)) = reader.read_next().unwrap() {
                    out.push(md);
                }
            }
            out
        }

        /// A shm-pointer request that names its segment resolves before the
        /// single-row guard — both on the cached `serve` path and on the
        /// per-call `serve_one` path.
        #[test]
        fn pointer_request_batch_resolves_via_segment_named_in_metadata() {
            let seg = ShmSegment::create(1024 * 1024).unwrap();
            let payload = b"serialized-request-blob";

            let seen = Arc::new(Mutex::new(Vec::new()));
            let server = payload_server(seen.clone());
            let mut output: Vec<u8> = Vec::new();
            server.serve(
                Cursor::new(pointer_request(&seg, payload, true)),
                &mut output,
            );
            assert_eq!(lock_ok(&seen).as_slice(), &[payload.to_vec()]);

            // Direct serve_one (no connection cache): one-shot attach.
            let seen2 = Arc::new(Mutex::new(Vec::new()));
            let server2 = payload_server(seen2.clone());
            let mut input = Cursor::new(pointer_request(&seg, payload, true));
            let mut output2: Vec<u8> = Vec::new();
            assert!(server2.serve_one(&mut input, &mut output2).unwrap());
            assert_eq!(lock_ok(&seen2).as_slice(), &[payload.to_vec()]);
        }

        /// The client names its segment once; a later offset-only pointer
        /// request resolves against the connection-cached attachment.
        #[test]
        fn serve_caches_client_segment_for_offset_only_requests() {
            let seg = ShmSegment::create(1024 * 1024).unwrap();

            // Request A: inline, advertising the segment (first sight).
            let mut input = inline_request(b"first", Some(&seg));

            // Request B: offset-only pointer — no segment name in sight.
            let (off, len) = seg
                .allocate_and_write(&request_batch(b"second"))
                .unwrap()
                .expect("payload fits");
            let (ptr, mut ptr_md) =
                make_shm_pointer_batch(params_schema().as_ref(), off, len).unwrap();
            ptr_md.insert(RPC_METHOD_KEY.into(), "do_thing".into());
            ptr_md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
            {
                let mut w = StreamWriter::new(&mut input, ptr.schema().as_ref()).unwrap();
                w.write(&ptr, Some(&ptr_md)).unwrap();
                w.finish().unwrap();
            }

            let seen = Arc::new(Mutex::new(Vec::new()));
            let server = payload_server(seen.clone());
            let mut output: Vec<u8> = Vec::new();
            server.serve(Cursor::new(input), &mut output);
            assert_eq!(
                lock_ok(&seen).as_slice(),
                &[b"first".to_vec(), b"second".to_vec()]
            );
        }

        /// With neither a named segment nor a cached one, the 0-row pointer
        /// trips the single-row guard and the request fails.
        #[test]
        fn pointer_request_without_segment_trips_single_row_guard() {
            let seg = ShmSegment::create(1024 * 1024).unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let server = payload_server(seen.clone());
            let mut output: Vec<u8> = Vec::new();
            server.serve(
                Cursor::new(pointer_request(&seg, b"orphan", false)),
                &mut output,
            );
            assert!(lock_ok(&seen).is_empty(), "guard should reject dispatch");
        }

        /// The response routes through shm only when the client signalled
        /// shm for THIS exchange. The C++ client resolves shm responses only
        /// for the methods it shm-routed; an inline control request (bind,
        /// catalog_*) expects an inline response, and a shm-routed one is
        /// reported as empty.
        #[test]
        fn response_routed_through_shm_only_when_request_signalled_shm() {
            let seg = ShmSegment::create(1024 * 1024).unwrap();

            // Request A advertises the segment; request B is plain inline
            // on the same connection (cache now holds the segment).
            let mut input = inline_request(b"a", Some(&seg));
            input.extend(inline_request(b"b", None));

            let seen = Arc::new(Mutex::new(Vec::new()));
            let server = payload_server(seen.clone());
            let mut output: Vec<u8> = Vec::new();
            server.serve(Cursor::new(input), &mut output);
            assert_eq!(lock_ok(&seen).len(), 2);

            let mds = response_metadata(&output);
            assert_eq!(mds.len(), 2, "one data batch per response");
            assert!(
                mds[0].contains_key(SHM_OFFSET_KEY),
                "response A (segment advertised) should route through shm"
            );
            assert!(
                !mds[1].contains_key(SHM_OFFSET_KEY),
                "response B (no shm signal) must stay inline despite the cached segment"
            );
        }
    }
}
