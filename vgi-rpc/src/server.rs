//! RPC server dispatch — reads requests, invokes handlers, writes responses.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use arrow_array::RecordBatch;
use arrow_cast::cast_with_options;
use arrow_schema::{Schema, SchemaRef};

use crate::errors::{Result, RpcError};
use crate::log::{LogLevel, LogMessage};
use crate::metadata::{
    CANCEL_KEY, LOG_EXTRA_KEY, LOG_LEVEL_KEY, LOG_MESSAGE_KEY, REQUEST_ID_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY, SERVER_ID_KEY,
};
use crate::stream::{
    empty_schema, Emitted, ExchangeState, OutputCollector, ProducerState, StreamResult,
    StreamStateKind,
};
use crate::wire::{empty_batch, md_get, Metadata, ReadBatch, StreamReader, StreamWriter};

/// Context supplied to each handler invocation.
#[derive(Clone)]
pub struct CallContext {
    pub server_id: String,
    pub method: String,
    pub request_id: String,
    pub transport_metadata: Arc<Metadata>,
    pub(crate) log_sink: Arc<Mutex<Vec<LogMessage>>>,
}

impl CallContext {
    pub fn client_log(&self, level: LogLevel, message: impl Into<String>) {
        self.log_sink
            .lock()
            .unwrap()
            .push(LogMessage::new(level, message));
    }

    pub fn client_log_with(&self, msg: LogMessage) {
        self.log_sink.lock().unwrap().push(msg);
    }

    pub(crate) fn drain_logs(&self) -> Vec<LogMessage> {
        std::mem::take(&mut *self.log_sink.lock().unwrap())
    }
}

/// A request batch parsed from the wire.
pub struct Request {
    pub method: String,
    pub request_id: String,
    pub batch: RecordBatch,
    pub metadata: Metadata,
}

impl Request {
    pub fn column(&self, name: &str) -> Option<&dyn arrow_array::Array> {
        let idx = self.batch.schema().index_of(name).ok()?;
        Some(self.batch.column(idx).as_ref())
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
pub type UnaryHandler = Arc<
    dyn Fn(&Request, &CallContext) -> Result<Option<RecordBatch>>
        + Send
        + Sync,
>;

/// A handler function for a streaming RPC method.
pub type StreamHandler =
    Arc<dyn Fn(&Request, &CallContext) -> Result<StreamResult> + Send + Sync>;

/// Fluent builder for [`RpcServer`] with describe/identity/version knobs.
#[derive(Default)]
pub struct RpcServerBuilder {
    server_id: Option<String>,
    server_version: Option<String>,
    protocol_name: Option<String>,
    enable_describe: bool,
    dispatch_hook: Option<Arc<dyn crate::hooks::DispatchHook>>,
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

    pub fn enable_describe(mut self, enabled: bool) -> Self {
        self.enable_describe = enabled;
        self
    }

    pub fn with_hook(mut self, hook: Arc<dyn crate::hooks::DispatchHook>) -> Self {
        self.dispatch_hook = Some(hook);
        self
    }

    pub fn build(self) -> RpcServer {
        RpcServer {
            methods: HashMap::new(),
            server_id: self
                .server_id
                .unwrap_or_else(|| crate::util::short_random_id()),
            server_version: self.server_version.unwrap_or_default(),
            protocol_name: self.protocol_name.unwrap_or_default(),
            describe_enabled: self.enable_describe,
            dispatch_hook: self.dispatch_hook,
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
}

impl MethodInfo {
    /// Start building a unary method registration.
    pub fn unary(
        name: impl Into<String>,
        params_schema: SchemaRef,
        result_schema: SchemaRef,
        handler: impl Fn(&Request, &CallContext) -> Result<Option<RecordBatch>>
            + Send
            + Sync
            + 'static,
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
        }
    }

    /// Start building a streaming method registration.
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
        }
    }

    pub fn doc(mut self, s: impl Into<String>) -> Self {
        self.doc = Some(s.into());
        self
    }

    pub fn param_type(mut self, param: impl Into<String>, ty: impl Into<String>) -> Self {
        self.param_types.push((param.into(), ty.into()));
        self
    }

    pub fn param_default(
        mut self,
        param: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
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
    pub(crate) describe_enabled: bool,
    pub(crate) dispatch_hook: Option<Arc<dyn crate::hooks::DispatchHook>>,
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
        handler: impl Fn(&Request, &CallContext) -> Result<Option<RecordBatch>>
            + Send
            + Sync
            + 'static,
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
        let mut names: Vec<_> = self.methods.keys().map(String::as_str).collect();
        names.sort();
        names
    }

    /// Run the serve loop over a single reader/writer pair (pipe or socket).
    pub fn serve<R: Read, W: Write>(&self, mut r: R, mut w: W) {
        loop {
            match self.serve_one(&mut r, &mut w) {
                Ok(keep_going) => {
                    if !keep_going {
                        return;
                    }
                }
                Err(_e) => {
                    return;
                }
            }
        }
    }

    /// Handle one request. Returns `Ok(true)` to continue, `Ok(false)` on EOS/EOF.
    pub fn serve_one<R: Read, W: Write>(&self, r: &mut R, w: &mut W) -> Result<bool> {
        let result = self._serve_one(r, w);
        let _ = w.flush();
        result
    }

    fn _serve_one<R: Read, W: Write>(&self, r: &mut R, w: &mut W) -> Result<bool> {
        let req = match self.read_request(r)? {
            Some(rq) => rq,
            None => return Ok(false),
        };

        let ctx = CallContext {
            server_id: self.server_id.clone(),
            method: req.method.clone(),
            request_id: req.request_id.clone(),
            transport_metadata: Arc::new(req.metadata.clone()),
            log_sink: Arc::new(Mutex::new(Vec::new())),
        };

        let stats = Arc::new(Mutex::new(crate::hooks::CallStatistics::default()));
        // Record the unary request batch as input stats (one row).
        {
            let mut s = stats.lock().unwrap();
            s.input_batches = 1;
            s.input_rows = req.batch.num_rows() as u64;
        }

        // Built-in __describe__ introspection.
        if self.describe_enabled && req.method == crate::introspect::DESCRIBE_METHOD_NAME {
            match crate::introspect::build_describe(
                &self.protocol_name,
                &self.methods,
                &self.server_id,
            ) {
                Ok((batch, md)) => {
                    crate::introspect::write_describe_response(w, &batch, &md)?;
                }
                Err(err) => {
                    write_error_stream(
                        w,
                        &empty_schema(),
                        &err,
                        &self.server_id,
                        &req.request_id,
                    )?;
                }
            }
            return Ok(true);
        }

        let Some(info) = self.methods.get(&req.method) else {
            let mut names = self.method_names();
            names.sort();
            let msg = format!(
                "Unknown method: '{}'. Available methods: {:?}",
                req.method, names
            );
            write_error_stream(
                w,
                &empty_schema(),
                &RpcError::new("AttributeError", msg),
                &self.server_id,
                &req.request_id,
            )?;
            return Ok(true);
        };

        let dispatch_info = crate::hooks::DispatchInfo {
            method: req.method.clone(),
            method_type: match info.method_type {
                MethodType::Unary => "unary",
                _ => "stream",
            },
            server_id: self.server_id.clone(),
            request_id: req.request_id.clone(),
            transport_metadata: Arc::new(req.metadata.clone()),
            principal: String::new(),
            auth_domain: String::new(),
            authenticated: false,
        };
        let hook_token = self
            .dispatch_hook
            .as_ref()
            .map(|h| h.on_dispatch_start(&dispatch_info));

        let mut app_err: Option<RpcError> = None;
        match info.method_type {
            MethodType::Unary => self.serve_unary(w, &req, info, &ctx, &stats, &mut app_err)?,
            MethodType::Producer | MethodType::Exchange | MethodType::Dynamic => {
                self.serve_stream(r, w, &req, info, &ctx, &stats, &mut app_err)?
            }
        }

        if let Some(hook) = self.dispatch_hook.as_ref() {
            let token = hook_token.unwrap_or(0);
            let final_stats = stats.lock().unwrap().clone();
            hook.on_dispatch_end(token, &dispatch_info, app_err.as_ref(), &final_stats);
        }
        Ok(true)
    }

    fn read_request<R: Read>(&self, r: &mut R) -> Result<Option<Request>> {
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
        let ReadBatch { batch, metadata } = match reader.read_next()? {
            Some(rb) => rb,
            None => return Ok(None),
        };
        reader.drain()?;
        let method = md_get(&metadata, RPC_METHOD_KEY).ok_or_else(|| {
            RpcError::protocol_error(
                "Missing 'vgi_rpc.method' in request batch custom_metadata.",
            )
        })?;
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
        if !batch.schema().fields().is_empty() && batch.num_rows() != 1 {
            return Err(RpcError::protocol_error(format!(
                "Expected 1 row in request batch, got {}",
                batch.num_rows()
            )));
        }
        let request_id = md_get(&metadata, REQUEST_ID_KEY).unwrap_or("").to_string();
        Ok(Some(Request {
            method: method.to_string(),
            request_id,
            batch,
            metadata,
        }))
    }

    fn serve_unary<W: Write>(
        &self,
        w: &mut W,
        req: &Request,
        info: &MethodInfo,
        ctx: &CallContext,
        stats: &Arc<Mutex<crate::hooks::CallStatistics>>,
        app_err: &mut Option<RpcError>,
    ) -> Result<()> {
        let result = (info.unary.as_ref().unwrap())(req, ctx);
        let logs = ctx.drain_logs();
        match result {
            Ok(maybe_batch) => {
                let mut sw = StreamWriter::new(w, &info.result_schema)?;
                for log in logs {
                    let md = build_log_metadata(&log, &self.server_id, &req.request_id);
                    sw.write(&empty_batch(&info.result_schema)?, Some(&md))?;
                }
                let out_batch = match maybe_batch {
                    Some(b) => b,
                    None => empty_batch(&info.result_schema)?,
                };
                {
                    let mut s = stats.lock().unwrap();
                    s.output_batches = 1;
                    s.output_rows = out_batch.num_rows() as u64;
                }
                sw.write(&out_batch, None)?;
                sw.finish()?;
            }
            Err(err) => {
                let mut sw = StreamWriter::new(w, &info.result_schema)?;
                for log in logs {
                    let md = build_log_metadata(&log, &self.server_id, &req.request_id);
                    sw.write(&empty_batch(&info.result_schema)?, Some(&md))?;
                }
                let md = build_error_metadata(&err, &self.server_id, &req.request_id);
                sw.write(&empty_batch(&info.result_schema)?, Some(&md))?;
                sw.finish()?;
                *app_err = Some(err);
            }
        }
        Ok(())
    }

    fn serve_stream<R: Read, W: Write>(
        &self,
        r: &mut R,
        w: &mut W,
        req: &Request,
        info: &MethodInfo,
        ctx: &CallContext,
        stats: &Arc<Mutex<crate::hooks::CallStatistics>>,
        app_err: &mut Option<RpcError>,
    ) -> Result<()> {
        let init_result = (info.stream.as_ref().unwrap())(req, ctx);
        let init_logs = ctx.drain_logs();
        let stream = match init_result {
            Ok(s) => s,
            Err(err) => {
                // Init error: write as unary-style error stream.
                let output_schema = info.result_schema.clone();
                let mut sw = StreamWriter::new(w, &output_schema)?;
                for log in init_logs {
                    let md = build_log_metadata(&log, &self.server_id, &req.request_id);
                    sw.write(&empty_batch(&output_schema)?, Some(&md))?;
                }
                let md = build_error_metadata(&err, &self.server_id, &req.request_id);
                sw.write(&empty_batch(&output_schema)?, Some(&md))?;
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

        // Write header as its own IPC stream if present.
        let wrote_header = header.is_some();
        if let Some(header_batch) = header {
            let mut hw = StreamWriter::new(&mut *w, header_batch.schema().as_ref())?;
            for log in &init_logs {
                let md = build_log_metadata(log, &self.server_id, &req.request_id);
                hw.write(&empty_batch(header_batch.schema().as_ref())?, Some(&md))?;
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

        // If we didn't already write init logs into a header stream, write them now.
        if !wrote_header {
            for log in &init_logs {
                let md = build_log_metadata(log, &self.server_id, &req.request_id);
                out_writer.write(&empty_batch(output_schema.as_ref())?, Some(&md))?;
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
            let Some(ReadBatch { batch: input_batch, metadata: input_md }) = read else {
                break;
            };
            {
                let mut s = stats.lock().unwrap();
                s.input_batches += 1;
                s.input_rows += input_batch.num_rows() as u64;
            }

            // Cancellation signal.
            if md_get(&input_md, CANCEL_KEY).is_some() {
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
                            let md = build_error_metadata(&e, &self.server_id, &req.request_id);
                            out_writer
                                .write(&empty_batch(output_schema.as_ref())?, Some(&md))?;
                            break 'lockstep;
                        }
                    }
                }
                _ => input_batch,
            };

            let mut out =
                OutputCollector::new(output_schema.clone(), input_schema.is_none());

            let iter_result = match &mut state {
                StreamStateKind::Producer(p) => p.produce(&mut out, ctx),
                StreamStateKind::Exchange(e) => e.exchange(&casted, &mut out, ctx),
            };

            // Flush any iteration-level logs first (logs appended during produce/exchange).
            let iter_logs = ctx.drain_logs();
            for log in iter_logs {
                let md = build_log_metadata(&log, &self.server_id, &req.request_id);
                out_writer.write(&empty_batch(output_schema.as_ref())?, Some(&md))?;
            }

            if let Err(err) = iter_result {
                let md = build_error_metadata(&err, &self.server_id, &req.request_id);
                out_writer.write(&empty_batch(output_schema.as_ref())?, Some(&md))?;
                *app_err = Some(err);
                break;
            }

            let finished = out.finished();

            // Flush collected emitted items (logs added via OutputCollector, then batches).
            for item in out.items.drain(..) {
                match item {
                    Emitted::Log(log) => {
                        let md = build_log_metadata(&log, &self.server_id, &req.request_id);
                        out_writer.write(&empty_batch(output_schema.as_ref())?, Some(&md))?;
                    }
                    Emitted::Batch { batch, metadata } => {
                        {
                            let mut s = stats.lock().unwrap();
                            s.output_batches += 1;
                            s.output_rows += batch.num_rows() as u64;
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

pub fn cast_batch_public(batch: &RecordBatch, target: &Schema) -> Result<RecordBatch> {
    cast_batch(batch, target)
}

fn cast_batch(batch: &RecordBatch, target: &Schema) -> Result<RecordBatch> {
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
    RecordBatch::try_new(Arc::new(target.clone()), cols).map_err(RpcError::from)
}

fn build_log_metadata(msg: &LogMessage, server_id: &str, request_id: &str) -> Metadata {
    let mut md = vec![
        (LOG_LEVEL_KEY.to_string(), msg.level.as_str().to_string()),
        (LOG_MESSAGE_KEY.to_string(), msg.message.clone()),
    ];
    if !msg.extras.is_empty() {
        md.push((LOG_EXTRA_KEY.to_string(), msg.extras_json()));
    }
    if !server_id.is_empty() {
        md.push((SERVER_ID_KEY.to_string(), server_id.to_string()));
    }
    if !request_id.is_empty() {
        md.push((REQUEST_ID_KEY.to_string(), request_id.to_string()));
    }
    md
}

fn build_error_metadata(err: &RpcError, server_id: &str, request_id: &str) -> Metadata {
    let extra = serde_json::json!({
        "exception_type": err.error_type,
        "exception_message": err.message,
        "traceback": err.traceback,
    })
    .to_string();
    let mut md = vec![
        (LOG_LEVEL_KEY.to_string(), "EXCEPTION".to_string()),
        (LOG_MESSAGE_KEY.to_string(), err.message.clone()),
        (LOG_EXTRA_KEY.to_string(), extra),
    ];
    if !server_id.is_empty() {
        md.push((SERVER_ID_KEY.to_string(), server_id.to_string()));
    }
    if !request_id.is_empty() {
        md.push((REQUEST_ID_KEY.to_string(), request_id.to_string()));
    }
    md
}

/// Write an error as a complete single-batch IPC stream.
pub fn write_error_stream<W: Write>(
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
