//! The blocking [`RpcClient`] over byte-stream transports (subprocess / unix /
//! pipe / shm) plus its lockstep [`StreamSession`].

use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::Schema;

use vgi_rpc::errors::{Result, RpcError};
use vgi_rpc::introspect::DESCRIBE_METHOD_NAME;
use vgi_rpc::log::LogMessage;
use vgi_rpc::metadata::{CANCEL_KEY, TRANSPORT_SHM_KEY};
use vgi_rpc::transport_options::TRANSPORT_OPTIONS_METHOD_NAME;
use vgi_rpc::wire::{empty_batch, md_get, Metadata, StreamReader, StreamWriter};

use crate::envelope::{classify, BatchKind};
use crate::introspect::{empty_schema, parse_describe_batch, ServiceDescription};
use crate::request::{build_request_metadata, generate_request_id};
use crate::transport::{RpcDeadline, Transport};

struct DeadlineTurn(Option<RpcDeadline>);

impl DeadlineTurn {
    fn start(deadline: Option<RpcDeadline>) -> Result<Self> {
        if let Some(deadline) = &deadline {
            deadline.start()?;
        }
        Ok(Self(deadline))
    }
}

impl Drop for DeadlineTurn {
    fn drop(&mut self) {
        if let Some(deadline) = &self.0 {
            deadline.finish();
        }
    }
}

/// Callback invoked for each out-of-band log message received during a call.
pub type OnLog = Box<dyn FnMut(LogMessage) + Send>;

/// Handle to the optional shared-memory side-channel. Carries an
/// [`Arc<ShmSegment>`](vgi_rpc::shm::ShmSegment) under the `shm` feature, and
/// is a zero-sized `Option<()>` otherwise so the byte-stream paths compile
/// uniformly without `#[cfg]` at every call site.
#[cfg(feature = "shm")]
type ShmHandle = Option<Arc<vgi_rpc::shm::ShmSegment>>;
#[cfg(not(feature = "shm"))]
type ShmHandle = Option<()>;

/// Merge the shm-segment advertisement keys into request metadata when a
/// segment is present (so the server may use shm for its output batches).
fn shm_request_md(shm: &ShmHandle, base: Option<&Metadata>) -> Option<Metadata> {
    #[cfg(feature = "shm")]
    if let Some(seg) = shm.as_deref() {
        let mut md = base.cloned().unwrap_or_default();
        md.insert(
            vgi_rpc::metadata::SHM_SEGMENT_NAME_KEY.to_string(),
            // Advertise the BARE name (no leading `/`): the cross-language
            // convention. Python's SharedMemory prepends `/`, and the Rust
            // server's attach normalizes a missing leading slash. Sending the
            // slash would make Python open `//vgi_rpc_...` → FileNotFound.
            seg.name().trim_start_matches('/').to_string(),
        );
        md.insert(
            vgi_rpc::metadata::SHM_SEGMENT_SIZE_KEY.to_string(),
            seg.size().to_string(),
        );
        return Some(md);
    }
    let _ = shm;
    base.cloned()
}

/// Resolve an inbound shm pointer batch. Copied dictionary payloads are freed
/// here; zero-copy payloads release their slot when the last Arrow buffer is
/// dropped (no-op without the `shm` feature or segment).
fn shm_resolve_inbound(
    batch: RecordBatch,
    md: Metadata,
    shm: &ShmHandle,
) -> Result<(RecordBatch, Metadata)> {
    #[cfg(feature = "shm")]
    if let Some(seg) = shm.as_deref() {
        let r = vgi_rpc::shm::resolve_shm_batch(batch, md, Some(seg))?;
        if let Some(off) = r.release_offset {
            let _ = seg.free(off);
        }
        return Ok((r.batch, r.metadata));
    }
    let _ = shm;
    Ok((batch, md))
}

/// The kind of stream a [`StreamSession`] drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Producer: the client `tick`s, the server emits.
    Producer,
    /// Exchange: bidirectional lockstep.
    Exchange,
}

/// Transport capabilities reported by `__transport_options__`.
#[derive(Debug, Clone, Default)]
pub struct ClientTransportOptions {
    /// Whether the worker advertises the shared-memory side-channel.
    pub shm: bool,
    /// All `vgi_rpc.transport.*` response metadata, verbatim.
    pub raw: Metadata,
}

/// A blocking RPC client over a byte-stream transport.
///
/// The client is *dynamic* and schema-first: callers build the params
/// `RecordBatch` (params-as-columns, one row) and receive the result batch,
/// mirroring the schema-driven Python client and the Rust server's model.
pub struct RpcClient {
    transport: Box<dyn Transport>,
    on_log: Option<OnLog>,
    protocol_version: Option<String>,
    relax_nullability: bool,
    shm: ShmHandle,
}

impl RpcClient {
    /// Wrap an already-constructed transport.
    pub fn from_transport(transport: Box<dyn Transport>) -> Self {
        Self {
            transport,
            on_log: None,
            protocol_version: None,
            relax_nullability: false,
            shm: None,
        }
    }

    /// Spawn `cmd` as a worker subprocess and talk over its stdin/stdout.
    pub fn connect(cmd: &[impl AsRef<std::ffi::OsStr>]) -> Result<Self> {
        let t = crate::transport::SubprocessTransport::spawn(cmd)?;
        Ok(Self::from_transport(Box::new(t)))
    }

    /// Spawn a subprocess with a monotonic response/read timeout per RPC.
    ///
    /// A timeout kills, reaps, and poisons the subprocess connection so late
    /// response bytes can never desynchronize a later call. Unix terminates
    /// the worker's private process group; other platforms terminate the
    /// direct child and bound the reader join, detaching it if a descendant
    /// retained stdout. Anonymous-pipe writes themselves are not interruptible
    /// by `std`; see
    /// [`crate::transport::SubprocessTransport::spawn_with_stderr_and_timeout`].
    pub fn connect_with_timeout(
        cmd: &[impl AsRef<std::ffi::OsStr>],
        rpc_timeout: Option<std::time::Duration>,
    ) -> Result<Self> {
        let t = crate::transport::SubprocessTransport::spawn_with_stderr_and_timeout(
            cmd,
            crate::transport::StderrMode::default(),
            rpc_timeout,
        )?;
        Ok(Self::from_transport(Box::new(t)))
    }

    /// Connect to a worker listening on an AF_UNIX socket.
    #[cfg(unix)]
    pub fn unix_connect(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let t = crate::transport::UnixTransport::connect(path)?;
        Ok(Self::from_transport(Box::new(t)))
    }

    /// Connect to a worker listening on a TCP socket at `host:port`.
    ///
    /// Raw TCP carries no authentication or encryption; connect only to
    /// workers on a trusted network. Use the HTTP transport for untrusted
    /// peers.
    pub fn tcp_connect(host: &str, port: u16) -> Result<Self> {
        let t = crate::transport::TcpTransport::connect(host, port)?;
        Ok(Self::from_transport(Box::new(t)))
    }

    /// Connect to a TCP socket with a per-read timeout (recommended for
    /// untrusted peers — a stalled peer then ends the call with a
    /// `TransportError` instead of hanging the thread).
    pub fn tcp_connect_with_timeout(
        host: &str,
        port: u16,
        read_timeout: Option<std::time::Duration>,
    ) -> Result<Self> {
        let t = crate::transport::TcpTransport::connect_with_timeout(host, port, read_timeout)?;
        Ok(Self::from_transport(Box::new(t)))
    }

    /// Connect to a TCP worker through a strict SOCKS5h proxy. The worker
    /// hostname is resolved by the proxy and proxy failure never falls back
    /// to a direct TCP connection.
    pub fn tcp_connect_socks5h(
        proxy: crate::transport::Socks5hProxy,
        host: &str,
        port: u16,
        connect_timeout: std::time::Duration,
        read_timeout: Option<std::time::Duration>,
    ) -> Result<Self> {
        let transport = crate::transport::TcpTransport::connect_socks5h(
            proxy,
            host,
            port,
            connect_timeout,
            read_timeout,
        )?;
        Ok(Self::from_transport(Box::new(transport)))
    }

    /// Connect to a unix socket with a per-read timeout (recommended for
    /// untrusted peers — a stalled peer then ends the call with a
    /// `TransportError` instead of hanging the thread).
    ///
    /// Subprocess response reads use a deadline-aware pipe adapter configured
    /// by [`Self::connect_with_timeout`]. Anonymous-pipe writes remain a
    /// trusted-peer boundary because `std` cannot interrupt a blocked write.
    #[cfg(unix)]
    pub fn unix_connect_with_timeout(
        path: impl AsRef<std::path::Path>,
        read_timeout: Option<std::time::Duration>,
    ) -> Result<Self> {
        let t = crate::transport::UnixTransport::connect_with_timeout(path, read_timeout)?;
        Ok(Self::from_transport(Box::new(t)))
    }

    /// Spawn a worker subprocess and attach a POSIX shared-memory side-channel
    /// of `seg_size` bytes. The segment is advertised on every request so the
    /// server may return large batches through shm; the client resolves the
    /// resulting pointer batches transparently. Trusted-peer only.
    #[cfg(feature = "shm")]
    pub fn shm_connect(cmd: &[impl AsRef<std::ffi::OsStr>], seg_size: usize) -> Result<Self> {
        let seg = Arc::new(vgi_rpc::shm::ShmSegment::create(seg_size)?);
        let t = crate::transport::SubprocessTransport::spawn(cmd)?;
        let mut c = Self::from_transport(Box::new(t));
        c.shm = Some(seg);
        Ok(c)
    }

    /// Install a log callback (consumes & returns self, builder-style).
    pub fn on_log(mut self, f: OnLog) -> Self {
        self.on_log = Some(f);
        self
    }

    /// Send `vgi_rpc.protocol_version` on every request.
    pub fn protocol_version(mut self, v: impl Into<String>) -> Self {
        self.protocol_version = Some(v.into());
        self
    }

    /// Promote response schemas to fully-nullable on read (needed for Python
    /// servers that declare non-nullable fields but legitimately send nulls).
    pub fn relax_nullability(mut self, yes: bool) -> Self {
        self.relax_nullability = yes;
        self
    }

    /// Close the underlying transport.
    pub fn close(mut self) -> Result<()> {
        self.transport.close()
    }

    /// Whether the byte stream remains synchronized for another RPC.
    pub fn is_reusable(&self) -> bool {
        self.transport.is_reusable()
    }

    /// Make a unary call: send `params` (one row), return the result batch.
    pub fn call_unary(
        &mut self,
        method: &str,
        params: &RecordBatch,
        metadata: Option<&Metadata>,
    ) -> Result<(RecordBatch, Metadata)> {
        let _deadline = DeadlineTurn::start(self.transport.rpc_deadline())?;
        let req_id = generate_request_id();
        // Advertise the shm segment (when present) so the server may return
        // large result batches through shared memory. Inputs are sent inline:
        // the server resolves shm only for stream input and writes shm only for
        // output, so the client never writes request params to shm.
        let shm_md = shm_request_md(&self.shm, metadata);
        let req_md = build_request_metadata(
            method,
            &req_id,
            self.protocol_version.as_deref(),
            shm_md.as_ref().or(metadata),
        );
        let relax = self.relax_nullability;
        let on_log = &mut self.on_log;
        let shm = &self.shm;
        let (r, w) = self.transport.split();

        // Phase 1: write the request as one complete IPC stream.
        {
            let mut sw = StreamWriter::new(&mut *w, params.schema().as_ref())?;
            sw.write(params, Some(&req_md))?;
            sw.finish()?;
        }

        // Phase 2: read the response stream, dispatching logs, until the
        // single data batch (or an error envelope).
        let mut reader = StreamReader::new(&mut *r)?;
        if relax {
            reader = reader.relax_nullability();
        }
        let mut result: Option<(RecordBatch, Metadata)> = None;
        while let Some((batch, md)) = reader.read_next()? {
            match classify(&batch, &md) {
                BatchKind::Log(m) => dispatch_log(on_log, m),
                BatchKind::Exception(e) => {
                    let _ = reader.drain();
                    return Err(e);
                }
                BatchKind::Data => {
                    if result.is_none() {
                        // Resolve a shm pointer (no-op when not shm).
                        result = Some(shm_resolve_inbound(batch, md, shm)?);
                    }
                }
            }
        }
        result.ok_or_else(|| RpcError::new("TransportError", "no result batch in response"))
    }

    /// Open a producer stream.
    pub fn open_producer(
        &mut self,
        method: &str,
        params: &RecordBatch,
        metadata: Option<&Metadata>,
        has_header: bool,
    ) -> Result<StreamSession<'_>> {
        self.open_stream(method, params, metadata, has_header, StreamKind::Producer)
    }

    /// Open an exchange stream.
    pub fn open_exchange(
        &mut self,
        method: &str,
        params: &RecordBatch,
        metadata: Option<&Metadata>,
        has_header: bool,
    ) -> Result<StreamSession<'_>> {
        self.open_stream(method, params, metadata, has_header, StreamKind::Exchange)
    }

    fn open_stream(
        &mut self,
        method: &str,
        params: &RecordBatch,
        metadata: Option<&Metadata>,
        has_header: bool,
        kind: StreamKind,
    ) -> Result<StreamSession<'_>> {
        let deadline = self.transport.rpc_deadline();
        let _deadline_turn = DeadlineTurn::start(deadline.clone())?;
        let req_id = generate_request_id();
        let shm_md = shm_request_md(&self.shm, metadata);
        let req_md = build_request_metadata(
            method,
            &req_id,
            self.protocol_version.as_deref(),
            shm_md.as_ref().or(metadata),
        );
        let relax = self.relax_nullability;
        let shm = self.shm.clone();
        let on_log = &mut self.on_log;
        let (r, w) = self.transport.split();

        // Phase 1: write the request params stream.
        {
            let mut sw = StreamWriter::new(&mut *w, params.schema().as_ref())?;
            sw.write(params, Some(&req_md))?;
            sw.finish()?;
        }

        // Phase 2a: read the header sub-stream first when the method declares
        // one (the server writes it before the output schema).
        let header = if has_header {
            match read_substream(&mut *r, on_log, relax)? {
                Some((b, m)) => Some(shm_resolve_inbound(b, m, &shm)?),
                None => None,
            }
        } else {
            None
        };

        // Phase 2b: do NOT open the output reader yet. Servers differ in
        // ordering — the Rust server writes the output schema before reading
        // input, but the Python server reads the input schema *first*. Opening
        // the output reader eagerly would deadlock against the latter. Defer it
        // until after the first input batch is written (matching the canonical
        // Python client), which is compatible with both orderings.
        Ok(StreamSession {
            reader_raw: Some(r),
            out_reader: None,
            writer_raw: Some(w),
            in_writer: None,
            on_log,
            header,
            kind,
            relax,
            shm,
            cancelled: false,
            finished: false,
            closed: false,
            deadline,
        })
    }

    /// Fetch the service description via `__describe__`.
    pub fn describe(&mut self) -> Result<ServiceDescription> {
        let params = empty_batch(empty_schema().as_ref())?;
        let (batch, md) = self.call_unary(DESCRIBE_METHOD_NAME, &params, None)?;
        parse_describe_batch(&batch, &md)
    }

    /// Perform the `__transport_options__` capability handshake.
    pub fn transport_options(&mut self) -> Result<ClientTransportOptions> {
        let params = empty_batch(empty_schema().as_ref())?;
        let (_batch, md) = self.call_unary(TRANSPORT_OPTIONS_METHOD_NAME, &params, None)?;
        Ok(ClientTransportOptions {
            shm: md_get(&md, TRANSPORT_SHM_KEY) == Some("true"),
            raw: md,
        })
    }
}

#[inline]
fn dispatch_log(on_log: &mut Option<OnLog>, m: LogMessage) {
    if let Some(cb) = on_log.as_mut() {
        cb(m);
    }
}

/// Read one complete sub-stream (schema + logs + at most one data batch + EOS),
/// dispatching logs. Returns the first data batch, if any.
fn read_substream(
    r: &mut dyn std::io::Read,
    on_log: &mut Option<OnLog>,
    relax: bool,
) -> Result<Option<(RecordBatch, Metadata)>> {
    let mut reader = StreamReader::new(r)?;
    if relax {
        reader = reader.relax_nullability();
    }
    let mut data = None;
    while let Some((batch, md)) = reader.read_next()? {
        match classify(&batch, &md) {
            BatchKind::Log(m) => dispatch_log(on_log, m),
            BatchKind::Exception(e) => {
                let _ = reader.drain();
                return Err(e);
            }
            BatchKind::Data => {
                if data.is_none() {
                    data = Some((batch, md));
                }
            }
        }
    }
    Ok(data)
}

/// A lockstep stream over a byte-stream transport.
///
/// Holds the output reader and (lazily) the input writer as disjoint borrows
/// of the owning [`RpcClient`]'s transport.
pub struct StreamSession<'c> {
    reader_raw: Option<&'c mut dyn std::io::Read>,
    out_reader: Option<StreamReader<&'c mut dyn std::io::Read>>,
    writer_raw: Option<&'c mut dyn std::io::Write>,
    in_writer: Option<StreamWriter<&'c mut dyn std::io::Write>>,
    on_log: &'c mut Option<OnLog>,
    header: Option<(RecordBatch, Metadata)>,
    kind: StreamKind,
    relax: bool,
    shm: ShmHandle,
    cancelled: bool,
    finished: bool,
    closed: bool,
    deadline: Option<RpcDeadline>,
}

impl StreamSession<'_> {
    /// The stream's header batch + metadata, if the method declared one.
    pub fn header(&self) -> Option<&(RecordBatch, Metadata)> {
        self.header.as_ref()
    }

    /// The kind of stream (producer / exchange).
    pub fn kind(&self) -> StreamKind {
        self.kind
    }

    /// Whether the server has signalled end-of-stream.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    fn ensure_input_writer(&mut self, schema: &Schema) -> Result<()> {
        if self.in_writer.is_none() {
            let raw = self
                .writer_raw
                .take()
                .ok_or_else(|| RpcError::new("TransportError", "input writer unavailable"))?;
            self.in_writer = Some(StreamWriter::new(raw, schema)?);
        }
        Ok(())
    }

    /// Open the output reader lazily — only after the first input has been
    /// written, so we never block on the output schema before the server has
    /// read our input schema (the Python server reads input first).
    fn ensure_output_reader(&mut self) -> Result<()> {
        if self.out_reader.is_none() {
            let raw = self
                .reader_raw
                .take()
                .ok_or_else(|| RpcError::new("TransportError", "output reader unavailable"))?;
            let mut rd = StreamReader::new(raw)?;
            if self.relax {
                rd = rd.relax_nullability();
            }
            self.out_reader = Some(rd);
        }
        Ok(())
    }

    /// Producer step: send a tick, return the next emitted batch, or `None`
    /// at end-of-stream.
    pub fn tick(&mut self) -> Result<Option<(RecordBatch, Metadata)>> {
        self.tick_with_metadata(None)
    }

    /// Producer step with application custom metadata attached to the tick.
    pub fn tick_with_metadata(
        &mut self,
        metadata: Option<&Metadata>,
    ) -> Result<Option<(RecordBatch, Metadata)>> {
        if self.cancelled || self.closed {
            return Err(RpcError::protocol_error("tick after close/cancel"));
        }
        if self.finished {
            return Ok(None);
        }
        let _deadline = DeadlineTurn::start(self.deadline.clone())?;
        let tick_schema = Schema::empty();
        self.ensure_input_writer(&tick_schema)?;
        let batch = empty_batch(&tick_schema)?;
        {
            let w = self.in_writer.as_mut().unwrap();
            w.write(&batch, metadata)?;
            w.flush()?;
        }
        self.ensure_output_reader()?;
        self.read_next_data()
    }

    /// Exchange step: send `input`, return the server's response batch.
    pub fn exchange(
        &mut self,
        input: &RecordBatch,
        metadata: Option<&Metadata>,
    ) -> Result<Option<(RecordBatch, Metadata)>> {
        if self.cancelled || self.closed {
            return Err(RpcError::protocol_error("exchange after close/cancel"));
        }
        if self.finished {
            return Ok(None);
        }
        let _deadline = DeadlineTurn::start(self.deadline.clone())?;
        // Inputs are sent inline; the server resolves shm only for output.
        self.ensure_input_writer(input.schema().as_ref())?;
        {
            let w = self.in_writer.as_mut().unwrap();
            w.write(input, metadata)?;
            w.flush()?;
        }
        self.ensure_output_reader()?;
        self.read_next_data()
    }

    fn read_next_data(&mut self) -> Result<Option<(RecordBatch, Metadata)>> {
        let reader = self
            .out_reader
            .as_mut()
            .ok_or_else(|| RpcError::new("TransportError", "output reader not open"))?;
        loop {
            match reader.read_next()? {
                None => {
                    self.finished = true;
                    return Ok(None);
                }
                Some((batch, md)) => match classify(&batch, &md) {
                    BatchKind::Log(m) => dispatch_log(self.on_log, m),
                    BatchKind::Exception(e) => {
                        self.finished = true;
                        let _ = reader.drain();
                        return Err(e);
                    }
                    // Resolve a shm pointer (no-op when not shm).
                    BatchKind::Data => return shm_resolve_inbound(batch, md, &self.shm).map(Some),
                },
            }
        }
    }

    /// Cancel the stream: send a cancel sentinel, then drain output. Idempotent.
    pub fn cancel(&mut self) -> Result<()> {
        if self.cancelled || self.finished {
            self.cancelled = true;
            return Ok(());
        }
        let _deadline = DeadlineTurn::start(self.deadline.clone())?;
        let schema = self
            .in_writer
            .as_ref()
            .map(|w| w.schema())
            .unwrap_or_else(|| Arc::new(Schema::empty()));
        self.ensure_input_writer(schema.as_ref())?;
        let batch = empty_batch(schema.as_ref())?;
        let mut md = Metadata::new();
        md.insert(CANCEL_KEY.to_string(), "1".to_string());
        {
            let w = self.in_writer.as_mut().unwrap();
            w.write(&batch, Some(&md))?;
            w.flush()?;
        }
        self.cancelled = true;
        if self.ensure_output_reader().is_ok() {
            if let Some(rd) = self.out_reader.as_mut() {
                let _ = rd.drain();
            }
        }
        Ok(())
    }

    /// Close the stream cleanly: signal input EOS, drain output. Idempotent.
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if self.cancelled {
            return Ok(());
        }
        let _deadline = DeadlineTurn::start(self.deadline.clone())?;
        // Finish the input writer (or open+finish an empty one) so the server
        // sees EOS and stops, then drain any trailing output.
        if let Some(mut w) = self.in_writer.take() {
            let _ = w.finish();
        } else if let Some(raw) = self.writer_raw.take() {
            if let Ok(mut w) = StreamWriter::new(raw, &Schema::empty()) {
                let _ = w.finish();
            }
        }
        if self.ensure_output_reader().is_ok() {
            if let Some(rd) = self.out_reader.as_mut() {
                let _ = rd.drain();
            }
        }
        Ok(())
    }
}

impl Drop for StreamSession<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
