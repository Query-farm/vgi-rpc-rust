//! Low-level IPC stream helpers that preserve per-batch custom metadata.
//!
//! The standard `arrow-ipc` `StreamWriter` / `StreamReader` types do not
//! expose per-message `custom_metadata`, but the vgi_rpc wire protocol
//! relies on that field to carry `vgi_rpc.method`,
//! `vgi_rpc.request_version`, log keys, externalisation pointers,
//! state tokens, etc. This module hand-rolls the framing layer so the
//! crate can depend on **stock** arrow-rs from crates.io rather than a
//! patched fork — the published vgi-rpc crate is therefore directly
//! installable without any `[patch.crates-io]` directives downstream.
//!
//! Internally we delegate column encoding / decoding to
//! [`arrow_ipc::writer::IpcDataGenerator`] and the
//! [`arrow_ipc::reader::read_record_batch`] / `read_dictionary`
//! functions, and only intercept the flatbuffer `Message` wrapper to
//! attach / extract `custom_metadata`. That keeps the code small and
//! the on-wire bytes byte-for-byte compatible with arrow-rs's
//! `StreamWriter`.
//!
//! ## DoS guard
//!
//! [`StreamReader::new`] pre-validates the schema-message length prefix
//! against [`MAX_IPC_SCHEMA_BYTES`] *before* allocating; a remote
//! client cannot trigger a multi-gigabyte alloc by sending a crafted
//! 4-byte payload. A per-batch message body is bounded twice: an absurd
//! `bodyLength` is refused outright against [`MAX_IPC_MESSAGE_BYTES`],
//! and what survives that is buffered as the peer actually delivers it
//! rather than on the strength of the claim — so the flatbuffer
//! overshoot the fuzz harness surfaced costs a few MiB and an EOF.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_buffer::Buffer as ArrowBuffer;
use arrow_ipc::reader as ipc_reader;
use arrow_ipc::writer::{write_message, DictionaryTracker, IpcDataGenerator, IpcWriteOptions};
use arrow_ipc::{convert as ipc_convert, root_as_message, MessageHeader};
use arrow_schema::{Schema, SchemaRef};
use flatbuffers::FlatBufferBuilder;

use crate::errors::{Result, RpcError};

/// Per-batch metadata pairs. Order is not preserved across
/// serialisation; that matches Python's `RecordBatch.custom_metadata`
/// semantics.
pub type Metadata = HashMap<String, String>;

/// Look up a key in a [`Metadata`] map, returning the value as `&str`.
#[inline]
pub fn md_get<'a>(md: &'a Metadata, key: &str) -> Option<&'a str> {
    md.get(key).map(String::as_str)
}

/// Maximum permitted size, in bytes, of the schema-message flatbuffer
/// at the head of an IPC stream. Schemas are typically tens to
/// hundreds of bytes; 16 MiB is gracious headroom that still rejects
/// the crafted 4-byte input `[0x1A, 0x2C, 0xF5, 0x2C]` that
/// `fuzz/wire_stream_reader` discovered would OOM the process by
/// claiming a ~720 MB schema. Applies to the *schema* message length
/// prefix on the wire.
pub const MAX_IPC_SCHEMA_BYTES: usize = 16 * 1024 * 1024;

/// Maximum permitted total size of any per-batch IPC message (header
/// flatbuffer + body bytes) — the sanity ceiling that refuses the
/// `bodyLength = 0x4000000100000` overshoot the fuzz harness surfaced.
///
/// This used to be 256 MiB, which also made it a hard limit on
/// *legitimate* payloads: a >2 GiB `large_binary` round-trip is well
/// within what the Python reference accepts, and the
/// `large_payload.echo_binary_over_int32_max` conformance test sends
/// exactly that. Refusing it was a conformance defect, not a defence.
///
/// The ceiling no longer carries the anti-OOM job on its own —
/// `read_message_bytes` grows the body buffer from the bytes that
/// actually arrive (see `BODY_PREALLOC_LIMIT`), so a crafted length
/// costs a few MiB and an EOF rather than the amount it claimed.
/// `u32::MAX` keeps the constant expressible on 32-bit targets, where
/// it saturates to `usize::MAX` and the allocation guard is the only
/// one that can meaningfully apply anyway.
pub const MAX_IPC_MESSAGE_BYTES: usize = u32::MAX as usize;

/// Bytes reserved up front for a message body before any of it has
/// arrived. Beyond this the buffer grows amortised as the peer actually
/// delivers, so a header claiming a petabyte cannot turn a 4-byte frame
/// into a multi-gigabyte allocation.
///
/// Growing rather than pre-sizing also keeps the *read* side out of the
/// trouble [`ChunkedWriter`] fixes on the write side: `impl Read for
/// &UnixStream` calls `recv(2)` with the length unclamped, exactly as
/// its `Write` counterpart calls `send(2)`, so handing it a single
/// >2 GiB spare region would earn the same `EINVAL`. Doubling from here
/// means the largest slice ever offered is about half the body — a
/// 1 GiB read for a 2 GiB message — and never reaches `INT_MAX`.
const BODY_PREALLOC_LIMIT: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

const CONTINUATION_MARKER: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// Largest slice offered to a single underlying `write` call.
///
/// Sits well under `INT_MAX`, which is where the two macOS failure modes
/// live (see [`ChunkedWriter`]). Slicing is free, so the whole cost of
/// the clamp is one extra syscall per gigabyte.
const MAX_WRITE_CHUNK: usize = 1 << 30; // 1 GiB

/// Clamp every `write` to [`MAX_WRITE_CHUNK`] so a large payload
/// survives the syscall underneath.
///
/// Every raw transport writer here is unbuffered on purpose, so one
/// `write` maps onto one `write(2)` / `send(2)`. That syscall is not
/// obliged to accept the whole buffer, and above 2 GiB on macOS it
/// refuses to — in one of two different ways depending on what is
/// underneath:
///
/// * **pipes** return a short count of exactly `INT_MAX` with *no
///   error*, so a writer that trusts the return value silently drops
///   the tail and the peer blocks forever waiting for bytes the Arrow
///   IPC header promised. The symptom is a deadlock, not an exception.
/// * **sockets** (Unix domain and TCP) fail outright with `EINVAL`.
///
/// Both halves are needed. `io::Write::write_all` already loops on the
/// returned count, and `std`'s file-descriptor writer clamps to
/// `INT_MAX` for us — but `impl Write for &UnixStream` and `&TcpStream`
/// do *not* go through it. They call `send(2)` with
/// `cmp::min(buf.len(), wrlen_t::MAX)`, and `wrlen_t` is `usize` on
/// unix, so the length reaches the kernel unclamped and a >2 GiB Arrow
/// IPC body dies with `EINVAL`. Clamping here is what makes the socket
/// transports behave like the pipe ones.
///
/// Deliberately does *not* forward `write_vectored`: the default
/// implementation routes back through `write`, which is where the clamp
/// lives.
struct ChunkedWriter<W: Write> {
    inner: W,
    limit: usize,
}

impl<W: Write> ChunkedWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            limit: MAX_WRITE_CHUNK,
        }
    }

    /// Same behaviour with a smaller clamp, so the chunking can be
    /// exercised without allocating a gigabyte.
    #[cfg(test)]
    fn with_limit(inner: W, limit: usize) -> Self {
        Self { inner, limit }
    }

    fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let end = buf.len().min(self.limit);
        self.inner.write(&buf[..end])
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A streaming IPC writer that supports per-batch custom metadata.
///
/// The byte sequence written for a complete stream is:
///   `SchemaMessage → [DictionaryMessage]* → [RecordBatchMessage]* → EOS(4xFF 0x00)`.
///
/// Each call to [`write`](Self::write) emits one record-batch message
/// (preceded by any newly-needed dictionary messages) with its
/// `custom_metadata` attached at the IPC Message level.
///
/// Every byte the crate puts on a transport passes through here, which
/// is why the `ChunkedWriter` clamp lives at this level rather than in
/// each transport: `serve` takes an arbitrary `W`, so a worker that
/// hands it a raw socket gets the same protection as `serve_unix` does.
pub struct StreamWriter<W: Write> {
    writer: ChunkedWriter<W>,
    schema: SchemaRef,
    opts: IpcWriteOptions,
    data_gen: IpcDataGenerator,
    dict_tracker: DictionaryTracker,
    finished: bool,
    /// Reused across `write` calls so the per-batch metadata repack doesn't
    /// allocate a fresh flatbuffer builder (and its internal vectors) each
    /// time. `reset()` before each use; the buffer's capacity is retained.
    fbb: FlatBufferBuilder<'static>,
}

impl<W: Write> StreamWriter<W> {
    /// Create a new writer and emit the schema message.
    pub fn new(writer: W, schema: &Schema) -> Result<Self> {
        let mut writer = ChunkedWriter::new(writer);
        let opts = IpcWriteOptions::default();
        let data_gen = IpcDataGenerator::default();
        let mut dict_tracker = DictionaryTracker::new(false);
        let encoded =
            data_gen.schema_to_bytes_with_dictionary_tracker(schema, &mut dict_tracker, &opts);
        write_message(&mut writer, encoded, &opts)?;
        Ok(Self {
            writer,
            schema: Arc::new(schema.clone()),
            opts,
            data_gen,
            dict_tracker,
            finished: false,
            fbb: FlatBufferBuilder::new(),
        })
    }

    /// Write one RecordBatch carrying optional `metadata` as the IPC
    /// Message-level `custom_metadata` field. Pass `None` to omit the
    /// field (saves a few bytes per message).
    pub fn write(&mut self, batch: &RecordBatch, metadata: Option<&Metadata>) -> Result<()> {
        if self.finished {
            return Err(RpcError::new("IOError", "writer already finished"));
        }
        let mut ctx = Default::default();
        let (dicts, data) = self
            .data_gen
            .encode(batch, &mut self.dict_tracker, &self.opts, &mut ctx)
            .map_err(RpcError::from)?;
        for d in dicts {
            write_message(&mut self.writer, d, &self.opts).map_err(RpcError::from)?;
        }
        if let Some(md) = metadata.filter(|m| !m.is_empty()) {
            self.fbb.reset();
            repack_record_batch_message_with_metadata(&mut self.fbb, &data.ipc_message, md)?;
            let encoded = arrow_ipc::writer::EncodedData {
                ipc_message: self.fbb.finished_data().to_vec(),
                arrow_data: data.arrow_data,
            };
            write_message(&mut self.writer, encoded, &self.opts).map_err(RpcError::from)?;
        } else {
            write_message(&mut self.writer, data, &self.opts).map_err(RpcError::from)?;
        }
        Ok(())
    }

    /// Return the schema this writer was opened with.
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    /// Write the EOS continuation marker. Idempotent.
    pub fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.writer.write_all(&CONTINUATION_MARKER)?;
        self.writer.write_all(&[0u8; 4])?;
        self.writer.flush()?;
        self.finished = true;
        Ok(())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    pub fn get_mut(&mut self) -> &mut W {
        self.writer.get_mut()
    }
}

impl<W: Write> Drop for StreamWriter<W> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// Rebuild a Message flatbuffer with `custom_metadata` added,
/// preserving the embedded RecordBatch header unchanged.
fn repack_record_batch_message_with_metadata(
    fbb: &mut FlatBufferBuilder<'static>,
    msg_bytes: &[u8],
    metadata: &Metadata,
) -> Result<()> {
    use arrow_ipc::{KeyValue, KeyValueArgs, MessageBuilder, RecordBatchBuilder};

    let msg = root_as_message(msg_bytes)
        .map_err(|e| RpcError::new("IPC", format!("parsing message: {e}")))?;
    let version = msg.version();
    let header_type = msg.header_type();
    let body_length = msg.bodyLength();
    if header_type != MessageHeader::RecordBatch {
        return Err(RpcError::new(
            "IPC",
            format!("repack expected RecordBatch header, got {header_type:?}"),
        ));
    }
    let rb = msg
        .header_as_record_batch()
        .ok_or_else(|| RpcError::new("IPC", "missing RecordBatch header"))?;

    // The caller has already `reset()` the builder. Feed the field-node and
    // buffer descriptors straight from the source flatbuffer vectors via
    // `create_vector_from_iter` — no throwaway `Vec` per batch.
    let src_nodes = rb
        .nodes()
        .ok_or_else(|| RpcError::new("IPC", "RecordBatch missing nodes"))?;
    let nodes_vec = fbb.create_vector_from_iter(src_nodes.iter());

    let src_buffers = rb
        .buffers()
        .ok_or_else(|| RpcError::new("IPC", "RecordBatch missing buffers"))?;
    let buffers_vec = fbb.create_vector_from_iter(src_buffers.iter());

    let variadic_vec = rb
        .variadicBufferCounts()
        .map(|v| fbb.create_vector_from_iter(v.iter()));

    let new_rb = {
        let mut b = RecordBatchBuilder::new(fbb);
        b.add_length(rb.length());
        b.add_nodes(nodes_vec);
        b.add_buffers(buffers_vec);
        if let Some(v) = variadic_vec {
            b.add_variadicBufferCounts(v);
        }
        // Note: we don't carry compression here; the conformance worker
        // does not enable IPC batch compression, so this is safe.
        b.finish()
    };

    // Build custom_metadata vector. Order matches HashMap iteration —
    // not stable, but that matches both upstream arrow-ipc and Python
    // `RecordBatch.custom_metadata` semantics.
    let kvs: Vec<_> = metadata
        .iter()
        .map(|(k, v)| {
            let k_off = fbb.create_string(k);
            let v_off = fbb.create_string(v);
            KeyValue::create(
                fbb,
                &KeyValueArgs {
                    key: Some(k_off),
                    value: Some(v_off),
                },
            )
        })
        .collect();
    let md_vec = fbb.create_vector(&kvs);

    let mut mb = MessageBuilder::new(fbb);
    mb.add_version(version);
    mb.add_header_type(header_type);
    mb.add_header(new_rb.as_union_value());
    mb.add_bodyLength(body_length);
    mb.add_custom_metadata(md_vec);
    let m = mb.finish();
    fbb.finish(m, None);
    Ok(())
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// A streaming IPC reader that surfaces per-message custom metadata.
///
/// [`read_next`](Self::read_next) returns `Some((batch, metadata))`
/// for each RecordBatch message and `None` on end-of-stream.
/// Dictionary and schema messages are consumed transparently.
pub struct StreamReader<R: Read> {
    reader: R,
    schema: SchemaRef,
    dictionaries: HashMap<i64, arrow_array::ArrayRef>,
    finished: bool,
    /// When `Some`, every read batch is rewrapped with this relaxed
    /// schema before being returned to the caller (used by the
    /// conformance worker to accept Python's nullable-flag-lying
    /// `ArrowSerializableDataclass` outputs).
    relaxed_schema: Option<SchemaRef>,
}

impl<R: Read> StreamReader<R> {
    /// Create a new reader and consume the schema message.
    ///
    /// The schema-message length prefix is validated against
    /// [`MAX_IPC_SCHEMA_BYTES`] *before* allocating, so a remote
    /// client cannot trigger a multi-gigabyte alloc by sending a
    /// crafted short payload.
    pub fn new(mut reader: R) -> Result<Self> {
        let msg = read_message_bytes(&mut reader, MAX_IPC_SCHEMA_BYTES)?
            .ok_or_else(|| RpcError::new("IPC", "empty IPC stream (no schema)"))?;
        let msg_fb = root_as_message(&msg.message_bytes)
            .map_err(|e| RpcError::new("IPC", format!("parse schema message: {e}")))?;
        if msg_fb.header_type() != MessageHeader::Schema {
            return Err(RpcError::new(
                "IPC",
                format!("expected Schema, got {:?}", msg_fb.header_type()),
            ));
        }
        let ipc_schema = msg_fb
            .header_as_schema()
            .ok_or_else(|| RpcError::new("IPC", "bad schema header"))?;
        // A legitimate Arrow Schema message always carries a `fields` vector
        // (possibly empty). When it's absent, `fb_to_schema` does
        // `fb.fields().unwrap()` and panics — under cargo-fuzz's `panic=abort`
        // that aborts the process before any `catch_unwind` can intercept.
        // Reject the malformed frame explicitly here. (crates.io arrow tolerates
        // this; the pinned arrow-rs fork the fuzz harness uses does not.)
        if ipc_schema.fields().is_none() {
            return Err(RpcError::new("IPC", "schema message has no fields vector"));
        }
        // `fb_to_schema` still `unwrap()`s other optional members while walking
        // field types; keep the `catch_unwind` net (matching record-batch
        // decode) so any residual panic becomes a clean `RpcError` in normal
        // (panic=unwind) builds rather than escaping the reader.
        let schema = decode_guard("schema message", || ipc_convert::fb_to_schema(ipc_schema))?;
        Ok(Self {
            reader,
            schema: Arc::new(schema),
            dictionaries: HashMap::new(),
            finished: false,
            relaxed_schema: None,
        })
    }

    /// Get the schema of the stream (relaxed schema, if relaxation was
    /// requested).
    pub fn schema(&self) -> SchemaRef {
        self.relaxed_schema
            .clone()
            .unwrap_or_else(|| self.schema.clone())
    }

    /// Promote every field in the stream's schema to `nullable = true`,
    /// recursively (lists, structs, fixed-size lists). Use when a
    /// producer declares a field non-nullable but legitimately sends
    /// nulls — e.g. Python's `ArrowSerializableDataclass` for
    /// `Annotated[T | None, ArrowType(...)]`.
    pub fn relax_nullability(mut self) -> Self {
        self.relaxed_schema = Some(Arc::new(relax_schema_nullability(self.schema.as_ref())));
        self
    }

    /// Read the next record batch, or `None` on end-of-stream.
    /// Returns `(batch, metadata)` where `metadata` carries the IPC
    /// Message-level `custom_metadata` (empty when the producer
    /// omitted the field).
    pub fn read_next(&mut self) -> Result<Option<(RecordBatch, Metadata)>> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let msg = match read_message_bytes(&mut self.reader, MAX_IPC_MESSAGE_BYTES)? {
                Some(m) => m,
                None => {
                    self.finished = true;
                    return Ok(None);
                }
            };
            let msg_fb = root_as_message(&msg.message_bytes)
                .map_err(|e| RpcError::new("IPC", format!("parse message: {e}")))?;
            let version = msg_fb.version();
            match msg_fb.header_type() {
                MessageHeader::DictionaryBatch => {
                    let dict = msg_fb
                        .header_as_dictionary_batch()
                        .ok_or_else(|| RpcError::new("IPC", "bad dictionary header"))?;
                    let body_buf = ArrowBuffer::from_vec(msg.body);
                    // Reject buffer descriptors that point outside the
                    // body *before* handing them to arrow-ipc, which
                    // would otherwise panic on an out-of-bounds slice.
                    if let Some(data) = dict.data() {
                        validate_record_batch_buffers(&data, body_buf.len())?;
                    }
                    // arrow-ipc's decoder still has internal invariants
                    // we don't re-check; `catch_unwind` is the backstop
                    // that turns any residual panic into a clean error.
                    decode_guard("dictionary batch", || {
                        ipc_reader::read_dictionary(
                            &body_buf,
                            dict,
                            self.schema.as_ref(),
                            &mut self.dictionaries,
                            &version,
                        )
                    })?
                    .map_err(RpcError::from)?;
                }
                MessageHeader::RecordBatch => {
                    let rb_fb = msg_fb
                        .header_as_record_batch()
                        .ok_or_else(|| RpcError::new("IPC", "bad record batch header"))?;
                    let body_buf = ArrowBuffer::from_vec(msg.body);
                    validate_record_batch_buffers(&rb_fb, body_buf.len())?;
                    // When relaxation is in effect, feed the relaxed
                    // schema directly to `read_record_batch` so its
                    // validation accepts the legitimate null buffers
                    // a producer (e.g. Python
                    // `ArrowSerializableDataclass`) emits for fields
                    // it declared `nullable=false`.
                    let decode_schema = self
                        .relaxed_schema
                        .clone()
                        .unwrap_or_else(|| self.schema.clone());
                    let batch = decode_guard("record batch", || {
                        ipc_reader::read_record_batch(
                            &body_buf,
                            rb_fb,
                            decode_schema,
                            &self.dictionaries,
                            None,
                            &version,
                        )
                    })?
                    .map_err(RpcError::from)?;
                    let metadata = parse_custom_metadata(&msg_fb);
                    return Ok(Some((batch, metadata)));
                }
                MessageHeader::Schema => {
                    return Err(RpcError::new("IPC", "unexpected schema message mid-stream"));
                }
                MessageHeader::NONE => continue,
                other => {
                    return Err(RpcError::new(
                        "IPC",
                        format!("unsupported message type {other:?}"),
                    ));
                }
            }
        }
    }

    /// Drain and discard any remaining messages.
    pub fn drain(&mut self) -> Result<()> {
        while self.read_next()?.is_some() {}
        Ok(())
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

fn parse_custom_metadata(msg: &arrow_ipc::Message) -> Metadata {
    let Some(md) = msg.custom_metadata() else {
        return Metadata::new();
    };
    // Size the map to the known key count so it doesn't rehash while filling.
    let mut out = Metadata::with_capacity(md.len());
    for kv in md.iter() {
        let k = kv.key().unwrap_or("").to_string();
        let v = kv.value().unwrap_or("").to_string();
        out.insert(k, v);
    }
    out
}

/// Validate that every `(offset, length)` buffer descriptor in an IPC
/// record-batch header references a region wholly inside the message
/// body. arrow-ipc's column decoders index into the body using these
/// descriptors verbatim and will panic (slice out-of-bounds / arithmetic
/// overflow) on a crafted frame whose descriptors are inconsistent with
/// the body it shipped. Catching that here turns a hostile frame into a
/// clean `RpcError` instead of a thread panic.
fn validate_record_batch_buffers(rb: &arrow_ipc::RecordBatch, body_len: usize) -> Result<()> {
    if let Some(buffers) = rb.buffers() {
        for buf in buffers.iter() {
            let offset = buf.offset();
            let length = buf.length();
            if offset < 0 || length < 0 {
                return Err(RpcError::new("IPC", "negative IPC buffer descriptor"));
            }
            let end = (offset as u64)
                .checked_add(length as u64)
                .ok_or_else(|| RpcError::new("IPC", "IPC buffer descriptor overflows"))?;
            if end > body_len as u64 {
                return Err(RpcError::new(
                    "IPC",
                    "IPC buffer descriptor exceeds message body",
                ));
            }
        }
    }
    Ok(())
}

/// Run an arrow-ipc decode call, converting any panic into a clean
/// `RpcError`. The descriptor pre-validation above catches the common
/// crafted-frame cases; this is the defence-in-depth net for any other
/// internal arrow-ipc invariant a hostile frame might trip.
fn decode_guard<T>(what: &str, f: impl FnOnce() -> T) -> Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .map_err(|_| RpcError::new("IPC", format!("panic decoding {what} (malformed frame)")))
}

struct RawMessage {
    message_bytes: Vec<u8>,
    body: Vec<u8>,
}

fn read_exact(r: &mut impl Read, buf: &mut [u8]) -> Result<bool> {
    let mut read = 0;
    while read < buf.len() {
        match r.read(&mut buf[read..]) {
            Ok(0) => {
                if read == 0 {
                    return Ok(false);
                }
                return Err(RpcError::new("IOError", "unexpected EOF in IPC message"));
            }
            Ok(n) => read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

/// Read one IPC message off `r`, capping the header and body at
/// `max_bytes` so a crafted length prefix or flatbuffer
/// `bodyLength` cannot trigger an unbounded allocation.
///
/// The header flatbuffer has to be buffered whole before it can be
/// parsed, so its length prefix is checked against `max_bytes` and
/// allocated outright. The body is not: it is grown from the bytes the
/// peer actually delivers, so the ceiling can be generous enough for a
/// legitimate multi-gigabyte batch without a lying `bodyLength` costing
/// more than [`BODY_PREALLOC_LIMIT`] and an EOF.
fn read_message_bytes(r: &mut impl Read, max_bytes: usize) -> Result<Option<RawMessage>> {
    let mut prefix = [0u8; 4];
    if !read_exact(r, &mut prefix)? {
        return Ok(None);
    }
    let size_bytes = if prefix == CONTINUATION_MARKER {
        let mut sb = [0u8; 4];
        if !read_exact(r, &mut sb)? {
            return Ok(None);
        }
        sb
    } else {
        prefix
    };
    let size = u32::from_le_bytes(size_bytes) as usize;
    if size == 0 {
        // EOS
        return Ok(None);
    }
    if size > max_bytes {
        return Err(RpcError::new(
            "IPC",
            format!(
                "IPC message header length {size} bytes exceeds cap {max_bytes} — \
                 refusing to allocate before parsing"
            ),
        ));
    }
    let mut message_bytes = vec![0u8; size];
    if !read_exact(r, &mut message_bytes)? {
        return Err(RpcError::new("IOError", "unexpected EOF in message body"));
    }
    // Parse just enough to learn the body length, then refuse an absurd
    // claim outright. This blocks the `bodyLength = 1 TB` attack vector
    // even when the header itself is small.
    let msg = root_as_message(&message_bytes)
        .map_err(|e| RpcError::new("IPC", format!("parse message header: {e}")))?;
    let body_length_signed = msg.bodyLength();
    if body_length_signed < 0 {
        return Err(RpcError::new(
            "IPC",
            format!("IPC message has negative bodyLength ({body_length_signed})"),
        ));
    }
    // Compare in u64: on a 32-bit target the claim can exceed anything
    // `usize` can hold, and truncating first would let it wrap under the
    // cap.
    if body_length_signed as u64 > max_bytes as u64 {
        return Err(RpcError::new(
            "IPC",
            format!(
                "IPC message bodyLength {body_length_signed} bytes exceeds cap {max_bytes} — \
                 refusing to allocate before parsing"
            ),
        ));
    }
    let body_length = body_length_signed as usize;
    // Reserve only what a normal batch needs; past that the buffer grows
    // as the bytes arrive, so the peer pays for the size it claimed
    // before we do.
    let mut body = Vec::with_capacity(body_length.min(BODY_PREALLOC_LIMIT));
    if body_length > 0 {
        let read = (&mut *r)
            .take(body_length as u64)
            .read_to_end(&mut body)
            .map_err(RpcError::from)?;
        if read != body_length {
            return Err(RpcError::new("IOError", "unexpected EOF in message body"));
        }
    }
    Ok(Some(RawMessage {
        message_bytes,
        body,
    }))
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Serialize one record batch as a complete IPC stream
/// (schema + batch + EOS), with optional custom metadata on the batch.
pub fn write_one_batch(batch: &RecordBatch, metadata: Option<&Metadata>) -> Result<Vec<u8>> {
    write_one_batch_as(batch, batch.schema().as_ref(), metadata)
}

/// Like [`write_one_batch`] but declares `schema` on the stream instead of
/// the batch's own schema, writing the batch's buffers unchanged.
///
/// [`StreamWriter::write`] never reconciles a batch against the schema its
/// stream was opened with — it encodes the buffers and the reader decodes
/// them under the declared schema. So a batch that differs from its
/// enclosing stream's schema only cosmetically (field nullability,
/// dictionary encoding, schema-level metadata) round-trips invisibly while
/// it stays inline.
///
/// That stops being true the moment the batch is lifted onto a *standalone*
/// stream, as external-location payloads are: the payload declares its own
/// schema, and a peer that validates it against the schema it was promised
/// (the enclosing stream's) sees a hard mismatch over a difference that
/// never mattered before. Passing the enclosing schema here keeps the two
/// delivery routes indistinguishable.
///
/// Deliberately not a cast: the buffers are emitted as-is, so this cannot
/// silently do nothing the way an "equivalent schemas" fast path in a cast
/// helper would, and it cannot change the bytes either.
pub fn write_one_batch_as(
    batch: &RecordBatch,
    schema: &Schema,
    metadata: Option<&Metadata>,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema)?;
        w.write(batch, metadata)?;
        w.finish()?;
    }
    Ok(buf)
}

/// Lowercase hex encoding of a byte slice. Internal helper — use the
/// `hex` crate from your application code.
// Only the http/external/mtls modules call this; unused in a minimal
// (macros-only) wasm build, so suppress the conditional dead-code warning.
#[allow(dead_code)]
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn relax_field_nullability(f: &arrow_schema::Field) -> arrow_schema::Field {
    use arrow_schema::DataType;
    let dt = match f.data_type() {
        DataType::List(inner) => DataType::List(Arc::new(relax_field_nullability(inner))),
        DataType::LargeList(inner) => DataType::LargeList(Arc::new(relax_field_nullability(inner))),
        DataType::FixedSizeList(inner, n) => {
            DataType::FixedSizeList(Arc::new(relax_field_nullability(inner)), *n)
        }
        DataType::Struct(fields) => DataType::Struct(
            fields
                .iter()
                .map(|child| Arc::new(relax_field_nullability(child)))
                .collect(),
        ),
        // Map: leave the entries struct alone (Arrow requires
        // entries/keys to be non-nullable); leaf nullability inside
        // the values child is preserved by the original schema.
        other => other.clone(),
    };
    #[allow(deprecated)]
    let new_field = if let DataType::Dictionary(_, _) = f.data_type() {
        arrow_schema::Field::new_dict(
            f.name(),
            dt,
            true,
            f.dict_id().unwrap_or(0),
            f.dict_is_ordered().unwrap_or(false),
        )
    } else {
        arrow_schema::Field::new(f.name(), dt, true)
    };
    new_field.with_metadata(f.metadata().clone())
}

fn relax_schema_nullability(s: &Schema) -> Schema {
    let new_fields: Vec<arrow_schema::Field> = s
        .fields()
        .iter()
        .map(|f| relax_field_nullability(f))
        .collect();
    Schema::new_with_metadata(new_fields, s.metadata().clone())
}

/// Build a zero-row `RecordBatch` matching the given schema.
pub fn empty_batch(schema: &Schema) -> Result<RecordBatch> {
    use arrow_array::array::new_empty_array;
    use arrow_array::RecordBatchOptions;
    let cols: Vec<arrow_array::ArrayRef> = schema
        .fields()
        .iter()
        .map(|f| new_empty_array(f.data_type()))
        .collect();
    RecordBatch::try_new_with_options(
        Arc::new(schema.clone()),
        cols,
        &RecordBatchOptions::new().with_row_count(Some(0)),
    )
    .map_err(RpcError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{Int64Array, StringArray};
    use arrow_schema::{DataType, Field};

    /// Records what each `write` call was *offered* and honours a
    /// caller-chosen short-count, so both halves of the large-payload
    /// contract can be observed: the clamp and the retry.
    struct SabotageWriter {
        offered: Vec<usize>,
        accept: usize,
        sink: Vec<u8>,
    }

    impl Write for SabotageWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.offered.push(buf.len());
            let n = buf.len().min(self.accept);
            self.sink.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn chunked_writer_clamps_and_retries() {
        // A macOS pipe answers a >2 GiB write with a short count and no
        // error; a macOS socket answers it with EINVAL. Surviving both
        // needs the clamp *and* the loop, so assert both here rather
        // than trusting `write_all` alone.
        let mut w = ChunkedWriter::with_limit(
            SabotageWriter {
                offered: Vec::new(),
                accept: 3,
                sink: Vec::new(),
            },
            8,
        );
        let payload: Vec<u8> = (0..50u8).collect();
        w.write_all(&payload).unwrap();
        let inner = w.get_mut();
        assert!(
            inner.offered.iter().all(|n| *n <= 8),
            "a write was offered more than the clamp: {:?}",
            inner.offered
        );
        assert_eq!(inner.sink, payload, "short writes lost bytes");
    }

    #[test]
    fn write_chunk_stays_under_int_max() {
        // The clamp is only worth anything if it lands below the size at
        // which macOS starts rejecting or truncating.
        assert!(MAX_WRITE_CHUNK < i32::MAX as usize);
    }

    #[test]
    fn oversized_body_claim_costs_nothing_to_refuse() {
        // The ceiling is generous enough for a legitimate multi-gigabyte
        // batch, so the flatbuffer overshoot the fuzzer found has to be
        // refused by the cap and not by a lucky allocation failure.
        assert!(MAX_IPC_MESSAGE_BYTES as u64 > (1u64 << 31) + 1);
        assert!((0x4000000100000u64) > MAX_IPC_MESSAGE_BYTES as u64);
    }

    #[test]
    fn roundtrip_with_metadata() {
        let schema = Schema::new(vec![
            Field::new("idx", DataType::Int64, false),
            Field::new("name", DataType::Utf8, false),
        ]);
        let batch = RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3])) as _,
                Arc::new(StringArray::from(vec!["a", "b", "c"])) as _,
            ],
        )
        .unwrap();

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
            let mut md = Metadata::new();
            md.insert("vgi_rpc.method".into(), "echo_string".into());
            w.write(&batch, Some(&md)).unwrap();
            w.finish().unwrap();
        }

        let mut r = StreamReader::new(buf.as_slice()).unwrap();
        let (rb, md) = r.read_next().unwrap().expect("batch");
        assert_eq!(rb.num_rows(), 3);
        assert_eq!(md_get(&md, "vgi_rpc.method"), Some("echo_string"));
        assert!(r.read_next().unwrap().is_none());
    }

    #[test]
    fn zero_row_metadata_only() {
        let schema = Schema::empty();
        let batch = empty_batch(&schema).unwrap();

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
            let mut md = Metadata::new();
            md.insert("vgi_rpc.log_level".into(), "INFO".into());
            w.write(&batch, Some(&md)).unwrap();
            w.finish().unwrap();
        }
        let mut r = StreamReader::new(buf.as_slice()).unwrap();
        let (rb, md) = r.read_next().unwrap().expect("batch");
        assert_eq!(rb.num_rows(), 0);
        assert_eq!(md_get(&md, "vgi_rpc.log_level"), Some("INFO"));
    }

    #[test]
    fn rejects_oversize_schema_length_prefix() {
        // The 4-byte payload `[0x1A, 0x2C, 0xF5, 0x2C]` parsed LE
        // claims ~720 MB of schema-message body — must be refused
        // before any allocation.
        let bomb: &[u8] = &[0x1A, 0x2C, 0xF5, 0x2C];
        let err = StreamReader::new(bomb).err().expect("must reject");
        assert!(
            err.message.contains("exceeds cap"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_oversize_message_bodylength() {
        // Encode a tiny but well-formed schema then send a record-
        // batch message whose flatbuffer claims a multi-GB
        // `bodyLength` — must be refused before allocating the body.
        use arrow_ipc::{Buffer as FbBuffer, FieldNode, MessageBuilder, RecordBatchBuilder};
        // Build a real schema first so the schema gate passes.
        let schema = Schema::new(vec![Field::new("v", DataType::Int64, false)]);
        let mut buf: Vec<u8> = Vec::new();
        {
            let w = StreamWriter::new(&mut buf, &schema).unwrap();
            // Don't write any batches; we'll append a hand-crafted
            // malicious message below.
            // Drop without finish so EOS is not written.
            std::mem::forget(w);
        }
        // Hand-craft a RecordBatch Message flatbuffer with absurd
        // bodyLength.
        let mut fbb = FlatBufferBuilder::new();
        let nodes_vec = fbb.create_vector(&[FieldNode::new(0, 0)]);
        let buffers_vec = fbb.create_vector(&[FbBuffer::new(0, 0)]);
        let rb_off = {
            let mut b = RecordBatchBuilder::new(&mut fbb);
            b.add_length(0);
            b.add_nodes(nodes_vec);
            b.add_buffers(buffers_vec);
            b.finish()
        };
        let msg_off = {
            let mut mb = MessageBuilder::new(&mut fbb);
            mb.add_version(arrow_ipc::MetadataVersion::V5);
            mb.add_header_type(MessageHeader::RecordBatch);
            mb.add_header(rb_off.as_union_value());
            mb.add_bodyLength(MAX_IPC_MESSAGE_BYTES as i64 + 1);
            mb.finish()
        };
        fbb.finish(msg_off, None);
        let msg_bytes = fbb.finished_data();
        // Frame: continuation + 4-byte LE length + flatbuffer body.
        buf.extend_from_slice(&CONTINUATION_MARKER);
        buf.extend_from_slice(&(msg_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(msg_bytes);
        // No body — but we never get that far; the cap rejects first.

        let mut r = StreamReader::new(buf.as_slice()).unwrap();
        let err = r.read_next().expect_err("must reject");
        assert!(
            err.message.contains("bodyLength") && err.message.contains("exceeds cap"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn malformed_schema_message_is_error_not_panic() {
        // Regression for a fuzz-found crash: a structurally-parseable but
        // malformed Schema message made arrow-ipc's `fb_to_schema` panic
        // (`Option::unwrap()` on `None` in convert.rs) out of `StreamReader::new`
        // — aborting the process instead of returning a clean error. The
        // schema parse must now be caught like the per-batch decode.
        // `crash-cea0477693563377f77c693ca8d3df51ee421811` from
        // `fuzz/wire_stream_reader`.
        let crash: &[u8] = &[
            22, 0, 0, 0, 12, 0, 0, 0, 0, 0, 8, 0, 4, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 134,
        ];
        // Must not panic; either an Err here or a clean reader is acceptable —
        // the contract is "no unwind escapes".
        let _ = StreamReader::new(crash);
    }

    #[test]
    fn rejects_buffer_descriptor_past_body() {
        // A record-batch message whose body is 8 bytes but whose buffer
        // descriptor claims offset 0 / length 1000. arrow-ipc would
        // index out of bounds and panic; the descriptor pre-check must
        // reject it as a clean `RpcError` first.
        use arrow_ipc::{Buffer as FbBuffer, FieldNode, MessageBuilder, RecordBatchBuilder};
        let schema = Schema::new(vec![Field::new("v", DataType::Int64, false)]);
        let mut buf: Vec<u8> = Vec::new();
        {
            let w = StreamWriter::new(&mut buf, &schema).unwrap();
            std::mem::forget(w);
        }
        let mut fbb = FlatBufferBuilder::new();
        let nodes_vec = fbb.create_vector(&[FieldNode::new(1, 0)]);
        // offset 0, length 1000 — far past the 8-byte body below.
        let buffers_vec = fbb.create_vector(&[FbBuffer::new(0, 1000)]);
        let rb_off = {
            let mut b = RecordBatchBuilder::new(&mut fbb);
            b.add_length(1);
            b.add_nodes(nodes_vec);
            b.add_buffers(buffers_vec);
            b.finish()
        };
        let msg_off = {
            let mut mb = MessageBuilder::new(&mut fbb);
            mb.add_version(arrow_ipc::MetadataVersion::V5);
            mb.add_header_type(MessageHeader::RecordBatch);
            mb.add_header(rb_off.as_union_value());
            mb.add_bodyLength(8);
            mb.finish()
        };
        fbb.finish(msg_off, None);
        let msg_bytes = fbb.finished_data().to_vec();
        buf.extend_from_slice(&CONTINUATION_MARKER);
        buf.extend_from_slice(&(msg_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&msg_bytes);
        buf.extend_from_slice(&[0u8; 8]); // the 8-byte body

        let mut r = StreamReader::new(buf.as_slice()).unwrap();
        let err = r.read_next().expect_err("must reject");
        assert!(
            err.message.contains("buffer descriptor"),
            "unexpected error: {err:?}"
        );
    }
}
