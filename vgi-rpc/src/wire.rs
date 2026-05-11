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
//! 4-byte payload. Each subsequent message body is also bounded by
//! [`MAX_IPC_MESSAGE_BYTES`] before we allocate, mitigating the
//! flatbuffer-`bodyLength` overshoot that the fuzz harness surfaced.

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
/// flatbuffer + body bytes). Default 256 MiB — large enough for any
/// reasonable Arrow batch, small enough to refuse the
/// `bodyLength = 0x4000000100000` overshoot the fuzz harness
/// surfaced.
pub const MAX_IPC_MESSAGE_BYTES: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

const CONTINUATION_MARKER: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// A streaming IPC writer that supports per-batch custom metadata.
///
/// The byte sequence written for a complete stream is:
///   `SchemaMessage → [DictionaryMessage]* → [RecordBatchMessage]* → EOS(4xFF 0x00)`.
///
/// Each call to [`write`](Self::write) emits one record-batch message
/// (preceded by any newly-needed dictionary messages) with its
/// `custom_metadata` attached at the IPC Message level.
pub struct StreamWriter<W: Write> {
    writer: W,
    schema: SchemaRef,
    opts: IpcWriteOptions,
    data_gen: IpcDataGenerator,
    dict_tracker: DictionaryTracker,
    finished: bool,
}

impl<W: Write> StreamWriter<W> {
    /// Create a new writer and emit the schema message.
    pub fn new(mut writer: W, schema: &Schema) -> Result<Self> {
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
            let new_msg = repack_record_batch_message_with_metadata(&data.ipc_message, md)?;
            let encoded = arrow_ipc::writer::EncodedData {
                ipc_message: new_msg,
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
        &mut self.writer
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
    msg_bytes: &[u8],
    metadata: &Metadata,
) -> Result<Vec<u8>> {
    use arrow_ipc::{
        Buffer as FbBuffer, FieldNode, KeyValue, KeyValueArgs, MessageBuilder, RecordBatchBuilder,
    };

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

    let mut fbb = FlatBufferBuilder::new();

    let src_nodes = rb
        .nodes()
        .ok_or_else(|| RpcError::new("IPC", "RecordBatch missing nodes"))?;
    let nodes: Vec<FieldNode> = src_nodes.iter().copied().collect();
    let nodes_vec = fbb.create_vector(&nodes);

    let src_buffers = rb
        .buffers()
        .ok_or_else(|| RpcError::new("IPC", "RecordBatch missing buffers"))?;
    let buffers: Vec<FbBuffer> = src_buffers.iter().copied().collect();
    let buffers_vec = fbb.create_vector(&buffers);

    let variadic_vec = rb.variadicBufferCounts().map(|v| {
        let counts: Vec<i64> = v.iter().collect();
        fbb.create_vector(&counts)
    });

    let new_rb = {
        let mut b = RecordBatchBuilder::new(&mut fbb);
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
                &mut fbb,
                &KeyValueArgs {
                    key: Some(k_off),
                    value: Some(v_off),
                },
            )
        })
        .collect();
    let md_vec = fbb.create_vector(&kvs);

    let mut mb = MessageBuilder::new(&mut fbb);
    mb.add_version(version);
    mb.add_header_type(header_type);
    mb.add_header(new_rb.as_union_value());
    mb.add_bodyLength(body_length);
    mb.add_custom_metadata(md_vec);
    let m = mb.finish();
    fbb.finish(m, None);
    Ok(fbb.finished_data().to_vec())
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
        let schema = ipc_convert::fb_to_schema(ipc_schema);
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
                    ipc_reader::read_dictionary(
                        &body_buf,
                        dict,
                        self.schema.as_ref(),
                        &mut self.dictionaries,
                        &version,
                    )
                    .map_err(RpcError::from)?;
                }
                MessageHeader::RecordBatch => {
                    let rb_fb = msg_fb
                        .header_as_record_batch()
                        .ok_or_else(|| RpcError::new("IPC", "bad record batch header"))?;
                    let body_buf = ArrowBuffer::from_vec(msg.body);
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
                    let batch = ipc_reader::read_record_batch(
                        &body_buf,
                        rb_fb,
                        decode_schema,
                        &self.dictionaries,
                        None,
                        &version,
                    )
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
    let mut out = Metadata::new();
    if let Some(md) = msg.custom_metadata() {
        for kv in md.iter() {
            let k = kv.key().unwrap_or("").to_string();
            let v = kv.value().unwrap_or("").to_string();
            out.insert(k, v);
        }
    }
    out
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
    // Parse just enough to learn the body length, then cap it the same
    // way before allocating. This blocks the `bodyLength = 1 TB`
    // attack vector even when the header itself is small.
    let msg = root_as_message(&message_bytes)
        .map_err(|e| RpcError::new("IPC", format!("parse message header: {e}")))?;
    let body_length_signed = msg.bodyLength();
    if body_length_signed < 0 {
        return Err(RpcError::new(
            "IPC",
            format!("IPC message has negative bodyLength ({body_length_signed})"),
        ));
    }
    let body_length = body_length_signed as usize;
    if body_length > max_bytes {
        return Err(RpcError::new(
            "IPC",
            format!(
                "IPC message bodyLength {body_length} bytes exceeds cap {max_bytes} — \
                 refusing to allocate before parsing"
            ),
        ));
    }
    let mut body = vec![0u8; body_length];
    if body_length > 0 && !read_exact(r, &mut body)? {
        return Err(RpcError::new("IOError", "unexpected EOF in message body"));
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
    let schema = batch.schema();
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref())?;
        w.write(batch, metadata)?;
        w.finish()?;
    }
    Ok(buf)
}

/// Lowercase hex encoding of a byte slice.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
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
            let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
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
        let err = r.read_next().err().expect("must reject");
        assert!(
            err.message.contains("bodyLength") && err.message.contains("exceeds cap"),
            "unexpected error: {err:?}"
        );
    }
}
