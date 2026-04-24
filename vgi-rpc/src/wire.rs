//! Low-level IPC stream helpers that preserve per-batch custom metadata.
//!
//! The standard `arrow-ipc` `StreamWriter`/`StreamReader` do not expose
//! per-message `custom_metadata`, but the vgi_rpc wire protocol relies on
//! it to carry `vgi_rpc.method`, `vgi_rpc.request_version`, log keys, state
//! tokens, etc. This module provides a thin reader/writer that parses and
//! injects metadata on the flatbuffer `Message` wrapper while delegating
//! record-batch encoding/decoding to `arrow_ipc`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_buffer::Buffer as ArrowBuffer;
use arrow_ipc::{
    convert as ipc_convert, root_as_message, reader as ipc_reader, writer::DictionaryTracker,
    writer::IpcDataGenerator, writer::IpcWriteOptions, writer::write_message, Buffer as FbBuffer,
    FieldNode, KeyValue, KeyValueArgs, MessageBuilder, MessageHeader, MetadataVersion,
    RecordBatchBuilder,
};
use arrow_schema::{Schema, SchemaRef};
use flatbuffers::FlatBufferBuilder;

use crate::errors::{Result, RpcError};

/// Metadata pairs attached to a single IPC message.
pub type Metadata = Vec<(String, String)>;

/// Look up a key in a [`Metadata`] list.
pub fn md_get<'a>(md: &'a Metadata, key: &str) -> Option<&'a str> {
    md.iter().find_map(|(k, v)| (k == key).then_some(v.as_str()))
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

const CONTINUATION_MARKER: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// A streaming IPC writer that supports per-batch custom metadata.
///
/// The sequence written for a complete stream is:
///   `SchemaMessage → [DictionaryMessage]* → [RecordBatchMessage]* → EOS(4xFF 0x00)`.
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
        let encoded = data_gen.schema_to_bytes_with_dictionary_tracker(
            schema,
            &mut dict_tracker,
            &opts,
        );
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

    /// Write one RecordBatch with optional custom metadata.
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

    /// Write the EOS continuation marker.
    pub fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.writer.write_all(&CONTINUATION_MARKER)?;
        self.writer.write_all(&[0u8; 4])?;
        self.finished = true;
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

/// Rebuild a Message flatbuffer with `custom_metadata` added, preserving
/// the embedded RecordBatch header unchanged.
fn repack_record_batch_message_with_metadata(
    msg_bytes: &[u8],
    metadata: &Metadata,
) -> Result<Vec<u8>> {
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
        // Note: we don't carry compression here; the conformance server
        // does not enable IPC batch compression, so this is safe.
        b.finish()
    };

    // Build custom_metadata vector.
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
/// Returns batches one at a time via [`read_next`]. Dictionary and schema
/// messages are consumed transparently.
pub struct StreamReader<R: Read> {
    reader: R,
    schema: SchemaRef,
    dictionaries: HashMap<i64, arrow_array::ArrayRef>,
    finished: bool,
}

/// A batch returned by the reader together with the message custom metadata.
#[derive(Debug)]
pub struct ReadBatch {
    pub batch: RecordBatch,
    pub metadata: Metadata,
}

impl<R: Read> StreamReader<R> {
    /// Create a new reader and consume the schema message.
    pub fn new(mut reader: R) -> Result<Self> {
        let msg = read_message_bytes(&mut reader)?
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
        })
    }

    /// Get the schema of the stream.
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    /// Read the next record batch, or `None` on end-of-stream.
    pub fn read_next(&mut self) -> Result<Option<ReadBatch>> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let msg = match read_message_bytes(&mut self.reader)? {
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
                    let batch = ipc_reader::read_record_batch(
                        &body_buf,
                        rb_fb,
                        self.schema.clone(),
                        &self.dictionaries,
                        None,
                        &version,
                    )
                    .map_err(RpcError::from)?;
                    let metadata = parse_custom_metadata(&msg_fb);
                    return Ok(Some(ReadBatch { batch, metadata }));
                }
                MessageHeader::Schema => {
                    return Err(RpcError::new(
                        "IPC",
                        "unexpected schema message mid-stream",
                    ));
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
    let mut out = Vec::new();
    if let Some(md) = msg.custom_metadata() {
        for kv in md.iter() {
            let k = kv.key().unwrap_or("").to_string();
            let v = kv.value().unwrap_or("").to_string();
            out.push((k, v));
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

fn read_message_bytes(r: &mut impl Read) -> Result<Option<RawMessage>> {
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
    let mut message_bytes = vec![0u8; size];
    if !read_exact(r, &mut message_bytes)? {
        return Err(RpcError::new("IOError", "unexpected EOF in message body"));
    }
    // Parse to learn body length
    let msg = root_as_message(&message_bytes)
        .map_err(|e| RpcError::new("IPC", format!("parse message header: {e}")))?;
    let body_length = msg.bodyLength() as usize;
    let mut body = vec![0u8; body_length];
    if body_length > 0 && !read_exact(r, &mut body)? {
        return Err(RpcError::new("IOError", "unexpected EOF in message body"));
    }
    Ok(Some(RawMessage { message_bytes, body }))
}

// ---------------------------------------------------------------------------
// Utility — build a zero-row record batch matching a given schema
// ---------------------------------------------------------------------------

/// Build a zero-row `RecordBatch` matching the given schema.
pub fn empty_batch(schema: &Schema) -> Result<RecordBatch> {
    use arrow_array::RecordBatchOptions;
    use arrow_array::array::new_empty_array;
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
            let md = vec![("vgi_rpc.method".to_string(), "echo_string".to_string())];
            w.write(&batch, Some(&md)).unwrap();
            w.finish().unwrap();
        }

        let mut r = StreamReader::new(buf.as_slice()).unwrap();
        let rb = r.read_next().unwrap().expect("batch");
        assert_eq!(rb.batch.num_rows(), 3);
        assert_eq!(md_get(&rb.metadata, "vgi_rpc.method"), Some("echo_string"));
        assert!(r.read_next().unwrap().is_none());
    }

    #[test]
    fn zero_row_metadata_only() {
        let schema = Schema::empty();
        let batch = empty_batch(&schema).unwrap();

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
            let md = vec![("vgi_rpc.log_level".into(), "INFO".into())];
            w.write(&batch, Some(&md)).unwrap();
            w.finish().unwrap();
        }
        let mut r = StreamReader::new(buf.as_slice()).unwrap();
        let rb = r.read_next().unwrap().expect("batch");
        assert_eq!(rb.batch.num_rows(), 0);
        assert_eq!(md_get(&rb.metadata, "vgi_rpc.log_level"), Some("INFO"));
    }
}
