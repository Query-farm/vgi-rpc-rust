//! Thin IPC stream wrappers around `arrow_ipc` that propagate per-batch
//! `custom_metadata` via [`RecordBatch::custom_metadata`].
//!
//! Upstream `arrow_ipc::reader::StreamReader` / `writer::StreamWriter`
//! handle the flatbuffer Message-level `custom_metadata` field directly:
//! readers populate `batch.custom_metadata()` from each RecordBatch
//! message, and writers emit it on every `write(&batch)` call. This
//! module exists only to:
//!
//! - Surface our `Result` / `RpcError` shape on the boundary.
//! - Map "empty IPC stream" / EOF into `Ok(None)` from `read_next`.
//! - Provide schema relaxation so producers that declare non-nullable
//!   fields but emit nulls (e.g. Python's `ArrowSerializableDataclass`)
//!   read cleanly. The relaxation rewrites the schema and rewraps each
//!   batch via `RecordBatch::with_schema`, which preserves
//!   custom_metadata.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_ipc::reader::StreamReader as IpcStreamReader;
use arrow_ipc::writer::StreamWriter as IpcStreamWriter;
use arrow_schema::{Schema, SchemaRef};

use crate::errors::{Result, RpcError};

/// Per-batch metadata pairs (HashMap-backed, mirroring
/// `RecordBatch::custom_metadata`).
pub type Metadata = HashMap<String, String>;

/// Look up a key in a [`Metadata`] map, returning the value as `&str`.
#[inline]
pub fn md_get<'a>(md: &'a Metadata, key: &str) -> Option<&'a str> {
    md.get(key).map(String::as_str)
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Streaming IPC writer wrapping `arrow_ipc::writer::StreamWriter`.
///
/// Per-batch custom metadata travels via `RecordBatch::custom_metadata` —
/// attach with [`RecordBatch::with_custom_metadata`] before calling
/// [`StreamWriter::write`].
pub struct StreamWriter<W: Write> {
    inner: IpcStreamWriter<W>,
    schema: SchemaRef,
}

impl<W: Write> StreamWriter<W> {
    /// Create a new writer and emit the schema message.
    pub fn new(writer: W, schema: &Schema) -> Result<Self> {
        let inner = IpcStreamWriter::try_new(writer, schema).map_err(RpcError::from)?;
        Ok(Self {
            inner,
            schema: Arc::new(schema.clone()),
        })
    }

    /// Write one record batch; its `custom_metadata` is emitted as the
    /// IPC Message-level `custom_metadata`.
    pub fn write(&mut self, batch: &RecordBatch) -> Result<()> {
        self.inner.write(batch).map_err(RpcError::from)
    }

    /// Schema this writer was opened with.
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    /// Write the EOS continuation marker.
    pub fn finish(&mut self) -> Result<()> {
        self.inner.finish().map_err(RpcError::from)
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> Result<()> {
        self.inner.flush()?;
        Ok(())
    }

    pub fn get_mut(&mut self) -> &mut W {
        self.inner.get_mut()
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Streaming IPC reader wrapping `arrow_ipc::reader::StreamReader`.
///
/// Each batch returned by [`StreamReader::read_next`] carries its
/// per-message `custom_metadata` via `RecordBatch::custom_metadata`.
pub struct StreamReader<R: Read> {
    inner: IpcStreamReader<R>,
    schema: SchemaRef,
    /// When `Some`, every read batch is rewrapped with this relaxed
    /// schema before being returned to the caller.
    relaxed_schema: Option<SchemaRef>,
}

impl<R: Read> StreamReader<R> {
    /// Create a new reader and consume the schema message.
    pub fn new(reader: R) -> Result<Self> {
        let inner = IpcStreamReader::try_new(reader, None).map_err(|e| {
            // Map upstream "empty stream" to our IPC error so callers can
            // recognize the EOF-at-request-boundary case.
            let msg = e.to_string();
            if msg.contains("Expected schema message, found empty stream") {
                RpcError::new("IPC", "empty IPC stream (no schema)")
            } else {
                RpcError::from(e)
            }
        })?;
        let schema = inner.schema();
        Ok(Self {
            inner,
            schema,
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
    ///
    /// Also disables IPC-level validation (the columns have legitimate
    /// null buffers; only the schema flag was a lie) so the upstream
    /// reader doesn't reject the stream before we get a chance to
    /// rewrap with the relaxed schema.
    pub fn relax_nullability(self) -> Self {
        let relaxed = Some(Arc::new(relax_schema_nullability(self.schema.as_ref())));
        // SAFETY: The remote producer guarantees column data is valid;
        // we are only working around an over-strict nullability flag.
        let inner = unsafe { self.inner.with_skip_validation(true) };
        Self {
            inner,
            schema: self.schema,
            relaxed_schema: relaxed,
        }
    }

    /// Read the next record batch, or `None` on end-of-stream.
    pub fn read_next(&mut self) -> Result<Option<RecordBatch>> {
        match self.inner.next() {
            None => Ok(None),
            Some(Ok(batch)) => {
                if let Some(relaxed) = &self.relaxed_schema {
                    let md = batch.custom_metadata().clone();
                    let rebatch = batch
                        .with_schema(relaxed.clone())
                        .map_err(RpcError::from)?
                        .with_custom_metadata(md);
                    Ok(Some(rebatch))
                } else {
                    Ok(Some(batch))
                }
            }
            Some(Err(e)) => Err(RpcError::from(e)),
        }
    }

    /// Drain and discard any remaining batches.
    pub fn drain(&mut self) -> Result<()> {
        while self.read_next()?.is_some() {}
        Ok(())
    }

    pub fn get_mut(&mut self) -> &mut R {
        self.inner.get_mut()
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Serialize one record batch as a complete IPC stream
/// (schema + batch + EOS). Per-batch metadata travels via
/// `batch.custom_metadata()`.
pub fn write_one_batch(batch: &RecordBatch) -> Result<Vec<u8>> {
    let schema = batch.schema();
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref())?;
        w.write(batch)?;
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

/// Convenience: attach `metadata` to `batch` via
/// [`RecordBatch::with_custom_metadata`]. Equivalent to a direct call
/// but reads more naturally at sites that mostly speak in `Metadata`.
#[inline]
pub fn batch_with_md(batch: RecordBatch, metadata: Metadata) -> RecordBatch {
    batch.with_custom_metadata(metadata)
}

/// Like [`batch_with_md`] but a no-op when `metadata` is `None`.
#[inline]
pub fn attach_md_opt(batch: RecordBatch, metadata: Option<Metadata>) -> RecordBatch {
    match metadata {
        Some(m) => batch.with_custom_metadata(m),
        None => batch,
    }
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
        let mut md: Metadata = HashMap::new();
        md.insert("vgi_rpc.method".into(), "echo_string".into());
        let batch = batch.with_custom_metadata(md);

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
            w.write(&batch).unwrap();
            w.finish().unwrap();
        }

        let mut r = StreamReader::new(buf.as_slice()).unwrap();
        let rb = r.read_next().unwrap().expect("batch");
        assert_eq!(rb.num_rows(), 3);
        assert_eq!(
            md_get(rb.custom_metadata(), "vgi_rpc.method"),
            Some("echo_string")
        );
        assert!(r.read_next().unwrap().is_none());
    }

    #[test]
    fn zero_row_metadata_only() {
        let schema = Schema::empty();
        let batch = empty_batch(&schema).unwrap();
        let mut md: Metadata = HashMap::new();
        md.insert("vgi_rpc.log_level".into(), "INFO".into());
        let batch = batch.with_custom_metadata(md);

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
            w.write(&batch).unwrap();
            w.finish().unwrap();
        }
        let mut r = StreamReader::new(buf.as_slice()).unwrap();
        let rb = r.read_next().unwrap().expect("batch");
        assert_eq!(rb.num_rows(), 0);
        assert_eq!(
            md_get(rb.custom_metadata(), "vgi_rpc.log_level"),
            Some("INFO")
        );
    }
}
