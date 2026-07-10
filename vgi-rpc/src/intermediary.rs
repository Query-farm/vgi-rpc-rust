//! Public wire-framing helpers for VGI-RPC **intermediaries**.
//!
//! vgi-rpc has two first-class roles: *client* (`vgi_rpc_client::Client`) and
//! *server* ([`RpcServer`](crate::RpcServer)). A third role — an **intermediary**
//! (proxy, router, gateway, test harness) — needs to read a request off the wire,
//! rewrite it, re-frame it for forwarding, and synthesize in-band error
//! responses, without standing up a full client or server.
//!
//! This module is the stable public surface for that role, so intermediaries
//! don't reach into the server's private framing paths or re-derive the wire
//! format from scratch.
//!
//! It is the Rust counterpart of Python's `vgi_rpc.wire` module. (Rust's
//! [`crate::wire`] is the *low-level IPC codec* — the analog of Python's private
//! `vgi_rpc.rpc._wire` — and these helpers layer on top of its
//! [`StreamReader`](crate::wire::StreamReader) /
//! [`StreamWriter`](crate::wire::StreamWriter).)

use std::io::Cursor;

use arrow_array::{Array, BinaryArray, RecordBatch};
use arrow_schema::{Schema, SchemaRef};

use crate::errors::{Result, RpcError};
use crate::log::LogLevel;
use crate::metadata::{
    LOG_LEVEL_KEY, PROTOCOL_VERSION_KEY, REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY,
    RPC_METHOD_KEY, SERVER_ID_KEY, STATE_KEY,
};
use crate::server::Request;
use crate::wire::{empty_batch, md_get, Metadata, StreamReader, StreamWriter};

/// Parse a request IPC body into a [`Request`] (method, request id, parameter
/// batch, and metadata).
///
/// The Rust counterpart of Python's `read_request(data) -> (method, kwargs)`:
/// the parameter "kwargs" are the columns of [`Request::batch`], readable by
/// name via [`Request::column`].
///
/// Validates `vgi_rpc.request_version` and requires `vgi_rpc.method` — an
/// intermediary reading a raw body has no URL path to derive the method from.
///
/// # Errors
///
/// Returns a protocol/version error for a malformed, empty, or wrong-version
/// stream. Externalized (`vgi_rpc.location`) pointer requests are *not* resolved
/// here; resolve them with [`crate::external`] before calling, or treat an
/// unresolved pointer as a fail-closed denial.
pub fn read_request(data: &[u8]) -> Result<Request> {
    let mut reader = StreamReader::new(Cursor::new(data))?;
    let (batch, metadata) = reader
        .read_next()?
        .ok_or_else(|| RpcError::protocol_error("empty IPC stream"))?;
    reader.drain()?;
    Request::from_read_batch(batch, metadata, true)
}

/// Frame a request as a complete IPC stream body for forwarding.
///
/// `params` is the single-row parameter batch (its schema is the method's
/// parameter schema). `protocol_version` stamps the application protocol version
/// so a versioned backend's dispatch-boundary check still sees the *originating*
/// client's version — pass `None` to emit a request that is structurally exempt
/// from that check. `request_id` is echoed on the response; pass `None` to omit.
pub fn write_request(
    method: &str,
    params: &RecordBatch,
    protocol_version: Option<&str>,
    request_id: Option<&str>,
) -> Result<Vec<u8>> {
    let mut md = Metadata::new();
    md.insert(RPC_METHOD_KEY.to_string(), method.to_string());
    md.insert(REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string());
    if let Some(id) = request_id.filter(|s| !s.is_empty()) {
        md.insert(REQUEST_ID_KEY.to_string(), id.to_string());
    }
    if let Some(pv) = protocol_version.filter(|s| !s.is_empty()) {
        md.insert(PROTOCOL_VERSION_KEY.to_string(), pv.to_string());
    }
    let mut buf = Vec::new();
    {
        let mut sw = StreamWriter::new(&mut buf, params.schema().as_ref())?;
        sw.write(params, Some(&md))?;
        sw.finish()?;
    }
    Ok(buf)
}

/// Build a complete IPC stream carrying a single error batch.
///
/// This is the wire shape an intermediary returns to deny or abort a call
/// in-band — the client decodes it back into a raised [`RpcError`]. `schema`
/// defaults to the empty schema; `server_id` is stamped when non-empty.
pub fn build_error_stream(
    err: &RpcError,
    schema: Option<&Schema>,
    server_id: Option<&str>,
) -> Result<Vec<u8>> {
    let empty = Schema::empty();
    let schema = schema.unwrap_or(&empty);
    let mut buf = Vec::new();
    {
        let mut sw = StreamWriter::new(&mut buf, schema)?;
        let mut md = crate::server::build_error_metadata(err, server_id.unwrap_or(""), "");
        // `build_error_metadata` omits an empty server id already; drop an
        // explicitly-empty one for symmetry with Python's `server_id=None`.
        if server_id.is_none_or(str::is_empty) {
            md.remove(SERVER_ID_KEY);
        }
        sw.write(&empty_batch(schema)?, Some(&md))?;
        sw.finish()?;
    }
    Ok(buf)
}

/// Walk every batch of one or more **concatenated** IPC streams in `data`,
/// calling `f` with each batch's `custom_metadata` until it returns `Some`.
///
/// Two body shapes are handled by one walk: an exchange *request* is a single
/// stream whose first batch carries the key; a producer init/exchange *response*
/// may be several concatenated streams (a header stream, then the producer's
/// data stream), so the key can live in a later stream.
///
/// Lenient by construction: an unparseable stream ends the walk and yields
/// `None` rather than erroring — an intermediary forwards what it can't read.
fn scan_batch_metadata<T>(data: &[u8], mut f: impl FnMut(&Metadata) -> Option<T>) -> Option<T> {
    let mut offset = 0usize;
    while offset < data.len() {
        let start = offset;
        let mut cursor = Cursor::new(&data[offset..]);
        {
            let Ok(mut reader) = StreamReader::new(&mut cursor) else {
                return None;
            };
            while let Ok(Some((_batch, md))) = reader.read_next() {
                if let Some(found) = f(&md) {
                    return Some(found);
                }
            }
        }
        offset += cursor.position() as usize;
        if offset == start {
            return None; // no forward progress — avoid an infinite loop
        }
    }
    None
}

/// Return the stream-state continuation token carried in a request/response body.
///
/// The token (key [`STATE_KEY`]) rides in a record batch's `custom_metadata` —
/// not a header. Stream continuations recover their state from this token, never
/// from headers, so an intermediary routing or correlating a stream by it must
/// read the batch metadata.
///
/// Returns the first token found across all concatenated streams, or `None` when
/// absent or the body is unparseable.
///
/// Note: for a response that rotates the token across several data batches, the
/// *last* token is the continuation the peer will send next; this returns the
/// first. Single-token responses (the common case) make them identical.
pub fn find_state_token(data: &[u8]) -> Option<String> {
    scan_batch_metadata(data, |md| {
        md_get(md, STATE_KEY)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
    })
}

/// Return the application `protocol_version` stamped on a request body.
///
/// An intermediary that rewrites a request must recover and re-stamp this (see
/// [`write_request`]) so the backend's dispatch-boundary version check still
/// sees the originating client's version. Returns `None` when absent or
/// unparseable — a request that never carried one is structurally exempt from
/// that check.
pub fn find_protocol_version(data: &[u8]) -> Option<String> {
    scan_batch_metadata(data, |md| {
        md_get(md, PROTOCOL_VERSION_KEY)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

/// Unwrap a unary-RPC response into `(envelope_schema, raw_result_bytes)`.
///
/// A unary response is an IPC stream of zero or more leading **log batches**
/// (0-row, carrying [`LOG_LEVEL_KEY`]) followed by one data batch whose `result`
/// column holds the serialized response object. This returns the envelope schema
/// plus the **raw** result bytes — no typed decode — for an intermediary that
/// inspects or rewrites the response and re-wraps it via [`write_unary_result`].
///
/// Lenient: returns `Ok(None)` for an error / empty / non-`result` stream, so the
/// caller can forward it unchanged.
pub fn read_unary_result(data: &[u8]) -> Result<Option<(SchemaRef, Vec<u8>)>> {
    let mut reader = StreamReader::new(Cursor::new(data))?;
    while let Some((batch, md)) = reader.read_next()? {
        if batch.num_rows() > 0 {
            let Ok(idx) = batch.schema().index_of("result") else {
                return Ok(None);
            };
            let Some(col) = batch.column(idx).as_any().downcast_ref::<BinaryArray>() else {
                return Ok(None);
            };
            if col.is_null(0) {
                return Ok(None);
            }
            return Ok(Some((batch.schema(), col.value(0).to_vec())));
        }
        // Skip leading log batches. An error envelope is a 0-row batch too and is
        // stamped with the EXCEPTION *level*, so a presence-only check on
        // LOG_LEVEL_KEY would skip it and hand back a later data batch — turning a
        // failed call into a successful one. Stop on it, and on any 0-row batch
        // that is not a log batch at all.
        match md_get(&md, LOG_LEVEL_KEY) {
            Some(level) if level != LogLevel::Exception.as_str() => continue,
            _ => return Ok(None),
        }
    }
    Ok(None)
}

/// Build a unary-RPC response IPC stream wrapping `result_bytes`.
///
/// The inverse of [`read_unary_result`]: emit a single data batch whose `result`
/// column carries `result_bytes` under `envelope_schema`.
pub fn write_unary_result(envelope_schema: &Schema, result_bytes: &[u8]) -> Result<Vec<u8>> {
    let col = BinaryArray::from(vec![Some(result_bytes)]);
    let batch = RecordBatch::try_new(
        SchemaRef::from(envelope_schema.clone()),
        vec![std::sync::Arc::new(col)],
    )
    .map_err(|e| RpcError::runtime_error(format!("unary result batch: {e}")))?;
    let mut buf = Vec::new();
    {
        let mut sw = StreamWriter::new(&mut buf, envelope_schema)?;
        sw.write(&batch, None)?;
        sw.finish()?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::Int64Array;
    use arrow_schema::{DataType, Field};
    use std::sync::Arc;

    fn params_batch(n: i64) -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, true)]));
        RecordBatch::try_new(schema, vec![Arc::new(Int64Array::from(vec![n]))]).unwrap()
    }

    fn envelope_schema() -> Schema {
        Schema::new(vec![Field::new("result", DataType::Binary, true)])
    }

    #[test]
    fn request_round_trips_through_write_and_read() {
        let body = write_request("bind", &params_batch(7), Some("1.2.3"), Some("req-1")).unwrap();
        let req = read_request(&body).unwrap();
        assert_eq!(req.method, "bind");
        assert_eq!(req.request_id, "req-1");
        let col = req.column("n").unwrap();
        let ints = col.as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(ints.value(0), 7);
        assert_eq!(find_protocol_version(&body).as_deref(), Some("1.2.3"));
    }

    #[test]
    fn write_request_without_protocol_version_omits_the_key() {
        let body = write_request("bind", &params_batch(1), None, None).unwrap();
        assert_eq!(find_protocol_version(&body), None);
        assert_eq!(read_request(&body).unwrap().request_id, "");
    }

    #[test]
    fn read_request_rejects_a_non_request_stream() {
        let err = build_error_stream(&RpcError::runtime_error("boom"), None, None).unwrap();
        assert!(read_request(&err).is_err());
    }

    #[test]
    fn error_stream_decodes_back_to_the_error() {
        let body = build_error_stream(
            &RpcError::runtime_error("boom"),
            Some(&envelope_schema()),
            Some("srv-1"),
        )
        .unwrap();
        let mut reader = StreamReader::new(Cursor::new(&body[..])).unwrap();
        let (batch, md) = reader.read_next().unwrap().unwrap();
        assert_eq!(batch.num_rows(), 0);
        assert_eq!(md_get(&md, LOG_LEVEL_KEY), Some("EXCEPTION"));
        assert_eq!(md_get(&md, SERVER_ID_KEY), Some("srv-1"));
        // Not a unary result stream — an intermediary forwards it unchanged.
        assert!(read_unary_result(&body).unwrap().is_none());
    }

    #[test]
    fn unary_result_round_trips() {
        let schema = envelope_schema();
        let body = write_unary_result(&schema, b"payload").unwrap();
        let (got_schema, bytes) = read_unary_result(&body).unwrap().unwrap();
        assert_eq!(got_schema.field(0).name(), "result");
        assert_eq!(bytes, b"payload");
    }

    #[test]
    fn read_unary_result_skips_leading_log_batches() {
        let schema = envelope_schema();
        let mut buf = Vec::new();
        {
            let mut sw = StreamWriter::new(&mut buf, &schema).unwrap();
            let mut log_md = Metadata::new();
            log_md.insert(LOG_LEVEL_KEY.to_string(), "INFO".to_string());
            sw.write(&empty_batch(&schema).unwrap(), Some(&log_md))
                .unwrap();
            let batch = RecordBatch::try_new(
                SchemaRef::from(schema.clone()),
                vec![Arc::new(BinaryArray::from(vec![Some(&b"payload"[..])]))],
            )
            .unwrap();
            sw.write(&batch, None).unwrap();
            sw.finish().unwrap();
        }
        let (_, bytes) = read_unary_result(&buf).unwrap().unwrap();
        assert_eq!(bytes, b"payload");
    }

    /// An error envelope is a 0-row batch carrying the EXCEPTION *level*, so it
    /// looks structurally like a log batch. It must terminate the scan, not be
    /// skipped — otherwise a failed call whose stream also carries a data batch
    /// would be reported to the intermediary as a success.
    #[test]
    fn read_unary_result_stops_at_an_error_envelope_before_a_data_batch() {
        let schema = envelope_schema();
        let mut buf = Vec::new();
        {
            let mut sw = StreamWriter::new(&mut buf, &schema).unwrap();
            let err_md =
                crate::server::build_error_metadata(&RpcError::runtime_error("boom"), "srv", "req");
            sw.write(&empty_batch(&schema).unwrap(), Some(&err_md))
                .unwrap();
            let batch = RecordBatch::try_new(
                SchemaRef::from(schema.clone()),
                vec![Arc::new(BinaryArray::from(vec![Some(&b"payload"[..])]))],
            )
            .unwrap();
            sw.write(&batch, None).unwrap();
            sw.finish().unwrap();
        }
        assert!(
            read_unary_result(&buf).unwrap().is_none(),
            "an EXCEPTION batch must not be skipped like an INFO log batch"
        );
    }

    #[test]
    fn find_state_token_reads_the_batch_metadata() {
        let batch = params_batch(1);
        let mut buf = Vec::new();
        {
            let mut sw = StreamWriter::new(&mut buf, batch.schema().as_ref()).unwrap();
            let mut md = Metadata::new();
            md.insert(STATE_KEY.to_string(), "dG9rZW4=".to_string());
            sw.write(&batch, Some(&md)).unwrap();
            sw.finish().unwrap();
        }
        assert_eq!(find_state_token(&buf).as_deref(), Some("dG9rZW4="));
    }

    #[test]
    fn find_state_token_walks_concatenated_streams() {
        // A producer response: a header stream (no token) then a data stream
        // whose batch carries the continuation token.
        let header = write_request("init", &params_batch(0), None, None).unwrap();
        let batch = params_batch(2);
        let mut data = Vec::new();
        {
            let mut sw = StreamWriter::new(&mut data, batch.schema().as_ref()).unwrap();
            let mut md = Metadata::new();
            md.insert(STATE_KEY.to_string(), "c3RhdGU=".to_string());
            sw.write(&batch, Some(&md)).unwrap();
            sw.finish().unwrap();
        }
        let body = [header, data].concat();
        assert_eq!(find_state_token(&body).as_deref(), Some("c3RhdGU="));
    }

    #[test]
    fn finders_return_none_on_garbage() {
        assert_eq!(find_state_token(b"not an ipc stream"), None);
        assert_eq!(find_protocol_version(b"not an ipc stream"), None);
        assert_eq!(find_state_token(&[]), None);
    }

    #[test]
    fn find_state_token_is_none_when_absent() {
        let body = write_request("bind", &params_batch(1), None, None).unwrap();
        assert_eq!(find_state_token(&body), None);
    }
}
