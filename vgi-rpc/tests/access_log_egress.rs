//! Egress accounting on HTTP access-log records.
//!
//! `request_bytes` / `response_bytes` measure what crossed the network;
//! `input_bytes` / `output_bytes` measure logical Arrow buffers. Conflating
//! them is how an egress bill ends up wrong by orders of magnitude — a
//! compressible result that measures 200 KB in memory can be a couple of
//! hundred bytes on the wire.
//!
//! `response_bytes` is the reason emission is deferred at all: compression
//! runs in the post-processing middleware, after the handler has finished, so
//! a record written where the handler ends can only report the uncompressed
//! body.

use std::io::Write;
use std::sync::{Arc, Mutex};

use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{REQUEST_VERSION, REQUEST_VERSION_KEY};
use vgi_rpc::wire::{Metadata, StreamWriter};
use vgi_rpc::{AccessLogHook, MethodInfo, RpcServer};

struct BufSink(Arc<Mutex<Vec<u8>>>);
impl Write for BufSink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_unary_body(schema: &Schema, batch: &RecordBatch) -> Vec<u8> {
    let mut md = Metadata::new();
    md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema).unwrap();
        w.write(batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// A server whose one method returns a large, highly compressible result.
fn state(log: Arc<Mutex<Vec<u8>>>) -> Arc<HttpState> {
    let mut srv = RpcServer::builder()
        .server_id("it")
        .protocol_name("Test")
        .with_hook(AccessLogHook::new(BufSink(log), "test-1"))
        .build();
    srv.register(MethodInfo::unary(
        "big",
        Schema::new(vec![Field::new("value", DataType::Utf8, false)]).into(),
        Schema::new(vec![Field::new("result", DataType::Utf8, false)]).into(),
        |_req, _| {
            let big = "abcdefgh".repeat(25_600); // 200 KiB of repetition
            let schema = Arc::new(Schema::new(vec![Field::new(
                "result",
                DataType::Utf8,
                false,
            )]));
            Ok(Some(
                RecordBatch::try_new(schema, vec![Arc::new(StringArray::from(vec![big]))]).unwrap(),
            ))
        },
    ));
    HttpState::builder().server(Arc::new(srv)).build()
}

/// POST `/big` with the given `Accept-Encoding`, returning
/// `(request body length, response body length, the emitted record)`.
async fn call(accept_encoding: &str) -> (usize, usize, serde_json::Value) {
    let log: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let app = vgi_rpc::http::build_router(state(log.clone()));
    let params_schema = Schema::new(vec![Field::new("value", DataType::Utf8, false)]);
    let batch = RecordBatch::try_new(
        Arc::new(params_schema.clone()),
        vec![Arc::new(StringArray::from(vec!["x"]))],
    )
    .unwrap();
    let body = encode_unary_body(&params_schema, &batch);
    let request_len = body.len();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/big")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .header(header::ACCEPT_ENCODING, accept_encoding)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let response_len = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .len();

    let text = String::from_utf8(log.lock().unwrap().clone()).unwrap();
    let mut records = text.lines().filter(|l| !l.trim().is_empty());
    let record: serde_json::Value = serde_json::from_str(
        records
            .next()
            .expect("the response was returned, so the record must have been emitted"),
    )
    .unwrap();
    assert!(records.next().is_none(), "one record per call");
    (request_len, response_len, record)
}

#[tokio::test]
async fn response_bytes_reports_the_compressed_body() {
    let (request_len, compressed_len, compressed) = call("zstd").await;
    let (_, identity_len, identity) = call("identity").await;

    // The record reports what was actually sent, not what the handler built.
    assert_eq!(
        compressed["response_bytes"].as_u64().unwrap() as usize,
        compressed_len
    );
    assert_eq!(
        identity["response_bytes"].as_u64().unwrap() as usize,
        identity_len
    );
    // ...and the two differ by orders of magnitude, which is the entire
    // reason the figure has to be taken after compression runs.
    assert!(
        compressed_len * 100 < identity_len,
        "expected the compressed body to be far smaller: {compressed_len} vs {identity_len}"
    );

    // `request_bytes` is the body as received, before decompression.
    assert_eq!(
        compressed["request_bytes"].as_u64().unwrap() as usize,
        request_len
    );

    // Nothing was externalised, so the field stays absent rather than zero.
    assert!(compressed.get("externalized_bytes").is_none());
}

#[tokio::test]
async fn http_records_mark_the_payload_as_omitted() {
    // Not logging the request payload at this level loses nothing, so the
    // record must say `payload_omitted` rather than claim data was shed —
    // and it must say something, or the schema's "unary requires
    // request_data" rule fails for every HTTP record.
    let (_, _, record) = call("identity").await;
    assert_eq!(record["truncated"], "payload_omitted");
    assert!(record.get("request_data").is_none());
    assert!(record["original_request_bytes"].as_u64().unwrap() > 0);
}
