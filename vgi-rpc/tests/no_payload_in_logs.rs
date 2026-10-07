//! No request payload or stream state reaches any log, at any level.
//!
//! The framework cannot know which parameters are secret: a VGI
//! `catalog_attach` carries API keys and passwords in its options. So a call
//! whose argument *and* stream state hold a sentinel secret is driven over
//! HTTP (unary, then a stream through `/init` and every continuation) with the
//! access log attached and every `tracing` target at TRACE, and the sentinel
//! must appear nowhere in either output -- not verbatim, and not in any base64
//! alignment of it. Before this change the access log wrote each stream turn's
//! decrypted state as `response_state`, and this test failed on that field.

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use arrow_array::{Array, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{
    CALL_STATE_KEY, PROTOCOL_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY, STATE_KEY,
};
use vgi_rpc::server::MethodType;
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult, StreamStateKind};
use vgi_rpc::stream_codec::{bincode_decode, bincode_encode};
use vgi_rpc::wire::{empty_batch, md_get, StreamReader, StreamWriter};
use vgi_rpc::{AccessLogHook, CallContext, MethodInfo, Result, RpcServer};

const SENTINEL: &str = "SENTINEL-sk-live-9f3b2c71d0e4a5b6c7d8";
const PROTOCOL: &str = "Secrets";

/// One shared buffer for everything `tracing` emits in this test binary.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Every `tracing` event from every thread (dispatch runs off the test
/// thread), at TRACE: the most verbose logging there is.
fn tracing_capture() -> Captured {
    static CAPTURED: OnceLock<Captured> = OnceLock::new();
    CAPTURED
        .get_or_init(|| {
            let captured = Captured::default();
            let writer = captured.clone();
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .init();
            captured
        })
        .clone()
}

/// A producer whose state carries the secret for the life of the stream.
#[derive(Serialize, Deserialize)]
struct Tail {
    api_key: String,
    next: i64,
}

impl ProducerState for Tail {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.next >= 3 {
            out.finish();
            return Ok(());
        }
        let arr: arrow_array::ArrayRef = Arc::new(Int64Array::from(vec![self.next]));
        self.next += 1;
        out.emit(RecordBatch::try_new(out_schema(), vec![arr])?)?;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
}

fn out_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]))
}

fn params_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "api_key",
        DataType::Utf8,
        false,
    )]))
}

fn api_key(batch: &RecordBatch) -> String {
    batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .filter(|a| !a.is_empty())
        .map(|a| a.value(0).to_string())
        .unwrap_or_default()
}

fn state(access_log: Arc<Mutex<Vec<u8>>>) -> Arc<HttpState> {
    let mut srv = RpcServer::builder()
        .server_id("no-payload")
        .protocol_name(PROTOCOL)
        .with_hook(AccessLogHook::new(Captured(access_log), "test-1"))
        .build();
    srv.register(MethodInfo::unary(
        "login",
        params_schema(),
        Schema::new(vec![Field::new("result", DataType::Utf8, false)]).into(),
        |req, _| {
            let ok = api_key(&req.batch) == SENTINEL;
            let schema = Arc::new(Schema::new(vec![Field::new(
                "result",
                DataType::Utf8,
                false,
            )]));
            Ok(Some(RecordBatch::try_new(
                schema,
                vec![Arc::new(StringArray::from(vec![if ok {
                    "ok"
                } else {
                    "denied"
                }]))],
            )?))
        },
    ));
    srv.register(
        MethodInfo::stream("tail", MethodType::Producer, params_schema(), |req, _| {
            Ok(StreamResult::producer(
                out_schema(),
                Box::new(Tail {
                    api_key: api_key(&req.batch),
                    next: 0,
                }),
            ))
        })
        .with_state_decoder(Arc::new(|bytes: &[u8]| {
            let tail: Tail = bincode_decode(bytes)?;
            Ok(StreamStateKind::Producer(Box::new(tail)))
        })),
    );
    HttpState::builder().server(Arc::new(srv)).build()
}

fn body(method: &str, schema: &Schema, batch: &RecordBatch, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut md = HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (PROTOCOL_KEY.to_string(), PROTOCOL.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
    ]);
    for (k, v) in extra {
        md.insert((*k).to_string(), (*v).to_string());
    }
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema).unwrap();
        w.write(batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

fn secret_batch() -> RecordBatch {
    RecordBatch::try_new(
        params_schema(),
        vec![Arc::new(StringArray::from(vec![SENTINEL]))],
    )
    .unwrap()
}

async fn post(state: &Arc<HttpState>, path: &str, body: Vec<u8>) -> Vec<u8> {
    let resp = vgi_rpc::http::build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri(path)
                .method("POST")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{path}: {}", resp.status());
    to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

fn tokens(body: &[u8]) -> (Option<String>, Option<String>) {
    let mut r = StreamReader::new(body).unwrap();
    let (mut cursor, mut call) = (None, None);
    while let Some((_, md)) = r.read_next().unwrap() {
        if let Some(t) = md_get(&md, STATE_KEY) {
            cursor = Some(t.to_string());
        }
        if let Some(t) = md_get(&md, CALL_STATE_KEY) {
            call = Some(t.to_string());
        }
    }
    (cursor, call)
}

/// The sentinel in every base64 alignment: whatever bytes precede it, the
/// interior of its encoding is one of these three strings.
fn base64_forms() -> Vec<String> {
    (0..3)
        .map(|pad| {
            let mut bytes = vec![0u8; pad];
            bytes.extend_from_slice(SENTINEL.as_bytes());
            let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
            // Drop the groups that mix in the unknown neighbours.
            let start = if pad == 0 { 0 } else { 4 };
            encoded[start..encoded.len() - 4].to_string()
        })
        .collect()
}

fn assert_clean(what: &str, text: &str) {
    assert!(
        !text.contains(SENTINEL),
        "{what} contains the secret:\n{text}"
    );
    for form in base64_forms() {
        assert!(
            !text.contains(&form),
            "{what} contains the secret base64-encoded ({form}):\n{text}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secret_argument_and_stream_state_never_reach_any_log() {
    let traced = tracing_capture();
    let access_log: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let state = state(access_log.clone());
    let schema = params_schema();

    // Unary: the secret is an argument.
    let resp = post(
        &state,
        &format!("/{PROTOCOL}/login"),
        body("login", &schema, &secret_batch(), &[]),
    )
    .await;
    assert!(!resp.is_empty());

    // Stream: the secret is an argument on /init and lives in the state every
    // turn hands back and receives.
    let init = post(
        &state,
        &format!("/{PROTOCOL}/tail/init"),
        body("tail", &schema, &secret_batch(), &[]),
    )
    .await;
    let (mut cursor, call_token) = tokens(&init);
    let call_token = call_token.expect("/init hands over a call token");
    let mut turns = 0;
    while let Some(c) = cursor.clone() {
        turns += 1;
        assert!(turns < 10, "producer did not terminate");
        let empty = Schema::empty();
        let cont = body(
            "tail",
            &empty,
            &empty_batch(&empty).unwrap(),
            &[
                (STATE_KEY, c.as_str()),
                (CALL_STATE_KEY, call_token.as_str()),
            ],
        );
        cursor = tokens(&post(&state, &format!("/{PROTOCOL}/tail/exchange"), cont).await).0;
    }
    assert!(
        turns >= 2,
        "the stream must round-trip its state: {turns} turns"
    );

    let log = String::from_utf8(access_log.lock().unwrap().clone()).unwrap();
    let records: Vec<serde_json::Value> = log
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // Non-vacuous: the records exist and describe what they may describe.
    assert!(
        records.len() >= 4,
        "expected unary + every stream turn: {log}"
    );
    let login = records.iter().find(|r| r["method"] == "login").unwrap();
    assert_eq!(
        login["request_fields"],
        serde_json::json!([{"name": "api_key", "type": "Utf8"}])
    );
    assert_eq!(login["request_rows"], 1);
    assert!(
        records
            .iter()
            .any(|r| r["response_state_bytes"].as_u64().is_some_and(|n| n > 0)),
        "stream turns must report their state by size: {log}"
    );
    assert!(
        records
            .iter()
            .any(|r| r["request_state_bytes"].as_u64().is_some_and(|n| n > 0)),
        "continuations must report the state received by size: {log}"
    );
    for rec in &records {
        for forbidden in ["request_data", "request_state", "response_state"] {
            assert!(rec.get(forbidden).is_none(), "{forbidden} in {rec}");
        }
    }

    assert_clean("the access log", &log);
    assert_clean("the tracing output (TRACE)", &traced.text());
}
