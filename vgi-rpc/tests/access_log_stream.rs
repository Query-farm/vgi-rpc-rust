//! A stream is not exempt from the access log.
//!
//! `access-log-spec.md` is "one record per RPC call", and over HTTP a stream's
//! call is not one request: it is the `/init` plus every `/exchange`. So the
//! rule reads, concretely, as one record per *turn*, all of them carrying the
//! same `stream_id`, with `request_data` on the init record alone and
//! `response_state` present exactly while the stream is resumable.
//!
//! Nothing caught the port that emitted *nothing* here, because a record
//! validator validates the records that exist: no records means nothing to
//! validate, and the result reads as "clean" rather than "unexamined". These
//! tests assert the records are *there*, which is the half no schema can check
//! — and streams are the calls that run longest and move the most data, so a
//! transport that logs unary and not streams drops precisely the traffic an
//! operator is reading the log for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arrow_array::{Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use vgi_rpc::hooks::{CallStatistics, DispatchHook, DispatchInfo, HookToken};
use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{
    CALL_STATE_KEY, PROTOCOL_KEY, REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY,
    RPC_METHOD_KEY, STATE_KEY,
};
use vgi_rpc::server::MethodType;
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult, StreamStateKind};
use vgi_rpc::stream_codec::{bincode_decode, bincode_encode, StreamStateCodec};
use vgi_rpc::wire::{empty_batch, md_get, StreamReader, StreamWriter};
use vgi_rpc::{CallContext, MethodInfo, Result, RpcServer};

const PROTOCOL: &str = "Counter";
const METHOD: &str = "count_to";

/// What one access record carries about the stream it belongs to.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    method_type: String,
    protocol: String,
    protocol_hash: String,
    stream_id: String,
    request_data_len: usize,
    response_state_len: usize,
    output_rows: u64,
    status_error: bool,
}

#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<Seen>>,
}

impl Recorder {
    fn records(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn for_method(&self, method: &str) -> Vec<Seen> {
        self.records()
            .into_iter()
            .filter(|r| r.method == method)
            .collect()
    }
}

impl DispatchHook for Recorder {
    fn on_dispatch_start(&self, _info: &DispatchInfo) -> HookToken {
        0
    }
    fn on_dispatch_end(
        &self,
        _token: HookToken,
        info: &DispatchInfo,
        error: Option<&vgi_rpc::RpcError>,
        stats: &CallStatistics,
    ) {
        self.seen.lock().unwrap().push(Seen {
            method: info.method.clone(),
            method_type: info.method_type.to_string(),
            protocol: info.protocol.clone(),
            protocol_hash: info.protocol_hash.clone(),
            stream_id: info.stream_id.clone(),
            request_data_len: info.request_data.len(),
            response_state_len: info.response_state.len(),
            output_rows: stats.output_rows,
            status_error: error.is_some(),
        });
    }
}

// ---------------------------------------------------------------------------
// A producer that emits one row per turn for `n` turns.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Counter {
    next: i64,
    limit: i64,
}

impl StreamStateCodec for Counter {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        bincode_decode(bytes)
    }
}

impl ProducerState for Counter {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.next >= self.limit {
            out.finish();
            return Ok(());
        }
        let arr: arrow_array::ArrayRef = Arc::new(Int64Array::from(vec![self.next]));
        self.next += 1;
        out.emit(RecordBatch::try_new(out_schema(), vec![arr])?)?;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

fn out_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]))
}

fn params_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "limit",
        DataType::Int64,
        false,
    )]))
}

/// A fixed signing key, so two independently built `HttpState`s can verify
/// each other's tokens — which is what a fleet behind a load balancer actually
/// configures, and what makes the cross-worker test below meaningful.
const SHARED_TOKEN_KEY: &[u8; 32] = b"access-log-stream-test-key-32byt";

fn build(hook: Arc<Recorder>) -> Arc<HttpState> {
    let mut srv = RpcServer::builder()
        .server_id("stream-log")
        .protocol_name(PROTOCOL)
        .protocol_version("1.0.0")
        .with_hook(hook)
        .build();
    srv.register(
        MethodInfo::stream(
            METHOD,
            MethodType::Producer,
            params_schema(),
            |req, _ctx| {
                let limit = req
                    .batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .map(|a| a.value(0))
                    .unwrap_or(0);
                Ok(StreamResult::producer(
                    out_schema(),
                    Box::new(Counter { next: 0, limit }),
                ))
            },
        )
        .with_state_decoder(Arc::new(|bytes: &[u8]| {
            Ok(StreamStateKind::Producer(Box::new(Counter::decode(bytes)?)))
        })),
    );
    HttpState::builder()
        .server(Arc::new(srv))
        .token_key(SHARED_TOKEN_KEY)
        .build()
}

fn init_body(limit: i64) -> Vec<u8> {
    let batch = RecordBatch::try_new(
        params_schema(),
        vec![Arc::new(Int64Array::from(vec![limit]))],
    )
    .unwrap();
    let md = HashMap::<String, String>::from([
        (RPC_METHOD_KEY.to_string(), METHOD.to_string()),
        (PROTOCOL_KEY.to_string(), PROTOCOL.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "stream-init".to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, params_schema().as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

fn continuation_body(cursor: &str, call_token: &str) -> Vec<u8> {
    let schema = Schema::empty();
    let batch = empty_batch(&schema).unwrap();
    let md = HashMap::<String, String>::from([
        (STATE_KEY.to_string(), cursor.to_string()),
        (CALL_STATE_KEY.to_string(), call_token.to_string()),
        (PROTOCOL_KEY.to_string(), PROTOCOL.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), "stream-cont".to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, &schema).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Returns (cursor, call_token) from a stream response body.
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

/// Drive `count_to(2)` to completion over the protocol-qualified routes and
/// return the records it produced.
async fn drive_to_completion(hook: &Arc<Recorder>, state: &Arc<HttpState>) -> Vec<Seen> {
    let body = post(state, &format!("/{PROTOCOL}/{METHOD}/init"), init_body(2)).await;
    let (mut cursor, call_token) = tokens(&body);
    let call_token = call_token.expect("/init must hand over a call token");

    // Continue until the stream stops handing back a cursor.
    let mut turns = 0;
    while let Some(c) = cursor.clone() {
        turns += 1;
        assert!(turns < 10, "producer did not terminate");
        let body = post(
            state,
            &format!("/{PROTOCOL}/{METHOD}/exchange"),
            continuation_body(&c, &call_token),
        )
        .await;
        cursor = tokens(&body).0;
    }
    hook.for_method(METHOD)
}

#[tokio::test]
async fn every_turn_of_an_http_stream_is_logged() {
    let hook = Arc::new(Recorder::default());
    let state = build(hook.clone());
    let records = drive_to_completion(&hook, &state).await;

    assert!(
        records.len() >= 2,
        "an HTTP stream's init and its continuations are separate RPC calls and \
         each owes a record; saw {}",
        records.len()
    );
    for rec in &records {
        assert_eq!(
            rec.method_type, "stream",
            "a stream turn logged method_type={:?}",
            rec.method_type
        );
        assert!(!rec.status_error, "unexpected error record: {rec:?}");
    }
}

#[tokio::test]
async fn one_call_produces_one_stream_id() {
    let hook = Arc::new(Recorder::default());
    let state = build(hook.clone());
    let records = drive_to_completion(&hook, &state).await;

    let ids: std::collections::BTreeSet<&str> =
        records.iter().map(|r| r.stream_id.as_str()).collect();
    assert_eq!(
        ids.len(),
        1,
        "records of one stream call must share a stream_id; without that a \
         reader cannot reassemble the call's turns. Saw {ids:?}"
    );
    let id = ids.into_iter().next().unwrap();
    assert_eq!(id.len(), 32, "stream_id must be 32 hex characters: {id:?}");
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "stream_id must be lowercase hex with no dashes: {id:?}"
    );
}

/// The id survives a continuation that lands on a *different* process.
///
/// This is the property that makes the field worth anything behind a load
/// balancer: the id rides the call token, not process memory, so a fleet-wide
/// log still reassembles the call. A port that minted a fresh id per turn would
/// pass every single-worker test and produce one-record streams in production.
#[tokio::test]
async fn the_stream_id_survives_a_continuation_on_another_worker() {
    let first = Arc::new(Recorder::default());
    let state_a = build(first.clone());
    let body = post(
        &state_a,
        &format!("/{PROTOCOL}/{METHOD}/init"),
        init_body(4),
    )
    .await;
    let (cursor, call_token) = tokens(&body);
    let init_id = first.for_method(METHOD)[0].stream_id.clone();

    // A genuinely separate server process, standing in for the second worker a
    // load balancer might route the continuation to: its own `HttpState`, its
    // own in-process caches, its own recorder — sharing only the token-signing
    // key an operator configures fleet-wide.
    let second = Arc::new(Recorder::default());
    let state_b = build(second.clone());
    let _ = post(
        &state_b,
        &format!("/{PROTOCOL}/{METHOD}/exchange"),
        continuation_body(&cursor.unwrap(), &call_token.unwrap()),
    )
    .await;

    let cont = second.for_method(METHOD);
    assert_eq!(cont.len(), 1, "the continuation owes exactly one record");
    assert_eq!(
        cont[0].stream_id, init_id,
        "a continuation must file under the stream_id /init minted, not a fresh \
         one: the id rides the call token precisely so a turn handled elsewhere \
         still joins the call it belongs to"
    );
}

/// `request_data` belongs to the init record alone: a continuation's body is a
/// cursor, not the call's arguments, and logging it every turn would multiply
/// the payload by the length of the stream while adding nothing.
#[tokio::test]
async fn request_data_is_carried_by_the_init_record_only() {
    let hook = Arc::new(Recorder::default());
    let state = build(hook.clone());
    let records = drive_to_completion(&hook, &state).await;

    assert!(
        !records.is_empty(),
        "the stream produced no access records at all"
    );
    assert!(
        records[0].request_data_len > 0,
        "the init record must carry the call's request payload"
    );
    for rec in &records[1..] {
        assert_eq!(
            rec.request_data_len, 0,
            "a continuation record must not carry request_data"
        );
    }
}

/// `response_state` marks a turn as resumable, so its absence is what marks the
/// terminal one. A port that stamped it on every turn would leave a reader
/// unable to tell where a stream ended.
#[tokio::test]
async fn response_state_is_present_while_the_stream_is_resumable() {
    let hook = Arc::new(Recorder::default());
    let state = build(hook.clone());
    let records = drive_to_completion(&hook, &state).await;

    assert!(
        !records.is_empty(),
        "the stream produced no access records at all"
    );
    let (terminal, resumable) = records.split_last().unwrap();
    for rec in resumable {
        assert!(
            rec.response_state_len > 0,
            "a turn that handed back a continuation token must log the state it \
             handed back: {rec:?}"
        );
    }
    assert_eq!(
        terminal.response_state_len, 0,
        "the terminal turn hands back no cursor, so it must log no \
         response_state -- that absence is how a reader finds the end of a stream"
    );
}

/// Identity comes from the resolved binding, never stamped at the emit site.
#[tokio::test]
async fn a_stream_record_names_its_own_protocol() {
    let hook = Arc::new(Recorder::default());
    let state = build(hook.clone());
    let records = drive_to_completion(&hook, &state).await;
    // Asserted before the loop: a `for` over an empty vec is the exact shape of
    // vacuous pass this whole file exists to rule out.
    assert!(
        !records.is_empty(),
        "the stream produced no access records at all"
    );
    for rec in &records {
        assert_eq!(rec.protocol, PROTOCOL);
        assert!(
            !rec.protocol_hash.is_empty(),
            "protocol_hash is the registry key for decoding an archived record"
        );
    }
}

/// Rows are attributed to the turn that produced them, not to the whole call.
#[tokio::test]
async fn output_rows_are_counted_per_turn() {
    let hook = Arc::new(Recorder::default());
    let state = build(hook.clone());
    let records = drive_to_completion(&hook, &state).await;
    let total: u64 = records.iter().map(|r| r.output_rows).sum();
    assert_eq!(
        total, 2,
        "count_to(2) emits one row per turn for two turns; the records' \
         output_rows must add up to what the stream actually produced"
    );
}
