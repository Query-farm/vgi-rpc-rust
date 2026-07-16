//! Continuation-only stream resume: `HttpClient::resume_stream` constructs a
//! session positioned at a continuation token without a bind/init round-trip
//! (the server recovers producer state, schemas, and function identity from
//! the signed token alone), and `next_with_token` yields one `(batch, token)`
//! per call — the basis for a stateless relay that holds a per-batch token.
//! Mirrors Python `_HttpProxy.resume_stream` / `next_with_token` /
//! `seek_to_token` (vgi-rpc c8426f8).

#![cfg(feature = "http")]

use std::sync::Arc;
use std::thread;

use arrow_array::cast::AsArray;
use arrow_array::types::Int64Type;
use arrow_array::{Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use vgi_rpc::http::{build_router, HttpState};
use vgi_rpc::server::{MethodInfo, MethodType, RpcServer, StateDecoder};
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult, StreamStateKind};
use vgi_rpc::stream_codec::StreamStateCodec;
use vgi_rpc::{CallContext, Result, RpcError};
use vgi_rpc_client::HttpClient;

fn i64_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Int64, false)]))
}

struct CountTo {
    n: i64,
    cur: i64,
}

// Hand-rolled 16-byte LE codec — the client crate's dev-deps carry no serde.
impl StreamStateCodec for CountTo {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&self.n.to_le_bytes());
        buf.extend_from_slice(&self.cur.to_le_bytes());
        Ok(buf)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 16 {
            return Err(RpcError::protocol_error("bad CountTo state"));
        }
        Ok(CountTo {
            n: i64::from_le_bytes(bytes[..8].try_into().unwrap()),
            cur: i64::from_le_bytes(bytes[8..].try_into().unwrap()),
        })
    }
}

impl ProducerState for CountTo {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.n {
            out.finish();
            return Ok(());
        }
        let b = RecordBatch::try_new(
            i64_schema("value"),
            vec![Arc::new(Int64Array::from(vec![self.cur]))],
        )?;
        self.cur += 1;
        out.emit(b)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

fn producer_decoder() -> StateDecoder {
    Arc::new(|bytes: &[u8]| Ok(StreamStateKind::Producer(Box::new(CountTo::decode(bytes)?))))
}

fn build_server() -> RpcServer {
    let mut srv = RpcServer::builder().build();
    srv.register(
        MethodInfo::stream(
            "count_to",
            MethodType::Producer,
            i64_schema("n"),
            move |req, _ctx| {
                let n = req
                    .column("n")
                    .unwrap()
                    .as_primitive::<Int64Type>()
                    .value(0);
                Ok(StreamResult::producer(
                    i64_schema("value"),
                    Box::new(CountTo { n, cur: 0 }),
                ))
            },
        )
        .with_state_decoder(producer_decoder()),
    );
    srv
}

/// Start the server on a background runtime with per-batch continuation
/// tokens (producer_batch_limit(1)); return the bound port.
fn start_server() -> u16 {
    let state = HttpState::builder()
        .server(Arc::new(build_server()))
        .token_key(&[0x42u8; 32])
        .producer_batch_limit(1)
        .build();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tx.send(port).unwrap();
            axum::serve(listener, build_router(state)).await.unwrap();
        });
    });
    rx.recv().unwrap()
}

fn client(port: u16) -> HttpClient {
    HttpClient::connect(format!("http://127.0.0.1:{port}"))
        .build()
        .unwrap()
}

fn params(n: i64) -> RecordBatch {
    RecordBatch::try_new(i64_schema("n"), vec![Arc::new(Int64Array::from(vec![n]))]).unwrap()
}

fn value_of(batch: &RecordBatch) -> i64 {
    batch.column(0).as_primitive::<Int64Type>().value(0)
}

/// Walk the stream batch-by-batch via `next_with_token`, resuming each step
/// on a *fresh* session constructed from the previous step's token — the
/// stateless-relay pattern.
#[test]
fn resume_stream_continues_from_a_per_batch_token() {
    let port = start_server();

    // First turn: a real init. producer_batch_limit(1) → one batch + token.
    let mut c = client(port);
    let mut session = c
        .open_producer("count_to", &params(3), None, false)
        .unwrap();
    let (first, token) = session.next_with_token().unwrap().expect("first batch");
    assert_eq!(value_of(&first.0), 0);
    let mut token = token.expect("per-batch continuation token");

    // Every later turn: continuation-only resume, no init round-trip —
    // a brand-new session (as a relay on another node would build).
    let mut values = vec![value_of(&first.0)];
    loop {
        let mut c = client(port);
        let mut resumed = c.resume_stream("count_to", token.clone());
        match resumed.next_with_token().unwrap() {
            Some((item, next)) => {
                values.push(value_of(&item.0));
                match next {
                    Some(t) => token = t,
                    None => {
                        // Final data batch arrived without a refreshed token —
                        // the stream is complete.
                        assert_eq!(resumed.next_with_token().unwrap(), None);
                        break;
                    }
                }
            }
            None => break,
        }
    }
    assert_eq!(values, vec![0, 1, 2]);
}

/// `seek_to_token` repositions an existing session: drop its preloaded
/// batches and continue from the supplied token.
#[test]
fn seek_to_token_repositions_an_initialised_session() {
    let port = start_server();
    let mut c = client(port);

    let mut session = c
        .open_producer("count_to", &params(3), None, false)
        .unwrap();
    let (_first, token) = session.next_with_token().unwrap().expect("first batch");
    let token = token.expect("token");

    // A second, fresh init has batch 0 preloaded; seek discards it and
    // resumes after batch 0 instead.
    let mut c2 = client(port);
    let mut session2 = c2
        .open_producer("count_to", &params(3), None, false)
        .unwrap();
    session2.seek_to_token(token);
    let (item, _next) = session2.next_with_token().unwrap().expect("resumed batch");
    assert_eq!(value_of(&item.0), 1, "seek skips the preloaded first batch");
}
