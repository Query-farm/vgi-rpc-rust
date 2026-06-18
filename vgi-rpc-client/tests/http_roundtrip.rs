//! In-process HTTP round-trip tests: a real axum `vgi_rpc::http` server on a
//! background tokio runtime, driven by the blocking `HttpClient`. Covers
//! unary, describe, capabilities, and a finite producer (drained in the init
//! response via `producer_batch_limit(0)` — no continuation token, so no
//! state decoder is required). Producer-continuation and exchange-over-HTTP
//! need state codecs and are covered by the Phase 2 conformance harness
//! against the real worker.

#![cfg(feature = "http")]

use std::sync::Arc;
use std::thread;

use arrow_array::cast::AsArray;
use arrow_array::types::Int64Type;
use arrow_array::{Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use vgi_rpc::http::{build_router, HttpState};
use vgi_rpc::server::{MethodInfo, MethodType, RpcServer};
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult};
use vgi_rpc::{CallContext, Result};
use vgi_rpc_client::HttpClient;

fn utf8_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Utf8, false)]))
}
fn i64_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Int64, false)]))
}

struct CountTo {
    n: i64,
    cur: i64,
    schema: SchemaRef,
}
impl ProducerState for CountTo {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.n {
            out.finish();
            return Ok(());
        }
        let b = RecordBatch::try_new(
            self.schema.clone(),
            vec![Arc::new(Int64Array::from(vec![self.cur]))],
        )?;
        self.cur += 1;
        out.emit(b)
    }
}

fn build_server() -> RpcServer {
    let mut srv = RpcServer::builder().enable_describe(true).build();
    let r = utf8_schema("result");
    let r2 = r.clone();
    srv.register(MethodInfo::unary(
        "echo_string",
        utf8_schema("value"),
        r,
        move |req, _ctx| {
            let v = req
                .column("value")
                .unwrap()
                .as_string::<i32>()
                .value(0)
                .to_string();
            Ok(Some(RecordBatch::try_new(
                r2.clone(),
                vec![Arc::new(StringArray::from(vec![format!("echo: {v}")]))],
            )?))
        },
    ));
    let os = i64_schema("value");
    srv.register(MethodInfo::stream(
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
                os.clone(),
                Box::new(CountTo {
                    n,
                    cur: 0,
                    schema: os.clone(),
                }),
            ))
        },
    ));
    srv
}

/// Start the server on a background runtime; return the bound port.
fn start_server() -> u16 {
    let state = HttpState::builder()
        .server(Arc::new(build_server()))
        .producer_batch_limit(0) // drain finite producers in the init response
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

#[test]
fn http_unary_describe_capabilities() {
    let port = start_server();
    let mut c = client(port);

    let params = RecordBatch::try_new(
        utf8_schema("value"),
        vec![Arc::new(StringArray::from(vec!["hi"]))],
    )
    .unwrap();
    let (batch, _md) = c.call_unary("echo_string", &params, None).unwrap();
    assert_eq!(batch.column(0).as_string::<i32>().value(0), "echo: hi");

    let desc = c.describe().unwrap();
    assert_eq!(desc.describe_version, "4");
    assert!(desc.methods.contains_key("echo_string"));

    // Capabilities probe should succeed (sticky disabled here).
    let caps = c.capabilities().unwrap();
    assert!(!caps.sticky_enabled);
}

#[test]
fn http_producer_finite() {
    let port = start_server();
    let mut c = client(port);
    let params = RecordBatch::try_new(
        i64_schema("n"),
        vec![Arc::new(Int64Array::from(vec![4i64]))],
    )
    .unwrap();
    let mut got = Vec::new();
    {
        let mut session = c.open_producer("count_to", &params, None, false).unwrap();
        while let Some((batch, _md)) = session.tick().unwrap() {
            got.push(batch.column(0).as_primitive::<Int64Type>().value(0));
        }
    }
    assert_eq!(got, vec![0, 1, 2, 3]);
}
