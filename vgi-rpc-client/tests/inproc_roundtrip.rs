//! In-process round-trip tests: a real `vgi_rpc::RpcServer` on a background
//! thread, driven by the blocking `RpcClient` over a socketpair. Exercises
//! unary, producer, exchange, cancel, describe, and transport_options without
//! needing an external worker binary.

#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use arrow_array::cast::AsArray;
use arrow_array::types::Int64Type;
use arrow_array::{Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use vgi_rpc::server::{MethodInfo, MethodType, RpcServer};
use vgi_rpc::stream::{ExchangeState, OutputCollector, ProducerState, StreamResult};
use vgi_rpc::{CallContext, Result};
use vgi_rpc_client::{PipeTransport, RpcClient};

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
        out.emit(b)?;
        Ok(())
    }
}

struct Forever {
    schema: SchemaRef,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}
impl ProducerState for Forever {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        out.emit(RecordBatch::try_new(
            self.schema.clone(),
            vec![Arc::new(Int64Array::from(vec![1i64]))],
        )?)
    }
    fn on_cancel(&mut self, _ctx: &CallContext) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

struct Double {
    schema: SchemaRef,
}
impl ExchangeState for Double {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        let col = input.column(0).as_primitive::<Int64Type>();
        let vals: Vec<i64> = (0..col.len()).map(|i| col.value(i) * 2).collect();
        out.emit(RecordBatch::try_new(
            self.schema.clone(),
            vec![Arc::new(Int64Array::from(vals))],
        )?)
    }
}

fn build_server(cancel_flag: Arc<std::sync::atomic::AtomicBool>) -> RpcServer {
    let mut srv = RpcServer::builder().enable_describe(true).build();

    let p = utf8_schema("value");
    let r = utf8_schema("result");
    let r2 = r.clone();
    srv.register(MethodInfo::unary("echo_string", p, r, move |req, _ctx| {
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
    }));

    let out_schema = i64_schema("value");
    let os = out_schema.clone();
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

    let ds = out_schema.clone();
    srv.register(MethodInfo::stream(
        "double",
        MethodType::Exchange,
        Arc::new(Schema::empty()),
        move |_req, _ctx| {
            Ok(StreamResult::exchange(
                ds.clone(),
                ds.clone(),
                Box::new(Double { schema: ds.clone() }),
            ))
        },
    ));

    let fs = out_schema.clone();
    let cf = cancel_flag;
    srv.register(MethodInfo::stream(
        "forever",
        MethodType::Producer,
        Arc::new(Schema::empty()),
        move |_req, _ctx| {
            Ok(StreamResult::producer(
                fs.clone(),
                Box::new(Forever {
                    schema: fs.clone(),
                    cancelled: cf.clone(),
                }),
            ))
        },
    ));

    srv
}

fn connect() -> (
    RpcClient,
    thread::JoinHandle<()>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let (client_sock, server_sock) = UnixStream::pair().unwrap();
    let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cf = cancel_flag.clone();
    let handle = thread::spawn(move || {
        let srv = build_server(cf);
        let r = server_sock.try_clone().unwrap();
        let w = server_sock;
        srv.serve(r, w);
    });
    let client_read = client_sock.try_clone().unwrap();
    let transport = PipeTransport::new(Box::new(client_read), Box::new(client_sock));
    (
        RpcClient::from_transport(Box::new(transport)),
        handle,
        cancel_flag,
    )
}

#[test]
fn unary_echo() {
    let (mut client, handle, _) = connect();
    let params = RecordBatch::try_new(
        utf8_schema("value"),
        vec![Arc::new(StringArray::from(vec!["world"]))],
    )
    .unwrap();
    let (batch, _md) = client.call_unary("echo_string", &params, None).unwrap();
    assert_eq!(batch.column(0).as_string::<i32>().value(0), "echo: world");
    drop(client);
    handle.join().unwrap();
}

#[test]
fn producer_stream() {
    let (mut client, handle, _) = connect();
    let params = RecordBatch::try_new(
        i64_schema("n"),
        vec![Arc::new(Int64Array::from(vec![5i64]))],
    )
    .unwrap();
    let mut got = Vec::new();
    {
        let mut session = client
            .open_producer("count_to", &params, None, false)
            .unwrap();
        while let Some((batch, _md)) = session.tick().unwrap() {
            got.push(batch.column(0).as_primitive::<Int64Type>().value(0));
        }
    }
    assert_eq!(got, vec![0, 1, 2, 3, 4]);
    drop(client);
    handle.join().unwrap();
}

#[test]
fn exchange_stream() {
    let (mut client, handle, _) = connect();
    let params = vgi_rpc::wire::empty_batch(&Schema::empty()).unwrap();
    {
        let mut session = client
            .open_exchange("double", &params, None, false)
            .unwrap();
        for v in [3i64, 7, 11] {
            let input = RecordBatch::try_new(
                i64_schema("value"),
                vec![Arc::new(Int64Array::from(vec![v]))],
            )
            .unwrap();
            let (out, _md) = session.exchange(&input, None).unwrap().unwrap();
            assert_eq!(out.column(0).as_primitive::<Int64Type>().value(0), v * 2);
        }
    }
    drop(client);
    handle.join().unwrap();
}

#[test]
fn cancel_producer() {
    let (mut client, handle, cancel_flag) = connect();
    let params = vgi_rpc::wire::empty_batch(&Schema::empty()).unwrap();
    {
        let mut session = client
            .open_producer("forever", &params, None, false)
            .unwrap();
        for _ in 0..3 {
            assert!(session.tick().unwrap().is_some());
        }
        session.cancel().unwrap();
        // Post-cancel tick must raise ProtocolError.
        assert!(session.tick().is_err());
    }
    assert!(cancel_flag.load(std::sync::atomic::Ordering::SeqCst));
    drop(client);
    handle.join().unwrap();
}

#[test]
fn describe_and_transport_options() {
    let (mut client, handle, _) = connect();
    let desc = client.describe().unwrap();
    assert_eq!(desc.describe_version, "4");
    assert!(desc.methods.contains_key("echo_string"));
    assert_eq!(desc.method("count_to").unwrap().method_type, "stream");
    let opts = client.transport_options().unwrap();
    // No shm feature in this test build.
    assert!(!opts.shm || opts.raw.contains_key("vgi_rpc.transport.shm"));
    drop(client);
    handle.join().unwrap();
}
