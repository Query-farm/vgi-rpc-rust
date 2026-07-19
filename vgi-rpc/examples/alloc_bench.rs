//! In-process allocation + latency benchmark for the server dispatch and
//! wire hot paths. Not shipped; used to measure the effect of the
//! allocation-reduction work (findings in the perf review).
//!
//! Run: `cargo run --release --example alloc_bench`
//!
//! A counting global allocator tallies allocation count + bytes so we can
//! report allocations-per-op deterministically (the metric the perf work
//! targets), alongside wall-clock ns/op.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arrow_array::{Int64Array, RecordBatch, RecordBatchOptions};
use arrow_schema::{DataType, Field, Schema};
use vgi_rpc::metadata::{REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY};
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult};
use vgi_rpc::wire::{Metadata, StreamWriter};
use vgi_rpc::{CallContext, LogLevel, MethodInfo, MethodType, Request, RpcServer};

// ---- counting allocator ---------------------------------------------------

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn snapshot() -> (u64, u64) {
    (
        ALLOCS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    )
}

// ---- a trivial producer ---------------------------------------------------

struct CountTo {
    count: i64,
    cur: i64,
}

impl ProducerState for CountTo {
    fn produce(
        &mut self,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<(), vgi_rpc::RpcError> {
        if self.cur >= self.count {
            out.finish();
            return Ok(());
        }
        let batch = RecordBatch::try_new(
            producer_schema(),
            vec![Arc::new(Int64Array::from(vec![self.cur]))],
        )?;
        out.emit(batch)?;
        self.cur += 1;
        Ok(())
    }
}

fn producer_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]))
}

/// A producer that emits one client log line per tick — exercises the
/// per-envelope metadata path (`EnvelopeMeta`).
struct CountToLogging {
    count: i64,
    cur: i64,
}

impl ProducerState for CountToLogging {
    fn produce(
        &mut self,
        out: &mut OutputCollector,
        ctx: &CallContext,
    ) -> Result<(), vgi_rpc::RpcError> {
        if self.cur >= self.count {
            out.finish();
            return Ok(());
        }
        ctx.client_log(LogLevel::Info, "tick");
        let batch = RecordBatch::try_new(
            producer_schema(),
            vec![Arc::new(Int64Array::from(vec![self.cur]))],
        )?;
        out.emit(batch)?;
        self.cur += 1;
        Ok(())
    }
}

// ---- request/tick encoding ------------------------------------------------

fn empty_schema() -> Arc<Schema> {
    Arc::new(Schema::empty())
}

/// A one-row, zero-column request stream carrying method + version metadata.
fn encode_request(method: &str) -> Vec<u8> {
    let schema = empty_schema();
    let batch = RecordBatch::try_new_with_options(
        schema.clone(),
        vec![],
        &RecordBatchOptions::new().with_row_count(Some(1)),
    )
    .unwrap();
    let mut md = Metadata::new();
    md.insert(RPC_METHOD_KEY.into(), method.into());
    md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// A stream of `n` empty tick batches (producer continuation ticks), each
/// carrying a small non-empty metadata map so the server's read-side
/// metadata parse is exercised realistically.
fn encode_ticks(n: usize) -> Vec<u8> {
    let schema = empty_schema();
    let batch = RecordBatch::try_new_with_options(
        schema.clone(),
        vec![],
        &RecordBatchOptions::new().with_row_count(Some(0)),
    )
    .unwrap();
    let mut md = Metadata::new();
    md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref()).unwrap();
        for _ in 0..n {
            w.write(&batch, Some(&md)).unwrap();
        }
        w.finish().unwrap();
    }
    buf
}

fn build_server() -> RpcServer {
    let mut server = RpcServer::new("bench-server");
    let empty = empty_schema();
    // Unary noop: returns nothing (like the benchmark `noop`).
    server.register(MethodInfo::unary(
        "noop",
        empty.clone(),
        empty.clone(),
        |_req: &Request, _ctx: &CallContext| Ok(None),
    ));
    // Producer emitting `count` single-row batches.
    server.register(MethodInfo::stream(
        "count_to",
        MethodType::Producer,
        empty.clone(),
        |_req: &Request, _ctx: &CallContext| {
            Ok(StreamResult::producer(
                producer_schema(),
                Box::new(CountTo { count: 64, cur: 0 }),
            ))
        },
    ));
    // Producer that also logs one line per tick (exercises EnvelopeMeta).
    server.register(MethodInfo::stream(
        "count_to_logging",
        MethodType::Producer,
        empty.clone(),
        |_req: &Request, _ctx: &CallContext| {
            Ok(StreamResult::producer(
                producer_schema(),
                Box::new(CountToLogging { count: 64, cur: 0 }),
            ))
        },
    ));
    server
}

fn bench<F: FnMut()>(name: &str, iters: u64, ops_per_iter: u64, mut f: F) {
    // warmup
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let (a0, b0) = snapshot();
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    let dt = t0.elapsed();
    let (a1, b1) = snapshot();
    let total_ops = iters * ops_per_iter;
    let allocs = a1 - a0;
    let bytes = b1 - b0;
    println!(
        "{name:<24} {:>10.1} allocs/op  {:>12.1} bytes/op  {:>10.0} ns/op",
        allocs as f64 / total_ops as f64,
        bytes as f64 / total_ops as f64,
        dt.as_nanos() as f64 / total_ops as f64,
    );
}

fn main() {
    let server = build_server();

    // ---- unary noop ----
    let noop_req = encode_request("noop");
    let mut sink: Vec<u8> = Vec::with_capacity(4096);
    bench("unary noop", 50_000, 1, || {
        let mut r = Cursor::new(noop_req.as_slice());
        sink.clear();
        server.serve_one(&mut r, &mut sink).unwrap();
    });

    // ---- producer: 64 emitted batches per stream ----
    // Feed enough ticks to drive all 64 produce() calls plus the finishing one.
    let prod_input = {
        let mut v = encode_request("count_to");
        v.extend_from_slice(&encode_ticks(66));
        v
    };
    let mut sink2: Vec<u8> = Vec::with_capacity(1 << 16);
    // ops = number of produced batches (64) so the report is per-tick.
    bench("producer 64-tick", 5_000, 64, || {
        let mut r = Cursor::new(prod_input.as_slice());
        sink2.clear();
        server.serve_one(&mut r, &mut sink2).unwrap();
    });

    // ---- producer that logs one line per tick (exercises EnvelopeMeta) ----
    let log_input = {
        let mut v = encode_request("count_to_logging");
        v.extend_from_slice(&encode_ticks(66));
        v
    };
    let mut sink3: Vec<u8> = Vec::with_capacity(1 << 16);
    bench("producer 64-tick +log", 5_000, 64, || {
        let mut r = Cursor::new(log_input.as_slice());
        sink3.clear();
        server.serve_one(&mut r, &mut sink3).unwrap();
    });

    println!("\n(metadata is HashMap<String,String>; allocs include per-string.)");
}
