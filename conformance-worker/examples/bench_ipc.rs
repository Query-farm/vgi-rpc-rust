//! In-memory IPC microbench: serialize + deserialize a Float64 batch
//! through `arrow_ipc`'s reader/writer with no transport. Apples-to-
//! apples ceiling against `scripts/bench_ipc.py` (pyarrow).
//!
//! Run: `cargo run --release --example bench_ipc -p vgi-rpc-conformance-rust`

use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

use arrow_array::{Float64Array, RecordBatch};
use arrow_ipc::reader::StreamReader;
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{DataType, Field, Schema};

const SIZES: &[usize] = &[1_000, 100_000, 1_000_000, 10_000_000];
const ITERS: usize = 50;

fn make_batch(rows: usize) -> RecordBatch {
    let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Float64, true)]));
    let arr = Float64Array::from((0..rows).map(|i| i as f64).collect::<Vec<_>>());
    RecordBatch::try_new(schema, vec![Arc::new(arr)]).unwrap()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    println!(
        "{:>10} {:>12} {:>8} {:>8}",
        "rows", "phase", "med_ms", "GB/s"
    );
    for &rows in SIZES {
        let batch = make_batch(rows);
        let bytes_per_batch = rows * 8;

        // Serialize
        let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(ITERS);
        let mut ts = Vec::with_capacity(ITERS);
        for _ in 0..ITERS {
            let mut buf = Vec::with_capacity(bytes_per_batch + 4096);
            let t0 = Instant::now();
            {
                let mut w = StreamWriter::try_new(&mut buf, batch.schema_ref()).unwrap();
                w.write(&batch).unwrap();
                w.finish().unwrap();
            }
            ts.push(t0.elapsed().as_secs_f64() * 1000.0);
            bufs.push(buf);
        }
        let ms = median(ts);
        println!(
            "{rows:>10} {:>12} {ms:>8.3} {:>8.2}",
            "serialize",
            bytes_per_batch as f64 / (ms / 1000.0) / 1e9
        );

        // Deserialize via StreamReader (Read source — copies)
        let mut ts = Vec::with_capacity(ITERS);
        for buf in &bufs {
            let t0 = Instant::now();
            let mut r = StreamReader::try_new(Cursor::new(buf.as_slice()), None).unwrap();
            let _ = r.next().unwrap().unwrap();
            ts.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let ms = median(ts);
        println!(
            "{rows:>10} {:>12} {ms:>8.3} {:>8.2}",
            "deser_read",
            bytes_per_batch as f64 / (ms / 1000.0) / 1e9
        );

        // Deserialize via StreamDecoder + Buffer::from_vec (zero-copy)
        let mut ts = Vec::with_capacity(ITERS);
        for buf in &bufs {
            let owned = arrow_buffer::Buffer::from_vec(buf.clone());
            let mut b = owned;
            let t0 = Instant::now();
            let mut decoder = arrow_ipc::reader::StreamDecoder::new();
            let _batch = loop {
                if let Some(rb) = decoder.decode(&mut b).unwrap() {
                    break rb;
                }
                if b.is_empty() {
                    panic!("buffer drained without batch");
                }
            };
            ts.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let ms = median(ts);
        println!(
            "{rows:>10} {:>12} {ms:>8.3} {:>8.2}",
            "deser_buffer",
            bytes_per_batch as f64 / (ms / 1000.0) / 1e9
        );
    }
}
