#!/usr/bin/env python3
"""In-memory IPC microbench: serialize + deserialize a Float64 batch
through pyarrow's reader/writer with no transport. Establishes a
ceiling for a Python-side comparison number against an equivalent
arrow-rs benchmark."""
import io
import statistics
import time

import pyarrow as pa
from pyarrow import ipc

SIZES = [1_000, 100_000, 1_000_000, 10_000_000]
ITERS = 50


def main() -> None:
    print(f"{'rows':>10} {'phase':>12} {'med_ms':>8} {'GB/s':>8}")
    for rows in SIZES:
        batch = pa.RecordBatch.from_arrays(
            [pa.array([float(i) for i in range(rows)], type=pa.float64())],
            schema=pa.schema([pa.field("v", pa.float64())]),
        )
        bytes_per_batch = rows * 8

        # Serialize
        ts = []
        bufs = []
        for _ in range(ITERS):
            sink = pa.BufferOutputStream()
            t0 = time.perf_counter()
            with ipc.new_stream(sink, batch.schema) as w:
                w.write_batch(batch)
            ts.append(time.perf_counter() - t0)
            bufs.append(sink.getvalue())
        ms = statistics.median(ts) * 1000
        print(f"{rows:>10} {'serialize':>12} {ms:>8.3f} "
              f"{bytes_per_batch / (ms/1000) / 1e9:>8.2f}")

        # Deserialize
        ts = []
        for buf in bufs:
            t0 = time.perf_counter()
            r = ipc.open_stream(buf)
            _ = r.read_next_batch()
            ts.append(time.perf_counter() - t0)
        ms = statistics.median(ts) * 1000
        print(f"{rows:>10} {'deserialize':>12} {ms:>8.3f} "
              f"{bytes_per_batch / (ms/1000) / 1e9:>8.2f}")


if __name__ == "__main__":
    main()
