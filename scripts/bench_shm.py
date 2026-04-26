#!/usr/bin/env python3
"""Microbench: SHM transport vs plain stdio against the Rust conformance worker.

Drives `exchange_scale(factor=1.0)` round-trips with a tunable batch
shape (rows x columns of float64) and prints rows/sec, MB/sec, and
median round-trip latency for both transports.
"""
import argparse
import contextlib
import statistics
import time
from pathlib import Path

import pyarrow as pa
from vgi_rpc.conformance import ConformanceService
from vgi_rpc.rpc import AnnotatedBatch, SubprocessTransport, _RpcProxy
from vgi_rpc.shm import ShmSegment


class _ShmAdapter:
    __slots__ = ("_inner", "_shm")

    def __init__(self, inner, shm):
        self._inner = inner
        self._shm = shm

    @property
    def reader(self):
        return self._inner.reader

    @property
    def writer(self):
        return self._inner.writer

    @property
    def shm(self):
        return self._shm

    def close(self):
        self._inner.close()


def make_batch(rows: int) -> AnnotatedBatch:
    return AnnotatedBatch(
        batch=pa.RecordBatch.from_arrays(
            [pa.array([float(i) for i in range(rows)], type=pa.float64())],
            schema=pa.schema([pa.field("value", pa.float64(), nullable=True)]),
        )
    )


def run(*, worker_cmd: list, rows: int, iters: int, use_shm: bool, shm_size_mb: int) -> dict:
    inner = SubprocessTransport(worker_cmd)
    shm = None
    try:
        if use_shm:
            shm = ShmSegment.create(shm_size_mb * 1024 * 1024)
            transport = _ShmAdapter(inner, shm)
        else:
            transport = inner
        proxy = _RpcProxy(ConformanceService, transport, None)
        sample = make_batch(rows)
        # Warmup to prime allocators / page caches.
        with proxy.exchange_scale(factor=1.0) as session:
            for _ in range(5):
                session.exchange(sample)
        latencies = []
        with proxy.exchange_scale(factor=1.0) as session:
            for _ in range(iters):
                t0 = time.perf_counter()
                out = session.exchange(sample)
                t1 = time.perf_counter()
                assert out.batch.num_rows == rows
                latencies.append((t1 - t0) * 1000.0)
        bytes_per_batch = rows * 8  # float64
        total_bytes = bytes_per_batch * iters * 2  # round-trip
        total_s = sum(latencies) / 1000.0
        return {
            "transport": "shm_pipe" if use_shm else "pipe",
            "rows": rows,
            "iters": iters,
            "median_ms": statistics.median(latencies),
            "p10_ms": statistics.quantiles(latencies, n=10)[0],
            "p90_ms": statistics.quantiles(latencies, n=10)[8],
            "throughput_rows_per_s": rows * iters / total_s,
            "throughput_MB_per_s": total_bytes / 1e6 / total_s,
        }
    finally:
        inner.close()
        if shm is not None:
            with contextlib.suppress(BufferError):
                shm.close()
            shm.unlink()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rows", type=int, action="append",
                   help="Rows per batch (repeatable). Default: 1k, 16k, 256k, 1M")
    p.add_argument("--iters", type=int, default=200)
    p.add_argument("--shm-size-mb", type=int, default=64)
    p.add_argument("--worker", default=str(
        Path(__file__).resolve().parent.parent / "target" / "release" / "vgi-rpc-conformance-rust"
    ))
    p.add_argument("--python-worker", action="store_true",
                   help="Bench against the Python conformance worker for comparison")
    args = p.parse_args()
    sizes = args.rows or [1_000, 16_000, 256_000, 1_000_000]
    if args.python_worker:
        import sys as _sys
        worker_cmd = [_sys.executable, str(
            Path(__file__).resolve().parent.parent.parent / "vgi-rpc" / "tests" / "serve_conformance_pipe.py"
        )]
        worker_label = "py-worker"
    else:
        worker_cmd = [args.worker]
        worker_label = "rust-worker"

    print(f"# worker = {worker_label} ({' '.join(worker_cmd)})")
    print(f"{'rows':>8} {'transport':>10} {'iters':>6} "
          f"{'med_ms':>8} {'p10_ms':>8} {'p90_ms':>8} "
          f"{'M_rows/s':>10} {'MB/s':>10}")
    for rows in sizes:
        for use_shm in (False, True):
            r = run(worker_cmd=worker_cmd, rows=rows, iters=args.iters,
                    use_shm=use_shm, shm_size_mb=args.shm_size_mb)
            print(f"{r['rows']:>8} {r['transport']:>10} {r['iters']:>6} "
                  f"{r['median_ms']:>8.3f} {r['p10_ms']:>8.3f} {r['p90_ms']:>8.3f} "
                  f"{r['throughput_rows_per_s']/1e6:>10.2f} "
                  f"{r['throughput_MB_per_s']:>10.1f}")


if __name__ == "__main__":
    main()
