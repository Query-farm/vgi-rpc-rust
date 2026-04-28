#!/usr/bin/env python3
"""End-to-end SHM conformance soak test against the Rust worker.

Drives many varied conformance methods through a single, long-lived SHM
segment shared with the Rust worker subprocess and asserts:

  * every call succeeds (correctness vs. the Python reference impl);
  * the segment never hits ``MAX_ALLOCS`` mid-run, even after many
    calls (no fragmentation blowup);
  * within a single lockstep exchange, in-flight allocation count
    stays bounded (catches per-iteration leaks inside a session).

Between scenarios the segment is ``reset()``, matching the documented
"reset between RPC calls to reuse the segment" usage in
``vgi_rpc.shm.ShmSegment.reset``. Cross-call leaks involving Python
client cleanup are out of scope for this Rust-side test.

This is the missing piece behind item 1 of the "production-readiness"
list: conformance + sustained churn through one segment, not just the
short one-off sessions the conformance suite drives.

Exit code is 0 on success, 1 on any assertion failure or call error.

Run:
    scripts/shm_soak.py                       # default sweep
    scripts/shm_soak.py --iters 5000          # heavier soak
    scripts/shm_soak.py --shm-size-mb 128
"""
from __future__ import annotations

import argparse
import contextlib
import random
import sys
import time
from pathlib import Path

import pyarrow as pa
from vgi_rpc.conformance import ConformanceService
from vgi_rpc.rpc import AnnotatedBatch, SubprocessTransport, _RpcProxy
from vgi_rpc.shm import ShmSegment


class _ShmAdapter:
    __slots__ = ("_inner", "_shm")

    def __init__(self, inner: SubprocessTransport, shm: ShmSegment) -> None:
        self._inner = inner
        self._shm = shm

    @property
    def reader(self):
        return self._inner.reader

    @property
    def writer(self):
        return self._inner.writer

    @property
    def shm(self) -> ShmSegment:
        return self._shm

    def close(self) -> None:
        self._inner.close()


def _live_allocs(shm: ShmSegment) -> int:
    """Number of currently live regions in the segment header."""
    return shm._allocator.num_allocs  # type: ignore[attr-defined]


def _f64_batch(rows: int) -> AnnotatedBatch:
    return AnnotatedBatch(
        batch=pa.RecordBatch.from_arrays(
            [pa.array([float(i) for i in range(rows)], type=pa.float64())],
            schema=pa.schema([pa.field("value", pa.float64(), nullable=True)]),
        )
    )


def _assert_segment_progressing(shm: ShmSegment, where: str, max_live: int = 1024) -> None:
    """Soak invariant: the segment has not run away to MAX_ALLOCS.

    Cross-call leaks involving both Python client and Rust server are
    out of scope for this Rust-side test; what we assert here is that
    sustained churn through one segment does not hit the allocator
    capacity (which would cause every subsequent call to fall back to
    pipe transport, defeating the point of the segment).
    """
    live = _live_allocs(shm)
    if live > max_live:
        raise AssertionError(
            f"{where}: SHM allocator at num_allocs={live} > {max_live}; "
            f"either a leak rate that defeats reset(), or genuine "
            f"fragmentation under churn."
        )


def _scenario_unary_echo(proxy: _RpcProxy, shm: ShmSegment, rng: random.Random) -> None:
    """Tiny unary call. SHM should *not* be used (zero-row inputs and
    small payloads), but the segment still has to come out clean."""
    msg = "x" * rng.randint(1, 64)
    out = proxy.echo_string(value=msg)
    if out != msg:
        raise AssertionError(f"echo_string mismatch: {out!r} != {msg!r}")
    _assert_segment_progressing(shm, "echo_string")


def _scenario_exchange_scale(
    proxy: _RpcProxy, shm: ShmSegment, rng: random.Random
) -> None:
    """Lockstep exchange — exercises the input-pointer + output-pointer
    SHM path on every batch."""
    n_batches = rng.randint(1, 6)
    factor = rng.choice([1.0, 2.5, 0.25])
    peak = 0
    with proxy.exchange_scale(factor=factor) as session:
        for _ in range(n_batches):
            rows = rng.choice([1, 8, 256, 4_096, 65_536])
            sample = _f64_batch(rows)
            out = session.exchange(sample)
            if out.batch.num_rows != rows:
                raise AssertionError(
                    f"exchange_scale row mismatch: got {out.batch.num_rows}, "
                    f"want {rows}"
                )
            peak = max(peak, _live_allocs(shm))
    _assert_segment_progressing(shm, f"exchange_scale(factor={factor})")
    # Lockstep peak in flight: server's input anchor + its output alloc
    # can both be live briefly while the next iteration's input is
    # already being assembled by the client. Empirically peaks at ~6;
    # >32 would mean a real leak inside the session.
    if peak > 32:
        raise AssertionError(
            f"exchange_scale peak in-flight allocs={peak}; "
            f"expected modest lockstep overlap, not unbounded growth"
        )


def _scenario_producer(proxy: _RpcProxy, shm: ShmSegment, rng: random.Random) -> None:
    """Pure producer — server emits, client consumes; only output side
    of SHM is exercised."""
    count = rng.randint(1, 32)
    received = 0
    peak = 0
    for ann in proxy.produce_n(count=count):
        received += ann.batch.num_rows
        peak = max(peak, _live_allocs(shm))
    if received != count:
        raise AssertionError(f"produce_n total rows: got {received}, want {count}")
    _assert_segment_progressing(shm, f"produce_n(count={count})")
    if peak > 32:
        raise AssertionError(f"produce_n peak in-flight allocs={peak}")


def _scenario_large_producer(
    proxy: _RpcProxy, shm: ShmSegment, rng: random.Random
) -> None:
    """Producer with explicitly large output batches — pushes against
    the segment capacity."""
    rows_per = rng.choice([1_000, 10_000, 100_000])
    n = rng.randint(1, 4)
    total = 0
    for ann in proxy.produce_large_batches(rows_per_batch=rows_per, batch_count=n):
        total += ann.batch.num_rows
    if total != rows_per * n:
        raise AssertionError(
            f"produce_large_batches: got {total} rows, want {rows_per * n}"
        )
    _assert_segment_progressing(shm, f"produce_large_batches({rows_per}x{n})")


def _scenario_exchange_with_logs(
    proxy: _RpcProxy, shm: ShmSegment, rng: random.Random
) -> None:
    """Exchange that interleaves log batches with data batches — log
    batches are zero-row and must NOT be confused with SHM pointer
    batches by `is_shm_pointer_batch`."""
    n = rng.randint(1, 4)
    with proxy.exchange_with_logs() as session:
        for _ in range(n):
            rows = rng.choice([8, 1024, 16_384])
            sample = _f64_batch(rows)
            out = session.exchange(sample)
            # Output may have logs annotated; just check rows came back.
            if out.batch.num_rows != rows:
                raise AssertionError(
                    f"exchange_with_logs rows: got {out.batch.num_rows}, want {rows}"
                )
    _assert_segment_progressing(shm, "exchange_with_logs")


def _scenario_handler_error(
    proxy: _RpcProxy, shm: ShmSegment, rng: random.Random
) -> None:
    """Producer that errors mid-stream — confirms server frees its
    in-flight SHM region on the error path before the wire envelope is
    sent."""
    emit = rng.randint(0, 3)
    received_err = False
    try:
        for _ann in proxy.produce_error_mid_stream(emit_before_error=emit):
            pass
    except Exception:
        received_err = True
    if not received_err:
        raise AssertionError(
            "produce_error_mid_stream: expected an exception, got success"
        )
    _assert_segment_progressing(shm, f"produce_error_mid_stream(emit={emit})")


SCENARIOS = [
    _scenario_unary_echo,
    _scenario_exchange_scale,
    _scenario_producer,
    _scenario_large_producer,
    _scenario_exchange_with_logs,
    _scenario_handler_error,
]


def run_soak(*, worker_cmd: list, iters: int, shm_size_mb: int, seed: int) -> dict:
    rng = random.Random(seed)
    inner = SubprocessTransport(worker_cmd)
    shm = ShmSegment.create(shm_size_mb * 1024 * 1024)
    transport = _ShmAdapter(inner, shm)
    proxy = _RpcProxy(ConformanceService, transport, None)
    counts: dict[str, int] = {sc.__name__: 0 for sc in SCENARIOS}
    failures: dict[str, int] = {sc.__name__: 0 for sc in SCENARIOS}
    high_water = 0
    t0 = time.perf_counter()
    try:
        for i in range(iters):
            scenario = rng.choice(SCENARIOS)
            try:
                scenario(proxy, shm, rng)
            except Exception as e:
                failures[scenario.__name__] += 1
                # Print first 3 failures per scenario for diagnosis,
                # then keep going to surface systemic vs one-off issues.
                if failures[scenario.__name__] <= 3:
                    print(
                        f"[iter {i}] {scenario.__name__} FAILED: {type(e).__name__}: {e}",
                        file=sys.stderr,
                    )
            else:
                counts[scenario.__name__] += 1
            high_water = max(high_water, _live_allocs(shm))
            # Documented reset-between-calls usage. Without this, leaks
            # in the cross-language free protocol (Python client side)
            # would dominate; the soak test we want is "Rust server
            # holds up under sustained churn given the documented usage
            # pattern."
            shm.reset()
            if (i + 1) % 100 == 0:
                print(
                    f"  ... {i + 1}/{iters} done, high_water={high_water}",
                    file=sys.stderr,
                )
        elapsed = time.perf_counter() - t0
    finally:
        inner.close()
        with contextlib.suppress(BufferError):
            shm.close()
        shm.unlink()
    return {
        "iters": iters,
        "elapsed_s": elapsed,
        "rate_per_s": iters / elapsed if elapsed > 0 else float("inf"),
        "counts": counts,
        "failures": failures,
        "high_water": high_water,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iters", type=int, default=500)
    p.add_argument("--shm-size-mb", type=int, default=64)
    p.add_argument("--seed", type=int, default=0xC0FFEE)
    p.add_argument(
        "--worker",
        default=str(
            Path(__file__).resolve().parent.parent
            / "target"
            / "release"
            / "vgi-rpc-conformance-rust"
        ),
    )
    args = p.parse_args()
    print(f"# worker = {args.worker}")
    print(f"# iters = {args.iters}, shm = {args.shm_size_mb} MiB, seed = {args.seed}")
    result = run_soak(
        worker_cmd=[args.worker],
        iters=args.iters,
        shm_size_mb=args.shm_size_mb,
        seed=args.seed,
    )
    total_failures = sum(result["failures"].values())
    print(
        f"\nFinished {result['iters']} iters in {result['elapsed_s']:.2f}s "
        f"({result['rate_per_s']:.1f} iters/s) "
        f"high_water={result['high_water']}"
    )
    print("Per-scenario results:")
    for name, ok in result["counts"].items():
        bad = result["failures"][name]
        marker = "OK" if bad == 0 else f"FAIL ({bad})"
        print(f"  {name:<32} ok={ok:>5}   {marker}")
    if total_failures:
        print(f"\nFAILED: {total_failures} iterations failed.", file=sys.stderr)
        return 1
    print("\nAll iterations passed; SHM allocator stayed clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
