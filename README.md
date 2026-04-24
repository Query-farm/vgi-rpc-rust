# vgi-rpc-rust

Rust implementation of [vgi-rpc](https://github.com/Query-farm/vgi-rpc), a
transport-agnostic RPC framework built on Apache Arrow IPC.

## Status

All 114 Python canonical conformance tests pass across all four transports
(pipe / subprocess / http / unix) — 450 passing cases total.

## Layout

- `vgi-rpc/` — library crate. Wire protocol, server dispatch, HTTP.
- `conformance-worker/` — binary crate producing `vgi-rpc-conformance-rust`,
  driven by the Python conformance suite in `vgi-rpc`.

## Running conformance tests

Requires `vgi-rpc` installed in a venv that `scripts/conf.py` can find
(defaults to `~/Development/vgi-rpc/.venv`).

```bash
# Build and run the whole suite over all transports.
./scripts/conf.py run --transport all

# Quick slice: one test class over one transport.
./scripts/conf.py run --transport pipe --class TestProducer

# Query results (no re-run).
./scripts/conf.py summary
./scripts/conf.py failures
./scripts/conf.py show TestProducer::test_produce_n
```

The binary also supports:

- Default (stdio): `./conformance-worker-rust`
- HTTP: `./conformance-worker-rust --http` (prints `PORT:<n>` then serves)
- Unix: `./conformance-worker-rust --unix /tmp/sock` (prints `UNIX:/tmp/sock`)
