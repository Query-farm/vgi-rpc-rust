# vgi-rpc-conformance-rust

Worker binary for the Python `vgi-rpc` conformance test suite. It
registers every method in `ConformanceService` (the ~52-method surface
used by the Python conformance tests) on top of the `vgi-rpc` Rust
library crate, and serves them over stdio, Unix sockets, or HTTP.

## Modes

```bash
# stdio (default) — intended to be spawned as a subprocess.
vgi-rpc-conformance-rust

# HTTP — prints PORT:<n> then serves until SIGTERM / SIGINT.
vgi-rpc-conformance-rust --http

# Unix socket — prints UNIX:<path> then accepts connections.
vgi-rpc-conformance-rust --unix /tmp/my.sock
```

## Environment variables

| var | effect |
|-----|--------|
| `VGI_ACCESS_LOG=path` | Emit one JSON-per-call access record to `path`, matching the Python `vgi_rpc.access_log_conformance` validator. |

## Running the suite

See [`scripts/conf.py`](../scripts/conf.py) in the workspace root.

```bash
./scripts/conf.py run --transport all
./scripts/conf.py summary
./scripts/conf.py failures
```

The Python side of the harness lives at the workspace root in
[`test_rust_conformance.py`](../test_rust_conformance.py).

## License

Apache-2.0.
