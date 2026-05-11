# vgi-rpc fuzz targets

`cargo-fuzz` harnesses over the trust-the-bytes surfaces of the crate.

## Setup

```bash
cargo install cargo-fuzz
rustup install nightly  # libFuzzer requires nightly
```

## Targets

| Target | What it covers |
|--------|---------------|
| `wire_stream_reader` | `vgi_rpc::wire::StreamReader` — the hand-crafted flatbuffer framer that parses Arrow IPC messages with per-message `custom_metadata`. Catches panics on malformed flatbuffer wrappers, schema messages, or batch frames. |

## Running

```bash
# Run forever (or until a crash) on the wire stream reader.
cargo +nightly fuzz run wire_stream_reader

# Time-boxed run (10 minutes).
cargo +nightly fuzz run wire_stream_reader -- -max_total_time=600

# Reproduce a saved crash artifact.
cargo +nightly fuzz run wire_stream_reader fuzz/artifacts/wire_stream_reader/crash-<hash>
```

Crashes land in `fuzz/artifacts/<target>/` and corpus seeds (interesting
inputs the engine has discovered) in `fuzz/corpus/<target>/`. Neither
directory is committed.

## Notes

This crate is intentionally **outside** the main workspace (see
`Cargo.toml` `[workspace]` block). `cargo-fuzz` builds with a custom
sanitizer-enabled `rustc` invocation that doesn't compose with stable
toolchain workspace builds.
