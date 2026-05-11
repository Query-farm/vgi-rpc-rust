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

## Known findings

### Fixed

- **OOM from short length prefix (4-byte input).** `[0x1A, 0x2C,
  0xF5, 0x2C]` parsed as a legacy IPC length prefix == ~720 MB,
  which upstream `arrow_ipc::reader::StreamReader::try_new`
  pre-allocates eagerly. **Fixed** by the `MAX_IPC_SCHEMA_BYTES`
  guard added to `vgi_rpc::wire::StreamReader::new` — the length
  prefix is now validated before allocation. Regression covered
  by `wire::tests::rejects_oversize_schema_length_prefix`.

### Open — known limitation

- **OOM from malformed schema flatbuffer's `bodyLength` field.**
  A 50-byte input whose 26-byte schema-message flatbuffer encodes
  `Message::bodyLength = 0x4000000100000` (~1 TB) causes
  `arrow_ipc::reader::MessageReader::maybe_next` to allocate the
  declared body buffer. Our `MAX_IPC_SCHEMA_BYTES` cap only
  protects the wire-level length prefix, not the body length
  encoded *inside* the flatbuffer.

  Proper fix needs one of:
  - Patch our `arrow-rs` fork (`rustyconover/arrow-rs feat/...`)
    to add a `max_body_size` config on `StreamReader`.
  - Pre-parse the schema flatbuffer in `wire::StreamReader::new`
    and validate `bodyLength` before handing off.
  - Wrap the input in a `Read` adapter that caps cumulative bytes
    (mitigation only — the allocation still happens before the
    read fails).

  Reproducer: `fuzz/corpus/wire_stream_reader/seed-malformed-schema-body-length`
  (regenerate by running the fuzz target).
