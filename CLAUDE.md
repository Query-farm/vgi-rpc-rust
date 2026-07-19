# CLAUDE.md

Operator / contributor guide for this Rust port of `vgi-rpc`. Intended for
future sessions (human or AI) that need to extend, debug, or release the
crate without re-deriving design decisions.

## Project shape

Workspace at `~/Development/vgi-rpc-rust/` with eight crates (five published —
`vgi-rpc`, `vgi-rpc-macros`, `vgi-rpc-client`, `vgi-rpc-s3`, `vgi-rpc-gcs`;
three internal test/benchmark crates):

| crate | published | purpose |
|-------|:-:|---------|
| `vgi-rpc/` | ✅ | The library. All wire-protocol, server, HTTP, auth, observability, external-location, and unix/launcher code. |
| `vgi-rpc-macros/` | ✅ | Proc-macros: `#[service]`, `#[unary]`, `#[producer]`, `#[exchange]`, `#[derive(VgiArrow)]`, `#[derive(StreamState)]`. Re-exported from `vgi-rpc` behind the default `macros` feature. |
| `vgi-rpc-client/` | ✅ | The Rust client library — drives a vgi-rpc server over pipe / unix / http (and shm), mirroring the Go/Python client patterns. Cross-language conformance green. |
| `vgi-rpc-s3/` | ✅ | `PresignedS3Storage` + shared `HttpFetcher`. |
| `vgi-rpc-gcs/` | ✅ | `SignedGcsStorage`. |
| `conformance-worker/` | — | Test binary `vgi-rpc-conformance-rust` that registers every Python `ConformanceService` method and serves stdio / `--http` / `--unix` (with `--idle-timeout`). The artifact the Python conformance suite drives. |
| `conformance-client-driver/` | — | Binary `vgi-rpc-conformance-client-driver` exercising the `vgi-rpc-client` role against a Python/Rust server in the cross-language conformance matrix. |
| `benchmark-worker/` | — | `vgi-rpc-benchmark-rust` — apples-to-apples benchmark target mirroring the Go / Python benchmark workers. |

The Python canonical lives at `~/Development/vgi-rpc/vgi_rpc/`; the Go port
at `~/Development/vgi-rpc-go/vgirpc/`. Read them alongside the Rust code
when extending — the wire format is Python-canonical and byte-for-byte
compatibility with the Python conformance suite is the definition of "done"
for each feature.

## Daily commands

All via `scripts/conf.py`:

```bash
# Build worker + run full 901-test conformance suite across transports.
./scripts/conf.py run --transport all

# Slice: one test class over one transport (fast iteration).
./scripts/conf.py run --transport pipe --class TestProducer

# Query previous run (no rebuild, no rerun).
./scripts/conf.py summary
./scripts/conf.py failures
./scripts/conf.py show TestProducer::test_produce_n
./scripts/conf.py names --status failure
```

The script writes `.test-run/{junit.xml, pytest.log, build.log, args.txt}`
so you can reason about results without re-running tests. A one-minute
overall deadline and a 2-second per-test deadline are enforced so hangs
can't swallow a session.

Per-crate Rust tests:

```bash
cargo test --workspace --all-features     # all crates, all features
cargo test -p vgi-rpc --lib wire          # one module
cargo test -p vgi-rpc --test http_auth    # one integration file
```

Pre-commit gate (also runs in CI):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/conf.py run --transport all
```

## Architecture, module by module

### Wire protocol — `vgi-rpc/src/wire.rs`

`arrow-ipc`'s `StreamReader` / `StreamWriter` do not expose per-message
`custom_metadata`, but the vgi_rpc wire protocol depends on it. This
module ships its own reader/writer that parses and injects metadata on
the flatbuffer `Message` wrapper while delegating record-batch
encoding/decoding to `arrow_ipc`. **Do not bypass this module** when
adding new metadata keys — hand-crafted framing will break conformance.

Key invariant: `empty_batch(&Schema)` constructs a zero-row batch with
`RecordBatchOptions::new().with_row_count(Some(0))` so
`arrow-ipc`-compatible readers accept it even on the empty schema.

### Server dispatch — `vgi-rpc/src/server.rs`

`RpcServer` holds a `HashMap<String, MethodInfo>` plus optional
`dispatch_hook` and (with the `http` feature) `external_config`. The
dispatch flow:

1. Read one IPC stream (`read_request`) → `Request { method, request_id, batch, metadata }`.
2. Handle `__transport_options__` inline — a pre-dispatch capability
   handshake (see `transport_options.rs`), answered before everything
   below so even a version-mismatched client can negotiate.
3. Enforce application protocol-version compatibility: if the server has
   an enforced `protocol_version`, reject a request whose
   `vgi_rpc.protocol_version` MAJOR differs (mirrors the Python gate).
4. Handle `__describe__` inline if enabled.
5. Build `CallContext` (with `auth`, `cookies`, `transport_metadata`).
6. Fire `on_dispatch_start`.
7. Call `serve_unary` or `serve_stream`. Both take `&mut Option<RpcError>`
   (`app_err`) so they can record a handler error without killing the
   serve loop.
8. On unary success, optionally externalize the result batch before
   writing it to the IPC writer.
9. Fire `on_dispatch_end` with the final `CallStatistics`.

Stream dispatch writes the output IPC stream's schema **before** opening
the input reader so the client can decode the schema without first sending
a tick. Every iteration flushes the output writer; producer ticks would
deadlock otherwise. Each iteration also publishes that tick's input-batch
metadata onto `CallContext` (read via `CallContext::tick_metadata(key)`),
so handlers can pick up per-tick signals like dynamic pushdown filters.

### Transport-capability handshake — `vgi-rpc/src/transport_options.rs`

`__transport_options__` is a framework method (parallel to `__describe__`)
that a client calls once, before `init`, to learn which transport features
the worker supports. It is **not** a registered method — `server.rs`
intercepts it pre-dispatch — so it never appears in `methods` /
`__describe__` and does not perturb the protocol hash. Capabilities ride
as `vgi_rpc.transport.*` response metadata on an empty batch; today the
only key is `vgi_rpc.transport.shm` (`metadata::TRANSPORT_SHM_KEY`),
`"true"` on POSIX builds with the `shm` feature. Mirrors Python
`vgi_rpc.transport_options` byte-for-byte.

### Unix listener + launcher worker contract — `vgi-rpc/src/unix.rs`

`serve_unix(server, path, idle_timeout, shutdown, on_bound)` (unix-only)
is the AF_UNIX accept loop: bind, fire `on_bound` (the caller prints the
`UNIX:<path>` line), then one thread per connection. With `idle_timeout`
set it self-terminates after a quiet period — `max(idle_timeout, 60s)`
startup grace, cancel-on-connect / re-arm-on-last-disconnect — so the
cross-language Python `vgi_rpc.launcher` can spawn, warm-reuse, and reap a
Rust worker. The conformance worker's `--unix` mode wires `--idle-timeout
SEC` to it. The launcher *tool* itself (client-side) is deferred; see
"What's not done".

### HTTP transport — `vgi-rpc/src/http.rs`

Endpoints:

```
POST   {prefix}/{method}            unary
POST   {prefix}/{method}/init       stream init (producer batches up to limit, else token)
POST   {prefix}/{method}/exchange   stream exchange / producer continuation / cancel
OPTIONS any of the above            CORS preflight

GET    {prefix}/                    landing page HTML
GET    {prefix}/describe            API reference HTML
GET    {prefix}/health              liveness probe
GET    {prefix}/.well-known/oauth-protected-resource   RFC 9728 JSON
```

Streaming is **stateless on the wire**: the full `StreamStateKind` is
sealed into an XChaCha20-Poly1305 AEAD token carried in the
`vgi_rpc.stream_state#b64` metadata key. Any worker behind a load
balancer with the same `token_key` can resume any continuation request.
No server-side session map, no reaper task. The token TTL (default 5
min) is embedded in the encrypted payload as a `created_at` timestamp
and checked after decryption.

**Token format v4** (matches Python `vgi_rpc/http/server/_state_token.py`):
`version=0x04 | nonce(24B) | ciphertext+tag`, base64-encoded. The
plaintext payload — `u64 created_at | len+state_bytes | len+output_schema_bytes |
len+input_schema_bytes | len+stream_id_bytes` — is hidden from anything
between client and server.  `(domain, principal)` are bound via AEAD
associated data so a token minted for one identity fails decryption when
presented by another.

**State serialization.** Each `ProducerState` / `ExchangeState` type
implements [`vgi_rpc::stream_codec::StreamStateCodec`] (bincode-backed
in the conformance worker; arbitrary format in principle). The method
registration carries a `state_decoder` function that rebuilds the
concrete state from bytes on continuation requests. See
`MethodInfo::with_state_decoder` + the `producer_decoder::<S>()` /
`exchange_decoder::<S>()` helpers in
`conformance-worker/src/conformance/streams.rs`.

Pipe/unix transports keep state in memory across lockstep iterations —
`encode_state` is unused on those paths. Same state type works for
both.

**Production token keys.** `HttpStateBuilder::token_key(...)` accepts
raw bytes; for deployments use `token_key_hex(...)`,
`token_key_base64(...)`, or `token_key_from_env(var)` (reads a key from
an env var, auto-detecting base64 or hex). Without an explicit key the
server logs a `vgi_rpc.http` warn-level line at startup and uses an
ephemeral per-process key — tokens won't survive a restart or load
balance across workers, so it's test-only.

Response post-processing (CORS headers + zstd compression) runs as an
axum `middleware::from_fn_with_state` layer applied at the top of
`build_router`, so every endpoint — including the HTML pages — gets the
same treatment.

### Auth — `vgi-rpc/src/auth/`

- `AuthContext { domain, authenticated, principal, claims }` — frozen
  once per call; propagated onto `CallContext.auth`.
- `AuthRequest` wraps `(method, headers, peer_addr)`; every helper
  consumes it.
- `Authenticate` is `Arc<dyn Fn(&AuthRequest) -> AuthResult + Send + Sync>`.
- `chain_authenticate(a, b)` + `chain_all([a, b, c])` — first-match-wins.
- Feature-gated: `auth::jwt` (behind `jwt`), `auth::pkce` (behind
  `oauth-pkce`), `auth::mtls` PEM helpers (behind `mtls-pem`, stub
  today — XFCC parsing is always compiled).

Errors returned by auth callbacks with `error_type = "PermissionError"`
or `"ValueError"` become HTTP 401 with a `WWW-Authenticate` header
(built from `OAuthResourceMetadata` when configured); other types become
500s.

### Introspection — `vgi-rpc/src/introspect.rs`

`build_describe(...)` emits a record batch whose columns match the
Python `_DESCRIBE_FIELDS` slim schema for `DESCRIBE_VERSION = "4"`:
`name`, `method_type`, `has_return`, `params_schema_ipc`,
`result_schema_ipc`, `has_header`, `header_schema_ipc`, `is_exchange`.
Python-flavoured columns (`doc`, `param_types_json`,
`param_defaults_json`, `param_docs_json`) are not on the wire — the
Protocol class is the source of truth for human-readable type info.

The response batch's custom metadata carries `vgi_rpc.protocol_name`,
`vgi_rpc.request_version`, `vgi_rpc.describe_version`,
`vgi_rpc.protocol_hash`, and `vgi_rpc.server_id`. `protocol_hash` is a
SHA-256 hex digest computed by `compute_protocol_hash` to mirror the
Python algorithm byte-for-byte; it's exposed via `RpcServer::protocol_hash()`
and threaded into every `DispatchInfo`. Within-port stable; cross-port
byte equality is *not* guaranteed because Arrow IPC schema bytes vary
across language Arrow libraries.

Conformance: register every method with `.header_schema()` where
applicable. The describe-conformance suite matches on schema/method
counts and the `protocol_hash` format.

### Hooks — `vgi-rpc/src/hooks.rs`

`DispatchHook` trait with `on_dispatch_start` / `on_dispatch_end`;
`ChainHook` composes several. `CallStatistics` is accumulated by the
dispatch loop (`input/output_batches`, `input/output_rows`). Built-in
implementations:

| hook | module | feature | purpose |
|------|--------|:-:|---------|
| `AccessLogHook`  | `access_log` | — | JSON-per-call access records (validated by Python's `vgi_rpc.access_log_conformance` and the `vgi_rpc/access_log.schema.json` JSON Schema). Records include `protocol_hash` always and `protocol_version` when set on the server. Configure via `RpcServerBuilder::protocol_version(...)`. |
| `OtelHook`       | `otel`       | `otel`   | `tracing::info!(target: "vgi_rpc.otel", ...)` spans + in-memory counters. |
| `SentryHook`     | `sentry`     | `sentry` | `tracing::error!(target: "vgi_rpc.sentry", ...)` on handler errors. |

### External locations — `vgi-rpc/src/external.rs`

`ExternalStorage` trait (upload) + `Fetcher` trait (download) +
`ExternalLocationConfig` (threshold, compression, URL validator).
`maybe_externalize_batch` returns a zero-row empty-schema pointer batch
with metadata keys `vgi_rpc.location`, `vgi_rpc.location.sha256`;
`resolve_external_location` reverses it and appends
`vgi_rpc.location.fetch_ms` to the user-visible metadata.

Integration into `RpcServer` is transparent for unary results and stream
output batches: set `RpcServer::builder().with_external_location(cfg)`.

## Wire protocol rules of thumb

Gotchas discovered while porting (all baked into the Rust code but worth
keeping in mind when extending):

- **Nullability defaults**. Pyarrow defaults `list` inner fields,
  `map` value fields, and dynamic schema fields to `nullable=true`.
  Conformance schema-equality checks will reject responses that use
  `nullable=false`. See `conformance-worker/src/conformance/param_schemas.rs`
  for the authoritative reference shapes.
- **Stream output writer first**. In the server stream loop, open the
  output `StreamWriter` + flush its schema **before** opening the input
  reader. The client won't send a tick until it has the output schema.
- **Flush after every lockstep iteration** or producers deadlock.
- **Cast input schemas** — use `arrow_cast::cast_with_options` plus an
  explicit field-name check so the existing "column-name mismatch is a
  TypeError" conformance test stays green.
- **__describe__ method_type**. Python's `MethodType` has only `unary`
  and `stream`; collapse `Producer | Exchange | Dynamic` → `"stream"` in
  the describe response.
- **Error envelopes** are zero-row batches whose custom metadata carries
  `vgi_rpc.log_level = "EXCEPTION"`, `vgi_rpc.log_message`, and a JSON
  `vgi_rpc.log_extra` with at least `exception_type`.

## Conformance harness (`scripts/conf.py`)

Subcommands:

```
run          Build (or --no-build) + run the suite, write junit.xml.
             --transport {pipe,subprocess,http,unix,all}
             --class "TestClass and not TestFoo" (forwarded as -k)
             -k "pytest_filter"
             --release / --debug
             --timeout 55  (overall ceiling, capped at 59)
             --per-test-timeout 2
summary      Parse junit.xml and print pass/fail/error/skipped counts.
failures     List failing tests with 1-line summaries.
show PAT     Dump full message + body for tests matching regex PAT.
names        List test names (optionally filtered by --status).
log          Tail the pytest log (pytest.log).
```

The harness sets `VGI_TRANSPORTS` so the same test file exercises each
transport in turn. `RUST_CONFORMANCE_WORKER` overrides the binary path.
The `_TRANSPORTS` fixture in `test_rust_conformance.py` uses
`request.getfixturevalue` so HTTP / unix fixtures only spin up when the
`http` / `unix` parametrize cases are active.

## Ports from other languages

When mirroring a Python or Go module, keep the file naming loosely
aligned so cross-referencing is easy. Python module ↔ Rust module:

| Python | Rust |
|--------|------|
| `vgi_rpc/rpc/_server.py` + `_wire.py` | `server.rs` + `wire.rs` |
| `vgi_rpc/metadata.py` | `metadata.rs` |
| `vgi_rpc/introspect.py` | `introspect.rs` |
| `vgi_rpc/transport_options.py` | `transport_options.rs` |
| `vgi_rpc/launcher.py` (worker contract only) | `unix.rs` |
| `vgi_rpc/log.py` | `log.rs` |
| `vgi_rpc/http/*.py` | `http.rs` (single file; modular submodules on demand) |
| `vgi_rpc/http/_bearer.py` / `_mtls.py` / `_oauth*.py` | `auth/bearer.rs` / `mtls.rs` / `oauth.rs` / `jwt.rs` / `pkce.rs` |
| `vgi_rpc/external.py` | `external.rs` |
| `vgi_rpc/s3.py` / `gcs.py` | `vgi-rpc-s3` / `vgi-rpc-gcs` crates |
| `vgi_rpc/otel.py` / `sentry.py` | `otel.rs` / `sentry.rs` |
| `vgi_rpc/access_log_conformance.py` (validator) | `access_log.rs` emits compatible records |

## Release process

All five published crates share one workspace version. The current line
is **0.14.x** (the port started at 0.1.0; every release is live on
crates.io, owned by `rustyconover`). A re-release **must** bump the
version — you cannot overwrite an existing one.

1. Bump the workspace version in the root `Cargo.toml`, and the internal
   path-dep `version = "..."` pins (`vgi-rpc-macros` in `vgi-rpc`;
   `vgi-rpc` in `vgi-rpc-client`/`vgi-rpc-s3`/`vgi-rpc-gcs`; `vgi-rpc-s3`
   in `vgi-rpc-gcs`). Run `cargo check` to refresh `Cargo.lock`.
2. Update `CHANGELOG.md` with a new `[x.y.z] — YYYY-MM-DD` section.
3. **Fuzz gate.** Run the wire-reader fuzz target to a clean stop —
   this is a release blocker, not optional:
   `cargo +nightly fuzz run wire_stream_reader -- -runs=1000000`.
   The wire reader parses hand-crafted flatbuffer frames; the
   `catch_unwind` + buffer-descriptor checks in `wire.rs` are the
   safety net, the fuzzer is how we know it holds. (`fuzz/` is a
   standalone workspace that still `[patch]`es arrow to a git fork; the
   *published* crates use crates.io arrow, so the patch never ships.)
4. Sanity-check packaging: `cargo publish --dry-run -p vgi-rpc-macros`.
   (Dry-running the downstream crates — `vgi-rpc`, `vgi-rpc-client`,
   `-s3`, `-gcs` — fails locally on a fresh version bump because their
   `version = "x.y.z"` pin can't resolve against crates.io until the
   upstream crate is actually published; the CI workflow handles this by
   publishing in dependency order. So only the leaf `vgi-rpc-macros`
   dry-run is meaningful before the first publish.)
5. **Publish via CI (preferred).** Push a `vX.Y.Z` tag (e.g. `v0.14.1`) —
   `.github/workflows/release.yml` triggers on that pattern, publishes
   all five crates **in dependency order** (`vgi-rpc-macros` → `vgi-rpc`
   → `vgi-rpc-client` → `vgi-rpc-s3` → `vgi-rpc-gcs`) via crates.io
   Trusted Publishing (OIDC, no long-lived token). It is idempotent (a
   version already on crates.io is skipped) and, when the `crates-io`
   GitHub Environment has required reviewers configured, gates on a human
   approval. `workflow_dispatch` with `dry_run: true` exercises the whole
   flow without uploading.
6. **Manual fallback** (only if CI is unavailable): publish in the same
   order — `cargo publish -p vgi-rpc-macros`, then `-p vgi-rpc`, then
   `-p vgi-rpc-client`, then `-p vgi-rpc-s3`, then `-p vgi-rpc-gcs` —
   sleeping ~30s between each for index propagation. Order matters: every
   crate depends on one published earlier.

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests, cargo doc, an
MSRV (1.90) build, and the Python-driven conformance job (full six-
transport matrix) on every push.

## Defining a service with the macro

The `vgi-rpc-macros` crate (re-exported from `vgi-rpc` behind the
default-on `macros` feature) lets you write services as a regular
`impl` block instead of hand-rolling Arrow schemas + closure
boilerplate. See `vgi-rpc-macros/README.md` for the user-facing
reference. Quick sketch:

```rust
#[service]
impl Calc {
    /// Echo a string back, prefixed.
    #[unary]
    fn echo(&self, value: String) -> Result<String> {
        Ok(format!("echo: {value}"))
    }
    #[producer(state = CountTo, output = i64)]
    fn count_to(&self, total: i64) -> Result<CountTo> {
        Ok(CountTo { total, cur: 0 })
    }
}
let mut srv = RpcServer::builder().build();
Calc::register_with(&mut srv, Arc::new(Calc));
```

`#[derive(VgiArrow)]` derives the trait for plain structs (mirroring
Python's `ArrowSerializableDataclass`). `#[derive(StreamState)]`
auto-impls `StreamStateCodec` (bincode) on stream-state types.
Compile-fail UI tests live in `vgi-rpc/tests/macro_compile_fail/`.

## What's **not** done (deferred)

Most of the original follow-ups have since shipped: the **Rust client**
(`vgi-rpc-client`, published, cross-language conformance green) and the
**shared-memory transport** (`shm` feature + `shm.rs` + the
`__transport_options__` capability handshake). What remains deferred and
is a candidate for a later phase:

- **Subprocess pool** — the optional Python/Go client-side feature that
  pools warm worker subprocesses is not ported.
- **Launcher *tool*** — the cross-language launcher *worker contract* is
  done (`vgi_rpc::unix::serve_unix` honours `--unix` + `--idle-timeout`,
  prints `UNIX:<path>`, and idle-exits, so the Python `vgi_rpc.launcher`
  can spawn/reuse/reap a Rust worker). A *Rust* port of the launcher
  itself (flock coordination, `.meta` discovery, `--status`/`--gc`)
  remains a follow-up.

## Trust boundaries

Not every transport is safe to expose to untrusted peers:

- **stdio / pipe** — `RpcServer::serve` does blocking reads with **no
  timeout**; a peer that connects and stalls pins the serve thread.
  There is no timeout API for stdio. Trusted-peer-only.
- **SHM** (`shm.rs`) — the client owns the OS segment and supplies its
  size in request metadata; a lie about the size can make the server
  `mmap` past the backing object and take a `SIGBUS` that `catch_unwind`
  cannot catch. Trusted-peer-only. See the `shm` module docs.
- **unix socket** — safe for untrusted peers *if* the caller sets a
  read timeout on the stream before handing it to `serve` (a
  `TimedOut`/`WouldBlock` error then cleanly ends the connection).
  `vgi_rpc::unix::serve_unix` serves each connection on its own thread
  with **no** per-connection read timeout, so a stalled peer pins one
  thread (and keeps `conn_count > 0`, suppressing the idle reaper) —
  trusted-peer / launcher use, not a hardened public listener.
- **HTTP** — the hardened path: body-size + request-timeout layers,
  AEAD-sealed stateless stream tokens, SSRF-filtered external fetches.

The wire reader (`wire.rs`) validates flatbuffer buffer descriptors and
wraps arrow-ipc decode in `catch_unwind`; handler panics are isolated by
`catch_unwind` in `server.rs` and surface as error envelopes. The
`cargo-fuzz` harness (`fuzz/wire_stream_reader`) is a release gate — see
the release process.

## Common pitfalls

- `cargo test` with `--all-features` may need 2–3 minutes on first
  build due to `reqwest`'s transitive compile graph; subsequent runs
  use the workspace cache and complete in under 10 s.
- The conformance harness uses `pytest-timeout --timeout-method=signal`
  — that only works on POSIX. Windows would need a different method.
- `scripts/conf.py` caps overall test wall-clock at 59 s. If the suite
  legitimately takes longer, either split by `--class` or chase the
  regression; don't raise the cap without thinking.

## Memory system

Long-lived context for this project lives under
`~/.claude/projects/-Users-rusty-Development-vgi-rpc-rust/memory/`. The
existing entries describe goal + status; update them when the scope or
architecture shifts materially.
