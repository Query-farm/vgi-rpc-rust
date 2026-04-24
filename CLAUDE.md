# CLAUDE.md

Operator / contributor guide for this Rust port of `vgi-rpc`. Intended for
future sessions (human or AI) that need to extend, debug, or release the
crate without re-deriving design decisions.

## Project shape

Workspace at `~/Development/vgi-rpc-rust/` with four crates:

| crate | purpose |
|-------|---------|
| `vgi-rpc/` | The library. All wire-protocol, server, HTTP, auth, observability, external-location code. |
| `conformance-worker/` | Test binary `vgi-rpc-conformance-rust` that registers every Python `ConformanceService` method and serves stdio / `--http` / `--unix`. This is the artifact the Python conformance suite drives. |
| `vgi-rpc-s3/` | `PresignedS3Storage` + shared `HttpFetcher`. |
| `vgi-rpc-gcs/` | `SignedGcsStorage`. |

The Python canonical lives at `~/Development/vgi-rpc/vgi_rpc/`; the Go port
at `~/Development/vgi-rpc-go/vgirpc/`. Read them alongside the Rust code
when extending — the wire format is Python-canonical and byte-for-byte
compatibility with the Python conformance suite is the definition of "done"
for each feature.

## Daily commands

All via `scripts/conf.py`:

```bash
# Build worker + run full 452-test conformance suite across transports.
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
2. Handle `__describe__` inline if enabled.
3. Build `CallContext` (with `auth`, `cookies`, `transport_metadata`).
4. Fire `on_dispatch_start`.
5. Call `serve_unary` or `serve_stream`. Both take `&mut Option<RpcError>`
   (`app_err`) so they can record a handler error without killing the
   serve loop.
6. On unary success, optionally externalize the result batch before
   writing it to the IPC writer.
7. Fire `on_dispatch_end` with the final `CallStatistics`.

Stream dispatch writes the output IPC stream's schema **before** opening
the input reader so the client can decode the schema without first sending
a tick. Every iteration flushes the output writer; producer ticks would
deadlock otherwise.

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

Stream state lives in an in-memory `HashMap<String, Session>` keyed by
an opaque HMAC-signed token the client echoes back. Sessions have a TTL
(default 5 min), a bounded cap (default 10 k), and are reaped by a
tokio interval task at 30-second cadence. The signing key is random per
process unless `HttpStateBuilder::signing_key(...)` is set.

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
Python `_DESCRIBE_FIELDS`. `DESCRIBE_VERSION = "3"`. The describe batch
attaches `vgi_rpc.protocol_name`, `vgi_rpc.request_version`,
`vgi_rpc.describe_version`, `vgi_rpc.server_id` as custom metadata.
Conformance: register every method with `.doc()`, `.param_type()`,
`.param_default()`, `.param_doc()` (where applicable), and
`.header_schema()` — the Python `run_describe_conformance` suite matches
on exact counts and strings.

### Hooks — `vgi-rpc/src/hooks.rs`

`DispatchHook` trait with `on_dispatch_start` / `on_dispatch_end`;
`ChainHook` composes several. `CallStatistics` is accumulated by the
dispatch loop (`input/output_batches`, `input/output_rows`). Built-in
implementations:

| hook | module | feature | purpose |
|------|--------|:-:|---------|
| `AccessLogHook`  | `access_log` | — | JSON-per-call access records (validated by Python's `vgi_rpc.access_log_conformance`). |
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
| `vgi_rpc/log.py` | `log.rs` |
| `vgi_rpc/http/*.py` | `http.rs` (single file; modular submodules on demand) |
| `vgi_rpc/http/_bearer.py` / `_mtls.py` / `_oauth*.py` | `auth/bearer.rs` / `mtls.rs` / `oauth.rs` / `jwt.rs` / `pkce.rs` |
| `vgi_rpc/external.py` | `external.rs` |
| `vgi_rpc/s3.py` / `gcs.py` | `vgi-rpc-s3` / `vgi-rpc-gcs` crates |
| `vgi_rpc/otel.py` / `sentry.py` | `otel.rs` / `sentry.rs` |
| `vgi_rpc/access_log_conformance.py` (validator) | `access_log.rs` emits compatible records |

## Release process

1. Bump the workspace version in the root `Cargo.toml`.
2. Update `CHANGELOG.md` with a new `[x.y.z] — YYYY-MM-DD` section.
3. `cargo publish --dry-run -p vgi-rpc` (repeat for `vgi-rpc-s3`,
   `vgi-rpc-gcs`).
4. Tag `vgi-rpc-vX.Y.Z`, push.
5. `cargo publish -p vgi-rpc` then `-p vgi-rpc-s3` then `-p vgi-rpc-gcs`
   (order matters; the backend crates depend on `vgi-rpc`).

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests, cargo doc, and
the Python-driven conformance job on every push.

## What's **not** done (deferred)

These weren't gated on conformance and are candidates for a later phase:

- **Rust client library** — today the crate is server-only. The Python /
  Go / Rust clients drive the server; a Rust client would be a separate
  crate or module and mirror the Go port's patterns.
- **Shared-memory transport** + subprocess pool (optional Python / Go
  feature).
- **Full OAuth2 + PKCE browser UI pages** — the crypto primitives ship
  in `auth::pkce` but the HTML flow (callback + logout + session cookie
  middleware) is left to downstream apps.
- **JWT verifier bundled** — `auth::jwt::jwt_authenticate_with` exposes
  the scaffolding and expects the user to plug in a `jsonwebtoken` or
  `josekit` verifier closure. A ready-made `jsonwebtoken` adapter is
  easy to add when needed.

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
