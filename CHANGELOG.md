# Changelog

All notable changes to `vgi-rpc` (the Rust port) are listed here.

## Unreleased

## [0.23.0] — 2026-08-23

### Added

- HTTP workers now encode gzip responses as well as zstd and advertise the
  mandatory `zstd, gzip` pair. The Rust HTTP client advertises both codecs and
  decodes gzip responses with the same encoded and decoded size bounds used
  for zstd.
- Producer ticks can carry application metadata through raw and HTTP clients,
  including continuation turns handled by the native conformance bridge.
- TCP, shared-memory, raw-adversarial, and same-connection stream-init recovery
  now participate in the normal shared conformance matrix.
- Recursive container serialization covers enums and Arrow dataclasses inside
  lists, maps, sets, and tagged unions, with protocol-version enforcement at
  dispatch.

### Changed

- HTTP producer requests are strictly lock-step: one request invokes the
  producer state exactly once and may return at most one data batch. Response
  byte caps size that turn but never authorize coalescing later turns.
- The conformance client preserves native continuation tokens and correctly
  distinguishes metadata-only token sentinels from zero-column data batches.

### Performance

- **A Unix socket got 8 KiB of kernel buffer, and so ran at half the pipe's
  throughput.** macOS defaults `net.local.stream.sendspace` to 8192 bytes —
  against ~64 KiB for a pipe — so a megabyte of Arrow crossed the kernel in 128
  trips instead of a handful. `unix::widen_socket_buffers` now requests 1 MiB,
  and `serve_unix` and `vgi-rpc-client`'s `UnixTransport::connect` both call it.

  Both ends have to: an `AF_UNIX` write is bounded by space in the *receiver's*
  buffer, so a tuned server still feeds an untuned client 8 KiB at a time.
  Fixing only the client end, against an already-tuned C++ worker, took echo
  throughput from 4,994 to **18,597 MB/s** at a 1 MiB payload (3.7x), 2,613 to
  4,438 at 64 KiB, and 2,373 to 5,369 at 16 MiB. The pipe control column moved
  3% across those runs, so that is the change rather than the machine.

  `TcpTransport` deliberately does not get the same call: TCP already starts at
  128 KiB and grows, an explicit `SO_RCVBUF` *disables* Linux's receive-window
  auto-tuning and pins the window at whatever constant we guessed, and an A/B
  on loopback showed no gain either way.

  Adds `socket2` as a `cfg(unix)` dependency of `vgi-rpc` and `vgi-rpc-client`.

### Fixed

- Stream initialization failures remain typed and leave persistent raw
  connections reusable.
- HTTP response parsing rejects genuinely coalesced data batches without
  rejecting a valid zero-column batch followed by a continuation sentinel.

- The conformance harness imported `httpx`, which the Python reference no
  longer installs — it moved to the `httpx2` fork. `test_rust_conformance.py`
  now accepts either, so collection stops failing before any test runs.

## [0.22.0] — 2026-08-14

### Fixed

- **A field named with a Rust keyword reached the wire with its `r#` prefix.**
  `#[derive(VgiArrow)]` took each column name from `Ident::to_string()`, which
  keeps the raw-identifier marker: a field that has to be spelled `r#type`
  produced an Arrow column literally named `"r#type"`. The VGI protocol has
  such a column — `catalog_schema_contents_functions` and `_macros` carry a
  `type` selector — so those methods could not be called by a Python, C++ or Go
  peer, which all send `type`. The prefix is now stripped on both the schema and
  the array-building path, matching how serde and the rest of the ecosystem
  treat raw identifiers.

- **Map columns used arrow-rs's child names rather than the protocol's.** The
  `Vec<(String, V)>` implementation built its entries struct as
  `keys`/`values` — arrow-rs's `MapBuilder` default — where pyarrow, the
  canonical Python protocol, the C++ extension and the Go worker all use
  `key`/`value`. Any map-valued field (`tags`, `options`, `estimated_object_count`)
  therefore went out with non-canonical child names. The read path was already
  positional, so only what is written changes.

### Wire compatibility

Both fixes change bytes on the wire, which is why this is a minor bump rather
than a patch. Both move Rust *toward* the canonical Python protocol, so a Rust
worker talking to a Python, C++ or Go peer is strictly more correct after
upgrading — one of the two methods above did not work at all before. A
Rust-to-Rust pair is unaffected in the map case, since that decoder reads
entries positionally.

## [0.21.1] — 2026-08-13

### Changed

- **The logo is transparent.** Both copies of the mark — `assets/vgi-logo.png`,
  which the crate READMEs link, and the `data:` URI inlined in the landing page
  `vgi-rpc` serves — were the old export on a white background with no alpha, so
  both wore a white rectangle wherever the page behind them was not white. Both
  are now cut from a committed master by `scripts/regenerate_logo_assets.py`.
  The inlined copy is palettized to 256 colours, which for flat artwork is
  visually indistinguishable from truecolour and holds the base64 compiled into
  every dependent binary at 20 KiB rather than 99 KiB.

No API or wire change; this is a patch.

## [0.20.0] — 2026-08-05

### Added

- **Access log: trace correlation.** Records carry `trace_id` / `span_id` as
  W3C hex when a valid span is current. `request_id` only joins records within
  one service, so without these a log line and the span describing the same
  call cannot be matched. The ids are read from whatever span is *current*,
  via a provider installed with `access_log::set_trace_context_provider`, so an
  application-opened span correlates as readily as a framework-opened one —
  and so the core keeps no OpenTelemetry dependency (the `otel` feature is
  tracing-only). Ids that are not 32 / 16 lowercase hex, or are all zeroes, are
  dropped rather than emitted, and the pair is always emitted together or not
  at all.
- **Access log: sampling.** `AccessLogHook::with_sample_rate(rate)`. Errors are
  never sampled — a rate below 1 exists because successes repeat, which
  failures do not. The decision is deterministic and keyed on `stream_id`, then
  `request_id`, so every record of one stream shares its init's fate rather
  than being shredded into fragments indistinguishable from data loss. Every
  kept record carries `sample_rate`, because a consumer scaling counts has to
  divide by it. An out-of-range rate is an error at construction, not at the
  first request.
- **Access log: egress accounting.** `request_bytes` (on-wire, before
  decompression), `response_bytes` (on-wire, after compression) and
  `externalized_bytes` (uploaded to external storage). Distinct from
  `input_bytes` / `output_bytes`, which measure logical Arrow buffers and can
  differ by a factor of a thousand on a compressible body. `response_bytes`
  cannot be measured where the others are — compression runs after the handler
  — so emission is deferred through a `hooks::AccessSink` that the HTTP
  post-processing middleware drains once the final body exists. A transport
  that installs no sink keeps logging inline.
- **Access log: claim redaction.** `claims` are now emitted, redacted by key
  (credentials plus the standard OIDC personal-data claims). Values are
  replaced rather than dropped, so which claims a credential carried stays
  answerable. `AccessLogHook::with_claim_redactor` replaces the policy;
  `access_log::no_redaction` opts out for a service that owns its logs end to
  end. A redactor that panics fails **closed** — the claims are dropped, never
  emitted raw.
- **Access log: `dropped_records`.** The bounded async queue already dropped
  rather than blocked; the loss is now reported in-band on the next record
  through, so a consumer can tell a quiet period from a lossy one.
- **Access log: per-record size cap.** `AccessLogHook::with_max_record_bytes`
  (default 1 MiB) sheds `request_data`, then `claims`, then everything but the
  required envelope (`truncated: "record_too_large"`). `error_message` is never
  truncated.
- Conformance worker: `--access-log-sample`, `--access-log-async`,
  `--access-log-queue-size`, `--access-log-max-record-bytes`.
- Conformance worker: `--access-log-debug` (DEBUG-equivalent verbosity, i.e.
  `AccessLogHook::with_verbose`), and CI now runs `vgi-rpc-test --access-log
  ... --require-request-data` against it. Validated at INFO the log simply
  never carries `request_data`, so every rule governing the field was
  satisfied vacuously — and the check itself was manual, which is how the
  contract drifted with four people having inspected it.

### Changed

- **Access log: `truncated` disambiguated.** A record that omits the request
  payload because this level does not log payloads now reports
  `"payload_omitted"`; `true` again means genuine size-driven shedding. The
  two shared one value, which fired on essentially every record and left a
  consumer scanning for real data loss with nothing to filter on.
- HTTP unary records now carry the request payload's size and the omission
  marker (previously neither, which failed the schema's "unary requires
  `request_data` unless truncated" rule for every HTTP record).
- `hooks::DispatchInfo` gains `request_bytes`, `externalized_bytes` and
  `access_sink`, and now implements `Default` so a later field addition does
  not break struct literals.

### Fixed

- **Payloads over 2 GiB survive the unix and TCP transports.** `impl Write for
  &UnixStream` / `&TcpStream` hand the full length to `send(2)` without the
  `INT_MAX` clamp `std`'s file-descriptor writer applies, so on macOS a >2 GiB
  Arrow IPC body died with `EINVAL` on both socket transports (pipes were
  already fine). Every write out of `wire::StreamWriter` is now clamped to
  1 GiB, which covers the transports the crate ships *and* a worker that hands
  `serve` a socket of its own. Linux hides the whole class — it caps a single
  transfer at `0x7ffff000` and returns a short count `write_all` absorbs — so
  the Linux CI could not have found this.
- **`wire::MAX_IPC_MESSAGE_BYTES` no longer caps legitimate payloads at
  256 MiB.** It was doing two jobs: refusing an absurd `bodyLength` before
  allocating on it, and — incidentally — imposing a hard size limit the Python
  reference does not have, which made a >2 GiB round-trip a conformance
  failure. The anti-OOM job now belongs to the reader, which buffers a body
  from the bytes that actually arrive rather than from the claim, so a crafted
  length costs a few MiB and an EOF. The ceiling moves to `u32::MAX`.

## [0.17.0] — 2026-07-27

### Added

- **Proxy proof** (`auth::proof`, feature `http`): a worker can refuse any
  request that did not arrive through a trusted proxy, by recomputing an
  HMAC-SHA256 over a timestamp, a nonce and the worker's own identifier
  against a secret shared only with that proxy. Unlike a forwarded assertion
  about what happened at a TLS terminator, a proof cannot be produced by
  someone who merely reaches the worker directly — without the secret there is
  nothing to replay.
  - `proof_authenticate(cfg, inner)` composes as an **AND**. It is deliberately
    not passed to `chain_authenticate`, whose first-non-anonymous-wins
    semantics would let a later credential bypass it.
  - `NonceCache` is bounded by capacity as well as TTL: a TTL bounds how long
    an entry lives, never how many arrive inside the window, so TTL-only would
    be a remote memory-exhaustion vector.
  - No new dependency — `hmac` and `sha2` were already in the tree, and
    `Mac::verify_slice` is constant-time internally.
  - Verified against golden vectors minted by the Python reference
    implementation: this port both verifies its tokens and mints byte-identical
    output, which is the only check that catches a canonical string framed
    differently from the other languages.
  - `HttpStateBuilder::proxy_proof_required(true)` advertises the
    `VGI-Proxy-Proof-Required: true` capability header (and CORS-exposes it) on
    every response, so a proxy can tell an enforcing worker from one silently
    ignoring the header — the misconfiguration that makes the feature a no-op.
    Advertisement only: the gate arrives through `authenticate` as an opaque
    callback the builder cannot introspect, so the operator states the posture.
    Emitted only for `require`; `allow` never denies, so it must not claim to.
  - `--http-proof` on the conformance worker; the shared `TestProxyProof` group
    (22 cases) runs against this port.

  Contract: `docs/proxy-proof-spec.md` in vgi-rpc.

## [0.16.0] — 2026-07-21

- **Fixed (http)** `max_body_size` is now actually enforced. axum installs a
  2 MiB `DefaultBodyLimit` on every route and checks it *before* our
  `RequestBodyLimitLayer`, so the configured ceiling — including the
  documented 64 MiB default — was silently inert above 2 MiB and every larger
  request body got a 413. Measured against a stock worker: 4 MiB was rejected
  before, accepted now; 80 MiB is still rejected against the 64 MiB ceiling.
  Found by a benchmark with realistic (incompressible) Arrow payloads, which
  produce ~4.4 MiB compressed exchange bodies; the previous benchmark payload
  compressed ~1242x, so bodies never approached the limit.
- **Changed (MSRV)** minimum supported Rust version raised 1.90 → 1.97.

## [0.15.0] — 2026-07-21

- **Changed (http, default)** zstd response compression is now **on by
  default** at level 1 (`DEFAULT_RESPONSE_COMPRESSION_LEVEL`), matching the
  Python SDK's `compression_level=1`. Level 1 measured 4.7x faster than
  level 3 *and* produced a smaller body on an 8.41 MB Arrow payload, so this
  is not a size/speed trade. A stock server therefore advertises
  `VGI-Supported-Encodings: zstd` and actually compresses.
- **Added (http)** `HttpStateBuilder::disable_response_compression()` — the
  explicit opt-out now that the default is on.
  `response_compression_level(n)` only changes the level.
- **Fixed (http)** capability (`VGI-*`) headers are now attached to
  compressed responses. The compressed early-return path skipped
  `attach_capability_headers`, so every compressed Arrow body arrived
  without a single capability header.
- **Fixed (http, CORS)** `Access-Control-Expose-Headers` now lists every
  `VGI-*` capability header the server emits (plus `X-VGI-Content-Encoding`,
  `X-VGI-RPC-Error`, and the sticky-session headers). Previously it named
  only `Content-Encoding` / `WWW-Authenticate`, so a browser `fetch()`
  client could not read a single server capability.
- **Fixed (client)** `VGI-Supported-Encodings` absent and present-but-empty
  are no longer conflated. Absent means a legacy server (assume `zstd`);
  present-but-empty means the server speaks no compression, and the client
  now stops sending compressed request bodies instead of eating a 415.

## [0.14.2] — 2026-07-19

- **Docs** fixed all rustdoc intra-doc-link warnings across `vgi-rpc` and
  `vgi-rpc-client` (broken/renamed/private links and an ambiguous
  `axum::serve` reference), so `cargo doc --all-features` builds clean and
  the affected items render as proper links on docs.rs. No code changes.

## [0.14.1] — 2026-07-19

- **Docs** added the Vector Gateway Interface logo to the repository and
  crate READMEs (referenced by absolute URL so it renders on both GitHub
  and crates.io). No code changes.

## [0.14.0] — 2026-07-19

Headline: **hot-path allocation reductions** across server dispatch, the
Arrow-IPC wire writer, and the HTTP transport. No cross-language wire
change — the full 901-test conformance suite stays green on every
transport.

- **Changed (API)** `Request.metadata` is now `Arc<Metadata>` (was
  `Metadata`). Reads via deref (`req.metadata.get(...)`, `&req.metadata`)
  are unaffected; the field is now shared with `CallContext` /
  `DispatchInfo` by `Arc` bump instead of two deep hashmap clones per
  request.
- **Performance (dispatch)** the `DispatchInfo` build and the request
  batch re-serialization now run only when a dispatch hook is registered,
  so the hookless path skips a full Arrow re-encode and a large
  owned-clone struct per request. Roughly halves unary-noop allocations.
- **Performance (streams)** per-tick input metadata is moved into the
  context instead of deep-cloned; `cast_batch` reuses the caller's
  `SchemaRef` instead of deep-cloning the `Schema`; the zero-row envelope
  batch is built once per stream; and a reusable, lazily-allocated
  `EnvelopeMeta` builds log/error envelope metadata without rebuilding
  the map (or re-stringifying the ids) per line — and allocates nothing
  on calls that never log.
- **Performance (wire)** `StreamWriter` reuses one `FlatBufferBuilder`
  for the per-batch metadata repack and drops the two throwaway
  descriptor `Vec`s (`create_vector_from_iter`); `parse_custom_metadata`
  pre-sizes its map.
- **Performance (http)** stream continuations reuse the schema bytes
  already carried in the token instead of a decode→re-encode of both
  schemas every turn; the post-processing middleware extracts only the
  header values it needs instead of cloning the whole request
  `HeaderMap`; capability + CORS response headers are precomputed once at
  build time.
- **Changed (http)** zstd response compression now skips bodies below a
  1 KiB threshold and keeps the compressed form only when it is actually
  smaller, so tiny error / continuation-token responses ship
  uncompressed. (`Accept-Encoding` is a client capability, not a demand,
  so this is transparent to conformant clients.)

## [0.13.0] — 2026-07-16

Headline: **shm request-batch resolution**, **HTTP exchange metadata parity
with the Python reference**, and **continuation-only stream resume** on the
client.

- **Fixed (shm)** shm-routed *request* batches now resolve against a
  per-connection segment cache (attach-from-request-metadata when the cache is
  empty); responses route through shm only when the request signalled shm this
  exchange. Mirrors vgi-rpc-python 42701df.
- **Fixed (http)** the init request's custom metadata now reaches a producer's
  first tick (`CallContext::tick_metadata`), so result-cache conditional
  revalidation (`vgi.cache.if_none_match` / `if_modified_since`) fires over
  HTTP. Parity with the Go/Java/TS ports.
- **Added (client)** continuation-only stream resume:
  `HttpClient::resume_stream`, `HttpStreamSession::next_with_token` /
  `seek_to_token` — resume a producer stream from a relayed token without a
  bind/init round-trip.
- **Fixed (wasm)** the crate builds on `wasm32-wasip2` again with `shm`
  enabled: `windows-sys` is target-gated to Windows, the proc-macro decoders
  are gated on `stream-codec` (not `http`), and the shm module gained a
  fallback backend (create/attach return `NotImplementedError`) for platforms
  with neither POSIX shm nor Win32 sections.

## [0.7.0] — 2026-06-26

Headline: the crate now **builds for `wasm32-wasi`** (a VGI worker can be
compiled to WebAssembly and served over stdio/TCP under a WASI runtime), with
no change to native builds.

- **Added** a lightweight `stream-codec` feature (serde + bincode only, no
  server stack) and moved `stream_codec` behind it instead of `http`. The core
  dispatch path uses `stream_codec`, so it must be available without the
  axum/tokio HTTP stack (which does not compile to wasm). `http` re-includes it.
- **Fixed** `std::process::id()` aborting on `wasm32-wasi` ("no pids on this
  platform"): `access_log::random_stream_id` and the unary id helper fall back
  to `0` under `cfg(wasm32)` — time + counter already disambiguate within the
  single wasm process.

## [0.6.0] — 2026-06-26

Headline: a **raw-TCP socket transport** — the network analog of the existing
Unix-socket transport, speaking the same raw Arrow-IPC framing without the HTTP
envelope.

- **Added** `serve_tcp` (server) and `TcpTransport` + `RpcClient::tcp_connect`
  (client), plus `TransportKind::Tcp`. Binds loopback (`127.0.0.1`) by default;
  `port 0` auto-selects. `TCP_NODELAY` enabled; optional idle self-termination
  mirroring the Unix serve loop. **No auth/TLS** — trusted networks only; use
  HTTP otherwise.
- The conformance worker gains `--tcp [HOST:]PORT`, emitting a
  `TCP:<host>:<port>` discovery line. Verified at full conformance parity with
  the `--unix` baseline via the Python `vgi-rpc-test --tcp` harness.

## [0.3.0] — 2026-06-18

Headline: a new **`vgi-rpc-client`** crate — a blocking, dynamic, schema-first
client for the canonical wire protocol — validated by running the Python
reference conformance suite against it across pipe / subprocess / unix / HTTP /
shm, driving the Rust, Python, and Go conformance servers.

- **Added** the `vgi-rpc-client` crate. `RpcClient` (unary / producer /
  exchange / cancel / `describe` / `transport_options`) over the byte-stream
  transports (subprocess, AF_UNIX, pipe, shm) plus an `HttpClient`. HTTP
  production surface: transparent external-location resolution, sticky sessions
  (with a session stack for nesting), 413 request-externalization via vended
  upload URLs, 415/zstd request-codec negotiation, a default request timeout,
  and connection-level retry on idempotent calls (never on `exchange`). The
  lockstep stream session opens its output reader lazily so it is compatible
  with both the Rust server (writes the output schema first) and the Python
  server (reads the input schema first). Native tests cover in-process
  round-trips and HTTP fault injection (timeout / retry / garbage responses).
- **Added** a lightweight `external` cargo feature on `vgi-rpc` (zstd only, no
  axum/tokio server stack) so a client can reuse the external-location module;
  `http` now implies `external`.
- **Added** `external::fetch_external_ipc_bytes`, and
  `resolve_external_location` now merges the *inner* externalized batch's
  metadata in addition to the outer pointer's — peers differ on where they
  stamp per-batch keys like the stream-state token (Rust on the outer pointer,
  Python inside the payload), and the client resolves either layout.
- **Changed** the HTTP unary and stream-init handlers to run inside
  `call_guard`, so a panicking handler surfaces as a structured Arrow
  `EXCEPTION` batch (HTTP 200) matching the stdio/unix loop, rather than a bare
  500. New `http_panic` integration test.
- **Internal** the `CallContext::with_auth_cookies` / `set_sticky` helpers are
  now gated behind the `http` feature (they are http-only; this keeps non-http
  builds warning-clean). The conformance harness (`scripts/conf.py`,
  `test_rust_conformance.py`) gained `--role {server,client}` /
  `--server {rust,python,go}` so the Rust client is conformance-tested against
  all three servers, and CI runs a `{server,rust}` / `{client,rust}` /
  `{client,python}` matrix.

## [0.2.0] — 2026-06-03

First release since the initial `0.1.0` port. Headline: a production-hardening
pass, AEAD-sealed stateless stream tokens, opt-in sticky sessions, application
protocol-version enforcement, and the `__transport_options__` capability
handshake. Byte-for-byte conformant with the Python canonical — 901/901
conformance tests pass across pipe / subprocess / HTTP / unix.

- **Added** `__transport_options__` framework handshake (parallel to
  `__describe__`): a pre-dispatch interception in `RpcServer` that reports
  transport capabilities (currently POSIX shared memory) as
  `vgi_rpc.transport.*` response metadata. Not a registered method, so it stays
  out of `methods` / `__describe__` and does not perturb the protocol hash.
  Mirrors Python `vgi_rpc.transport_options`. New `vgi_rpc::transport_options`
  module and `metadata::TRANSPORT_SHM_KEY`.
- **Added** per-tick input-batch metadata surfaced to producer/exchange
  handlers via `CallContext::tick_metadata` (e.g. dynamic `vgi_pushdown_filters`),
  plus an optional per-producer `ProducerState::batch_limit` HTTP continuation
  cap.
- **Added** launcher worker contract (server side): `vgi_rpc::unix::serve_unix`
  — an AF_UNIX accept loop with optional idle self-termination
  (`max(idle_timeout, 60s)` startup grace, cancel-on-connect /
  re-arm-on-last-disconnect), and a `--idle-timeout SEC` flag on the
  conformance worker's `--unix` mode. A Rust worker can now be spawned, warm-
  reused, and reaped by the Python `vgi_rpc.launcher` unchanged. The launcher
  *tool* itself (client-side orchestration) remains deferred with the Rust
  client.
- **Added** application protocol-version major-compatibility enforcement on
  incoming requests, and `protocol_version` in the `__describe__` response.
- **Fixed** describe-conformance harness: provide the `conformance_describe`
  fixture the upstream `TestDescribeConformance` now requires (describe via a
  real `__describe__` call across the transport matrix).

### AEAD-sealed state tokens (token format v4)

- **Breaking** Stream-state tokens are now sealed with XChaCha20-Poly1305
  (`chacha20poly1305 = "0.10"`) instead of HMAC-SHA256-signed. The
  on-wire layout is `version=0x04 | nonce(24B) | ciphertext+tag`,
  base64-encoded; the `created_at` timestamp moves inside the
  ciphertext and TTL is enforced after authenticity. State contents
  are now confidential to anything between client and server.
- **Breaking** `HttpStateBuilder` rename: `signing_key` → `token_key`,
  `signing_key_hex` → `token_key_hex`, `signing_key_base64` →
  `token_key_base64`, `signing_key_from_env` → `token_key_from_env`.
  Examples, integration tests, and the conformance worker have been
  updated.
- **Changed** principal binding switches from a per-(domain, principal)
  HKDF-derived HMAC subkey to a single master key with the identity
  carried in AEAD associated data. Cross-principal and cross-domain
  replay still fail (now via AAD mismatch); key rotation is simpler
  with a single key to roll.
- **Added** new token-format tests: tampered-ciphertext, tampered-nonce,
  unknown-version, malformed-base64.

### Phase 4: external-location batches + S3 / GCS backends

- **Added** `vgi_rpc::external` module: `ExternalStorage` + `Fetcher`
  traits, `ExternalLocationConfig` (threshold, compression, URL
  validator), `maybe_externalize_batch`, `resolve_external_location`,
  and an `InMemoryStorage` backend for tests/CI. Pointer batches carry
  `vgi_rpc.location`, `vgi_rpc.location.sha256`, and an observability
  `vgi_rpc.location.fetch_ms` claim.
- **Added** server-side transparent externalization: oversized unary
  results and stream output batches are uploaded and replaced with
  zero-row pointer batches when `RpcServer::builder().with_external_location(cfg)`
  is set.
- **Added** `vgi-rpc-s3` crate (`PresignedS3Storage`) + `vgi-rpc-gcs`
  crate (`SignedGcsStorage`) — lean design where users supply a
  pre-signed PUT URL factory so the core avoids pulling the heavy
  aws-sdk-s3 transitive tree. Shared HTTPS `HttpFetcher` lives in
  `vgi-rpc-s3` and is re-exported from `vgi-rpc-gcs`.
- **Added** 5 unit tests + 3 integration tests + 3 backend unit tests.

### Phase 3: observability + HTTP polish

- **Added** `otel::OtelHook` (feature `otel`): per-call `tracing` events
  tagged `vgi_rpc.otel` with method, principal, status, durations,
  statistics; `OtelMetrics` counter/histogram for in-memory scraping;
  W3C `traceparent` extraction helper.
- **Added** `sentry::SentryHook` (feature `sentry`): thin `DispatchHook`
  that emits `tracing::error!` events tagged `vgi_rpc.sentry` on
  handler errors so a `sentry-tracing` layer can capture them.
- **Added** `retry::RetryConfig` with exponential backoff + jitter +
  iterator schedule.
- **Added** HTTP polish: CORS (`cors_origins` / `cors_max_age`) with
  preflight handler, `Accept-Encoding: zstd` response compression via
  an axum middleware, URL prefix mounting, `GET /` landing page,
  `GET /describe` API reference page, `GET /health` liveness probe.
- **Added** 12 new unit tests and a `tests/http_polish.rs` integration
  suite (CORS, prefix, health, describe page, zstd response).

### Phase 2: auth surface

- **Added** core auth framework: `AuthContext`, `AuthRequest`, `Authenticate`
  callback type, `chain_authenticate` / `chain_all`. `AuthContext` is now
  propagated on every `CallContext`, and HTTP requests carry a `cookies`
  map into user handlers.
- **Added** bearer-token helpers:
  `auth::bearer::bearer_authenticate(validator)` and
  `bearer_authenticate_static(HashMap)`.
- **Added** mTLS via `x-forwarded-client-cert` (RFC 8705) with
  `mtls_authenticate_fingerprint`, `mtls_authenticate_subject`, and
  `mtls_authenticate_xfcc`; XFCC parser handles quoted values + multi-hop
  chains.
- **Added** OAuth 2.0 Protected Resource Metadata (RFC 9728):
  `OAuthResourceMetadata`, auto-served at
  `/.well-known/oauth-protected-resource`, with a pre-built
  `WWW-Authenticate` header on 401 responses.
- **Added** JWKS-backed JWT validation behind the `jwt` feature:
  `jwt_authenticate_with` + `JwtConfig` + single-flight JWKS refresh.
- **Added** OAuth2 + PKCE primitives behind `oauth-pkce`:
  `generate_pkce_pair`, HMAC-signed state cookies, return-origin allowlist.
- **Added** `HttpState::builder().authenticate(cb).oauth_resource_metadata(m)`.
- **Added** 4 HTTP integration tests and 11 new unit tests covering auth
  helpers end-to-end.

### Phase 1: production hygiene

- **Added** `__describe__` introspection behind `RpcServer::builder().enable_describe(true)`.
- **Added** `MethodInfo` fluent builder with `.doc()`, `.param_type()`,
  `.param_default()`, `.param_doc()`, `.header_schema()`.
- **Added** `RpcServer::builder()` and `HttpState::builder()` with
  `server_id`, `server_version`, `enable_describe`, `with_hook`,
  `producer_batch_limit`, `token_ttl`, `max_sessions`, `max_body_size`,
  `signing_key` knobs.
- **Added** HTTP session TTL (default 5 min), background reaper, bounded
  session map (default 10k), typed "expired vs unknown" errors.
- **Added** graceful shutdown for HTTP (`axum::serve::with_graceful_shutdown`)
  and Unix listeners (SIGTERM/SIGINT via `ctrlc` / `tokio::signal`).
- **Added** `DispatchHook` trait + `CallStatistics` accumulator; wired
  through pipe/unix unary + stream dispatch and HTTP unary.
- **Added** `AccessLogHook` — JSON-per-call access records matching the
  Python `vgi_rpc.access_log_conformance` validator.
- **Added** live describe conformance test (`TestRustDescribeConformance`)
  that runs the Python `run_describe_conformance` suite against the Rust
  worker over pipe + HTTP.

## 0.1.0 — initial port

- Wire protocol reader/writer with per-batch custom metadata.
- `RpcServer` dispatch over stdio / Unix sockets.
- HTTP server with HMAC-signed stream state tokens.
- Conformance worker + `scripts/conf.py` harness. All 450 Python
  conformance cases pass across pipe / subprocess / http / unix.
