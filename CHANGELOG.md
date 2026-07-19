# Changelog

All notable changes to `vgi-rpc` (the Rust port) are listed here.

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
