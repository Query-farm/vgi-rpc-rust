# Changelog

All notable changes to `vgi-rpc` (the Rust port) are listed here.

## [Unreleased] — Phase 4: external-location batches + S3 / GCS backends

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

## [Unreleased] — Phase 3: observability + HTTP polish

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

## [Unreleased] — Phase 2: auth surface

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

## [Unreleased] — Phase 1: production hygiene

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
