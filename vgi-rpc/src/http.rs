//! HTTP transport. Implements the vgi-rpc protocol over HTTP:
//!   `POST /{method}`            unary
//!   `POST /{method}/init`       stream init (producer or exchange)
//!   `POST /{method}/exchange`   stream continuation
//!
//! Streaming is stateless on the wire: the full `StreamStateKind` is
//! sealed into an XChaCha20-Poly1305 AEAD token (v4 wire format) carried
//! in the `vgi_rpc.stream_state#b64` metadata key. Any worker with the
//! same token key can resume any continuation request — no server-side
//! session map, no reaper, no cross-worker affinity. The token contents
//! are confidential as well as authenticated: only the server can read
//! the serialized state.

use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::{Schema, SchemaRef};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use base64::Engine;
use rand::RngCore;

use crate::errors::{Result, RpcError};
use crate::metadata::{CANCEL_KEY, REQUEST_ID_KEY, STATE_KEY};
use crate::server::{
    build_error_metadata, build_log_metadata, cast_batch, CallContext, MethodType, Request,
    RpcServer,
};
use crate::stream::{empty_schema, Emitted, OutputCollector, StreamResult, StreamStateKind};
use crate::wire::{bytes_to_hex, empty_batch, md_get, Metadata, StreamReader, StreamWriter};

pub const ARROW_CONTENT_TYPE: &str = "application/vnd.apache.arrow.stream";

/// HTTP server state shared across all handlers.
///
/// Build via [`HttpState::builder`] (preferred) or [`HttpState::new`] for a
/// default configuration.
///
/// Streaming is stateless: the full `StreamStateKind` travels in every
/// HTTP continuation request inside an AEAD-sealed state token, so any
/// worker behind a load balancer can resume any stream. No session map
/// is held on the server.
pub struct HttpState {
    server: Arc<RpcServer>,
    token_key: [u8; 32],
    producer_batch_limit: usize,
    token_ttl: std::time::Duration,
    max_body_size: usize,
    /// Wall-clock ceiling for a single HTTP request, enforced by a
    /// `tower_http::timeout::TimeoutLayer`. A stalled handler or a
    /// slow-loris client cannot pin a runtime worker indefinitely.
    request_timeout: std::time::Duration,
    authenticate: Option<crate::auth::Authenticate>,
    #[allow(dead_code)]
    oauth_metadata: Option<Arc<crate::auth::oauth::OAuthResourceMetadata>>,
    oauth_metadata_json: Option<Vec<u8>>,
    www_authenticate: Option<String>,
    cors_origins: Option<String>,
    cors_max_age: u32,
    prefix: String,
    response_compression_level: Option<i32>,
    landing_page_enabled: bool,
    describe_page_enabled: bool,
    health_enabled: bool,
    max_request_bytes: Option<usize>,
    max_upload_bytes: Option<usize>,
    /// Hard cap on the HTTP body size for unary and stream-exchange
    /// responses (advertised via `VGI-Max-Response-Bytes`).  `None` =
    /// unbounded.  Externalised payloads do not count toward this — they
    /// leave only tiny pointer batches on the wire.
    max_response_bytes: Option<usize>,
    /// Hard cap on bytes uploaded to external storage during one HTTP
    /// response (advertised via `VGI-Max-Externalized-Response-Bytes`).
    /// Always hard — externalised uploads have no escape valve.
    max_externalized_response_bytes: Option<usize>,
    upload_url_provider: Option<Arc<dyn crate::external::UploadUrlProvider>>,
}

/// Fluent builder for [`HttpState`].
#[derive(Default)]
pub struct HttpStateBuilder {
    server: Option<Arc<RpcServer>>,
    token_key: Option<[u8; 32]>,
    producer_batch_limit: Option<usize>,
    token_ttl: Option<std::time::Duration>,
    max_body_size: Option<usize>,
    request_timeout: Option<std::time::Duration>,
    authenticate: Option<crate::auth::Authenticate>,
    oauth_metadata: Option<Arc<crate::auth::oauth::OAuthResourceMetadata>>,
    cors_origins: Option<String>,
    cors_max_age: Option<u32>,
    prefix: Option<String>,
    response_compression_level: Option<i32>,
    landing_page_enabled: Option<bool>,
    describe_page_enabled: Option<bool>,
    health_enabled: Option<bool>,
    max_request_bytes: Option<usize>,
    max_upload_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
    max_externalized_response_bytes: Option<usize>,
    upload_url_provider: Option<Arc<dyn crate::external::UploadUrlProvider>>,
}

impl HttpStateBuilder {
    pub fn server(mut self, server: Arc<RpcServer>) -> Self {
        self.server = Some(server);
        self
    }

    /// AEAD master key used to seal state tokens. **Must be ≥32 bytes**
    /// — the XChaCha20-Poly1305 key size; the first 32 bytes are used. A
    /// shorter slice is a configuration error and panics rather than
    /// being silently zero-padded into a weak key. When not set, a
    /// random 32-byte key is generated at `build()` time.
    pub fn token_key(mut self, key: &[u8]) -> Self {
        assert!(
            key.len() >= 32,
            "token_key: signing key must be at least 32 bytes (got {}). \
             Generate one with `openssl rand -hex 32`.",
            key.len()
        );
        let mut k = [0u8; 32];
        k.copy_from_slice(&key[..32]);
        self.token_key = Some(k);
        self
    }

    /// Set the token key from a lowercase-hex string (64 hex chars →
    /// 32 bytes). Panics on invalid input — intended for startup config,
    /// not runtime callers.
    pub fn token_key_hex(self, hex: &str) -> Self {
        let bytes = decode_hex_key(hex).expect("token_key_hex: invalid hex or wrong length");
        self.token_key(&bytes)
    }

    /// Set the token key from a base64-encoded string (standard alphabet,
    /// padding optional). Panics on invalid input.
    pub fn token_key_base64(self, b64: &str) -> Self {
        let bytes =
            decode_base64_key(b64).expect("token_key_base64: invalid base64 or wrong length");
        self.token_key(&bytes)
    }

    /// Read the token key from environment variable `var`. Accepts either
    /// base64 or lowercase-hex (auto-detected). Panics if the variable is
    /// unset, empty, or decodes to fewer than 32 bytes. Use this for
    /// production deployments where the key is supplied by a secret manager.
    pub fn token_key_from_env(self, var: &str) -> Self {
        let raw = std::env::var(var)
            .unwrap_or_else(|_| panic!("token_key_from_env: env var {var} is unset or not UTF-8"));
        let trimmed = raw.trim();
        let bytes = decode_base64_key(trimmed)
            .or_else(|_| decode_hex_key(trimmed))
            .unwrap_or_else(|e| {
                panic!("token_key_from_env: {var} is not valid base64 or hex ({e})")
            });
        self.token_key(&bytes)
    }

    /// Maximum data batches per producer HTTP response (0 = unbounded).
    /// Default `1` to mirror the Python/Go servers.
    pub fn producer_batch_limit(mut self, n: usize) -> Self {
        self.producer_batch_limit = Some(n);
        self
    }

    /// Maximum age of a state token. Continuation requests with a token
    /// older than this are rejected. Default `5 minutes`. Set to
    /// `Duration::ZERO` to disable TTL enforcement.
    pub fn token_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.token_ttl = Some(ttl);
        self
    }

    /// Maximum request body size (post-decompression) in bytes. Default
    /// `64 * 1024 * 1024` (64 MiB). Enforced as a hard ceiling on the
    /// raw request body by a `RequestBodyLimitLayer` — independent of the
    /// `Content-Length` header, so a chunked upload cannot bypass it.
    pub fn max_body_size(mut self, n: usize) -> Self {
        self.max_body_size = Some(n);
        self
    }

    /// Wall-clock timeout for a single HTTP request. Default 30 s.
    pub fn request_timeout(mut self, d: std::time::Duration) -> Self {
        self.request_timeout = Some(d);
        self
    }

    /// Register an authenticate callback run on every request. Not set →
    /// anonymous for all callers (mirrors the Python `make_wsgi_app` default).
    pub fn authenticate(mut self, cb: crate::auth::Authenticate) -> Self {
        self.authenticate = Some(cb);
        self
    }

    /// Attach RFC 9728 Protected Resource Metadata. When set, the server
    /// exposes `/.well-known/oauth-protected-resource` and includes a
    /// `WWW-Authenticate` header on 401 responses.
    pub fn oauth_resource_metadata(
        mut self,
        metadata: crate::auth::oauth::OAuthResourceMetadata,
    ) -> Self {
        self.oauth_metadata = Some(Arc::new(metadata));
        self
    }

    /// Enable CORS with the given `Access-Control-Allow-Origin` value.
    /// Pass `"*"` for a permissive server or a specific origin URL.
    pub fn cors_origins(mut self, origins: impl Into<String>) -> Self {
        self.cors_origins = Some(origins.into());
        self
    }

    /// Override the preflight cache lifetime (seconds). Default `7200`.
    pub fn cors_max_age(mut self, seconds: u32) -> Self {
        self.cors_max_age = Some(seconds);
        self
    }

    /// Mount the router under a URL prefix (e.g. `/v1`). Default empty.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Enable zstd response compression at the given level (1..=22) when
    /// the client sends `Accept-Encoding: zstd`. Default off.
    pub fn response_compression_level(mut self, level: i32) -> Self {
        self.response_compression_level = Some(level);
        self
    }

    /// Serve a friendly HTML landing page at `GET /`. Default on.
    pub fn enable_landing_page(mut self, enabled: bool) -> Self {
        self.landing_page_enabled = Some(enabled);
        self
    }

    /// Serve an API reference HTML page at `GET /describe`. Default on.
    pub fn enable_describe_page(mut self, enabled: bool) -> Self {
        self.describe_page_enabled = Some(enabled);
        self
    }

    /// Serve a liveness probe at `GET /health`. Default on.
    pub fn enable_health(mut self, enabled: bool) -> Self {
        self.health_enabled = Some(enabled);
        self
    }

    /// Maximum inline-request body size advertised via the
    /// `VGI-Max-Request-Bytes` capability header and enforced server-side
    /// (413 Payload Too Large for non-exempt routes). When set together
    /// with [`Self::upload_url_provider`], clients can externalize
    /// oversize requests via `__upload_url__/init` + a pointer batch.
    pub fn max_request_bytes(mut self, n: usize) -> Self {
        self.max_request_bytes = Some(n);
        self
    }

    /// Advertised upper bound on the size of any single client-vended
    /// upload (header `VGI-Max-Upload-Bytes`). Advertisement only — no
    /// server-side enforcement.
    pub fn max_upload_bytes(mut self, n: usize) -> Self {
        self.max_upload_bytes = Some(n);
        self
    }

    /// HTTP body cap (header `VGI-Max-Response-Bytes`). Hard for unary
    /// and stream-exchange — overshoot replaces the response with a
    /// fresh EXCEPTION-only IPC stream surfaced via 200 +
    /// `X-VGI-RPC-Error: true`. Externalised payloads do not count
    /// toward this cap.
    pub fn max_response_bytes(mut self, n: usize) -> Self {
        self.max_response_bytes = Some(n);
        self
    }

    /// Cap on bytes uploaded to external storage during one HTTP
    /// response (header `VGI-Max-Externalized-Response-Bytes`).  Always
    /// hard — externalised uploads have no escape valve.
    pub fn max_externalized_response_bytes(mut self, n: usize) -> Self {
        self.max_externalized_response_bytes = Some(n);
        self
    }

    /// Install an [`UploadUrlProvider`](crate::external::UploadUrlProvider).
    /// When set, the server exposes `POST /__upload_url__/init` and
    /// advertises `VGI-Upload-URL-Support: true`.
    pub fn upload_url_provider(
        mut self,
        provider: Arc<dyn crate::external::UploadUrlProvider>,
    ) -> Self {
        self.upload_url_provider = Some(provider);
        self
    }

    pub fn build(self) -> Arc<HttpState> {
        let server = self.server.expect("HttpStateBuilder::server is required");
        // A wildcard CORS origin combined with a credentialed auth
        // callback is unsafe and a browser would refuse it anyway: an
        // `Access-Control-Allow-Origin: *` response cannot carry
        // `Allow-Credentials: true`. Fail fast at config time instead of
        // shipping a server whose authenticated cross-origin requests
        // silently break.
        assert!(
            !(self.cors_origins.as_deref() == Some("*") && self.authenticate.is_some()),
            "HttpStateBuilder: cors_origins(\"*\") cannot be combined with an \
             authenticate callback — browsers reject credentialed requests \
             against a wildcard origin. Configure a specific origin."
        );
        let token_key = self.token_key.unwrap_or_else(|| {
            tracing::warn!(
                target: "vgi_rpc.http",
                "no token_key configured; using ephemeral per-process AEAD key — \
                 state tokens will not survive restart or load-balance across workers"
            );
            let mut k = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut k);
            k
        });
        let oauth_metadata_json = self
            .oauth_metadata
            .as_ref()
            .map(|m| m.to_json().into_bytes());
        let www_authenticate = self.oauth_metadata.as_ref().map(|m| m.www_authenticate());
        Arc::new(HttpState {
            server,
            token_key,
            producer_batch_limit: self.producer_batch_limit.unwrap_or(1),
            token_ttl: self
                .token_ttl
                .unwrap_or_else(|| std::time::Duration::from_secs(300)),
            max_body_size: self.max_body_size.unwrap_or(64 * 1024 * 1024),
            request_timeout: self
                .request_timeout
                .unwrap_or_else(|| std::time::Duration::from_secs(30)),
            authenticate: self.authenticate,
            oauth_metadata: self.oauth_metadata,
            oauth_metadata_json,
            www_authenticate,
            cors_origins: self.cors_origins,
            cors_max_age: self.cors_max_age.unwrap_or(7200),
            prefix: self.prefix.unwrap_or_default(),
            response_compression_level: self.response_compression_level,
            landing_page_enabled: self.landing_page_enabled.unwrap_or(true),
            describe_page_enabled: self.describe_page_enabled.unwrap_or(true),
            health_enabled: self.health_enabled.unwrap_or(true),
            max_request_bytes: self.max_request_bytes,
            max_upload_bytes: self.max_upload_bytes,
            max_response_bytes: self.max_response_bytes,
            max_externalized_response_bytes: self.max_externalized_response_bytes,
            upload_url_provider: self.upload_url_provider,
        })
    }
}

impl HttpState {
    /// Create an `HttpState` with default configuration. See [`HttpState::builder`]
    /// for the full set of knobs.
    pub fn new(server: Arc<RpcServer>) -> Arc<Self> {
        Self::builder().server(server).build()
    }

    pub fn builder() -> HttpStateBuilder {
        HttpStateBuilder::default()
    }

    pub fn token_ttl(&self) -> std::time::Duration {
        self.token_ttl
    }

    pub fn max_body_size(&self) -> usize {
        self.max_body_size
    }

    /// Seal a v4 state token bound to the supplied auth identity.
    ///
    /// `(domain, principal)` are carried as AEAD associated data, so a
    /// token issued under one identity fails decryption when presented
    /// by another — same anti-replay guarantee as the prior HMAC subkey
    /// derivation, expressed via AAD instead of key derivation.
    pub(crate) fn pack_state_token(
        &self,
        auth: &crate::auth::AuthContext,
        state_bytes: &[u8],
        output_schema_bytes: &[u8],
        input_schema_bytes: &[u8],
        stream_id: &str,
    ) -> String {
        let aad = compute_aad(auth);
        pack_state_token(
            &self.token_key,
            &aad,
            state_bytes,
            output_schema_bytes,
            input_schema_bytes,
            stream_id,
            current_unix_secs(),
        )
    }

    /// Open a v4 state token, decrypting under the current caller's
    /// identity-derived AAD and enforcing TTL after authenticity.
    pub(crate) fn unpack_state_token(
        &self,
        auth: &crate::auth::AuthContext,
        token: &str,
    ) -> Result<UnpackedToken> {
        let ttl = if self.token_ttl.is_zero() {
            None
        } else {
            Some(self.token_ttl)
        };
        let aad = compute_aad(auth);
        unpack_state_token(&self.token_key, &aad, token, ttl)
    }
}

/// Build the AEAD associated data that binds a state token to the
/// authenticated identity of its issuer. Anonymous and authenticated
/// callers produce distinct AAD strings so a token minted in one
/// context cannot be opened in another. Mirrors Python's `_compute_aad`.
fn compute_aad(auth: &crate::auth::AuthContext) -> Vec<u8> {
    let prefix = b"vgi_rpc.state.v4\x00";
    if !auth.authenticated {
        let mut out = Vec::with_capacity(prefix.len() + b"\x00anonymous".len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(b"\x00anonymous");
        return out;
    }
    let mut out =
        Vec::with_capacity(prefix.len() + 1 + auth.domain.len() + 1 + auth.principal.len());
    out.extend_from_slice(prefix);
    out.push(0x01);
    out.extend_from_slice(auth.domain.as_bytes());
    out.push(0);
    out.extend_from_slice(auth.principal.as_bytes());
    out
}

/// Token version supported by this crate.
pub(crate) const STATE_TOKEN_VERSION: u8 = 0x04;

/// Decomposed contents of a v4 state token after AEAD authentication.
#[derive(Debug, Clone)]
pub(crate) struct UnpackedToken {
    pub state_bytes: Vec<u8>,
    pub output_schema_bytes: Vec<u8>,
    pub input_schema_bytes: Vec<u8>,
    pub stream_id: String,
    #[allow(dead_code)]
    pub created_at: u64,
}

/// Current time as seconds since the UNIX epoch.
fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seal a state token (v4 wire format).
///
/// On-wire layout (base64-encoded):
///
/// ```text
/// [1]    version = 0x04
/// [24]   XChaCha20-Poly1305 nonce (random)
/// [..]   ciphertext = XChaCha20-Poly1305-Seal(plaintext, aad, nonce, key)
///        plaintext (little-endian):
///          [8]  created_at (u64 seconds since epoch)
///          [4]  len(state_bytes)           [N] state_bytes
///          [4]  len(output_schema_bytes)   [M] output_schema_bytes
///          [4]  len(input_schema_bytes)    [K] input_schema_bytes
///          [4]  len(stream_id_bytes)       [L] stream_id_bytes (UTF-8)
///        [16]   Poly1305 tag (appended by AEAD construction)
/// ```
///
/// `created_at` lives inside the ciphertext so TTL enforcement runs
/// after authenticity is established. The version byte is not part of
/// the AAD — it acts as a format selector; a tampered version byte still
/// fails decryption because [`crypto::open_bytes`] rejects it before
/// touching the cipher.
///
/// The AEAD envelope (version byte + nonce + ciphertext+tag) is owned by
/// [`crypto`]; only the *plaintext* framing inside the ciphertext is this
/// function's concern.
pub(crate) fn pack_state_token(
    token_key: &[u8; 32],
    aad: &[u8],
    state_bytes: &[u8],
    output_schema_bytes: &[u8],
    input_schema_bytes: &[u8],
    stream_id: &str,
    created_at: u64,
) -> String {
    let mut plaintext = Vec::with_capacity(
        8 + 4
            + state_bytes.len()
            + 4
            + output_schema_bytes.len()
            + 4
            + input_schema_bytes.len()
            + 4
            + stream_id.len(),
    );
    plaintext.extend_from_slice(&created_at.to_le_bytes());
    plaintext.extend_from_slice(&(state_bytes.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(state_bytes);
    plaintext.extend_from_slice(&(output_schema_bytes.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(output_schema_bytes);
    plaintext.extend_from_slice(&(input_schema_bytes.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(input_schema_bytes);
    plaintext.extend_from_slice(&(stream_id.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(stream_id.as_bytes());

    crate::crypto::seal_base64(&plaintext, token_key, aad, STATE_TOKEN_VERSION)
}

/// Open and verify a v4 state token. [`crypto::open_bytes`] authenticates
/// the payload; every malformed, wrong-version, tampered, wrong-key, or
/// AAD-mismatched (e.g. cross-principal replay) token surfaces as the same
/// uniform signature-verification error so callers cannot distinguish
/// failure modes via timing or message content. Only a base64 decode
/// failure — observable before any crypto work — stays a distinct
/// "Malformed state token".
pub(crate) fn unpack_state_token(
    token_key: &[u8; 32],
    aad: &[u8],
    token: &str,
    token_ttl: Option<std::time::Duration>,
) -> Result<UnpackedToken> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token.as_bytes())
        .map_err(|_| RpcError::runtime_error("Malformed state token"))?;

    let plaintext = crate::crypto::open_bytes(&raw, token_key, aad, STATE_TOKEN_VERSION)
        .map_err(|_| RpcError::runtime_error("State token signature verification failed"))?;

    if plaintext.len() < 8 {
        return Err(RpcError::runtime_error("Malformed state token"));
    }
    let created_at = u64::from_le_bytes(plaintext[0..8].try_into().unwrap());

    if let Some(ttl) = token_ttl {
        let now = current_unix_secs();
        if now > created_at && now - created_at > ttl.as_secs() {
            return Err(RpcError::runtime_error("State token expired"));
        }
        // A `created_at` in the future is clock skew between workers (or
        // a tampered host clock). Without this guard the expiry check
        // above is simply skipped — a token minted on a fast-clocked
        // worker would dodge the TTL on every normal-clocked peer.
        const MAX_CLOCK_SKEW_SECS: u64 = 60;
        if created_at > now && created_at - now > MAX_CLOCK_SKEW_SECS {
            return Err(RpcError::runtime_error(
                "State token timestamp is implausibly in the future",
            ));
        }
    }

    let mut pos = 8;
    let state_bytes = read_segment(&plaintext, &mut pos)?;
    let output_schema_bytes = read_segment(&plaintext, &mut pos)?;
    let input_schema_bytes = read_segment(&plaintext, &mut pos)?;
    let stream_id_bytes = read_segment(&plaintext, &mut pos)?;
    if pos != plaintext.len() {
        return Err(RpcError::runtime_error("Malformed state token"));
    }
    let stream_id = String::from_utf8(stream_id_bytes)
        .map_err(|_| RpcError::runtime_error("Malformed state token"))?;

    Ok(UnpackedToken {
        state_bytes,
        output_schema_bytes,
        input_schema_bytes,
        stream_id,
        created_at,
    })
}

fn read_segment(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    if *pos + 4 > buf.len() {
        return Err(RpcError::runtime_error("Malformed state token"));
    }
    let len = u32::from_le_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + len > buf.len() {
        return Err(RpcError::runtime_error("Malformed state token"));
    }
    let out = buf[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(out)
}

/// Serialize an Arrow schema into transportable bytes — wraps it in a
/// zero-row IPC stream since the stock writer doesn't expose a raw
/// `Schema.serialize()` path. Round-trip via [`read_schema_bytes`].
fn write_schema_bytes(schema: &Schema) -> Result<Vec<u8>> {
    let empty = empty_batch(schema)?;
    crate::wire::write_one_batch(&empty, None)
}

/// Inverse of [`write_schema_bytes`].
fn read_schema_bytes(bytes: &[u8]) -> Result<SchemaRef> {
    let r = StreamReader::new(bytes)?;
    Ok(r.schema())
}

/// A future that resolves when the process receives SIGTERM or SIGINT
/// (or a Ctrl-C event on non-Unix). Pass to [`axum::serve`]'s
/// `with_graceful_shutdown` to stop accepting new connections, drain
/// in-flight requests, and exit cleanly.
///
/// ```no_run
/// # async fn run(state: std::sync::Arc<vgi_rpc::http::HttpState>) {
/// let app = vgi_rpc::http::build_router(state);
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
/// axum::serve(listener, app)
///     .with_graceful_shutdown(vgi_rpc::http::shutdown_signal())
///     .await
///     .unwrap();
/// # }
/// ```
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut intr = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {},
            _ = intr.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Serve `state` on `listener`, terminating cleanly on SIGTERM/SIGINT.
/// Convenience wrapper around [`build_router`] +
/// [`axum::serve`] + [`shutdown_signal`].
pub async fn serve_with_shutdown(
    state: Arc<HttpState>,
    listener: tokio::net::TcpListener,
) -> std::io::Result<()> {
    let app = build_router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
}

/// Absolute ceiling on a buffered HTTP response body in the
/// post-processing middleware. Mirrors `wire::MAX_IPC_MESSAGE_BYTES` —
/// large enough for any reasonable Arrow batch, small enough that the
/// middleware can never be driven to exhaust the heap.
///
/// This is **distinct** from the operator's `max_response_bytes`, which
/// is a *soft* producer-side cap: a producer is allowed to overshoot it
/// by one batch and then mint a continuation token, so the response
/// body on the wire can legitimately exceed `max_response_bytes`. The
/// middleware therefore caps at `max(this, 2 × max_response_bytes)` —
/// see [`response_buffer_ceiling`].
const MAX_RESPONSE_BYTES_HARD_CAP: usize = 256 * 1024 * 1024;

/// Hard ceiling the post-processing middleware buffers a response under.
/// Always at least [`MAX_RESPONSE_BYTES_HARD_CAP`]; when a (soft)
/// `max_response_bytes` is configured, it leaves headroom for the
/// one-batch producer overshoot that the continuation-token design
/// permits.
fn response_buffer_ceiling(state: &HttpState) -> usize {
    match state.max_response_bytes {
        Some(soft) => MAX_RESPONSE_BYTES_HARD_CAP.max(soft.saturating_mul(2)),
        None => MAX_RESPONSE_BYTES_HARD_CAP,
    }
}

pub fn build_router(state: Arc<HttpState>) -> Router {
    let body_limit = state.max_body_size;
    let request_timeout = state.request_timeout;
    build_router_inner(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            postprocess_middleware,
        ))
        // Hard ceiling on the raw request body, enforced regardless of
        // the `Content-Length` header (chunked uploads included).
        .layer(tower_http::limit::RequestBodyLimitLayer::new(body_limit))
        // Wall-clock ceiling per request so a stalled handler or a
        // slow-loris client can't pin a runtime worker forever.
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        // Convert a panic in handler code into a 500 instead of a
        // dropped connection. The `unwrap`s on the HTTP hot path are on
        // infallible `Vec` writers and server-controlled schemas, but
        // this is the defence-in-depth net for any that slip through.
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
}

async fn postprocess_middleware(
    axum::extract::State(state): axum::extract::State<Arc<HttpState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    use axum::body::to_bytes;
    // Bind the server to the HTTP transport on first request. Idempotent
    // for the (kind, caps) pair so calling it per-request is cheap;
    // fork-safe for pre-fork deployments because each child fires once.
    state.server.notify_transport(
        crate::transport::TransportKind::Http,
        crate::transport::TransportCapabilities::none(),
    );
    let req_headers = req.headers().clone();
    let req_method = req.method().clone();
    let req_path = req.uri().path().to_string();

    // Enforce server-advertised max_request_bytes before invoking the
    // handler. Exempt the upload-URL flow itself and `/health` so
    // clients can still discover capabilities and request URLs even if
    // their next request would exceed the limit.
    if let Some(limit) = state.max_request_bytes {
        let exempt = req_path.ends_with("/__upload_url__/init")
            || req_path.contains("/__upload_url__/")
            || req_path == "/health"
            || req_path.ends_with("/health");
        if !exempt {
            if let Some(cl) = req
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
            {
                if cl > limit {
                    let mut h = HeaderMap::new();
                    attach_capability_headers(&state, &mut h, &req_method);
                    attach_cors_headers(&state, &mut h, &req_headers, false);
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        h,
                        format!(
                            "Request body of {cl} bytes exceeds advertised \
                             max_request_bytes={limit}. Use the upload-URL \
                             flow (__upload_url__/init) to externalize."
                        ),
                    )
                        .into_response();
                }
            }
        }
    }

    let resp = next.run(req).await;
    let (mut parts, body) = resp.into_parts();
    // Buffer the response under a hard ceiling. `usize::MAX` here let a
    // large handler response exhaust the heap; on overflow fail loud
    // with a 500 rather than `unwrap_or_default()` silently shipping an
    // empty 200. The ceiling is *not* `max_response_bytes` (a soft
    // producer-side cap the wire may legitimately overshoot) — see
    // `response_buffer_ceiling`. Externalised payloads leave only tiny
    // pointer batches on the wire, so they never approach this bound.
    let response_limit = response_buffer_ceiling(&state);
    let bytes = match to_bytes(body, response_limit).await {
        Ok(b) => b,
        Err(_) => {
            let mut h = HeaderMap::new();
            attach_cors_headers(&state, &mut h, &req_headers, false);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                h,
                "response body exceeded the configured size limit",
            )
                .into_response();
        }
    };
    let is_arrow = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        == Some(ARROW_CONTENT_TYPE);

    if is_arrow {
        if let Some(level) = state.response_compression_level {
            let accepts = req_headers
                .get(header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if accepts.contains("zstd") {
                if let Ok(compressed) = zstd::encode_all(std::io::Cursor::new(&bytes), level) {
                    parts
                        .headers
                        .insert(header::CONTENT_ENCODING, HeaderValue::from_static("zstd"));
                    attach_cors_headers(&state, &mut parts.headers, &req_headers, false);
                    let body_new = axum::body::Body::from(compressed);
                    return Response::from_parts(parts, body_new);
                }
            }
        }
    }
    attach_cors_headers(&state, &mut parts.headers, &req_headers, false);
    attach_capability_headers(&state, &mut parts.headers, &req_method);
    Response::from_parts(parts, axum::body::Body::from(bytes))
}

/// Attach `VGI-Max-Request-Bytes`, `VGI-Upload-URL-Support`,
/// `VGI-Max-Upload-Bytes` capability headers when configured. On
/// `OPTIONS` responses also stamp `Cache-Control: public, max-age=300`
/// so clients cache discovery results, mirroring the Python
/// `_CapabilitiesMiddleware`.
fn attach_capability_headers(
    state: &Arc<HttpState>,
    out: &mut HeaderMap,
    method: &axum::http::Method,
) {
    let mut any = false;
    if let Some(n) = state.max_request_bytes {
        if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
            out.insert("vgi-max-request-bytes", v);
            any = true;
        }
    }
    if let Some(n) = state.max_response_bytes {
        if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
            out.insert("vgi-max-response-bytes", v);
            any = true;
        }
    }
    if let Some(n) = state.max_externalized_response_bytes {
        if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
            out.insert("vgi-max-externalized-response-bytes", v);
            any = true;
        }
    }
    // Always present so capability-aware clients can decide whether to
    // expect externalised payloads.
    out.insert(
        "vgi-externalization-enabled",
        HeaderValue::from_static(if state.server.external_config().is_some() {
            "true"
        } else {
            "false"
        }),
    );
    if state.upload_url_provider.is_some() {
        out.insert("vgi-upload-url-support", HeaderValue::from_static("true"));
        any = true;
        if let Some(n) = state.max_upload_bytes {
            if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
                out.insert("vgi-max-upload-bytes", v);
            }
        }
    }
    if any && method == axum::http::Method::OPTIONS {
        out.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
    }
}

fn build_router_inner(state: Arc<HttpState>) -> Router {
    let prefix = state.prefix.clone();
    let api = Router::new()
        .route("/:method", post(handle_unary).options(handle_preflight))
        .route(
            "/:method/init",
            post(handle_stream_init).options(handle_preflight),
        )
        .route(
            "/:method/exchange",
            post(handle_stream_exchange).options(handle_preflight),
        );

    let api = if state.upload_url_provider.is_some() {
        api.route(
            "/__upload_url__/init",
            post(handle_upload_url).options(handle_preflight),
        )
    } else {
        api
    };

    let mut app = if prefix.is_empty() {
        api
    } else {
        Router::new().nest(&prefix, api)
    };

    app = app.route(
        &format!(
            "{}{}",
            prefix,
            crate::auth::oauth::OAuthResourceMetadata::well_known_path()
        ),
        axum::routing::get(handle_oauth_metadata),
    );

    if state.health_enabled {
        // Always mount `/health` at the absolute root, regardless of
        // the API prefix. Liveness probes / load-balancer health
        // checks should never have to know which URL prefix the API
        // is under, and the conformance suite verifies it bypasses
        // auth even when every RPC endpoint requires it.
        app = app.route(
            "/health",
            axum::routing::get(handle_health).options(handle_preflight),
        );
    }
    if state.landing_page_enabled {
        let landing_path = if prefix.is_empty() {
            "/".to_string()
        } else {
            prefix.clone()
        };
        app = app.route(&landing_path, axum::routing::get(handle_landing));
    }
    if state.describe_page_enabled {
        app = app.route(
            &format!("{prefix}/describe"),
            axum::routing::get(handle_describe_page),
        );
    }

    app.with_state(state)
}

async fn handle_preflight(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> Response {
    let mut h = HeaderMap::new();
    attach_cors_headers(&state, &mut h, &headers, true);
    (StatusCode::NO_CONTENT, h).into_response()
}

async fn handle_health(State(state): State<Arc<HttpState>>) -> Response {
    let body = serde_json::json!({
        "status": "ok",
        "server_id": state.server.server_id,
        "protocol": state.server.protocol_name(),
    })
    .to_string();
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (StatusCode::OK, h, body).into_response()
}

async fn handle_landing(State(state): State<Arc<HttpState>>) -> Response {
    let body = render_landing(&state);
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    (StatusCode::OK, h, body).into_response()
}

async fn handle_describe_page(State(state): State<Arc<HttpState>>) -> Response {
    let body = render_describe_page(&state);
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    (StatusCode::OK, h, body).into_response()
}

fn render_landing(state: &Arc<HttpState>) -> String {
    let name = if state.server.protocol_name().is_empty() {
        "vgi-rpc service"
    } else {
        state.server.protocol_name()
    };
    let server_id = &state.server.server_id;
    let describe_link = if state.describe_page_enabled {
        format!(
            r#"<p><a href="{0}/describe">API reference</a></p>"#,
            state.prefix
        )
    } else {
        String::new()
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{name}</title></head><body>\
         <h1>{name}</h1><p>server_id: <code>{server_id}</code></p>{describe_link}\
         </body></html>"
    )
}

fn render_describe_page(state: &Arc<HttpState>) -> String {
    let mut body = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>API reference</title></head><body>",
    );
    body.push_str(&format!(
        "<h1>{}</h1><table><tr><th>method</th><th>type</th><th>doc</th></tr>",
        state.server.protocol_name()
    ));
    for name in state.server.sorted_method_names() {
        let m = &state.server.methods()[name];
        let kind = match m.method_type {
            crate::server::MethodType::Unary => "unary",
            _ => "stream",
        };
        let doc = m.doc.as_deref().unwrap_or("");
        body.push_str(&format!(
            "<tr><td><code>{name}</code></td><td>{kind}</td><td>{}</td></tr>",
            html_escape(doc)
        ));
    }
    body.push_str("</table></body></html>");
    body
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn attach_cors_headers(
    state: &Arc<HttpState>,
    out: &mut HeaderMap,
    req_headers: &HeaderMap,
    is_preflight: bool,
) {
    let Some(origins) = state.cors_origins.as_deref() else {
        return;
    };
    if let Ok(v) = HeaderValue::from_str(origins) {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    // When an authenticate callback is configured, requests carry
    // credentials (cookie / bearer). A browser only honours those
    // cross-origin when `Allow-Credentials: true` is present *and* the
    // origin is specific — `HttpStateBuilder::build` rejects the
    // `"*"` + auth combination, so the configured origin here is
    // always concrete.
    if state.authenticate.is_some() {
        out.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    out.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, GET, OPTIONS"),
    );
    let requested = req_headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Content-Type, Authorization, Cookie, Accept-Encoding");
    if let Ok(v) = HeaderValue::from_str(requested) {
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
    }
    out.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("Content-Encoding, WWW-Authenticate"),
    );
    if is_preflight {
        if let Ok(v) = HeaderValue::from_str(&state.cors_max_age.to_string()) {
            out.insert(header::ACCESS_CONTROL_MAX_AGE, v);
        }
    }
}

async fn handle_oauth_metadata(State(state): State<Arc<HttpState>>) -> Response {
    match state.oauth_metadata_json.as_ref() {
        Some(body) => {
            let mut h = HeaderMap::new();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            h.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            (StatusCode::OK, h, body.clone()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "").into_response(),
    }
}

/// Parse a `Cookie:` header into a name→value map. Surrounding
/// double-quotes on a value (RFC 6265 quoted form) are stripped.
fn parse_cookies(raw: Option<&str>) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let Some(raw) = raw else { return out };
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(v);
            out.insert(k.trim().to_string(), v.to_string());
        }
    }
    out
}

/// Copy the request headers into a `Vec<(String, String)>` for AuthRequest.
fn headers_to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect()
}

/// Run the authenticate callback (if any); on error, build a 401 response
/// with WWW-Authenticate attached.
fn authenticate_request(
    state: &Arc<HttpState>,
    method: &str,
    headers: &HeaderMap,
) -> std::result::Result<crate::auth::AuthContext, Response> {
    let Some(cb) = state.authenticate.as_ref() else {
        return Ok(crate::auth::AuthContext::anonymous());
    };
    let pairs = headers_to_pairs(headers);
    let req = crate::auth::AuthRequest {
        method,
        headers: &pairs,
        peer_addr: None,
    };
    match (cb)(&req) {
        Ok(ctx) => Ok(ctx),
        Err(err) => {
            let status = match err.error_type.as_str() {
                "PermissionError" | "ValueError" => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            let mut h = HeaderMap::new();
            // The response body must not echo internal detail. A 401 is
            // part of the auth contract, but the verifier's message can
            // carry an attacker-supplied `kid` or a raw library error —
            // keep that in the logs, return a generic body. A 500 from
            // the auth callback (e.g. a JWKS fetch failure) is purely
            // internal and gets the same treatment.
            let body = if status == StatusCode::UNAUTHORIZED {
                if let Some(wa) = state.www_authenticate.as_deref() {
                    if let Ok(hv) = HeaderValue::from_str(wa) {
                        h.insert(header::WWW_AUTHENTICATE, hv);
                    }
                }
                tracing::info!(
                    target: "vgi_rpc.http",
                    error = %err.message,
                    "request authentication rejected"
                );
                "authentication failed"
            } else {
                tracing::error!(
                    target: "vgi_rpc.http",
                    error = %err.message,
                    "authentication callback errored"
                );
                "internal error during authentication"
            };
            Err((status, h, body).into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn arrow_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(ARROW_CONTENT_TYPE),
    );
    (status, headers, body).into_response()
}

/// Hard wire-cap enforcement helper for stream-exchange responses.
/// Returns the original 200 response when within budget; otherwise
/// rebuilds the response as an EXCEPTION-only IPC stream surfaced via
/// 200 + `X-VGI-RPC-Error: true`.
fn enforce_response_body_cap(
    state: &Arc<HttpState>,
    schema: &arrow_schema::Schema,
    body: Vec<u8>,
    method: &str,
    server_id: &str,
    request_id: &str,
) -> Response {
    if let Some(limit) = state.max_response_bytes {
        if body.len() > limit {
            let err = RpcError::runtime_error(format!(
                "HTTP body exceeds max_response_bytes ({} > {}) for method {:?}",
                body.len(),
                limit,
                method
            ));
            return cap_error_response(schema, &err, server_id, request_id);
        }
    }
    arrow_response(StatusCode::OK, body)
}

/// Build a fresh IPC stream containing only an EXCEPTION batch and emit
/// it as 200 + `X-VGI-RPC-Error: true` so RPC clients see the message
/// as `RpcError`, not a transport failure. Used by the response-cap
/// strict-fail path.
fn cap_error_response(
    schema: &arrow_schema::Schema,
    err: &RpcError,
    server_id: &str,
    request_id: &str,
) -> Response {
    let mut buf = Vec::new();
    {
        let mut sw = StreamWriter::new(&mut buf, schema).unwrap();
        let md = build_error_metadata(err, server_id, request_id);
        let _ = sw.write(&empty_batch(schema).unwrap(), Some(&md));
        let _ = sw.finish();
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(ARROW_CONTENT_TYPE),
    );
    headers.insert("x-vgi-rpc-error", HeaderValue::from_static("true"));
    (StatusCode::OK, headers, buf).into_response()
}

fn plain_error(status: StatusCode, msg: String) -> Response {
    (status, msg).into_response()
}

fn has_arrow_ct(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s == ARROW_CONTENT_TYPE)
        .unwrap_or(false)
}

fn maybe_decompress(headers: &HeaderMap, body: &Bytes, max_size: usize) -> Result<Vec<u8>> {
    let enc = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if body.len() > max_size {
        return Err(RpcError::runtime_error(format!(
            "Request body exceeds max size ({} bytes > {})",
            body.len(),
            max_size
        )));
    }
    if enc.eq_ignore_ascii_case("zstd") {
        decode_zstd_bounded(body.as_ref(), max_size)
    } else {
        Ok(body.to_vec())
    }
}

/// Stream-decode a zstd payload, aborting once the decompressed length
/// exceeds `max_size`. Defends against zip-bomb-style oversized payloads
/// without first allocating the full decompressed result.
fn decode_zstd_bounded(input: &[u8], max_size: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = zstd::Decoder::new(input)
        .map_err(|e| RpcError::runtime_error(format!("zstd decode: {e}")))?;
    let mut out = Vec::with_capacity(input.len().min(max_size).min(64 * 1024));
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| RpcError::runtime_error(format!("zstd decode: {e}")))?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_size {
            return Err(RpcError::runtime_error(format!(
                "Decompressed body exceeds max size ({}+ bytes > {})",
                out.len() + n,
                max_size
            )));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn parse_request_from_body(body: &[u8]) -> Result<Request> {
    let mut r = StreamReader::new(body)?;
    let (batch, metadata) = r
        .read_next()?
        .ok_or_else(|| RpcError::protocol_error("empty IPC stream"))?;
    r.drain()?;
    Request::from_read_batch(batch, metadata, false)
}

fn error_stream_bytes(
    schema: &Schema,
    err: &RpcError,
    server_id: &str,
    request_id: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = StreamWriter::new(&mut buf, schema).unwrap();
    let md = build_error_metadata(err, server_id, request_id);
    let _ = w.write(&empty_batch(schema).unwrap(), Some(&md));
    let _ = w.finish();
    drop(w);
    buf
}

/// Build a complete arrow-typed error response. Centralizes the
/// `arrow_response(status, error_stream_bytes(Schema::empty(), ...))`
/// pattern used by every error-returning branch of the HTTP handlers.
fn arrow_error(
    state: &Arc<HttpState>,
    status: StatusCode,
    err: &RpcError,
    request_id: &str,
) -> Response {
    arrow_response(
        status,
        error_stream_bytes(&Schema::empty(), err, &state.server.server_id, request_id),
    )
}

fn decode_hex_key(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    if out.len() < 32 {
        return Err(format!(
            "signing key must be ≥ 32 bytes (got {} bytes)",
            out.len()
        ));
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> std::result::Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex character: {:?}", c as char)),
    }
}

fn decode_base64_key(s: &str) -> std::result::Result<Vec<u8>, String> {
    // Accept both padded and unpadded standard base64.
    let s = s.trim().trim_end_matches('=');
    let mut padded = s.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| format!("base64 decode: {e}"))?;
    if bytes.len() < 32 {
        return Err(format!(
            "signing key must be ≥ 32 bytes (got {} bytes)",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn new_session_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    bytes_to_hex(&b)
}

// ---------------------------------------------------------------------------
// Upload-URL endpoint
// ---------------------------------------------------------------------------

const UPLOAD_URL_METHOD: &str = "__upload_url__";
const MAX_UPLOAD_URL_COUNT: i64 = 100;

fn upload_url_response_schema() -> Schema {
    use arrow_schema::{DataType, Field, TimeUnit};
    Schema::new(vec![
        Field::new("upload_url", DataType::Utf8, false),
        Field::new("download_url", DataType::Utf8, false),
        Field::new(
            "expires_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ])
}

async fn handle_upload_url(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = match authenticate_request(&state, UPLOAD_URL_METHOD, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let _ = auth;
    if !has_arrow_ct(&headers) {
        return plain_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "need arrow content type".into(),
        );
    }
    let provider = match state.upload_url_provider.as_ref() {
        Some(p) => p.clone(),
        None => return plain_error(StatusCode::NOT_FOUND, "upload-url not enabled".into()),
    };

    let body = match maybe_decompress(&headers, &body, state.max_body_size) {
        Ok(b) => b,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };
    let req = match parse_request_from_body(&body) {
        Ok(r) => r,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };
    if !req.method.is_empty() && req.method != UPLOAD_URL_METHOD {
        let err = RpcError::protocol_error(format!(
            "Method mismatch: expected '{UPLOAD_URL_METHOD}', got '{}'",
            req.method
        ));
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }
    // Pull `count` from the int64 column (default 1, clamped to [1, MAX]).
    let mut count: i64 = 1;
    if let Some(arr) = req.column("count") {
        use arrow_array::Array;
        if let Some(c) = arr.as_any().downcast_ref::<arrow_array::Int64Array>() {
            if !c.is_empty() && !Array::is_null(c, 0) {
                count = c.value(0);
            }
        }
    }
    count = count.clamp(1, MAX_UPLOAD_URL_COUNT);

    // Generate URLs (provider may block on HTTP — same caveat as
    // ExternalStorage::upload, hence block_in_place).
    let urls_res = tokio::task::block_in_place(|| {
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            out.push(provider.generate_upload_url()?);
        }
        Ok::<_, RpcError>(out)
    });

    let schema = upload_url_response_schema();
    let mut body_buf = Vec::new();
    {
        let mut sw = match StreamWriter::new(&mut body_buf, &schema) {
            Ok(w) => w,
            Err(e) => {
                return arrow_error(
                    &state,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &e,
                    &req.request_id,
                )
            }
        };
        match urls_res {
            Ok(urls) => {
                use arrow_array::{StringArray, TimestampMicrosecondArray};
                let upload_arr = StringArray::from(
                    urls.iter()
                        .map(|u| u.upload_url.clone())
                        .collect::<Vec<_>>(),
                );
                let download_arr = StringArray::from(
                    urls.iter()
                        .map(|u| u.download_url.clone())
                        .collect::<Vec<_>>(),
                );
                let expires_arr = TimestampMicrosecondArray::from(
                    urls.iter().map(|u| u.expires_at_micros).collect::<Vec<_>>(),
                )
                .with_timezone("UTC");
                let batch = match RecordBatch::try_new(
                    Arc::new(schema.clone()),
                    vec![
                        Arc::new(upload_arr),
                        Arc::new(download_arr),
                        Arc::new(expires_arr),
                    ],
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        let err = RpcError::runtime_error(format!("upload-url batch: {e}"));
                        let md =
                            build_error_metadata(&err, &state.server.server_id, &req.request_id);
                        let _ = sw.write(&empty_batch(&schema).unwrap(), Some(&md));
                        let _ = sw.finish();
                        drop(sw);
                        return arrow_response(StatusCode::OK, body_buf);
                    }
                };
                let _ = sw.write(&batch, None);
            }
            Err(err) => {
                let md = build_error_metadata(&err, &state.server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(&schema).unwrap(), Some(&md));
            }
        }
        let _ = sw.finish();
    }
    arrow_response(StatusCode::OK, body_buf)
}

// ---------------------------------------------------------------------------
// Unary
// ---------------------------------------------------------------------------

async fn handle_unary(
    State(state): State<Arc<HttpState>>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Authenticate before any other rejection: an unauthenticated
    // caller should always see 401, regardless of whether they sent
    // the right content type or anything else.
    let auth = match authenticate_request(&state, &method, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !has_arrow_ct(&headers) {
        return plain_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "need arrow content type".into(),
        );
    }
    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let server = state.server.clone();

    let body = match maybe_decompress(&headers, &body, state.max_body_size) {
        Ok(b) => b,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };
    let mut req = match parse_request_from_body(&body) {
        Ok(r) => r,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };

    // If the request batch is an external-location pointer (zero rows +
    // `vgi_rpc.location` metadata), fetch the referenced bytes and use
    // the inner batch's columns for parameter extraction. Dispatch
    // metadata (method, request_id) is taken from the outer batch.
    if md_get(&req.metadata, crate::metadata::LOCATION_KEY).is_some() {
        if let Some(cfg) = server.external_config().as_ref() {
            let outer_md = req.metadata.clone();
            let outer_batch = req.batch.clone();
            let resolved = tokio::task::block_in_place(|| {
                crate::external::resolve_external_location(&outer_batch, &outer_md, cfg)
            });
            match resolved {
                Ok((inner_batch, _user_md)) => {
                    req.batch = inner_batch;
                }
                Err(err) => {
                    return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
                }
            }
        }
    }

    // __describe__ introspection — served as a unary call.
    if server.describe_enabled() && method == crate::introspect::DESCRIBE_METHOD_NAME {
        let (batch, md) = match crate::introspect::build_describe(
            server.protocol_name(),
            server.methods(),
            &server.server_id,
        ) {
            Ok(x) => x,
            Err(err) => {
                return arrow_error(
                    &state,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &err,
                    &req.request_id,
                );
            }
        };
        let mut buf = Vec::new();
        let _ = crate::introspect::write_describe_response(&mut buf, &batch, &md);
        return arrow_response(StatusCode::OK, buf);
    }

    let Some(info) = server
        .method(&method)
        .filter(|m| m.method_type == MethodType::Unary)
    else {
        let err = RpcError::attribute_error(format!("Unknown method: '{}'", method));
        return arrow_error(&state, StatusCode::NOT_FOUND, &err, &req.request_id);
    };

    let ctx = CallContext::with_auth_cookies(&server, &req, auth.clone(), cookies);
    let dispatch_info = crate::hooks::DispatchInfo::from_request(&server, &req, "unary", &auth);
    let hook = server.dispatch_hook.clone();
    let hook_token = hook.as_ref().map(|h| h.on_dispatch_start(&dispatch_info));

    let mut stats = crate::hooks::CallStatistics {
        input_batches: 1,
        input_rows: req.batch.num_rows() as u64,
        ..Default::default()
    };

    let result = (info.unary.as_ref().unwrap())(&req, &ctx);
    let logs = ctx.drain_logs();
    let mut app_err: Option<RpcError> = None;

    let mut buf = Vec::new();
    {
        let mut sw = StreamWriter::new(&mut buf, &info.result_schema).unwrap();
        for log in &logs {
            let md = build_log_metadata(log, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(&info.result_schema).unwrap(), Some(&md));
        }
        match result {
            Ok(batch_opt) => {
                let out_batch =
                    batch_opt.unwrap_or_else(|| empty_batch(&info.result_schema).unwrap());
                stats.output_batches = 1;
                stats.output_rows = out_batch.num_rows() as u64;
                if let Some(cfg) = server.external_config().as_ref() {
                    // `maybe_externalize_batch` may invoke a blocking
                    // upload (e.g. reqwest::blocking). Allow blocking
                    // in this async handler so the inner client's
                    // tokio runtime can drop without panicking.
                    let externalized = tokio::task::block_in_place(|| {
                        crate::external::maybe_externalize_batch(&out_batch, None, cfg)
                    });
                    match externalized {
                        Ok(Some((ptr, md))) => {
                            let _ = sw.write(&ptr, Some(&md));
                        }
                        Ok(None) => {
                            let _ = sw.write(&out_batch, None);
                        }
                        Err(err) => {
                            let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                            let _ = sw.write(&empty_batch(&info.result_schema).unwrap(), Some(&md));
                            app_err = Some(err);
                        }
                    }
                } else {
                    let _ = sw.write(&out_batch, None);
                }
            }
            Err(err) => {
                let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(&info.result_schema).unwrap(), Some(&md));
                app_err = Some(err);
            }
        }
        let _ = sw.finish();
    }

    if let Some(hook) = hook {
        hook.on_dispatch_end(
            hook_token.unwrap_or(0),
            &dispatch_info,
            app_err.as_ref(),
            &stats,
        );
    }
    // Operator-facing wire body cap.  Hard for unary — overshoot
    // replaces the response with an EXCEPTION-only IPC stream surfaced
    // via 200 + `X-VGI-RPC-Error: true`.  Mirrors Python's strict-fail
    // contract; the literal `max_response_bytes` token in the message
    // is what the cross-language conformance suite asserts on.
    if let Some(limit) = state.max_response_bytes {
        if buf.len() > limit {
            let err = RpcError::runtime_error(format!(
                "HTTP body exceeds max_response_bytes ({} > {}) for method {:?}",
                buf.len(),
                limit,
                method
            ));
            return cap_error_response(
                &info.result_schema,
                &err,
                &server.server_id,
                &req.request_id,
            );
        }
    }
    arrow_response(StatusCode::OK, buf)
}

// ---------------------------------------------------------------------------
// Stream init
// ---------------------------------------------------------------------------

async fn handle_stream_init(
    State(state): State<Arc<HttpState>>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = match authenticate_request(&state, &method, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !has_arrow_ct(&headers) {
        return plain_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "need arrow content type".into(),
        );
    }
    let auth_for_token = auth.clone();
    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let server = state.server.clone();
    let body = match maybe_decompress(&headers, &body, state.max_body_size) {
        Ok(b) => b,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };
    let req = match parse_request_from_body(&body) {
        Ok(r) => r,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };

    let Some(info) = server
        .method(&method)
        .filter(|m| m.method_type != MethodType::Unary)
    else {
        let err = RpcError::attribute_error(format!("Unknown stream method: '{}'", method));
        return arrow_error(&state, StatusCode::NOT_FOUND, &err, &req.request_id);
    };

    let ctx = CallContext::with_auth_cookies(&server, &req, auth, cookies);
    let init_result = (info.stream.as_ref().unwrap())(&req, &ctx);
    let init_logs = ctx.drain_logs();

    let sr = match init_result {
        Ok(s) => s,
        Err(err) => {
            return arrow_response(
                StatusCode::OK,
                error_stream_bytes(&empty_schema(), &err, &server.server_id, &req.request_id),
            );
        }
    };

    let StreamResult {
        output_schema,
        input_schema,
        state: mut ss,
        header,
        header_metadata,
    } = sr;

    let mut body_buf = Vec::new();

    // Write header stream (if any) into body_buf.
    if let Some(header_batch) = header.as_ref() {
        let hdr_schema = header_batch.schema();
        let mut hw = StreamWriter::new(&mut body_buf, hdr_schema.as_ref()).unwrap();
        for log in &init_logs {
            let md = build_log_metadata(log, &server.server_id, &req.request_id);
            let _ = hw.write(&empty_batch(hdr_schema.as_ref()).unwrap(), Some(&md));
        }
        let _ = hw.write(header_batch, header_metadata.as_ref());
        let _ = hw.finish();
    }

    let is_producer = matches!(ss, StreamStateKind::Producer(_));
    let stream_id = new_session_id();

    let mut finished = false;
    let mut init_error: Option<RpcError> = None;
    {
        let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
        if header.is_none() {
            for log in &init_logs {
                let md = build_log_metadata(log, &server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            }
        }
        let _ = header_metadata;
        if is_producer {
            finished = run_producer(
                &mut sw,
                &mut ss,
                &output_schema,
                &server,
                &req,
                state.producer_batch_limit,
            );
        }
        if !finished {
            match build_continuation_token(
                &state,
                &auth_for_token,
                &ss,
                &output_schema,
                input_schema.as_ref(),
                &stream_id,
            ) {
                Ok(token) => {
                    let md = Metadata::from([(STATE_KEY.to_string(), token)]);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                }
                Err(err) => {
                    // Handler doesn't implement encode_state — emit as an
                    // error envelope so the client sees a useful message
                    // instead of a hung stream.
                    let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    init_error = Some(err);
                }
            }
        }
        let _ = sw.finish();
    }
    let _ = init_error; // surfaced via error envelope already

    arrow_response(StatusCode::OK, body_buf)
}

/// Encode a `StreamStateKind` into a signed state token. The token is
/// bound to `auth` so a different identity replaying it will fail HMAC
/// verification on the next continuation request.
fn build_continuation_token(
    state: &Arc<HttpState>,
    auth: &crate::auth::AuthContext,
    ss: &StreamStateKind,
    output_schema: &SchemaRef,
    input_schema: Option<&SchemaRef>,
    stream_id: &str,
) -> Result<String> {
    let state_bytes = match ss {
        StreamStateKind::Producer(p) => p.encode_state()?,
        StreamStateKind::Exchange(e) => e.encode_state()?,
    };
    let out_schema_bytes = write_schema_bytes(output_schema.as_ref())?;
    let in_schema_bytes = match input_schema {
        Some(s) => write_schema_bytes(s.as_ref())?,
        None => Vec::new(),
    };
    Ok(state.pack_state_token(
        auth,
        &state_bytes,
        &out_schema_bytes,
        &in_schema_bytes,
        stream_id,
    ))
}

fn run_producer<W: std::io::Write>(
    sw: &mut StreamWriter<W>,
    ss: &mut StreamStateKind,
    output_schema: &SchemaRef,
    server: &Arc<RpcServer>,
    req: &Request,
    limit: usize,
) -> bool {
    // Continuation producers run without auth context (session-bound).
    let ctx = CallContext::for_request(server, req);
    let producer = match ss {
        StreamStateKind::Producer(p) => p,
        StreamStateKind::Exchange(_) => unreachable!(),
    };
    let mut batches_written = 0usize;
    while limit == 0 || batches_written < limit {
        let mut out = OutputCollector::new(output_schema.clone(), true);
        let result = producer.produce(&mut out, &ctx);
        for log in ctx.drain_logs() {
            let md = build_log_metadata(&log, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
        }
        if let Err(err) = result {
            let md = build_error_metadata(&err, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            return true;
        }
        let finished = out.finished();
        let mut emitted_data = false;
        for item in out.items.drain(..) {
            match item {
                Emitted::Log(log) => {
                    let md = build_log_metadata(&log, &server.server_id, &req.request_id);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                }
                Emitted::Batch { batch, metadata } => {
                    let _ = sw.write(&batch, metadata.as_ref());
                    emitted_data = true;
                }
            }
        }
        if emitted_data {
            batches_written += 1;
        }
        if finished {
            return true;
        }
        if !emitted_data {
            // Guard against degenerate producers that neither emit nor finish.
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Stream exchange / producer continuation / cancel
// ---------------------------------------------------------------------------

async fn handle_stream_exchange(
    State(state): State<Arc<HttpState>>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = match authenticate_request(&state, &method, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !has_arrow_ct(&headers) {
        return plain_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "need arrow content type".into(),
        );
    }

    let server = state.server.clone();
    let body = match maybe_decompress(&headers, &body, state.max_body_size) {
        Ok(b) => b,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };
    // Parse input batch (may be empty-schema for cancel / producer continuation).
    let (batch, metadata) = match read_input_batch(&body) {
        Ok(x) => x,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };

    let Some(token) = md_get(&metadata, STATE_KEY).map(str::to_owned) else {
        let err = RpcError::runtime_error("Missing state token in exchange request");
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, "");
    };
    let cancelled = md_get(&metadata, CANCEL_KEY).is_some();

    let unpacked = match state.unpack_state_token(&auth, &token) {
        Ok(u) => u,
        Err(err) => return arrow_error(&state, StatusCode::BAD_REQUEST, &err, ""),
    };

    // Reconstruct schemas from token-carried IPC bytes.
    let output_schema = match read_schema_bytes(&unpacked.output_schema_bytes) {
        Ok(s) => s,
        Err(err) => return arrow_error(&state, StatusCode::BAD_REQUEST, &err, ""),
    };
    let input_schema: Option<SchemaRef> = if unpacked.input_schema_bytes.is_empty() {
        None
    } else {
        match read_schema_bytes(&unpacked.input_schema_bytes) {
            Ok(s) => Some(s),
            Err(err) => return arrow_error(&state, StatusCode::BAD_REQUEST, &err, ""),
        }
    };

    // Resolve the method's state decoder from URL path.
    let Some(info) = server
        .method(&method)
        .filter(|m| m.method_type != MethodType::Unary)
    else {
        let err = RpcError::attribute_error(format!("Unknown stream method: '{}'", method));
        return arrow_error(&state, StatusCode::NOT_FOUND, &err, "");
    };
    let Some(decoder) = info.state_decoder.as_ref() else {
        let err = RpcError::runtime_error(format!(
            "Stream method '{method}' is registered without a state decoder; \
             it cannot serve HTTP continuation requests"
        ));
        return arrow_error(&state, StatusCode::INTERNAL_SERVER_ERROR, &err, "");
    };
    let mut ss = match decoder(&unpacked.state_bytes) {
        Ok(s) => s,
        Err(err) => return arrow_error(&state, StatusCode::BAD_REQUEST, &err, ""),
    };

    let req = Request {
        method: method.clone(),
        request_id: md_get(&metadata, REQUEST_ID_KEY).unwrap_or("").to_string(),
        batch: empty_batch(&Schema::empty()).unwrap(),
        metadata: metadata.clone(),
    };
    let ctx = CallContext::for_request(&server, &req);

    let mut body_buf = Vec::new();

    if cancelled {
        match &mut ss {
            StreamStateKind::Producer(p) => p.on_cancel(&ctx),
            StreamStateKind::Exchange(e) => e.on_cancel(&ctx),
        }
        {
            let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
            let _ = sw.finish();
        }
        return arrow_response(StatusCode::OK, body_buf);
    }

    if matches!(ss, StreamStateKind::Producer(_)) {
        // Producer continuation.
        let finished;
        {
            let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
            finished = run_producer(
                &mut sw,
                &mut ss,
                &output_schema,
                &server,
                &req,
                state.producer_batch_limit,
            );
            if !finished {
                match build_continuation_token(
                    &state,
                    &auth,
                    &ss,
                    &output_schema,
                    input_schema.as_ref(),
                    &unpacked.stream_id,
                ) {
                    Ok(new_token) => {
                        let md = Metadata::from([(STATE_KEY.to_string(), new_token)]);
                        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    }
                    Err(err) => {
                        let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    }
                }
            }
            let _ = sw.finish();
        }
        return arrow_response(StatusCode::OK, body_buf);
    }

    // Exchange continuation.
    let casted = match &input_schema {
        Some(exp) if batch.schema() != *exp => match cast_batch(&batch, exp) {
            Ok(b) => b,
            Err(e) => {
                let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
                let md = build_error_metadata(&e, &server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                let _ = sw.finish();
                drop(sw);
                return arrow_response(StatusCode::OK, body_buf);
            }
        },
        _ => batch,
    };

    let mut out = OutputCollector::new(output_schema.clone(), false);
    let res = match &mut ss {
        StreamStateKind::Exchange(e) => e.exchange(&casted, &mut out, &ctx),
        _ => unreachable!(),
    };

    {
        let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
        for log in ctx.drain_logs() {
            let md = build_log_metadata(&log, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
        }
        if let Err(err) = res {
            let md = build_error_metadata(&err, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
        } else {
            let new_token = match build_continuation_token(
                &state,
                &auth,
                &ss,
                &output_schema,
                input_schema.as_ref(),
                &unpacked.stream_id,
            ) {
                Ok(t) => t,
                Err(err) => {
                    let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    let _ = sw.finish();
                    drop(sw);
                    return arrow_response(StatusCode::OK, body_buf);
                }
            };
            let mut wrote_data = false;
            for item in out.items.drain(..) {
                match item {
                    Emitted::Log(log) => {
                        let md = build_log_metadata(&log, &server.server_id, &req.request_id);
                        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    }
                    Emitted::Batch { batch, metadata } => {
                        let mut md = metadata.unwrap_or_default();
                        md.insert(STATE_KEY.to_string(), new_token.clone());
                        let _ = sw.write(&batch, Some(&md));
                        wrote_data = true;
                    }
                }
            }
            if !wrote_data {
                let md = Metadata::from([(STATE_KEY.to_string(), new_token)]);
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            }
        }
        let _ = sw.finish();
    }

    enforce_response_body_cap(
        &state,
        output_schema.as_ref(),
        body_buf,
        &method,
        &server.server_id,
        "",
    )
}

fn read_input_batch(body: &[u8]) -> Result<(RecordBatch, Metadata)> {
    let mut r = StreamReader::new(body)?;
    let (batch, metadata) = r
        .read_next()?
        .ok_or_else(|| RpcError::runtime_error("no batch in exchange request"))?;
    r.drain()?;
    Ok((batch, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn state_with_key() -> Arc<HttpState> {
        use crate::server::RpcServer;
        let server = Arc::new(RpcServer::builder().server_id("test").build());
        HttpState::builder()
            .server(server)
            .token_key(&[7u8; 32])
            .token_ttl(Duration::from_millis(50))
            .max_body_size(1024)
            .build()
    }

    fn sample_schema_bytes() -> Vec<u8> {
        use arrow_schema::{DataType, Field, Schema};
        write_schema_bytes(&Schema::new(vec![Field::new("x", DataType::Int64, false)])).unwrap()
    }

    #[tokio::test]
    async fn pack_unpack_roundtrip() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let state_bytes = b"state-payload";
        let out_sch = sample_schema_bytes();
        let in_sch = sample_schema_bytes();
        let token = s.pack_state_token(&auth, state_bytes, &out_sch, &in_sch, "sid-123");
        let unpacked = s.unpack_state_token(&auth, &token).unwrap();
        assert_eq!(unpacked.state_bytes, state_bytes);
        assert_eq!(unpacked.output_schema_bytes, out_sch);
        assert_eq!(unpacked.input_schema_bytes, in_sch);
        assert_eq!(unpacked.stream_id, "sid-123");
    }

    #[tokio::test]
    async fn unpack_rejects_tampered_ciphertext() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let token = s.pack_state_token(&auth, b"s", b"o", b"i", "sid");
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(token.as_bytes())
            .unwrap();
        // Flip a bit inside the ciphertext (past the 1-byte version + 24-byte
        // nonce header owned by `crypto`).
        let cipher_idx = 1 + 24;
        bytes[cipher_idx] ^= 0x01;
        let tampered = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert!(s.unpack_state_token(&auth, &tampered).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_tampered_nonce() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let token = s.pack_state_token(&auth, b"s", b"o", b"i", "sid");
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(token.as_bytes())
            .unwrap();
        // Flip the first nonce byte; AEAD decryption must reject.
        bytes[1] ^= 0x01;
        let tampered = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert!(s.unpack_state_token(&auth, &tampered).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_unknown_version() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let token = s.pack_state_token(&auth, b"s", b"o", b"i", "sid");
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(token.as_bytes())
            .unwrap();
        bytes[0] = 0x99;
        let tampered = base64::engine::general_purpose::STANDARD.encode(bytes);
        let err = s.unpack_state_token(&auth, &tampered).unwrap_err();
        // Wrong-version tokens map to the same uniform error as every other
        // bad-token mode — callers cannot distinguish failure modes.
        assert!(err.message.contains("signature verification failed"));
    }

    #[tokio::test]
    async fn unpack_rejects_malformed_base64() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let err = s.unpack_state_token(&auth, "not!base64!").unwrap_err();
        assert!(err.message.contains("Malformed"));
    }

    #[tokio::test]
    async fn unpack_rejects_different_key() {
        use crate::server::RpcServer;
        let server = Arc::new(RpcServer::builder().server_id("t").build());
        let a = HttpState::builder()
            .server(server.clone())
            .token_key(&[1u8; 32])
            .build();
        let b = HttpState::builder()
            .server(server)
            .token_key(&[2u8; 32])
            .build();
        let auth = crate::auth::AuthContext::anonymous();
        let tok = a.pack_state_token(&auth, b"s", b"o", b"i", "sid");
        assert!(b.unpack_state_token(&auth, &tok).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_expired_token() {
        let s = state_with_key(); // ttl = 50ms
        let auth = crate::auth::AuthContext::anonymous();
        // Pack a token whose created_at is far in the past, using the
        // same AAD the server will reconstruct for an anonymous caller.
        let aad = compute_aad(&auth);
        let stale = pack_state_token(&[7u8; 32], &aad, b"s", b"o", b"i", "sid", 0);
        let err = s.unpack_state_token(&auth, &stale).unwrap_err();
        assert!(err.message.contains("expired"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn unpack_rejects_different_principal() {
        let s = state_with_key();
        let alice = crate::auth::AuthContext::for_principal("bearer", "alice");
        let bob = crate::auth::AuthContext::for_principal("bearer", "bob");
        let tok = s.pack_state_token(&alice, b"s", b"o", b"i", "sid");
        assert!(s.unpack_state_token(&alice, &tok).is_ok());
        assert!(s.unpack_state_token(&bob, &tok).is_err());
        let anon = crate::auth::AuthContext::anonymous();
        assert!(s.unpack_state_token(&anon, &tok).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_authenticated_replay_of_anonymous_token() {
        let s = state_with_key();
        let anon = crate::auth::AuthContext::anonymous();
        let alice = crate::auth::AuthContext::for_principal("bearer", "alice");
        let tok = s.pack_state_token(&anon, b"s", b"o", b"i", "sid");
        assert!(s.unpack_state_token(&alice, &tok).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_cross_domain_replay() {
        let s = state_with_key();
        let bearer_alice = crate::auth::AuthContext::for_principal("bearer", "alice");
        let mtls_alice = crate::auth::AuthContext::for_principal("mtls", "alice");
        let tok = s.pack_state_token(&bearer_alice, b"s", b"o", b"i", "sid");
        assert!(s.unpack_state_token(&mtls_alice, &tok).is_err());
    }

    #[tokio::test]
    async fn decompress_rejects_oversize() {
        let hdr = HeaderMap::new();
        let body = Bytes::from(vec![0u8; 1025]);
        let err = super::maybe_decompress(&hdr, &body, 1024).unwrap_err();
        assert!(err.message.contains("exceeds max size"));
    }

    #[test]
    fn zstd_bounded_rejects_zip_bomb_without_full_alloc() {
        // 8 MiB of zeroes compresses to a tiny payload — small enough to
        // pass the encoded-size check but it would blow past the limit
        // when fully decompressed.
        let huge = vec![0u8; 8 * 1024 * 1024];
        let compressed = zstd::encode_all(huge.as_slice(), 1).unwrap();
        assert!(compressed.len() < 100_000, "compressed should be tiny");
        let err = super::decode_zstd_bounded(&compressed, 64 * 1024).unwrap_err();
        assert!(
            err.message.contains("exceeds max size"),
            "expected oversize error, got: {}",
            err.message
        );
    }

    #[test]
    fn zstd_bounded_passes_small_payload() {
        let small = b"hello-world".repeat(10);
        let compressed = zstd::encode_all(small.as_slice(), 1).unwrap();
        let out = super::decode_zstd_bounded(&compressed, 1024).unwrap();
        assert_eq!(out, small);
    }

    #[test]
    fn decode_hex_key_roundtrip() {
        let key =
            decode_hex_key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0x00);
        assert_eq!(key[31], 0x1f);
    }

    #[test]
    fn decode_hex_key_rejects_short() {
        assert!(decode_hex_key("deadbeef").is_err());
    }

    #[test]
    fn decode_hex_key_rejects_bad_char() {
        assert!(decode_hex_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn decode_base64_key_accepts_padded() {
        let s = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let out = decode_base64_key(&s).unwrap();
        assert_eq!(out, vec![7u8; 32]);
    }

    #[test]
    fn decode_base64_key_accepts_unpadded() {
        let s = base64::engine::general_purpose::STANDARD
            .encode([7u8; 32])
            .trim_end_matches('=')
            .to_string();
        let out = decode_base64_key(&s).unwrap();
        assert_eq!(out, vec![7u8; 32]);
    }

    #[test]
    fn decode_base64_key_rejects_short() {
        let s = base64::engine::general_purpose::STANDARD.encode(b"short");
        assert!(decode_base64_key(&s).is_err());
    }

    #[tokio::test]
    async fn token_key_hex_round_trips_through_token() {
        use crate::server::RpcServer;
        let server = Arc::new(RpcServer::builder().server_id("t").build());
        let a = HttpState::builder()
            .server(server.clone())
            .token_key_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .build();
        let b = HttpState::builder()
            .server(server)
            .token_key_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .build();
        let auth = crate::auth::AuthContext::anonymous();
        let tok = a.pack_state_token(&auth, b"s", b"o", b"i", "sid");
        assert_eq!(b.unpack_state_token(&auth, &tok).unwrap().stream_id, "sid");
    }

    #[test]
    fn response_buffer_ceiling_never_below_hard_cap() {
        use crate::server::RpcServer;
        let mk = |soft: Option<usize>| {
            let server = Arc::new(RpcServer::builder().server_id("t").build());
            let mut b = HttpState::builder().server(server).token_key(&[9u8; 32]);
            if let Some(n) = soft {
                b = b.max_response_bytes(n);
            }
            b.build()
        };
        // No soft cap → exactly the hard cap.
        assert_eq!(
            response_buffer_ceiling(&mk(None)),
            MAX_RESPONSE_BYTES_HARD_CAP
        );
        // A small soft cap must NOT shrink the middleware ceiling — the
        // soft cap is a producer knob the wire may legitimately
        // overshoot.
        assert_eq!(
            response_buffer_ceiling(&mk(Some(8))),
            MAX_RESPONSE_BYTES_HARD_CAP
        );
        // A soft cap larger than the hard cap leaves overshoot headroom.
        let big = MAX_RESPONSE_BYTES_HARD_CAP;
        assert_eq!(response_buffer_ceiling(&mk(Some(big))), big * 2);
    }
}
