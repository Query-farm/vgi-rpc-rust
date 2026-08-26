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
use std::collections::HashMap;

use crate::metadata::{CALL_STATE_KEY, CANCEL_KEY, REQUEST_ID_KEY, STATE_KEY};
use crate::server::{
    build_error_metadata, build_log_metadata, cast_batch, validate_parameter_batch,
    validate_protocol_version, CallContext, MethodType, Request, RpcServer,
};
use crate::stream::{empty_schema, Emitted, OutputCollector, StreamResult, StreamStateKind};
use crate::unauthorized::{AuthReason, AUTH_PROXY_REQUIRED_HEADER, AUTH_REASON_HEADER};
use crate::wire::{bytes_to_hex, empty_batch, md_get, Metadata, StreamReader, StreamWriter};
use axum::http::HeaderName;

pub const ARROW_CONTENT_TYPE: &str = "application/vnd.apache.arrow.stream";

/// The shared, self-contained VGI landing page, vendored byte-identically
/// from `vgi-web-frontend/public/landing.html`. Served at `GET {prefix}/`
/// for browsers; it reads the worker's catalogs by speaking the VGI protocol
/// through [`CLIENT_BUNDLE`], imported same-origin from
/// `{prefix}/vgi-client.js`.
const LANDING_HTML: &str = include_str!("landing.html");

/// Browser build of the `@query-farm/vgi` JS client, vendored from
/// `vgi-web-frontend` (`bun run build:landing-client`) and served at
/// `GET {prefix}/vgi-client.js`.
///
/// The worker serves it rather than the page importing it from a CDN: the page
/// is same-origin with an authenticated worker and carries its session cookie,
/// so third-party script there would run with full access to that origin — and
/// a CDN dependency would break air-gapped deployments, which today need
/// nothing but the worker. Vendored and released as a pair with the page.
const CLIENT_BUNDLE: &str = include_str!("vgi-client.js");

/// Worker identity for the standardized VGI landing surface.
///
/// The shared `landing.html` reads catalog metadata by speaking the VGI
/// protocol through the client bundle the worker serves beside it, so nothing
/// about the catalog belongs here. What the protocol has no method for — which
/// worker this is, what it is called, what version it runs — rides on the JSON
/// status document at `GET {prefix}/?format=json`.
#[derive(Clone, Debug, Default)]
pub struct LandingInfo {
    /// Worker name shown as the page heading.
    pub name: String,
    /// One-line description shown under the heading.
    pub doc: String,
    /// Worker version string shown in the footer.
    pub version: String,
}

// Sticky-session header conventions (HTTP-only). Header names are
// compared case-insensitively by axum's `HeaderMap`, so the lowercase
// forms here match the canonical `VGI-Session` etc. on the wire.
const SESSION_HEADER: &str = "vgi-session";
const SESSION_ACCEPT_HEADER: &str = "vgi-session-accept";
const SESSION_CLOSE_HEADER: &str = "vgi-session-close";
const ECHO_HEADER_PREFIX: &str = "vgi-echo-";
const STICKY_ENABLED_HEADER: &str = "vgi-sticky-enabled";
const STICKY_DEFAULT_TTL_HEADER: &str = "vgi-sticky-default-ttl";
const STICKY_ECHO_HEADERS_HEADER: &str = "vgi-sticky-echo-headers";
/// Framework-managed sticky session teardown endpoint path segment.
const SESSION_ENDPOINT: &str = "__session__";

/// Response bodies smaller than this are never zstd-compressed: below it the
/// frame overhead dominates and often enlarges the payload, so the CPU and
/// allocation cost of compressing isn't repaid.
///
/// Private, so the public `HttpStateBuilder::response_compression_level` docs
/// spell the number out rather than link here (a public->private intra-doc
/// link is a rustdoc warning). Keep the two in sync if this changes.
const MIN_ZSTD_COMPRESS_BYTES: usize = 1024;

/// zstd level used for response compression when the builder is not told
/// otherwise. Response compression is **on by default**, matching the Python
/// SDK's `compression_level=1`.
///
/// Level 1 rather than the zstd default of 3 is not a size/speed trade: on an
/// 8.41 MB Arrow payload level 1 measured 4.7x faster than level 3 *and*
/// produced the smaller body. Arrow IPC is already dictionary/run-length
/// friendly, so the extra search effort at higher levels buys nothing here.
pub const DEFAULT_RESPONSE_COMPRESSION_LEVEL: i32 = 1;

/// VGI's own response-codec preference header. Clients that cannot set the
/// standard `Accept-Encoding` state their preference here instead — notably
/// browser `fetch()`, for which `Accept-Encoding` is a forbidden header name.
/// That is the WASM path, so ignoring this header would mean the browser
/// always gets identity-encoded responses.
const VGI_ACCEPT_ENCODING_HEADER: &str = "x-vgi-accept-encoding";
/// Response counterpart of [`VGI_ACCEPT_ENCODING_HEADER`]. Stamped instead of
/// the standard `Content-Encoding` when the winning codec was offered *only*
/// via the custom request header: such a client's fetch/proxy layer would
/// auto-decode or mangle a standard `Content-Encoding`, so the response must
/// not claim one.
const VGI_CONTENT_ENCODING_HEADER: &str = "x-vgi-content-encoding";
/// Marks a 200 response whose Arrow body carries an RPC error rather than a
/// result. Browser clients must be able to read it, so it is CORS-exposed.
const RPC_ERROR_HEADER: &str = "x-vgi-rpc-error";

/// A response content coding vgi-rpc knows how to negotiate.
///
/// Knowing a codec is not the same as being able to *produce* it — see
/// [`ResponseEncoding::producible`]. `identity` is a first-class token: a
/// client can ask for it explicitly to switch response compression off for
/// that request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseEncoding {
    /// No coding at all. Always producible; carries no response header.
    Identity,
    Zstd,
    Gzip,
}

/// The compressed codings this server advertises, in its own preference
/// order. Informational only — the *client's* order decides the winner (see
/// [`pick_response_encoding`]). `identity` is deliberately absent: it is
/// always available and so carries no information.
const RESPONSE_ENCODING_PREFERENCE: [ResponseEncoding; 2] =
    [ResponseEncoding::Zstd, ResponseEncoding::Gzip];

impl ResponseEncoding {
    /// Wire token, as it appears in `Accept-Encoding` / `Content-Encoding`.
    fn as_str(self) -> &'static str {
        match self {
            ResponseEncoding::Identity => "identity",
            ResponseEncoding::Zstd => "zstd",
            ResponseEncoding::Gzip => "gzip",
        }
    }

    /// Parse a single already-trimmed, already-lowercased token.
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "identity" => Some(ResponseEncoding::Identity),
            "zstd" => Some(ResponseEncoding::Zstd),
            "gzip" => Some(ResponseEncoding::Gzip),
            _ => None,
        }
    }

    /// Can this server actually emit this coding right now? True only when an
    /// encoder exists in the build *and* configuration enables it.
    ///
    /// This is the single source of truth for producibility: both the
    /// negotiation walk and the `VGI-Supported-Encodings` advertisement read
    /// it, so the two cannot drift. Registering a new producible codec is one
    /// arm here plus the matching arm in [`encode_response_body`].
    fn producible(self, compression_level: Option<i32>) -> bool {
        match self {
            // Shipping bytes unchanged needs no encoder and no configuration.
            ResponseEncoding::Identity => true,
            // Both encoders are hard dependencies of the HTTP feature;
            // `response_compression_level` is their shared configuration gate,
            // on by default at [`DEFAULT_RESPONSE_COMPRESSION_LEVEL`] and
            // cleared by `HttpStateBuilder::disable_response_compression`.
            ResponseEncoding::Zstd | ResponseEncoding::Gzip => compression_level.is_some(),
        }
    }

    /// Can this server decompress a *request* body in this coding? See
    /// [`decode_content_encoding`], which implements the request side.
    fn decodable(self) -> bool {
        match self {
            ResponseEncoding::Identity => true,
            ResponseEncoding::Zstd | ResponseEncoding::Gzip => true,
        }
    }
}

/// Value for the `VGI-Supported-Encodings` capability header: the codings this
/// server can handle in **both** directions — decode on requests *and* produce
/// on responses — in server-preference order, excluding `identity`.
///
/// The intersection is deliberate. The HTTP server implements zstd and gzip
/// in both directions, so an enabled server advertises `zstd, gzip`.
///
/// Empty when the intersection is empty — response compression disabled by
/// config (the default) or no encoder available. The header is still emitted
/// in that case: present-but-empty means "I speak no compression", which is a
/// different statement from an older server that omits the header entirely
/// (which clients read as "assume zstd").
///
/// Derived from [`ResponseEncoding::producible`] / [`ResponseEncoding::decodable`]
/// so it cannot drift from what the negotiation walk actually does.
fn supported_encodings_header_value(compression_level: Option<i32>) -> String {
    RESPONSE_ENCODING_PREFERENCE
        .iter()
        .filter(|e| {
            **e != ResponseEncoding::Identity && e.producible(compression_level) && e.decodable()
        })
        .map(|e| e.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse a comma-separated `Accept-Encoding`-style header value into an
/// ordered, de-duplicated list of the codings we know.
///
/// Mirrors the canonical Python `parse_encoding_list`: split on `,`, trim,
/// lowercase, drop everything after `;` (q-values are parsed off and
/// **ignored**, never honoured), skip unknown tokens, keep the first
/// occurrence of each codec, and preserve the client's stated order. A
/// missing or empty header parses to an empty list.
fn parse_encoding_list(header_value: Option<&str>) -> Vec<ResponseEncoding> {
    let mut out: Vec<ResponseEncoding> = Vec::new();
    let Some(value) = header_value else {
        return out;
    };
    for raw in value.split(',') {
        let token = raw
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        if let Some(enc) = ResponseEncoding::from_token(&token) {
            if !out.contains(&enc) {
                out.push(enc);
            }
        }
    }
    out
}

/// Negotiate the response content coding, honouring the **client's** stated
/// preference order rather than a server-side hardcoded one.
///
/// The merged sequence is `custom ++ [e for e in standard if e not in custom]`
/// where `custom` comes from `X-VGI-Accept-Encoding` and `standard` from
/// `Accept-Encoding`; the first entry this server can produce wins. VGI's own
/// preference header takes precedence because generic HTTP clients inject
/// their own list: the DuckDB engine uses cpp-httplib, which sends
/// `Accept-Encoding: deflate, gzip, br, zstd` — gzip *before* zstd — while VGI
/// states `X-VGI-Accept-Encoding: zstd, gzip`. Walking the generic header
/// first would pick gzip, which dominates large Arrow bodies.
///
/// `identity` participates in the walk like any other coding and is always
/// producible, so a client that lists it ahead of a compressed codec gets an
/// uncompressed body — an explicit, uniform way to switch compression off per
/// request. Winning as `identity` stamps no encoding header at all.
///
/// Returns `None` when the client offered nothing this server can produce (the
/// body then ships uncompressed — `Accept-Encoding` is a client capability,
/// not a demand). Otherwise returns the chosen codec plus `used_custom`: true
/// when the winner appeared only in the custom header, which selects
/// [`VGI_CONTENT_ENCODING_HEADER`] over the standard `Content-Encoding`.
fn pick_response_encoding(
    headers: &HeaderMap,
    compression_level: Option<i32>,
) -> Option<(ResponseEncoding, bool)> {
    let header_str = |name: &str| {
        headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
    };
    let custom = parse_encoding_list(header_str(VGI_ACCEPT_ENCODING_HEADER));
    let standard = parse_encoding_list(
        headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok()),
    );
    custom
        .iter()
        .copied()
        .chain(standard.iter().copied().filter(|e| !custom.contains(e)))
        .find(|enc| enc.producible(compression_level))
        .map(|enc| {
            let used_custom = custom.contains(&enc) && !standard.contains(&enc);
            (enc, used_custom)
        })
}

/// Compress `body` with `encoding` at `level`. `None` means "no compressed
/// form to ship", so the caller sends the body as-is and stamps no encoding
/// header. That covers the client explicitly choosing `identity` or an encoder
/// failure.
fn encode_response_body(encoding: ResponseEncoding, body: &[u8], level: i32) -> Option<Vec<u8>> {
    match encoding {
        ResponseEncoding::Identity => None,
        ResponseEncoding::Zstd => zstd::encode_all(std::io::Cursor::new(body), level).ok(),
        ResponseEncoding::Gzip => {
            let level = u32::try_from(level.clamp(0, 9)).ok()?;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level));
            std::io::Write::write_all(&mut encoder, body).ok()?;
            encoder.finish().ok()
        }
    }
}

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
    /// Operator-declared proxy-injected headers a custom authenticator
    /// depends on — the escape hatch for authenticators the framework
    /// cannot introspect.
    extra_proxy_auth_headers: Vec<String>,
    /// Whether the proxy-proof gate runs in require mode. Only then does it
    /// contribute its header to the §5 note.
    proxy_proof_required: bool,
    /// Size of the call-state cache; `0` disables it.
    call_state_cache_entries: usize,
    /// Accelerates the fixed half of a stream's state, keyed on the
    /// authenticated `call_id` paired with the caller's identity. Purely an
    /// accelerator: a miss reopens the call token the client echoed, so
    /// correctness never depends on a hit. See [`HttpState::resolve_call`].
    call_states: std::sync::Mutex<HashMap<String, (u64, Arc<ResolvedCall>)>>,
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
    cors_max_age: u32,
    prefix: String,
    response_compression_level: Option<i32>,
    landing_page_enabled: bool,
    describe_page_enabled: bool,
    health_enabled: bool,
    max_request_bytes: Option<usize>,
    /// Hard cap on the HTTP body size for unary and stream-exchange
    /// responses (advertised via `VGI-Max-Response-Bytes`).  `None` =
    /// unbounded.  Externalised payloads do not count toward this — they
    /// leave only tiny pointer batches on the wire.
    max_response_bytes: Option<usize>,
    /// Cap on bytes uploaded to external storage while producing one HTTP
    /// response (advertised via `VGI-Max-Externalized-Response-Bytes`).
    /// `None` = unbounded.
    ///
    /// **Hard on every method type**, unlike `max_response_bytes` which is
    /// soft for producers: a wire overshoot can be carried to the next turn
    /// by a continuation token, but bytes already uploaded cannot be
    /// un-uploaded, so there is nothing for a continuation to rescue.
    /// Enforced by pre-flighting the payload size before each upload (see
    /// [`crate::external::prepare_externalize_batch`]) with a post-flush
    /// backstop on the unary path.
    max_externalized_response_bytes: Option<usize>,
    upload_url_provider: Option<Arc<dyn crate::external::UploadUrlProvider>>,
    /// Sticky-session context, `Some` when the server is sticky-enabled.
    sticky: Option<Arc<crate::sticky::StickyContext>>,
    /// Token-introspection endpoint, `Some` only when an operator supplied a
    /// resolver. `None` leaves `{prefix}/__introspect_token__` answering a
    /// fixed `404 not_enabled` that looks nothing up.
    introspect: Option<Arc<crate::auth::introspect::TokenIntrospector>>,
    /// Producer for the standardized landing contract (`describe.json` +
    /// lazy columns). `Some` mounts the describe routes; `None` leaves the
    /// server serving only the shared `landing.html` at `GET {prefix}/`.
    landing_info: Option<LandingInfo>,
    /// Capability response headers precomputed from immutable config at
    /// build time, cloned into each response instead of re-formatting the
    /// numeric caps (`n.to_string()` + `HeaderValue::from_str`) per request.
    capability_headers: HeaderMap,
    /// Whether any capability header beyond the always-present flags is
    /// set — gates the preflight `Cache-Control` header.
    capability_has_any: bool,
    /// `Access-Control-Expose-Headers` value, precomputed alongside
    /// `capability_headers` so it lists exactly the `VGI-*` headers this
    /// server actually emits. Without it a browser can read none of them:
    /// `fetch()` hides every non-safelisted response header.
    cors_expose_headers: HeaderValue,
    /// `Access-Control-Allow-Origin` value precomputed from `cors_origins`
    /// so the per-response CORS path doesn't re-parse the origin string.
    cors_allow_origin: Option<HeaderValue>,
}

/// Fluent builder for [`HttpState`].
#[derive(Default)]
pub struct HttpStateBuilder {
    server: Option<Arc<RpcServer>>,
    token_key: Option<[u8; 32]>,
    token_ttl: Option<std::time::Duration>,
    max_body_size: Option<usize>,
    request_timeout: Option<std::time::Duration>,
    authenticate: Option<crate::auth::Authenticate>,
    oauth_metadata: Option<Arc<crate::auth::oauth::OAuthResourceMetadata>>,
    cors_origins: Option<String>,
    cors_max_age: Option<u32>,
    prefix: Option<String>,
    /// Two-level option so the builder can tell "never configured" (outer
    /// `None` — take [`DEFAULT_RESPONSE_COMPRESSION_LEVEL`]) apart from
    /// "explicitly switched off" (`Some(None)`), which the single-level form
    /// could not express once the default became on.
    response_compression_level: Option<Option<i32>>,
    landing_page_enabled: Option<bool>,
    describe_page_enabled: Option<bool>,
    health_enabled: Option<bool>,
    max_request_bytes: Option<usize>,
    max_upload_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
    max_externalized_response_bytes: Option<usize>,
    upload_url_provider: Option<Arc<dyn crate::external::UploadUrlProvider>>,
    enable_sticky: Option<bool>,
    sticky_default_ttl: Option<std::time::Duration>,
    sticky_echo_headers: Vec<(String, String)>,
    landing_info: Option<LandingInfo>,
    proxy_proof_required: Option<bool>,
    extra_proxy_auth_headers: Vec<String>,
    call_state_cache_entries: Option<usize>,
    introspect_resolver: Option<crate::auth::introspect::TokenResolver>,
    introspect_principals: Vec<String>,
    introspect_default_ttl_seconds: Option<u64>,
    introspect_rate_limit: Option<u32>,
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

    /// Assert the protocol's fixed producer limit of one data batch per HTTP
    /// response. Retained for source compatibility with callers that
    /// explicitly configured the former default; values other than `1` are
    /// rejected because HTTP requests are lock-step producer turns.
    pub fn producer_batch_limit(self, n: usize) -> Self {
        assert_eq!(
            n, 1,
            "producer_batch_limit is fixed at 1 by the lock-step protocol"
        );
        self
    }

    /// Maximum age of a state token. Continuation requests with a token
    /// older than this are rejected. Default `5 minutes`. Set to
    /// `Duration::ZERO` to disable TTL enforcement.
    /// Size the per-process call-state cache; `0` disables it.
    ///
    /// The cache is a pure accelerator — a miss reopens the call token the
    /// client echoed, so correctness never depends on a hit. Disabling it is
    /// the supported way to prove that: every continuation then takes the
    /// miss path, so a client that fails to echo the call token fails
    /// immediately instead of only once the cache goes cold in production.
    pub fn call_state_cache_entries(mut self, n: usize) -> Self {
        self.call_state_cache_entries = Some(n);
        self
    }

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

    /// Advertise `VGI-Proxy-Proof-Required: true` so a proxy can tell it is
    /// minting proofs for a worker that actually checks them. Set it when
    /// the [`proof gate`](crate::auth::proof::proof_authenticate) is
    /// installed in [`ProofMode::Require`](crate::auth::proof::ProofMode).
    ///
    /// Advertisement only — it enables and enforces nothing. The gate rides
    /// in through [`Self::authenticate`] as an opaque callback the builder
    /// cannot introspect, so the operator states the posture here.
    /// Declare proxy-injected headers this service's authentication depends
    /// on, for a custom authenticator the framework cannot introspect. The
    /// built-in proxy-proof gate registers its own header in require mode.
    pub fn proxy_auth_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.extra_proxy_auth_headers = headers.into_iter().map(Into::into).collect();
        self
    }

    pub fn proxy_proof_required(mut self, required: bool) -> Self {
        self.proxy_proof_required = Some(required);
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

    /// Override the zstd level (1..=22) used for response compression.
    ///
    /// Response compression is **on by default** at
    /// [`DEFAULT_RESPONSE_COMPRESSION_LEVEL`]; this only changes the level.
    /// It applies when the client offers zstd in `X-VGI-Accept-Encoding` or
    /// `Accept-Encoding` and the body is at least 1024 bytes (bodies below
    /// that threshold are sent uncompressed).
    /// Use [`HttpStateBuilder::disable_response_compression`] to turn it off.
    pub fn response_compression_level(mut self, level: i32) -> Self {
        self.response_compression_level = Some(Some(level));
        self
    }

    /// Turn response compression off entirely.
    ///
    /// The server then advertises an empty `VGI-Supported-Encodings` — a
    /// positive statement that it speaks no compression, distinct from a
    /// legacy server that omits the header — and ships every body
    /// uncompressed however the client asks. Use this when a proxy or CDN
    /// already compresses, or when measuring the uncompressed wire.
    pub fn disable_response_compression(mut self) -> Self {
        self.response_compression_level = Some(None);
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

    /// Opt in to sticky sessions (HTTP-only). When enabled the server
    /// advertises `VGI-Sticky-Enabled: true`, honours the `VGI-Session` /
    /// `VGI-Session-Accept` headers, and exposes `DELETE {prefix}/__session__`.
    /// Off by default — the non-sticky wire path is unchanged.
    pub fn enable_sticky(mut self, enabled: bool) -> Self {
        self.enable_sticky = Some(enabled);
        self
    }

    /// Default session TTL when a method calls `ctx.open_session` without
    /// an explicit TTL. Default 300 s. Advertised via `VGI-Sticky-Default-TTL`.
    pub fn sticky_default_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.sticky_default_ttl = Some(ttl);
        self
    }

    /// Headers the server tells the client to echo back on every
    /// subsequent request in a session (emitted as `VGI-Echo-<name>` on
    /// the session-opening response; advertised by name via
    /// `VGI-Sticky-Echo-Headers`). Used for client-driven routing
    /// (e.g. `fly-force-instance-id` on Fly.io).
    pub fn sticky_echo_headers(
        mut self,
        headers: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        self.sticky_echo_headers = headers.into_iter().collect();
        self
    }

    /// Supply the worker's identity for the standardized landing surface.
    /// When set, `GET {prefix}/` serves the shared `landing.html` plus a JSON
    /// status document carrying this identity, and `GET {prefix}/vgi-client.js`
    /// serves the browser client build the page reads the catalog with.
    pub fn landing_info(mut self, info: LandingInfo) -> Self {
        self.landing_info = Some(info);
        self
    }

    /// Enable `POST {prefix}/__introspect_token__`, which resolves an opaque
    /// bearer credential to a principal for a reverse proxy that must know the
    /// caller's identity before it can authorize.
    ///
    /// Off by default: the route answers a fixed `404 not_enabled` and holds no
    /// resolver, so no worker grows a credential-to-identity oracle by
    /// upgrading a dependency. It stays definitive rather than unrouted because
    /// a caller that classifies `401/403/404` as final and everything else as
    /// transient would retry a generic `415` forever.
    ///
    /// Requires [`introspect_principals`](Self::introspect_principals). See
    /// [`crate::auth::introspect`] for the guards and why it is deliberately
    /// *not* a replay through the server's own authenticate chain.
    pub fn introspect_resolver(mut self, resolver: crate::auth::introspect::TokenResolver) -> Self {
        self.introspect_resolver = Some(resolver);
        self
    }

    /// Principals permitted to introspect.
    ///
    /// Required alongside [`introspect_resolver`](Self::introspect_resolver),
    /// with **no permissive default**: authentication and introspection are
    /// different capabilities, and a deployment where any valid credential may
    /// introspect lets any user resolve any other user's credential to its
    /// owner.
    pub fn introspect_principals<I, S>(mut self, principals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.introspect_principals = principals.into_iter().map(Into::into).collect();
        self
    }

    /// Cache window advertised as `ttl_seconds` for a resolution that does not
    /// name its own. Default 300 s. Treat it as an authorization window: for
    /// any path the asker serves without re-presenting the credential, it is
    /// exactly that.
    pub fn introspect_default_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.introspect_default_ttl_seconds = Some(ttl.as_secs());
        self
    }

    /// Introspection requests allowed per caller per second (default 20).
    /// Bounds, rather than closes, the oracle an allowlisted-but-compromised
    /// caller still has.
    pub fn introspect_rate_limit(mut self, per_second: u32) -> Self {
        self.introspect_rate_limit = Some(per_second);
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
        let sticky = if self.enable_sticky.unwrap_or(false) {
            let ttl = self
                .sticky_default_ttl
                .unwrap_or_else(|| std::time::Duration::from_secs(300));
            Some(crate::sticky::StickyContext::new(
                token_key,
                ttl,
                self.sticky_echo_headers,
                server.server_id.clone(),
            ))
        } else {
            None
        };
        // Introspection is resolved here, before any route exists, so a
        // misconfiguration fails at construction rather than at the first proxy
        // preflight.
        let introspect = match self.introspect_resolver {
            Some(resolver) => Some(Arc::new(crate::auth::introspect::TokenIntrospector::new(
                resolver,
                self.introspect_principals,
                self.introspect_default_ttl_seconds
                    .unwrap_or(crate::auth::introspect::DEFAULT_INTROSPECT_TTL_SECONDS),
                self.introspect_rate_limit
                    .unwrap_or(crate::auth::introspect::DEFAULT_INTROSPECT_RATE_LIMIT),
            ))),
            None => {
                assert!(
                    self.introspect_principals.is_empty(),
                    "introspect_principals was given without introspect_resolver; the \
                     route stays disabled, so the allowlist would have no effect. Pass \
                     both or neither."
                );
                None
            }
        };
        let cors_allow_origin = self
            .cors_origins
            .as_deref()
            .and_then(|o| HeaderValue::from_str(o).ok());
        // Unconfigured ⇒ compression on at the default level. `Some(None)` is
        // the explicit opt-out from `disable_response_compression`.
        let response_compression_level = self
            .response_compression_level
            .unwrap_or(Some(DEFAULT_RESPONSE_COMPRESSION_LEVEL));
        let (capability_headers, capability_has_any, cors_expose_headers) =
            build_capability_headers(CapabilityInputs {
                max_request_bytes: self.max_request_bytes,
                max_response_bytes: self.max_response_bytes,
                max_externalized_response_bytes: self.max_externalized_response_bytes,
                externalization_enabled: server.external_config().is_some(),
                upload_url_support: self.upload_url_provider.is_some(),
                max_upload_bytes: self.max_upload_bytes,
                sticky: sticky.as_deref(),
                response_compression_level,
                proxy_proof_required: self.proxy_proof_required.unwrap_or(false),
                introspect_enabled: introspect.is_some(),
            });
        Arc::new(HttpState {
            extra_proxy_auth_headers: self.extra_proxy_auth_headers.clone(),
            proxy_proof_required: self.proxy_proof_required.unwrap_or(false),
            call_state_cache_entries: self
                .call_state_cache_entries
                .unwrap_or(CALL_STATE_CACHE_ENTRIES),
            call_states: std::sync::Mutex::new(HashMap::new()),
            server,
            token_key,
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
            cors_max_age: self.cors_max_age.unwrap_or(7200),
            prefix: self.prefix.unwrap_or_default(),
            response_compression_level,
            landing_page_enabled: self.landing_page_enabled.unwrap_or(true),
            describe_page_enabled: self.describe_page_enabled.unwrap_or(true),
            health_enabled: self.health_enabled.unwrap_or(true),
            max_request_bytes: self.max_request_bytes,
            max_response_bytes: self.max_response_bytes,
            max_externalized_response_bytes: self.max_externalized_response_bytes,
            upload_url_provider: self.upload_url_provider,
            sticky,
            introspect,
            landing_info: self.landing_info,
            capability_headers,
            capability_has_any,
            cors_expose_headers,
            cors_allow_origin,
        })
    }
}

/// Everything `build_capability_headers` advertises, grouped so the signature
/// stays readable as capabilities accumulate.
struct CapabilityInputs<'a> {
    max_request_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
    max_externalized_response_bytes: Option<usize>,
    externalization_enabled: bool,
    upload_url_support: bool,
    max_upload_bytes: Option<usize>,
    sticky: Option<&'a crate::sticky::StickyContext>,
    response_compression_level: Option<i32>,
    proxy_proof_required: bool,
    introspect_enabled: bool,
}

/// Response headers a browser client must be able to read that are *not*
/// capability headers, and so cannot be derived from the capability map:
/// the two content-coding stampings (`X-VGI-Content-Encoding` is how a
/// `fetch()` client learns it must decompress the body itself), the RPC
/// error marker, the auth challenge, and the two 401 discriminators. The
/// latter ride only rejection responses, so nothing on `/health` implies
/// them — yet a browser that cannot read `VGI-Auth-Reason` is back to
/// matching on message text, which is exactly what the reason code exists to
/// replace. `Content-Encoding` and `WWW-Authenticate` are technically
/// CORS-safelisted already; listing them costs nothing and keeps the set
/// explicit.
const CORS_EXPOSE_FIXED: [&str; 7] = [
    "Content-Encoding",
    VGI_CONTENT_ENCODING_HEADER,
    RPC_ERROR_HEADER,
    "WWW-Authenticate",
    AUTH_REASON_HEADER,
    AUTH_PROXY_REQUIRED_HEADER,
    // Rides every response including the failures, and is never advertised
    // on /health, so a check derived from advertisements cannot reach it.
    // It is what lets a browser client quote an id this server's own log can
    // be searched for.
    REQUEST_ID_RESPONSE_HEADER,
];

/// Per-request correlation id, echoed from the caller when supplied and
/// generated otherwise.
pub const REQUEST_ID_RESPONSE_HEADER: &str = "x-request-id";

/// Precompute the immutable capability response headers once, mirroring the
/// per-response logic that `attach_capability_headers` used to run. Returns
/// the header set, whether any "beyond the always-present flags" header is
/// present (which gates the preflight `Cache-Control`), and the matching
/// `Access-Control-Expose-Headers` value.
fn build_capability_headers(inputs: CapabilityInputs<'_>) -> (HeaderMap, bool, HeaderValue) {
    let CapabilityInputs {
        max_request_bytes,
        max_response_bytes,
        max_externalized_response_bytes,
        externalization_enabled,
        upload_url_support,
        max_upload_bytes,
        sticky,
        response_compression_level,
        proxy_proof_required,
        introspect_enabled,
    } = inputs;
    let mut out = HeaderMap::new();
    let mut any = false;
    // Compression codecs usable in both directions. Always emitted, even
    // empty: present-but-empty says "I speak no compression", while an
    // absent header means "legacy server, assume zstd". Like
    // `vgi-externalization-enabled`, an always-present flag does not flip
    // `any` (which gates the preflight `Cache-Control`).
    if let Ok(v) = HeaderValue::from_str(&supported_encodings_header_value(
        response_compression_level,
    )) {
        out.insert("vgi-supported-encodings", v);
    }
    if let Some(n) = max_request_bytes {
        if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
            out.insert("vgi-max-request-bytes", v);
            any = true;
        }
    }
    if let Some(n) = max_response_bytes {
        if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
            out.insert("vgi-max-response-bytes", v);
            any = true;
        }
    }
    if let Some(n) = max_externalized_response_bytes {
        if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
            out.insert("vgi-max-externalized-response-bytes", v);
            any = true;
        }
    }
    // Always present so capability-aware clients can decide whether to
    // expect externalised payloads.
    out.insert(
        "vgi-externalization-enabled",
        HeaderValue::from_static(if externalization_enabled {
            "true"
        } else {
            "false"
        }),
    );
    if upload_url_support {
        out.insert("vgi-upload-url-support", HeaderValue::from_static("true"));
        any = true;
        if let Some(n) = max_upload_bytes {
            if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
                out.insert("vgi-max-upload-bytes", v);
            }
        }
    }
    // Proxy-proof posture. Emitted only in `require` mode — `allow` never
    // denies, so advertising there would tell a proxy the hop is enforced
    // when it is not. Absence therefore means "not enforcing", which is why
    // there is no negative form.
    if proxy_proof_required {
        out.insert(
            crate::auth::proof::PROOF_REQUIRED_HEADER,
            HeaderValue::from_static("true"),
        );
        any = true;
    }
    // Token introspection. Positive form only — absence is the answer when the
    // route is disabled, and the point of the advert is that a fronting proxy
    // preflights at boot rather than discovering at first login that the worker
    // it depends on cannot resolve credentials. Riding the capability map means
    // it lands in `Access-Control-Expose-Headers` for free below.
    if introspect_enabled {
        out.insert(
            crate::auth::introspect::INTROSPECT_ENABLED_HEADER,
            HeaderValue::from_static("true"),
        );
        any = true;
    }
    // Sticky-session capabilities. Always emit the enabled flag (negative
    // form when off) so capability discovery is unambiguous.
    if let Some(sticky) = sticky {
        out.insert(STICKY_ENABLED_HEADER, HeaderValue::from_static("true"));
        any = true;
        if let Ok(v) = HeaderValue::from_str(&sticky.default_ttl.as_secs().to_string()) {
            out.insert(STICKY_DEFAULT_TTL_HEADER, v);
        }
        if !sticky.echo_headers.is_empty() {
            let names = sticky
                .echo_headers
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(",");
            if let Ok(v) = HeaderValue::from_str(&names) {
                out.insert(STICKY_ECHO_HEADERS_HEADER, v);
            }
        }
    } else {
        out.insert(STICKY_ENABLED_HEADER, HeaderValue::from_static("false"));
    }

    // Expose every capability header we actually emit, derived from `out`
    // itself so a capability added above is readable from a browser without
    // a second edit here. Previously nothing `vgi-*` was exposed at all, so
    // a `fetch()` client could see none of them — including
    // `VGI-Supported-Encodings`, which is the whole point of the
    // advertisement. Names are sorted only for a stable header value;
    // `Access-Control-Expose-Headers` is an unordered, case-insensitive set.
    let mut expose: Vec<String> = CORS_EXPOSE_FIXED.iter().map(|s| s.to_string()).collect();
    let mut cap_names: Vec<String> = out.keys().map(|k| k.as_str().to_string()).collect();
    // Sticky session headers are stamped per-response by
    // `stamp_session_headers`, not held in the capability map, so they have
    // to be named explicitly — a browser client cannot resume a session it
    // is unable to read the token for.
    if let Some(sticky) = sticky {
        cap_names.push(SESSION_HEADER.to_string());
        cap_names.push(SESSION_CLOSE_HEADER.to_string());
        cap_names.extend(
            sticky
                .echo_headers
                .iter()
                .map(|(n, _)| format!("{ECHO_HEADER_PREFIX}{n}")),
        );
    }
    cap_names.sort();
    expose.extend(cap_names);
    let expose = HeaderValue::from_str(&expose.join(", "))
        .unwrap_or_else(|_| HeaderValue::from_static("Content-Encoding, WWW-Authenticate"));
    (out, any, expose)
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

    /// Operator handle for graceful sticky-session drain, or `None` when
    /// the server is not sticky-enabled. Wire it into a SIGTERM handler.
    pub fn sticky_drain_handle(&self) -> Option<crate::sticky::DrainHandle> {
        self.sticky.as_ref().map(|c| c.drain_handle())
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
    pub(crate) fn pack_cursor_token(
        &self,
        auth: &crate::auth::AuthContext,
        state_bytes: &[u8],
        call_id: &[u8; CALL_ID_LEN],
    ) -> String {
        let aad = compute_aad(auth);
        pack_cursor_token(
            &self.token_key,
            &aad,
            state_bytes,
            call_id,
            current_unix_secs(),
        )
    }

    /// Mint a stream's call token and warm the cache with what we already
    /// hold, so the stream's first continuation need not open the token it
    /// was just handed.
    pub(crate) fn pack_call_token(
        &self,
        auth: &crate::auth::AuthContext,
        call_id: &[u8; CALL_ID_LEN],
        output_schema_bytes: &[u8],
        input_schema_bytes: &[u8],
        stream_id: &str,
    ) -> String {
        let aad = compute_call_aad(auth);
        let token = pack_call_token(
            &self.token_key,
            &aad,
            call_id,
            output_schema_bytes,
            input_schema_bytes,
            stream_id,
            current_unix_secs(),
        );
        self.cache_call(
            auth,
            call_id,
            Arc::new(ResolvedCall {
                output_schema_bytes: output_schema_bytes.to_vec(),
                input_schema_bytes: input_schema_bytes.to_vec(),
                stream_id: stream_id.to_string(),
            }),
        );
        token
    }

    fn token_ttl_opt(&self) -> Option<std::time::Duration> {
        if self.token_ttl.is_zero() {
            None
        } else {
            Some(self.token_ttl)
        }
    }

    /// Open a cursor token, decrypting under the current caller's
    /// identity-derived AAD and enforcing TTL after authenticity.
    pub(crate) fn unpack_cursor_token(
        &self,
        auth: &crate::auth::AuthContext,
        token: &str,
    ) -> Result<UnpackedCursor> {
        let aad = compute_aad(auth);
        unpack_cursor_token(&self.token_key, &aad, token, self.token_ttl_opt())
    }

    /// The proxy-injected headers this server's authentication depends on,
    /// or empty when it depends on none.
    ///
    /// Derived from configuration rather than from what failed on this
    /// request, so every 401 says the same thing (spec §5) and the note
    /// discloses nothing about which stage rejected a given attempt. A
    /// proxy-proof gate contributes only in require mode: in allow mode an
    /// absent proof never denies, so the note would misdirect.
    fn proxy_auth_headers(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.proxy_proof_required {
            out.push(crate::auth::proof::PROOF_HEADER.to_string());
        }
        out.extend(self.extra_proxy_auth_headers.iter().cloned());
        out
    }

    /// Render the standardized 401 of spec §4: the reason header, a
    /// no-store cache directive, the proxy note when this service's auth
    /// depends on a proxy, and the JSON envelope.
    ///
    /// §4.2 lets a service skip the HTML page and always answer with JSON;
    /// what it must never do is answer a non-HTML request with HTML. This
    /// port takes the JSON-only option.
    pub(crate) fn unauthorized_response(
        &self,
        mut headers: HeaderMap,
        reason: AuthReason,
        detail: &str,
    ) -> Response {
        let proxy_headers = self.proxy_auth_headers();
        let hint = if proxy_headers.is_empty() {
            None
        } else {
            Some(crate::unauthorized::proxy_hint(&proxy_headers))
        };
        if hint.is_some() {
            headers.insert(
                HeaderName::from_static(AUTH_PROXY_REQUIRED_HEADER),
                HeaderValue::from_static("true"),
            );
        }
        if let Ok(hv) = HeaderValue::from_str(reason.as_str()) {
            headers.insert(HeaderName::from_static(AUTH_REASON_HEADER), hv);
        }
        // A 401 is per-request and flips to 200 on the next attempt with a
        // credential, so it must never be held by a shared cache.
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let body = crate::unauthorized::envelope(reason, detail, hint.as_deref());
        (StatusCode::UNAUTHORIZED, headers, body).into_response()
    }

    /// Render the caller-identity half of a cache key.
    fn cache_identity(auth: &crate::auth::AuthContext) -> String {
        if !auth.authenticated {
            "\u{0}anonymous".to_string()
        } else {
            format!("{}\u{0}{}", auth.domain, auth.principal)
        }
    }

    fn cache_key(auth: &crate::auth::AuthContext, call_id: &[u8; CALL_ID_LEN]) -> String {
        format!("{:02x?}\u{0}{}", call_id, Self::cache_identity(auth))
    }

    fn cache_call(
        &self,
        auth: &crate::auth::AuthContext,
        call_id: &[u8; CALL_ID_LEN],
        call: Arc<ResolvedCall>,
    ) {
        if self.call_state_cache_entries == 0 {
            return;
        }
        let mut cache = self.call_states.lock().unwrap();
        let key = Self::cache_key(auth, call_id);
        if cache.len() >= self.call_state_cache_entries && !cache.contains_key(&key) {
            // Cheap bound: this is an accelerator, and a miss simply reopens
            // the client's token, so evicting wholesale costs correctness
            // nothing and keeps the map from growing without limit.
            cache.clear();
        }
        cache.insert(key, (current_unix_secs(), call));
    }

    /// Resolve a stream's fixed half for an already-authenticated cursor.
    ///
    /// Order matters here, and it is the whole security argument for the
    /// cache. The cursor is opened first by the caller; its AEAD tag covers
    /// the `call_id` and its AAD covers the caller's identity. Only then is
    /// that authenticated `call_id` used as a cache key. A client cannot
    /// name a call id the server did not mint for it, so a cache hit can
    /// never hand back another principal's call state — and on a hit the
    /// presented call token is not consulted at all, which is exactly the
    /// work we are trying to avoid.
    ///
    /// On a miss (cold process, evicted entry, or a request load-balanced to
    /// a node that never saw this stream's `/init`) the client-supplied call
    /// token is opened and verified, and its embedded `call_id` must match
    /// the one the cursor named.
    pub(crate) fn resolve_call(
        &self,
        auth: &crate::auth::AuthContext,
        cursor: &UnpackedCursor,
        call_token: Option<&str>,
    ) -> Result<Arc<ResolvedCall>> {
        let key = Self::cache_key(auth, &cursor.call_id);
        let ttl = self.token_ttl_opt();
        {
            let mut cache = self.call_states.lock().unwrap();
            if let Some((stored_at, call)) = cache.get(&key).cloned() {
                let fresh = match ttl {
                    Some(t) => current_unix_secs().saturating_sub(stored_at) <= t.as_secs(),
                    None => true,
                };
                if fresh {
                    return Ok(call);
                }
                cache.remove(&key);
            }
        }

        let Some(call_token) = call_token else {
            return Err(RpcError::runtime_error(
                "Missing call token in exchange request",
            ));
        };
        let aad = compute_call_aad(auth);
        let (call_id, resolved) = unpack_call_token(&self.token_key, &aad, call_token, ttl)?;
        if call_id != cursor.call_id {
            // The cursor named a different call. Uniform message: reachable
            // only by pairing two tokens the same principal legitimately
            // holds, so it carries nothing worth distinguishing.
            return Err(RpcError::runtime_error("Malformed state token"));
        }
        let resolved = Arc::new(resolved);
        self.cache_call(auth, &cursor.call_id, resolved.clone());
        Ok(resolved)
    }
}

/// Build the AEAD associated data that binds a state token to the
/// authenticated identity of its issuer. Anonymous and authenticated
/// callers produce distinct AAD strings so a token minted in one
/// context cannot be opened in another. Mirrors Python's `_compute_aad`.
fn compute_aad(auth: &crate::auth::AuthContext) -> Vec<u8> {
    compute_aad_with(b"vgi_rpc.state.v4\x00", auth)
}

/// [`compute_aad`]'s counterpart for call tokens. The prefix differs
/// deliberately, so a call token and a cursor token are not interchangeable
/// even for the same principal: presenting one where the other is expected
/// fails the AEAD tag check rather than decoding into a payload the reader
/// would misinterpret.
fn compute_call_aad(auth: &crate::auth::AuthContext) -> Vec<u8> {
    compute_aad_with(b"vgi_rpc.call.v1\x00", auth)
}

fn compute_aad_with(prefix: &[u8], auth: &crate::auth::AuthContext) -> Vec<u8> {
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

/// On-wire version bytes. The cursor and call tokens carry independent
/// version lines because they change for independent reasons.
///
/// Cursor history: v4 = AEAD over the framed plaintext; v5 = AEAD over a
/// codec-tagged, compressed payload; v6 = cursor-only, with the schemas and
/// stream id moved into the call token.
///
/// Each bump matters for rolling deploys: an older plaintext frames
/// differently, so a newer reader would mis-parse it. Rejecting the old
/// version outright turns that into the same clean failure as any other
/// stale token.
pub(crate) const CURSOR_TOKEN_VERSION: u8 = 0x06;
pub(crate) const CALL_TOKEN_VERSION: u8 = 0x01;

/// Length of the random per-stream id minted at `/init` that binds a call
/// token to its cursors.
pub(crate) const CALL_ID_LEN: usize = 16;

/// Bounds the per-process call-state cache.
const CALL_STATE_CACHE_ENTRIES: usize = 4096;

/// Codec tags for the token payload, written as the first plaintext byte
/// inside the seal. See [`pack_token_payload`].
const TOKEN_CODEC_RAW: u8 = 0x00;
const TOKEN_CODEC_ZSTD: u8 = 0x01;

/// Matches the Python reference's choice. At token payload sizes this
/// measures the same speed as level 1 and slightly smaller, while the levels
/// that compress materially better cost many times the CPU for a few hundred
/// bytes.
const TOKEN_ZSTD_LEVEL: i32 = 3;

/// Bounds decompression. The payload is authenticated before it is ever
/// decompressed, so this guards against a framework bug rather than an
/// attacker — but an unbounded decompress on a request path is not worth
/// having.
const MAX_TOKEN_PLAINTEXT_BYTES: usize = 64 << 20;

/// Compress a token payload and tag which codec was used.
///
/// Compression happens *inside* the seal, and the order is the whole point:
/// once sealed, a token is ciphertext, so the HTTP body codec can no longer
/// find any redundancy in it — it recovers only the slack base64 adds, never
/// the state's own structure. Compressing first reaches the real redundancy.
///
/// Compression is skipped when it does not pay, so a small token never grows
/// beyond its plaintext plus the one tag byte; the tag means the reader never
/// has to guess.
fn pack_token_payload(plaintext: &[u8]) -> Vec<u8> {
    if let Ok(packed) = zstd::bulk::compress(plaintext, TOKEN_ZSTD_LEVEL) {
        if packed.len() < plaintext.len() {
            let mut out = Vec::with_capacity(1 + packed.len());
            out.push(TOKEN_CODEC_ZSTD);
            out.extend_from_slice(&packed);
            return out;
        }
    }
    let mut out = Vec::with_capacity(1 + plaintext.len());
    out.push(TOKEN_CODEC_RAW);
    out.extend_from_slice(plaintext);
    out
}

/// Reverse [`pack_token_payload`].
///
/// An unknown tag or a body that will not decompress means a token this
/// server did not mint, so both surface as the same uniform error every other
/// token failure uses.
fn unpack_token_payload(data: &[u8]) -> Result<Vec<u8>> {
    let (tag, body) = data
        .split_first()
        .ok_or_else(|| RpcError::runtime_error("Malformed state token"))?;
    match *tag {
        TOKEN_CODEC_RAW => Ok(body.to_vec()),
        TOKEN_CODEC_ZSTD => zstd::bulk::decompress(body, MAX_TOKEN_PLAINTEXT_BYTES)
            .map_err(|_| RpcError::runtime_error("Malformed state token")),
        _ => Err(RpcError::runtime_error("Malformed state token")),
    }
}

/// Decomposed contents of a v4 state token after AEAD authentication.
#[derive(Debug, Clone)]
pub(crate) struct UnpackedCursor {
    pub state_bytes: Vec<u8>,
    /// The call token this cursor belongs to. Recovered from inside the
    /// cursor's ciphertext, so it is authenticated before it is trusted.
    pub call_id: [u8; CALL_ID_LEN],
    #[allow(dead_code)]
    pub created_at: u64,
}

/// The half of a stream's state that is fixed for the life of the call —
/// what a cursor's `call_id` resolves to, from cache or from the client's
/// echoed call token.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedCall {
    pub output_schema_bytes: Vec<u8>,
    pub input_schema_bytes: Vec<u8>,
    /// Chain-correlation id, stable across a stream's init and its
    /// continuations. Carried so the token round-trips it faithfully; this
    /// port does not yet surface it on the continuation dispatch path the
    /// way the Go port does.
    #[allow(dead_code)]
    pub stream_id: String,
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
pub(crate) fn pack_cursor_token(
    token_key: &[u8; 32],
    aad: &[u8],
    state_bytes: &[u8],
    call_id: &[u8; CALL_ID_LEN],
    created_at: u64,
) -> String {
    let mut plaintext = Vec::with_capacity(8 + CALL_ID_LEN + 4 + state_bytes.len());
    plaintext.extend_from_slice(&created_at.to_le_bytes());
    plaintext.extend_from_slice(call_id);
    plaintext.extend_from_slice(&(state_bytes.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(state_bytes);

    crate::crypto::seal_base64(
        &pack_token_payload(&plaintext),
        token_key,
        aad,
        CURSOR_TOKEN_VERSION,
    )
}

/// Seal the half of a stream's state that is fixed for the life of the call.
/// Minted once, by `/init`; never re-issued.
pub(crate) fn pack_call_token(
    token_key: &[u8; 32],
    aad: &[u8],
    call_id: &[u8; CALL_ID_LEN],
    output_schema_bytes: &[u8],
    input_schema_bytes: &[u8],
    stream_id: &str,
    created_at: u64,
) -> String {
    let mut plaintext = Vec::with_capacity(
        8 + CALL_ID_LEN
            + 4
            + output_schema_bytes.len()
            + 4
            + input_schema_bytes.len()
            + 4
            + stream_id.len(),
    );
    plaintext.extend_from_slice(&created_at.to_le_bytes());
    plaintext.extend_from_slice(call_id);
    plaintext.extend_from_slice(&(output_schema_bytes.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(output_schema_bytes);
    plaintext.extend_from_slice(&(input_schema_bytes.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(input_schema_bytes);
    plaintext.extend_from_slice(&(stream_id.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(stream_id.as_bytes());

    crate::crypto::seal_base64(
        &pack_token_payload(&plaintext),
        token_key,
        aad,
        CALL_TOKEN_VERSION,
    )
}

/// Open the AEAD envelope, decompress, and check the TTL. Shared by both
/// token kinds; returns the framed plaintext and its `created_at`.
fn open_token_plaintext(
    token_key: &[u8; 32],
    aad: &[u8],
    token: &str,
    version: u8,
    token_ttl: Option<std::time::Duration>,
) -> Result<(Vec<u8>, u64)> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token.as_bytes())
        .map_err(|_| RpcError::runtime_error("Malformed state token"))?;

    let sealed = crate::crypto::open_bytes(&raw, token_key, aad, version)
        .map_err(|_| RpcError::runtime_error("State token signature verification failed"))?;
    // Decompress only after authentication: nothing an attacker supplies
    // reaches the decoder without the token key.
    let plaintext = unpack_token_payload(&sealed)?;

    if plaintext.len() < 8 + CALL_ID_LEN {
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

    Ok((plaintext, created_at))
}

/// Open and verify a cursor token. [`crypto::open_bytes`] authenticates the
/// payload; every malformed, wrong-version, tampered, wrong-key, or
/// AAD-mismatched (e.g. cross-principal replay) token surfaces as the same
/// uniform signature-verification error so callers cannot distinguish
/// failure modes via timing or message content. Only a base64 decode
/// failure — observable before any crypto work — stays a distinct
/// "Malformed state token".
pub(crate) fn unpack_cursor_token(
    token_key: &[u8; 32],
    aad: &[u8],
    token: &str,
    token_ttl: Option<std::time::Duration>,
) -> Result<UnpackedCursor> {
    let (plaintext, created_at) =
        open_token_plaintext(token_key, aad, token, CURSOR_TOKEN_VERSION, token_ttl)?;

    let mut call_id = [0u8; CALL_ID_LEN];
    call_id.copy_from_slice(&plaintext[8..8 + CALL_ID_LEN]);

    let mut pos = 8 + CALL_ID_LEN;
    let state_bytes = read_segment(&plaintext, &mut pos)?;
    if pos != plaintext.len() {
        return Err(RpcError::runtime_error("Malformed state token"));
    }

    Ok(UnpackedCursor {
        state_bytes,
        call_id,
        created_at,
    })
}

/// Open and verify a call token, returning it paired with its embedded
/// `call_id` so the caller can check it against the cursor that named it.
pub(crate) fn unpack_call_token(
    token_key: &[u8; 32],
    aad: &[u8],
    token: &str,
    token_ttl: Option<std::time::Duration>,
) -> Result<([u8; CALL_ID_LEN], ResolvedCall)> {
    let (plaintext, _created_at) =
        open_token_plaintext(token_key, aad, token, CALL_TOKEN_VERSION, token_ttl)?;

    let mut call_id = [0u8; CALL_ID_LEN];
    call_id.copy_from_slice(&plaintext[8..8 + CALL_ID_LEN]);

    let mut pos = 8 + CALL_ID_LEN;
    let output_schema_bytes = read_segment(&plaintext, &mut pos)?;
    let input_schema_bytes = read_segment(&plaintext, &mut pos)?;
    let stream_id_bytes = read_segment(&plaintext, &mut pos)?;
    if pos != plaintext.len() {
        return Err(RpcError::runtime_error("Malformed state token"));
    }
    let stream_id = String::from_utf8(stream_id_bytes)
        .map_err(|_| RpcError::runtime_error("Malformed state token"))?;

    Ok((
        call_id,
        ResolvedCall {
            output_schema_bytes,
            input_schema_bytes,
            stream_id,
        },
    ))
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
/// (or a Ctrl-C event on non-Unix). Pass to [`axum::serve`](fn@axum::serve)'s
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
/// [`axum::serve`](fn@axum::serve) + [`shutdown_signal`].
///
/// # Runtime requirement
///
/// Run this on a multi-thread Tokio runtime when requests must make concurrent
/// progress. RPC handlers are synchronous so they can serve every transport;
/// the HTTP adapter uses `block_in_place` on a multi-thread runtime to keep a
/// slow handler from occupying an async worker. A current-thread runtime is
/// supported for single-request/embedded use, but one synchronous callback
/// necessarily delays unrelated requests on that sole thread.
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
/// post-processing middleware — large enough for any reasonable Arrow
/// batch, small enough that the middleware can never be driven to
/// exhaust the heap. Deliberately *not* tied to
/// `wire::MAX_IPC_MESSAGE_BYTES`, which is a sanity bound on a claimed
/// frame size rather than a policy limit on a response.
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

/// Build the Axum router for an HTTP RPC server.
///
/// Run the router on a multi-thread Tokio runtime when requests must make
/// concurrent progress. Synchronous RPC callbacks use `block_in_place` there;
/// on a current-thread runtime one callback necessarily delays other requests.
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
        //
        // `DefaultBodyLimit::disable()` is required for this to mean
        // anything. axum installs its own 2 MiB `DefaultBodyLimit` on every
        // route, and it is checked *before* this layer — so without the
        // disable, `max_body_size` was silently inert above 2 MiB and every
        // Arrow batch larger than that got a 413, whatever the builder said.
        // Measured before the fix: 2 MiB accepted, 4 MiB rejected, against a
        // configured ceiling of 64 MiB.
        .layer(axum::extract::DefaultBodyLimit::disable())
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
    mut req: axum::http::Request<axum::body::Body>,
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
    // Extract only the header values the post-processing needs, rather than
    // deep-cloning the entire request `HeaderMap` on every request. The
    // request is consumed by `next.run(req)` below, so these must be taken
    // first. CORS echoes the client's `Access-Control-Request-Headers`;
    // compression negotiates over `X-VGI-Accept-Encoding` + `Accept-Encoding`.
    let req_acrh = req
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .cloned();
    // Echo the caller's correlation id, or mint one. Resolved *before* the
    // handler runs and written back onto the request headers, so a handler
    // (and the access-log record it produces) sees exactly the value the
    // response will carry — including the minted case. An id that is on the
    // response but names a different request in the log is worse than none:
    // it looks like a working trail right up to the moment someone follows
    // it. Set on the way out so it rides every exit path, including the
    // errors anybody actually looks up.
    let request_id = req
        .headers()
        .get(REQUEST_ID_RESPONSE_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(str::to_owned)
        .unwrap_or_else(new_session_id);
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        req.headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_RESPONSE_HEADER), v);
    }
    let req_encoding = pick_response_encoding(req.headers(), state.response_compression_level);
    let req_method = req.method().clone();
    let req_path = req.uri().path().to_owned();

    // Enforce server-advertised max_request_bytes before invoking the
    // handler. The upload-URL control body is client-controlled and must be
    // capped before it can allocate storage; only payload-free health routes
    // are exempt.
    if let Some(limit) = state.max_request_bytes {
        let exempt = req_path == "/health" || req_path.ends_with("/health");
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
                    attach_cors_headers(&state, &mut h, req_acrh.as_ref(), false);
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

            // Content-Length is only a fast rejection. Chunked bodies have
            // no declared length, and a peer can otherwise stream an
            // arbitrarily large upload-control request through the advertised
            // cap. Buffer under limit+1 and restore the body for the handler;
            // handlers already consume complete Arrow bodies, so this adds no
            // new whole-body buffering behavior.
            let (parts, body) = req.into_parts();
            let bounded = to_bytes(body, limit.saturating_add(1)).await;
            let body = match bounded {
                Ok(body) if body.len() <= limit => body,
                Ok(body) => {
                    let mut h = HeaderMap::new();
                    attach_capability_headers(&state, &mut h, &req_method);
                    attach_cors_headers(&state, &mut h, req_acrh.as_ref(), false);
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        h,
                        format!(
                            "Request body of {} bytes exceeds advertised max_request_bytes={limit}",
                            body.len()
                        ),
                    )
                        .into_response();
                }
                Err(_) => {
                    let mut h = HeaderMap::new();
                    attach_capability_headers(&state, &mut h, &req_method);
                    attach_cors_headers(&state, &mut h, req_acrh.as_ref(), false);
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        h,
                        format!("Request body exceeds advertised max_request_bytes={limit}"),
                    )
                        .into_response();
                }
            };
            req = axum::http::Request::from_parts(parts, axum::body::Body::from(body));
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
            attach_cors_headers(&state, &mut h, req_acrh.as_ref(), false);
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

    // Attach CORS + capability headers *before* the compression branch, so a
    // compressed response can no longer return past them. It previously did,
    // leaving every compressed Arrow body without a single `VGI-*` header —
    // capability discovery silently degraded to defaults for exactly the
    // large responses that matter most.
    attach_cors_headers(&state, &mut parts.headers, req_acrh.as_ref(), false);
    attach_capability_headers(&state, &mut parts.headers, &req_method);
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        parts
            .headers
            .insert(HeaderName::from_static(REQUEST_ID_RESPONSE_HEADER), v);
    }

    if is_arrow {
        if let (Some(level), Some((encoding, used_custom))) =
            (state.response_compression_level, req_encoding)
        {
            // Only compress when the client offered a codec we can produce AND
            // the body is large enough to benefit. Below the threshold, frame
            // overhead dominates and can enlarge the payload — tiny bodies
            // (empty-schema error / continuation-token responses, small scalar
            // unary results) waste CPU and allocation for no gain.
            // `Accept-Encoding` is a client capability, not a demand, so an
            // uncompressed reply is always valid.
            if bytes.len() >= MIN_ZSTD_COMPRESS_BYTES {
                if let Some(compressed) = encode_response_body(encoding, &bytes, level) {
                    // Ship the compressed form only if it actually shrank the
                    // body; otherwise fall through and send it uncompressed.
                    if compressed.len() < bytes.len() {
                        // A client that had to use the custom request header
                        // is one whose fetch/proxy layer would auto-decode or
                        // mangle a standard `Content-Encoding`, so answer in
                        // kind on the custom response header.
                        let name = if used_custom {
                            axum::http::HeaderName::from_static(VGI_CONTENT_ENCODING_HEADER)
                        } else {
                            header::CONTENT_ENCODING
                        };
                        parts
                            .headers
                            .insert(name, HeaderValue::from_static(encoding.as_str()));
                        let compressed_len = compressed.len() as u64;
                        let body_new = axum::body::Body::from(compressed);
                        emit_deferred_access_records(&mut parts, compressed_len);
                        return Response::from_parts(parts, body_new);
                    }
                }
            }
        }
    }
    let body_len = bytes.len() as u64;
    emit_deferred_access_records(&mut parts, body_len);
    Response::from_parts(parts, axum::body::Body::from(bytes))
}

/// Emit the request's access-log records now that the body is final.
///
/// This runs after compression, which is the whole point: a record written
/// where the handler finished could only ever report the uncompressed size,
/// and the two differ by orders of magnitude on a compressible Arrow body.
/// The cost is that a crash between handler and response loses the record;
/// the alternative is a permanently wrong number.
fn emit_deferred_access_records(parts: &mut axum::http::response::Parts, response_bytes: u64) {
    if let Some(sink) = parts.extensions.remove::<crate::hooks::AccessSink>() {
        sink.emit(Some(response_bytes));
    }
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
    // The capability set is immutable config, precomputed once in `build()`.
    for (k, v) in state.capability_headers.iter() {
        out.insert(k.clone(), v.clone());
    }
    if state.capability_has_any && method == axum::http::Method::OPTIONS {
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

    let api = if state.sticky.is_some() {
        api.route(
            "/__session__",
            axum::routing::delete(handle_delete_session).options(handle_preflight),
        )
    } else {
        api
    };

    // Always routed, but only ever an oracle when a resolver exists. With
    // introspection off the handler holds nothing and looks nothing up; it is
    // there so a caller gets a definitive 404 instead of the 415 the generic
    // `/:method` route answers a JSON body with — which a caller classifying
    // 401/403/404 as final reads as "retry later" and spins on forever.
    let api = api.route(
        crate::auth::introspect::INTROSPECT_ENDPOINT,
        post(handle_introspect_token).options(handle_preflight),
    );

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
    // The browser client build the shared `landing.html` imports. Mounted
    // alongside the page whenever the application supplied its identity.
    if state.landing_info.is_some() {
        app = app.route(
            &format!("{prefix}/vgi-client.js"),
            axum::routing::get(handle_client_bundle),
        );
    }

    app.with_state(state)
}

/// `DELETE {prefix}/__session__` — idempotent best-effort session teardown.
/// Token absent / stale / forged / wrong-principal ⇒ 200 (no info leak);
/// a live session ⇒ close it, emit `VGI-Session-Close: true`, 204.
async fn handle_delete_session(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> Response {
    let auth = match authenticate_request(&state, SESSION_ENDPOINT, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let Some(ctx) = state.sticky.as_ref() else {
        return StatusCode::OK.into_response();
    };
    let session_header = headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok());
    match crate::sticky::handle_delete(ctx, &auth, session_header) {
        crate::sticky::DeleteOutcome::Idempotent => StatusCode::OK.into_response(),
        crate::sticky::DeleteOutcome::Closed => {
            let mut h = HeaderMap::new();
            h.insert(SESSION_CLOSE_HEADER, HeaderValue::from_static("true"));
            (StatusCode::NO_CONTENT, h).into_response()
        }
    }
}

/// `POST {prefix}/__introspect_token__` — opaque credential to principal.
///
/// Two rejection axes, deliberately distinguishable from each other and
/// deliberately uniform within themselves: `403` says the *caller* may not
/// introspect, `404` says the *subject* credential did not resolve. Both are
/// definitive and may be negative-cached; anything transient reaches the caller
/// as `503` so it is retried instead.
async fn handle_introspect_token(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    use crate::auth::introspect::{IntrospectOutcome, MAX_INTROSPECT_BODY_BYTES};

    let Some(introspector) = state.introspect.as_ref() else {
        // Deliberately no authentication of its own: "this worker does not do
        // introspection" is not a secret, and a caller needs to learn it at
        // preflight rather than after arranging credentials.
        return introspect_refusal(StatusCode::NOT_FOUND, "not_enabled", None);
    };
    let auth = match authenticate_request(
        &state,
        crate::auth::introspect::INTROSPECT_ENDPOINT,
        &headers,
    ) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    // Bounded here rather than by the global body limit: the only legitimate
    // content is one credential, and an over-length body collapses onto the
    // same answer an unknown one gets.
    let bytes = axum::body::to_bytes(body, MAX_INTROSPECT_BODY_BYTES)
        .await
        .unwrap_or_default();

    match introspector.introspect(&auth, &bytes) {
        IntrospectOutcome::Resolved {
            principal,
            token_name,
            ttl_seconds,
        } => {
            // A closed set of three keys. A `claims` field would let this
            // worker choose its caller's tenant routing, row scope and policy
            // branch; the asker derives what it needs from the principal alone.
            let body = serde_json::json!({
                "principal": principal,
                "token_name": token_name,
                "ttl_seconds": ttl_seconds,
            })
            .to_string();
            introspect_json(StatusCode::OK, body, None)
        }
        IntrospectOutcome::NotAnIntrospector => {
            introspect_refusal(StatusCode::FORBIDDEN, "not_an_introspector", None)
        }
        IntrospectOutcome::Unresolved => {
            introspect_refusal(StatusCode::NOT_FOUND, "unresolved", None)
        }
        IntrospectOutcome::RateLimited => {
            introspect_refusal(StatusCode::TOO_MANY_REQUESTS, "rate_limited", Some(1))
        }
        IntrospectOutcome::Unavailable {
            retry_after_seconds,
        } => introspect_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            Some(retry_after_seconds),
        ),
    }
}

/// A rejection carrying no detail about why beyond the coarse code.
fn introspect_refusal(status: StatusCode, error: &str, retry_after: Option<u32>) -> Response {
    introspect_json(
        status,
        serde_json::json!({ "error": error }).to_string(),
        retry_after,
    )
}

fn introspect_json(status: StatusCode, body: String, retry_after: Option<u32>) -> Response {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // A credential's resolution can change; nothing here may sit in a shared
    // cache.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(secs) = retry_after {
        if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
            h.insert(header::RETRY_AFTER, v);
        }
    }
    (status, h, body).into_response()
}

async fn handle_preflight(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> Response {
    let mut h = HeaderMap::new();
    attach_cors_headers(
        &state,
        &mut h,
        headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS),
        true,
    );
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

/// `GET {prefix}/` — the shared, self-contained `landing.html` for browsers
/// (Accept: text/html); a small JSON status for health checks / `?format=json`
/// / `Accept: application/json`. Mirrors the Python `LandingPageResource`.
async fn handle_landing(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let format_json = query.as_deref().map(query_has_format_json).unwrap_or(false);
    let want_json =
        format_json || (accept.contains("application/json") && !accept.contains("text/html"));

    let mut h = HeaderMap::new();
    if want_json {
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        // Worker identity is not catalog data and has no protocol method, so
        // the page reads it from here.
        let info = state.landing_info.clone().unwrap_or_default();
        let body = serde_json::json!({
            "status": "ok",
            "server_id": state.server.server_id,
            "protocol": state.server.protocol_name(),
            "worker": info.name,
            "doc": info.doc,
            "version": info.version,
            "lang": "rust",
            "oauth": state.oauth_metadata.is_some(),
            "cupola_base": "https://cupola.query-farm.services",
        })
        .to_string();
        return (StatusCode::OK, h, body).into_response();
    }
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    (StatusCode::OK, h, LANDING_HTML).into_response()
}

/// Whether a raw query string carries `format=json`.
fn query_has_format_json(raw: &str) -> bool {
    raw.split('&')
        .any(|pair| pair == "format=json" || pair.strip_prefix("format=") == Some("json"))
}

/// `GET {prefix}/vgi-client.js` — the browser client build the page imports.
async fn handle_client_bundle() -> Response {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    // Immutable for a given worker build: the page and the bundle are vendored
    // and released together.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    (StatusCode::OK, h, CLIENT_BUNDLE).into_response()
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
    requested_headers: Option<&HeaderValue>,
    is_preflight: bool,
) {
    let Some(origin) = state.cors_allow_origin.as_ref() else {
        return;
    };
    out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
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
    // Echo the client's requested headers when present, else a sensible
    // default. When the client already sent a valid `HeaderValue` we reuse
    // it directly rather than round-tripping through `&str`.
    match requested_headers {
        Some(v) => {
            out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v.clone());
        }
        None => {
            out.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                // `X-VGI-Accept-Encoding` is how a browser states a codec
                // preference at all: `fetch()` cannot set `Accept-Encoding`
                // (forbidden header name), so it must be allowed here. The
                // three `VGI-*` request headers fail quietly when omitted:
                // the browser simply drops them, taking out sticky sessions
                // and every call behind a proof gate while plain calls keep
                // working.
                HeaderValue::from_static(
                    "Content-Type, Authorization, Cookie, Accept-Encoding, \
                     X-VGI-Accept-Encoding, VGI-Session, VGI-Session-Accept, \
                     VGI-Proxy-Proof",
                ),
            );
        }
    }
    // Precomputed in `build_capability_headers` from the capability headers
    // this server actually emits, plus `CORS_EXPOSE_FIXED`. Everything
    // `VGI-*` is listed: a browser sees only safelisted response headers
    // otherwise, so an unexposed capability header may as well not exist.
    out.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        state.cors_expose_headers.clone(),
    );
    // A server that has opted into serving cross-origin callers has, by
    // construction, opted into being embeddable by them: without this a
    // caller under COEP require-corp has the response blocked outright.
    out.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
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
// Err is an axum `Response` (large), shared throughout the HTTP layer; boxing
// it would churn every call site for no real benefit.
#[allow(clippy::result_large_err)]
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
        Err(err) if err.is_auth_unavailable() => {
            // Not a rejection: the authority could not be reached. A 401 here
            // tells every caller to re-authenticate against a service that is
            // simply down, and invites them to negative-cache an outage.
            tracing::warn!(
                target: "vgi_rpc.http",
                error = %err.message,
                "authentication unavailable"
            );
            let mut h = HeaderMap::new();
            let retry_after = err
                .retry_after_seconds
                .unwrap_or(crate::errors::DEFAULT_AUTH_RETRY_AFTER_SECONDS);
            if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                h.insert(header::RETRY_AFTER, v);
            }
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                h,
                "authentication service unavailable",
            )
                .into_response())
        }
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
            if status == StatusCode::UNAUTHORIZED {
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
                // A classified failure names its own reason; otherwise guess
                // from the error's *type*, mirroring the Python reference —
                // PermissionError means the caller got as far as being
                // identified. Guessing more finely would mean matching on
                // message text, which misclassifies on any rewording.
                let reason = err
                    .auth_reason
                    .unwrap_or(if err.error_type == "PermissionError" {
                        AuthReason::InsufficientScope
                    } else {
                        AuthReason::Unauthorized
                    });
                // Echo the detail only when the authenticator classified the
                // failure, i.e. chose that text deliberately. An unclassified
                // message is an arbitrary verifier/library string that may
                // carry attacker-supplied input (a `kid`, say), and spec §2
                // keeps that out of the body — it stays in the log above.
                let detail = if err.auth_reason.is_some() {
                    err.message.as_str()
                } else {
                    ""
                };
                return Err(state.unauthorized_response(h, reason, detail));
            }
            let body = {
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

/// The one message shape for a `max_externalized_response_bytes` overshoot.
///
/// Every enforcement site funnels through here so the wording cannot drift
/// between the unary pre-flight, the producer turn, the exchange turn and
/// the post-flush backstops. The literal `max_externalized_response_bytes`
/// token is load-bearing: the cross-language conformance suite matches the
/// client-visible `RpcError` against exactly that string, and the reference
/// implementations emit the same `(actual > limit) for method ...` shape.
fn external_cap_error(bytes: usize, limit: usize, method: &str) -> RpcError {
    RpcError::runtime_error(format!(
        "Externalised payload exceeds max_externalized_response_bytes ({bytes} > {limit}) for method {method:?}"
    ))
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
    headers.insert(RPC_ERROR_HEADER, HeaderValue::from_static("true"));
    (StatusCode::OK, headers, buf).into_response()
}

/// Stamp `X-VGI-RPC-Error: true` on a 200 whose Arrow body carries an
/// EXCEPTION batch rather than a result.
///
/// A failed RPC answers **200**: the call reached the method and the method
/// raised, so the failure is application-level and rides the body. The status
/// line therefore says nothing, and this header is the only signal a client
/// has short of parsing the stream. It must discriminate — a flag on every
/// response carries no information, which is the same outage as never
/// setting it — so call this only on the error paths.
///
/// Transport-level rejections (400/404/415/401) keep their status and do
/// *not* carry the flag; it marks a 200 that is really a failure.
fn stamp_rpc_error(resp: &mut Response) {
    resp.headers_mut()
        .insert(RPC_ERROR_HEADER, HeaderValue::from_static("true"));
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
        .and_then(|v| v.to_str().ok());
    if body.len() > max_size {
        return Err(RpcError::runtime_error(format!(
            "Request body exceeds max size ({} bytes > {})",
            body.len(),
            max_size
        )));
    }
    decode_content_encoding(body.as_ref(), enc, Some(max_size))
}

fn zstd_window_log_for_limit(max_size: usize) -> u32 {
    // Streaming encoders do not know the eventual content size and zstd's
    // level-1 profile therefore advertises a 512 KiB history window even for
    // tiny frames. Keep that bounded interoperability floor while still
    // refusing larger attacker-selected windows for small output budgets.
    const INTEROPERABLE_WINDOW_LOG_FLOOR: u32 = 19;
    let bounded = max_size.max(1 << INTEROPERABLE_WINDOW_LOG_FLOOR);
    let ceil_log = usize::BITS - bounded.saturating_sub(1).leading_zeros();
    ceil_log.clamp(INTEROPERABLE_WINDOW_LOG_FLOOR, 31)
}

fn request_decode_limit(state: &HttpState) -> usize {
    state
        .max_request_bytes
        .unwrap_or(state.max_body_size)
        .min(state.max_body_size)
}

fn request_decode_error(state: &Arc<HttpState>, error: &RpcError) -> Response {
    let status = if error.message.contains("exceeds max size") {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    };
    arrow_error(state, status, error, "")
}

/// Most codings [`decode_content_encoding`] will apply from one
/// `Content-Encoding` header. Real bodies carry one; the cap bounds the decode
/// work an attacker can buy with a single bounded request body.
pub const MAX_CONTENT_CODINGS: usize = 4;

/// Decode an HTTP body per its `Content-Encoding`, or return it unchanged.
///
/// Handles the codings vgi-rpc speaks (`zstd`, `gzip`); the header may list
/// several applied in order, which are decoded in reverse. `identity` and
/// unknown codings are left as-is. Intended for an intermediary (proxy/gateway)
/// that must read a compressed request/response body to inspect or rewrite it —
/// see [`crate::intermediary`] for the framing helpers that go with it.
///
/// `max_output_size` caps the decompressed length of **each** coding, defending
/// against zip-bomb-style payloads without first allocating the full result.
/// At most [`MAX_CONTENT_CODINGS`] codings are applied, so total decode work
/// stays bounded by that multiple of the cap rather than by attacker-chosen
/// header length.
///
/// # Errors
///
/// Fails on a corrupt payload, a coding that decodes past `max_output_size`, or
/// a header listing more than [`MAX_CONTENT_CODINGS`] codings.
pub fn decode_content_encoding(
    data: &[u8],
    content_encoding: Option<&str>,
    max_output_size: Option<usize>,
) -> Result<Vec<u8>> {
    let Some(header) = content_encoding.filter(|h| !h.trim().is_empty()) else {
        return Ok(data.to_vec());
    };
    let max_size = max_output_size.unwrap_or(usize::MAX);
    let codings = header
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty());
    // Each coding gets the full `max_size` budget, so an unbounded list would let
    // one bounded request body cost K x max_size of decode work and peak memory.
    // Real bodies carry one coding; refuse an absurd chain rather than serve it.
    if codings.clone().count() > MAX_CONTENT_CODINGS {
        return Err(RpcError::runtime_error(format!(
            "Content-Encoding lists more than {MAX_CONTENT_CODINGS} codings"
        )));
    }
    let mut result = data.to_vec();
    for name in codings.rev() {
        result = match name.as_str() {
            "zstd" => {
                let mut decoder = zstd::Decoder::new(result.as_slice())
                    .map_err(|e| RpcError::runtime_error(format!("zstd decode: {e}")))?;
                decoder
                    .window_log_max(zstd_window_log_for_limit(max_size))
                    .map_err(|e| RpcError::runtime_error(format!("zstd window limit: {e}")))?;
                decode_bounded(decoder, result.len(), max_size, "zstd")?
            }
            "gzip" => decode_bounded(
                flate2::read::GzDecoder::new(result.as_slice()),
                result.len(),
                max_size,
                "gzip",
            )?,
            _ => result, // identity / unknown coding — leave as-is
        };
    }
    Ok(result)
}

/// Stream a decoder to completion, aborting once the decoded length exceeds
/// `max_size` rather than allocating the full result first.
fn decode_bounded(
    mut decoder: impl std::io::Read,
    input_len: usize,
    max_size: usize,
    coding: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input_len.min(max_size).min(64 * 1024));
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| RpcError::runtime_error(format!("{coding} decode: {e}")))?;
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
    Request::from_read_batch(batch, metadata, true)
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

/// Resolve sticky headers on an incoming request. `Ok(Some(sink))` to
/// install on the [`CallContext`]; `Ok(None)` when sticky is disabled;
/// `Err(resp)` to short-circuit with a `SessionLostError` response when a
/// presented token failed to resolve.
#[allow(clippy::result_large_err)]
fn sticky_for_request(
    state: &Arc<HttpState>,
    auth: &crate::auth::AuthContext,
    headers: &HeaderMap,
) -> std::result::Result<Option<Arc<crate::sticky::StickySinkImpl>>, Response> {
    let Some(ctx) = state.sticky.as_ref() else {
        return Ok(None);
    };
    let accept = headers
        .get(SESSION_ACCEPT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let session_header = headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok());
    match crate::sticky::resolve(ctx, auth, accept, session_header) {
        crate::sticky::StickyResolution::Sink(s) => Ok(Some(s)),
        crate::sticky::StickyResolution::Lost(err) => Err(cap_error_response(
            &Schema::empty(),
            &err,
            &state.server.server_id,
            "",
        )),
    }
}

/// Stamp `VGI-Session` (+ echo headers) and `VGI-Session-Close` onto a
/// response according to the per-request sink's mint/close signals.
fn stamp_session_headers(
    resp: &mut Response,
    state: &Arc<HttpState>,
    sink: &Arc<crate::sticky::StickySinkImpl>,
) {
    let headers = resp.headers_mut();
    if let Some(token) = sink.mint_token() {
        if let Ok(v) = HeaderValue::from_str(&token) {
            headers.insert(SESSION_HEADER, v);
        }
        if let Some(ctx) = state.sticky.as_ref() {
            for (name, value) in &ctx.echo_headers {
                let full = format!("{ECHO_HEADER_PREFIX}{name}");
                if let (Ok(n), Ok(v)) = (
                    axum::http::HeaderName::from_bytes(full.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    headers.insert(n, v);
                }
            }
        }
    }
    if sink.was_closed() {
        headers.insert(SESSION_CLOSE_HEADER, HeaderValue::from_static("true"));
    }
}

fn decode_hex_key(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
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
    while !padded.len().is_multiple_of(4) {
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

// The method name, count cap, and response schema are the public wire contract;
// they live in `crate::external` so intermediaries share one definition.
use crate::external::{
    upload_url_params_schema, upload_url_response_schema, MAX_UPLOAD_URL_COUNT, UPLOAD_URL_METHOD,
};

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

    let body = match maybe_decompress(&headers, &body, request_decode_limit(&state)) {
        Ok(b) => b,
        Err(e) => return request_decode_error(&state, &e),
    };
    let req = match parse_request_from_body(&body) {
        Ok(r) => r,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };
    if req.method != UPLOAD_URL_METHOD {
        let err = RpcError::protocol_error(format!(
            "Method mismatch: expected '{UPLOAD_URL_METHOD}', got '{}'",
            req.method
        ));
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }
    if let Err(err) = validate_protocol_version(state.server.protocol_version(), &req.metadata) {
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }
    if let Err(err) = validate_parameter_batch(&req.batch, &upload_url_params_schema()) {
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
    let schema_ref = schema.as_ref();
    let mut body_buf = Vec::new();
    {
        let mut sw = match StreamWriter::new(&mut body_buf, schema_ref) {
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
                    schema.clone(),
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
                        let _ = sw.write(&empty_batch(schema_ref).unwrap(), Some(&md));
                        let _ = sw.finish();
                        drop(sw);
                        return arrow_response(StatusCode::OK, body_buf);
                    }
                };
                let _ = sw.write(&batch, None);
            }
            Err(err) => {
                let md = build_error_metadata(&err, &state.server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(schema_ref).unwrap(), Some(&md));
            }
        }
        let _ = sw.finish();
    }
    arrow_response(StatusCode::OK, body_buf)
}

// ---------------------------------------------------------------------------
// Unary
// ---------------------------------------------------------------------------

/// Run one synchronous RPC callback without occupying an async HTTP worker.
///
/// `RpcServer` handlers are deliberately synchronous so the same implementation
/// can serve pipe, Unix, TCP, and HTTP transports. Calling one directly from an
/// Axum handler, however, lets a slow database/file/network operation pin a
/// Tokio worker and starve unrelated HTTP requests. `block_in_place` tells a
/// multi-thread runtime to hand that worker's async tasks to a replacement.
///
/// Router users and unit tests may choose Tokio's current-thread runtime,
/// where `block_in_place` is unavailable. Keep direct execution there: one
/// current-thread runtime cannot concurrently serve another request while a
/// synchronous callback is running. Deployments that require concurrent HTTP
/// request progress must run the router on a multi-thread Tokio runtime (as
/// VGI's built-in HTTP worker does).
fn dispatch_sync<T>(callback: impl FnOnce() -> T) -> T {
    let multi_thread = tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if multi_thread {
        tokio::task::block_in_place(callback)
    } else {
        callback()
    }
}

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
    // Resolve sticky-session headers before dispatch. A presented token
    // that fails to resolve short-circuits with a SessionLostError stream.
    let sticky_sink = match sticky_for_request(&state, &auth, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let server = state.server.clone();

    // Measured before decompression: this is what the peer actually sent,
    // which is the number an egress bill is computed from. `input_bytes`
    // below counts logical Arrow buffers and is a different question.
    let request_wire_bytes = body.len() as u64;
    let body = match maybe_decompress(&headers, &body, request_decode_limit(&state)) {
        Ok(b) => b,
        Err(e) => return request_decode_error(&state, &e),
    };
    let mut req = match parse_request_from_body(&body) {
        Ok(r) => r,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };
    if req.method != method {
        let err = RpcError::protocol_error(format!(
            "Method mismatch: route names '{method}', request metadata names '{}'",
            req.method
        ));
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }
    if let Err(err) = validate_protocol_version(server.protocol_version(), &req.metadata) {
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }

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
                    return cap_error_response(
                        &Schema::empty(),
                        &err,
                        &server.server_id,
                        &req.request_id,
                    );
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
            server.protocol_version(),
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
    if let Err(err) = validate_parameter_batch(&req.batch, &info.params_schema) {
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }

    let mut ctx = CallContext::with_auth_cookies(&server, &req, auth.clone(), cookies);
    if let Some(s) = sticky_sink.clone() {
        ctx.set_sticky(s);
    }
    let mut dispatch_info = crate::hooks::DispatchInfo::from_request(&server, &req, "unary", &auth);
    // Log the HTTP correlation id, not the Arrow-level one. `X-Request-ID`
    // on the response and `request_id` in the record have to name the same
    // request or the trail cannot be joined; `postprocess_middleware`
    // normalizes the inbound header to the value it will stamp on the way
    // out, so reading it here is what makes the two agree. Falls back to the
    // wire request id for a handler reached without that middleware.
    if let Some(id) = headers
        .get(REQUEST_ID_RESPONSE_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        dispatch_info.request_id = id.to_string();
    }
    let hook = server.dispatch_hook.clone();
    // Records cannot be written here: response compression runs after this
    // handler returns, so the on-wire size is not known yet. Park them in a
    // sink the post-processing middleware drains once the body is final.
    let access_sink = hook.as_ref().map(|_| crate::hooks::AccessSink::new());
    if hook.is_some() {
        dispatch_info.request_bytes = Some(request_wire_bytes);
        dispatch_info.access_sink = access_sink.clone();
        // Best-effort self-contained IPC bytes of the request batch for
        // `request_data`; a failure here must not abort dispatch.
        if let Ok(bytes) = crate::server::serialize_request_batch(&req.batch) {
            dispatch_info.request_data = bytes;
        }
    }
    let hook_token = hook.as_ref().map(|h| h.on_dispatch_start(&dispatch_info));
    // Externalised uploads never reach the HTTP body, so they are counted
    // where they happen. No `.await` runs between here and the read below,
    // which is what keeps a thread-local honest on an async handler.
    let externalized = crate::external::ExternalizedScope::new();

    let mut stats = crate::hooks::CallStatistics {
        input_batches: 1,
        input_rows: req.batch.num_rows() as u64,
        ..Default::default()
    };

    // Isolate handler panics: convert them to an `RpcError` that flows into the
    // structured Arrow error envelope below, matching the stdio/unix serve loop.
    // Without this a panic would bottom out at the `CatchPanicLayer` as a bare
    // 500 the DuckDB client can't parse as a VGI error.
    let result = dispatch_sync(|| {
        crate::server::call_guard(|| (info.unary.as_ref().unwrap())(&req, &ctx)).and_then(|r| r)
    });
    let logs = ctx.drain_logs();
    let mut app_err: Option<RpcError> = None;
    // Bytes this response pushed to external storage, in the units
    // `max_externalized_response_bytes` is expressed in (raw, pre-compression
    // IPC). Kept separate from `dispatch_info.externalized_bytes`, which is
    // the compressed egress figure the access log wants.
    let mut external_bytes_written = 0usize;

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
                    // Prepare (serialize + compress) but do not upload yet:
                    // `max_externalized_response_bytes` is pre-flighted below
                    // so a violating response costs no storage round trip.
                    // The prepare/upload pair may invoke a blocking client
                    // (e.g. reqwest::blocking), so both run under
                    // `block_in_place` — otherwise the inner client's tokio
                    // runtime panics on drop inside this async handler.
                    let externalized = tokio::task::block_in_place(|| {
                        // The result schema, not `out_batch.schema()`: the
                        // response stream declares the former, so that is
                        // what the client will validate the fetched payload
                        // against.
                        let prepared = crate::external::prepare_externalize_batch(
                            &out_batch,
                            &info.result_schema,
                            None,
                            cfg,
                        )?;
                        match prepared {
                            None => Ok(None),
                            Some(p) => {
                                if let Some(limit) = state.max_externalized_response_bytes {
                                    if p.cap_bytes() > limit {
                                        return Err(external_cap_error(
                                            p.cap_bytes(),
                                            limit,
                                            &method,
                                        ));
                                    }
                                }
                                external_bytes_written += p.cap_bytes();
                                crate::external::upload_prepared(p, cfg).map(Some)
                            }
                        }
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

    dispatch_info.externalized_bytes = externalized.finish();
    if let Some(hook) = hook {
        hook.on_dispatch_end(
            hook_token.unwrap_or(0),
            &dispatch_info,
            app_err.as_ref(),
            &stats,
        );
    }
    // Operator-facing caps.  Both are hard for unary — overshoot replaces
    // the response with an EXCEPTION-only IPC stream surfaced via 200 +
    // `X-VGI-RPC-Error: true`.  Mirrors Python's strict-fail contract; the
    // literal `max_response_bytes` / `max_externalized_response_bytes`
    // tokens in the messages are what the cross-language conformance suite
    // asserts on.
    //
    // The external cap has already been pre-flighted above, before the
    // upload; this is the backstop that catches an upload path added later
    // that forgot to pre-flight.
    let body_cap_error = state
        .max_response_bytes
        .filter(|limit| buf.len() > *limit)
        .map(|limit| {
            RpcError::runtime_error(format!(
                "HTTP body exceeds max_response_bytes ({} > {}) for method {:?}",
                buf.len(),
                limit,
                method
            ))
        })
        .or_else(|| {
            state
                .max_externalized_response_bytes
                .filter(|limit| external_bytes_written > *limit)
                .map(|limit| external_cap_error(external_bytes_written, limit, &method))
        });
    if let Some(err) = body_cap_error {
        let mut resp = cap_error_response(
            &info.result_schema,
            &err,
            &server.server_id,
            &req.request_id,
        );
        if let Some(s) = sticky_sink.as_ref() {
            stamp_session_headers(&mut resp, &state, s);
        }
        attach_access_sink(&mut resp, access_sink);
        return resp;
    }
    let mut resp = arrow_response(StatusCode::OK, buf);
    if app_err.is_some() {
        // The handler raised (or externalisation failed): the body is an
        // EXCEPTION batch behind a 200, so flag it.
        stamp_rpc_error(&mut resp);
    }
    if let Some(s) = sticky_sink.as_ref() {
        stamp_session_headers(&mut resp, &state, s);
    }
    attach_access_sink(&mut resp, access_sink);
    resp
}

/// Hand the request's deferred access-log records to the response, so
/// `postprocess_middleware` can emit them once the final body exists.
///
/// Response extensions rather than a task-local: the records ride the same
/// value the middleware is already holding, and a response that never
/// reaches the middleware still emits when the sink is dropped.
fn attach_access_sink(resp: &mut Response, sink: Option<crate::hooks::AccessSink>) {
    if let Some(sink) = sink {
        if !sink.is_empty() {
            resp.extensions_mut().insert(sink);
        }
    }
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
    let sticky_sink = match sticky_for_request(&state, &auth, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let auth_for_token = auth.clone();
    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let server = state.server.clone();
    let body = match maybe_decompress(&headers, &body, request_decode_limit(&state)) {
        Ok(b) => b,
        Err(e) => return request_decode_error(&state, &e),
    };
    let mut req = match parse_request_from_body(&body) {
        Ok(r) => r,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };
    if req.method != method {
        let err = RpcError::protocol_error(format!(
            "Method mismatch: route names '{method}', request metadata names '{}'",
            req.method
        ));
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }
    if let Err(err) = validate_protocol_version(server.protocol_version(), &req.metadata) {
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }

    // Stream initialization accepts the same externalized parameter shape as
    // unary calls. Keep routing metadata from the pointer request and replace
    // only the parameter batch with the fetched batch.
    if md_get(&req.metadata, crate::metadata::LOCATION_KEY).is_some() {
        if let Some(cfg) = server.external_config().as_ref() {
            let resolved = tokio::task::block_in_place(|| {
                crate::external::resolve_external_location(&req.batch, &req.metadata, cfg)
            });
            match resolved {
                Ok((inner_batch, _user_md)) => req.batch = inner_batch,
                Err(err) => {
                    return cap_error_response(
                        &Schema::empty(),
                        &err,
                        &server.server_id,
                        &req.request_id,
                    );
                }
            }
        }
    }

    let Some(info) = server
        .method(&method)
        .filter(|m| m.method_type != MethodType::Unary)
    else {
        let err = RpcError::attribute_error(format!("Unknown stream method: '{}'", method));
        return arrow_error(&state, StatusCode::NOT_FOUND, &err, &req.request_id);
    };
    if let Err(err) = validate_parameter_batch(&req.batch, &info.params_schema) {
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, &req.request_id);
    }

    let mut ctx = CallContext::with_auth_cookies(&server, &req, auth, cookies);
    if let Some(s) = sticky_sink.clone() {
        ctx.set_sticky(s);
    }
    // Isolate handler panics into the structured stream error envelope below
    // (see the unary path for rationale).
    let init_result = dispatch_sync(|| {
        crate::server::call_guard(|| (info.stream.as_ref().unwrap())(&req, &ctx)).and_then(|r| r)
    });
    let init_logs = ctx.drain_logs();

    let sr = match init_result {
        Ok(s) => s,
        Err(err) => {
            let mut resp = arrow_response(
                StatusCode::OK,
                error_stream_bytes(&empty_schema(), &err, &server.server_id, &req.request_id),
            );
            stamp_rpc_error(&mut resp);
            return resp;
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
    // Set when the body ends up carrying an EXCEPTION envelope — either the
    // producer's first turn raised, or the state token could not be minted.
    let mut wrote_error = false;
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
            // The producer's first turn folds into this /init request, so the
            // init request's custom metadata is what the pipe transports
            // would have delivered on the first tick batch.
            let turn = run_producer(
                &mut sw,
                &mut ss,
                &output_schema,
                &state,
                &method,
                &req,
                sticky_sink.as_ref(),
                Some(req.metadata.as_ref()),
            );
            finished = turn.finished;
            wrote_error |= turn.errored;
        }
        if !finished {
            match build_init_tokens(
                &state,
                &auth_for_token,
                &ss,
                &output_schema,
                input_schema.as_ref(),
                &stream_id,
            ) {
                Ok((token, call_token)) => {
                    // /init is the one response that hands over the call
                    // token; continuations re-mint the cursor alone.
                    let md = Metadata::from([
                        (STATE_KEY.to_string(), token),
                        (CALL_STATE_KEY.to_string(), call_token),
                    ]);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                }
                Err(err) => {
                    // Handler doesn't implement encode_state — emit as an
                    // error envelope so the client sees a useful message
                    // instead of a hung stream.
                    let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    wrote_error = true;
                }
            }
        }
        let _ = sw.finish();
    }

    let mut resp = arrow_response(StatusCode::OK, body_buf);
    if wrote_error {
        // The body is an EXCEPTION envelope behind a 200; without the flag a
        // client reads the failure as a result.
        stamp_rpc_error(&mut resp);
    }
    if let Some(s) = sticky_sink.as_ref() {
        stamp_session_headers(&mut resp, &state, s);
    }
    resp
}

/// Encode a `StreamStateKind` into a signed state token. The token is
/// bound to `auth` so a different identity replaying it will fail HMAC
/// verification on the next continuation request.
/// Mint a stream's pair of tokens at `/init`: the call token, which carries
/// everything fixed for the life of the call, and the first cursor.
fn build_init_tokens(
    state: &Arc<HttpState>,
    auth: &crate::auth::AuthContext,
    ss: &StreamStateKind,
    output_schema: &SchemaRef,
    input_schema: Option<&SchemaRef>,
    stream_id: &str,
) -> Result<(String, String)> {
    let out_schema_bytes = write_schema_bytes(output_schema.as_ref())?;
    let in_schema_bytes = match input_schema {
        Some(s) => write_schema_bytes(s.as_ref())?,
        None => Vec::new(),
    };
    let mut call_id = [0u8; CALL_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut call_id);

    let call_token = state.pack_call_token(
        auth,
        &call_id,
        &out_schema_bytes,
        &in_schema_bytes,
        stream_id,
    );
    let cursor = build_cursor_token(state, auth, ss, &call_id)?;
    Ok((cursor, call_token))
}

/// Like [`build_continuation_token`] but takes the already-serialized schema
/// IPC bytes. Continuation requests carry these verbatim in the incoming
/// token, so re-serializing the `SchemaRef`s (a decode→re-encode round trip,
/// plus two `empty_batch` builds) on every turn is pure waste — thread the
/// bytes straight through instead.
fn build_cursor_token(
    state: &Arc<HttpState>,
    auth: &crate::auth::AuthContext,
    ss: &StreamStateKind,
    call_id: &[u8; CALL_ID_LEN],
) -> Result<String> {
    let state_bytes = dispatch_sync(|| {
        crate::server::call_guard(|| match ss {
            StreamStateKind::Producer(p) => p.encode_state(),
            StreamStateKind::Exchange(e) => e.encode_state(),
        })
        .and_then(|result| result)
    })?;
    Ok(state.pack_cursor_token(auth, &state_bytes, call_id))
}

/// What the HTTP stream paths should do with one output batch after the
/// external-location machinery has had a look at it.
enum StreamEmit {
    /// Externalised: write this zero-row pointer batch with this metadata.
    Pointer(RecordBatch, Metadata),
    /// Not externalised (no storage configured, or below the threshold) —
    /// write the batch inline exactly as the worker emitted it.
    Inline,
    /// Refused or failed. The turn must stop and emit this error envelope.
    Failed(RpcError),
}

/// Externalize one stream output batch, enforcing the **hard** external cap.
///
/// Both HTTP stream shapes route their emitted batches through here.  Before
/// this existed the HTTP transport was the only one that never externalised
/// stream output: `maybe_externalize_batch` was wired into the unary handler
/// and into the pipe/unix serve loop, but the HTTP producer and exchange
/// loops wrote every batch inline.  Python (`_flush_collector` under
/// `_run_http_producer_turn` / `_run_http_exchange_turn`) and TypeScript
/// (`produceStreamResponse`) both externalise here, so a client talking to a
/// Rust worker over HTTP got whole batches on the wire where the other ports
/// handed back a pointer.
///
/// `cumulative_external` is the running total for *this HTTP turn*, in the
/// units the cap is expressed in, and is advanced only when an upload is
/// actually performed.
///
/// The cap is checked **before** the upload and is hard: a producer's *wire*
/// overshoot (`max_response_bytes`) is absorbed by minting a continuation
/// token, but there is no equivalent rescue for the external channel —
/// by the time a continuation could be minted the bytes are already in
/// object storage. So an overshoot ends the turn with an error instead.
fn externalize_stream_batch(
    state: &Arc<HttpState>,
    batch: &RecordBatch,
    output_schema: &SchemaRef,
    metadata: Option<&Metadata>,
    method: &str,
    cumulative_external: &mut usize,
) -> StreamEmit {
    let Some(cfg) = state.server.external_config() else {
        return StreamEmit::Inline;
    };
    // The upload may drive a blocking client (e.g. reqwest::blocking) whose
    // inner runtime panics if dropped on an async worker thread; see the
    // unary path for the same treatment.
    tokio::task::block_in_place(|| {
        // `output_schema`, not `batch.schema()` — the response stream was
        // opened with the former, and a batch that differs from it only
        // cosmetically must externalise to the same bytes it would have
        // been delivered as inline.
        let prepared =
            match crate::external::prepare_externalize_batch(batch, output_schema, metadata, cfg) {
                Ok(Some(p)) => p,
                Ok(None) => return StreamEmit::Inline,
                Err(err) => return StreamEmit::Failed(err),
            };
        let cap_bytes = prepared.cap_bytes();
        if let Some(limit) = state.max_externalized_response_bytes {
            let projected = *cumulative_external + cap_bytes;
            if projected > limit {
                return StreamEmit::Failed(external_cap_error(projected, limit, method));
            }
        }
        match crate::external::upload_prepared(prepared, cfg) {
            Ok((ptr, md)) => {
                // Charged after the upload succeeded — a failed upload put
                // nothing in storage, so charging it would shrink the budget
                // for bytes that never left.
                *cumulative_external += cap_bytes;
                StreamEmit::Pointer(ptr, md)
            }
            Err(err) => StreamEmit::Failed(err),
        }
    })
}

/// Outcome of one HTTP producer turn.
///
/// `errored` is separate from `finished` because a raising `produce` ends the
/// turn exactly like a clean completion does: both stop the loop, but only one
/// leaves an EXCEPTION envelope in the body, and that is the case the enclosing
/// 200 must be flagged for.
struct ProducerTurn {
    /// The stream is over — no continuation token should be minted.
    finished: bool,
    /// The turn wrote an EXCEPTION envelope rather than data.
    errored: bool,
}

/// Metadata keys the HTTP transport itself puts on a stream continuation
/// request. They are transport plumbing, not application metadata: the pipe
/// transports carry the equivalent state in the connection rather than on the
/// batch, so a worker must never see them on a tick. [`STATE_KEY`] in
/// particular is a sealed cursor token.
const FRAMEWORK_TICK_METADATA_KEYS: [&str; 3] = [STATE_KEY, CALL_STATE_KEY, CANCEL_KEY];

/// Returns `md` with the framework's transport keys removed, so a continuation
/// request's metadata can be surfaced to user code as that turn's tick
/// metadata.
fn strip_framework_tick_metadata(md: &Metadata) -> Metadata {
    md.iter()
        .filter(|(k, _)| !FRAMEWORK_TICK_METADATA_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// `tick_md` is surfaced as [`CallContext::tick_metadata`] on the single
/// `produce` call of this HTTP turn. On the pipe transports every
/// producer turn is a distinct tick batch whose custom metadata reaches the
/// worker; over HTTP the first turn folds into the /init request and later
/// turns are continuation POSTs, so callers pass the corresponding request's
/// metadata (framework transport keys stripped by
/// [`strip_framework_tick_metadata`]). That carries both the /init-time
/// revalidators (`vgi.cache.if_none_match`) and DuckDB's between-tick
/// dynamic-filter updates (`vgi_pushdown_filters`).
#[allow(clippy::too_many_arguments)]
fn run_producer<W: std::io::Write>(
    sw: &mut StreamWriter<W>,
    ss: &mut StreamStateKind,
    output_schema: &SchemaRef,
    state: &Arc<HttpState>,
    method: &str,
    req: &Request,
    sticky: Option<&Arc<crate::sticky::StickySinkImpl>>,
    tick_md: Option<&Metadata>,
) -> ProducerTurn {
    let server = &state.server;
    // Continuation producers run without auth context (session-bound).
    let mut ctx = CallContext::for_request(server, req);
    if let Some(s) = sticky {
        ctx.set_sticky(s.clone());
    }
    if let Some(md) = tick_md {
        ctx.set_tick_metadata(md.clone());
    }
    let producer = match ss {
        StreamStateKind::Producer(p) => p,
        StreamStateKind::Exchange(_) => unreachable!(),
    };
    // Bytes this turn has pushed to external storage. Resets per HTTP turn,
    // matching the reference: each turn is one response and the cap is a
    // per-response ceiling.
    let mut cumulative_external = 0usize;
    let mut out = OutputCollector::new(output_schema.clone(), true);
    let result = dispatch_sync(|| {
        crate::server::call_guard(|| producer.produce(&mut out, &ctx)).and_then(|result| result)
    });
    for log in ctx.drain_logs() {
        let md = build_log_metadata(&log, &server.server_id, &req.request_id);
        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
    }
    if let Err(err) = result {
        let md = build_error_metadata(&err, &server.server_id, &req.request_id);
        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
        return ProducerTurn {
            finished: true,
            errored: true,
        };
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
                match externalize_stream_batch(
                    state,
                    &batch,
                    output_schema,
                    metadata.as_ref(),
                    method,
                    &mut cumulative_external,
                ) {
                    StreamEmit::Pointer(ptr, md) => {
                        let _ = sw.write(&ptr, Some(&md));
                    }
                    StreamEmit::Inline => {
                        let _ = sw.write(&batch, metadata.as_ref());
                    }
                    StreamEmit::Failed(err) => {
                        // Hard stop: no continuation token is minted, so
                        // the client sees an `RpcError` on iteration
                        // rather than a stream that quietly resumes past
                        // a cap it just blew.
                        let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                        return ProducerTurn {
                            finished: true,
                            errored: true,
                        };
                    }
                }
                emitted_data = true;
            }
        }
    }
    ProducerTurn {
        // Guard against degenerate producers that neither emit nor finish.
        finished: finished || !emitted_data,
        errored: false,
    }
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
    let sticky_sink = match sticky_for_request(&state, &auth, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let server = state.server.clone();
    let body = match maybe_decompress(&headers, &body, request_decode_limit(&state)) {
        Ok(b) => b,
        Err(e) => return request_decode_error(&state, &e),
    };
    // Parse input batch (may be empty-schema for cancel / producer continuation).
    let (mut batch, mut metadata) = match read_input_batch(&body) {
        Ok(x) => x,
        Err(e) => return arrow_error(&state, StatusCode::BAD_REQUEST, &e, ""),
    };

    // Resolve externally uploaded exchange input before reading state tokens
    // or dispatching. The resolver merges outer and inner metadata, preserving
    // cursor/call tokens regardless of which side of the pointer carried them.
    if md_get(&metadata, crate::metadata::LOCATION_KEY).is_some() {
        if let Some(cfg) = server.external_config().as_ref() {
            let resolved = tokio::task::block_in_place(|| {
                crate::external::resolve_external_location(&batch, &metadata, cfg)
            });
            match resolved {
                Ok((inner_batch, inner_metadata)) => {
                    batch = inner_batch;
                    metadata = inner_metadata;
                }
                Err(err) => {
                    return cap_error_response(&Schema::empty(), &err, &server.server_id, "");
                }
            }
        }
    }

    let Some(token) = md_get(&metadata, STATE_KEY).map(str::to_owned) else {
        let err = RpcError::runtime_error("Missing state token in exchange request");
        return arrow_error(&state, StatusCode::BAD_REQUEST, &err, "");
    };
    let cancelled = md_get(&metadata, CANCEL_KEY).is_some();
    let call_token = md_get(&metadata, CALL_STATE_KEY).map(str::to_owned);

    // Open the cursor FIRST: its AEAD tag covers the call id and its AAD
    // covers the caller, so the id is authenticated before it is used to
    // resolve anything. See HttpState::resolve_call for why that ordering is
    // the whole security argument for the cache.
    let unpacked = match state.unpack_cursor_token(&auth, &token) {
        Ok(u) => u,
        Err(err) => return arrow_error(&state, StatusCode::BAD_REQUEST, &err, ""),
    };
    let call = match state.resolve_call(&auth, &unpacked, call_token.as_deref()) {
        Ok(c) => c,
        Err(err) => return arrow_error(&state, StatusCode::BAD_REQUEST, &err, ""),
    };

    // Reconstruct schemas from the call token's IPC bytes.
    let output_schema = match read_schema_bytes(&call.output_schema_bytes) {
        Ok(s) => s,
        Err(err) => return arrow_error(&state, StatusCode::BAD_REQUEST, &err, ""),
    };
    let input_schema: Option<SchemaRef> = if call.input_schema_bytes.is_empty() {
        None
    } else {
        match read_schema_bytes(&call.input_schema_bytes) {
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
    let mut ss = match dispatch_sync(|| {
        crate::server::call_guard(|| decoder(&unpacked.state_bytes)).and_then(|result| result)
    }) {
        Ok(s) => s,
        Err(err) => return arrow_error(&state, StatusCode::BAD_REQUEST, &err, ""),
    };

    let req = Request {
        method: method.clone(),
        request_id: md_get(&metadata, REQUEST_ID_KEY).unwrap_or("").to_string(),
        batch: empty_batch(&Schema::empty()).unwrap(),
        metadata: Arc::new(metadata.clone()),
    };
    let mut ctx = CallContext::for_request(&server, &req);
    if let Some(s) = sticky_sink.clone() {
        ctx.set_sticky(s);
    }

    let mut body_buf = Vec::new();

    if cancelled {
        let cancel_result = dispatch_sync(|| {
            crate::server::call_guard(|| match &mut ss {
                StreamStateKind::Producer(p) => p.on_cancel(&ctx),
                StreamStateKind::Exchange(e) => e.on_cancel(&ctx),
            })
        });
        {
            let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
            for log in ctx.drain_logs() {
                let md = build_log_metadata(&log, &server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            }
            if let Err(err) = &cancel_result {
                let md = build_error_metadata(err, &server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            }
            let _ = sw.finish();
        }
        let mut resp = arrow_response(StatusCode::OK, body_buf);
        if cancel_result.is_err() {
            stamp_rpc_error(&mut resp);
        }
        if let Some(s) = sticky_sink.as_ref() {
            stamp_session_headers(&mut resp, &state, s);
        }
        return resp;
    }

    if matches!(ss, StreamStateKind::Producer(_)) {
        // Producer continuation.
        let mut wrote_error = false;
        {
            let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
            // The continuation request's custom metadata is this turn's tick
            // metadata. On the pipe transports every producer turn is a tick
            // batch whose metadata reaches the worker, and DuckDB uses that to
            // push *updated* dynamic filters (`vgi_pushdown_filters` — Top-N
            // boundary tightening, join-key IN sets) between ticks. Over HTTP
            // a turn is a continuation POST, so its metadata has to be
            // forwarded here or those updates are silently dropped. The
            // framework's own transport keys are stripped first: the pipe
            // transports never put them on a tick, and the stream-state value
            // is a sealed cursor token that must not surface to user code.
            let continuation_md = strip_framework_tick_metadata(&metadata);
            let turn = run_producer(
                &mut sw,
                &mut ss,
                &output_schema,
                &state,
                &method,
                &req,
                sticky_sink.as_ref(),
                Some(&continuation_md),
            );
            wrote_error |= turn.errored;
            if !turn.finished {
                match build_cursor_token(&state, &auth, &ss, &unpacked.call_id) {
                    Ok(new_token) => {
                        let md = Metadata::from([(STATE_KEY.to_string(), new_token)]);
                        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    }
                    Err(err) => {
                        let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                        wrote_error = true;
                    }
                }
            }
            let _ = sw.finish();
        }
        let mut resp = arrow_response(StatusCode::OK, body_buf);
        if wrote_error {
            stamp_rpc_error(&mut resp);
        }
        if let Some(s) = sticky_sink.as_ref() {
            stamp_session_headers(&mut resp, &state, s);
        }
        return resp;
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
                let mut resp = arrow_response(StatusCode::OK, body_buf);
                stamp_rpc_error(&mut resp);
                return resp;
            }
        },
        _ => batch,
    };

    // This turn's input-batch metadata is what the pipe transports surface as
    // `CallContext::tick_metadata`: server.rs's lockstep loop moves each input
    // batch's own metadata into the context before dispatching the exchange.
    // Over HTTP an exchange turn is a continuation POST, so that request's
    // metadata plays the same role and has to be forwarded here — without it
    // an identical worker sees its `vgi.cache.*` revalidators (and any other
    // per-batch metadata) over subprocess and nothing at all over HTTP.
    //
    // The framework's own transport keys are stripped first, exactly as on the
    // producer continuation turn: the pipe transports keep the stream cursor
    // and call state in the CONNECTION rather than on a batch, and the cursor
    // is an AEAD-sealed token that must not surface to application code.
    ctx.set_tick_metadata(strip_framework_tick_metadata(&metadata));

    let mut out = OutputCollector::new(output_schema.clone(), false);
    let res = dispatch_sync(|| {
        crate::server::call_guard(|| match &mut ss {
            StreamStateKind::Exchange(e) => e.exchange(&casted, &mut out, &ctx),
            _ => unreachable!(),
        })
        .and_then(|result| result)
    });

    let mut wrote_error = false;
    {
        let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
        for log in ctx.drain_logs() {
            let md = build_log_metadata(&log, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
        }
        if let Err(err) = res {
            let md = build_error_metadata(&err, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            wrote_error = true;
        } else {
            let new_token = match build_cursor_token(&state, &auth, &ss, &unpacked.call_id) {
                Ok(t) => t,
                Err(err) => {
                    let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    let _ = sw.finish();
                    drop(sw);
                    let mut resp = arrow_response(StatusCode::OK, body_buf);
                    stamp_rpc_error(&mut resp);
                    return resp;
                }
            };
            let mut wrote_data = false;
            // Per-response external budget, same units and same hard
            // semantics as the producer path.
            let mut cumulative_external = 0usize;
            for item in out.items.drain(..) {
                match item {
                    Emitted::Log(log) => {
                        let md = build_log_metadata(&log, &server.server_id, &req.request_id);
                        let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    }
                    Emitted::Batch { batch, metadata } => {
                        // The refreshed cursor rides the data batch's
                        // metadata, so it has to survive externalisation —
                        // pass it in as the pointer batch's inline metadata
                        // rather than stamping the batch we may not write.
                        let mut md = metadata.unwrap_or_default();
                        md.insert(STATE_KEY.to_string(), new_token.clone());
                        match externalize_stream_batch(
                            &state,
                            &batch,
                            &output_schema,
                            Some(&md),
                            &method,
                            &mut cumulative_external,
                        ) {
                            StreamEmit::Pointer(ptr, ptr_md) => {
                                let _ = sw.write(&ptr, Some(&ptr_md));
                            }
                            StreamEmit::Inline => {
                                let _ = sw.write(&batch, Some(&md));
                            }
                            StreamEmit::Failed(err) => {
                                let emd =
                                    build_error_metadata(&err, &server.server_id, &req.request_id);
                                let _ = sw.write(
                                    &empty_batch(output_schema.as_ref()).unwrap(),
                                    Some(&emd),
                                );
                                wrote_error = true;
                                break;
                            }
                        }
                        wrote_data = true;
                    }
                }
            }
            // A cap overshoot already wrote the EXCEPTION envelope and left
            // `wrote_data` false; handing back a fresh cursor after it would
            // invite the client to keep going on a turn that failed.
            if !wrote_data && !wrote_error {
                let md = Metadata::from([(STATE_KEY.to_string(), new_token)]);
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            }
        }
        let _ = sw.finish();
    }

    let mut resp = enforce_response_body_cap(
        &state,
        output_schema.as_ref(),
        body_buf,
        &method,
        &server.server_id,
        "",
    );
    if wrote_error {
        // The handler raised; the envelope is in the body behind a 200.
        // (A cap overshoot is already flagged by `cap_error_response`.)
        stamp_rpc_error(&mut resp);
    }
    if let Some(s) = sticky_sink.as_ref() {
        stamp_session_headers(&mut resp, &state, s);
    }
    resp
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

    const TEST_CALL_ID: [u8; CALL_ID_LEN] = [9u8; CALL_ID_LEN];

    fn sample_schema_bytes() -> Vec<u8> {
        use arrow_schema::{DataType, Field, Schema};
        write_schema_bytes(&Schema::new(vec![Field::new("x", DataType::Int64, false)])).unwrap()
    }

    // Token payloads are compressed *inside* the seal. The ordering is the
    // whole point: once a token is sealed it is ciphertext, so the HTTP body
    // codec can find no redundancy in it — it recovers only the slack base64
    // adds, never the state's own structure. Compressing before sealing
    // reaches the real redundancy.
    //
    // None of this is visible on the wire, so the cross-language conformance
    // suite cannot reach it; docs/WIRE_PROTOCOL.md in the reference repo
    // makes it normative and asks each port to pin it with a language-local
    // test like these.

    #[test]
    fn token_payload_compresses_when_redundant() {
        let plaintext = b"vgi-rpc-state-".repeat(1000);
        let packed = pack_token_payload(&plaintext);
        assert_eq!(packed[0], TOKEN_CODEC_ZSTD, "expected the zstd codec tag");
        assert!(
            packed.len() < plaintext.len() / 4,
            "expected real compression on a redundant payload, got {} from {}",
            packed.len(),
            plaintext.len()
        );
    }

    #[test]
    fn token_payload_stays_raw_when_incompressible() {
        // A counter pattern with no repeats gives the codec nothing to find.
        // Skipping is what keeps the guarantee one-directional: a token may
        // get smaller, never larger than its plaintext plus the one tag byte.
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let packed = pack_token_payload(&plaintext);
        assert_eq!(packed[0], TOKEN_CODEC_RAW, "expected the raw codec tag");
        assert_eq!(
            packed.len(),
            plaintext.len() + 1,
            "raw payload must not grow beyond the tag byte"
        );
    }

    #[test]
    fn token_payload_round_trips_under_either_codec() {
        let incompressible: Vec<u8> = (0u8..=255).collect();
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"x".to_vec(),
            incompressible,
            b"vgi-rpc-state-".repeat(500),
        ];
        for plaintext in cases {
            let packed = pack_token_payload(&plaintext);
            let got = unpack_token_payload(&packed).expect("round trip");
            assert_eq!(got, plaintext, "round trip changed the payload");
        }
    }

    #[test]
    fn token_payload_rejects_malformed_input() {
        // An unknown tag, an empty payload, or a body that will not
        // decompress all mean a token this server did not mint, so all three
        // surface as the same uniform error the caller maps to 400.
        assert!(unpack_token_payload(&[]).is_err(), "empty payload");
        assert!(
            unpack_token_payload(&[0x7f, b'p', b'a', b'y']).is_err(),
            "unknown codec tag"
        );
        let mut corrupt = vec![TOKEN_CODEC_ZSTD];
        corrupt.extend_from_slice(b"not-a-zstd-frame");
        assert!(unpack_token_payload(&corrupt).is_err(), "corrupt zstd body");
    }

    #[tokio::test]
    async fn sealed_token_shrinks_with_a_compressible_state() {
        // End to end: compression inside the seal shrinks the token itself.
        // Guards the ordering rather than the codec — a token sealed around
        // an uncompressed payload comes out *larger* than its input once
        // base64 inflation is counted, which is the regression this catches.
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let state_bytes = b"vgi-rpc-call-state-".repeat(400);
        let token = s.pack_cursor_token(&auth, &state_bytes, &TEST_CALL_ID);
        assert!(
            token.len() < state_bytes.len() / 4,
            "sealed token ({}B) should be far smaller than its state ({}B)",
            token.len(),
            state_bytes.len()
        );

        let unpacked = s.unpack_cursor_token(&auth, &token).unwrap();
        assert_eq!(unpacked.state_bytes, state_bytes, "state survived the seal");
    }

    #[tokio::test]
    async fn pack_unpack_roundtrip() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let state_bytes = b"state-payload";
        let out_sch = sample_schema_bytes();
        let in_sch = sample_schema_bytes();
        let token = s.pack_cursor_token(&auth, state_bytes, &TEST_CALL_ID);
        let unpacked = s.unpack_cursor_token(&auth, &token).unwrap();
        assert_eq!(unpacked.state_bytes, state_bytes);
        assert_eq!(unpacked.call_id, TEST_CALL_ID);

        // The schemas and stream id ride the call token now, not the cursor.
        let call_token = s.pack_call_token(&auth, &TEST_CALL_ID, &out_sch, &in_sch, "sid-123");
        let call = s.resolve_call(&auth, &unpacked, Some(&call_token)).unwrap();
        assert_eq!(call.output_schema_bytes, out_sch);
        assert_eq!(call.input_schema_bytes, in_sch);
        assert_eq!(call.stream_id, "sid-123");
    }

    #[tokio::test]
    async fn unpack_rejects_tampered_ciphertext() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let token = s.pack_cursor_token(&auth, b"s", &TEST_CALL_ID);
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(token.as_bytes())
            .unwrap();
        // Flip a bit inside the ciphertext (past the 1-byte version + 24-byte
        // nonce header owned by `crypto`).
        let cipher_idx = 1 + 24;
        bytes[cipher_idx] ^= 0x01;
        let tampered = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert!(s.unpack_cursor_token(&auth, &tampered).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_tampered_nonce() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let token = s.pack_cursor_token(&auth, b"s", &TEST_CALL_ID);
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(token.as_bytes())
            .unwrap();
        // Flip the first nonce byte; AEAD decryption must reject.
        bytes[1] ^= 0x01;
        let tampered = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert!(s.unpack_cursor_token(&auth, &tampered).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_unknown_version() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let token = s.pack_cursor_token(&auth, b"s", &TEST_CALL_ID);
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(token.as_bytes())
            .unwrap();
        bytes[0] = 0x99;
        let tampered = base64::engine::general_purpose::STANDARD.encode(bytes);
        let err = s.unpack_cursor_token(&auth, &tampered).unwrap_err();
        // Wrong-version tokens map to the same uniform error as every other
        // bad-token mode — callers cannot distinguish failure modes.
        assert!(err.message.contains("signature verification failed"));
    }

    #[tokio::test]
    async fn unpack_rejects_malformed_base64() {
        let s = state_with_key();
        let auth = crate::auth::AuthContext::anonymous();
        let err = s.unpack_cursor_token(&auth, "not!base64!").unwrap_err();
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
        let tok = a.pack_cursor_token(&auth, b"s", &TEST_CALL_ID);
        assert!(b.unpack_cursor_token(&auth, &tok).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_expired_token() {
        let s = state_with_key(); // ttl = 50ms
        let auth = crate::auth::AuthContext::anonymous();
        // Pack a token whose created_at is far in the past, using the
        // same AAD the server will reconstruct for an anonymous caller.
        let aad = compute_aad(&auth);
        let stale = pack_cursor_token(&[7u8; 32], &aad, b"s", &TEST_CALL_ID, 0);
        let err = s.unpack_cursor_token(&auth, &stale).unwrap_err();
        assert!(err.message.contains("expired"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn unpack_rejects_different_principal() {
        let s = state_with_key();
        let alice = crate::auth::AuthContext::for_principal("bearer", "alice");
        let bob = crate::auth::AuthContext::for_principal("bearer", "bob");
        let tok = s.pack_cursor_token(&alice, b"s", &TEST_CALL_ID);
        assert!(s.unpack_cursor_token(&alice, &tok).is_ok());
        assert!(s.unpack_cursor_token(&bob, &tok).is_err());
        let anon = crate::auth::AuthContext::anonymous();
        assert!(s.unpack_cursor_token(&anon, &tok).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_authenticated_replay_of_anonymous_token() {
        let s = state_with_key();
        let anon = crate::auth::AuthContext::anonymous();
        let alice = crate::auth::AuthContext::for_principal("bearer", "alice");
        let tok = s.pack_cursor_token(&anon, b"s", &TEST_CALL_ID);
        assert!(s.unpack_cursor_token(&alice, &tok).is_err());
    }

    #[tokio::test]
    async fn unpack_rejects_cross_domain_replay() {
        let s = state_with_key();
        let bearer_alice = crate::auth::AuthContext::for_principal("bearer", "alice");
        let mtls_alice = crate::auth::AuthContext::for_principal("mtls", "alice");
        let tok = s.pack_cursor_token(&bearer_alice, b"s", &TEST_CALL_ID);
        assert!(s.unpack_cursor_token(&mtls_alice, &tok).is_err());
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
        let err =
            super::decode_content_encoding(&compressed, Some("zstd"), Some(64 * 1024)).unwrap_err();
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
        let out = super::decode_content_encoding(&compressed, Some("zstd"), Some(1024)).unwrap();
        assert_eq!(out, small);
    }

    #[test]
    fn zstd_bounded_rejects_large_window_for_small_output() {
        use std::io::Write;

        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
        encoder.window_log(20).unwrap();
        encoder.include_contentsize(false).unwrap();
        encoder.write_all(b"tiny").unwrap();
        let frame = encoder.finish().unwrap();

        let err = super::decode_content_encoding(&frame, Some("zstd"), Some(1024))
            .expect_err("a 1 MiB history window must exceed the 512 KiB decoder floor");
        assert!(
            err.message.contains("window") || err.message.contains("memory"),
            "expected window-limit error, got: {}",
            err.message
        );
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn decode_content_encoding_handles_gzip() {
        let payload = b"hello-gzip".repeat(10);
        let out = super::decode_content_encoding(&gzip(&payload), Some("gzip"), None).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn decode_content_encoding_bounds_gzip_zip_bombs() {
        let huge = vec![0u8; 8 * 1024 * 1024];
        let compressed = gzip(&huge);
        assert!(compressed.len() < 100_000, "compressed should be tiny");
        let err =
            super::decode_content_encoding(&compressed, Some("gzip"), Some(64 * 1024)).unwrap_err();
        assert!(err.message.contains("exceeds max size"));
    }

    #[test]
    fn decode_content_encoding_applies_a_coding_list_in_reverse() {
        // `Content-Encoding: gzip, zstd` means gzip was applied first, then zstd.
        let payload = b"layered".repeat(20);
        let body = zstd::encode_all(gzip(&payload).as_slice(), 1).unwrap();
        let out = super::decode_content_encoding(&body, Some("gzip, zstd"), None).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn decode_content_encoding_refuses_an_absurd_coding_chain() {
        let chain = std::iter::repeat_n("zstd", super::MAX_CONTENT_CODINGS + 1)
            .collect::<Vec<_>>()
            .join(", ");
        let err = super::decode_content_encoding(b"x", Some(&chain), Some(1024)).unwrap_err();
        assert!(err.message.contains("more than"), "got: {}", err.message);
    }

    #[test]
    fn decode_content_encoding_allows_a_chain_up_to_the_cap() {
        // gzip applied twice, then zstd: 3 codings, under the cap.
        let payload = b"bounded".repeat(8);
        let body = zstd::encode_all(gzip(&gzip(&payload)).as_slice(), 1).unwrap();
        let out = super::decode_content_encoding(&body, Some("gzip, gzip, zstd"), Some(64 * 1024))
            .unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn decode_content_encoding_passes_through_identity_and_unknown() {
        let raw = b"plain bytes";
        for header in [None, Some(""), Some("identity"), Some("br")] {
            let out = super::decode_content_encoding(raw, header, None).unwrap();
            assert_eq!(out, raw, "header {header:?} should pass through");
        }
    }

    // ---- response-codec negotiation ------------------------------------
    //
    // `pick_response_encoding` walks the *client's* stated order over the
    // merged `X-VGI-Accept-Encoding ++ Accept-Encoding` list. The tests below
    // pin the ordering, parsing, and which response header carries the answer.

    /// Build a `HeaderMap` from `(name, value)` pairs.
    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn parse_encoding_list_is_ordered_deduped_and_ignores_q_values() {
        use super::ResponseEncoding::*;
        assert_eq!(super::parse_encoding_list(None), vec![]);
        assert_eq!(super::parse_encoding_list(Some("")), vec![]);
        assert_eq!(super::parse_encoding_list(Some("  ,  ,")), vec![]);
        // Unknown tokens are skipped, known ones keep the client's order.
        assert_eq!(
            super::parse_encoding_list(Some("deflate, gzip, br, zstd")),
            vec![Gzip, Zstd]
        );
        // q-values are parsed off and ignored — not honoured as weights.
        assert_eq!(
            super::parse_encoding_list(Some("zstd;q=0.5, gzip")),
            vec![Zstd, Gzip]
        );
        // Case-insensitive, whitespace-tolerant, first occurrence wins.
        assert_eq!(
            super::parse_encoding_list(Some(" ZSTD , gzip ,zstd")),
            vec![Zstd, Gzip]
        );
        // `identity` is a first-class token, ordered like any other.
        assert_eq!(
            super::parse_encoding_list(Some("identity, zstd")),
            vec![Identity, Zstd]
        );
        // `identity;q=0` is not special-cased — q is parsed off and ignored,
        // so order alone decides and identity still leads.
        assert_eq!(
            super::parse_encoding_list(Some("identity;q=0, zstd")),
            vec![Identity, Zstd]
        );
    }

    #[test]
    fn custom_header_alone_negotiates_and_stamps_the_custom_response_header() {
        // The browser/WASM case: `fetch()` cannot set `Accept-Encoding`, so
        // the only preference the server sees is the custom header. Before
        // this negotiation existed such a client always got identity.
        let h = headers(&[("x-vgi-accept-encoding", "zstd, gzip")]);
        let (enc, used_custom) = super::pick_response_encoding(&h, Some(3)).unwrap();
        assert_eq!(enc, super::ResponseEncoding::Zstd);
        assert!(
            used_custom,
            "zstd came only from the custom header, so the custom response \
             header must carry it"
        );
    }

    #[test]
    fn custom_header_wins_over_a_gzip_first_standard_header() {
        // The cpp-httplib regression case: the DuckDB engine's HTTP client
        // injects `Accept-Encoding: deflate, gzip, br, zstd` (gzip first)
        // while VGI states zstd first. zstd must win, and because it is in
        // both lists the answer rides the standard `Content-Encoding`.
        let h = headers(&[
            ("accept-encoding", "deflate, gzip, br, zstd"),
            ("x-vgi-accept-encoding", "zstd, gzip"),
        ]);
        let (enc, used_custom) = super::pick_response_encoding(&h, Some(3)).unwrap();
        assert_eq!(enc, super::ResponseEncoding::Zstd);
        assert!(
            !used_custom,
            "zstd is in the standard header too, so stamp Content-Encoding"
        );
    }

    #[test]
    fn no_encoding_headers_means_uncompressed() {
        assert!(super::pick_response_encoding(&HeaderMap::new(), Some(3)).is_none());
    }

    #[test]
    fn an_unknown_codec_means_uncompressed() {
        for pairs in [
            &[("accept-encoding", "br, deflate")][..],
            &[("x-vgi-accept-encoding", "br")][..],
        ] {
            let h = headers(pairs);
            assert!(
                super::pick_response_encoding(&h, Some(3)).is_none(),
                "unexpected codec chosen for {pairs:?}"
            );
        }
    }

    #[test]
    fn compression_disabled_means_uncompressed_whatever_the_client_offers() {
        // The configuration gate is part of "producible": default-off stays
        // off no matter how the client asks.
        let h = headers(&[
            ("accept-encoding", "zstd"),
            ("x-vgi-accept-encoding", "zstd"),
        ]);
        assert!(!matches!(
            super::pick_response_encoding(&h, None),
            Some((super::ResponseEncoding::Zstd, _))
        ));
    }

    #[test]
    fn standard_header_alone_still_negotiates_on_the_standard_response_header() {
        let h = headers(&[("accept-encoding", "zstd, identity")]);
        let (enc, used_custom) = super::pick_response_encoding(&h, Some(3)).unwrap();
        assert_eq!(enc, super::ResponseEncoding::Zstd);
        assert!(!used_custom);
    }

    #[test]
    fn gzip_only_offer_negotiates_and_round_trips() {
        use std::io::Read;

        let h = headers(&[("accept-encoding", "gzip")]);
        let (enc, used_custom) = super::pick_response_encoding(&h, Some(3)).unwrap();
        assert_eq!(enc, super::ResponseEncoding::Gzip);
        assert!(!used_custom);

        let body = b"gzip-response".repeat(1024);
        let encoded = super::encode_response_body(enc, &body, 3).unwrap();
        assert!(encoded.len() < body.len());
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(encoded.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn q_values_do_not_reorder_the_walk() {
        // `zstd;q=0.5, gzip` — a q-value-honouring parser would prefer gzip.
        // We parse q off and keep the stated order, so zstd stays first.
        let h = headers(&[("x-vgi-accept-encoding", "zstd;q=0.5, gzip")]);
        let (enc, _) = super::pick_response_encoding(&h, Some(3)).unwrap();
        assert_eq!(enc, super::ResponseEncoding::Zstd);
    }

    #[test]
    fn identity_first_wins_and_suppresses_compression() {
        // `identity` is always producible, so reaching it first ends the walk
        // — an explicit, uniform way for a client to turn compression off for
        // one request. Encoding it produces no compressed form, so the caller
        // ships the body as-is and stamps no header.
        for pairs in [
            &[("x-vgi-accept-encoding", "identity")][..],
            &[
                ("x-vgi-accept-encoding", "identity"),
                ("accept-encoding", "gzip, zstd"),
            ][..],
            &[("x-vgi-accept-encoding", "identity, zstd")][..],
            &[("accept-encoding", "identity, gzip")][..],
        ] {
            let h = headers(pairs);
            let (enc, _) = super::pick_response_encoding(&h, Some(3)).unwrap();
            assert_eq!(
                enc,
                super::ResponseEncoding::Identity,
                "identity should win for {pairs:?}"
            );
            assert!(
                super::encode_response_body(enc, &vec![0u8; 4096], 3).is_none(),
                "identity must never produce a compressed body"
            );
        }
    }

    #[test]
    fn identity_after_a_producible_codec_does_not_win() {
        let h = headers(&[("x-vgi-accept-encoding", "zstd, identity")]);
        let (enc, used_custom) = super::pick_response_encoding(&h, Some(3)).unwrap();
        assert_eq!(enc, super::ResponseEncoding::Zstd);
        assert!(used_custom);
        // A producible gzip offer ahead of identity wins.
        let h = headers(&[("x-vgi-accept-encoding", "gzip, identity, zstd")]);
        let (enc, _) = super::pick_response_encoding(&h, Some(3)).unwrap();
        assert_eq!(enc, super::ResponseEncoding::Gzip);
    }

    #[test]
    fn supported_encodings_is_the_both_directions_intersection() {
        assert_eq!(
            super::supported_encodings_header_value(Some(3)),
            "zstd, gzip"
        );
        // Compression off — the default — advertises an empty list, not an
        // absent header. Present-but-empty means "I speak no compression".
        assert_eq!(super::supported_encodings_header_value(None), "");
        // `identity` is never advertised: always available, no information.
        assert!(!super::supported_encodings_header_value(Some(3)).contains("identity"));
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
        let tok = a.pack_cursor_token(&auth, b"s", &TEST_CALL_ID);
        assert_eq!(
            b.unpack_cursor_token(&auth, &tok).unwrap().call_id,
            TEST_CALL_ID
        );
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
