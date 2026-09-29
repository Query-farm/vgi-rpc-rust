//! Caller-supplied synchronous HTTP executor for [`HttpClient`](crate::HttpClient).
//!
//! The HTTP client's protocol logic (capability discovery, codec
//! negotiation, sticky sessions, request externalization, external-location
//! resolution) is independent of how bytes reach the server. By default it
//! uses a blocking reqwest client (`reqwest` feature). An embedder that owns
//! its own HTTP stack — for example a DuckDB-WASM host whose only egress is
//! a synchronous browser `XMLHttpRequest` — implements [`HttpExecutor`] and
//! hands it to [`HttpClientBuilder::executor`](crate::HttpClientBuilder::executor).
//! Building with an executor needs only the `http` feature, so the crate
//! compiles for targets reqwest does not support.
//!
//! Every request the client issues goes through the executor: RPC calls,
//! capability discovery, session teardown, `PUT`s to server-vended upload
//! URLs, and `GET`s that resolve external-location pointers. Nothing on the
//! executor path spawns threads; connection-level retries (opt-in via
//! [`HttpClientBuilder::retry`](crate::HttpClientBuilder::retry)) sleep on the
//! calling thread.

use std::time::Duration;

/// One outgoing request handed to an [`HttpExecutor`].
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    /// Upper-case HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`).
    pub method: &'a str,
    /// Absolute URL.
    pub url: &'a str,
    /// Request headers in send order. Names may repeat.
    pub headers: &'a [(String, String)],
    /// Request body (empty for body-less methods).
    pub body: &'a [u8],
    /// Whole-request timeout. [`Duration::ZERO`] means the client configured
    /// no timeout.
    pub timeout: Duration,
    /// Whether the executor may follow 3xx redirects itself. `false` for
    /// external-location fetches, which validate every redirect target
    /// against the configured URL policy before following it; an executor
    /// that cannot disable redirect following should reject such requests
    /// rather than silently follow.
    pub follow_redirects: bool,
}

/// A complete response returned by an [`HttpExecutor`].
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers. Repeated names must be preserved as separate
    /// entries, in order: the client rejects duplicated capability headers.
    pub headers: Vec<(String, String)>,
    /// Response body. When [`ExecutorCaps::transparent_decompression`] is
    /// set this is the body *after* any transport-level `Content-Encoding`
    /// decoding; otherwise it is the raw body as sent on the wire.
    pub body: Vec<u8>,
}

/// Failure to obtain a response (connection, DNS, timeout, abort...). An HTTP
/// error status is *not* an `HttpExecError`; return it as an [`HttpResponse`].
#[derive(Debug, Clone)]
pub struct HttpExecError {
    pub message: String,
    /// `true` when the request certainly did not reach the server, so an
    /// opt-in retry cannot duplicate side effects. Only consulted for
    /// requests the client already considers retryable.
    pub retry_safe: bool,
}

impl std::fmt::Display for HttpExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HttpExecError {}

/// What the executor's transport can and cannot do. Drives protocol choices
/// in [`HttpClient`](crate::HttpClient).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutorCaps {
    /// The transport can issue `OPTIONS`. When `false`, capability discovery
    /// uses `GET {prefix}/health` instead of `OPTIONS {prefix}/health`; the
    /// server stamps the same capability headers on both.
    pub supports_options: bool,
    /// The transport decodes standard `Content-Encoding` itself and may
    /// forbid setting `Accept-Encoding` (browsers). When `true` the client
    /// never sends `Accept-Encoding`, negotiates with
    /// `X-VGI-Accept-Encoding: zstd, gzip` instead, decodes a response body
    /// only when the server answers with `X-VGI-Content-Encoding`, treats a
    /// standard `Content-Encoding` as already decoded, and ignores
    /// `Content-Length` (which then describes the encoded body).
    pub transparent_decompression: bool,
}

/// A synchronous HTTP transport.
///
/// Implementations must return the full response (status, headers with
/// duplicates preserved, body) or an [`HttpExecError`]. The client bounds
/// response sizes after the fact, so an executor that can enforce its own
/// ceiling should do so.
pub trait HttpExecutor: Send + Sync {
    fn execute(&self, req: HttpRequest<'_>) -> Result<HttpResponse, HttpExecError>;

    /// Transport capabilities. Defaults to a plain native HTTP stack:
    /// `OPTIONS` supported, no transparent decompression.
    fn caps(&self) -> ExecutorCaps {
        ExecutorCaps {
            supports_options: true,
            transparent_decompression: false,
        }
    }
}
