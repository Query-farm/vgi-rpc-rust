//! Storage transfers: presigned PUT/GET with a connect timeout and a stall
//! timeout, never a whole-request deadline.
//!
//! A large object on a slow link can take minutes. A total deadline (the old
//! `reqwest::blocking` 30 s `timeout`) kills such a transfer while it is still
//! making progress, and every retry resends the whole body. Instead:
//!
//! - **connect timeout** ([`DEFAULT_CONNECT_TIMEOUT`], 30 s): TCP + TLS setup;
//! - **stall timeout** ([`DEFAULT_STALL_TIMEOUT`], 30 s, or
//!   [`ENV_STALL_TIMEOUT`]): the request fails only when no bytes move — no
//!   request-body chunk is taken by the connection, no response bytes
//!   arrive — for that long. The request body is fed to the connection in
//!   64 KiB chunks, so the clock restarts on every chunk written, not once
//!   per body;
//! - **retries** ([`RetryPolicy`]: 3 attempts, 0.25 s × 2^(n-1) backoff capped
//!   at 5 s, jitter ×[0.5, 1.0)) on transient failures only: connect errors,
//!   resets, stalls, 429 and 5xx. A transfer that is progressing is never
//!   cut off, so it is never retried.
//!
//! These match vgi-rpc-python's storage client (httpx connect/read/write
//! timeouts of 30 s, which bound each operation, not the request).
//!
//! The transfers run on a small dedicated tokio runtime and the callers block
//! on a channel, so this module is safe to call from any thread that may
//! block (the same contract as `reqwest::blocking`, without its panic when
//! called near a runtime).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;

/// Environment variable overriding [`DEFAULT_STALL_TIMEOUT`], in seconds
/// (a positive number; fractions allowed). The same name in every vgi-rpc SDK.
pub const ENV_STALL_TIMEOUT: &str = "VGI_RPC_STORAGE_STALL_TIMEOUT_SECONDS";
/// TCP + TLS connect timeout for storage requests.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a storage transfer may move no bytes before it fails.
pub const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Size of the request-body chunks handed to the connection; the stall clock
/// restarts on each one.
const CHUNK: usize = 64 * 1024;
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Connect and stall timeouts for storage transfers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferTimeouts {
    /// TCP + TLS connect timeout.
    pub connect: Duration,
    /// Longest period with no bytes moving in either direction.
    pub stall: Duration,
}

impl Default for TransferTimeouts {
    fn default() -> Self {
        TransferTimeouts {
            connect: DEFAULT_CONNECT_TIMEOUT,
            stall: DEFAULT_STALL_TIMEOUT,
        }
    }
}

impl TransferTimeouts {
    /// The defaults, with the stall timeout taken from
    /// [`ENV_STALL_TIMEOUT`] when it is set to a positive number of seconds.
    /// An unparsable value is ignored with a warning.
    pub fn from_env() -> Self {
        Self::from_lookup(&|name| std::env::var(name).ok())
    }

    pub(crate) fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Self {
        let mut t = TransferTimeouts::default();
        if let Some(raw) = lookup(ENV_STALL_TIMEOUT) {
            let raw = raw.trim();
            if !raw.is_empty() {
                match raw.parse::<f64>() {
                    Ok(v) if v.is_finite() && v > 0.0 && v < 1e9 => {
                        t.stall = Duration::from_secs_f64(v);
                    }
                    _ => tracing::warn!(
                        "{ENV_STALL_TIMEOUT}={raw:?} is not a positive number of seconds; using {}s",
                        DEFAULT_STALL_TIMEOUT.as_secs()
                    ),
                }
            }
        }
        t
    }
}

/// Retry policy for storage requests: `max_attempts` in all, exponential
/// backoff from `backoff`, capped at 5 s, jittered ×[0.5, 1.0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts per request, at least 1.
    pub max_attempts: u32,
    /// Delay before the second attempt (doubles each attempt after).
    pub backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            backoff: Duration::from_millis(250),
        }
    }
}

impl RetryPolicy {
    /// Sleep before attempt `attempt` (0-based; no sleep before the first).
    pub(crate) fn pause(&self, attempt: u32) {
        if attempt == 0 {
            return;
        }
        let base = self
            .backoff
            .saturating_mul(1u32 << (attempt - 1).min(16))
            .min(MAX_BACKOFF);
        std::thread::sleep(base.mul_f64(0.5 + rand_unit() / 2.0));
    }

    pub(crate) fn attempts(&self) -> u32 {
        self.max_attempts.max(1)
    }
}

/// A uniform `[0, 1)` value for retry jitter (no RNG dependency needed).
pub(crate) fn rand_unit() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    (h.finish() >> 11) as f64 / (1u64 << 53) as f64
}

/// Why a storage request failed before a response (or mid-body). All three
/// are transient: callers retry them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferError {
    /// TCP or TLS setup failed or timed out.
    Connect,
    /// No bytes moved for the stall timeout.
    Stall,
    /// The connection failed (reset, closed early, protocol error).
    Transport,
}

impl TransferError {
    /// Short label for diagnostics (never contains the URL).
    pub fn label(self) -> &'static str {
        match self {
            TransferError::Connect => "connect error",
            TransferError::Stall => "stalled",
            TransferError::Transport => "transport error",
        }
    }
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vgi-rpc-storage")
            .enable_all()
            .build()
            .expect("vgi-rpc-s3 storage runtime")
    })
}

/// Run `fut` on the storage runtime and block the calling thread until it
/// finishes.
pub(crate) fn block_on<F>(fut: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    runtime().spawn(async move {
        let _ = tx.send(fut.await);
    });
    rx.recv().expect("storage runtime task dropped")
}

/// Run `fut` on the storage runtime and block until it finishes; `Err` when
/// it panicked (e.g. a third-party credential provider), instead of
/// propagating the panic into the caller.
pub(crate) fn try_block_on<F>(fut: F) -> std::result::Result<F::Output, ()>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    runtime().spawn(async move {
        let _ = tx.send(fut.await);
    });
    rx.recv().map_err(|_| ())
}

/// Milliseconds since `origin` of the last observed byte movement; `0` means
/// none yet.
struct Progress {
    origin: Instant,
    last_ms: AtomicU64,
}

impl Progress {
    fn new() -> Arc<Self> {
        Arc::new(Progress {
            origin: Instant::now(),
            last_ms: AtomicU64::new(0),
        })
    }

    fn touch(&self) {
        let ms = self.origin.elapsed().as_millis() as u64;
        self.last_ms.store(ms.max(1), Ordering::Relaxed);
    }

    /// Resolve once no progress has been seen for `stall` (or, before the
    /// first progress, for `connect + stall`).
    async fn stalled(&self, timeouts: TransferTimeouts) {
        // Re-check at least this often, so progress made while asleep moves
        // the deadline (the first wait is connect + stall long).
        let tick = (timeouts.stall / 4).clamp(Duration::from_millis(10), Duration::from_secs(1));
        loop {
            let last = self.last_ms.load(Ordering::Relaxed);
            let deadline = if last == 0 {
                self.origin + timeouts.connect + timeouts.stall
            } else {
                self.origin + Duration::from_millis(last) + timeouts.stall
            };
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline.min(Instant::now() + tick).into()).await;
        }
    }
}

/// A request body of known length, yielded in [`CHUNK`]-sized slices; each
/// slice the connection takes counts as progress.
struct ChunkedBody {
    data: Bytes,
    progress: Arc<Progress>,
}

impl http_body::Body for ChunkedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<http_body::Frame<Bytes>, Self::Error>>> {
        if self.data.is_empty() {
            return Poll::Ready(None);
        }
        // Taking the next chunk means the previous one has been written.
        self.progress.touch();
        let n = self.data.len().min(CHUNK);
        let chunk = self.data.split_to(n);
        Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_empty()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.data.len() as u64)
    }
}

fn classify(e: &reqwest::Error) -> TransferError {
    if e.is_connect() {
        TransferError::Connect
    } else if e.is_timeout() {
        TransferError::Stall
    } else {
        TransferError::Transport
    }
}

/// HTTP client for storage hosts (signed URLs): no redirects, no default
/// headers, connect + stall timeouts, no total deadline.
#[derive(Clone)]
pub struct StorageClient {
    client: reqwest::Client,
    timeouts: TransferTimeouts,
}

impl std::fmt::Debug for StorageClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageClient")
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

impl Default for StorageClient {
    fn default() -> Self {
        Self::new(TransferTimeouts::from_env())
    }
}

impl StorageClient {
    /// A client with these timeouts.
    pub fn new(timeouts: TransferTimeouts) -> Self {
        // No redirects: a presigned PUT or a fetch of an already-validated URL
        // has no legitimate reason to be redirected, and following one could
        // carry a signed URL to a host nobody vetted (SSRF). Callers that
        // allow redirects follow them by hand, validating each hop.
        let client = reqwest::Client::builder()
            .connect_timeout(timeouts.connect)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");
        StorageClient { client, timeouts }
    }

    /// The timeouts this client applies.
    pub fn timeouts(&self) -> TransferTimeouts {
        self.timeouts
    }

    /// Send one request (no retries) and return once the response headers
    /// arrive. The body, if any, is sent with an exact `Content-Length`.
    ///
    /// # Errors
    ///
    /// [`TransferError`] for a connect failure, a stall, or a broken
    /// connection.
    pub fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> std::result::Result<StorageResponse, TransferError> {
        let parsed = reqwest::Url::parse(url).map_err(|_| TransferError::Transport)?;
        self.send_url(method, parsed, headers, body)
    }

    /// [`send`](Self::send) with a parsed URL.
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send).
    pub fn send_url(
        &self,
        method: reqwest::Method,
        url: reqwest::Url,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> std::result::Result<StorageResponse, TransferError> {
        let progress = Progress::new();
        let mut req = self.client.request(method, url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(data) = body {
            req = req.body(reqwest::Body::wrap(ChunkedBody {
                data,
                progress: progress.clone(),
            }));
        }
        let timeouts = self.timeouts;
        let resp = block_on(async move {
            tokio::select! {
                r = req.send() => r.map_err(|e| classify(&e)),
                () = progress.stalled(timeouts) => Err(TransferError::Stall),
            }
        })?;
        Ok(StorageResponse {
            status: resp.status(),
            headers: resp.headers().clone(),
            content_length: resp.content_length(),
            inner: Some(resp),
            pending: Bytes::new(),
            stall: timeouts.stall,
        })
    }
}

/// A storage response whose body is read with the stall timeout applied to
/// each read. Implements [`std::io::Read`]; a stalled read fails with
/// [`std::io::ErrorKind::TimedOut`].
pub struct StorageResponse {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    content_length: Option<u64>,
    inner: Option<reqwest::Response>,
    pending: Bytes,
    stall: Duration,
}

impl StorageResponse {
    /// HTTP status.
    pub fn status(&self) -> reqwest::StatusCode {
        self.status
    }

    /// Response headers.
    pub fn headers(&self) -> &reqwest::header::HeaderMap {
        &self.headers
    }

    /// Declared `Content-Length`, if any.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// The next body chunk, or `None` at the end.
    ///
    /// # Errors
    ///
    /// [`TransferError::Stall`] when no bytes arrive for the stall timeout,
    /// [`TransferError::Transport`] when the connection breaks.
    pub fn chunk(&mut self) -> std::result::Result<Option<Bytes>, TransferError> {
        if !self.pending.is_empty() {
            return Ok(Some(std::mem::take(&mut self.pending)));
        }
        let Some(mut resp) = self.inner.take() else {
            return Ok(None);
        };
        let stall = self.stall;
        let (resp, result) = block_on(async move {
            let r = tokio::time::timeout(stall, resp.chunk()).await;
            (resp, r)
        });
        match result {
            Err(_) => Err(TransferError::Stall),
            Ok(Err(e)) => Err(match classify(&e) {
                TransferError::Connect => TransferError::Transport,
                other => other,
            }),
            Ok(Ok(None)) => Ok(None),
            Ok(Ok(Some(c))) => {
                self.inner = Some(resp);
                Ok(Some(c))
            }
        }
    }

    /// Read the whole body, refusing more than `max` bytes.
    ///
    /// # Errors
    ///
    /// [`ReadError::TooLarge`] past `max`, [`ReadError::Transfer`] on a stall
    /// or a broken connection.
    pub fn read_capped(mut self, max: u64) -> std::result::Result<Vec<u8>, ReadError> {
        let mut out = Vec::new();
        if let Some(n) = self.content_length.filter(|n| *n <= max) {
            out.reserve_exact(n as usize);
        }
        while let Some(c) = self.chunk().map_err(ReadError::Transfer)? {
            if out.len() as u64 + c.len() as u64 > max {
                return Err(ReadError::TooLarge);
            }
            out.extend_from_slice(&c);
        }
        Ok(out)
    }
}

impl std::io::Read for StorageResponse {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pending.is_empty() {
            match self.chunk() {
                Ok(Some(c)) => self.pending = c,
                Ok(None) => return Ok(0),
                Err(TransferError::Stall) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "storage transfer stalled",
                    ))
                }
                Err(e) => return Err(std::io::Error::other(e.label())),
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending.split_to(n));
        Ok(n)
    }
}

/// Why [`StorageResponse::read_capped`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The body is larger than the cap.
    TooLarge,
    /// The transfer stalled or the connection broke (transient).
    Transfer(TransferError),
}

#[cfg(test)]
mod tests {
    //! Throttle tests: local servers that trickle bytes at a fixed slow rate,
    //! or stop moving bytes entirely.
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicUsize;

    fn fast() -> TransferTimeouts {
        TransferTimeouts {
            connect: Duration::from_secs(5),
            stall: Duration::from_secs(1),
        }
    }

    /// Read a request head; returns (head, any body bytes already read).
    fn read_head(s: &mut TcpStream) -> (String, Vec<u8>) {
        let mut got = Vec::new();
        loop {
            if let Some(p) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..p]).to_string();
                return (head, got[p + 4..].to_vec());
            }
            let mut b = [0u8; 4096];
            let n = s.read(&mut b).unwrap();
            assert_ne!(n, 0, "closed before head");
            got.extend_from_slice(&b[..n]);
        }
    }

    fn content_length(head: &str) -> usize {
        head.lines()
            .find_map(|l| {
                l.split_once(':').and_then(|(k, v)| {
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().unwrap())
                })
            })
            .unwrap_or(0)
    }

    /// A server that accepts connections, counting them, and runs `handler`
    /// on each in its own thread.
    fn serve(handler: impl Fn(TcpStream) + Send + Sync + 'static) -> (String, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let handler = Arc::new(handler);
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { return };
                c.fetch_add(1, Ordering::SeqCst);
                let h = handler.clone();
                std::thread::spawn(move || h(s));
            }
        });
        (format!("http://{addr}"), count)
    }

    #[test]
    fn env_stall_timeout() {
        let t = TransferTimeouts::from_lookup(&|_| Some(" 2.5 ".into()));
        assert_eq!(t.stall, Duration::from_millis(2500));
        assert_eq!(t.connect, DEFAULT_CONNECT_TIMEOUT);
        for bad in ["0", "-1", "abc", "nan", "inf"] {
            let t = TransferTimeouts::from_lookup(&|_| Some(bad.into()));
            assert_eq!(t.stall, DEFAULT_STALL_TIMEOUT, "{bad}");
        }
        assert_eq!(
            TransferTimeouts::from_lookup(&|_| None),
            TransferTimeouts::default()
        );
    }

    /// A 3 s download at 256 KiB/s with a 1 s stall timeout succeeds.
    #[test]
    fn slow_download_longer_than_stall_succeeds() {
        const TOTAL: usize = 768 * 1024;
        let (base, count) = serve(|mut s| {
            read_head(&mut s);
            write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {TOTAL}\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let chunk = vec![7u8; 16 * 1024];
            for _ in 0..TOTAL / chunk.len() {
                s.write_all(&chunk).unwrap();
                std::thread::sleep(Duration::from_millis(62));
            }
        });
        let client = StorageClient::new(fast());
        let start = Instant::now();
        let resp = client
            .send(reqwest::Method::GET, &format!("{base}/obj"), &[], None)
            .unwrap();
        let body = resp.read_capped(u64::MAX).unwrap();
        let took = start.elapsed();
        assert_eq!(body.len(), TOTAL);
        assert!(took > Duration::from_millis(2500), "took {took:?}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// A 32 MiB upload the server reads at ~3 MiB/s (about 10 s) with a 4 s
    /// stall timeout succeeds in one attempt. (The stall timeout must exceed
    /// the time the last chunk spends in socket buffers — up to ~10 MiB on
    /// loopback — before the server reads it; with the 30 s default that
    /// only matters below ~300 KiB/s on a loopback-sized buffer.)
    #[test]
    fn slow_upload_longer_than_stall_succeeds() {
        const TOTAL: usize = 32 * 1024 * 1024;
        let (base, count) = serve(|mut s| {
            let (head, already) = read_head(&mut s);
            let want = content_length(&head);
            assert_eq!(want, TOTAL);
            let mut got = already.len();
            let mut b = vec![0u8; 16 * 1024];
            while got < want {
                let n = s.read(&mut b).unwrap();
                assert_ne!(n, 0);
                got += n;
                std::thread::sleep(Duration::from_millis(5));
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let client = StorageClient::new(TransferTimeouts {
            connect: Duration::from_secs(5),
            stall: Duration::from_secs(4),
        });
        let start = Instant::now();
        let resp = client
            .send(
                reqwest::Method::PUT,
                &format!("{base}/obj"),
                &[],
                Some(Bytes::from(vec![1u8; TOTAL])),
            )
            .unwrap();
        assert_eq!(resp.status(), 200);
        let took = start.elapsed();
        assert!(took > Duration::from_secs(5), "took {took:?}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// A server that sends half the body and then goes silent fails the read
    /// within the stall timeout plus slack.
    #[test]
    fn stalled_download_fails_within_stall_timeout() {
        let (base, _) = serve(|mut s| {
            read_head(&mut s);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
                .unwrap();
            s.write_all(&[0u8; 1000]).unwrap();
            std::thread::sleep(Duration::from_secs(30));
        });
        let client = StorageClient::new(fast());
        let resp = client
            .send(reqwest::Method::GET, &format!("{base}/obj"), &[], None)
            .unwrap();
        let start = Instant::now();
        let err = resp.read_capped(u64::MAX).unwrap_err();
        let took = start.elapsed();
        assert_eq!(err, ReadError::Transfer(TransferError::Stall));
        assert!(took < Duration::from_secs(3), "took {took:?}");
    }

    /// A server that never answers fails within connect-free stall bounds.
    #[test]
    fn silent_server_fails_with_stall() {
        let (base, _) = serve(|mut s| {
            read_head(&mut s);
            std::thread::sleep(Duration::from_secs(30));
        });
        let t = TransferTimeouts {
            connect: Duration::from_millis(500),
            stall: Duration::from_secs(1),
        };
        let start = Instant::now();
        let err = StorageClient::new(t)
            .send(reqwest::Method::GET, &format!("{base}/obj"), &[], None)
            .err()
            .unwrap();
        let took = start.elapsed();
        assert_eq!(err, TransferError::Stall);
        assert!(took < Duration::from_secs(3), "took {took:?}");
    }

    /// A server that stops reading the request body fails the upload within
    /// the stall timeout plus slack (once the socket buffers fill).
    #[test]
    fn stalled_upload_fails_within_stall_timeout() {
        let (base, _) = serve(|mut s| {
            read_head(&mut s);
            std::thread::sleep(Duration::from_secs(60));
        });
        let client = StorageClient::new(fast());
        let start = Instant::now();
        let err = client
            .send(
                reqwest::Method::PUT,
                &format!("{base}/obj"),
                &[],
                Some(Bytes::from(vec![1u8; 64 * 1024 * 1024])),
            )
            .err()
            .unwrap();
        let took = start.elapsed();
        assert_eq!(err, TransferError::Stall);
        assert!(took < Duration::from_secs(4), "took {took:?}");
    }
}
