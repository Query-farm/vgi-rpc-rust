//! Byte-stream transports for the blocking client.
//!
//! A [`Transport`] is the pipe/subprocess/unix family: a paired reader +
//! writer over which complete Arrow IPC streams flow sequentially. HTTP is
//! *not* a `Transport` (it is request/response) — see [`crate::http`].
//!
//! The [`Transport::split`] method hands out the reader and writer as
//! *disjoint* mutable borrows so a [`crate::StreamSession`] can hold an input
//! writer and an output reader simultaneously without upsetting the borrow
//! checker.

use std::io::{BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vgi_rpc::errors::{Result, RpcError};

/// A bidirectional byte-stream transport: schema-framed Arrow IPC streams
/// flow over `reader`/`writer` sequentially.
pub trait Transport: Send {
    /// Borrow the read half and write half as disjoint mutable references.
    fn split(&mut self) -> (&mut dyn Read, &mut dyn Write);

    /// Return this transport's per-RPC deadline controller, when supported.
    #[doc(hidden)]
    fn rpc_deadline(&self) -> Option<RpcDeadline> {
        None
    }

    /// Whether framing is safe for another RPC.
    fn is_reusable(&self) -> bool {
        true
    }

    /// Shut the transport down (flush + signal EOF + reap any child).
    fn close(&mut self) -> Result<()>;
}

/// How to handle a spawned worker's stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StderrMode {
    /// Inherit the parent's stderr (the default — surfaces worker logs).
    #[default]
    Inherit,
    /// Discard the worker's stderr.
    Null,
}

impl StderrMode {
    fn to_stdio(self) -> Stdio {
        match self {
            StderrMode::Inherit => Stdio::inherit(),
            StderrMode::Null => Stdio::null(),
        }
    }
}

/// A worker spawned as a child process; the RPC wire is its stdin/stdout.
pub struct SubprocessTransport {
    stdin: Option<ChildStdin>,
    stdout: SubprocessReader,
    io: Arc<SubprocessIo>,
    deadline: Option<RpcDeadline>,
}

/// Shared monotonic deadline for one subprocess RPC at a time.
#[derive(Clone)]
pub struct RpcDeadline {
    timeout: Duration,
    deadline: Arc<Mutex<Option<Instant>>>,
    io: Option<Arc<SubprocessIo>>,
}

impl RpcDeadline {
    /// Create a monotonic per-RPC deadline controller for an external
    /// transport. [`RpcClient`](crate::RpcClient) starts and clears it around
    /// every complete unary or streaming turn.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            deadline: Arc::new(Mutex::new(None)),
            io: None,
        }
    }

    /// Remaining time in the active RPC budget, or `None` between calls.
    pub fn remaining(&self) -> Option<Duration> {
        (*self.deadline.lock().unwrap())
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    pub(crate) fn start(&self) -> Result<()> {
        if self
            .io
            .as_ref()
            .is_some_and(|io| io.poisoned.load(Ordering::Acquire))
        {
            return Err(RpcError::new(
                "TransportError",
                "subprocess transport is poisoned after an RPC timeout",
            ));
        }
        let expires = Instant::now().checked_add(self.timeout).ok_or_else(|| {
            RpcError::new("TransportError", "subprocess RPC timeout exceeds Instant")
        })?;
        *self.deadline.lock().unwrap() = Some(expires);
        Ok(())
    }

    pub(crate) fn finish(&self) {
        *self.deadline.lock().unwrap() = None;
    }
}

struct SubprocessIo {
    child: Mutex<Child>,
    process_group: u32,
    reader_thread: Mutex<Option<JoinHandle<()>>>,
    poisoned: AtomicBool,
    stopping: Arc<AtomicBool>,
    closed: AtomicBool,
}

impl SubprocessIo {
    fn terminate_timeout(&self) {
        self.poisoned.store(true, Ordering::Release);
        self.stopping.store(true, Ordering::Release);
        if self.closed.swap(true, Ordering::AcqRel) {
            self.join_reader();
            return;
        }
        let mut child = self.child.lock().unwrap();
        kill_subprocess_tree(&mut child, self.process_group);
        let _ = child.wait();
        drop(child);
        self.join_reader();
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            self.join_reader();
            return;
        }
        let deadline = Instant::now() + CLOSE_GRACE;
        let mut child = self.child.lock().unwrap();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(CLOSE_POLL),
                _ => break,
            }
        }
        // Even when the group leader exited cooperatively, a wrapper may have
        // left descendants holding stdout open. End the still-owned process
        // group before joining the reader or that join can wait forever.
        kill_subprocess_tree(&mut child, self.process_group);
        let _ = child.wait();
        drop(child);
        self.stopping.store(true, Ordering::Release);
        self.join_reader();
    }

    fn join_reader(&self) {
        if let Some(thread) = self.reader_thread.lock().unwrap().take() {
            #[cfg(unix)]
            {
                // The child owns a private process group, so terminating that
                // group closes every inherited stdout handle. A full join is
                // therefore safe and proves the reader has released the pipe.
                let _ = thread.join();
            }
            #[cfg(not(unix))]
            {
                // `std::process` can terminate only the wrapper on these
                // platforms. A descendant may retain the inherited stdout
                // handle, so never let its missing EOF strand close/timeout.
                // Dropping an unfinished JoinHandle detaches only this reader;
                // it owns no client state and exits when the handle closes.
                let _ = join_reader_bounded(thread, READER_JOIN_GRACE);
            }
        }
    }
}

#[cfg(any(not(unix), test))]
fn join_reader_bounded(thread: JoinHandle<()>, grace: Duration) -> bool {
    let deadline = Instant::now().checked_add(grace);
    while !thread.is_finished() && deadline.is_some_and(|deadline| Instant::now() < deadline) {
        std::thread::sleep(CLOSE_POLL);
    }
    if thread.is_finished() {
        let _ = thread.join();
        true
    } else {
        // Dropping a JoinHandle detaches the thread. This is the only bounded
        // option when the platform cannot close stdout handles inherited by a
        // process outside the wrapper's lifetime.
        false
    }
}

enum ReaderMessage {
    Data(Vec<u8>),
    Eof,
    Error(std::io::Error),
}

struct SubprocessReader {
    receiver: mpsc::Receiver<ReaderMessage>,
    buffered: Vec<u8>,
    offset: usize,
    deadline: Arc<Mutex<Option<Instant>>>,
    io: Arc<SubprocessIo>,
}

impl Read for SubprocessReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset < self.buffered.len() {
            let count = output.len().min(self.buffered.len() - self.offset);
            output[..count].copy_from_slice(&self.buffered[self.offset..self.offset + count]);
            self.offset += count;
            return Ok(count);
        }
        self.buffered.clear();
        self.offset = 0;

        let deadline = *self.deadline.lock().unwrap();
        let message = match deadline {
            Some(deadline) => {
                if Instant::now() >= deadline {
                    self.io.terminate_timeout();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "subprocess RPC deadline elapsed; worker terminated",
                    ));
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                match self.receiver.recv_timeout(remaining) {
                    Ok(message) => message,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        self.io.terminate_timeout();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "subprocess RPC deadline elapsed; worker terminated",
                        ));
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => ReaderMessage::Eof,
                }
            }
            None => self.receiver.recv().unwrap_or(ReaderMessage::Eof),
        };
        match message {
            ReaderMessage::Data(bytes) => {
                self.buffered = bytes;
                self.read(output)
            }
            ReaderMessage::Eof => Ok(0),
            ReaderMessage::Error(error) => Err(error),
        }
    }
}

impl SubprocessTransport {
    /// Spawn `cmd[0]` with `cmd[1..]` as arguments, piping stdin/stdout.
    pub fn spawn(cmd: &[impl AsRef<std::ffi::OsStr>]) -> Result<Self> {
        Self::spawn_with_stderr_and_timeout(cmd, StderrMode::default(), None)
    }

    /// Spawn with an explicit stderr disposition.
    pub fn spawn_with_stderr(
        cmd: &[impl AsRef<std::ffi::OsStr>],
        stderr: StderrMode,
    ) -> Result<Self> {
        Self::spawn_with_stderr_and_timeout(cmd, stderr, None)
    }

    /// Spawn with explicit stderr handling and a monotonic per-RPC timeout.
    ///
    /// The deadline bounds response reads and kills the child on expiry. On
    /// Unix, the child runs in a private process group which is terminated in
    /// full before its reader is joined. Other platforms can terminate only
    /// the direct child through `std::process`; reader shutdown waits for a
    /// short bounded grace and then detaches if a descendant retained stdout.
    /// Rust anonymous pipes cannot interrupt a thread blocked writing a very
    /// large request to a worker that never reads stdin; callers should keep
    /// pipe request batches bounded or use a socket/HTTP transport for hostile
    /// peers.
    pub fn spawn_with_stderr_and_timeout(
        cmd: &[impl AsRef<std::ffi::OsStr>],
        stderr: StderrMode,
        rpc_timeout: Option<Duration>,
    ) -> Result<Self> {
        let (program, args) = cmd
            .split_first()
            .ok_or_else(|| RpcError::value_error("empty command for SubprocessTransport"))?;
        let mut command = Command::new(program);
        command
            .args(args.iter().map(|a| a.as_ref()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr.to_stdio());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|e| RpcError::new("TransportError", format!("spawn worker: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| RpcError::new("TransportError", "child stdin not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RpcError::new("TransportError", "child stdout not piped"))?;
        let deadline = Arc::new(Mutex::new(None));
        let (sender, receiver) = mpsc::sync_channel(8);
        let stopping = Arc::new(AtomicBool::new(false));
        let reader_stopping = Arc::clone(&stopping);
        let reader_thread = std::thread::Builder::new()
            .name("vgi-subprocess-reader".into())
            .spawn(move || read_subprocess_stdout(stdout, sender, reader_stopping))
            .map_err(|error| {
                let process_group = child.id();
                kill_subprocess_tree(&mut child, process_group);
                let _ = child.wait();
                RpcError::new(
                    "TransportError",
                    format!("spawn subprocess reader: {error}"),
                )
            })?;
        let process_group = child.id();
        let io = Arc::new(SubprocessIo {
            child: Mutex::new(child),
            process_group,
            reader_thread: Mutex::new(Some(reader_thread)),
            poisoned: AtomicBool::new(false),
            stopping,
            closed: AtomicBool::new(false),
        });
        let deadline_control = rpc_timeout.map(|timeout| RpcDeadline {
            timeout,
            deadline: Arc::clone(&deadline),
            io: Some(Arc::clone(&io)),
        });
        Ok(Self {
            stdin: Some(stdin),
            stdout: SubprocessReader {
                receiver,
                buffered: Vec::new(),
                offset: 0,
                deadline,
                io: Arc::clone(&io),
            },
            io,
            deadline: deadline_control,
        })
    }
}

fn kill_subprocess_tree(child: &mut Child, _process_group: u32) {
    #[cfg(unix)]
    {
        // The child was placed in its own process group before exec. Kill the
        // group so wrappers cannot leave a descendant holding stdout open and
        // strand the reader thread during timeout recovery.
        let pgid = i32::try_from(_process_group).unwrap_or(i32::MAX);
        // SAFETY: `kill` accepts any process-group id. A negative id targets
        // only the group created for this still-owned child.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

fn read_subprocess_stdout(
    mut stdout: ChildStdout,
    sender: mpsc::SyncSender<ReaderMessage>,
    stopping: Arc<AtomicBool>,
) {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) => {
                let _ = send_reader_message(&sender, ReaderMessage::Eof, &stopping);
                return;
            }
            Ok(count) => {
                if !send_reader_message(
                    &sender,
                    ReaderMessage::Data(buffer[..count].to_vec()),
                    &stopping,
                ) {
                    return;
                }
            }
            Err(error) => {
                let _ = send_reader_message(&sender, ReaderMessage::Error(error), &stopping);
                return;
            }
        }
    }
}

fn send_reader_message(
    sender: &mpsc::SyncSender<ReaderMessage>,
    mut message: ReaderMessage,
    stopping: &AtomicBool,
) -> bool {
    loop {
        match sender.try_send(message) {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
            Err(mpsc::TrySendError::Full(returned)) => {
                if stopping.load(Ordering::Acquire) {
                    return false;
                }
                message = returned;
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// How long [`SubprocessTransport::close`] lets a worker exit on its own before
/// killing it.
///
/// Generous enough that a worker finishing a flush is never killed for it,
/// short enough that a wedged one cannot stall a caller.
const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Poll interval while waiting out [`CLOSE_GRACE`].
const CLOSE_POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// Maximum non-Unix wait for a subprocess reader after the direct child exits.
///
/// Unix closes inherited pipe handles by terminating the private process group
/// and therefore joins without this fallback.
#[cfg(any(not(unix), test))]
const READER_JOIN_GRACE: std::time::Duration = std::time::Duration::from_millis(250);

impl Transport for SubprocessTransport {
    fn split(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        // `stdin` is always `Some` between `spawn` and `close`.
        let writer = self.stdin.as_mut().expect("transport already closed");
        (&mut self.stdout, writer)
    }

    fn rpc_deadline(&self) -> Option<RpcDeadline> {
        self.deadline.clone()
    }

    fn is_reusable(&self) -> bool {
        !self.io.poisoned.load(Ordering::Acquire)
    }

    fn close(&mut self) -> Result<()> {
        // Drop stdin to send EOF, then reap the child — but never wait for it
        // unboundedly.
        //
        // EOF is a *request* to exit, and a worker that cannot read is under no
        // obligation to notice it. The case that bites is a scan abandoned
        // mid-stream: the worker is blocked writing into a stdout pipe nobody
        // drains any more, so it never reaches its read, never sees the EOF,
        // and `wait()` blocks forever. Both sides are then stuck — a deadlock
        // that presents as a process pinned at 0% CPU with a live child, which
        // is exactly how it was found (a test harness stalling partway through
        // a long run, at a position that moved between runs).
        //
        // So: give it a short grace period to exit on its own, then kill it.
        // A cooperative worker pays a couple of polls; a wedged one costs
        // `CLOSE_GRACE` and dies.
        drop(self.stdin.take());

        self.io.close();
        Ok(())
    }
}

impl Drop for SubprocessTransport {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod reader_join_tests {
    use super::*;

    #[test]
    fn bounded_reader_join_detaches_instead_of_waiting_for_eof() {
        let (release_sender, release_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            release_receiver.recv().unwrap();
            finished_sender.send(()).unwrap();
        });

        let started = Instant::now();
        assert!(!join_reader_bounded(reader, Duration::from_millis(25)));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "bounded reader join blocked instead of detaching"
        );

        release_sender.send(()).unwrap();
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("detached reader can finish after its handle is released");
    }

    #[test]
    fn bounded_reader_join_reaps_a_finished_reader() {
        let reader = std::thread::spawn(|| {});
        assert!(join_reader_bounded(reader, READER_JOIN_GRACE));
    }
}

#[cfg(all(test, unix))]
mod subprocess_tests {
    use super::*;

    #[test]
    fn deadline_transport_preserves_multiple_pipe_turns() {
        let mut transport = SubprocessTransport::spawn_with_stderr_and_timeout(
            &["sh", "-c", "exec cat"],
            StderrMode::Null,
            Some(Duration::from_secs(2)),
        )
        .unwrap();
        let deadline = transport.rpc_deadline().unwrap();
        for message in [b"first".as_slice(), b"second".as_slice()] {
            deadline.start().unwrap();
            let (reader, writer) = transport.split();
            writer.write_all(message).unwrap();
            writer.flush().unwrap();
            let mut echoed = vec![0; message.len()];
            reader.read_exact(&mut echoed).unwrap();
            deadline.finish();
            assert_eq!(echoed, message);
        }
    }

    #[test]
    fn timeout_joins_a_reader_even_when_its_channel_is_full() {
        let mut transport = SubprocessTransport::spawn_with_stderr_and_timeout(
            &["sh", "-c", "exec yes flood"],
            StderrMode::Null,
            Some(Duration::from_millis(25)),
        )
        .unwrap();
        let deadline = transport.rpc_deadline().unwrap();
        deadline.start().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let (reader, _) = transport.split();
        let error = reader.read(&mut [0_u8; 1]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(!transport.is_reusable());
        transport.close().unwrap();
    }
}

/// A transport over an in-memory or caller-supplied reader/writer pair.
///
/// Used for socketpair-style tests and for wrapping an already-connected
/// stream.
pub struct PipeTransport {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

impl PipeTransport {
    pub fn new(reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>) -> Self {
        Self { reader, writer }
    }
}

impl Transport for PipeTransport {
    fn split(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        (&mut *self.reader, &mut *self.writer)
    }

    fn close(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

/// A transport over a connected AF_INET (TCP) socket — the network analog of
/// [`UnixTransport`].
///
/// Speaks the same raw Arrow-IPC framing protocol over a bare TCP socket.
/// Nagle's algorithm is disabled (`TCP_NODELAY`) so the lockstep
/// request/response framing is not delayed waiting to coalesce writes.
///
/// Raw TCP carries **no authentication and no TLS** — connect only to workers
/// on a trusted network. Use the HTTP transport for untrusted peers.
pub struct TcpTransport {
    reader: BufReader<std::net::TcpStream>,
    writer: std::net::TcpStream,
}

/// A strict SOCKS5h proxy endpoint used to reach a TCP worker.
///
/// The proxy itself must be an IP literal, which keeps proxy connection setup
/// inside the single monotonic deadline without invoking an unbounded local
/// DNS resolver. Worker domain names are IDNA-normalized and always sent to
/// the proxy as SOCKS domain names; they are never resolved locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socks5hProxy {
    address: std::net::SocketAddr,
}

impl Socks5hProxy {
    /// Parse `socks5h://IP:port`. Credentials, paths, query strings, and
    /// fragments are deliberately unsupported.
    pub fn parse(value: &str) -> Result<Self> {
        let parsed = url::Url::parse(value)
            .map_err(|_| RpcError::value_error("invalid SOCKS5h proxy URI"))?;
        if parsed.scheme() != "socks5h"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(RpcError::value_error(
                "SOCKS5h proxy must be socks5h://IP:port without credentials or options",
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| RpcError::value_error("SOCKS5h proxy host is required"))?;
        let ip = host
            .parse::<std::net::IpAddr>()
            .map_err(|_| RpcError::value_error("SOCKS5h proxy host must be an IP literal"))?;
        let port = parsed
            .port()
            .ok_or_else(|| RpcError::value_error("SOCKS5h proxy port is required"))?;
        Ok(Self {
            address: std::net::SocketAddr::new(ip, port),
        })
    }

    /// Return the proxy socket address.
    pub fn address(self) -> std::net::SocketAddr {
        self.address
    }
}

impl TcpTransport {
    /// Connect to a worker listening on a TCP socket at `host:port`.
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        Self::connect_with_timeout(host, port, None)
    }

    /// Connect with an optional per-read timeout. A read that exceeds the
    /// timeout surfaces as a `TransportError` (`WouldBlock`/`TimedOut`),
    /// cleanly ending the call rather than hanging the thread on a stalled
    /// peer. Recommended for untrusted TCP peers.
    pub fn connect_with_timeout(
        host: &str,
        port: u16,
        read_timeout: Option<std::time::Duration>,
    ) -> Result<Self> {
        let stream = std::net::TcpStream::connect((host, port))
            .map_err(|e| RpcError::new("TransportError", format!("connect tcp socket: {e}")))?;
        // Disable Nagle so lockstep framing isn't delayed.
        stream.set_nodelay(true).ok();
        if let Some(t) = read_timeout {
            stream.set_read_timeout(Some(t)).map_err(|e| {
                RpcError::new("TransportError", format!("set tcp read timeout: {e}"))
            })?;
        }
        let writer = stream
            .try_clone()
            .map_err(|e| RpcError::new("TransportError", format!("clone tcp socket: {e}")))?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
        })
    }

    /// Connect through a SOCKS5h proxy with one deadline covering the proxy
    /// TCP connection, method negotiation, and the proxy's target connection.
    ///
    /// Only SOCKS `NO AUTH` is offered. Failure never falls back to a direct
    /// connection. `host` is encoded as a domain name for proxy-side DNS, or
    /// as an address literal when it is already IPv4/IPv6.
    pub fn connect_socks5h(
        proxy: Socks5hProxy,
        host: &str,
        port: u16,
        connect_timeout: Duration,
        read_timeout: Option<Duration>,
    ) -> Result<Self> {
        if connect_timeout.is_zero() {
            return Err(RpcError::value_error(
                "SOCKS5h connect timeout must be positive",
            ));
        }
        let deadline = Instant::now()
            .checked_add(connect_timeout)
            .ok_or_else(|| RpcError::value_error("SOCKS5h connect timeout exceeds Instant"))?;
        let mut stream =
            std::net::TcpStream::connect_timeout(&proxy.address(), socks_remaining(deadline)?)
                .map_err(|error| {
                    RpcError::new("TransportError", format!("connect SOCKS5h proxy: {error}"))
                })?;
        stream.set_nodelay(true).map_err(|error| {
            RpcError::new(
                "TransportError",
                format!("configure SOCKS5h socket: {error}"),
            )
        })?;

        socks_write_all(&mut stream, &[5, 1, 0], deadline)?;
        let mut method = [0_u8; 2];
        socks_read_exact(&mut stream, &mut method, deadline)?;
        if method != [5, 0] {
            return Err(RpcError::new(
                "TransportError",
                "SOCKS5h proxy rejected the NO AUTH method",
            ));
        }

        let mut request = vec![5, 1, 0];
        match url::Host::parse(host)
            .map_err(|_| RpcError::value_error("invalid SOCKS5h target host"))?
        {
            url::Host::Ipv4(address) => {
                request.push(1);
                request.extend_from_slice(&address.octets());
            }
            url::Host::Ipv6(address) => {
                request.push(4);
                request.extend_from_slice(&address.octets());
            }
            url::Host::Domain(domain) => {
                let bytes = domain.as_bytes();
                if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                    return Err(RpcError::value_error(
                        "SOCKS5h target domain must contain 1..255 IDNA bytes",
                    ));
                }
                request.push(3);
                request.push(bytes.len() as u8);
                request.extend_from_slice(bytes);
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        socks_write_all(&mut stream, &request, deadline)?;

        let mut response = [0_u8; 4];
        socks_read_exact(&mut stream, &mut response, deadline)?;
        if response[0] != 5 || response[2] != 0 {
            return Err(RpcError::new(
                "TransportError",
                "malformed SOCKS5h connect response",
            ));
        }
        if response[1] != 0 {
            return Err(RpcError::new(
                "TransportError",
                format!(
                    "SOCKS5h proxy rejected target connection (reply {})",
                    response[1]
                ),
            ));
        }
        let address_bytes = match response[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut length = [0_u8; 1];
                socks_read_exact(&mut stream, &mut length, deadline)?;
                usize::from(length[0])
            }
            _ => {
                return Err(RpcError::new(
                    "TransportError",
                    "SOCKS5h response used an invalid address type",
                ))
            }
        };
        let mut bound = vec![0_u8; address_bytes + 2];
        socks_read_exact(&mut stream, &mut bound, deadline)?;

        stream.set_write_timeout(None).map_err(|error| {
            RpcError::new(
                "TransportError",
                format!("clear SOCKS5h write deadline: {error}"),
            )
        })?;
        stream.set_read_timeout(read_timeout).map_err(|error| {
            RpcError::new("TransportError", format!("set tcp read timeout: {error}"))
        })?;
        let writer = stream.try_clone().map_err(|error| {
            RpcError::new("TransportError", format!("clone tcp socket: {error}"))
        })?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
        })
    }
}

fn socks_remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| RpcError::new("TransportError", "SOCKS5h connection deadline elapsed"))
}

fn socks_write_all(
    stream: &mut std::net::TcpStream,
    value: &[u8],
    deadline: Instant,
) -> Result<()> {
    stream
        .set_write_timeout(Some(socks_remaining(deadline)?))
        .and_then(|_| stream.write_all(value))
        .map_err(|error| {
            RpcError::new(
                "TransportError",
                format!("write SOCKS5h handshake: {error}"),
            )
        })
}

fn socks_read_exact(
    stream: &mut std::net::TcpStream,
    value: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    stream
        .set_read_timeout(Some(socks_remaining(deadline)?))
        .and_then(|_| stream.read_exact(value))
        .map_err(|error| {
            RpcError::new("TransportError", format!("read SOCKS5h handshake: {error}"))
        })
}

#[cfg(test)]
mod socks5h_tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn proxy_uri_rejects_credentials_options_and_local_dns() {
        for value in [
            "socks5://127.0.0.1:1080",
            "socks5h://user@127.0.0.1:1080",
            "socks5h://127.0.0.1:1080/path",
            "socks5h://127.0.0.1:1080/?x=1",
            "socks5h://localhost:1080",
            "socks5h://127.0.0.1",
        ] {
            assert!(Socks5hProxy::parse(value).is_err(), "accepted {value}");
        }
        assert_eq!(
            Socks5hProxy::parse("socks5h://127.0.0.1:1080")
                .unwrap()
                .address(),
            "127.0.0.1:1080".parse().unwrap()
        );
    }

    #[test]
    fn domain_is_idna_encoded_and_resolved_only_by_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = Socks5hProxy {
            address: listener.local_addr().unwrap(),
        };
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut greeting = [0_u8; 3];
            connection.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            for byte in [5_u8, 0] {
                connection.write_all(&[byte]).unwrap();
            }

            let mut prefix = [0_u8; 5];
            connection.read_exact(&mut prefix).unwrap();
            assert_eq!(&prefix[..4], &[5, 1, 0, 3]);
            let mut target = vec![0_u8; usize::from(prefix[4]) + 2];
            connection.read_exact(&mut target).unwrap();
            assert_eq!(&target[..target.len() - 2], b"xn--bcher-kva.example");
            assert_eq!(&target[target.len() - 2..], &9400_u16.to_be_bytes());

            for chunk in [&[5_u8, 0][..], &[0, 1, 127][..], &[0, 0, 1, 0, 0][..]] {
                connection.write_all(chunk).unwrap();
            }
        });

        let mut transport = TcpTransport::connect_socks5h(
            proxy,
            "bücher.example",
            9400,
            Duration::from_secs(1),
            None,
        )
        .unwrap();
        transport.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn negotiation_uses_one_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = Socks5hProxy {
            address: listener.local_addr().unwrap(),
        };
        let server = std::thread::spawn(move || {
            let (_connection, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });
        let started = Instant::now();
        let error = match TcpTransport::connect_socks5h(
            proxy,
            "worker.example",
            9400,
            Duration::from_millis(30),
            None,
        ) {
            Ok(_) => panic!("stalled SOCKS5h negotiation unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.error_type, "TransportError");
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn proxy_rejection_never_connects_directly() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let target_port = target.local_addr().unwrap().port();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = Socks5hProxy {
            address: proxy_listener.local_addr().unwrap(),
        };
        let server = std::thread::spawn(move || {
            let (mut connection, _) = proxy_listener.accept().unwrap();
            let mut greeting = [0_u8; 3];
            connection.read_exact(&mut greeting).unwrap();
            connection.write_all(&[5, 0]).unwrap();
            let mut prefix = [0_u8; 4];
            connection.read_exact(&mut prefix).unwrap();
            let address_bytes = match prefix[3] {
                1 => 4,
                4 => 16,
                3 => {
                    let mut length = [0_u8; 1];
                    connection.read_exact(&mut length).unwrap();
                    usize::from(length[0])
                }
                value => panic!("unexpected SOCKS address type {value}"),
            };
            let mut rest = vec![0_u8; address_bytes + 2];
            connection.read_exact(&mut rest).unwrap();
            connection
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });
        assert!(TcpTransport::connect_socks5h(
            proxy,
            "127.0.0.1",
            target_port,
            Duration::from_secs(1),
            None,
        )
        .is_err());
        assert!(
            matches!(target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        server.join().unwrap();
    }
}

impl Transport for TcpTransport {
    fn split(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        (&mut self.reader, &mut self.writer)
    }

    fn close(&mut self) -> Result<()> {
        use std::net::Shutdown;
        self.writer.flush()?;
        let _ = self.writer.shutdown(Shutdown::Write);
        Ok(())
    }
}

#[cfg(unix)]
pub use unix_impl::UnixTransport;

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    /// A transport over a connected AF_UNIX SOCK_STREAM socket.
    pub struct UnixTransport {
        reader: BufReader<UnixStream>,
        writer: UnixStream,
    }

    impl UnixTransport {
        /// Connect to a unix socket at `path`.
        pub fn connect(path: impl AsRef<Path>) -> Result<Self> {
            Self::connect_with_timeout(path, None)
        }

        /// Connect with an optional per-read timeout. A read that exceeds the
        /// timeout surfaces as a `TransportError` (`WouldBlock`/`TimedOut`),
        /// cleanly ending the call rather than hanging the thread on a stalled
        /// peer. Recommended for untrusted unix peers.
        pub fn connect_with_timeout(
            path: impl AsRef<Path>,
            read_timeout: Option<std::time::Duration>,
        ) -> Result<Self> {
            let stream = UnixStream::connect(path.as_ref()).map_err(|e| {
                RpcError::new("TransportError", format!("connect unix socket: {e}"))
            })?;
            // Both ends have to ask, not just the server: an AF_UNIX write is
            // bounded by space in the *receiver's* buffer, so a tuned worker
            // still feeds an untuned client 8 KiB at a time.
            vgi_rpc::unix::widen_socket_buffers(&stream);
            if let Some(t) = read_timeout {
                stream.set_read_timeout(Some(t)).map_err(|e| {
                    RpcError::new("TransportError", format!("set unix read timeout: {e}"))
                })?;
            }
            let writer = stream
                .try_clone()
                .map_err(|e| RpcError::new("TransportError", format!("clone unix socket: {e}")))?;
            Ok(Self {
                reader: BufReader::new(stream),
                writer,
            })
        }
    }

    impl Transport for UnixTransport {
        fn split(&mut self) -> (&mut dyn Read, &mut dyn Write) {
            (&mut self.reader, &mut self.writer)
        }

        fn close(&mut self) -> Result<()> {
            use std::net::Shutdown;
            self.writer.flush()?;
            let _ = self.writer.shutdown(Shutdown::Write);
            Ok(())
        }
    }
}
