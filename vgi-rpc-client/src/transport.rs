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

use vgi_rpc::errors::{Result, RpcError};

/// A bidirectional byte-stream transport: schema-framed Arrow IPC streams
/// flow over `reader`/`writer` sequentially.
pub trait Transport: Send {
    /// Borrow the read half and write half as disjoint mutable references.
    fn split(&mut self) -> (&mut dyn Read, &mut dyn Write);

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
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl SubprocessTransport {
    /// Spawn `cmd[0]` with `cmd[1..]` as arguments, piping stdin/stdout.
    pub fn spawn(cmd: &[impl AsRef<std::ffi::OsStr>]) -> Result<Self> {
        Self::spawn_with_stderr(cmd, StderrMode::default())
    }

    /// Spawn with an explicit stderr disposition.
    pub fn spawn_with_stderr(
        cmd: &[impl AsRef<std::ffi::OsStr>],
        stderr: StderrMode,
    ) -> Result<Self> {
        let (program, args) = cmd
            .split_first()
            .ok_or_else(|| RpcError::value_error("empty command for SubprocessTransport"))?;
        let mut child = Command::new(program)
            .args(args.iter().map(|a| a.as_ref()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr.to_stdio())
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
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
        })
    }
}

impl Transport for SubprocessTransport {
    fn split(&mut self) -> (&mut dyn Read, &mut dyn Write) {
        // `stdin` is always `Some` between `spawn` and `close`.
        let writer = self.stdin.as_mut().expect("transport already closed");
        (&mut self.stdout, writer)
    }

    fn close(&mut self) -> Result<()> {
        // Drop stdin to send EOF, then reap the child (best-effort kill on a
        // wait error so we never leak a zombie).
        drop(self.stdin.take());
        match self.child.wait() {
            Ok(_) => Ok(()),
            Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                Ok(())
            }
        }
    }
}

impl Drop for SubprocessTransport {
    fn drop(&mut self) {
        let _ = self.close();
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
