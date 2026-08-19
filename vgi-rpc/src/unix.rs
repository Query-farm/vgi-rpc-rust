//! AF_UNIX accept loop with optional idle self-termination.
//!
//! This is the server half of the cross-language *launcher worker contract*
//! (Python `vgi_rpc.launcher`): a launcher spawns a warm worker that serves RPC
//! over an `AF_UNIX` socket, prints `UNIX:<absolute-path>` once it is listening,
//! and self-terminates after a quiet period so abandoned workers don't leak.
//!
//! [`serve_unix`] binds *path*, fires `on_bound` (the caller prints the
//! `UNIX:<path>` line there), then accepts connections — each served on its own
//! thread. With `idle_timeout` set it mirrors the Python semantics exactly:
//!
//! * A **startup grace** timer of `max(idle_timeout, 60s)` is armed at bind so a
//!   launcher has time to connect its first client.
//! * Every accepted connection **cancels** the idle timer; when the *last*
//!   connection closes the timer is **re-armed** for `idle_timeout`.
//! * When the timer elapses with zero active connections the accept loop stops,
//!   the listener is dropped, and the socket path is unlinked.
//!
//! The `shutdown` flag lets a caller's signal handler (SIGTERM/SIGINT) tear the
//! loop down the same way.
//!
//! The path checks protect stable pre-existing paths and accidental
//! collisions. They are not an atomic defence against another process with
//! the same UID racing pathname replacement. Put the socket in a
//! caller-owned directory mode `0700` when peers with the same UID are not
//! trusted.

use std::collections::HashMap;
use std::io;
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::RpcServer;

/// Socket buffer requested on both ends of an `AF_UNIX` connection.
///
/// macOS defaults `net.local.stream.sendspace` to 8192 bytes — against ~64 KiB
/// for a pipe — so a megabyte of Arrow crosses the kernel in 128 trips instead
/// of a handful. Widening it takes a Unix socket from roughly half the pipe's
/// throughput to ahead of it at 1 MiB and 16 MiB payloads.
///
/// TCP deliberately does not get the same treatment: it already starts at
/// 128 KiB and grows, and an explicit `SO_RCVBUF` *disables* Linux's
/// receive-window auto-tuning, pinning the window at whatever constant we
/// guessed.
pub const UNIX_SOCKET_BUFFER_BYTES: usize = 1 << 20;

/// Request [`UNIX_SOCKET_BUFFER_BYTES`] of send and receive buffer on `sock`.
///
/// Both ends must do this to get the benefit: an `AF_UNIX` write is bounded by
/// space in the *receiver's* buffer, so a tuned server still hands every
/// response to an untuned client one 8 KiB chunk at a time. [`serve_unix`]
/// calls it on each accepted connection; `vgi-rpc-client`'s `UnixTransport`
/// calls it on connect.
///
/// Best effort. The kernel clamps the request to its own maximum, and a
/// refusal is not worth failing a connection over.
pub fn widen_socket_buffers<S: std::os::fd::AsFd>(sock: &S) {
    let sock = socket2::SockRef::from(sock);
    let _ = sock.set_send_buffer_size(UNIX_SOCKET_BUFFER_BYTES);
    let _ = sock.set_recv_buffer_size(UNIX_SOCKET_BUFFER_BYTES);
}

/// Shared idle bookkeeping: how many connections are live, and — when zero —
/// the instant at which the worker should self-terminate.
struct IdleState {
    conn_count: usize,
    /// `Some(deadline)` while idle (or in startup grace); `None` while at least
    /// one connection is active. Always `None` when `idle_timeout` is unset.
    deadline: Option<Instant>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

fn socket_identity(path: &str) -> io::Result<SocketIdentity> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn prepare_socket_path(path: &str) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "refusing to replace a non-socket Unix path",
        ));
    }
    let existing_identity = SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    match UnixStream::connect(path) {
        Ok(stream) => {
            drop(stream);
            Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "refusing to replace an active Unix socket",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            if socket_identity(path)? != existing_identity {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Unix socket path changed while checking whether it was stale",
                ));
            }
            std::fs::remove_file(path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("cannot prove existing Unix socket is stale: {error}"),
        )),
    }
}

fn remove_owned_socket(path: &str, identity: SocketIdentity) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_socket()
        && metadata.dev() == identity.device
        && metadata.ino() == identity.inode
    {
        let _ = std::fs::remove_file(path);
    }
}

fn reap_finished(threads: &mut Vec<thread::JoinHandle<()>>) {
    let mut index = 0;
    while index < threads.len() {
        if threads[index].is_finished() {
            let handle = threads.swap_remove(index);
            let _ = handle.join();
        } else {
            index += 1;
        }
    }
}

fn join_until(threads: &mut Vec<thread::JoinHandle<()>>, deadline: Instant) {
    loop {
        reap_finished(threads);
        if threads.is_empty() || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Serve `server` on the `AF_UNIX` socket at `path`, one thread per connection.
///
/// Binds and listens (removing any stale socket file first), invokes `on_bound`
/// once listening succeeds — the caller typically prints `UNIX:{path}` and
/// flushes stdout there — then runs the accept loop until either `shutdown` is
/// set or, when `idle_timeout` is `Some`, the worker has been idle past its
/// deadline. On exit the listener is dropped and the socket path unlinked.
///
/// Returns the bind/listen error if the socket cannot be created; the accept
/// loop itself never returns an error (transient accept failures are retried,
/// terminal ones end the loop).
pub fn serve_unix<F: FnOnce()>(
    server: Arc<RpcServer>,
    path: &str,
    idle_timeout: Option<Duration>,
    shutdown: Arc<AtomicBool>,
    on_bound: F,
) -> io::Result<()> {
    prepare_socket_path(path)?;
    let listener = UnixListener::bind(path)?;
    let bound_identity = socket_identity(path)?;
    listener.set_nonblocking(true).ok();
    on_bound();

    // Startup grace: max(idle_timeout, 60s) before the first client connects,
    // matching the Python launcher's `_arm_timer_locked(max(idle_timeout, 60))`.
    let startup_deadline = idle_timeout.map(|t| Instant::now() + t.max(Duration::from_secs(60)));
    let state = Arc::new(Mutex::new(IdleState {
        conn_count: 0,
        deadline: startup_deadline,
    }));

    let mut threads: Vec<thread::JoinHandle<()>> = Vec::new();
    let active = Arc::new(Mutex::new(HashMap::<u64, UnixStream>::new()));
    let next_connection_id = AtomicU64::new(1);
    loop {
        reap_finished(&mut threads);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        // Idle self-termination: only when nothing is in flight and the
        // (startup or re-armed) deadline has elapsed.
        if idle_timeout.is_some() {
            let st = lock(&state);
            if st.conn_count == 0 {
                if let Some(dl) = st.deadline {
                    if Instant::now() >= dl {
                        break;
                    }
                }
            }
        }

        match listener.accept() {
            Ok((mut conn, _)) => {
                conn.set_nonblocking(false).ok();
                widen_socket_buffers(&conn);
                // Both clones are prerequisites: the worker needs one reader
                // and the accept loop needs an independent handle that can
                // interrupt a stalled read during shutdown. Never account or
                // spawn a connection that cannot be interrupted.
                let mut reader = match conn.try_clone() {
                    Ok(reader) => reader,
                    Err(_) => continue,
                };
                let interrupter = match conn.try_clone() {
                    Ok(interrupter) => interrupter,
                    Err(_) => continue,
                };
                {
                    let mut st = lock(&state);
                    st.conn_count += 1;
                    st.deadline = None; // cancel idle timer while active
                }
                let srv = server.clone();
                let state2 = state.clone();
                let active2 = active.clone();
                let connection_id = next_connection_id.fetch_add(1, Ordering::Relaxed);
                lock(&active).insert(connection_id, interrupter);
                threads.push(thread::spawn(move || {
                    srv.serve(&mut reader, &mut conn);
                    let mut st = lock(&state2);
                    st.conn_count -= 1;
                    // Re-arm the idle timer once the last connection drains.
                    if st.conn_count == 0 {
                        if let Some(t) = idle_timeout {
                            st.deadline = Some(Instant::now() + t);
                        }
                    }
                    drop(st);
                    lock(&active2).remove(&connection_id);
                }));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    drop(listener);
    for connection in lock(&active).values() {
        let _ = connection.shutdown(Shutdown::Both);
    }
    remove_owned_socket(path, bound_identity);
    // Poll only completed handles. Calling `join` on an unfinished handle
    // would make the nominal deadline unbounded.
    let deadline = Instant::now() + Duration::from_secs(2);
    join_until(&mut threads, deadline);
    Ok(())
}
