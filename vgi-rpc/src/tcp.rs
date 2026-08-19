//! AF_INET (TCP) accept loop with optional idle self-termination.
//!
//! This is the network analog of the [`crate::unix`] serve path: it speaks the
//! exact same raw Arrow-IPC framing protocol, only the listening socket differs
//! (`TcpListener`/`TcpStream` bound to `host:port`). A worker serves RPC over a
//! bare TCP socket, prints `TCP:<host>:<port>` once it is listening, and
//! self-terminates after a quiet period so abandoned workers don't leak.
//!
//! Raw TCP carries **no authentication and no TLS**. Bind it to a trusted
//! network only — the default host is loopback-only (`127.0.0.1`). Binding a
//! routable address (e.g. `0.0.0.0`) exposes the unauthenticated, unencrypted
//! framing protocol on the network; use the HTTP transport for untrusted peers.
//!
//! [`serve_tcp`] binds `(host, port)` (with `port = 0` letting the OS choose a
//! free port), fires `on_bound` with `(host, actual_port)` (the caller prints
//! the `TCP:<host>:<port>` line there), then accepts connections — each served
//! on its own thread. With `idle_timeout` set it mirrors the Unix semantics
//! exactly:
//!
//! * A **startup grace** timer of `max(idle_timeout, 60s)` is armed at bind so a
//!   launcher has time to connect its first client.
//! * Every accepted connection **cancels** the idle timer; when the *last*
//!   connection closes the timer is **re-armed** for `idle_timeout`.
//! * When the timer elapses with zero active connections the accept loop stops
//!   and the listener is dropped.
//!
//! The `shutdown` flag lets a caller's signal handler (SIGTERM/SIGINT) tear the
//! loop down the same way.

use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::RpcServer;

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

/// Serve `server` on a TCP socket bound to `(host, port)`, one thread per
/// connection.
///
/// Binds and listens, invokes `on_bound` with `(host, actual_port)` once
/// listening succeeds — the caller typically prints `TCP:{host}:{port}` and
/// flushes stdout there. `port = 0` lets the OS pick a free port, which is read
/// back from `local_addr()` and reported to `on_bound`. Nagle's algorithm is
/// disabled (`TCP_NODELAY`) on each accepted connection so the lockstep
/// request/response framing is not delayed waiting to coalesce writes.
///
/// The accept loop runs until either `shutdown` is set or, when `idle_timeout`
/// is `Some`, the worker has been idle past its deadline. On exit the listener
/// is dropped.
///
/// Returns the bind/listen error if the socket cannot be created; the accept
/// loop itself never returns an error (transient accept failures are retried,
/// terminal ones end the loop).
pub fn serve_tcp<F: FnOnce(&str, u16)>(
    server: Arc<RpcServer>,
    host: &str,
    port: u16,
    idle_timeout: Option<Duration>,
    shutdown: Arc<AtomicBool>,
    on_bound: F,
) -> io::Result<()> {
    let listener = TcpListener::bind((host, port))?;
    let bound_port = listener.local_addr()?.port();
    listener.set_nonblocking(true).ok();
    on_bound(host, bound_port);

    // Startup grace: max(idle_timeout, 60s) before the first client connects,
    // matching the Unix launcher's `_arm_timer_locked(max(idle_timeout, 60))`.
    let startup_deadline = idle_timeout.map(|t| Instant::now() + t.max(Duration::from_secs(60)));
    let state = Arc::new(Mutex::new(IdleState {
        conn_count: 0,
        deadline: startup_deadline,
    }));

    let mut threads: Vec<thread::JoinHandle<()>> = Vec::new();
    let active = Arc::new(Mutex::new(HashMap::<u64, TcpStream>::new()));
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
                // Disable Nagle so lockstep framing isn't delayed.
                conn.set_nodelay(true).ok();
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
    // Poll only completed handles. Calling `join` on an unfinished handle
    // would make the nominal deadline unbounded.
    let deadline = Instant::now() + Duration::from_secs(2);
    join_until(&mut threads, deadline);
    Ok(())
}
