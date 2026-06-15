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

use std::io;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
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
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
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
    loop {
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
                {
                    let mut st = lock(&state);
                    st.conn_count += 1;
                    st.deadline = None; // cancel idle timer while active
                }
                let srv = server.clone();
                let state2 = state.clone();
                threads.push(thread::spawn(move || {
                    if let Ok(mut reader) = conn.try_clone() {
                        srv.serve(&mut reader, &mut conn);
                    }
                    let mut st = lock(&state2);
                    st.conn_count -= 1;
                    // Re-arm the idle timer once the last connection drains.
                    if st.conn_count == 0 {
                        if let Some(t) = idle_timeout {
                            st.deadline = Some(Instant::now() + t);
                        }
                    }
                }));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    drop(listener);
    let _ = std::fs::remove_file(path);
    // Bounded wait for in-flight connections to wrap up.
    let deadline = Instant::now() + Duration::from_secs(2);
    for t in threads {
        if Instant::now() >= deadline {
            break;
        }
        let _ = t.join();
    }
    Ok(())
}
