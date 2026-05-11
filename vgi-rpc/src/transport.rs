//! Transport identity advertised by a bound [`RpcServer`].
//!
//! Workers (RPC implementations) read [`RpcServer::transport_kind`] —
//! or register a [`ServeStartHook`] via
//! [`RpcServerBuilder::on_serve_start`] — to tailor startup behaviour
//! to the transport they were bound to. Mirrors the Python
//! `TransportKind` / `on_serve_start` API.

use std::sync::Arc;

/// Coarse identifier of the transport binding an [`crate::RpcServer`].
///
/// The wire-form value (returned by [`Self::as_str`]) matches the Python
/// `TransportKind` StrEnum so logs and metrics are portable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// Stdio / `BufReader<Stdin>` + `BufWriter<Stdout>` — including the
    /// shared-memory pipe variant. Subprocess workers also report `Pipe`
    /// because they speak Arrow IPC over their parent's stdin/stdout.
    Pipe,
    /// HTTP (`axum`).
    Http,
    /// AF_UNIX socket.
    Unix,
}

impl TransportKind {
    /// Wire-form identifier; matches the Python `TransportKind` value.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportKind::Pipe => "pipe",
            TransportKind::Http => "http",
            TransportKind::Unix => "unix",
        }
    }
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Capabilities advertised alongside a [`TransportKind`].
///
/// Kept as a small struct rather than a string set so the common case
/// — branching on a single boolean — stays cheap and type-checked.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct TransportCapabilities {
    /// True when the transport supports zero-copy shared-memory exchange
    /// (matches Python's `frozenset({"shm"})`).
    pub shm: bool,
}

impl TransportCapabilities {
    /// Capabilities of a vanilla transport (no extras).
    pub const fn none() -> Self {
        Self { shm: false }
    }

    /// Capabilities of a shared-memory-aware pipe transport.
    pub const fn shm() -> Self {
        Self { shm: true }
    }
}

/// One-shot lifecycle hook fired before the first request is dispatched
/// on each (kind, capabilities) combination.
///
/// Register via [`crate::RpcServerBuilder::on_serve_start`]. Hooks run
/// synchronously on the thread that first observes the transport, after
/// the framework has recorded the binding but before any handler runs.
/// A hook that panics aborts the serve path; if you want errors to be
/// recoverable, catch them inside the closure.
pub type ServeStartHook =
    Arc<dyn Fn(TransportKind, &TransportCapabilities) + Send + Sync + 'static>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RpcServer;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[test]
    fn notify_transport_fires_hook_once_per_combination() {
        let calls: Arc<Mutex<Vec<(TransportKind, TransportCapabilities)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let recorder = calls.clone();
        let hook: ServeStartHook = Arc::new(move |k, c| {
            recorder.lock().unwrap().push((k, *c));
        });
        let server = RpcServer::builder().on_serve_start(hook).build();

        // First call → fires.
        server.notify_transport(TransportKind::Pipe, TransportCapabilities::none());
        // Same (kind, caps) → idempotent no-op.
        server.notify_transport(TransportKind::Pipe, TransportCapabilities::none());
        server.notify_transport(TransportKind::Pipe, TransportCapabilities::none());
        // Different caps → re-fires.
        server.notify_transport(TransportKind::Pipe, TransportCapabilities::shm());
        // Different kind → re-fires.
        server.notify_transport(TransportKind::Http, TransportCapabilities::none());

        let log = calls.lock().unwrap().clone();
        assert_eq!(
            log,
            vec![
                (TransportKind::Pipe, TransportCapabilities::none()),
                (TransportKind::Pipe, TransportCapabilities::shm()),
                (TransportKind::Http, TransportCapabilities::none()),
            ]
        );
    }

    #[test]
    fn transport_kind_and_capabilities_observed_after_notify() {
        let server = RpcServer::builder().build();
        assert!(server.transport_kind().is_none());
        assert_eq!(
            server.transport_capabilities(),
            TransportCapabilities::none()
        );

        server.notify_transport(TransportKind::Unix, TransportCapabilities::none());
        assert_eq!(server.transport_kind(), Some(TransportKind::Unix));
        assert_eq!(
            server.transport_capabilities(),
            TransportCapabilities::none()
        );

        server.notify_transport(TransportKind::Pipe, TransportCapabilities::shm());
        assert_eq!(server.transport_kind(), Some(TransportKind::Pipe));
        assert!(server.transport_capabilities().shm);
    }

    #[test]
    fn notify_without_hook_is_no_op_safe() {
        // Server with no hook registered — must still record state.
        let server = RpcServer::builder().build();
        server.notify_transport(TransportKind::Http, TransportCapabilities::none());
        assert_eq!(server.transport_kind(), Some(TransportKind::Http));
    }

    #[test]
    fn concurrent_notify_fires_hook_once() {
        // Stress: N threads racing on the same (kind, caps) must result
        // in exactly one hook invocation.
        let fire_count = Arc::new(AtomicUsize::new(0));
        let counter = fire_count.clone();
        let hook: ServeStartHook = Arc::new(move |_, _| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        let server = Arc::new(RpcServer::builder().on_serve_start(hook).build());

        let mut handles = Vec::new();
        for _ in 0..32 {
            let srv = server.clone();
            handles.push(std::thread::spawn(move || {
                srv.notify_transport(TransportKind::Http, TransportCapabilities::none());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(fire_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn as_str_matches_python_wire_form() {
        assert_eq!(TransportKind::Pipe.as_str(), "pipe");
        assert_eq!(TransportKind::Http.as_str(), "http");
        assert_eq!(TransportKind::Unix.as_str(), "unix");
    }
}
