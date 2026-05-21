//! Rust port of the vgi-rpc ConformanceService.
//!
//! Registers ~45 RPC methods against an [`vgi_rpc::RpcServer`] mirroring
//! the Python canonical implementation (`vgi_rpc/conformance/_impl.py`).

// `macro_demo` builds and demonstrates the proc-macro parity, but
// registering it would drift the describe-conformance method-set check.
// The macro shape is exercised by `vgi-rpc/tests/macro_smoke.rs`.
#[allow(dead_code)]
mod macro_demo;
mod params;
mod streams;
mod types;
mod unary;
mod wide_types;

use std::sync::Arc;

use vgi_rpc::RpcServer;

/// Build an `RpcServer` with all conformance methods registered.
pub fn build_server() -> RpcServer {
    build_server_with_external(None)
}

/// Build an `RpcServer` with all conformance methods registered, optionally
/// wired to an external-location config (used by `TestExternalLocation`).
pub fn build_server_with_external(
    external: Option<vgi_rpc::external::ExternalLocationConfig>,
) -> RpcServer {
    let mut builder = RpcServer::builder()
        .server_id("rust-conf-0001")
        .protocol_name("ConformanceService")
        .protocol_version("1.0.0")
        .server_version("rust-conformance-0.2.0")
        .enable_describe(true);

    if let Some(cfg) = external {
        builder = builder.with_external_location(cfg);
    }

    // When VGI_ACCESS_LOG is set, emit JSON-per-call access records to that
    // file. Used for manual validation against vgi_rpc.access_log_conformance.
    if let Ok(path) = std::env::var("VGI_ACCESS_LOG") {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => {
                let hook = vgi_rpc::AccessLogHook::new(f, "rust-conformance-0.2.0");
                builder = builder.with_hook(hook);
            }
            Err(e) => {
                eprintln!("[vgi-rpc] could not open VGI_ACCESS_LOG={path:?}: {e}");
            }
        }
    }

    let mut srv = builder.build();
    unary::register(&mut srv);
    streams::register(&mut srv);
    srv
}

/// Sticky-session state for the conformance counter methods (unary +
/// streaming). Shared by `unary::open_counter` (which binds it via
/// `ctx.open_session`) and the `streams` session-counter methods (which
/// read it back via `ctx.session`). Interior mutability via an atomic so
/// it mutates through the shared `Arc` the session registry hands out.
pub(crate) struct StickyCounter {
    value: std::sync::atomic::AtomicI64,
}

impl StickyCounter {
    pub(crate) fn new(initial: i64) -> Self {
        Self {
            value: std::sync::atomic::AtomicI64::new(initial),
        }
    }
    pub(crate) fn add(&self, by: i64) -> i64 {
        self.value
            .fetch_add(by, std::sync::atomic::Ordering::SeqCst)
            + by
    }
    pub(crate) fn get(&self) -> i64 {
        self.value.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Shared cancel probe state (counters observed by cancel conformance tests).
pub(crate) static CANCEL_PROBE: once_cell::sync::Lazy<Arc<parking_lot::Mutex<[i64; 3]>>> =
    once_cell::sync::Lazy::new(|| Arc::new(parking_lot::Mutex::new([0, 0, 0])));

pub(crate) fn bump_cancel_produce() {
    CANCEL_PROBE.lock()[0] += 1;
}
pub(crate) fn bump_cancel_exchange() {
    CANCEL_PROBE.lock()[1] += 1;
}
pub(crate) fn bump_cancel_oncancel() {
    CANCEL_PROBE.lock()[2] += 1;
}
pub(crate) fn read_cancel_probe() -> [i64; 3] {
    *CANCEL_PROBE.lock()
}
pub(crate) fn reset_cancel_probe() {
    *CANCEL_PROBE.lock() = [0, 0, 0];
}
