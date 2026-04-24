//! Rust port of the vgi-rpc ConformanceService.
//!
//! Registers ~45 RPC methods against an [`vgi_rpc::RpcServer`] mirroring
//! the Python canonical implementation (`vgi_rpc/conformance/_impl.py`).

mod param_schemas;
mod params;
mod results;
mod streams;
mod types;
mod unary;

use std::sync::Arc;

use vgi_rpc::RpcServer;

/// Build an `RpcServer` with all conformance methods registered.
pub fn build_server() -> RpcServer {
    let mut srv = RpcServer::builder()
        .server_id("rust-conf-0001")
        .protocol_name("ConformanceService")
        .enable_describe(true)
        .build();
    unary::register(&mut srv);
    streams::register(&mut srv);
    srv
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
