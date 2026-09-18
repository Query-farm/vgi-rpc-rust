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

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// Build an `RpcServer` with all conformance methods registered.
pub fn build_server() -> RpcServer {
    build_server_with_external(None, None)
}

/// Build an `RpcServer` with a caller-chosen `server_id`.
///
/// `TestSticky::test_token_from_other_worker_rejected` runs two workers that
/// share one AEAD key and asserts they report distinct `server_id` before it
/// asserts anything else — otherwise a token that supposedly "belongs to the
/// other worker" belongs to this one, and the test proves nothing.
pub fn build_server_with_id(server_id: Option<&str>) -> RpcServer {
    build_server_with_external_and_hook(None, server_id, None, None)
}

/// Build a conformance server with an explicit transport-start hook.
pub fn build_server_with_id_and_hook(
    server_id: Option<&str>,
    hook: vgi_rpc::ServeStartHook,
) -> RpcServer {
    build_server_with_external_and_hook(None, server_id, Some(hook), None)
}

/// Build a conformance server that also co-hosts `vgi_rpc.Identity.v1`.
///
/// Backs the two identity fixtures the shared group needs. Deliberately a
/// separate entry point rather than a default: the group asserts against the
/// *plain* worker that a deployment configuring no hook hosts no identity
/// protocol at all, which is the property that keeps a dependency upgrade from
/// growing a credential-to-identity oracle on every existing worker.
pub fn build_server_with_identity(
    server_id: Option<&str>,
    identity: vgi_rpc::token_identity::IdentityImpl,
) -> RpcServer {
    build_server_with_external_and_hook(None, server_id, None, Some(identity))
}

/// Build an `RpcServer` with all conformance methods registered, optionally
/// wired to an external-location config (used by `TestExternalLocation`) and
/// with an optional `server_id` override.
pub fn build_server_with_external(
    external: Option<vgi_rpc::external::ExternalLocationConfig>,
    server_id: Option<&str>,
) -> RpcServer {
    build_server_with_external_and_hook(external, server_id, None, None)
}

fn build_server_with_external_and_hook(
    external: Option<vgi_rpc::external::ExternalLocationConfig>,
    server_id: Option<&str>,
    serve_start_hook: Option<vgi_rpc::ServeStartHook>,
    identity: Option<vgi_rpc::token_identity::IdentityImpl>,
) -> RpcServer {
    let mut builder = RpcServer::builder()
        .server_id(server_id.unwrap_or("rust-conf-0001"))
        .protocol_name("ConformanceService")
        .protocol_version("2.0.0")
        .server_version("rust-conformance-0.2.0");

    if let Some(cfg) = external {
        builder = builder.with_external_location(cfg);
    }
    if let Some(hook) = serve_start_hook {
        builder = builder.on_serve_start(hook);
    }
    if let Some(identity) = identity {
        builder = builder.identity(identity);
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
                let version = "rust-conformance-0.2.0";
                let hook = match env_usize("VGI_ACCESS_LOG_QUEUE_SIZE") {
                    // Async emission is opt-in: it trades the guarantee that
                    // a record on disk means the call completed.
                    Some(queue) if env_flag("VGI_ACCESS_LOG_ASYNC") => {
                        vgi_rpc::AccessLogHook::buffered(f, version, queue)
                    }
                    _ if env_flag("VGI_ACCESS_LOG_ASYNC") => {
                        vgi_rpc::AccessLogHook::buffered(f, version, 10_000)
                    }
                    _ => vgi_rpc::AccessLogHook::new(f, version),
                };
                let hook = match env_usize("VGI_ACCESS_LOG_MAX_RECORD_BYTES") {
                    Some(n) => hook.with_max_record_bytes(n),
                    None => hook,
                };
                // DEBUG-equivalent: the only setting that puts `request_data`
                // on the record, so it is what `--require-request-data`
                // validates against.
                let hook = hook.with_verbose(env_flag("VGI_ACCESS_LOG_DEBUG"));
                let hook = match std::env::var("VGI_ACCESS_LOG_SAMPLE") {
                    Ok(raw) => {
                        let rate: f64 = raw.parse().unwrap_or_else(|_| {
                            eprintln!(
                                "[vgi-rpc] --access-log-sample must be a number, got {raw:?}"
                            );
                            std::process::exit(2);
                        });
                        // Out of range fails here rather than at the first
                        // request: 100 meaning "100%" would otherwise
                        // silently log everything.
                        hook.with_sample_rate(rate).unwrap_or_else(|e| {
                            eprintln!("[vgi-rpc] {}", e.message);
                            std::process::exit(2);
                        })
                    }
                    Err(_) => hook,
                };
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

#[cfg(test)]
mod hash_tests {
    /// The `ConformanceService` digest every port agrees on.
    ///
    /// Pinned here because it is what the access log publishes as
    /// `protocol_hash` -- `access-log-spec.md` §3 calls that "the registry key
    /// when decoding archived records", and a record keyed on a port-local
    /// digest cannot be decoded against any other port's description. The
    /// failure is silent: such a record is well-formed and passes the schema.
    ///
    /// The digest this worker used to publish was not this one. It was taken
    /// over serialized Arrow IPC bytes of the retired `__describe__` payload,
    /// and each language may legitimately spell those differently for the same
    /// logical schema -- so it was only ever comparable against itself.
    const CANONICAL: &str = "4b0269208a5a8fdeb7d8fe0f62a352713a3bfc071d7de99e5e12408c5f0b9402";

    #[test]
    fn the_access_log_publishes_the_canonical_digest() {
        let srv = super::build_server();
        assert_eq!(srv.protocol_hash(), CANONICAL);
        assert_eq!(
            srv.protocol_identity(srv.protocol_name()).hash,
            CANONICAL,
            "the accessor every emit site reads must return the same digest"
        );
    }
}
