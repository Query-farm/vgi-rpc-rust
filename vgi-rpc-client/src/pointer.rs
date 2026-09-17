//! External-location pointer resolution, shared by every transport.
//!
//! Externalization is not an HTTP feature (WIRE_PROTOCOL.md §12): any
//! transport that carries record batches carries pointer batches, and the
//! persistent byte-stream transports (pipe, subprocess, unix, tcp) resolve
//! them through this same path. A port whose resolution lives only in its HTTP
//! client has an untested half — which is what the shared
//! `TestExternalByteStream` conformance group exists to find.
//!
//! An externalized *cycle* is a whole IPC stream — this turn's log batches
//! followed by its single data batch — so resolution walks the fetched object
//! rather than taking its first batch. Stopping at the first data batch drops
//! logs that were delivered inline before externalization was switched on, a
//! regression no data assertion can see.

use arrow_array::RecordBatch;

use vgi_rpc::errors::{Result, RpcError};
use vgi_rpc::metadata::LOCATION_KEY;
use vgi_rpc::wire::{md_get, Metadata};

use crate::client::OnLog;

/// The handle a client keeps on its resolver.
///
/// A zero-sized `Option<()>` without the `http` feature, so every call site
/// compiles uniformly and the "arrived with nothing to resolve it" branch
/// exists on both builds instead of being `#[cfg]`-ed away.
#[cfg(feature = "http")]
pub type ExternalHandle = Option<vgi_rpc::external::ExternalLocationConfig>;
#[cfg(not(feature = "http"))]
pub type ExternalHandle = Option<()>;

/// A pointer arrived and nothing is configured to fetch it.
///
/// Loud on purpose. The alternative — handing the caller the pointer as if it
/// were data — is a zero-row batch that reads as an empty result, which is
/// silent row loss on every externalized batch.
pub(crate) fn unresolved_pointer_error(md: &Metadata) -> RpcError {
    let url = md_get(md, LOCATION_KEY).unwrap_or("");
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "<unparseable>".to_string());
    RpcError::new(
        "ProtocolError",
        format!(
            "received an external-location pointer batch (storage host {host}) but this \
             client has no external-location resolver configured; the payload would \
             otherwise be delivered as a zero-row batch"
        ),
    )
}

/// Fetch and unpack one pointer batch, dispatching any logs bundled with it.
///
/// Returns the payload's data batch plus the metadata a resolved batch
/// carries: the inner batch's keys merged over the pointer's non-location
/// ones, with `vgi_rpc.location.fetch_ms` and `vgi_rpc.location.source`
/// stamped by this reader (see [`vgi_rpc::external::resolved_metadata`]).
#[cfg(feature = "http")]
pub(crate) fn resolve_pointer(
    pointer_md: &Metadata,
    cfg: &vgi_rpc::external::ExternalLocationConfig,
    on_log: &mut Option<OnLog>,
    relax: bool,
) -> Result<(RecordBatch, Metadata)> {
    use crate::envelope::{classify, BatchKind};
    use vgi_rpc::wire::StreamReader;

    let url = md_get(pointer_md, LOCATION_KEY)
        .ok_or_else(|| RpcError::new("ProtocolError", "resolve_pointer: frame is not a pointer"))?
        .to_string();
    let started = std::time::Instant::now();
    let ipc_bytes = vgi_rpc::external::fetch_external_ipc_bytes(pointer_md, cfg)?
        .ok_or_else(|| RpcError::new("ProtocolError", "resolve_pointer: frame is not a pointer"))?;
    let fetch_ms = started.elapsed().as_secs_f64() * 1000.0;

    let mut reader = StreamReader::new(&ipc_bytes[..])?;
    if relax {
        reader = reader.relax_nullability();
    }
    let mut data: Option<(RecordBatch, Metadata)> = None;
    while let Some((batch, md)) = reader.read_next()? {
        match classify(&batch, &md) {
            BatchKind::Log(m) => {
                if let Some(cb) = on_log.as_mut() {
                    cb(m);
                }
            }
            BatchKind::Exception(e) => return Err(e),
            // One level only. A payload that points somewhere else is a
            // redirect loop, not a second hop to follow.
            BatchKind::Pointer => {
                return Err(RpcError::new(
                    "ProtocolError",
                    "external payload contains another external-location pointer (redirect loop)",
                ))
            }
            BatchKind::Data => {
                if data.is_some() {
                    return Err(RpcError::new(
                        "ProtocolError",
                        "external payload contains more than one data batch",
                    ));
                }
                data = Some((batch, md));
            }
        }
    }
    let (batch, inner_md) = data
        .ok_or_else(|| RpcError::new("ProtocolError", "external payload contains no data batch"))?;
    let resolved_md = vgi_rpc::external::resolved_metadata(pointer_md, inner_md, &url, fetch_ms);
    Ok((batch, resolved_md))
}

/// Resolve a pointer when a resolver is configured; fail loudly when not.
pub(crate) fn resolve_with(
    external: &ExternalHandle,
    pointer_md: &Metadata,
    on_log: &mut Option<OnLog>,
    relax: bool,
) -> Result<(RecordBatch, Metadata)> {
    #[cfg(feature = "http")]
    if let Some(cfg) = external.as_ref() {
        return resolve_pointer(pointer_md, cfg, on_log, relax);
    }
    let _ = (external, on_log, relax);
    Err(unresolved_pointer_error(pointer_md))
}
