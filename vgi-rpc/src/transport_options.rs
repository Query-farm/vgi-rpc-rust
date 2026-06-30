//! The `__transport_options__` RPC method — transport capability negotiation.
//!
//! A framework-level handshake, parallel to `__describe__` (see
//! [`crate::introspect`]). The client calls it once per worker, before `init`,
//! to discover which transport features the worker supports; the shared-memory
//! side-channel (and, later, compression / AEAD) is used only when both peers
//! advertise support.
//!
//! Capabilities ride as request/response *metadata* under the
//! `vgi_rpc.transport.*` namespace (not as batch rows), consistent with how the
//! SHM segment itself is advertised and decode-safe (the params batch stays
//! empty). Each capability is one `vgi_rpc.transport.<name>` key with a string
//! value; unknown keys are ignored, so the set is open-ended.
//!
//! Mirrors Python `vgi_rpc.transport_options` byte-for-byte on the wire.

use crate::metadata::TRANSPORT_SHM_KEY;
use crate::wire::Metadata;

/// The reserved method name for the transport-capability handshake.
pub const TRANSPORT_OPTIONS_METHOD_NAME: &str = "__transport_options__";

/// Whether this worker can use the POSIX shared-memory side-channel.
///
/// The VGI shm channel is named shared memory — POSIX `shm_open`/`mmap` on
/// Unix and a page-file-backed named `CreateFileMapping`/`MapViewOfFile`
/// section on Windows — interoperating across the C++/Go/Java/Python peers on
/// all three platforms. It is compiled in only under the `shm` feature.
pub fn shm_available() -> bool {
    cfg!(feature = "shm")
}

/// This worker's transport capabilities, as `__transport_options__` response
/// metadata. String values mirror Python's `b"true"` / `b"false"` byte values
/// once serialized onto the wire.
pub fn worker_transport_metadata() -> Metadata {
    let mut md = Metadata::new();
    md.insert(
        TRANSPORT_SHM_KEY.to_string(),
        if shm_available() { "true" } else { "false" }.to_string(),
    );
    md
}
