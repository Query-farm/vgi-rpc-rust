//! Well-known metadata keys used in the vgi-rpc wire protocol.
//!
//! These keys appear as Arrow IPC `custom_metadata` on record batches.

pub const RPC_METHOD_KEY: &str = "vgi_rpc.method";

/// Names the protocol a request addresses -- the routing key.
///
/// Dispatch resolves the pair `(protocol, method)`: a server hosts one or more
/// protocols and method names may collide across them, which is what lets
/// protocols be authored independently. Required on every request, including
/// against a server hosting exactly one protocol -- an exemption would let an
/// intermediary that rebuilds a request and drops the field land silently on
/// whichever protocol happened to be first, rather than being told.
///
/// The major version is part of the protocol name (`vgi_rpc.Reflection.v1`), so
/// an incompatible major is a routing failure rather than a parse failure, and
/// v1 and v2 can be served side by side while clients migrate.
pub const PROTOCOL_KEY: &str = "vgi_rpc.protocol";
pub const REQUEST_VERSION_KEY: &str = "vgi_rpc.request_version";
pub const REQUEST_VERSION: &str = "1";
pub const REQUEST_ID_KEY: &str = "vgi_rpc.request_id";

/// Typed error classification on EXCEPTION-level batches. An open enum —
/// values beyond the well-known tokens are valid and should be treated as
/// unknown kinds by clients. Lets a caller pattern-match on a stable
/// identifier instead of substring-searching the exception message, which is
/// the only way to tell a *definitive* rejection from a *transient* one once
/// every handler failure surfaces through the same envelope.
pub const ERROR_KIND_KEY: &str = "vgi_rpc.error_kind";

pub const LOG_LEVEL_KEY: &str = "vgi_rpc.log_level";
pub const LOG_MESSAGE_KEY: &str = "vgi_rpc.log_message";
pub const LOG_EXTRA_KEY: &str = "vgi_rpc.log_extra";

pub const SERVER_ID_KEY: &str = "vgi_rpc.server_id";

pub const STATE_KEY: &str = "vgi_rpc.stream_state#b64";
/// The stream's *call state* — the half of a stream's state fixed for the
/// life of the call (the init request, the resolved schemas). A server that
/// splits its stream state mints this once on `/init` and never re-issues
/// it; only [`STATE_KEY`], the cursor, comes back per turn. A client must
/// echo it on every subsequent request: the server may resolve it from a
/// cache while one is warm, but a continuation landing on a process that
/// never saw the `/init` has only the client's copy to work from.
pub const CALL_STATE_KEY: &str = "vgi_rpc.call_state#b64";
pub const CANCEL_KEY: &str = "vgi_rpc.cancel";

/// Pointer-batch keys — the only two an external-location pointer carries on
/// the wire (WIRE_PROTOCOL.md §12).
pub const LOCATION_KEY: &str = "vgi_rpc.location";
pub const LOCATION_SHA256_KEY: &str = "vgi_rpc.location.sha256";

/// Provenance keys, stamped by the **reader** at resolve time and never
/// written by a producer. [`LOCATION_FETCH_MS_KEY`] is the elapsed fetch time
/// and [`LOCATION_SOURCE_KEY`] the URL that was actually fetched; a pointer on
/// the wire MUST NOT carry either, because a writer's guess at the source is
/// not a URL anyone fetched.
pub const LOCATION_FETCH_MS_KEY: &str = "vgi_rpc.location.fetch_ms";
pub const LOCATION_SOURCE_KEY: &str = "vgi_rpc.location.source";

pub const PROTOCOL_NAME_KEY: &str = "vgi_rpc.protocol_name";
pub const DESCRIBE_VERSION_KEY: &str = "vgi_rpc.describe_version";
pub const PROTOCOL_HASH_KEY: &str = "vgi_rpc.protocol_hash";
pub const PROTOCOL_VERSION_KEY: &str = "vgi_rpc.protocol_version";

pub const SHM_OFFSET_KEY: &str = "vgi_rpc.shm_offset";
pub const SHM_LENGTH_KEY: &str = "vgi_rpc.shm_length";
pub const SHM_SOURCE_KEY: &str = "vgi_rpc.shm_source";
pub const SHM_SEGMENT_NAME_KEY: &str = "vgi_rpc.shm_segment_name";
pub const SHM_SEGMENT_SIZE_KEY: &str = "vgi_rpc.shm_segment_size";

/// Transport capability negotiation (`__transport_options__` request/response
/// metadata, `vgi_rpc.transport.*` namespace). Each capability is one
/// `vgi_rpc.transport.<name>` key with a string value; unknown keys are
/// ignored, so the set is open-ended. Mirrors Python `vgi_rpc.metadata`.
pub const TRANSPORT_SHM_KEY: &str = "vgi_rpc.transport.shm";

pub const TRACEPARENT_KEY: &str = "traceparent";
pub const TRACESTATE_KEY: &str = "tracestate";

/// Build a single `(key, value)` metadata entry with minimal ceremony.
#[inline]
pub fn md_entry(k: &str, v: impl Into<String>) -> (String, String) {
    (k.to_string(), v.into())
}

/// Fluent builder for a `Metadata` map.
#[derive(Default, Debug)]
pub struct MetadataBuilder {
    entries: std::collections::HashMap<String, String>,
}

impl MetadataBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `(k, v)`.
    pub fn push(mut self, k: &str, v: impl Into<String>) -> Self {
        self.entries.insert(k.to_string(), v.into());
        self
    }

    /// Insert `(k, v)` only when `v` is non-empty.
    pub fn push_if_non_empty(mut self, k: &str, v: impl Into<String>) -> Self {
        let s = v.into();
        if !s.is_empty() {
            self.entries.insert(k.to_string(), s);
        }
        self
    }

    /// Extend from an iterator.
    pub fn extend<I>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        self.entries.extend(it);
        self
    }

    pub fn build(self) -> std::collections::HashMap<String, String> {
        self.entries
    }
}
