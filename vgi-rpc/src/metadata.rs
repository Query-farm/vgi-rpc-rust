//! Well-known metadata keys used in the vgi-rpc wire protocol.
//!
//! These keys appear as Arrow IPC `custom_metadata` on record batches.

pub const RPC_METHOD_KEY: &str = "vgi_rpc.method";
pub const REQUEST_VERSION_KEY: &str = "vgi_rpc.request_version";
pub const REQUEST_VERSION: &str = "1";
pub const REQUEST_ID_KEY: &str = "vgi_rpc.request_id";

pub const LOG_LEVEL_KEY: &str = "vgi_rpc.log_level";
pub const LOG_MESSAGE_KEY: &str = "vgi_rpc.log_message";
pub const LOG_EXTRA_KEY: &str = "vgi_rpc.log_extra";

pub const SERVER_ID_KEY: &str = "vgi_rpc.server_id";

pub const STATE_KEY: &str = "vgi_rpc.stream_state#b64";
pub const CANCEL_KEY: &str = "vgi_rpc.cancel";

pub const LOCATION_KEY: &str = "vgi_rpc.location";
pub const LOCATION_SHA256_KEY: &str = "vgi_rpc.location.sha256";
pub const LOCATION_FETCH_MS_KEY: &str = "vgi_rpc.location.fetch_ms";

pub const PROTOCOL_NAME_KEY: &str = "vgi_rpc.protocol_name";
pub const DESCRIBE_VERSION_KEY: &str = "vgi_rpc.describe_version";

pub const SHM_OFFSET_KEY: &str = "vgi_rpc.shm_offset";
pub const SHM_LENGTH_KEY: &str = "vgi_rpc.shm_length";

pub const TRACEPARENT_KEY: &str = "traceparent";
pub const TRACESTATE_KEY: &str = "tracestate";
