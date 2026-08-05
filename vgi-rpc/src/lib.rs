//! vgi-rpc — transport-agnostic RPC framework built on Apache Arrow IPC.
//!
//! This crate provides a server-side implementation compatible with the
//! Python `vgi_rpc` canonical wire protocol. Clients (pipe/subprocess/unix/http)
//! supplied by other languages can drive a [`RpcServer`] transparently.

pub mod access_log;
pub mod arrow_type;
pub mod auth;
#[cfg(feature = "http")]
pub mod crypto;
pub mod errors;
pub mod retry;

#[cfg(feature = "external")]
pub mod external;

#[cfg(feature = "otel")]
pub mod otel;

pub mod hooks;
/// Wire-framing helpers for proxies, routers, and gateways. Unfeatured, so an
/// intermediary needn't pull the server or HTTP stack.
pub mod intermediary;
pub mod introspect;
pub mod log;
pub mod metadata;
#[cfg(feature = "sentry-sdk")]
pub mod sentry_sdk;
#[cfg(feature = "sentry-tracing")]
pub mod sentry_tracing;
pub mod server;
#[cfg(feature = "shm")]
pub mod shm;
pub mod stream;
// stream_codec is pure serde+bincode (no axum/tokio/crypto) and is used by the
// core dispatch path, so it's available without the full `http` stack — keeping
// the crate wasm-buildable. `http` still pulls it in transitively.
#[cfg(feature = "stream-codec")]
pub mod stream_codec;
pub mod tcp;
pub mod transport;
pub mod transport_options;
pub mod unauthorized;
#[cfg(unix)]
pub mod unix;
pub(crate) mod util;
pub mod wire;

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub mod sticky;

pub use access_log::AccessLogHook;
pub use arrow_type::{
    Bytes, Decimal20_4, DictString, FixedBinary, LargeBytes, LargeString, UtcTimestamp, VgiArrow,
};

pub use auth::oauth::OAuthResourceMetadata;
pub use auth::{chain_all, chain_authenticate, AuthContext, AuthRequest, AuthResult, Authenticate};
pub use errors::{Result, RpcError};
#[cfg(feature = "external")]
pub use external::{
    upload_url_params_schema, upload_url_response_schema, MAX_UPLOAD_URL_COUNT, UPLOAD_URL_METHOD,
};
pub use hooks::{
    AccessSink, CallStatistics, ChainHook, DeferredRecord, DispatchHook, DispatchInfo, HookToken,
    SharedHook,
};
pub use intermediary::{
    build_error_stream, find_protocol_version, find_state_token, read_request, read_unary_result,
    write_request, write_unary_result,
};
pub use introspect::{DESCRIBE_METHOD_NAME, DESCRIBE_VERSION};
pub use log::{LogLevel, LogMessage};
pub use retry::RetryConfig;
pub use server::{
    CallContext, MethodInfo, MethodType, Request, RpcServer, RpcServerBuilder, StickySink,
};
#[cfg(feature = "http")]
pub use sticky::{DrainHandle, SessionRegistry};
pub use stream::{ExchangeState, OutputCollector, ProducerState, StreamResult};
pub use transport::{ServeStartHook, TransportCapabilities, TransportKind};

#[cfg(feature = "otel")]
pub use otel::{OtelConfig, OtelHook, OtelMetrics};
#[cfg(feature = "sentry-sdk")]
pub use sentry_sdk::{SentrySdkConfig, SentrySdkHook};
#[cfg(feature = "sentry-tracing")]
pub use sentry_tracing::{TracingSentryConfig, TracingSentryHook};

#[cfg(feature = "macros")]
pub use vgi_rpc_macros::{exchange, param, producer, service, unary, StreamState, VgiArrow};
