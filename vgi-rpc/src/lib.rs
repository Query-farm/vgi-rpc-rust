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

#[cfg(feature = "http")]
pub mod external;

#[cfg(feature = "otel")]
pub mod otel;

pub mod hooks;
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
#[cfg(feature = "http")]
pub mod stream_codec;
pub mod transport;
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
pub use hooks::{CallStatistics, ChainHook, DispatchHook, DispatchInfo, HookToken, SharedHook};
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
