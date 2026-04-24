//! vgi-rpc — transport-agnostic RPC framework built on Apache Arrow IPC.
//!
//! This crate provides a server-side implementation compatible with the
//! Python `vgi_rpc` canonical wire protocol. Clients (pipe/subprocess/unix/http)
//! supplied by other languages can drive a [`RpcServer`] transparently.

pub mod access_log;
pub mod auth;
pub mod errors;
pub mod hooks;
pub mod introspect;
pub mod log;
pub mod metadata;
pub(crate) mod probe;
pub mod server;
pub mod stream;
pub(crate) mod util;
pub mod wire;

#[cfg(feature = "http")]
pub mod http;

pub use access_log::AccessLogHook;
pub use auth::{chain_all, chain_authenticate, AuthContext, AuthRequest, AuthResult, Authenticate};
pub use errors::{Result, RpcError};
pub use hooks::{CallStatistics, ChainHook, DispatchHook, DispatchInfo, HookToken, SharedHook};
pub use introspect::{DESCRIBE_METHOD_NAME, DESCRIBE_VERSION};
pub use log::{LogLevel, LogMessage};
pub use server::{CallContext, MethodInfo, MethodType, RpcServer, RpcServerBuilder};
pub use stream::{ExchangeState, OutputCollector, ProducerState, StreamResult};
