//! vgi-rpc — transport-agnostic RPC framework built on Apache Arrow IPC.
//!
//! This crate provides a server-side implementation compatible with the
//! Python `vgi_rpc` canonical wire protocol. Clients (pipe/subprocess/unix/http)
//! supplied by other languages can drive a [`RpcServer`] transparently.

pub mod errors;
pub mod log;
pub mod metadata;
pub mod probe;
pub mod server;
pub mod stream;
pub mod wire;

#[cfg(feature = "http")]
pub mod http;

pub use errors::{Result, RpcError};
pub use log::{LogLevel, LogMessage};
pub use server::{CallContext, RpcServer};
pub use stream::{ExchangeState, OutputCollector, ProducerState, StreamResult};
