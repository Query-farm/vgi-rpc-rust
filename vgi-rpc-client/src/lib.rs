//! Blocking client for the [`vgi-rpc`](vgi_rpc) Arrow-IPC RPC framework.
//!
//! Mirrors the canonical Python `vgi_rpc` client over subprocess/stdio,
//! AF_UNIX, TCP, HTTP, optional native HTTP-over-Iroh, and the POSIX
//! shared-memory side-channel.
//! The client is *dynamic* and schema-first: callers build the params
//! `RecordBatch` (params-as-columns, one row) and receive the result batch,
//! matching the schema-driven server model.
//!
//! ```no_run
//! use vgi_rpc_client::RpcClient;
//! use arrow_array::{RecordBatch, StringArray};
//! use arrow_schema::{DataType, Field, Schema};
//! use std::sync::Arc;
//!
//! let mut client = RpcClient::connect(&["my-worker"]).unwrap();
//! let schema = Arc::new(Schema::new(vec![Field::new("value", DataType::Utf8, false)]));
//! let params = RecordBatch::try_new(schema, vec![Arc::new(StringArray::from(vec!["hi"]))]).unwrap();
//! let (result, _md) = client.call_unary("echo_string", &params, None).unwrap();
//! ```

pub mod client;
pub mod envelope;
pub mod introspect;
pub mod request;
pub mod transport;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "iroh")]
pub mod httpi;

#[cfg(feature = "http")]
pub use http::{
    HttpClient, HttpClientBuilder, HttpServerCapabilities, HttpStreamSession, UploadUrl,
};

#[cfg(feature = "iroh")]
pub use httpi::{HttpiClientBuilder, HttpiTarget};

pub use client::{ClientTransportOptions, OnLog, RpcClient, StreamKind, StreamSession};
pub use envelope::{classify, BatchKind};
pub use introspect::{MethodDescription, ServiceDescription};
pub use transport::{
    PipeTransport, Socks5hProxy, StderrMode, SubprocessTransport, TcpTransport, Transport,
};

#[cfg(unix)]
pub use transport::UnixTransport;

// Re-export the shared wire types so downstreams need only this crate.
pub use vgi_rpc::errors::{Result, RpcError};
pub use vgi_rpc::log::{LogLevel, LogMessage};
pub use vgi_rpc::wire::{md_get, Metadata};
