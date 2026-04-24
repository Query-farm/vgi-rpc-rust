//! HTTP transport (axum). Feature-gated behind the `http` feature.
//!
//! Not yet implemented; added to allow compilation.

use crate::server::RpcServer;
use std::sync::Arc;

/// Placeholder HTTP server wrapper — real implementation lands in a follow-up.
pub struct HttpServer {
    pub inner: Arc<RpcServer>,
}

impl HttpServer {
    pub fn new(server: Arc<RpcServer>) -> Self {
        Self { inner: server }
    }
}
