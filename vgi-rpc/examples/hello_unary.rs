//! Minimal HTTP server exposing two unary RPC methods.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example hello_unary
//! ```
//!
//! Then probe with curl using the Python or Go vgi-rpc client, or
//! point a browser at `http://127.0.0.1:8080/` for the landing page.

use std::sync::Arc;

use vgi_rpc::http::{serve_with_shutdown, HttpState};
use vgi_rpc::{service, Result, RpcServer};

struct Echo;

#[service]
impl Echo {
    /// Echo a string back, prefixed.
    #[unary]
    fn echo(&self, value: String) -> Result<String> {
        Ok(format!("echo: {value}"))
    }

    /// Add two integers.
    #[unary]
    #[param(name = "a", default = 0)]
    #[param(name = "b", default = 0)]
    fn add(&self, a: i64, b: i64) -> Result<i64> {
        Ok(a + b)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let mut server = RpcServer::builder()
        .server_id("hello-unary")
        .protocol_name("Echo")
        .server_version("0.1.0")
        .enable_describe(true)
        .build();
    Echo::register_with(&mut server, Arc::new(Echo));

    let state = HttpState::builder()
        .server(Arc::new(server))
        .signing_key(&[0xau8; 32]) // dev-only — use signing_key_from_env in prod
        .cors_origins("*")
        .build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    println!("listening on http://127.0.0.1:8080");
    serve_with_shutdown(state, listener).await
}
