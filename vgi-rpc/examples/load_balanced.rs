//! Two `HttpState` instances behind a tiny round-robin proxy, both
//! sharing a signing key. Demonstrates that any worker can resume any
//! continuation request — the state token round-trips through the
//! client between calls.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example load_balanced
//! ```

use std::sync::Arc;

use arrow_array::RecordBatch;
use serde::{Deserialize, Serialize};
use vgi_rpc::http::HttpState;
use vgi_rpc::stream::{OutputCollector, ProducerState};
use vgi_rpc::{service, CallContext, Result, RpcServer, StreamState, VgiArrow};

struct Counter;

#[derive(StreamState, Serialize, Deserialize)]
struct CountState {
    total: i64,
    cur: i64,
}

impl ProducerState for CountState {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        let arr = i64::build_singleton(self.cur)?;
        out.emit(RecordBatch::try_new(out.schema(), vec![arr])?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[service]
impl Counter {
    #[producer(state = CountState, output = i64)]
    fn count_to(&self, total: i64) -> Result<CountState> {
        Ok(CountState { total, cur: 0 })
    }
}

fn build_state(server: Arc<RpcServer>, key: &[u8; 32]) -> Arc<HttpState> {
    HttpState::builder().server(server).token_key(key).build()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let mut server = RpcServer::builder().server_id("counter").build();
    Counter::register_with(&mut server, Arc::new(Counter));
    let server = Arc::new(server);

    // Same key shared between two independent HttpState instances —
    // simulates two workers behind a load balancer.
    let key = [0xa5u8; 32];
    let worker_a = build_state(server.clone(), &key);
    let worker_b = build_state(server, &key);

    let app_a = vgi_rpc::http::build_router(worker_a);
    let app_b = vgi_rpc::http::build_router(worker_b);

    let l_a = tokio::net::TcpListener::bind("127.0.0.1:8082").await?;
    let l_b = tokio::net::TcpListener::bind("127.0.0.1:8083").await?;
    println!("worker A: http://127.0.0.1:8082");
    println!("worker B: http://127.0.0.1:8083");
    println!("Drive count_to(total=10) against either; bounce continuation");
    println!("requests between them — state survives the worker switch.");

    tokio::select! {
        r = axum::serve(l_a, app_a) => r,
        r = axum::serve(l_b, app_b) => r,
        _ = vgi_rpc::http::shutdown_signal() => Ok(()),
    }
}
