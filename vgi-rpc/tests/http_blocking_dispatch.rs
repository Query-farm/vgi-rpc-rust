//! Synchronous RPC callbacks must not occupy Axum's async worker threads.
//!
//! The server API is synchronous by design (the same handlers serve pipe,
//! Unix, TCP, and HTTP). A slow producer turn used to run directly on Tokio's
//! sole worker here, preventing an unrelated unary request from even starting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use arrow_schema::Schema;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{REQUEST_ID_KEY, REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY};
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult};
use vgi_rpc::wire::{empty_batch, write_one_batch};
use vgi_rpc::{CallContext, MethodInfo, Result, RpcServer};

fn request_body(method: &str) -> Vec<u8> {
    let empty = empty_batch(&Schema::empty()).unwrap();
    let metadata = std::collections::HashMap::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
        (REQUEST_ID_KEY.to_string(), format!("{method}-request")),
    ]);
    write_one_batch(&empty, Some(&metadata)).unwrap()
}

async fn post(app: axum::Router, method: &str, stream_init: bool) -> StatusCode {
    let path = if stream_init {
        format!("/{method}/init")
    } else {
        format!("/{method}")
    };
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
            .body(Body::from(request_body(method)))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[derive(Default)]
struct BlockingProbe {
    entered: AtomicBool,
    released: Mutex<bool>,
    release: Condvar,
}

impl BlockingProbe {
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.release.wait(released).unwrap();
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }
}

struct SlowProducer(Arc<BlockingProbe>);

impl ProducerState for SlowProducer {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        self.0.block();
        out.finish();
        Ok(())
    }
}

fn server(probe: Arc<BlockingProbe>) -> Arc<RpcServer> {
    let mut server = RpcServer::builder().server_id("blocking-dispatch").build();
    server.register(MethodInfo::unary(
        "fast",
        Schema::empty().into(),
        Schema::empty().into(),
        |_req, _ctx| Ok(None),
    ));
    server.register(MethodInfo::stream(
        "slow",
        vgi_rpc::server::MethodType::Producer,
        Schema::empty().into(),
        move |_req, _ctx| {
            Ok(StreamResult::producer(
                Schema::empty().into(),
                Box::new(SlowProducer(Arc::clone(&probe))),
            ))
        },
    ));
    Arc::new(server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn slow_producer_turn_does_not_starve_unrelated_http_request() {
    let probe = Arc::new(BlockingProbe::default());
    let app = vgi_rpc::http::build_router(
        HttpState::builder()
            .server(server(Arc::clone(&probe)))
            .build(),
    );
    let slow = tokio::spawn(post(app.clone(), "slow", true));

    // A watchdog bounds the pre-fix failure: without `block_in_place`, the
    // callback below occupies this runtime's sole async worker, so this test
    // future cannot run to release it. With the fix, the replacement worker
    // observes `entered` immediately and sends the concurrent fast request.
    let watchdog_probe = Arc::clone(&probe);
    let watchdog_fired = Arc::new(AtomicBool::new(false));
    let watchdog_flag = Arc::clone(&watchdog_fired);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        watchdog_flag.store(true, Ordering::Release);
        watchdog_probe.release();
    });
    while !probe.entered.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    assert!(
        !watchdog_fired.load(Ordering::Acquire),
        "async runtime resumed only after the deadlock watchdog released the producer"
    );
    let fast = tokio::time::timeout(Duration::from_millis(500), post(app, "fast", false))
        .await
        .expect("fast request was starved by synchronous producer dispatch");
    assert_eq!(fast, StatusCode::OK);

    probe.release();
    assert_eq!(slow.await.unwrap(), StatusCode::OK);
}
