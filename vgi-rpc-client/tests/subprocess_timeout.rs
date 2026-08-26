// Copyright 2025, 2026 Query Farm LLC - https://query.farm

//! Subprocess response deadlines end the connection instead of abandoning a read.

#![cfg(unix)]

use std::path::Path;
use std::time::{Duration, Instant};

use arrow_array::RecordBatch;
use arrow_schema::Schema;
use vgi_rpc::wire::empty_batch;
use vgi_rpc_client::RpcClient;

fn params() -> RecordBatch {
    empty_batch(&Schema::empty()).unwrap()
}

fn stalled_client(entered: &Path, timeout: Duration) -> RpcClient {
    RpcClient::connect_with_timeout(
        &[
            "sh",
            "-c",
            "dd bs=1 count=1 of=/dev/null 2>/dev/null; : > \"$0\"; sleep 60",
            entered.to_str().unwrap(),
        ],
        Some(timeout),
    )
    .unwrap()
}

#[test]
fn a_stalled_response_kills_and_poisons_the_subprocess() {
    let entered = std::env::temp_dir().join(format!(
        "vgi-rpc-timeout-entered-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut client = stalled_client(&entered, Duration::from_secs(2));
    let call = std::thread::spawn(move || {
        let first = client.call_unary("stall", &params(), None);
        let retry_started = Instant::now();
        let second = client.call_unary("late", &params(), None);
        (first, second, retry_started.elapsed(), client.is_reusable())
    });

    let wait_until = Instant::now() + Duration::from_secs(5);
    while !entered.exists() && Instant::now() < wait_until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(entered.exists(), "the worker never consumed the request");

    let (first, second, retry_elapsed, reusable) = call.join().unwrap();
    let first = first.unwrap_err().to_string();
    assert!(first.contains("deadline elapsed"), "{first}");
    let second = second.unwrap_err().to_string();
    assert!(second.contains("poisoned after an RPC timeout"), "{second}");
    assert!(!reusable);
    assert!(retry_elapsed < Duration::from_secs(1));
    let _ = std::fs::remove_file(entered);
}

#[test]
fn a_zero_timeout_immediately_poisons_the_subprocess() {
    let entered = std::env::temp_dir().join(format!("vgi-rpc-zero-timeout-{}", std::process::id()));
    let mut client = stalled_client(&entered, Duration::ZERO);
    let first = client.call_unary("never", &params(), None);
    let first = first.unwrap_err().to_string();
    assert!(first.contains("deadline elapsed"), "{first}");
    assert!(!client.is_reusable());
    let second = client.call_unary("late", &params(), None);
    let second = second.unwrap_err().to_string();
    assert!(second.contains("poisoned after an RPC timeout"), "{second}");
    let _ = std::fs::remove_file(entered);
}
