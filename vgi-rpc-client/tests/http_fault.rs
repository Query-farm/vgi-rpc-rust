//! Fault-injection tests for the HTTP client's timeout + retry behavior,
//! driven by a tiny mock TCP server (we're testing the client's transport
//! resilience, not the protocol, so the server is hand-rolled HTTP).

#![cfg(feature = "http")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arrow_array::cast::AsArray;
use arrow_array::types::Int64Type;
use arrow_array::{Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema};
use std::sync::OnceLock;

use vgi_rpc::retry::RetryConfig;
use vgi_rpc::wire::{write_one_batch, Metadata};
use vgi_rpc_client::{HttpClient, RpcError};

/// Drain whatever the client sent (best-effort, bounded by a short read
/// timeout) so we don't reset the connection mid-write.
fn drain_request(stream: &TcpStream) {
    let s = stream.try_clone().unwrap();
    s.set_read_timeout(Some(Duration::from_millis(150))).ok();
    let mut s = s;
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {
                // Heuristic: a small request arrives in one or two reads; stop
                // after the first non-empty read once we've likely got it all.
                if s.read(&mut buf).map(|n| n == 0).unwrap_or(true) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// A valid HTTP 200 carrying an Arrow unary response (`result` = 42).
fn ok_response() -> Vec<u8> {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "result",
        DataType::Int64,
        false,
    )]));
    let batch =
        RecordBatch::try_new(schema, vec![Arc::new(Int64Array::from(vec![42i64]))]).unwrap();
    let body = write_one_batch(&batch, Some(&Metadata::new())).unwrap();
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apache.arrow.stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(&body);
    resp
}

fn echo_params() -> RecordBatch {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]));
    RecordBatch::try_new(schema, vec![Arc::new(Int64Array::from(vec![42i64]))]).unwrap()
}

/// Spawn a mock server. `behavior(attempt, stream)` runs per accepted
/// connection (1-indexed attempt). Returns the bound base URL.
fn mock_server(behavior: impl Fn(usize, TcpStream) + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut attempt = 0;
        for stream in listener.incoming() {
            attempt += 1;
            if let Ok(s) = stream {
                behavior(attempt, s);
            }
        }
    });
    format!("http://127.0.0.1:{port}")
}

#[test]
fn request_times_out() {
    // Server accepts then stalls forever — the client must give up on its
    // timeout rather than hang. Retry disabled so the test is quick.
    let url = mock_server(|_attempt, stream| {
        drain_request(&stream);
        std::thread::sleep(Duration::from_secs(30)); // never respond
    });
    let mut client = HttpClient::connect(url)
        .timeout(Some(Duration::from_millis(300)))
        .retry(RetryConfig::disabled())
        .build()
        .unwrap();
    let err = client
        .call_unary("echo_int", &echo_params(), None)
        .expect_err("must time out");
    assert_eq!(err.error_type, "TransportError", "got: {err:?}");
}

#[test]
fn retries_then_succeeds() {
    // First two connections are dropped mid-flight (connection error); the
    // third returns a valid response. With max_attempts=3 the call succeeds.
    static SEEN: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Arc::new(AtomicUsize::new(0))).clone();
    let url = mock_server(move |attempt, mut stream| {
        seen.store(attempt, Ordering::SeqCst);
        drain_request(&stream);
        if attempt >= 3 {
            let _ = stream.write_all(&ok_response());
            let _ = stream.flush();
        }
        // attempts 1,2: drop the stream → client sees a connection error.
    });
    let mut client = HttpClient::connect(url)
        .timeout(Some(Duration::from_secs(2)))
        .retry(RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(50),
            multiplier: 2.0,
            jitter: 0.0,
        })
        .build()
        .unwrap();
    let (batch, _md) = client
        .call_unary("echo_int", &echo_params(), None)
        .expect("retry should succeed on the 3rd attempt");
    assert_eq!(batch.column(0).as_primitive::<Int64Type>().value(0), 42);
}

fn http_body(status: &str, body: &[u8]) -> Vec<u8> {
    let mut resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/vnd.apache.arrow.stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body);
    resp
}

#[test]
fn garbage_response_is_error_not_panic() {
    // A 200 with a non-Arrow body must surface a clean error, never a panic
    // or hang (decode-path robustness against a hostile/broken server).
    for body in [
        &b"not arrow at all"[..],
        &b""[..],
        &[0x28, 0xb5, 0x2f, 0xfd, 0x00][..], // zstd-magic-ish junk
        &[0xff, 0xff, 0xff, 0xff, 0x10, 0x00, 0x00, 0x00][..], // truncated IPC frame
    ] {
        let payload = body.to_vec();
        let url = mock_server(move |_a, mut stream| {
            drain_request(&stream);
            let _ = stream.write_all(&http_body("200 OK", &payload));
            let _ = stream.flush();
        });
        let mut client = HttpClient::connect(url)
            .retry(RetryConfig::disabled())
            .build()
            .unwrap();
        // Must return Err (not panic / not hang).
        let r = client.call_unary("echo_int", &echo_params(), None);
        assert!(r.is_err(), "garbage body {body:?} should be an error");
    }
}

#[test]
fn no_retry_exhausted_is_transport_error() {
    // Every connection drops → after exhausting attempts the client surfaces a
    // TransportError (it does not hang or panic).
    let url = mock_server(|_attempt, stream| {
        drain_request(&stream);
        // drop immediately
    });
    let mut client = HttpClient::connect(url)
        .timeout(Some(Duration::from_millis(500)))
        .retry(RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(20),
            multiplier: 2.0,
            jitter: 0.0,
        })
        .build()
        .unwrap();
    let err: RpcError = client
        .call_unary("echo_int", &echo_params(), None)
        .expect_err("all attempts fail");
    assert_eq!(err.error_type, "TransportError");
}
