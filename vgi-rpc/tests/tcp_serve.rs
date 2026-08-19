//! `serve_tcp` serves the raw Arrow-IPC framing over an AF_INET socket — the
//! network analog of `serve_unix` — and self-terminates after the idle timeout
//! once the last client disconnects. The `on_bound` callback reports the actual
//! bound port (resolved from `port = 0`).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use arrow_array::{RecordBatch, RecordBatchOptions};
use arrow_schema::Schema;
use vgi_rpc::metadata::{REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY};
use vgi_rpc::wire::{Metadata, StreamWriter};
use vgi_rpc::{MethodInfo, RpcServer};

/// One zero-column, one-row request body for `method`.
fn empty_body(method: &str) -> Vec<u8> {
    let schema = Arc::new(Schema::empty());
    let batch = RecordBatch::try_new_with_options(
        schema.clone(),
        vec![],
        &RecordBatchOptions::new().with_row_count(Some(1)),
    )
    .unwrap();
    let mut md = Metadata::new();
    md.insert(RPC_METHOD_KEY.into(), method.into());
    md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema.as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

#[test]
fn tcp_worker_serves_then_idle_exits() {
    let mut server = RpcServer::new("tcp-test");
    let schema = Arc::new(Schema::empty());
    server.register(MethodInfo::unary(
        "ping",
        schema.clone(),
        schema.clone(),
        |_req, _ctx| Ok(None),
    ));
    let server = Arc::new(server);

    let shutdown = Arc::new(AtomicBool::new(false));
    let (bound_tx, bound_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let srv = server.clone();
    let sd = shutdown.clone();
    let handle = std::thread::spawn(move || {
        // 300ms idle timeout; the 60s startup grace never fires because the
        // client connects immediately. `port = 0` → OS picks a free port,
        // reported back through `on_bound`.
        vgi_rpc::tcp::serve_tcp(
            srv,
            "127.0.0.1",
            0,
            Some(Duration::from_millis(300)),
            sd,
            move |host, port| {
                bound_tx.send((host.to_string(), port)).ok();
            },
        )
        .unwrap();
        done_tx.send(()).ok();
    });

    let (host, port) = bound_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server should bind and listen");
    assert_eq!(host, "127.0.0.1");
    assert_ne!(port, 0, "port 0 must resolve to a real OS-assigned port");

    // A real round-trip proves the loop actually serves requests.
    {
        let mut stream = TcpStream::connect((host.as_str(), port)).expect("connect to worker");
        stream.write_all(&empty_body("ping")).unwrap();
        stream.flush().unwrap();
        // Half-close so the serve loop sees EOF after this one request.
        stream.shutdown(std::net::Shutdown::Write).ok();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).unwrap();
        assert!(!resp.is_empty(), "expected an IPC response stream");
        // Connection drops at end of scope → idle timer re-arms to 300ms.
    }

    // The worker must self-terminate from the idle timeout — we never set the
    // shutdown flag.
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker should idle-exit after the last client disconnects");
    handle.join().unwrap();
    assert!(
        !shutdown.load(Ordering::Relaxed),
        "exit must be from idle timeout, not the shutdown flag"
    );
}

#[test]
fn tcp_shutdown_interrupts_a_stalled_connection() {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (bound_tx, bound_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let server_shutdown = shutdown.clone();
    let handle = std::thread::spawn(move || {
        vgi_rpc::tcp::serve_tcp(
            Arc::new(RpcServer::new("tcp-shutdown-test")),
            "127.0.0.1",
            0,
            None,
            server_shutdown,
            move |host, port| {
                bound_tx.send((host.to_string(), port)).unwrap();
            },
        )
        .unwrap();
        done_tx.send(()).unwrap();
    });
    let (host, port) = bound_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let stalled = TcpStream::connect((host.as_str(), port)).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    shutdown.store(true, Ordering::Relaxed);
    done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("shutdown must interrupt a connection stalled before its first frame");
    handle.join().unwrap();
    drop(stalled);
}
