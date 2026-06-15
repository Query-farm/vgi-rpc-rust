//! Launcher worker contract: `serve_unix` serves over AF_UNIX and
//! self-terminates after the idle timeout once the last client disconnects.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
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
fn unix_worker_serves_then_idle_exits() {
    let path = std::env::temp_dir()
        .join(format!("vgi-idle-{}.sock", std::process::id()))
        .to_string_lossy()
        .into_owned();

    let mut server = RpcServer::new("idle-test");
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
    let p = path.clone();
    let sd = shutdown.clone();
    let handle = std::thread::spawn(move || {
        // 300ms idle timeout; the 60s startup grace never fires because the
        // client connects immediately.
        vgi_rpc::unix::serve_unix(srv, &p, Some(Duration::from_millis(300)), sd, move || {
            bound_tx.send(()).ok();
        })
        .unwrap();
        done_tx.send(()).ok();
    });

    bound_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server should bind and listen");

    // A real round-trip proves the loop actually serves requests.
    {
        let mut stream = UnixStream::connect(&path).expect("connect to worker");
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
