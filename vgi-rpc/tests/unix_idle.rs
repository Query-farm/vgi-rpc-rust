//! Launcher worker contract: `serve_unix` serves over AF_UNIX and
//! self-terminates after the idle timeout once the last client disconnects.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use arrow_array::{RecordBatch, RecordBatchOptions};
use arrow_schema::Schema;
use vgi_rpc::metadata::{REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY};
use vgi_rpc::wire::{Metadata, StreamWriter};
use vgi_rpc::{MethodInfo, RpcServer};

static PATH_ID: AtomicU64 = AtomicU64::new(1);

fn socket_path(label: &str) -> String {
    std::env::temp_dir()
        .join(format!(
            "vgi-{label}-{}-{}.sock",
            std::process::id(),
            PATH_ID.fetch_add(1, Ordering::Relaxed)
        ))
        .to_string_lossy()
        .into_owned()
}

fn empty_server() -> Arc<RpcServer> {
    Arc::new(RpcServer::new("listener-test"))
}

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
    let path = socket_path("idle");

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
    assert!(!std::path::Path::new(&path).exists());
}

#[test]
fn unix_listener_refuses_regular_files_and_symlinks() {
    let regular = socket_path("regular");
    std::fs::write(&regular, b"keep me").unwrap();
    let err = vgi_rpc::unix::serve_unix(
        empty_server(),
        &regular,
        None,
        Arc::new(AtomicBool::new(true)),
        || panic!("must not bind over a regular file"),
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&regular).unwrap(), b"keep me");

    let target = socket_path("target");
    let link = socket_path("symlink");
    std::fs::write(&target, b"target").unwrap();
    symlink(&target, &link).unwrap();
    let err = vgi_rpc::unix::serve_unix(
        empty_server(),
        &link,
        None,
        Arc::new(AtomicBool::new(true)),
        || panic!("must not bind over a symlink"),
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&target).unwrap(), b"target");
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());

    std::fs::remove_file(regular).unwrap();
    std::fs::remove_file(link).unwrap();
    std::fs::remove_file(target).unwrap();
}

#[test]
fn unix_listener_refuses_an_active_socket() {
    let path = socket_path("active");
    let existing = UnixListener::bind(&path).unwrap();
    let err = vgi_rpc::unix::serve_unix(
        empty_server(),
        &path,
        None,
        Arc::new(AtomicBool::new(true)),
        || panic!("must not replace an active listener"),
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    assert!(UnixStream::connect(&path).is_ok());
    drop(existing);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn unix_shutdown_interrupts_a_stalled_connection() {
    let path = socket_path("shutdown");
    let shutdown = Arc::new(AtomicBool::new(false));
    let (bound_tx, bound_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let server_shutdown = shutdown.clone();
    let server_path = path.clone();
    let handle = std::thread::spawn(move || {
        vgi_rpc::unix::serve_unix(
            empty_server(),
            &server_path,
            None,
            server_shutdown,
            move || {
                bound_tx.send(()).unwrap();
            },
        )
        .unwrap();
        done_tx.send(()).unwrap();
    });
    bound_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let stalled = UnixStream::connect(&path).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    shutdown.store(true, Ordering::Relaxed);
    done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("shutdown must interrupt a connection stalled before its first frame");
    handle.join().unwrap();
    drop(stalled);
}

#[test]
fn unix_cleanup_does_not_unlink_a_replacement_file() {
    let path = socket_path("replacement");
    let shutdown = Arc::new(AtomicBool::new(false));
    let (bound_tx, bound_rx) = mpsc::channel();
    let server_shutdown = shutdown.clone();
    let server_path = path.clone();
    let handle = std::thread::spawn(move || {
        vgi_rpc::unix::serve_unix(
            empty_server(),
            &server_path,
            None,
            server_shutdown,
            move || {
                bound_tx.send(()).unwrap();
            },
        )
        .unwrap();
    });
    bound_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    shutdown.store(true, Ordering::Relaxed);
    handle.join().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    std::fs::remove_file(path).unwrap();
}
