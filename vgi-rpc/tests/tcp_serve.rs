//! `serve_tcp` serves the raw Arrow-IPC framing over an AF_INET socket — the
//! network analog of `serve_unix` — and self-terminates after the idle timeout
//! once the last client disconnects. The `on_bound` callback reports the actual
//! bound port (resolved from `port = 0`).

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use arrow_array::{RecordBatch, RecordBatchOptions};
use arrow_schema::Schema;
use vgi_rpc::metadata::{REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY};
use vgi_rpc::tcp::TcpIdentityOptions;
use vgi_rpc::wire::{Metadata, StreamWriter};
use vgi_rpc::{peer_identity_primary, IdentityAssurance, MethodInfo, RpcServer, SubjectKind};

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

fn canonical_iroh_preamble() -> Vec<u8> {
    let mut value = vec![
        0x0d,
        0x0a,
        0x0d,
        0x0a,
        0x00,
        0x0d,
        0x0a,
        0x51,
        0x55,
        0x49,
        0x54,
        0x0a,
        0x21,
        0x00,
        0x00,
        0x24,
        vgi_rpc::VGI_IROH_ENDPOINT_TLV,
        0x00,
        0x21,
        0x01,
    ];
    value.extend(0_u8..32);
    value
}

#[test]
fn tcp_worker_authenticates_canonical_forwarded_iroh_identity() {
    let endpoint = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let (identity_tx, identity_rx) = mpsc::channel();
    let mut server = RpcServer::new("tcp-iroh-test");
    let schema = Arc::new(Schema::empty());
    server.register(MethodInfo::unary(
        "whoami",
        schema.clone(),
        schema,
        move |_request, context| {
            let identity = context.peer_evidence.unique_verified_subject("iroh")?;
            identity_tx
                .send((
                    context.auth.authenticated,
                    context.auth.principal.clone(),
                    identity.subject_key().map(str::to_owned),
                    identity.issuer().to_owned(),
                    identity.assurance(),
                    identity.subject_kind(),
                    identity.attributes().get("original_assurance").cloned(),
                ))
                .map_err(|_| vgi_rpc::RpcError::runtime_error("test receiver dropped"))?;
            Ok(None)
        },
    ));

    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let (bound_tx, bound_rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        vgi_rpc::tcp::serve_tcp_with_identity(
            Arc::new(server),
            "127.0.0.1",
            0,
            None,
            server_shutdown,
            TcpIdentityOptions {
                proxy_protocol_v2_required: true,
                trusted_proxy_addresses: BTreeSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST)]),
                iroh_proxy_issuer: Some("production-mesh".into()),
                policy: Some(peer_identity_primary("iroh")),
                ..TcpIdentityOptions::default()
            },
            move |host, port| bound_tx.send((host.to_owned(), port)).unwrap(),
        )
        .unwrap();
    });
    let (host, port) = bound_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut stream = TcpStream::connect((host.as_str(), port)).unwrap();
    let mut request = canonical_iroh_preamble();
    request.extend_from_slice(&empty_body("whoami"));
    stream.write_all(&request).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(!response.is_empty());

    let (authenticated, principal, subject, issuer, assurance, kind, original_assurance) =
        identity_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(authenticated);
    assert_eq!(principal, format!("peer/iroh/production-mesh/{endpoint}"));
    assert_eq!(subject.as_deref(), Some(endpoint));
    assert_eq!(issuer, "production-mesh");
    assert_eq!(assurance, IdentityAssurance::ConfiguredProxy);
    assert_eq!(kind, SubjectKind::Endpoint);
    assert_eq!(
        original_assurance,
        Some(serde_json::Value::String("cryptographic_peer".into()))
    );

    shutdown.store(true, Ordering::Relaxed);
    handle.join().unwrap();
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
