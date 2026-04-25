//! vgi-rpc Rust conformance worker.
//!
//! Supports stdin/stdout (default), `--http` (print `PORT:<n>`), and
//! `--unix <path>` (print `UNIX:<path>`) modes, mirroring the Go worker.
//!
//! SIGTERM / SIGINT trigger graceful shutdown of HTTP and unix listeners.

mod conformance;

use std::io::{self, Write};
use std::sync::Arc;

fn main() {
    let server = Arc::new(conformance::build_server());
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--http" {
        run_http(server, false);
        return;
    }

    if args.len() > 1 && args[1] == "--http-auth" {
        // Run the HTTP transport with a reject-all `authenticate`
        // callback, used by the conformance suite's TestHealth to
        // assert that `/health` bypasses auth while RPC endpoints
        // return 401.
        run_http(server, true);
        return;
    }

    if args.len() > 2 && args[1] == "--unix" {
        run_unix(server, &args[2]);
        return;
    }

    // Default: stdio.
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut r = stdin.lock();
    let mut w = stdout.lock();
    server.serve(&mut r, &mut w);
    let _ = w.flush();
}

fn run_unix(server: Arc<vgi_rpc::RpcServer>, path: &str) {
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).expect("bind unix socket");
    listener.set_nonblocking(true).ok();
    println!("UNIX:{path}");
    io::stdout().flush().ok();

    // SIGTERM/SIGINT → flip the flag → main loop breaks.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let sd = shutdown.clone();
        let _ = ctrlc::try_set_handler(move || {
            sd.store(true, Ordering::Relaxed);
        });
    }

    let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut conn, _)) => {
                conn.set_nonblocking(false).ok();
                let srv = server.clone();
                threads.push(std::thread::spawn(move || {
                    let reader = match conn.try_clone() {
                        Ok(r) => r,
                        Err(_) => return,
                    };
                    let mut reader = reader;
                    srv.serve(&mut reader, &mut conn);
                }));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
    // Drop listener and clean up the socket path.
    drop(listener);
    let _ = std::fs::remove_file(path);
    // Wait briefly for in-flight connections to wrap up.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    for t in threads {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let _ = t.join();
    }
}

fn run_http(server: Arc<vgi_rpc::RpcServer>, reject_all_auth: bool) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        let mut builder = vgi_rpc::http::HttpState::builder().server(server);
        if reject_all_auth {
            // Reject every request with PermissionError → mapped to 401.
            // /health bypasses authenticate_request entirely, so it stays 200.
            builder = builder
                .authenticate(std::sync::Arc::new(|_req| {
                    Err(vgi_rpc::RpcError::permission_error(
                        "auth required (conformance test fixture)",
                    ))
                }))
                .prefix("/vgi");
        }
        let state = builder.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tcp");
        let port = listener.local_addr().unwrap().port();
        println!("PORT:{port}");
        io::stdout().flush().ok();
        vgi_rpc::http::serve_with_shutdown(state, listener)
            .await
            .expect("axum serve");
    });
}
