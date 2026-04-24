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
        run_http(server);
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

fn run_http(server: Arc<vgi_rpc::RpcServer>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        let state = vgi_rpc::http::HttpState::new(server);
        let app = vgi_rpc::http::build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tcp");
        let port = listener.local_addr().unwrap().port();
        println!("PORT:{port}");
        io::stdout().flush().ok();
        let shutdown = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
                let mut intr = signal(SignalKind::interrupt()).expect("install SIGINT handler");
                tokio::select! {
                    _ = term.recv() => {},
                    _ = intr.recv() => {},
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        };
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .expect("axum serve");
    });
}
