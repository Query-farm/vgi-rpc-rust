//! vgi-rpc Rust conformance worker.
//!
//! Supports stdin/stdout (default), `--http` (print `PORT:<n>`), and
//! `--unix <path>` (print `UNIX:<path>`) modes, mirroring the Go worker.

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
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).expect("bind unix socket");
    println!("UNIX:{path}");
    io::stdout().flush().ok();

    for conn in listener.incoming() {
        let Ok(mut conn) = conn else { break };
        let srv = server.clone();
        std::thread::spawn(move || {
            let reader = conn.try_clone().unwrap();
            let mut reader = reader;
            srv.serve(&mut reader, &mut conn);
        });
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
        axum::serve(listener, app).await.expect("axum serve");
    });
}
