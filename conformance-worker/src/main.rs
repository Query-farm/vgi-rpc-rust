//! vgi-rpc Rust conformance worker.
//!
//! Supports stdin/stdout (default), `--http` (print `PORT:<n>`), and
//! `--unix <path>` (print `UNIX:<path>`) modes, mirroring the Go worker.

mod conformance;

use std::io::{self, Write};
use std::sync::Arc;
use tokio::signal;

fn main() {
    let server = Arc::new(conformance::build_server());
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--http" {
        #[cfg(feature = "http")]
        {
            run_http(server);
            return;
        }
        #[cfg(not(feature = "http"))]
        {
            eprintln!("built without http feature");
            std::process::exit(2);
        }
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

#[cfg(feature = "http")]
fn run_http(_server: Arc<vgi_rpc::RpcServer>) {
    // HTTP implementation lands in a follow-up milestone; for now bail out.
    eprintln!("--http transport not yet implemented");
    std::process::exit(3);
}
