//! vgi-rpc Rust conformance worker.
//!
//! Supports stdin/stdout (default), `--http` (print `PORT:<n>`), and
//! `--unix <path>` (print `UNIX:<path>`) modes, mirroring the Go worker.
//!
//! SIGTERM / SIGINT trigger graceful shutdown of HTTP and unix listeners.

mod conformance;
mod fake_storage;

use std::io::{self, Write};
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // --access-log <path> may appear anywhere on the command line. Forward it
    // to the existing VGI_ACCESS_LOG plumbing in conformance::build_server.
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "--access-log" {
            // SAFETY: set_var is unsafe in newer std but still used; suppress with allow.
            std::env::set_var("VGI_ACCESS_LOG", &args[i + 1]);
            break;
        }
    }

    if args.len() > 1 && args[1] == "--http" {
        let server = Arc::new(conformance::build_server());
        let strict = args.iter().any(|a| a == "--strict");
        let max_resp = parse_usize_flag(&args, "--max-response-bytes");
        let max_ext = parse_usize_flag(&args, "--max-externalized-response-bytes");
        run_http(server, false, strict, max_resp, max_ext);
        return;
    }

    if args.len() > 1 && args[1] == "--http-auth" {
        // Run the HTTP transport with a reject-all `authenticate`
        // callback, used by the conformance suite's TestHealth to
        // assert that `/health` bypasses auth while RPC endpoints
        // return 401.
        let server = Arc::new(conformance::build_server());
        run_http(server, true, false, None, None);
        return;
    }

    // `--http-with-storage <base_url> [--zstd] [--externalize-threshold N]
    //  [--max-request-bytes N]` wires the conformance worker against the
    // external-location feature for the upstream TestExternalLocation suite,
    // and (with threshold=1, max-request-bytes=1MiB) the
    // ``http_externalize_always`` transport variant that re-runs the entire
    // conformance suite forcing every non-empty response batch to externalize.
    // `<base_url>` is the `vgi_rpc.conformance.fake_storage` HTTP service.
    if args.len() > 2 && args[1] == "--http-with-storage" {
        let storage_url = args[2].clone();
        let zstd = args.iter().any(|a| a == "--zstd");
        let threshold = parse_usize_flag(&args, "--externalize-threshold").unwrap_or(16 * 1024);
        // Inline-request cap is independent of the externalize threshold so
        // the ``externalize-always`` mode (threshold=1, cap=1MiB) keeps
        // normal-sized request bodies flowing inline. Defaults to 4096 to
        // preserve the previous fixed cap for the existing storage tests.
        let max_req = parse_usize_flag(&args, "--max-request-bytes").unwrap_or(4096);
        run_http_with_storage(&storage_url, zstd, threshold, max_req);
        return;
    }

    if args.len() > 2 && args[1] == "--unix" {
        let server = Arc::new(conformance::build_server());
        server.notify_transport(
            vgi_rpc::TransportKind::Unix,
            vgi_rpc::TransportCapabilities::none(),
        );
        run_unix(server, &args[2]);
        return;
    }

    // Default: stdio.
    //
    // `io::stdout().lock()` is wrapped in a `LineWriter` that flushes on
    // any `\n` byte; in binary Arrow IPC data those bytes are common, so
    // it triggers a write syscall every ~1 KB. Wrap explicitly with a
    // generous `BufWriter` so the IPC writer's many small `write_all`
    // calls coalesce into a few large writes. `stdin().lock()` already
    // has an 8 KB buffer; bump it for symmetry on large inbound batches.
    let server = Arc::new(conformance::build_server());
    // SHM is opportunistic per-request; the worker is built against
    // `vgi-rpc[shm]` so the capability is always present here.
    server.notify_transport(
        vgi_rpc::TransportKind::Pipe,
        vgi_rpc::TransportCapabilities::shm(),
    );
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut r = io::BufReader::with_capacity(1024 * 1024, stdin.lock());
    let mut w = io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
    server.serve(&mut r, &mut w);
    let _ = w.flush();
}

#[allow(dead_code)]
fn build_server_with_storage(storage_url: &str, zstd: bool) -> vgi_rpc::RpcServer {
    use std::sync::Arc as StdArc;
    use vgi_rpc::external::{Compression, ExternalLocationConfig};
    let storage = StdArc::new(fake_storage::FakeStorage::new(storage_url));
    let fetcher = StdArc::new(vgi_rpc_s3::HttpFetcher::new());
    let mut cfg = ExternalLocationConfig::new(storage, fetcher)
        .with_threshold_bytes(16 * 1024)
        .with_url_validator(vgi_rpc::external::any_url_validator());
    if zstd {
        cfg = cfg.with_compression(Compression::Zstd(0));
    }
    conformance::build_server_with_external(Some(cfg))
}

/// Borrow the shared `FakeStorage` instance, used both as the
/// `ExternalStorage` (response externalization) and the
/// `UploadUrlProvider` (client-vended uploads). Constructed once per
/// `--http-with-storage` invocation in [`run_http_with_storage`].
fn build_shared_storage(storage_url: &str) -> std::sync::Arc<fake_storage::FakeStorage> {
    std::sync::Arc::new(fake_storage::FakeStorage::new(storage_url))
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

/// Parse `--flag <N>` from a positional argv slice. Returns None if the
/// flag is absent or has no numeric value following it.
fn parse_usize_flag(args: &[String], flag: &str) -> Option<usize> {
    let idx = args.iter().position(|a| a == flag)?;
    let raw = args.get(idx + 1)?;
    raw.parse::<usize>().ok()
}

fn run_http_with_storage(
    storage_url: &str,
    zstd: bool,
    threshold: usize,
    max_request_bytes: usize,
) {
    use std::sync::Arc as StdArc;
    use vgi_rpc::external::{Compression, ExternalLocationConfig};

    let storage = build_shared_storage(storage_url);
    let fetcher = StdArc::new(vgi_rpc_s3::HttpFetcher::new());
    // Same instance fronts both ExternalStorage (response uploads) and
    // UploadUrlProvider (client-vended request uploads).
    let storage_as_ext: StdArc<dyn vgi_rpc::external::ExternalStorage> = storage.clone();
    let upload_provider: StdArc<dyn vgi_rpc::external::UploadUrlProvider> = storage.clone();
    let mut cfg = ExternalLocationConfig::new(storage_as_ext, fetcher)
        .with_threshold_bytes(threshold)
        .with_url_validator(vgi_rpc::external::any_url_validator());
    if zstd {
        cfg = cfg.with_compression(Compression::Zstd(0));
    }
    let server = Arc::new(conformance::build_server_with_external(Some(cfg)));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        let state = vgi_rpc::http::HttpState::builder()
            .server(server)
            .upload_url_provider(upload_provider)
            .max_request_bytes(max_request_bytes)
            .max_upload_bytes(64 * 1024 * 1024)
            .build();
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

fn run_http(
    server: Arc<vgi_rpc::RpcServer>,
    reject_all_auth: bool,
    strict: bool,
    max_response_bytes_arg: Option<usize>,
    max_externalized_response_bytes_arg: Option<usize>,
) {
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
        // Strict-cap mode: tight body + external caps so the
        // http_response_cap.* conformance tests can deliberately
        // overshoot. Defaults match Python's
        // tests/serve_conformance_http_strict.py (1 MiB).
        let strict_default = 1024 * 1024usize;
        let max_resp = max_response_bytes_arg.or(if strict { Some(strict_default) } else { None });
        let max_ext = max_externalized_response_bytes_arg.or(if strict {
            Some(strict_default)
        } else {
            None
        });
        if let Some(n) = max_resp {
            builder = builder.max_response_bytes(n);
        }
        if let Some(n) = max_ext {
            builder = builder.max_externalized_response_bytes(n);
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
