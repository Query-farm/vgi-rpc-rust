//! vgi-rpc Rust conformance worker.
//!
//! Supports stdin/stdout (default), `--http` (print `PORT:<n>`), and
//! `--unix <path>` (print `UNIX:<path>`) modes, mirroring the Go worker.
//! `--unix` honours the launcher worker contract: `--idle-timeout <SEC>`
//! self-terminates the worker after a quiet period.
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
        // Launcher worker contract: `--idle-timeout SEC` self-terminates the
        // worker after a quiet period so abandoned warm workers don't leak.
        let idle_timeout = parse_secs_flag(&args, "--idle-timeout")
            .filter(|s| *s > 0.0)
            .map(std::time::Duration::from_secs_f64);
        run_unix(server, &args[2], idle_timeout);
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

fn run_unix(
    server: Arc<vgi_rpc::RpcServer>,
    path: &str,
    idle_timeout: Option<std::time::Duration>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};

    // SIGTERM/SIGINT → flip the flag → the accept loop unwinds.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let sd = shutdown.clone();
        let _ = ctrlc::try_set_handler(move || {
            sd.store(true, Ordering::Relaxed);
        });
    }

    // The library helper owns bind / accept / per-connection threads / idle
    // self-termination; we just print the `UNIX:<path>` contract line once it
    // is listening.
    let path_owned = path.to_string();
    let result = vgi_rpc::unix::serve_unix(server, path, idle_timeout, shutdown, move || {
        println!("UNIX:{path_owned}");
        io::stdout().flush().ok();
    });
    if let Err(e) = result {
        eprintln!("failed to bind unix socket {path}: {e}");
        std::process::exit(1);
    }
}

/// Parse `--flag <N>` from a positional argv slice. Returns None if the
/// flag is absent or has no numeric value following it.
fn parse_usize_flag(args: &[String], flag: &str) -> Option<usize> {
    let idx = args.iter().position(|a| a == flag)?;
    let raw = args.get(idx + 1)?;
    raw.parse::<usize>().ok()
}

/// Parse `--flag <SEC>` as fractional seconds (the launcher passes a float).
fn parse_secs_flag(args: &[String], flag: &str) -> Option<f64> {
    let idx = args.iter().position(|a| a == flag)?;
    let raw = args.get(idx + 1)?;
    raw.parse::<f64>().ok()
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
        // Sticky sessions on by default (matches Python's
        // serve_conformance_http.py) so the canonical TestSticky group
        // runs. A fixed marker echo header gives
        // TestSticky::test_echo_header_round_trip a stable contract.
        builder = builder.enable_sticky(true).sticky_echo_headers([(
            "x-vgi-conformance-echo".to_string(),
            "conformance-fixed-marker".to_string(),
        )]);
        let state = builder.build();
        let drain = state.sticky_drain_handle();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tcp");
        let port = listener.local_addr().unwrap().port();
        println!("PORT:{port}");
        io::stdout().flush().ok();
        let app = with_test_drain_route(vgi_rpc::http::build_router(state), drain);
        axum::serve(listener, app)
            .with_graceful_shutdown(vgi_rpc::http::shutdown_signal())
            .await
            .expect("axum serve");
    });
}

/// Attach the test-only `POST/DELETE /__test_drain__` admin endpoint that
/// lets `TestSticky::test_drain_rejects_new_opens` flip the registry's
/// drain flag over the wire without sending SIGTERM. Only mounted when
/// sticky is enabled (the conformance test skips on 404 otherwise).
fn with_test_drain_route(app: axum::Router, drain: Option<vgi_rpc::DrainHandle>) -> axum::Router {
    let Some(handle) = drain else {
        return app;
    };
    let on = handle.clone();
    let off = handle.clone();
    app.route(
        "/__test_drain__",
        axum::routing::post(move || {
            let h = on.clone();
            async move {
                h.drain();
                axum::http::StatusCode::NO_CONTENT
            }
        })
        .delete(move || {
            let h = off.clone();
            async move {
                h.set_draining(false);
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    )
}
