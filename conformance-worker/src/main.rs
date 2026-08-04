//! vgi-rpc Rust conformance worker.
//!
//! Supports stdin/stdout (default), `--http` (print `PORT:<n>`),
//! `--unix <path>` (print `UNIX:<path>`), and `--tcp [HOST:]PORT` (print
//! `TCP:<host>:<port>`) modes, mirroring the Go worker. `--unix`/`--tcp` honour
//! the launcher worker contract: `--idle-timeout <SEC>` self-terminates the
//! worker after a quiet period. The `--tcp` host defaults to loopback
//! (`127.0.0.1`) and carries no auth/TLS — trusted networks only.
//!
//! SIGTERM / SIGINT trigger graceful shutdown of HTTP, unix, and tcp listeners.
//!
//! `--no-compression` may appear anywhere on the command line and disables
//! response compression on **every** HTTP path, so the server advertises a
//! present-but-empty `VGI-Supported-Encodings`. It backs the shared
//! conformance case `test_empty_advertisement_means_never_compressed`: that
//! state is a *server configuration* ("I can produce no codecs") which no
//! client request can induce — `identity` is the client-side opt-out and is
//! covered separately.

mod conformance;
mod fake_storage;

use std::io::{self, Write};
use std::sync::Arc;

/// Header letting a conformance request name the reason it wants refused
/// with, so the suite can prove this server *discriminates* between reason
/// codes rather than stamping one constant on every 401.
///
/// A fixture affordance, never a protocol behaviour — nothing outside the
/// conformance worker reads it.
const CONFORMANCE_REASON_HEADER: &str = "x-conformance-auth-reason";

/// Reject every request, with the reason the caller named when it named one
/// the spec allows a request to ask for.
///
/// `proxy_required` is deliberately unreachable here: the spec derives it
/// from server configuration, never from the request, so a worker that let a
/// caller summon it would model the contract wrong. Anything unrecognised
/// falls through to the unclassified path.
fn reject_all(req: &vgi_rpc::auth::AuthRequest) -> vgi_rpc::auth::AuthResult {
    use vgi_rpc::unauthorized::AuthReason;
    let requested = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(CONFORMANCE_REASON_HEADER))
        .map(|(_, v)| v.as_str());
    let reason = match requested {
        Some("missing_credential") => Some(AuthReason::MissingCredential),
        Some("invalid_credential") => Some(AuthReason::InvalidCredential),
        Some("expired_credential") => Some(AuthReason::ExpiredCredential),
        Some("insufficient_scope") => Some(AuthReason::InsufficientScope),
        _ => None,
    };
    match reason {
        // The detail is the reason code itself so the suite can assert the
        // header and the JSON body agree without pinning prose.
        Some(r) => Err(vgi_rpc::RpcError::auth_failure(r, r.as_str())),
        // ValueError, not PermissionError: the latter is a *classified*
        // rejection meaning "identified but not permitted", so it would land
        // on insufficient_scope. This branch is the unclassified one and must
        // reach the `unauthorized` fallback. Mirrors the reference worker.
        None => Err(vgi_rpc::RpcError::value_error(
            "auth required (conformance test fixture)",
        )),
    }
}

/// Fixed conformance values for the token-introspection group, mirroring the
/// module constants in the shared `_pytest_suite.py`. A port supplying
/// `conformance_http_introspect_port` MUST configure exactly these: the shared
/// tests post the subject credential and assert the principal, so they are part
/// of the fixture's contract rather than decoration.
mod introspect_fixture {
    pub const INTROSPECTOR: &str = "conformance-introspector";
    pub const SUBJECT_TOKEN: &str = "conformance-opaque-subject-token";
    pub const SUBJECT_PRINCIPAL: &str = "subject@conformance.example";
    pub const SUBJECT_TOKEN_NAME: &str = "conformance-subject";
    /// A JWS-shaped credential the resolver *would* resolve. Deliberately
    /// resolvable: against an unknown JWS a port with no shape guard rejects it
    /// as unknown and passes the test for the wrong reason. Made resolvable,
    /// the guard is the only thing that can produce a rejection.
    pub const JWS_TRAP_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
}

/// Resolve the one fixed subject credential the shared tests post.
fn conformance_resolve_token(
    token: &str,
) -> Result<Option<vgi_rpc::auth::introspect::TokenIdentity>, vgi_rpc::RpcError> {
    use introspect_fixture::*;
    Ok(
        (token == SUBJECT_TOKEN || token == JWS_TRAP_TOKEN).then(|| {
            vgi_rpc::auth::introspect::TokenIdentity::new(SUBJECT_PRINCIPAL)
                .with_token_name(SUBJECT_TOKEN_NAME)
        }),
    )
}

/// Resolve the principal named in `X-Conformance-Principal`, or stay anonymous.
///
/// Naming yourself in a header is obviously not authentication — it is the
/// cheapest thing every port can implement identically, and the cases that use
/// it only need two identities to be distinguishable. Requests without the
/// header stay anonymous rather than being rejected: the suite probes /health
/// and the capability endpoint before it authenticates anything.
fn principal_from_header(req: &vgi_rpc::auth::AuthRequest) -> vgi_rpc::auth::AuthResult {
    Ok(match req.header("x-conformance-principal") {
        Some(principal) if !principal.is_empty() => {
            vgi_rpc::auth::AuthContext::for_principal("conformance", principal)
        }
        _ => vgi_rpc::auth::AuthContext::anonymous(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // The access-log flags may appear anywhere on the command line. Forward
    // them to the VGI_ACCESS_LOG* plumbing in conformance::build_server,
    // mirroring the Python reference's flag names and env vars.
    for (flag, var) in [
        ("--access-log", "VGI_ACCESS_LOG"),
        ("--access-log-sample", "VGI_ACCESS_LOG_SAMPLE"),
        ("--access-log-queue-size", "VGI_ACCESS_LOG_QUEUE_SIZE"),
        (
            "--access-log-max-record-bytes",
            "VGI_ACCESS_LOG_MAX_RECORD_BYTES",
        ),
    ] {
        if let Some(value) = parse_str_flag(&args, flag) {
            // SAFETY: set_var is unsafe in newer std but still used; suppress with allow.
            std::env::set_var(var, value);
        }
    }
    if args.iter().any(|a| a == "--access-log-async") {
        std::env::set_var("VGI_ACCESS_LOG_ASYNC", "1");
    }
    // `request_data` is the DEBUG-only field, so a log emitted without this
    // flag never carries it and every rule governing it goes unexercised —
    // the validator only checks it is well-formed *when present*. Mirrors the
    // Python worker's `--access-log-debug`, which exists for the same reason.
    if args.iter().any(|a| a == "--access-log-debug") {
        std::env::set_var("VGI_ACCESS_LOG_DEBUG", "1");
    }

    // Positional-flag scan rather than a per-mode flag, so the opt-out reaches
    // every HTTP state construction below. Wiring only one of them is exactly
    // the bug the Python worker shipped first (it still advertised zstd).
    let no_compression = args.iter().any(|a| a == "--no-compression");

    if args.len() > 1 && args[1] == "--http" {
        let server = Arc::new(conformance::build_server_with_id(
            parse_str_flag(&args, "--server-id").as_deref(),
        ));
        let strict = args.iter().any(|a| a == "--strict");
        let max_resp = parse_usize_flag(&args, "--max-response-bytes");
        let max_ext = parse_usize_flag(&args, "--max-externalized-response-bytes");
        run_http(
            server,
            false,
            strict,
            max_resp,
            max_ext,
            no_compression,
            StickyOpts::from_args(&args),
        );
        return;
    }

    if args.len() > 1 && args[1] == "--http-proof" {
        // Run the HTTP transport gated on proxy proof, so the shared
        // TestProxyProof conformance group can drive this port.
        let server = Arc::new(conformance::build_server());
        run_http_proof(server, &args);
        return;
    }

    if args.len() > 1 && args[1] == "--http-auth" {
        // Run the HTTP transport with a reject-all `authenticate`
        // callback, used by the conformance suite's TestHealth to
        // assert that `/health` bypasses auth while RPC endpoints
        // return 401.
        let server = Arc::new(conformance::build_server());
        run_http(
            server,
            true,
            false,
            None,
            None,
            no_compression,
            StickyOpts::default(),
        );
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
        run_http_with_storage(&storage_url, zstd, threshold, max_req, no_compression);
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

    if args.len() > 2 && args[1] == "--tcp" {
        // Raw TCP transport: same Arrow-IPC framing as `--unix`, only the
        // listening socket differs. No auth/TLS — trusted networks only; the
        // host defaults to loopback (127.0.0.1).
        let server = Arc::new(conformance::build_server());
        server.notify_transport(
            vgi_rpc::TransportKind::Tcp,
            vgi_rpc::TransportCapabilities::none(),
        );
        let (host, port) = parse_tcp_address(&args[2]);
        let idle_timeout = parse_secs_flag(&args, "--idle-timeout")
            .filter(|s| *s > 0.0)
            .map(std::time::Duration::from_secs_f64);
        run_tcp(server, &host, port, idle_timeout);
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
    conformance::build_server_with_external(Some(cfg), None)
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

/// Parse a `[HOST:]PORT` argument into `(host, port)`, defaulting the host to
/// loopback (`127.0.0.1`). `rpartition(':')` lets bare `PORT` work and tolerates
/// host portions that themselves contain colons (e.g. IPv6 literals).
fn parse_tcp_address(address: &str) -> (String, u16) {
    let (host, port_part) = match address.rsplit_once(':') {
        Some((h, p)) => {
            let host = if h.is_empty() { "127.0.0.1" } else { h };
            (host.to_string(), p)
        }
        None => ("127.0.0.1".to_string(), address),
    };
    let port = port_part
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("invalid TCP port in --tcp argument: {address:?}"));
    (host, port)
}

fn run_tcp(
    server: Arc<vgi_rpc::RpcServer>,
    host: &str,
    port: u16,
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
    // self-termination; we just print the `TCP:<host>:<port>` contract line once
    // it is listening (the bound port is resolved when `port = 0`).
    let result = vgi_rpc::tcp::serve_tcp(
        server,
        host,
        port,
        idle_timeout,
        shutdown,
        move |bound_host, bound_port| {
            println!("TCP:{bound_host}:{bound_port}");
            io::stdout().flush().ok();
        },
    );
    if let Err(e) = result {
        eprintln!("failed to bind tcp socket {host}:{port}: {e}");
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
    no_compression: bool,
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
    let server = Arc::new(conformance::build_server_with_external(Some(cfg), None));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        let mut builder = vgi_rpc::http::HttpState::builder()
            .server(server)
            .upload_url_provider(upload_provider)
            .max_request_bytes(max_request_bytes)
            .max_upload_bytes(64 * 1024 * 1024);
        if no_compression {
            builder = builder.disable_response_compression();
        }
        // The CORS fixture points here rather than at the plain worker: the
        // derived exposure check can only catch a missing entry for a header
        // the worker actually advertises, and the upload/size-cap trio only
        // exists in storage mode.
        if let Some(origin) = parse_str_flag(&std::env::args().collect::<Vec<_>>(), "--cors-origin")
        {
            builder = builder.cors_origins(origin);
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

fn parse_str_flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn run_http_proof(server: Arc<vgi_rpc::RpcServer>, args: &[String]) {
    use vgi_rpc::auth::proof::{parse_proof_secrets, proof_authenticate, ProofConfig, ProofMode};

    let secrets = parse_proof_secrets(&parse_str_flag(args, "--proof-secrets").unwrap_or_default())
        .expect("valid --proof-secrets");
    let origin_id =
        parse_str_flag(args, "--proof-origin-id").unwrap_or_else(|| "conformance-origin".into());
    let mode = match parse_str_flag(args, "--proof-mode").as_deref() {
        Some("allow") => ProofMode::Allow,
        Some("off") => ProofMode::Off,
        _ => ProofMode::Require,
    };
    let mut cfg = ProofConfig::new(mode, origin_id, secrets);
    if let Some(skew) = parse_str_flag(args, "--proof-skew").and_then(|s| s.parse().ok()) {
        cfg = cfg.with_skew_seconds(skew);
    }
    if args.iter().any(|a| a == "--proof-no-replay-cache") {
        cfg = cfg.without_replay_cache();
    }
    let gate = proof_authenticate(cfg, None).expect("valid proof config");
    // The gate is opaque to the builder, so state the posture explicitly.
    let advertise = mode == ProofMode::Require;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        let state = vgi_rpc::http::HttpState::builder()
            .server(server)
            .authenticate(gate)
            .proxy_proof_required(advertise)
            .prefix("/vgi")
            .build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        println!("PORT:{port}");
        use std::io::Write as _;
        std::io::stdout().flush().ok();
        vgi_rpc::http::serve_with_shutdown(state, listener)
            .await
            .expect("axum serve");
    });
}

/// Sticky knobs the upstream failure-path fixtures drive.
///
/// Each backs one `TestSticky` case that cannot run against the plain worker;
/// see the reference repo's `docs/sticky-sessions-spec.md` §9.1.
#[derive(Default)]
struct StickyOpts {
    /// `--sticky-ttl <SECONDS>` — short enough that the expiry case can outwait
    /// it. Whole seconds, matching what `VGI-Sticky-Default-TTL` advertises.
    ttl_secs: Option<u64>,
    /// `--token-key <HEX>` — pins the AEAD key so two workers can open each
    /// other's session tokens, leaving `server_id` as the only thing that can
    /// reject one.
    token_key_hex: Option<String>,
    /// `--sticky-auth` — resolve the principal named in
    /// `X-Conformance-Principal` so one worker is reachable as two identities.
    principal_auth: bool,
}

impl StickyOpts {
    fn from_args(args: &[String]) -> Self {
        Self {
            ttl_secs: parse_str_flag(args, "--sticky-ttl").and_then(|v| v.parse::<u64>().ok()),
            token_key_hex: parse_str_flag(args, "--token-key"),
            principal_auth: args.iter().any(|a| a == "--sticky-auth"),
        }
    }
}

fn run_http(
    server: Arc<vgi_rpc::RpcServer>,
    reject_all_auth: bool,
    strict: bool,
    max_response_bytes_arg: Option<usize>,
    max_externalized_response_bytes_arg: Option<usize>,
    no_compression: bool,
    sticky: StickyOpts,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        let mut builder = vgi_rpc::http::HttpState::builder().server(server);
        // Disabling the call-state cache forces every stream continuation
        // down the cache-miss path, so the client's obligation to echo the
        // call token is checked deterministically rather than by luck.
        if std::env::args().any(|a| a == "--no-call-state-cache") {
            builder = builder.call_state_cache_entries(0);
        }
        // `--cors-origin <origin>` backs the shared TestCors group, which
        // needs a worker that grants exactly one origin. Read from argv here
        // rather than threaded through this function's parameter list, same
        // as the cache opt-out above. Absent, the worker stays CORS-off —
        // TestCorsOffMode asserts precisely that of the plain worker.
        if let Some(origin) = parse_str_flag(&std::env::args().collect::<Vec<_>>(), "--cors-origin")
        {
            builder = builder.cors_origins(origin);
        }
        if reject_all_auth {
            // Reject every request with PermissionError → mapped to 401.
            // /health bypasses authenticate_request entirely, so it stays 200.
            builder = builder
                .authenticate(std::sync::Arc::new(reject_all))
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
        if let Some(secs) = sticky.ttl_secs {
            builder = builder.sticky_default_ttl(std::time::Duration::from_secs(secs));
        }
        if let Some(hex) = sticky.token_key_hex.as_deref() {
            builder = builder.token_key_hex(hex);
        }
        // `--introspect` backs the shared TestTokenIntrospection group: the
        // endpoint plus a single-principal allowlist. It implies principal-
        // header auth so the allowlist has something to check — without an
        // identity every caller is anonymous and the group could only ever
        // observe the refusal. Read from argv here rather than threaded through
        // this function's parameter list, same as the two options above.
        let introspect = std::env::args().any(|a| a == "--introspect");
        if sticky.principal_auth || introspect {
            // Unlike the reject-all mode above, this deliberately leaves the
            // prefix at the root — the suite connects to this worker exactly as
            // to the plain one.
            builder = builder.authenticate(std::sync::Arc::new(principal_from_header));
        }
        if introspect {
            builder = builder
                .introspect_resolver(std::sync::Arc::new(conformance_resolve_token))
                .introspect_principals([introspect_fixture::INTROSPECTOR]);
        }
        if no_compression {
            builder = builder.disable_response_compression();
        }
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
