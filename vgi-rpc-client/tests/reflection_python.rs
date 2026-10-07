//! `list_protocols` / `describe_protocol` against the Python reference
//! conformance server (`python -m vgi_rpc.conformance._cli`), on every
//! transport it serves: subprocess pipe, shm pipe, unix, TCP and HTTP.
//!
//! The reference hosts reflection only when started with `--describe`
//! (`enable_describe=True`), which is what lets these tests reach a real
//! server *without* reflection -- a Rust server always hosts it.
//!
//! Ignored by default because it needs the reference installed; CI runs it
//! with `VGI_RPC_PYTHON` pointing at that interpreter:
//! `cargo test -p vgi-rpc-client --all-features --test reflection_python -- --ignored`.

#![cfg(all(unix, feature = "reqwest"))]

use std::env;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::{Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use vgi_rpc_client::{
    describe_protocol, list_protocols, HttpClient, ReflectionError, ReflectionTarget, RpcClient,
};

const PRIMARY: &str = "ConformanceService";
const SECONDARY: &str = "conformance.Secondary.v1";
const REFLECTION: &str = "vgi_rpc.Reflection.v1";
/// The reference primary's declared version; its calls are gated on it
/// (reflection is exempt).
const PRIMARY_VERSION: &str = "2.0.0";

fn python() -> String {
    env::var("VGI_RPC_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

fn worker_cmd(describe: bool) -> Vec<String> {
    let mut cmd = vec![
        python(),
        "-m".to_string(),
        "vgi_rpc.conformance._cli".to_string(),
    ];
    if describe {
        cmd.push("--describe".to_string());
    }
    cmd
}

/// A reference server listening on a socket, killed on drop.
struct Listening {
    child: Child,
    _stdout: BufReader<ChildStdout>,
    ready: String,
}

impl Listening {
    fn start(describe: bool, args: &[&str]) -> Self {
        let cmd = worker_cmd(describe);
        let mut child = Command::new(&cmd[0])
            .args(&cmd[1..])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("start Python reference server with {cmd:?}: {e}"));
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        stdout.read_line(&mut ready).unwrap();
        Self {
            child,
            _stdout: stdout,
            ready: ready.trim().to_string(),
        }
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn utf8_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Utf8, false)]))
}

fn echo_params(value: &str) -> RecordBatch {
    RecordBatch::try_new(
        utf8_schema("value"),
        vec![Arc::new(StringArray::from(vec![value]))],
    )
    .unwrap()
}

fn produce_params(n: i64) -> RecordBatch {
    RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new(
            "count",
            DataType::Int64,
            false,
        )])),
        vec![Arc::new(Int64Array::from(vec![n]))],
    )
    .unwrap()
}

/// What each client type needs for the "still usable" checks.
trait Conn: ReflectionTarget {
    fn echo(&mut self, value: &str) -> String;
    fn produce(&mut self, n: i64) -> usize;
}

impl Conn for RpcClient {
    fn echo(&mut self, value: &str) -> String {
        let (b, _) = self
            .call_unary("echo_string", &echo_params(value), None)
            .unwrap();
        b.column(0).as_string::<i32>().value(0).to_string()
    }

    fn produce(&mut self, n: i64) -> usize {
        let mut s = self
            .open_producer("produce_n", &produce_params(n), None, false)
            .unwrap();
        let mut rows = 0;
        while let Some((b, _)) = s.tick().unwrap() {
            rows += b.num_rows();
        }
        rows
    }
}

impl Conn for HttpClient {
    fn echo(&mut self, value: &str) -> String {
        let (b, _) = self
            .call_unary("echo_string", &echo_params(value), None)
            .unwrap();
        b.column(0).as_string::<i32>().value(0).to_string()
    }

    fn produce(&mut self, n: i64) -> usize {
        let mut s = self
            .open_producer("produce_n", &produce_params(n), None, false)
            .unwrap();
        let mut rows = 0;
        while let Some((b, _)) = s.tick().unwrap() {
            rows += b.num_rows();
        }
        rows
    }
}

/// Listing, describing, the unknown name, and the connection carrying calls
/// between and after.
fn exercise<C: Conn>(client: &mut C) {
    assert_eq!(client.echo("a"), "a");
    let hosted = list_protocols(client).unwrap();
    let names: Vec<&str> = hosted.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, [PRIMARY, SECONDARY, REFLECTION]);
    for p in &hosted {
        assert_eq!(p.hash.len(), 64, "{p:?}");
        assert!(!p.deprecated);
        assert!(p.features.is_empty());
    }

    let desc = describe_protocol(client, PRIMARY).unwrap();
    assert_eq!(desc.protocol_name, PRIMARY);
    assert_eq!(desc.protocol_hash, hosted[0].hash);
    assert!(!desc.server_id.is_empty());
    assert_eq!(desc.methods["echo_string"].method_type, "unary");
    assert_eq!(desc.methods["produce_n"].is_exchange, Some(false));
    let reflection = describe_protocol(client, REFLECTION).unwrap();
    let mut methods: Vec<&str> = reflection.methods.keys().map(String::as_str).collect();
    methods.sort_unstable();
    assert_eq!(methods, ["describe", "list_protocols"]);

    assert_eq!(client.echo("b"), "b");
    assert_eq!(client.produce(3), 3);

    match describe_protocol(client, "nope.v1") {
        Err(ReflectionError::Rpc(e)) => {
            assert_eq!(e.error_kind.as_deref(), Some("protocol_not_supported"))
        }
        other => panic!("expected protocol_not_supported, got {other:?}"),
    }
    assert_eq!(list_protocols(client).unwrap(), hosted);
    assert_eq!(client.echo("c"), "c");
}

/// A server without reflection: the specific error, the server's fields,
/// never an inferred listing, and the connection still usable.
fn exercise_without_reflection<C: Conn>(client: &mut C) {
    assert_eq!(client.echo("a"), "a");
    match list_protocols(client) {
        Err(ReflectionError::NotSupported(e)) => {
            assert_eq!(e.error_kind.as_deref(), Some("protocol_not_supported"));
            assert_eq!(e.error_code(), "UNIMPLEMENTED");
        }
        other => panic!("expected NotSupported, got {other:?}"),
    }
    assert_eq!(client.echo("b"), "b");
    // describe_protocol lists first, so this is "no reflection", not "no
    // such protocol".
    assert!(matches!(
        describe_protocol(client, PRIMARY),
        Err(ReflectionError::NotSupported(_))
    ));
    assert_eq!(client.produce(2), 2);
}

fn subprocess(describe: bool) -> RpcClient {
    RpcClient::connect(&worker_cmd(describe))
        .unwrap()
        .protocol(PRIMARY)
        .protocol_version(PRIMARY_VERSION)
}

fn http(server: &Listening) -> HttpClient {
    let port: u16 = server
        .ready
        .strip_prefix("PORT:")
        .expect(&server.ready)
        .parse()
        .unwrap();
    // PORT is printed before waitress binds; wait for it to accept.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "server never accepted"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    HttpClient::connect(format!("http://127.0.0.1:{port}"))
        .protocol(PRIMARY)
        .protocol_version(PRIMARY_VERSION)
        .build()
        .unwrap()
}

#[test]
#[ignore = "needs the Python reference (VGI_RPC_PYTHON)"]
fn subprocess_pipe() {
    let mut client = subprocess(true);
    exercise(&mut client);
    assert!(client.is_reusable());
    client.close().unwrap();
}

#[cfg(feature = "shm")]
#[test]
#[ignore = "needs the Python reference (VGI_RPC_PYTHON)"]
fn shm_pipe() {
    let mut client = RpcClient::shm_connect(&worker_cmd(true), 4 * 1024 * 1024)
        .unwrap()
        .protocol(PRIMARY)
        .protocol_version(PRIMARY_VERSION);
    exercise(&mut client);
}

#[test]
#[ignore = "needs the Python reference (VGI_RPC_PYTHON)"]
fn unix() {
    let dir = env::temp_dir().join(format!("vgi-reflect-py-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.sock");
    let server = Listening::start(true, &["--unix", path.to_str().unwrap()]);
    assert!(server.ready.starts_with("UNIX:"), "{}", server.ready);
    // UNIX: is printed before the socket is bound; wait for it to accept.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(&path).is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "server never accepted"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let mut client = RpcClient::unix_connect(&path)
        .unwrap()
        .protocol(PRIMARY)
        .protocol_version(PRIMARY_VERSION);
    exercise(&mut client);
    drop(client);
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "needs the Python reference (VGI_RPC_PYTHON)"]
fn tcp() {
    let server = Listening::start(true, &["--tcp", "127.0.0.1:0"]);
    let addr = server.ready.strip_prefix("TCP:").expect(&server.ready);
    let (host, port) = addr.rsplit_once(':').unwrap();
    let mut client = RpcClient::tcp_connect(host, port.parse().unwrap())
        .unwrap()
        .protocol(PRIMARY)
        .protocol_version(PRIMARY_VERSION);
    exercise(&mut client);
}

#[test]
#[ignore = "needs the Python reference (VGI_RPC_PYTHON)"]
fn http_transport() {
    let server = Listening::start(true, &["--http", "0"]);
    exercise(&mut http(&server));
}

#[test]
#[ignore = "needs the Python reference (VGI_RPC_PYTHON)"]
fn pipe_without_reflection() {
    let mut client = subprocess(false);
    exercise_without_reflection(&mut client);
    assert!(client.is_reusable());
}

#[test]
#[ignore = "needs the Python reference (VGI_RPC_PYTHON)"]
fn http_without_reflection() {
    let server = Listening::start(false, &["--http", "0"]);
    exercise_without_reflection(&mut http(&server));
}
