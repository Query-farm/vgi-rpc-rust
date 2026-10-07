//! `list_protocols` / `describe_protocol`: reflection over a held connection,
//! against in-process Rust servers on every transport this crate reaches
//! without an external worker (pipe, unix, TCP, HTTP). The Python reference
//! server -- including one without reflection -- is driven from
//! `reflection_python.rs`; raw Iroh from `vgi-rpc-iroh/tests/loopback.rs`;
//! HTTP over Iroh from `httpi_roundtrip.rs`.
//!
//! The point of the API is that it reuses the caller's connection, so each
//! byte-stream transport here counts the connections its listener accepted,
//! and the HTTP one routes through a recording executor: reflection that
//! dialled anew, or closed what it was handed, fails here.

#![cfg(unix)]

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use arrow_array::cast::AsArray;
use arrow_array::types::Int64Type;
use arrow_array::{Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use vgi_rpc::conformance_secondary::{conformance_secondary_protocol, SECONDARY_PROTOCOL_NAME};
use vgi_rpc::server::{MethodInfo, MethodType, RpcServer};
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult};
use vgi_rpc::CallContext;
use vgi_rpc_client::{
    describe_protocol, list_protocols, HostedProtocol, PipeTransport, ReflectionError, RpcClient,
};

const PRIMARY: &str = "ConformanceService";
const REFLECTION: &str = "vgi_rpc.Reflection.v1";

fn utf8_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Utf8, false)]))
}

fn i64_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Int64, false)]))
}

struct CountTo {
    n: i64,
    cur: i64,
    schema: SchemaRef,
}

impl ProducerState for CountTo {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> vgi_rpc::Result<()> {
        if self.cur >= self.n {
            out.finish();
            return Ok(());
        }
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![Arc::new(Int64Array::from(vec![self.cur]))],
        )?;
        self.cur += 1;
        out.emit(batch)
    }
}

/// A primary with a unary and a producer, plus the conformance secondary.
fn build_server() -> RpcServer {
    let mut srv = RpcServer::builder()
        .protocol_name(PRIMARY)
        .add_protocol(conformance_secondary_protocol())
        .build();
    let r = utf8_schema("result");
    let r2 = r.clone();
    srv.register(MethodInfo::unary(
        "echo_string",
        utf8_schema("value"),
        r,
        move |req, _ctx| {
            let v = req
                .column("value")
                .unwrap()
                .as_string::<i32>()
                .value(0)
                .to_string();
            Ok(Some(RecordBatch::try_new(
                r2.clone(),
                vec![Arc::new(StringArray::from(vec![v]))],
            )?))
        },
    ));
    let out = i64_schema("value");
    srv.register(MethodInfo::stream(
        "produce_n",
        MethodType::Producer,
        i64_schema("count"),
        move |req, _ctx| {
            let n = req
                .column("count")
                .unwrap()
                .as_primitive::<Int64Type>()
                .value(0);
            Ok(StreamResult::producer(
                out.clone(),
                Box::new(CountTo {
                    n,
                    cur: 0,
                    schema: out.clone(),
                }),
            ))
        },
    ));
    srv
}

fn echo(client: &mut RpcClient, value: &str) -> String {
    let params = RecordBatch::try_new(
        utf8_schema("value"),
        vec![Arc::new(StringArray::from(vec![value]))],
    )
    .unwrap();
    let (batch, _) = client.call_unary("echo_string", &params, None).unwrap();
    batch.column(0).as_string::<i32>().value(0).to_string()
}

fn produce(client: &mut RpcClient, n: i64) -> usize {
    let params = RecordBatch::try_new(
        i64_schema("count"),
        vec![Arc::new(Int64Array::from(vec![n]))],
    )
    .unwrap();
    let mut session = client
        .open_producer("produce_n", &params, None, false)
        .unwrap();
    let mut rows = 0;
    while let Some((batch, _)) = session.tick().unwrap() {
        rows += batch.num_rows();
    }
    rows
}

fn assert_listing(hosted: &[HostedProtocol]) {
    let names: Vec<&str> = hosted.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, [PRIMARY, SECONDARY_PROTOCOL_NAME, REFLECTION]);
    for p in hosted {
        assert_eq!(p.hash.len(), 64, "{p:?}");
        assert!(
            p.hash
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{p:?}"
        );
        assert!(!p.deprecated);
        assert!(p.deprecation_message.is_empty());
        assert!(p.features.is_empty());
    }
    assert_eq!(
        hosted[1].hash,
        vgi_rpc::conformance_secondary::SECONDARY_PROTOCOL_HASH
    );
}

/// The full contract on one held client: listing, describing, the unknown
/// name, and the connection still carrying unary and stream calls between
/// and after.
fn exercise(client: &mut RpcClient) {
    assert_eq!(echo(client, "a"), "a");
    let hosted = list_protocols(client).unwrap();
    assert_listing(&hosted);

    let desc = describe_protocol(client, PRIMARY).unwrap();
    assert_eq!(desc.protocol_name, PRIMARY);
    assert_eq!(desc.protocol_hash, hosted[0].hash);
    assert!(!desc.server_id.is_empty());
    let mut methods: Vec<&str> = desc.methods.keys().map(String::as_str).collect();
    methods.sort_unstable();
    assert_eq!(methods, ["echo_string", "produce_n"]);
    assert_eq!(desc.methods["produce_n"].is_exchange, Some(false));
    let reflection = describe_protocol(client, REFLECTION).unwrap();
    let mut methods: Vec<&str> = reflection.methods.keys().map(String::as_str).collect();
    methods.sort_unstable();
    assert_eq!(methods, ["describe", "list_protocols"]);

    assert_eq!(echo(client, "b"), "b");
    assert_eq!(produce(client, 3), 3);

    match describe_protocol(client, "nope.v1") {
        Err(ReflectionError::Rpc(e)) => {
            assert_eq!(e.error_kind.as_deref(), Some("protocol_not_supported"))
        }
        other => panic!("expected protocol_not_supported, got {other:?}"),
    }

    // The method forms are the same calls.
    assert_eq!(client.list_protocols().unwrap(), hosted);
    assert_eq!(client.describe().unwrap().protocol_name, PRIMARY);
    assert_eq!(echo(client, "c"), "c");
}

#[test]
fn pipe() {
    let (client_sock, server_sock) = UnixStream::pair().unwrap();
    thread::spawn(move || {
        let r = server_sock.try_clone().unwrap();
        build_server().serve(r, server_sock);
    });
    let r = client_sock.try_clone().unwrap();
    let mut client = RpcClient::from_transport(Box::new(PipeTransport::new(
        Box::new(r),
        Box::new(client_sock),
    )))
    .protocol(PRIMARY);
    exercise(&mut client);
}

#[test]
fn client_bound_to_another_protocol() {
    let (client_sock, server_sock) = UnixStream::pair().unwrap();
    thread::spawn(move || {
        let r = server_sock.try_clone().unwrap();
        build_server().serve(r, server_sock);
    });
    let r = client_sock.try_clone().unwrap();
    let mut client = RpcClient::from_transport(Box::new(PipeTransport::new(
        Box::new(r),
        Box::new(client_sock),
    )))
    .protocol(SECONDARY_PROTOCOL_NAME);
    assert_listing(&list_protocols(&mut client).unwrap());
    // Still the secondary's connection: its echo prefixes.
    let echoed = echo(&mut client, "x");
    assert!(echoed.ends_with('x') && echoed != "x", "{echoed}");
}

/// Accept on `listener` forever, counting connections, serving each.
fn serve_counting_unix(listener: UnixListener) -> Arc<AtomicUsize> {
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let r = stream.try_clone().unwrap();
                build_server().serve(r, stream);
            });
        }
    });
    accepted
}

#[test]
fn unix_reuses_the_one_connection() {
    let dir = std::env::temp_dir().join(format!("vgi-reflect-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.sock");
    let _ = std::fs::remove_file(&path);
    let accepted = serve_counting_unix(UnixListener::bind(&path).unwrap());
    let mut client = RpcClient::unix_connect(&path).unwrap().protocol(PRIMARY);
    exercise(&mut client);
    assert!(client.is_reusable());
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "reflection dialled anew"
    );
    client.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tcp_reuses_the_one_connection() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let r = stream.try_clone().unwrap();
                build_server().serve(r, stream);
            });
        }
    });
    let mut client = RpcClient::tcp_connect("127.0.0.1", port)
        .unwrap()
        .protocol(PRIMARY);
    exercise(&mut client);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "reflection dialled anew"
    );
}

#[cfg(feature = "reqwest")]
mod http {
    use super::*;

    use vgi_rpc::http::{build_router, HttpState};
    use vgi_rpc_client::{
        ExecutorCaps, HttpClient, HttpExecError, HttpExecutor, HttpRequest, HttpResponse,
    };

    fn start_http() -> u16 {
        let state = HttpState::builder()
            .server(Arc::new(build_server()))
            .build();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap().port()).unwrap();
                axum::serve(listener, build_router(state)).await.unwrap();
            });
        });
        rx.recv().unwrap()
    }

    /// A reqwest-backed executor recording each URL, which can rewrite
    /// reflection answers into what a server older than protocol-scoped
    /// routes sends: a bare, non-Arrow 404.
    struct Recording {
        client: reqwest::blocking::Client,
        urls: Mutex<Vec<String>>,
        bare_404_for_reflection: bool,
    }

    impl Recording {
        fn new(bare_404_for_reflection: bool) -> Arc<Self> {
            Arc::new(Self {
                client: reqwest::blocking::Client::new(),
                urls: Mutex::new(Vec::new()),
                bare_404_for_reflection,
            })
        }

        fn reflection_posts(&self) -> usize {
            self.urls
                .lock()
                .unwrap()
                .iter()
                .filter(|u| u.contains(REFLECTION))
                .count()
        }
    }

    impl HttpExecutor for Recording {
        fn execute(&self, req: HttpRequest<'_>) -> Result<HttpResponse, HttpExecError> {
            self.urls.lock().unwrap().push(req.url.to_string());
            let method = reqwest::Method::from_bytes(req.method.as_bytes()).unwrap();
            let mut builder = self.client.request(method, req.url);
            for (name, value) in req.headers {
                builder = builder.header(name, value);
            }
            let response = builder
                .body(req.body.to_vec())
                .send()
                .map_err(|e| HttpExecError {
                    message: e.to_string(),
                    retry_safe: false,
                })?;
            let status = response.status().as_u16();
            let mut headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_string()))
                .collect();
            let mut body = response.bytes().unwrap().to_vec();
            if self.bare_404_for_reflection && req.url.contains(REFLECTION) {
                headers.retain(|(n, _)| {
                    !n.eq_ignore_ascii_case("content-type")
                        && !n.eq_ignore_ascii_case("content-encoding")
                        && !n.eq_ignore_ascii_case("content-length")
                });
                headers.push(("content-type".into(), "text/plain".into()));
                body = b"Not Found".to_vec();
                return Ok(HttpResponse {
                    status: 404,
                    headers,
                    body,
                });
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        }

        fn caps(&self) -> ExecutorCaps {
            ExecutorCaps {
                supports_options: true,
                transparent_decompression: false,
            }
        }
    }

    fn http_echo(client: &mut HttpClient, value: &str) -> String {
        let params = RecordBatch::try_new(
            utf8_schema("value"),
            vec![Arc::new(StringArray::from(vec![value]))],
        )
        .unwrap();
        let (batch, _) = client.call_unary("echo_string", &params, None).unwrap();
        batch.column(0).as_string::<i32>().value(0).to_string()
    }

    #[test]
    fn http_goes_through_the_callers_client() {
        let port = start_http();
        let executor = Recording::new(false);
        let mut client = HttpClient::connect(format!("http://127.0.0.1:{port}"))
            .protocol(PRIMARY)
            .executor(executor.clone())
            .build()
            .unwrap();
        assert_eq!(http_echo(&mut client, "a"), "a");
        let hosted = list_protocols(&mut client).unwrap();
        assert_listing(&hosted);
        let desc = describe_protocol(&mut client, PRIMARY).unwrap();
        assert_eq!(desc.protocol_hash, hosted[0].hash);
        assert!(desc.methods.contains_key("produce_n"));
        match describe_protocol(&mut client, "nope.v1") {
            Err(ReflectionError::Rpc(e)) => {
                assert_eq!(e.error_kind.as_deref(), Some("protocol_not_supported"))
            }
            other => panic!("expected protocol_not_supported, got {other:?}"),
        }
        assert_eq!(client.list_protocols().unwrap(), hosted);
        assert_eq!(http_echo(&mut client, "b"), "b");
        // list, list+describe, list+describe(unknown), list: six reflection
        // POSTs, every one through the caller's own executor.
        assert_eq!(executor.reflection_posts(), 6);
    }

    #[test]
    fn http_bare_404_is_reflection_not_supported() {
        let port = start_http();
        let executor = Recording::new(true);
        let mut client = HttpClient::connect(format!("http://127.0.0.1:{port}"))
            .protocol(PRIMARY)
            .executor(executor.clone())
            .build()
            .unwrap();
        match list_protocols(&mut client) {
            Err(ReflectionError::NotSupported(e)) => {
                assert_eq!(e.error_type, "HttpError");
                assert!(e.message.starts_with("HTTP 404"), "{}", e.message);
            }
            other => panic!("expected NotSupported, got {other:?}"),
        }
        assert!(matches!(
            describe_protocol(&mut client, PRIMARY),
            Err(ReflectionError::NotSupported(_))
        ));
        assert_eq!(http_echo(&mut client, "still here"), "still here");
    }
}
