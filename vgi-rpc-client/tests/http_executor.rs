//! `HttpClient` driven through a caller-supplied `HttpExecutor` against a
//! real in-process axum `vgi_rpc::http` server. The test executors are built
//! on reqwest; the client under test never touches reqwest itself.

#![cfg(feature = "reqwest")]

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread;

use arrow_array::cast::AsArray;
use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use vgi_rpc::http::{build_router, HttpState};
use vgi_rpc::server::{MethodInfo, RpcServer};
use vgi_rpc_client::{
    ExecutorCaps, HttpClient, HttpExecError, HttpExecutor, HttpRequest, HttpResponse,
};

fn utf8_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Utf8, false)]))
}

fn start_server() -> u16 {
    let mut srv = RpcServer::builder().build();
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
                vec![Arc::new(StringArray::from(vec![format!("echo: {v}")]))],
            )?))
        },
    ));
    let state = HttpState::builder().server(Arc::new(srv)).build();
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

/// What one request looked like on the way out and what came back raw.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    url: String,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
}

/// A reqwest-backed executor that records traffic. `options` models a
/// transport without OPTIONS; `browser` models one that sets its own
/// `Accept-Encoding` and transparently decodes standard `Content-Encoding`
/// (keeping the header visible, as browsers do).
struct RecordingExecutor {
    client: reqwest::blocking::Client,
    caps: ExecutorCaps,
    browser: bool,
    seen: Mutex<Vec<Seen>>,
}

impl RecordingExecutor {
    fn new(caps: ExecutorCaps, browser: bool) -> Arc<Self> {
        Arc::new(Self {
            client: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            caps,
            browser,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl HttpExecutor for RecordingExecutor {
    fn execute(&self, req: HttpRequest<'_>) -> Result<HttpResponse, HttpExecError> {
        if req.method == "OPTIONS" && !self.caps.supports_options {
            return Err(HttpExecError {
                message: "OPTIONS not supported by this transport".into(),
                retry_safe: false,
            });
        }
        let method = reqwest::Method::from_bytes(req.method.as_bytes()).unwrap();
        let mut builder = self.client.request(method, req.url);
        for (name, value) in req.headers {
            if self.browser && name.eq_ignore_ascii_case("accept-encoding") {
                panic!("client set a forbidden Accept-Encoding header");
            }
            builder = builder.header(name, value);
        }
        if self.browser {
            builder = builder.header("accept-encoding", "zstd, gzip");
        }
        if !req.timeout.is_zero() {
            builder = builder.timeout(req.timeout);
        }
        let response = builder
            .body(req.body.to_vec())
            .send()
            .map_err(|e| HttpExecError {
                message: e.to_string(),
                retry_safe: true,
            })?;
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_string()))
            .collect();
        let raw = response.bytes().unwrap().to_vec();
        let encoding = headers
            .iter()
            .find(|(n, _)| n == "content-encoding")
            .map(|(_, v)| v.clone());
        let body = match encoding.as_deref() {
            Some("zstd") if self.browser => zstd::decode_all(raw.as_slice()).unwrap(),
            Some("gzip") if self.browser => {
                let mut out = Vec::new();
                flate2::read::GzDecoder::new(raw.as_slice())
                    .read_to_end(&mut out)
                    .unwrap();
                out
            }
            _ => raw,
        };
        self.seen.lock().unwrap().push(Seen {
            method: req.method.to_string(),
            url: req.url.to_string(),
            request_headers: req.headers.to_vec(),
            response_headers: headers.clone(),
        });
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    fn caps(&self) -> ExecutorCaps {
        self.caps
    }
}

fn header<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn client_with(port: u16, executor: Arc<RecordingExecutor>) -> HttpClient {
    HttpClient::connect(format!("http://127.0.0.1:{port}"))
        .protocol("Service")
        .executor(executor)
        .build()
        .unwrap()
}

fn echo(client: &mut HttpClient, value: &str) -> String {
    let params = RecordBatch::try_new(
        utf8_schema("value"),
        vec![Arc::new(StringArray::from(vec![value]))],
    )
    .unwrap();
    let (batch, _md) = client.call_unary("echo_string", &params, None).unwrap();
    batch.column(0).as_string::<i32>().value(0).to_string()
}

/// Large enough that the server compresses the response.
fn big_value() -> String {
    "abcdefgh".repeat(8 * 1024)
}

#[test]
fn executor_unary_round_trip_uses_options_by_default() {
    let port = start_server();
    let executor = RecordingExecutor::new(
        ExecutorCaps {
            supports_options: true,
            transparent_decompression: false,
        },
        false,
    );
    let mut client = client_with(port, executor.clone());
    assert_eq!(echo(&mut client, "hi"), "echo: hi");

    // Compressed response decoded by the client from standard Content-Encoding.
    let big = big_value();
    assert_eq!(echo(&mut client, &big), format!("echo: {big}"));

    let seen = executor.seen();
    assert_eq!(seen[0].method, "OPTIONS");
    assert!(seen[0].url.ends_with("/health"));
    assert!(seen[1..].iter().all(|s| s.method == "POST"));
    let last = seen.last().unwrap();
    assert!(header(&last.request_headers, "accept-encoding").is_some());
    assert_eq!(
        header(&last.response_headers, "content-encoding"),
        Some("zstd")
    );
}

#[test]
fn executor_without_options_discovers_via_get_health() {
    let port = start_server();
    let executor = RecordingExecutor::new(
        ExecutorCaps {
            supports_options: false,
            transparent_decompression: false,
        },
        false,
    );
    let client = client_with(port, executor.clone());
    let caps = client.capabilities().unwrap();
    assert!(caps.accept_max_response_bytes_support);
    assert!(!caps.sticky_enabled);
    assert_eq!(caps.supported_encodings, vec!["zstd", "gzip"]);

    let seen = executor.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert!(seen[0].url.ends_with("/health"));

    let mut client = client;
    assert_eq!(echo(&mut client, "no options"), "echo: no options");
    assert!(executor.seen().iter().all(|s| s.method != "OPTIONS"));
}

#[test]
fn transparent_decompression_decodes_x_vgi_content_encoding() {
    let port = start_server();
    // The transport does not decode anything here; the server must answer
    // on the VGI header because the codec was offered only there.
    let executor = RecordingExecutor::new(
        ExecutorCaps {
            supports_options: false,
            transparent_decompression: true,
        },
        false,
    );
    let mut client = client_with(port, executor.clone());
    let big = big_value();
    assert_eq!(echo(&mut client, &big), format!("echo: {big}"));

    let last = executor.seen().pop().unwrap();
    assert_eq!(header(&last.request_headers, "accept-encoding"), None);
    assert_eq!(
        header(&last.request_headers, "x-vgi-accept-encoding"),
        Some("zstd, gzip")
    );
    assert_eq!(
        header(&last.response_headers, "x-vgi-content-encoding"),
        Some("zstd")
    );
    assert_eq!(header(&last.response_headers, "content-encoding"), None);
}

#[test]
fn transparent_decompression_trusts_transport_decoded_content_encoding() {
    let port = start_server();
    // Browser-like transport: it advertises zstd itself, so the server picks
    // the standard `Content-Encoding`, which the transport decodes before the
    // client sees the body. The client must not decode it again.
    let executor = RecordingExecutor::new(
        ExecutorCaps {
            supports_options: false,
            transparent_decompression: true,
        },
        true,
    );
    let mut client = client_with(port, executor.clone());
    let big = big_value();
    assert_eq!(echo(&mut client, &big), format!("echo: {big}"));
    assert_eq!(echo(&mut client, "small"), "echo: small");

    let seen = executor.seen();
    let big_resp = &seen[seen.len() - 2];
    assert_eq!(
        header(&big_resp.response_headers, "content-encoding"),
        Some("zstd")
    );
}

#[test]
fn build_without_backend_or_with_executor() {
    // With reqwest compiled in, a plain build still works; with an executor
    // the executor is used even though reqwest is available.
    assert!(HttpClient::connect("http://127.0.0.1:1")
        .protocol("Service")
        .build()
        .is_ok());
    let executor = RecordingExecutor::new(ExecutorCaps::default(), false);
    let client = HttpClient::connect("http://127.0.0.1:1")
        .protocol("Service")
        .executor(executor.clone())
        .build()
        .unwrap();
    // Default caps (all false) ⇒ GET discovery; the connection fails.
    assert!(client.capabilities().is_err());
    assert!(executor.seen().is_empty());
}

/// Every RPC request names its protocol in the URL path: `{protocol}/{method}`
/// (and `/init`, `/exchange`). Only framework endpoints -- `/health`,
/// `__upload_url__` -- sit outside a protocol.
#[test]
fn every_request_names_its_protocol() {
    let port = start_server();
    let executor = RecordingExecutor::new(ExecutorCaps::default(), false);
    let mut client = client_with(port, executor.clone());
    assert_eq!(echo(&mut client, "x"), "echo: x");
    let rpc: Vec<_> = executor
        .seen()
        .into_iter()
        .filter(|s| s.method == "POST")
        .collect();
    assert!(!rpc.is_empty());
    for seen in rpc {
        assert!(
            seen.url.contains("/Service/") || seen.url.contains("/__upload_url__"),
            "unrouted request URL {}",
            seen.url
        );
    }
}

/// A client with no protocol cannot be built: there is no flat route to
/// fall back to.
#[test]
fn a_client_without_a_protocol_is_refused_at_build() {
    let err = HttpClient::connect("http://127.0.0.1:1")
        .build()
        .err()
        .unwrap();
    assert!(err.message.contains(".protocol("), "{}", err.message);
    let err = HttpClient::connect("http://127.0.0.1:1")
        .protocol("")
        .build()
        .err()
        .unwrap();
    assert!(err.message.contains(".protocol("), "{}", err.message);
}
