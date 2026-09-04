//! Typed native client qualification through the released `iroh-http/2`
//! server seam. This deliberately exercises `HttpClient` rather than the
//! lower-level transport-core request test.

#![cfg(feature = "iroh")]

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use arrow_array::cast::AsArray;
use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use http_body_util::BodyExt;
use iroh_http_core::{serve, Body, IrohEndpoint, NetworkingOptions, NodeOptions, ServeOptions};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use vgi_rpc::external::{
    any_url_validator, Compression, ExternalLocationConfig, ExternalStorage, Fetcher, UploadResult,
};
use vgi_rpc::http::{build_router, HttpState};
use vgi_rpc::server::{MethodInfo, RpcServer};
use vgi_rpc::{AuthContext, RpcError};
use vgi_rpc_client::HttpClient;

fn utf8_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Utf8, false)]))
}

fn server(external: Option<ExternalLocationConfig>) -> RpcServer {
    let builder = RpcServer::builder().enable_describe(true);
    let builder = match external {
        Some(config) => builder.with_external_location(config),
        None => builder,
    };
    let mut server = builder.build();
    let result_schema = utf8_schema("result");
    server.register(MethodInfo::unary(
        "echo_string",
        utf8_schema("value"),
        result_schema.clone(),
        move |request, _context| {
            let value = request
                .column("value")
                .expect("declared value column")
                .as_string::<i32>()
                .value(0);
            Ok(Some(RecordBatch::try_new(
                result_schema.clone(),
                vec![Arc::new(StringArray::from(vec![format!("echo: {value}")]))],
            )?))
        },
    ));
    server
}

struct LoopbackStorage {
    url: Arc<Mutex<Option<String>>>,
    payload: Arc<Mutex<Vec<u8>>>,
    uploads: Arc<AtomicUsize>,
}

impl ExternalStorage for LoopbackStorage {
    fn upload(&self, ipc_bytes: &[u8], _compression: Compression) -> vgi_rpc::Result<UploadResult> {
        *self.payload.lock().expect("payload lock") = ipc_bytes.to_vec();
        self.uploads.fetch_add(1, Ordering::SeqCst);
        Ok(UploadResult {
            url: self
                .url
                .lock()
                .expect("URL lock")
                .clone()
                .expect("external HTTP server URL"),
            sha256: format!("{:x}", Sha256::digest(ipc_bytes)),
        })
    }
}

struct UnusedFetcher;

impl Fetcher for UnusedFetcher {
    fn fetch(
        &self,
        _url: &str,
        _compression: Compression,
        _max_bytes: usize,
    ) -> vgi_rpc::Result<Vec<u8>> {
        Err(RpcError::runtime_error(
            "server-side test fetcher must never be used",
        ))
    }
}

fn start_server(externalize: bool) -> (String, Vec<String>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let payload = Arc::new(Mutex::new(Vec::new()));
    let external_url = Arc::new(Mutex::new(None));
    let uploads = Arc::new(AtomicUsize::new(0));
    let fetches = Arc::new(AtomicUsize::new(0));
    let thread_payload = payload.clone();
    let thread_url = external_url.clone();
    let thread_uploads = uploads.clone();
    let thread_fetches = fetches.clone();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("server runtime");
        runtime.block_on(async move {
            let external = if externalize {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind external payload server");
                let address = listener.local_addr().expect("external payload address");
                *thread_url.lock().expect("URL lock") =
                    Some(format!("http://{address}/external.arrow?signature=test"));

                let route_payload = thread_payload.clone();
                let route_fetches = thread_fetches.clone();
                let storage_router = axum::Router::new().route(
                    "/external.arrow",
                    axum::routing::get(move || {
                        let body = route_payload.lock().expect("payload lock").clone();
                        route_fetches.fetch_add(1, Ordering::SeqCst);
                        async move { body }
                    }),
                );
                tokio::spawn(async move {
                    axum::serve(listener, storage_router)
                        .await
                        .expect("serve external payload");
                });

                Some(
                    ExternalLocationConfig::new(
                        Arc::new(LoopbackStorage {
                            url: thread_url.clone(),
                            payload: thread_payload.clone(),
                            uploads: thread_uploads.clone(),
                        }),
                        Arc::new(UnusedFetcher),
                    )
                    .with_threshold_bytes(1)
                    .with_url_validator(any_url_validator()),
                )
            } else {
                None
            };

            let endpoint = IrohEndpoint::bind(NodeOptions {
                networking: NetworkingOptions {
                    disabled: true,
                    bind_addrs: vec!["127.0.0.1:0".into()],
                    ..NetworkingOptions::default()
                },
                ..NodeOptions::default()
            })
            .await
            .expect("bind Iroh HTTP server");
            let router = axum::Router::new().nest(
                "/vgi",
                build_router(
                    HttpState::builder()
                        .server(Arc::new(server(external)))
                        .authenticate(Arc::new(|request| {
                            if request.header("authorization") == Some("Bearer typed-test") {
                                Ok(AuthContext::for_principal("bearer", "native-client"))
                            } else {
                                Err(vgi_rpc::RpcError::permission_error("token required"))
                            }
                        }))
                        .build(),
                ),
            );
            let _guard = serve(
                endpoint.clone(),
                ServeOptions::default(),
                tower::service_fn(move |request: hyper::Request<Body>| {
                    let router = router.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        let bytes = body.collect().await.expect("request body").to_bytes();
                        let request =
                            hyper::Request::from_parts(parts, axum::body::Body::from(bytes));
                        let response = router.oneshot(request).await.expect("VGI response");
                        let (parts, body) = response.into_parts();
                        let bytes = body.collect().await.expect("response body").to_bytes();
                        Ok::<_, Infallible>(hyper::Response::from_parts(parts, Body::full(bytes)))
                    }
                }),
            );
            let id = vgi_iroh_transport::endpoint_id_hex(endpoint.raw().id());
            let direct = endpoint
                .raw()
                .addr()
                .ip_addrs()
                .map(ToString::to_string)
                .collect();
            ready_tx.send((id, direct)).expect("publish endpoint");
            std::future::pending::<()>().await;
        });
    });
    let (id, direct) = ready_rx.recv().expect("server endpoint");
    (id, direct, uploads, fetches)
}

#[test]
fn typed_unary_capabilities_and_describe_over_httpi() {
    let (endpoint_id, direct, _, _) = start_server(false);
    let target = format!("httpi://{endpoint_id}/vgi");
    let mut client = HttpClient::connect_httpi(&target)
        .expect("parse httpi target")
        .no_relay(true)
        .direct_addresses(direct)
        .connect_timeout(Duration::from_secs(5))
        .io_timeout(Duration::from_secs(5))
        .header("authorization", "Bearer typed-test")
        .unwrap()
        .build()
        .expect("build HTTPi client");

    let params = RecordBatch::try_new(
        utf8_schema("value"),
        vec![Arc::new(StringArray::from(vec!["native"]))],
    )
    .unwrap();
    let (batch, _) = client
        .call_unary("echo_string", &params, None)
        .expect("typed unary call");
    assert_eq!(batch.column(0).as_string::<i32>().value(0), "echo: native");
    assert!(client
        .describe()
        .unwrap()
        .methods
        .contains_key("echo_string"));
    assert!(
        client
            .capabilities()
            .unwrap()
            .accept_max_response_bytes_support
    );
}

#[test]
fn httpi_resolves_externalized_response_over_separate_http_fetch() {
    let (endpoint_id, direct, uploads, fetches) = start_server(true);
    let target = format!("httpi://{endpoint_id}/vgi");
    let mut client = HttpClient::connect_httpi(&target)
        .expect("parse httpi target")
        .no_relay(true)
        .direct_addresses(direct)
        .connect_timeout(Duration::from_secs(5))
        .io_timeout(Duration::from_secs(5))
        .header("authorization", "Bearer typed-test")
        .unwrap()
        .external_resolution_any()
        .build()
        .expect("build HTTPi client");

    let value = "externalized-through-httpi".repeat(128);
    let params = RecordBatch::try_new(
        utf8_schema("value"),
        vec![Arc::new(StringArray::from(vec![value.as_str()]))],
    )
    .unwrap();
    let (batch, _) = client
        .call_unary("echo_string", &params, None)
        .expect("externalized HTTPi unary call");

    assert_eq!(
        batch.column(0).as_string::<i32>().value(0),
        format!("echo: {value}")
    );
    assert_eq!(uploads.load(Ordering::SeqCst), 1);
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
}

#[test]
fn default_ephemeral_identity_is_process_stable() {
    let target = concat!(
        "httpi://",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    let first = HttpClient::connect_httpi(target)
        .unwrap()
        .no_relay(true)
        .build()
        .unwrap();
    let second = HttpClient::connect_httpi(target)
        .unwrap()
        .no_relay(true)
        .build()
        .unwrap();
    assert_eq!(first.iroh_endpoint_id(), second.iroh_endpoint_id());
}
