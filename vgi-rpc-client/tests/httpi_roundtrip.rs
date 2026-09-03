//! Typed native client qualification through the released `iroh-http/2`
//! server seam. This deliberately exercises `HttpClient` rather than the
//! lower-level transport-core request test.

#![cfg(feature = "iroh")]

use std::convert::Infallible;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use arrow_array::cast::AsArray;
use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use http_body_util::BodyExt;
use iroh_http_core::{serve, Body, IrohEndpoint, NetworkingOptions, NodeOptions, ServeOptions};
use tower::ServiceExt;
use vgi_rpc::http::{build_router, HttpState};
use vgi_rpc::server::{MethodInfo, RpcServer};
use vgi_rpc::AuthContext;
use vgi_rpc_client::HttpClient;

fn utf8_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Utf8, false)]))
}

fn server() -> RpcServer {
    let mut server = RpcServer::builder().enable_describe(true).build();
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

fn start_server() -> (String, Vec<String>) {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("server runtime");
        runtime.block_on(async move {
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
                        .server(Arc::new(server()))
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
    ready_rx.recv().expect("server endpoint")
}

#[test]
fn typed_unary_capabilities_and_describe_over_httpi() {
    let (endpoint_id, direct) = start_server();
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
