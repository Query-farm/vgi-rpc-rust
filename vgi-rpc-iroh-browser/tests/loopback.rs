#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use iroh_http_core::{serve, Body, IrohEndpoint, NetworkingOptions, NodeOptions, ServeOptions};
use vgi_rpc_iroh_browser::IrohHttpEndpoint;

fn local_options() -> NodeOptions {
    NodeOptions {
        networking: NetworkingOptions {
            disabled: true,
            bind_addrs: vec!["127.0.0.1:0".into()],
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn shared_endpoint_sends_hyper_request_to_iroh_http_core_server() {
    let server = IrohEndpoint::bind(local_options()).await.unwrap();
    let client = IrohEndpoint::bind(local_options()).await.unwrap();
    let expected_client_id = client.raw().id();
    let expected_peer_evidence = iroh_http_core::base32_encode(expected_client_id.as_bytes());

    let _server = serve(
        server.clone(),
        ServeOptions::default(),
        tower::service_fn(move |request: hyper::Request<Body>| async move {
            let peer = request
                .extensions()
                .get::<iroh_http_core::RemoteNodeId>()
                .map(|value| value.0.to_string())
                .unwrap_or_default();
            let path = request.uri().path().to_string();
            let request_bytes = request.into_body().collect().await.unwrap().to_bytes();
            let response = format!("{path} {peer} bytes={}", request_bytes.len());
            Ok::<_, Infallible>(hyper::Response::new(Body::full(Bytes::from(response))))
        }),
    );

    let mut remote = iroh::EndpointAddr::new(server.raw().id());
    for address in server.raw().addr().ip_addrs() {
        remote = remote.with_ip_addr(*address);
    }

    let shared = IrohHttpEndpoint::new(client.raw().clone());
    assert_eq!(shared.id(), expected_client_id);
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/vgi")
        .header(hyper::header::HOST, server.raw().id().to_string())
        .body(Full::new(Bytes::from_static(b"arrow-ipc")))
        .unwrap();
    let response = shared.request(remote, request).await.unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with(&format!("/vgi {expected_peer_evidence} ")),
        "response={text:?}"
    );
    assert!(text.ends_with("bytes=9"), "response={text:?}");
}
