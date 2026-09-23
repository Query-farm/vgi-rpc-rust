#![cfg(feature = "tcp-tls")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use vgi_rpc::tcp::{
    serve_tcp_with_mtls_identity, TcpIdentityOptions, TcpMutualTlsConfig, TcpMutualTlsOptions,
};
use vgi_rpc::{peer_identity_primary, MethodInfo, RpcServer};
use vgi_rpc_client::RpcClient;

fn pem_der(value: &str, label: &str) -> Vec<u8> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = value
        .split(&begin)
        .nth(1)
        .unwrap()
        .split(&end)
        .next()
        .unwrap()
        .lines()
        .map(str::trim)
        .collect::<String>();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

fn certificate(value: &str) -> rustls::pki_types::CertificateDer<'static> {
    rustls::pki_types::CertificateDer::from(pem_der(value, "CERTIFICATE"))
}

fn private_key(value: &str) -> rustls::pki_types::PrivateKeyDer<'static> {
    rustls::pki_types::PrivatePkcs8KeyDer::from(pem_der(value, "PRIVATE KEY")).into()
}

#[test]
fn rpc_client_round_trips_over_direct_mtls() {
    let server_cert = certificate(include_str!(
        "../../vgi-rpc/tests/data/tcp-mtls-server-cert.pem"
    ));
    let client_cert = certificate(include_str!(
        "../../vgi-rpc/tests/data/tcp-mtls-client-cert.pem"
    ));

    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(client_cert.clone()).unwrap();
    let tls = TcpMutualTlsConfig::new(
        vec![server_cert.clone()],
        private_key(include_str!(
            "../../vgi-rpc/tests/data/tcp-mtls-server-key.pem"
        )),
        client_roots,
        ["example.org"],
    )
    .unwrap();

    let output_schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Utf8,
        false,
    )]));
    let mut server = RpcServer::builder()
        .protocol_name("TlsTest")
        .protocol_version("1")
        .build();
    server.register(MethodInfo::unary(
        "whoami",
        Arc::new(Schema::empty()),
        output_schema.clone(),
        move |_request, context| {
            assert!(context.auth.authenticated);
            Ok(Some(RecordBatch::try_new(
                output_schema.clone(),
                vec![Arc::new(StringArray::from(vec![context
                    .auth
                    .principal
                    .as_str()]))],
            )?))
        },
    ));

    let shutdown = Arc::new(AtomicBool::new(false));
    let (bound_tx, bound_rx) = mpsc::sync_channel(1);
    let serve_shutdown = Arc::clone(&shutdown);
    let thread = std::thread::spawn(move || {
        serve_tcp_with_mtls_identity(
            Arc::new(server),
            "127.0.0.1",
            0,
            None,
            serve_shutdown,
            TcpMutualTlsOptions::new(tls).with_identity(TcpIdentityOptions {
                policy: Some(peer_identity_primary("spiffe")),
                ..TcpIdentityOptions::default()
            }),
            move |_host, port| bound_tx.send(port).unwrap(),
        )
        .unwrap();
    });
    let port = bound_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    let mut server_roots = rustls::RootCertStore::empty();
    server_roots.add(server_cert.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_tls = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(server_roots)
            .with_client_auth_cert(
                vec![client_cert],
                private_key(include_str!(
                    "../../vgi-rpc/tests/data/tcp-mtls-client-key.pem"
                )),
            )
            .unwrap(),
    );
    assert!(
        RpcClient::tls_tcp_connect(
            "127.0.0.1",
            port,
            "wrong.example.org",
            Arc::clone(&client_tls),
            Duration::from_secs(5),
            Some(Duration::from_secs(5)),
        )
        .is_err(),
        "the TLS client must reject a certificate for another server name"
    );

    let mut anonymous_roots = rustls::RootCertStore::empty();
    anonymous_roots.add(server_cert.clone()).unwrap();
    let anonymous_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(anonymous_roots)
    .with_no_client_auth();
    let mut anonymous = RpcClient::tls_tcp_connect(
        "127.0.0.1",
        port,
        "localhost",
        Arc::new(anonymous_tls),
        Duration::from_secs(5),
        Some(Duration::from_secs(5)),
    )
    .unwrap()
    .protocol("TlsTest")
    .protocol_version("1");
    let request = RecordBatch::new_empty(Arc::new(Schema::empty()));
    assert!(
        anonymous.call_unary("whoami", &request, None).is_err(),
        "the mutual-TLS server must reject a client without a certificate"
    );

    let mut client = RpcClient::tls_tcp_connect(
        "127.0.0.1",
        port,
        "localhost",
        client_tls,
        Duration::from_secs(5),
        Some(Duration::from_secs(5)),
    )
    .unwrap()
    .protocol("TlsTest")
    .protocol_version("1");
    let (response, _) = client.call_unary("whoami", &request, None).unwrap();
    assert!(response
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .value(0)
        .starts_with("peer/spiffe/"));

    client.close().unwrap();
    shutdown.store(true, Ordering::Release);
    // Wake the non-blocking accept loop promptly.
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    thread.join().unwrap();
}
