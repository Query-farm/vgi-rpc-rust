use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arrow_array::cast::AsArray;
use arrow_array::{Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use iroh::{endpoint::presets, Endpoint, RelayMode};
use vgi_rpc::{
    peer_identity_primary, AuthContext, CallContext, MethodInfo, MethodType, OutputCollector,
    PeerEvidenceSet, ProducerState, RpcServer, StreamResult,
};
use vgi_rpc_client::RpcClient;
use vgi_rpc_iroh::{
    CancellationToken, IrohClientOptions, IrohConnection, IrohServer, IrohServerOptions,
    VGI_IROH_ALPN,
};

fn string_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "identity",
        DataType::Utf8,
        false,
    )]))
}

struct CountTo {
    current: i64,
    end: i64,
    schema: SchemaRef,
}

impl ProducerState for CountTo {
    fn produce(
        &mut self,
        output: &mut OutputCollector,
        _context: &CallContext,
    ) -> vgi_rpc::Result<()> {
        if self.current == self.end {
            output.finish();
        } else {
            output.emit(RecordBatch::try_new(
                self.schema.clone(),
                vec![Arc::new(Int64Array::from(vec![self.current]))],
            )?)?;
            self.current += 1;
        }
        Ok(())
    }
}

fn worker(observed: Arc<Mutex<Vec<String>>>) -> RpcServer {
    let mut server = RpcServer::new("iroh-loopback");
    let result_schema = string_schema();
    server.register(MethodInfo::unary(
        "identity",
        Arc::new(Schema::empty()),
        result_schema.clone(),
        move |_request, context| {
            assert!(context.auth.authenticated);
            assert_eq!(context.auth.domain, "iroh");
            let identity = context.peer_evidence.unique_verified_subject("iroh")?;
            assert_eq!(
                identity.subject_key(),
                context.auth.claims.get("subject").map(String::as_str)
            );
            assert_eq!(identity.transport(), "iroh");
            assert_eq!(identity.issuer(), "test.mesh");
            observed
                .lock()
                .unwrap()
                .push(context.auth.principal.clone());
            Ok(Some(RecordBatch::try_new(
                result_schema.clone(),
                vec![Arc::new(StringArray::from(vec![context
                    .auth
                    .principal
                    .as_str()]))],
            )?))
        },
    ));

    let count_schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]));
    server.register(MethodInfo::stream(
        "count",
        MethodType::Producer,
        Arc::new(Schema::empty()),
        move |_request, _context| {
            Ok(StreamResult::producer(
                count_schema.clone(),
                Box::new(CountTo {
                    current: 0,
                    end: 3,
                    schema: count_schema.clone(),
                }),
            ))
        },
    ));
    server
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_connection_multiplexes_stateful_transports_with_one_identity_snapshot() {
    let server_endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![VGI_IROH_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let server_addr = server_endpoint.addr();
    let server_id = server_endpoint.id();
    let client_endpoint = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let client_id = client_endpoint.id();

    let observed = Arc::new(Mutex::new(Vec::new()));
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let primary = peer_identity_primary("iroh");
    let counted_policy = {
        let policy_calls = Arc::clone(&policy_calls);
        Arc::new(move |evidence: &PeerEvidenceSet, auth: &AuthContext| {
            policy_calls.fetch_add(1, Ordering::SeqCst);
            primary(evidence, auth)
        })
    };
    let shutdown = CancellationToken::new();
    let server = IrohServer::with_options(
        Arc::new(worker(observed.clone())),
        IrohServerOptions::default()
            .with_issuer("test.mesh")
            .with_policy(counted_policy),
    );
    let serve_shutdown = shutdown.clone();
    let serve_task = tokio::spawn(async move {
        server.serve(server_endpoint, serve_shutdown).await.unwrap();
    });

    let connection = IrohConnection::connect_addr(
        client_endpoint.clone(),
        server_addr,
        IrohClientOptions::default().with_rpc_timeout(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(connection.remote_id(), server_id);
    let first_transport = connection.open_transport().await.unwrap();
    let second_transport = connection.open_transport().await.unwrap();

    let client_subject = client_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let first = tokio::task::spawn_blocking(move || {
        let mut client = RpcClient::from_transport(Box::new(first_transport));
        let params = RecordBatch::new_empty(Arc::new(Schema::empty()));

        let (first, _) = client.call_unary("identity", &params, None).unwrap();
        let first = first.column(0).as_string::<i32>().value(0).to_owned();
        let (second, _) = client.call_unary("identity", &params, None).unwrap();
        assert_eq!(second.column(0).as_string::<i32>().value(0), first);

        let mut values = Vec::new();
        let mut stream = client.open_producer("count", &params, None, false).unwrap();
        while let Some((batch, _)) = stream.tick().unwrap() {
            values.push(
                batch
                    .column(0)
                    .as_primitive::<arrow_array::types::Int64Type>()
                    .value(0),
            );
        }
        assert_eq!(values, vec![0, 1, 2]);
        first
    });
    let second = tokio::task::spawn_blocking(move || {
        let mut client = RpcClient::from_transport(Box::new(second_transport));
        let params = RecordBatch::new_empty(Arc::new(Schema::empty()));
        let (identity, _) = client.call_unary("identity", &params, None).unwrap();
        identity.column(0).as_string::<i32>().value(0).to_owned()
    });
    let (principal, second_principal) = tokio::try_join!(first, second).unwrap();

    assert_eq!(principal, format!("peer/iroh/test.mesh/{client_subject}"));
    assert_eq!(client_subject.len(), 64);
    assert!(client_subject
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(second_principal, principal);
    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);
    let identities = observed.lock().unwrap().clone();
    assert_eq!(identities.len(), 3);
    assert!(identities.iter().all(|identity| identity == &principal));

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), serve_task)
        .await
        .unwrap()
        .unwrap();
    client_endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drip_fed_stream_is_terminated_without_poisoning_its_connection() {
    let server_endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![VGI_IROH_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let server_addr = server_endpoint.addr();
    let client_endpoint = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();

    let shutdown = CancellationToken::new();
    let server = IrohServer::with_options(
        Arc::new(worker(Arc::new(Mutex::new(Vec::new())))),
        IrohServerOptions {
            issuer: "test.mesh".into(),
            policy: Some(peer_identity_primary("iroh")),
            connection_io_timeout: Duration::from_secs(3),
            first_request_timeout: Duration::from_millis(200),
            ..IrohServerOptions::default()
        },
    );
    let serve_shutdown = shutdown.clone();
    let serve_task = tokio::spawn(async move {
        server.serve(server_endpoint, serve_shutdown).await.unwrap();
    });

    let connection = IrohConnection::connect_addr(
        client_endpoint.clone(),
        server_addr,
        IrohClientOptions::default().with_rpc_timeout(Duration::from_secs(3)),
    )
    .await
    .unwrap();
    let mut poison = connection.open_transport().await.unwrap();

    // Each byte arrives well inside the idle timeout. Only an absolute input
    // deadline can reject this incomplete Arrow frame.
    let poison_task = tokio::task::spawn_blocking(move || {
        let (_, writer) = vgi_rpc_client::Transport::split(&mut poison);
        for _ in 0..8 {
            if writer.write_all(&[0]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("server did not terminate a drip-fed logical stream");
    });
    tokio::time::timeout(Duration::from_secs(2), poison_task)
        .await
        .expect("server did not terminate the drip-fed stream")
        .unwrap();

    // The malformed stream is isolated. A new stream on the same pooled QUIC
    // connection remains usable and inherits the same connection identity.
    let healthy = connection.open_transport().await.unwrap();
    tokio::task::spawn_blocking(move || {
        let mut client = RpcClient::from_transport(Box::new(healthy));
        let params = RecordBatch::new_empty(Arc::new(Schema::empty()));
        client.call_unary("identity", &params, None).unwrap();
    })
    .await
    .unwrap();

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), serve_task)
        .await
        .unwrap()
        .unwrap();
    client_endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_bounds_an_idle_logical_stream_drain() {
    let server_endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![VGI_IROH_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let server_addr = server_endpoint.addr();
    let client_endpoint = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();

    let shutdown = CancellationToken::new();
    let server = IrohServer::with_options(
        Arc::new(RpcServer::new("iroh-drain")),
        IrohServerOptions {
            connection_io_timeout: Duration::from_secs(5),
            first_request_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_millis(100),
            ..IrohServerOptions::default()
        },
    );
    let serve_shutdown = shutdown.clone();
    let serve_task = tokio::spawn(async move {
        server.serve(server_endpoint, serve_shutdown).await.unwrap();
    });

    let connection = client_endpoint
        .connect(server_addr, VGI_IROH_ALPN)
        .await
        .unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), serve_task)
        .await
        .expect("server exceeded its bounded logical-stream drain")
        .unwrap();
    client_endpoint.close().await;
}
