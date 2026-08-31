use std::sync::{Arc, Mutex};
use std::time::Duration;

use arrow_array::cast::AsArray;
use arrow_array::{Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use iroh::{endpoint::presets, Endpoint, RelayMode};
use vgi_rpc::{
    peer_identity_primary, CallContext, MethodInfo, MethodType, OutputCollector, ProducerState,
    RpcServer, StreamResult,
};
use vgi_rpc_client::RpcClient;
use vgi_rpc_iroh::{
    CancellationToken, IrohClientOptions, IrohServer, IrohServerOptions, IrohTransport,
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
async fn raw_framing_is_stateful_and_snapshots_endpoint_identity() {
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
    let shutdown = CancellationToken::new();
    let server = IrohServer::with_options(
        Arc::new(worker(observed.clone())),
        IrohServerOptions::default()
            .with_issuer("test.mesh")
            .with_policy(peer_identity_primary("iroh")),
    );
    let serve_shutdown = shutdown.clone();
    let serve_task = tokio::spawn(async move {
        server.serve(server_endpoint, serve_shutdown).await.unwrap();
    });

    let transport = IrohTransport::connect_addr(
        client_endpoint.clone(),
        server_addr,
        IrohClientOptions::default().with_rpc_timeout(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(transport.remote_id(), server_id);

    let client_id_text = client_id.to_string();
    let principal = tokio::task::spawn_blocking(move || {
        let mut client = RpcClient::from_transport(Box::new(transport));
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
    })
    .await
    .unwrap();

    assert!(principal.ends_with(&client_id_text));
    let identities = observed.lock().unwrap().clone();
    assert_eq!(identities, vec![principal.clone(), principal]);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), serve_task)
        .await
        .unwrap()
        .unwrap();
    client_endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drip_fed_first_frame_cannot_extend_absolute_input_budget() {
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
        Arc::new(RpcServer::new("iroh-slowloris")),
        IrohServerOptions {
            connection_io_timeout: Duration::from_secs(3),
            first_request_timeout: Duration::from_millis(200),
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

    // Each byte arrives well inside the idle timeout. Only an absolute input
    // deadline can reject this incomplete Arrow frame.
    for _ in 0..8 {
        if send.write_all(&[0]).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("server did not close a drip-fed first request");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), serve_task)
        .await
        .unwrap()
        .unwrap();
    client_endpoint.close().await;
}
