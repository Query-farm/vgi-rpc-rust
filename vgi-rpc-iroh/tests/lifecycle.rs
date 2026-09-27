use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use iroh::{endpoint::presets, Endpoint, RelayMode, SecretKey};
use vgi_rpc::{peer_identity_primary, ConnectionContext, MethodInfo, RpcServer};
use vgi_rpc_client::RpcClient;
use vgi_rpc_iroh::{
    CancellationToken, IrohClientOptions, IrohConnection, IrohConnectionLifecycle, IrohServer,
    IrohServerOptions, VGI_IROH_ALPN,
};

#[derive(Default)]
struct Lifecycle {
    opened: AtomicUsize,
    closed: Mutex<Vec<String>>,
}

impl IrohConnectionLifecycle for Lifecycle {
    fn opened(&self, context: &mut ConnectionContext) -> vgi_rpc::Result<()> {
        assert!(context.auth.authenticated);
        let id = self.opened.fetch_add(1, Ordering::SeqCst).to_string();
        context.auth.claims.insert("test.connection".into(), id);
        Ok(())
    }

    fn closed(&self, context: &ConnectionContext) {
        self.closed
            .lock()
            .unwrap()
            .push(context.auth.claims["test.connection"].clone());
    }
}

async fn endpoint(key: u8) -> Endpoint {
    Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&[key; 32]))
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![VGI_IROH_ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

fn worker() -> RpcServer {
    let mut server = RpcServer::new("lifecycle");
    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Utf8, false)]));
    server.register(MethodInfo::unary(
        "connection",
        Arc::new(Schema::empty()),
        schema.clone(),
        move |_, context| {
            Ok(Some(RecordBatch::try_new(
                schema.clone(),
                vec![Arc::new(StringArray::from(vec![context.auth.claims
                    ["test.connection"]
                    .clone()]))],
            )?))
        },
    ));
    server
}

async fn request(connection: &IrohConnection) -> String {
    let transport = connection.open_transport().await.unwrap();
    tokio::task::spawn_blocking(move || {
        let mut client = RpcClient::from_transport(Box::new(transport)).protocol("Service");
        let (batch, _) = client
            .call_unary(
                "connection",
                &RecordBatch::new_empty(Arc::new(Schema::empty())),
                None,
            )
            .unwrap();
        batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .value(0)
            .to_string()
    })
    .await
    .unwrap()
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn physical_connection_lifecycle_preserves_other_connections_and_streams() {
    let server_endpoint = endpoint(1).await;
    let first_endpoint = endpoint(2).await;
    let second_endpoint = endpoint(2).await; // Same authenticated identity.
    let lifecycle = Arc::new(Lifecycle::default());
    let server = IrohServer::with_options(
        Arc::new(worker()),
        IrohServerOptions::default()
            .with_policy(peer_identity_primary("iroh"))
            .with_lifecycle(lifecycle.clone()),
    );
    let shutdown = CancellationToken::new();
    let task = {
        let shutdown = shutdown.clone();
        let server_endpoint = server_endpoint.clone();
        tokio::spawn(async move {
            server.serve(server_endpoint, shutdown).await.unwrap();
        })
    };
    let first = IrohConnection::connect_addr(
        first_endpoint.clone(),
        server_endpoint.addr(),
        IrohClientOptions::default(),
    )
    .await
    .unwrap();
    let first_id = request(&first).await;
    let second = IrohConnection::connect_addr(
        second_endpoint.clone(),
        server_endpoint.addr(),
        IrohClientOptions::default(),
    )
    .await
    .unwrap();
    let second_id = request(&second).await;
    assert_ne!(first_id, second_id);
    assert_eq!(request(&first).await, first_id);
    assert!(
        lifecycle.closed.lock().unwrap().is_empty(),
        "closing an RPC stream must not close the QUIC lifecycle"
    );
    first.close();
    wait_for(|| lifecycle.closed.lock().unwrap().len() == 1).await;
    assert_eq!(*lifecycle.closed.lock().unwrap(), vec![first_id]);
    assert_eq!(request(&second).await, second_id);
    shutdown.cancel();
    task.await.unwrap();
    assert_eq!(lifecycle.opened.load(Ordering::SeqCst), 2);
    assert_eq!(lifecycle.closed.lock().unwrap().len(), 2);
    assert!(lifecycle.closed.lock().unwrap().contains(&second_id));
    first_endpoint.close().await;
    second_endpoint.close().await;
    server_endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lifecycle_closes_on_first_stream_timeout_and_task_abort() {
    for abort in [false, true] {
        let server_endpoint = endpoint(3).await;
        let client_endpoint = endpoint(4).await;
        let lifecycle = Arc::new(Lifecycle::default());
        let server = IrohServer::with_options(
            Arc::new(worker()),
            IrohServerOptions {
                policy: Some(peer_identity_primary("iroh")),
                lifecycle: Some(lifecycle.clone()),
                stream_open_timeout: Duration::from_millis(300),
                ..IrohServerOptions::default()
            },
        );
        let shutdown = CancellationToken::new();
        let task = {
            let shutdown = shutdown.clone();
            let server_endpoint = server_endpoint.clone();
            tokio::spawn(async move {
                server.serve(server_endpoint, shutdown).await.unwrap();
            })
        };
        let connection = IrohConnection::connect_addr(
            client_endpoint.clone(),
            server_endpoint.addr(),
            IrohClientOptions::default(),
        )
        .await
        .unwrap();
        wait_for(|| lifecycle.opened.load(Ordering::SeqCst) == 1).await;
        if abort {
            task.abort();
        }
        wait_for(|| lifecycle.closed.lock().unwrap().len() == 1).await;
        shutdown.cancel();
        let _ = task.await;
        assert_eq!(lifecycle.closed.lock().unwrap().len(), 1);
        connection.close();
        client_endpoint.close().await;
        server_endpoint.close().await;
    }
}
