//! External-location resolution over a **byte-stream** transport.
//!
//! Externalization is not an HTTP feature (WIRE_PROTOCOL.md §12): any
//! transport that carries record batches carries pointer batches. This port's
//! byte-stream client resolved none of them for a while, which is silent row
//! loss — a pointer classified as data is a zero-row batch, and an empty
//! result is not an error anywhere.
//!
//! Driven over a socketpair against a real `RpcServer`, plus one hand-rolled
//! peer for the case a real server here cannot produce: an externalized
//! **stream header**. This crate's server writes its header batch directly and
//! externalizes only in the data path, so a port talking to itself never sees
//! a header pointer — the very reason §1.5 calls that path out as one an
//! implementation "cannot exercise against itself".

#![cfg(all(unix, feature = "http"))]

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;

use arrow_array::cast::AsArray;
use arrow_array::types::Int64Type;
use arrow_array::{Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};

use vgi_rpc::external::{
    any_url_validator, Compression, ExternalLocationConfig, ExternalStorage, Fetcher, UploadResult,
};
use vgi_rpc::metadata::{
    LOCATION_FETCH_MS_KEY, LOCATION_KEY, LOCATION_SHA256_KEY, LOCATION_SOURCE_KEY,
};
use vgi_rpc::server::{MethodInfo, MethodType, RpcServer};
use vgi_rpc::stream::{OutputCollector, ProducerState, StreamResult};
use vgi_rpc::wire::{md_get, Metadata, StreamReader, StreamWriter};
use vgi_rpc::{CallContext, LogLevel, Result};
use vgi_rpc_client::{PipeTransport, RpcClient};

// ---------------------------------------------------------------------------
// A storage backend and its matching fetcher, sharing one map.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MemStore {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemStore {
    fn uploads(&self) -> usize {
        self.objects.lock().unwrap().len()
    }
}

impl ExternalStorage for MemStore {
    fn upload(&self, ipc_bytes: &[u8], _compression: Compression) -> Result<UploadResult> {
        let mut map = self.objects.lock().unwrap();
        let url = format!("memory://objects/{}", map.len());
        map.insert(url.clone(), ipc_bytes.to_vec());
        Ok(UploadResult {
            url,
            sha256: String::new(),
        })
    }
}

impl Fetcher for MemStore {
    fn fetch(&self, url: &str, _compression: Compression, _max_bytes: usize) -> Result<Vec<u8>> {
        self.objects
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| vgi_rpc::RpcError::runtime_error(format!("no such object: {url}")))
    }
}

fn i64_schema(name: &str) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(name, DataType::Int64, false)]))
}

/// Threshold of one byte: every data-bearing batch travels through storage, so
/// a test that resolves nothing fails instead of passing on an inline batch.
fn config(store: Arc<MemStore>) -> ExternalLocationConfig {
    ExternalLocationConfig::new(store.clone(), store)
        .with_threshold_bytes(1)
        .with_url_validator(any_url_validator())
}

// ---------------------------------------------------------------------------
// A producer that logs, then emits one annotated batch per turn.
// ---------------------------------------------------------------------------

struct Annotated {
    total: i64,
    cur: i64,
    schema: SchemaRef,
}

impl ProducerState for Annotated {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        out.client_log(LogLevel::Info, format!("producing batch {}", self.cur));
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![Arc::new(Int64Array::from(vec![self.cur * 1_000_000]))],
        )?;
        let mut md = Metadata::new();
        md.insert("app.batch_index".to_string(), self.cur.to_string());
        md.insert("app.label".to_string(), "ünïcode-λ".to_string());
        out.emit_with_metadata(batch, md)?;
        self.cur += 1;
        Ok(())
    }
}

fn build_server(store: Arc<MemStore>) -> RpcServer {
    let mut srv = RpcServer::builder()
        .with_external_location(config(store))
        .build();

    let result = i64_schema("result");
    let r = result.clone();
    srv.register(MethodInfo::unary(
        "double",
        i64_schema("value"),
        result,
        move |req, _ctx| {
            let v = req
                .column("value")
                .unwrap()
                .as_primitive::<Int64Type>()
                .value(0);
            Ok(Some(RecordBatch::try_new(
                r.clone(),
                vec![Arc::new(Int64Array::from(vec![v * 2]))],
            )?))
        },
    ));

    let out_schema = i64_schema("value");
    let os = out_schema.clone();
    srv.register(MethodInfo::stream(
        "annotated",
        MethodType::Producer,
        i64_schema("count"),
        move |req, _ctx| {
            let total = req
                .column("count")
                .unwrap()
                .as_primitive::<Int64Type>()
                .value(0);
            Ok(StreamResult::producer(
                os.clone(),
                Box::new(Annotated {
                    total,
                    cur: 0,
                    schema: os.clone(),
                }),
            ))
        },
    ));
    srv
}

fn connect(store: Arc<MemStore>) -> (RpcClient, thread::JoinHandle<()>) {
    let (client_sock, server_sock) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || {
        let srv = build_server(store);
        let r = server_sock.try_clone().unwrap();
        srv.serve(r, server_sock);
    });
    let client_read = client_sock.try_clone().unwrap();
    let transport = PipeTransport::new(Box::new(client_read), Box::new(client_sock));
    (
        RpcClient::from_transport(Box::new(transport)).protocol("Service"),
        handle,
    )
}

/// A resolved batch carries the payload's metadata plus the reader's
/// provenance, and none of the pointer's own keys.
fn assert_resolved(md: &Metadata, what: &str) {
    assert!(
        md_get(md, LOCATION_KEY).is_none(),
        "{what}: pointer metadata leaked through -- a reader that returns the \
         pointer's metadata drops whatever rode on the data batch"
    );
    assert!(md_get(md, LOCATION_SHA256_KEY).is_none(), "{what}");
    assert!(
        md_get(md, LOCATION_FETCH_MS_KEY).is_some(),
        "{what}: no fetch_ms provenance"
    );
    assert!(
        md_get(md, LOCATION_SOURCE_KEY)
            .is_some_and(|source| source.starts_with("memory://objects/")),
        "{what}: location.source must be the URL that was fetched; a batch \
         carrying neither provenance key is indistinguishable from one whose \
         resolver never ran"
    );
}

#[test]
fn unary_result_resolves_over_a_byte_stream() {
    let store = Arc::new(MemStore::default());
    let (client, handle) = connect(store.clone());
    let mut client = client.external_config(config(store.clone()));
    let params = RecordBatch::try_new(
        i64_schema("value"),
        vec![Arc::new(Int64Array::from(vec![21i64]))],
    )
    .unwrap();
    let (batch, md) = client.call_unary("double", &params, None).unwrap();
    assert_eq!(batch.num_rows(), 1);
    assert_eq!(batch.column(0).as_primitive::<Int64Type>().value(0), 42);
    assert!(store.uploads() >= 1, "nothing was externalized");
    assert_resolved(&md, "double");
    drop(client);
    handle.join().unwrap();
}

#[test]
fn producer_batches_resolve_with_their_own_metadata_and_logs() {
    let store = Arc::new(MemStore::default());
    let (client, handle) = connect(store.clone());
    let logs = Arc::new(Mutex::new(Vec::new()));
    let sink = logs.clone();
    let mut client = client
        .external_config(config(store.clone()))
        .on_log(Box::new(move |m| sink.lock().unwrap().push(m.message)));

    let params = RecordBatch::try_new(
        i64_schema("count"),
        vec![Arc::new(Int64Array::from(vec![3i64]))],
    )
    .unwrap();
    let mut got = Vec::new();
    {
        let mut session = client
            .open_producer("annotated", &params, None, false)
            .unwrap();
        while let Some((batch, md)) = session.tick().unwrap() {
            assert_eq!(
                batch.num_rows(),
                1,
                "a pointer delivered as data reads as a zero-row batch"
            );
            got.push((
                batch.column(0).as_primitive::<Int64Type>().value(0),
                md.get("app.batch_index").cloned(),
                md.get("app.label").cloned(),
            ));
            assert_resolved(&md, "annotated");
        }
    }
    assert_eq!(
        got,
        vec![
            (0, Some("0".into()), Some("ünïcode-λ".into())),
            (1_000_000, Some("1".into()), Some("ünïcode-λ".into())),
            (2_000_000, Some("2".into()), Some("ünïcode-λ".into())),
        ],
        "per-emit metadata must be this batch's, not a cached first turn's"
    );
    assert!(store.uploads() >= 3, "batches stayed inline");
    assert_eq!(
        logs.lock().unwrap().len(),
        3,
        "logs bundled into an externalized cycle must still reach on_log"
    );
    drop(client);
    handle.join().unwrap();
}

#[test]
fn a_pointer_with_no_resolver_is_an_error_not_an_empty_batch() {
    let store = Arc::new(MemStore::default());
    let (mut client, handle) = connect(store);
    let params = RecordBatch::try_new(
        i64_schema("value"),
        vec![Arc::new(Int64Array::from(vec![21i64]))],
    )
    .unwrap();
    let err = client
        .call_unary("double", &params, None)
        .expect_err("a pointer must not be handed back as a zero-row data batch");
    assert!(
        err.message.contains("external-location pointer"),
        "unhelpful error: {}",
        err.message
    );
    drop(client);
    handle.join().unwrap();
}

// ---------------------------------------------------------------------------
// The externalized stream header.
// ---------------------------------------------------------------------------

/// Serve one producer stream whose **header** is a pointer batch.
///
/// Hand-rolled because no server in this workspace externalizes a header, so
/// there is nothing here to drive the client's header resolver with. The
/// reference does, which is how four ports discovered their header readers
/// classified the zero-row pointer as a log and then reported the header
/// absent rather than malformed.
fn serve_pointer_header(sock: UnixStream, store: Arc<MemStore>) {
    let header_schema = i64_schema("seed");
    let out_schema = i64_schema("value");
    let mut r = sock.try_clone().unwrap();
    let mut w = sock;

    // Request stream: one params batch, then EOS.
    {
        let mut reader = StreamReader::new(&mut r).unwrap();
        while reader.read_next().unwrap().is_some() {}
    }

    // Header sub-stream: a log, then the pointer standing in for the header.
    let header = RecordBatch::try_new(
        header_schema.clone(),
        vec![Arc::new(Int64Array::from(vec![42i64]))],
    )
    .unwrap();
    let cfg = config(store);
    let (ptr, ptr_md) =
        vgi_rpc::external::maybe_externalize_batch(&header, header_schema.as_ref(), None, &cfg)
            .unwrap()
            .expect("a one-byte threshold externalizes every non-empty batch");
    {
        let mut hw = StreamWriter::new(&mut w, header_schema.as_ref()).unwrap();
        hw.write(&ptr, Some(&ptr_md)).unwrap();
        hw.finish().unwrap();
    }

    // Output stream: schema first (the client opens its reader before ticking),
    // then one batch per tick until the client stops.
    let mut ow = StreamWriter::new(&mut w, out_schema.as_ref()).unwrap();
    ow.flush().unwrap();
    let mut input = StreamReader::new(&mut r).unwrap();
    // One turn is all this peer owes: the assertion under test is the header,
    // and the client closes the stream as soon as it has read it.
    if input.read_next().unwrap().is_some() {
        let batch = RecordBatch::try_new(
            out_schema.clone(),
            vec![Arc::new(Int64Array::from(vec![7i64]))],
        )
        .unwrap();
        ow.write(&batch, None).unwrap();
        ow.flush().unwrap();
    }
    ow.finish().unwrap();
}

#[test]
fn an_externalized_stream_header_resolves() {
    let store = Arc::new(MemStore::default());
    let (client_sock, server_sock) = UnixStream::pair().unwrap();
    let peer_store = store.clone();
    let handle = thread::spawn(move || serve_pointer_header(server_sock, peer_store));

    let client_read = client_sock.try_clone().unwrap();
    let transport = PipeTransport::new(Box::new(client_read), Box::new(client_sock));
    let mut client = RpcClient::from_transport(Box::new(transport))
        .protocol("Service")
        .external_config(config(store));

    let params = RecordBatch::try_new(
        i64_schema("count"),
        vec![Arc::new(Int64Array::from(vec![1i64]))],
    )
    .unwrap();
    {
        let session = client
            .open_producer("headered", &params, None, true)
            .unwrap();
        let (header, md) = session
            .header()
            .expect("the header is a zero-row pointer -- a reader that classifies it as a log reports it absent");
        assert_eq!(header.num_rows(), 1);
        assert_eq!(header.column(0).as_primitive::<Int64Type>().value(0), 42);
        assert_resolved(md, "header");
    }
    drop(client);
    handle.join().unwrap();
}
