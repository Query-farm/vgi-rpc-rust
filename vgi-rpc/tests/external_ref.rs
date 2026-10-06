//! Integration test: a unary method answering with a pre-published
//! [`ExternalRef`].
//!
//! The dispatcher must write the ref's pointer batch as-is on every
//! transport — zero rows, the method's result schema, `vgi_rpc.location`
//! plus `vgi_rpc.location.sha256` only when the ref has one — with no
//! upload during the call, regardless of the server's storage config or
//! threshold, and without tripping `max_externalized_response_bytes`.

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use vgi_rpc::external::{
    any_url_validator, publish_external, resolve_external_location, Compression,
    ExternalLocationConfig, ExternalStorage, Fetcher, InMemoryStorage,
};
use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{
    LOCATION_KEY, LOCATION_SHA256_KEY, LOG_LEVEL_KEY, PROTOCOL_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::wire::{md_get, Metadata, StreamReader, StreamWriter};
use vgi_rpc::{service, CallContext, ExternalRef, RefOr, Result, RpcError, RpcServer};

const PROTOCOL: &str = "Catalog";

struct Catalog {
    storage: Arc<InMemoryStorage>,
    published: Mutex<Option<ExternalRef>>,
}

#[service]
impl Catalog {
    /// Answer with a publish-once ref, or inline when `as_ref` is false.
    #[unary]
    fn catalog(&self, value: String, as_ref: bool) -> Result<RefOr<String>> {
        if !as_ref {
            return Ok(RefOr::Value(value));
        }
        let mut published = self.published.lock().unwrap();
        if let Some(r) = published.as_ref() {
            return Ok(r.clone().into());
        }
        let col: ArrayRef = Arc::new(StringArray::from(vec![value]));
        let batch = RecordBatch::try_new(result_schema(), vec![col])?;
        let r = publish_external(&batch, self.storage.as_ref(), Compression::None, true)?;
        *published = Some(r.clone());
        Ok(r.into())
    }

    /// A ref published out of band, without a digest.
    #[unary]
    fn digestless(&self) -> Result<RefOr<String>> {
        Ok(ExternalRef::new("https://inmem.test/out-of-band", None)?.into())
    }

    /// Records a ref, then fails: the error must win.
    #[unary]
    fn ref_then_fail(&self, ctx: &CallContext) -> Result<RefOr<String>> {
        ctx.respond_with_external_ref(ExternalRef::new("https://inmem.test/never", None)?);
        Err(RpcError::value_error(
            "handler failed after recording a ref",
        ))
    }
}

fn result_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![Field::new(
        "result",
        DataType::Utf8,
        false,
    )]))
}

fn external_cfg(storage: &Arc<InMemoryStorage>) -> ExternalLocationConfig {
    let s: Arc<dyn ExternalStorage> = storage.clone();
    let f: Arc<dyn Fetcher> = storage.clone();
    // Threshold 0: every ordinary result externalizes, so a ref that
    // uploaded anything during the call would show up in the store.
    ExternalLocationConfig::new(s, f)
        .with_threshold_bytes(0)
        .with_url_validator(any_url_validator())
}

fn server(storage: &Arc<InMemoryStorage>, with_external: bool) -> RpcServer {
    let mut builder = RpcServer::builder().protocol_name(PROTOCOL);
    if with_external {
        builder = builder.with_external_location(external_cfg(storage));
    }
    let mut srv = builder.build();
    Catalog::register_with(
        &mut srv,
        Arc::new(Catalog {
            storage: storage.clone(),
            published: Mutex::new(None),
        }),
    );
    srv
}

/// Frame one request for `method`; `catalog`'s params when `params` is set.
fn request(method: &str, params: Option<(&str, bool)>) -> Vec<u8> {
    use arrow_array::{BooleanArray, RecordBatchOptions};
    let batch = match params {
        Some((value, as_ref)) => {
            let schema = Arc::new(Schema::new(vec![
                Field::new("value", DataType::Utf8, false),
                Field::new("as_ref", DataType::Boolean, false),
            ]));
            let cols: Vec<ArrayRef> = vec![
                Arc::new(StringArray::from(vec![value])),
                Arc::new(BooleanArray::from(vec![as_ref])),
            ];
            RecordBatch::try_new(schema, cols).unwrap()
        }
        None => RecordBatch::try_new_with_options(
            Arc::new(Schema::empty()),
            vec![],
            &RecordBatchOptions::new().with_row_count(Some(1)),
        )
        .unwrap(),
    };
    let md = Metadata::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (PROTOCOL_KEY.to_string(), PROTOCOL.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
    ]);
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, batch.schema().as_ref()).unwrap();
        w.write(&batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Every batch of one response stream.
fn response_batches(body: &[u8]) -> Vec<(RecordBatch, Metadata)> {
    let mut r = StreamReader::new(body).unwrap();
    let mut out = Vec::new();
    while let Some(item) = r.read_next().unwrap() {
        out.push(item);
    }
    out
}

/// Serve each request over the byte-stream (pipe) loop; one response each.
fn serve_pipe(srv: &RpcServer, requests: &[Vec<u8>]) -> Vec<Vec<(RecordBatch, Metadata)>> {
    requests
        .iter()
        .map(|req| {
            let mut output = Vec::new();
            srv.serve(Cursor::new(req.clone()), &mut output);
            response_batches(&output)
        })
        .collect()
}

/// Assert `batches` is exactly one pointer batch; return its metadata.
fn single_pointer(batches: &[(RecordBatch, Metadata)]) -> Metadata {
    assert_eq!(batches.len(), 1, "expected exactly one batch");
    let (batch, md) = &batches[0];
    assert_eq!(batch.num_rows(), 0, "a ref answers with a zero-row pointer");
    assert_eq!(
        batch.schema(),
        result_schema(),
        "pointer carries the result schema"
    );
    assert!(
        md_get(md, LOCATION_KEY).is_some(),
        "pointer carries no location"
    );
    md.clone()
}

fn resolve_value(storage: &Arc<InMemoryStorage>, md: &Metadata) -> String {
    let cfg = external_cfg(storage);
    let ptr = arrow_array::RecordBatch::new_empty(result_schema());
    let (resolved, _) = resolve_external_location(&ptr, md, &cfg).unwrap();
    resolved
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .value(0)
        .to_string()
}

#[test]
fn pipe_writes_the_ref_pointer_and_uploads_once() {
    for with_external in [true, false] {
        let storage = InMemoryStorage::new();
        let srv = server(&storage, with_external);
        let responses = serve_pipe(
            &srv,
            &[
                request("catalog", Some(("hi", true))),
                request("catalog", Some(("hi", true))),
            ],
        );
        let first = single_pointer(&responses[0]);
        let second = single_pointer(&responses[1]);
        assert_eq!(
            md_get(&first, LOCATION_KEY),
            md_get(&second, LOCATION_KEY),
            "the cached ref is reused"
        );
        assert!(md_get(&first, LOCATION_SHA256_KEY).is_some());
        // Only the publish uploaded; answering with the ref uploads nothing,
        // even with a zero externalization threshold configured.
        assert_eq!(storage.len(), 1, "with_external={with_external}");
        assert_eq!(resolve_value(&storage, &first), "hi");
    }
}

#[test]
fn pipe_value_branch_is_an_ordinary_result() {
    let storage = InMemoryStorage::new();
    let srv = server(&storage, false);
    let responses = serve_pipe(&srv, &[request("catalog", Some(("inline", false)))]);
    let (batch, md) = &responses[0][0];
    assert_eq!(batch.num_rows(), 1);
    assert!(md_get(md, LOCATION_KEY).is_none());
    assert!(storage.is_empty());
}

#[test]
fn pipe_ref_without_digest_omits_the_sha_key() {
    let storage = InMemoryStorage::new();
    let srv = server(&storage, true);
    let responses = serve_pipe(&srv, &[request("digestless", None)]);
    let md = single_pointer(&responses[0]);
    assert_eq!(
        md_get(&md, LOCATION_KEY),
        Some("https://inmem.test/out-of-band")
    );
    assert!(md_get(&md, LOCATION_SHA256_KEY).is_none());
}

#[test]
fn pipe_handler_error_wins_over_a_recorded_ref() {
    let storage = InMemoryStorage::new();
    let srv = server(&storage, true);
    let responses = serve_pipe(&srv, &[request("ref_then_fail", None)]);
    let (_, md) = responses[0].last().unwrap();
    assert_eq!(md_get(md, LOG_LEVEL_KEY), Some("EXCEPTION"));
    assert!(md_get(md, LOCATION_KEY).is_none());
}

async fn post(app: axum::Router, method: &str, body: Vec<u8>) -> Vec<(RecordBatch, Metadata)> {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/{PROTOCOL}/{method}"))
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    response_batches(&body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_writes_the_ref_pointer_outside_the_external_cap() {
    let storage = InMemoryStorage::new();
    let state = HttpState::builder()
        .server(Arc::new(server(&storage, true)))
        // A one-byte external cap: an ordinary externalized result would
        // be refused, but a ref uploads nothing during the call.
        .max_externalized_response_bytes(1)
        .build();
    let app = vgi_rpc::http::build_router(state);

    let first = post(
        app.clone(),
        "catalog",
        request("catalog", Some(("hi", true))),
    )
    .await;
    let second = post(
        app.clone(),
        "catalog",
        request("catalog", Some(("hi", true))),
    )
    .await;
    let first = single_pointer(&first);
    let second = single_pointer(&second);
    assert_eq!(md_get(&first, LOCATION_KEY), md_get(&second, LOCATION_KEY));
    assert_eq!(storage.len(), 1, "only the publish uploaded");
    assert_eq!(resolve_value(&storage, &first), "hi");

    let digestless = post(app.clone(), "digestless", request("digestless", None)).await;
    assert!(md_get(&single_pointer(&digestless), LOCATION_SHA256_KEY).is_none());

    let failed = post(app, "ref_then_fail", request("ref_then_fail", None)).await;
    let (_, md) = failed.last().unwrap();
    assert_eq!(md_get(md, LOG_LEVEL_KEY), Some("EXCEPTION"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_ref_needs_no_storage_config() {
    let storage = InMemoryStorage::new();
    let state = HttpState::builder()
        .server(Arc::new(server(&storage, false)))
        .build();
    let app = vgi_rpc::http::build_router(state);
    let batches = post(app, "catalog", request("catalog", Some(("plain", true)))).await;
    let md = single_pointer(&batches);
    assert_eq!(resolve_value(&storage, &md), "plain");
}
