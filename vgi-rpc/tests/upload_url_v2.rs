//! Integration test: the version-2 upload-URL flow (`VGI-Upload-URL-Support: 2`).
//!
//! `__upload_url__/init` takes one `(size, sha256)` entry per upload and
//! answers with URLs signed for exactly that body plus the headers the PUT
//! must carry. Every malformed request -- the retired `count` shape included
//! -- is a 400 before a URL is minted, and a request pointer must carry
//! `vgi_rpc.location.sha256`, which the server verifies before decoding.

use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef, Int64Array, MapArray, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use vgi_rpc::external::{
    any_url_validator, upload_url_request_batch, ExternalLocationConfig, ExternalStorage, Fetcher,
    InMemoryStorage, UploadRequest, UploadUrlProvider,
};
use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{
    LOCATION_KEY, LOCATION_SHA256_KEY, LOG_LEVEL_KEY, LOG_MESSAGE_KEY, PROTOCOL_KEY,
    REQUEST_VERSION, REQUEST_VERSION_KEY, RPC_METHOD_KEY,
};
use vgi_rpc::wire::{md_get, Metadata, StreamReader, StreamWriter};
use vgi_rpc::{MethodInfo, RpcServer};

const MAX_UPLOAD: usize = 4096;

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn value_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Utf8,
        false,
    )]))
}

fn app(storage: &Arc<InMemoryStorage>) -> axum::Router {
    let s: Arc<dyn ExternalStorage> = storage.clone();
    let f: Arc<dyn Fetcher> = storage.clone();
    let cfg = ExternalLocationConfig::new(s, f).with_url_validator(any_url_validator());
    let mut srv = RpcServer::builder()
        .server_id("it")
        .protocol_name("Test")
        .with_external_location(cfg)
        .build();
    srv.register(MethodInfo::unary(
        "echo",
        value_schema(),
        value_schema(),
        |req, _| {
            let v = req.column("value").unwrap().as_string::<i32>().value(0);
            let arr: ArrayRef = Arc::new(StringArray::from(vec![format!("echo:{v}")]));
            Ok(Some(RecordBatch::try_new(value_schema(), vec![arr])?))
        },
    ));
    let provider: Arc<dyn UploadUrlProvider> = storage.clone();
    vgi_rpc::http::build_router(
        HttpState::builder()
            .server(Arc::new(srv))
            .disable_response_compression()
            .upload_url_provider(provider)
            .max_upload_bytes(MAX_UPLOAD)
            .build(),
    )
}

fn frame(batch: &RecordBatch, md: &Metadata) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, batch.schema().as_ref()).unwrap();
        w.write(batch, Some(md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

fn md_for(method: &str) -> Metadata {
    let mut md = Metadata::from([
        (RPC_METHOD_KEY.to_string(), method.to_string()),
        (REQUEST_VERSION_KEY.to_string(), REQUEST_VERSION.to_string()),
    ]);
    if method != "__upload_url__" {
        md.insert(PROTOCOL_KEY.to_string(), "Test".to_string());
    }
    md
}

async fn post(
    app: axum::Router,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<(RecordBatch, Metadata)>) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let mut r = StreamReader::new(&body[..]).unwrap();
    let mut out = Vec::new();
    while let Some(b) = r.read_next().unwrap() {
        out.push(b);
    }
    (status, out)
}

async fn init(app: axum::Router, batch: RecordBatch) -> (StatusCode, Vec<(RecordBatch, Metadata)>) {
    post(
        app,
        "/__upload_url__/init",
        frame(&batch, &md_for("__upload_url__")),
    )
    .await
}

/// The error message of the single exception batch in a refused reply.
fn refusal(status: StatusCode, batches: &[(RecordBatch, Metadata)]) -> String {
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, md) = batches.last().expect("an error batch");
    assert_eq!(md_get(md, LOG_LEVEL_KEY), Some("EXCEPTION"));
    md_get(md, LOG_MESSAGE_KEY).unwrap_or_default().to_string()
}

fn uploads(entries: &[(i64, &str)]) -> RecordBatch {
    upload_url_request_batch(
        &entries
            .iter()
            .map(|(size, sha)| UploadRequest {
                size: *size as u64,
                sha256: sha.to_string(),
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_capability_header_is_version_2() {
    let storage = InMemoryStorage::new();
    let resp = app(&storage)
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.headers().get("vgi-upload-url-support").unwrap(), "2");
    assert_eq!(
        resp.headers().get("vgi-max-upload-bytes").unwrap(),
        &MAX_UPLOAD.to_string()
    );
}

/// The full v2 round trip: init with (size, sha), PUT exactly those bytes
/// with every upload header, then dispatch a pointer carrying the download URL
/// and the sha.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_v2_upload_round_trips_through_a_request_pointer() {
    let storage = InMemoryStorage::new();
    let params = RecordBatch::try_new(
        value_schema(),
        vec![Arc::new(StringArray::from(vec!["hi"])) as ArrayRef],
    )
    .unwrap();
    let body = frame(&params, &md_for("echo"));
    let sha = sha_hex(&body);
    let other = b"second upload".to_vec();

    let (status, batches) = init(
        app(&storage),
        uploads(&[
            (body.len() as i64, &sha),
            (other.len() as i64, &sha_hex(&other)),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (resp, _) = &batches[0];
    assert_eq!(resp.num_rows(), 2, "one row per entry, in order");
    assert_eq!(
        resp.schema()
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .collect::<Vec<_>>(),
        ["upload_url", "download_url", "expires_at", "upload_headers"]
    );
    let up = resp.column(0).as_string::<i32>().value(0).to_string();
    let down = resp.column(1).as_string::<i32>().value(0).to_string();
    let headers = resp.column(3).as_any().downcast_ref::<MapArray>().unwrap();
    let entries = headers.value(0);
    let keys = entries.column(0).as_string::<i32>();
    let values = entries.column(1).as_string::<i32>();
    let sent: Vec<(String, String)> = (0..entries.len())
        .map(|i| (keys.value(i).to_string(), values.value(i).to_string()))
        .collect();
    assert!(sent.iter().any(|(k, _)| k == "x-amz-checksum-sha256"));
    assert!(!sent
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length")));

    // Storage refuses a body that is not the one the URL was signed for.
    let mut corrupt = body.clone();
    corrupt[body.len() / 2] ^= 0xff;
    let err = storage.put(&up, &sent, &corrupt).unwrap_err();
    assert!(err.message.contains("BadDigest"), "{}", err.message);
    storage.put(&up, &sent, &body).unwrap();

    let mut md = md_for("echo");
    md.insert(LOCATION_KEY.to_string(), down);
    md.insert(LOCATION_SHA256_KEY.to_string(), sha);
    let pointer = RecordBatch::new_empty(value_schema());
    let (status, batches) = post(app(&storage), "/Test/echo", frame(&pointer, &md)).await;
    assert_eq!(status, StatusCode::OK);
    let (result, _) = batches.last().unwrap();
    assert_eq!(result.column(0).as_string::<i32>().value(0), "echo:hi");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_retired_count_shape_is_refused() {
    let storage = InMemoryStorage::new();
    let schema = Arc::new(Schema::new(vec![Field::new(
        "count",
        DataType::Int64,
        true,
    )]));
    let batch = RecordBatch::try_new(
        schema,
        vec![Arc::new(Int64Array::from(vec![1])) as ArrayRef],
    )
    .unwrap();
    let (status, batches) = init(app(&storage), batch).await;
    let msg = refusal(status, &batches);
    assert!(msg.contains("retired count shape"), "{msg}");
    assert!(msg.contains("VGI-Upload-URL-Support: 2"), "{msg}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_entries_are_refused_before_minting() {
    let storage = InMemoryStorage::new();
    let good = sha_hex(b"x");
    let too_many: Vec<(i64, &str)> = (0..101).map(|_| (1, good.as_str())).collect();
    let upper = good.to_uppercase();
    let cases: Vec<(RecordBatch, &str)> = vec![
        (uploads(&[]), "1-100 entries"),
        (uploads(&too_many), "1-100 entries"),
        (uploads(&[(0, &good)]), "integer >= 1"),
        (uploads(&[(1, "abc")]), "64 lowercase hex"),
        (uploads(&[(1, &upper)]), "64 lowercase hex"),
        (
            uploads(&[(MAX_UPLOAD as i64 + 1, &good)]),
            "exceeds VGI-Max-Upload-Bytes",
        ),
    ];
    for (batch, want) in cases {
        let (status, batches) = init(app(&storage), batch).await;
        let msg = refusal(status, &batches);
        assert!(msg.contains(want), "want {want:?} in {msg}");
    }
    assert!(storage.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_pointer_without_sha256_is_refused() {
    let storage = InMemoryStorage::new();
    let params = RecordBatch::try_new(
        value_schema(),
        vec![Arc::new(StringArray::from(vec!["hi"])) as ArrayRef],
    )
    .unwrap();
    let body = frame(&params, &md_for("echo"));
    let grant = storage
        .generate_upload_url(body.len() as u64, &sha_hex(&body))
        .unwrap();
    storage
        .put(&grant.upload_url, &grant.headers, &body)
        .unwrap();

    let mut md = md_for("echo");
    md.insert(LOCATION_KEY.to_string(), grant.download_url.clone());
    let pointer = RecordBatch::new_empty(value_schema());
    let (_, batches) = post(app(&storage), "/Test/echo", frame(&pointer, &md)).await;
    let (_, emd) = batches.last().unwrap();
    assert_eq!(md_get(emd, LOG_LEVEL_KEY), Some("EXCEPTION"));
    let msg = md_get(emd, LOG_MESSAGE_KEY).unwrap();
    assert!(msg.contains("is missing vgi_rpc.location.sha256"), "{msg}");

    // A sha that does not match the stored bytes is refused too.
    md.insert(LOCATION_SHA256_KEY.to_string(), sha_hex(b"something else"));
    let (_, batches) = post(app(&storage), "/Test/echo", frame(&pointer, &md)).await;
    let (_, emd) = batches.last().unwrap();
    let msg = md_get(emd, LOG_MESSAGE_KEY).unwrap();
    assert!(msg.contains("sha256 mismatch"), "{msg}");
}

#[test]
fn the_request_schema_is_a_list_of_size_sha_structs() {
    let schema = vgi_rpc::upload_url_params_schema();
    assert_eq!(schema.fields().len(), 1);
    let f = schema.field(0);
    assert_eq!(f.name(), "uploads");
    assert!(!f.is_nullable());
    let DataType::List(item) = f.data_type() else {
        panic!("uploads must be a list");
    };
    let DataType::Struct(children) = item.data_type() else {
        panic!("entries must be structs");
    };
    assert_eq!(children[0].name(), "size");
    assert_eq!(children[0].data_type(), &DataType::Int64);
    assert!(!children[0].is_nullable());
    assert_eq!(children[1].name(), "sha256");
    assert_eq!(children[1].data_type(), &DataType::Utf8);
    assert!(!children[1].is_nullable());
}
