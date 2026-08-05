//! Integration test: externalize → pointer batch → fetch → resolve.
//!
//! Uses the in-memory storage backend so the test is self-contained.

use std::sync::Arc;

use arrow_array::{Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema};

use vgi_rpc::external::{
    any_url_validator, maybe_externalize_batch, resolve_external_location, Compression,
    ExternalLocationConfig, ExternalStorage, Fetcher, InMemoryStorage,
};
use vgi_rpc::metadata::{LOCATION_FETCH_MS_KEY, LOCATION_KEY};

fn make_batch(rows: usize) -> RecordBatch {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]));
    let col: Arc<dyn arrow_array::Array> =
        Arc::new(Int64Array::from((0..rows as i64).collect::<Vec<_>>()));
    RecordBatch::try_new(schema, vec![col]).unwrap()
}

fn cfg_from(
    storage: Arc<InMemoryStorage>,
    threshold: usize,
    compression: Compression,
) -> ExternalLocationConfig {
    let s: Arc<dyn ExternalStorage> = storage.clone();
    let f: Arc<dyn Fetcher> = storage;
    ExternalLocationConfig::new(s, f)
        .with_threshold_bytes(threshold)
        .with_compression(compression)
        .with_url_validator(any_url_validator())
}

#[test]
fn round_trip_5mb_uncompressed() {
    // 5MB worth of int64s.
    let storage = InMemoryStorage::new();
    let cfg = cfg_from(storage.clone(), 64 * 1024, Compression::None);
    let batch = make_batch(1_000_000);
    let (ptr, md) = maybe_externalize_batch(&batch, batch.schema().as_ref(), None, &cfg)
        .expect("externalize")
        .expect("threshold exceeded");
    assert_eq!(ptr.num_rows(), 0);
    assert_eq!(storage.len(), 1);
    // Pointer metadata carries the location + sha256.
    let url = md.get(LOCATION_KEY).cloned().unwrap();
    assert!(url.starts_with("https://inmem.test/"));

    let (resolved, user_md) = resolve_external_location(&ptr, &md, &cfg).unwrap();
    assert_eq!(resolved.num_rows(), 1_000_000);
    // fetch_ms gets appended for observability.
    assert!(user_md.contains_key(LOCATION_FETCH_MS_KEY));
}

#[test]
fn round_trip_with_zstd_compression() {
    let storage = InMemoryStorage::new();
    let cfg = cfg_from(storage.clone(), 16 * 1024, Compression::Zstd(3));
    let batch = make_batch(200_000);
    let (ptr, md) = maybe_externalize_batch(&batch, batch.schema().as_ref(), None, &cfg)
        .unwrap()
        .unwrap();
    let (resolved, _) = resolve_external_location(&ptr, &md, &cfg).unwrap();
    assert_eq!(resolved.num_rows(), 200_000);
}

#[test]
fn caller_metadata_preserved_through_externalization() {
    let storage = InMemoryStorage::new();
    let cfg = cfg_from(storage, 1024, Compression::None);
    let batch = make_batch(50_000);
    let caller_md = std::collections::HashMap::<String, String>::from([(
        "x-custom".to_string(),
        "value".to_string(),
    )]);
    let (ptr, md) =
        maybe_externalize_batch(&batch, batch.schema().as_ref(), Some(&caller_md), &cfg)
            .unwrap()
            .unwrap();
    assert!(md.iter().any(|(k, v)| k == "x-custom" && v == "value"));
    let _ = ptr; // pointer batch is a zero-row, zero-schema batch
}

/// Externalised payloads leave only a pointer batch on the wire, so a call
/// that ships 10 GB looks like a few hundred bytes to any transport-level
/// accounting. The counter therefore sits at the upload choke point, and a
/// scope reads it per call.
#[test]
fn externalized_bytes_are_counted_at_the_upload_choke_point() {
    use vgi_rpc::external::ExternalizedScope;

    let storage = InMemoryStorage::new();
    let cfg = cfg_from(storage.clone(), 64 * 1024, Compression::None);
    let batch = make_batch(100_000);

    let scope = ExternalizedScope::new();
    // Below the threshold: nothing is uploaded, so nothing is counted.
    assert!(
        maybe_externalize_batch(&make_batch(1), make_batch(1).schema().as_ref(), None, &cfg)
            .unwrap()
            .is_none()
    );
    let (ptr, _) = maybe_externalize_batch(&batch, batch.schema().as_ref(), None, &cfg)
        .expect("externalize")
        .expect("threshold exceeded");
    let one = scope.finish();
    assert!(one >= 800_000, "counted {one} for an 800 KB batch");
    assert_eq!(ptr.num_rows(), 0, "only a pointer batch reaches the wire");

    // The total accumulates across every upload the call makes.
    let scope = ExternalizedScope::new();
    for _ in 0..2 {
        maybe_externalize_batch(&batch, batch.schema().as_ref(), None, &cfg)
            .expect("externalize")
            .expect("threshold exceeded");
    }
    assert_eq!(scope.finish(), 2 * one);

    // A fresh scope starts from zero: the count is per call, not per process.
    let scope = ExternalizedScope::new();
    assert_eq!(scope.finish(), 0);
}
