//! `published_string`: the pre-published `ExternalRef` conformance method.
//!
//! Lives apart from the stateless [`super::unary::UnarySvc`] because it needs
//! the worker's own external storage and compression — the `--fake-storage`
//! backend and `--zstd` setting — plus a per-process publish-once cache.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{Field, Schema};
use vgi_rpc::external::{publish_external, Compression, ExternalLocationConfig, ExternalStorage};
use vgi_rpc::{service, ExternalRef, RefOr, Result, RpcError, RpcServer, VgiArrow};

/// Publishes `{result: [value]}` once per `(value, include_sha256)` and
/// answers every call with the cached ref.
pub struct PublishedSvc {
    storage: Option<Arc<dyn ExternalStorage>>,
    compression: Compression,
    published: Mutex<HashMap<(String, bool), ExternalRef>>,
}

#[service]
impl PublishedSvc {
    /// Return *value* through a pre-published ``ExternalRef`` (publish once, reuse).
    #[unary]
    fn published_string(&self, value: String, include_sha256: bool) -> Result<RefOr<String>> {
        let storage = self
            .storage
            .as_ref()
            .ok_or_else(|| RpcError::runtime_error("published_string requires external storage"))?;
        // Held across the publish so concurrent first calls upload once.
        let mut published = self
            .published
            .lock()
            .map_err(|_| RpcError::runtime_error("published_string cache poisoned"))?;
        let key = (value, include_sha256);
        if let Some(r) = published.get(&key) {
            return Ok(r.clone().into());
        }
        let schema = Arc::new(Schema::new(vec![Field::new(
            "result",
            <String as VgiArrow>::arrow_data_type(),
            <String as VgiArrow>::nullable(),
        )]));
        let column: ArrayRef = <String as VgiArrow>::build_singleton(key.0.clone())?;
        let batch = RecordBatch::try_new(schema, vec![column])?;
        let r = publish_external(&batch, storage.as_ref(), self.compression, include_sha256)?;
        published.insert(key, r.clone());
        Ok(r.into())
    }
}

/// Register `published_string`, publishing through `external`'s storage and
/// compression when the worker has them (and failing every call when not).
pub fn register(srv: &mut RpcServer, external: Option<&ExternalLocationConfig>) {
    let svc = PublishedSvc {
        storage: external.map(|cfg| Arc::clone(&cfg.storage)),
        compression: external.map_or(Compression::None, |cfg| cfg.compression),
        published: Mutex::new(HashMap::new()),
    };
    PublishedSvc::register_with(srv, Arc::new(svc));
}
