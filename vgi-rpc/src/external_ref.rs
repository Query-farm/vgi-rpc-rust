//! Pre-published external references for unary results.
//!
//! A unary method normally answers with its result batch, which the server
//! may externalize (upload, then send a pointer) when it exceeds the
//! configured threshold. Some results are large and change rarely — the same
//! bytes for every caller until the worker is redeployed — so re-serializing
//! and re-uploading them per call wastes CPU and storage and makes the URL
//! uncacheable. An [`ExternalRef`] lets the worker publish the payload once
//! (see `crate::external::publish_external`), keep the reference, and hand
//! the same reference back on later calls: the dispatcher writes the
//! ExternalLocation pointer batch directly.
//!
//! The wire is unchanged (WIRE_PROTOCOL.md §12 "Pre-published references"):
//! one zero-row batch with the method's result schema carrying
//! `vgi_rpc.location`, plus `vgi_rpc.location.sha256` only when the ref has a
//! digest. Clients resolve it like any other pointer.
//!
//! This module is deliberately unfeatured: answering with a ref needs no
//! storage backend, compression, or HTTP stack — only the pointer metadata
//! keys — so a server built without `external` can still return one.

use arrow_array::RecordBatch;
use arrow_schema::Schema;

use crate::errors::{Result, RpcError};
use crate::metadata::{LOCATION_KEY, LOCATION_SHA256_KEY};
use crate::wire::{empty_batch, Metadata};

/// A reference to an already-published unary result.
///
/// A unary method may answer with an `ExternalRef` in place of its declared
/// result value (return [`RefOr::Ref`] from a `#[unary]` method, or call
/// [`CallContext::respond_with_external_ref`](crate::CallContext::respond_with_external_ref)
/// from a hand-registered handler). The server then writes the
/// ExternalLocation pointer batch for [`url`](Self::url) directly — no result
/// serialization, compression, or upload happens during the call, and the
/// ref is used whether or not the server has external storage configured and
/// regardless of the externalization threshold. It is never inlined or routed
/// through shared memory, and it does not count toward
/// `max_externalized_response_bytes`.
///
/// Build one with `crate::external::publish_external` (or by hand with
/// [`ExternalRef::new`] for an object published out of band). The object at
/// the URL must be an Arrow IPC stream (optionally `Content-Encoding`
/// compressed) whose schema is the method's result schema and which holds
/// exactly one 1-row data batch.
///
/// The caller owns caching the ref and the object's lifecycle: a long-lived
/// ref must not point at an object under the short-TTL lifecycle rule used
/// for per-call uploads, and a pre-signed URL expires — re-sign or rebuild
/// the ref before then. Only return a ref to callers who are all entitled to
/// the same content.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExternalRef {
    url: String,
    sha256: Option<String>,
}

impl ExternalRef {
    /// Build a reference to the object at `url`.
    ///
    /// `sha256` is the lowercase hex SHA-256 of the raw (pre-compression)
    /// IPC stream bytes, sent as `vgi_rpc.location.sha256`. `None` omits the
    /// key so clients skip the content check — use it for an object rewritten
    /// in place, or one too large to be worth hashing on every fetch.
    ///
    /// # Errors
    ///
    /// A `ValueError` when `url` is empty or `sha256` is not exactly 64
    /// lowercase hex characters.
    pub fn new(url: impl Into<String>, sha256: Option<String>) -> Result<Self> {
        let url = url.into();
        if url.is_empty() {
            return Err(RpcError::value_error("ExternalRef.url must be non-empty"));
        }
        if let Some(digest) = sha256.as_deref() {
            let well_formed = digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !well_formed {
                return Err(RpcError::value_error(
                    "ExternalRef.sha256 must be 64 lowercase hex characters (or None)",
                ));
            }
        }
        Ok(Self { url, sha256 })
    }

    /// Where the published IPC stream lives.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Lowercase hex SHA-256 of the raw IPC stream bytes, when recorded.
    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }

    /// Build the zero-row pointer batch announcing this ref.
    ///
    /// `schema` is the method's result schema. The metadata carries
    /// `vgi_rpc.location` and, only when the ref has a digest,
    /// `vgi_rpc.location.sha256` — the same two keys the per-call
    /// externalizer writes.
    pub fn pointer_batch(&self, schema: &Schema) -> Result<(RecordBatch, Metadata)> {
        let batch = empty_batch(schema)?;
        let mut md = Metadata::new();
        md.insert(LOCATION_KEY.to_string(), self.url.clone());
        if let Some(digest) = &self.sha256 {
            md.insert(LOCATION_SHA256_KEY.to_string(), digest.clone());
        }
        Ok((batch, md))
    }
}

/// A unary result that is either a value or a pre-published [`ExternalRef`].
///
/// Declare a `#[unary]` method as `-> Result<RefOr<T>>` to let it answer
/// with a ref: the result schema is derived from `T` exactly as for
/// `-> Result<T>` (so the protocol hash is unchanged), `RefOr::Value(v)` is
/// sent like an ordinary `T`, and `RefOr::Ref(r)` makes the dispatcher write
/// `r`'s pointer batch. `ExternalRef` converts with `.into()`.
///
/// ```ignore
/// #[unary]
/// fn catalog(&self, ctx: &CallContext) -> Result<RefOr<String>> {
///     Ok(self.cached_ref()?.into())
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefOr<T> {
    /// An ordinary result value.
    Value(T),
    /// A pre-published reference; answered with its pointer batch.
    Ref(ExternalRef),
}

impl<T> From<ExternalRef> for RefOr<T> {
    fn from(r: ExternalRef) -> Self {
        RefOr::Ref(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::md_get;
    use arrow_schema::{DataType, Field};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_url_with_and_without_digest() {
        let r = ExternalRef::new("https://bucket/obj", Some(DIGEST.to_string())).unwrap();
        assert_eq!(r.url(), "https://bucket/obj");
        assert_eq!(r.sha256(), Some(DIGEST));
        let r = ExternalRef::new("https://bucket/obj", None).unwrap();
        assert_eq!(r.sha256(), None);
    }

    #[test]
    fn rejects_empty_url() {
        let err = ExternalRef::new("", None).unwrap_err();
        assert_eq!(err.error_type, "ValueError");
        assert!(err.message.contains("non-empty"));
    }

    #[test]
    fn rejects_malformed_digest() {
        for bad in [
            String::new(),
            "abc".to_string(),
            DIGEST.to_uppercase(),
            format!("{}0", DIGEST),
            DIGEST.replace('a', "g"),
        ] {
            let err = ExternalRef::new("https://bucket/obj", Some(bad.clone())).unwrap_err();
            assert_eq!(err.error_type, "ValueError", "{bad:?}");
            assert!(err.message.contains("64 lowercase hex"), "{bad:?}");
        }
    }

    #[test]
    fn pointer_batch_carries_location_and_digest_only_when_present() {
        let schema = Schema::new(vec![Field::new("result", DataType::Utf8, false)]);
        let with = ExternalRef::new("https://h/o", Some(DIGEST.to_string())).unwrap();
        let (batch, md) = with.pointer_batch(&schema).unwrap();
        assert_eq!(batch.num_rows(), 0);
        assert_eq!(batch.schema().as_ref(), &schema);
        assert_eq!(md_get(&md, LOCATION_KEY), Some("https://h/o"));
        assert_eq!(md_get(&md, LOCATION_SHA256_KEY), Some(DIGEST));
        assert_eq!(md.len(), 2);

        let without = ExternalRef::new("https://h/o", None).unwrap();
        let (_, md) = without.pointer_batch(&schema).unwrap();
        assert_eq!(md_get(&md, LOCATION_KEY), Some("https://h/o"));
        assert!(md_get(&md, LOCATION_SHA256_KEY).is_none());
        assert_eq!(md.len(), 1);
    }

    #[test]
    fn ref_converts_into_ref_or() {
        let r = ExternalRef::new("https://h/o", None).unwrap();
        let v: RefOr<String> = r.clone().into();
        assert_eq!(v, RefOr::Ref(r));
    }
}
