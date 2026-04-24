# vgi-rpc-gcs

Google Cloud Storage–backed [`ExternalStorage`](https://docs.rs/vgi-rpc/latest/vgi_rpc/external/trait.ExternalStorage.html)
adapter for [`vgi-rpc`](https://crates.io/crates/vgi-rpc).

Same design as [`vgi-rpc-s3`](https://crates.io/crates/vgi-rpc-s3): the
caller supplies a V4-signed PUT URL factory (backed by
`google-cloud-storage` or a custom signer) and this crate performs the
blocking HTTPS transfer. `HttpFetcher` is re-exported from
`vgi-rpc-s3` for the download side — one fetcher implementation for
both backends.

## Usage

```rust,no_run
use std::sync::Arc;
use vgi_rpc::external::{ExternalLocationConfig, Compression};
use vgi_rpc_gcs::{SignedGcsStorage, HttpFetcher};

let factory = Arc::new(|bucket: &str, object: &str| {
    // Produce a V4-signed PUT URL here using your preferred GCS signer.
    Ok(format!("https://storage.googleapis.com/{bucket}/{object}?X-Goog-Signature=..."))
});

let storage = SignedGcsStorage::new("my-bucket", "vgi-rpc/", factory);
let fetcher = HttpFetcher::new();

let cfg = ExternalLocationConfig::new(Arc::new(storage), Arc::new(fetcher))
    .with_compression(Compression::Zstd(3));
```

## License

Apache-2.0.
