<div align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi-rpc-rust/main/assets/vgi-logo.png" alt="Vector Gateway Interface" width="320">
</div>

# vgi-rpc-gcs

Google Cloud Storage–backed [`ExternalStorage`](https://docs.rs/vgi-rpc/latest/vgi_rpc/external/trait.ExternalStorage.html)
adapter for [`vgi-rpc`](https://crates.io/crates/vgi-rpc).

Same design as [`vgi-rpc-s3`](https://crates.io/crates/vgi-rpc-s3): the
caller supplies a factory for method-bound V4-signed PUT and GET URLs (backed by
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
    Ok(vgi_rpc::external::UploadUrl {
        upload_url: format!("https://storage.googleapis.com/{bucket}/{object}?put-signature=..."),
        download_url: format!("https://storage.googleapis.com/{bucket}/{object}?get-signature=..."),
        expires_at_micros: 0, // Set to the actual signing expiry.
    })
});

let storage = SignedGcsStorage::new("my-bucket", "vgi-rpc/", factory);
let fetcher = HttpFetcher::new();

let cfg = ExternalLocationConfig::new(Arc::new(storage), Arc::new(fetcher))
    .with_compression(Compression::Zstd(3));
```

This is an intentional breaking change from the former single-`String`
callback. Migrate by signing PUT and GET independently for the same object and
returning both in `vgi_rpc::external::UploadUrl`; the old PUT-as-download
behavior is not preserved.

## License

Apache-2.0.
