<div align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi-rpc-rust/main/assets/vgi-logo.png" alt="Vector Gateway Interface" width="320">
</div>

# vgi-rpc-s3

S3-backed [`ExternalStorage`](https://docs.rs/vgi-rpc/latest/vgi_rpc/external/trait.ExternalStorage.html)
adapter for [`vgi-rpc`](https://crates.io/crates/vgi-rpc).

Design: **user-supplied pre-signed URL factory + blocking HTTPS
transfer**. Keeping the AWS SDK out of the direct dependency tree keeps
first-build times reasonable (no multi-minute compile hit) and lets
callers pick their preferred signing library (`aws-sdk-s3`, `rust-s3`,
or a hand-rolled SigV4).

## Usage

```rust,no_run
use std::sync::Arc;
use vgi_rpc::external::{ExternalLocationConfig, Compression};
use vgi_rpc_s3::{PresignedS3Storage, HttpFetcher};

// Produce method-bound PUT and GET URLs for the same object key.
let factory = Arc::new(|bucket: &str, key: &str| {
    Ok(vgi_rpc::external::UploadUrl {
        upload_url: format!("https://{bucket}.s3.amazonaws.com/{key}?put-signature=..."),
        download_url: format!("https://{bucket}.s3.amazonaws.com/{key}?get-signature=..."),
        expires_at_micros: 0, // Set to the actual signing expiry.
    })
});

let storage = PresignedS3Storage::new("my-bucket", "vgi-rpc/", factory);
let fetcher = HttpFetcher::new();

let cfg = ExternalLocationConfig::new(Arc::new(storage), Arc::new(fetcher))
    .with_threshold_bytes(1 << 20)           // 1 MiB
    .with_compression(Compression::Zstd(3));

// Attach to a server:
// let server = vgi_rpc::RpcServer::builder()
//     .with_external_location(cfg)
//     .build();
```

For MinIO / LocalStack testing, use
`with_url_validator(vgi_rpc::external::any_url_validator())` so
`http://` URLs are accepted.

## Migrating from the single-URL callback

The URL factory API intentionally changed incompatibly: callbacks must now
return `vgi_rpc::external::UploadUrl` with separately signed PUT and GET URLs.
Code returning one `String` must add a GET presign operation and populate
`download_url`; reusing the PUT URL is not supported because method-bound cloud
signatures cannot be downloaded with GET.

## License

Apache-2.0.
