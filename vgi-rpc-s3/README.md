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

// Produce a short-lived PUT URL for each upload — typically via
// aws-sdk-s3::Client::presigned_put_object(...).
let factory = Arc::new(|bucket: &str, key: &str| {
    Ok(format!("https://{bucket}.s3.amazonaws.com/{key}?X-Amz-Signature=..."))
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

## License

Apache-2.0.
