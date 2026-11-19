//! The blob-vendor client against vgi-rpc-python's fake vendor.
//!
//! Needs a running `vgi-rpc-fake-vendor --test-routes` (the vgi repo's
//! `test/start_fake_blob_vendor.sh` starts one and exports the variables):
//! `VGI_BLOB_VENDOR_URL` and `VGI_BLOB_VENDOR_TOKEN`. Skips without them. The
//! fault routes are vendor-wide, so everything runs in one test, in order.

use sha2::{Digest, Sha256};
use vgi_rpc::external::{Compression, ExternalStorage, UploadUrlProvider};
use vgi_rpc_s3::vendor::{BlobScope, VendorBlobClient, VendorStorage};

fn vendor() -> Option<(String, String)> {
    let url = std::env::var("VGI_BLOB_VENDOR_URL")
        .ok()
        .filter(|u| !u.is_empty())?;
    let token = std::env::var("VGI_BLOB_VENDOR_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())?;
    Some((url, token))
}

fn admin(base: &str, path: &str) {
    let resp = reqwest::blocking::get(format!("{}{path}", base.trim_end_matches('/'))).unwrap();
    assert!(resp.status().is_success(), "{path}: {}", resp.status());
}

fn stat(base: &str, key: &str) -> u64 {
    let body = reqwest::blocking::get(format!("{}/__stats__", base.trim_end_matches('/')))
        .unwrap()
        .text()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    v[key].as_u64().unwrap()
}

fn sha_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn vendor_client_against_the_fake_vendor() {
    let Some((url, token)) = vendor() else {
        eprintln!("skipping: VGI_BLOB_VENDOR_URL / VGI_BLOB_VENDOR_TOKEN not set");
        return;
    };
    admin(&url, "/__admin__/reset");
    let blobs = VendorBlobClient::new(&url, &token).unwrap();
    let scope = BlobScope {
        shard: "exe-test".into(),
        execution_id: format!("s.{}", &sha_hex(b"vendor_fake")[..16]),
    };

    // Round trip, verified against the reference.
    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let puts = stat(&url, "puts");
    let blob = blobs.put_bytes(&data, Some(&scope), Some("k.0")).unwrap();
    assert_eq!(stat(&url, "puts"), puts + 1);
    assert_eq!(blob.size, data.len() as u64);
    assert_eq!(blob.sha256, sha_hex(&data));
    assert_eq!(blobs.get_bytes(&blob).unwrap(), data);

    // Empty blob.
    let empty = blobs.put_bytes(b"", Some(&scope), None).unwrap();
    assert_eq!(blobs.get_bytes(&empty).unwrap(), Vec::<u8>::new());

    // Idempotency: same key, same bytes -> same object; other bytes -> 409.
    let again = blobs.put_bytes(&data, Some(&scope), Some("k.0")).unwrap();
    assert_eq!(again.object_id, blob.object_id);
    let conflict = blobs
        .put_bytes(b"other", Some(&scope), Some("k.0"))
        .unwrap_err();
    assert_eq!(conflict.code.as_deref(), Some("idempotency_conflict"));

    // A reference whose digest disagrees with the bytes fails verification.
    let mut lying = blob.clone();
    lying.sha256 = sha_hex(b"not it");
    assert_eq!(
        blobs.get_bytes(&lying).unwrap_err().code.as_deref(),
        Some("sha256_mismatch")
    );
    let mut short = blob.clone();
    short.size -= 1;
    assert_eq!(
        blobs.get_bytes(&short).unwrap_err().code.as_deref(),
        Some("size_mismatch")
    );

    // Fault routes: a corrupted download, then a missing one.
    admin(&url, "/__admin__/fault?purpose=fs&action=corrupt&count=1");
    let corrupt = blobs.get_bytes(&blob).unwrap_err();
    assert_eq!(
        corrupt.code.as_deref(),
        Some("sha256_mismatch"),
        "{corrupt}"
    );
    admin(&url, "/__admin__/reset");
    assert_eq!(blobs.get_bytes(&blob).unwrap(), data);
    let second = blobs.put_bytes(b"second blob", Some(&scope), None).unwrap();
    admin(&url, "/__admin__/fault?purpose=fs&action=missing&count=1");
    let missing = blobs.get_bytes(&second).unwrap_err();
    assert!(missing.is_missing(), "{missing:?}");
    assert!(
        !missing.message.contains("X-Amz-Signature"),
        "{}",
        missing.message
    );
    admin(&url, "/__admin__/reset");

    // Deletes: by id, then by scope.
    assert_eq!(
        blobs
            .delete(std::slice::from_ref(&second.object_id))
            .unwrap(),
        1
    );
    let gone = blobs.get_bytes(&second).unwrap_err();
    assert!(gone.is_missing(), "{gone:?}");
    assert!(
        blobs
            .delete_scope(&scope.shard, &scope.execution_id)
            .unwrap()
            >= 1
    );
    assert!(blobs.get_bytes(&blob).unwrap_err().is_missing());

    // Result storage: upload returns a pinned download URL of the exact bytes.
    let storage = VendorStorage::new(&url, &token).unwrap();
    let payload = b"arrow ipc bytes".repeat(100);
    let uploaded = storage.upload(&payload, Compression::None).unwrap();
    assert_eq!(uploaded.sha256, sha_hex(&payload));
    (storage.url_validator())(&uploaded.url).unwrap();
    let fetched = reqwest::blocking::get(&uploaded.url)
        .unwrap()
        .bytes()
        .unwrap();
    assert_eq!(&fetched[..], &payload[..]);

    // Client upload URLs: an unsized PUT/GET pair on the vendor's hosts.
    let pair = storage.generate_upload_url().unwrap();
    (storage.url_validator())(&pair.upload_url).unwrap();
    (storage.url_validator())(&pair.download_url).unwrap();
    let client = reqwest::blocking::Client::new();
    let put = client
        .put(&pair.upload_url)
        .body(b"client bytes".to_vec())
        .send()
        .unwrap();
    assert!(put.status().is_success(), "{}", put.status());
    let got = client
        .get(&pair.download_url)
        .send()
        .unwrap()
        .bytes()
        .unwrap();
    assert_eq!(&got[..], b"client bytes");

    // A wrong token is refused, and the message names no token.
    let bad = VendorBlobClient::new(&url, "wrong-token-SECRET").unwrap();
    let refused = bad.put_bytes(b"x", None, None).unwrap_err();
    assert_eq!(refused.status, Some(401));
    assert!(!refused.message.contains("SECRET"));
}
