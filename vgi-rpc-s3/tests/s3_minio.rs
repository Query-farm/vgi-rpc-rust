//! Direct S3 backend against a real S3-compatible server (MinIO).
//!
//! Skips (passes) unless `VGI_TEST_S3_ENDPOINT` is set. The lane sets:
//! `VGI_TEST_S3_ENDPOINT` (`http://` or `https://`; for a private CA also
//! `SSL_CERT_FILE`), `VGI_TEST_S3_BUCKET`, `VGI_TEST_S3_ACCESS_KEY_ID`,
//! `VGI_TEST_S3_SECRET_ACCESS_KEY` and optionally `VGI_TEST_S3_SESSION_TOKEN`
//! (MinIO STS AssumeRole credentials).
#![cfg(feature = "aws")]

use std::collections::HashMap;

use vgi_rpc::external::{Compression, ExternalStorage, ObjectStore, UploadUrlProvider};
use vgi_rpc_s3::s3::{S3Settings, S3Storage};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn settings(extra: &[(&str, String)]) -> Option<S3Settings> {
    let endpoint = env("VGI_TEST_S3_ENDPOINT")?;
    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("VGI_STORAGE_S3_ENDPOINT".into(), endpoint);
    map.insert("VGI_STORAGE_S3_BUCKET".into(), env("VGI_TEST_S3_BUCKET")?);
    map.insert("VGI_STORAGE_S3_PREFIX".into(), "vgi-rust-test/".into());
    map.insert(
        "VGI_STORAGE_S3_ACCESS_KEY_ID".into(),
        env("VGI_TEST_S3_ACCESS_KEY_ID")?,
    );
    map.insert(
        "VGI_STORAGE_S3_SECRET_ACCESS_KEY".into(),
        env("VGI_TEST_S3_SECRET_ACCESS_KEY")?,
    );
    if let Some(t) = env("VGI_TEST_S3_SESSION_TOKEN") {
        map.insert("VGI_STORAGE_S3_SESSION_TOKEN".into(), t);
    }
    for (k, v) in extra {
        map.insert((*k).to_string(), v.clone());
    }
    Some(S3Settings::from_lookup(&|k| map.get(k).cloned()).unwrap())
}

macro_rules! storage_or_skip {
    ($extra:expr) => {
        match settings($extra) {
            Some(s) => S3Storage::new(s),
            None => {
                eprintln!("skipping: VGI_TEST_S3_ENDPOINT is not set");
                return;
            }
        }
    };
}

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder().build().unwrap()
}

#[test]
fn object_store_round_trip_and_missing() {
    let s = storage_or_skip!(&[]);
    s.verify().unwrap();
    let data = b"state ref object \x00\x01".repeat(1000);
    let id = s.put_object(&data).unwrap();
    assert!(id.starts_with("vgi-rust-test/obj/"), "{id}");
    assert_eq!(s.get(&id, 1 << 20).unwrap(), data);
    let err = s.get("vgi-rust-test/obj/nope.bin", 1 << 20).unwrap_err();
    assert!(vgi_rpc::external::is_object_missing(&err), "{err:?}");
    assert!(s.get(&id, 10).is_err(), "cap must hold");
}

#[test]
fn result_upload_is_downloadable_with_encoding() {
    let s = storage_or_skip!(&[]);
    let body = b"arrow ipc bytes".repeat(500);
    let r = s.upload(&body, Compression::Zstd(3)).unwrap();
    assert!(r.url.contains("X-Amz-Signature="));
    let resp = http().get(&r.url).send().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-encoding")
            .unwrap()
            .to_str()
            .unwrap(),
        "zstd"
    );
    assert_eq!(resp.bytes().unwrap().as_ref(), body.as_slice());
}

#[test]
fn upload_grant_is_bound_to_size_and_digest() {
    use sha2::Digest as _;
    let s = storage_or_skip!(&[]);
    let body = b"client upload body".repeat(64);
    let sha: String = sha2::Sha256::digest(&body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let grant = s.generate_upload_url(body.len() as u64, &sha).unwrap();
    let put = |data: &[u8], with_header: bool| {
        let mut req = http().put(&grant.upload_url).body(data.to_vec());
        if with_header {
            for (k, v) in &grant.headers {
                req = req.header(k, v);
            }
        }
        req.send().unwrap().status().as_u16()
    };
    let mut flipped = body.clone();
    flipped[3] ^= 1;
    // Storage refuses each (R2 and MinIO differ on 400 vs 403).
    for (what, status) in [
        ("flipped byte", put(&flipped, true)),
        ("short body", put(&body[1..], true)),
        ("checksum header dropped", put(&body, false)),
    ] {
        assert!(status == 400 || status == 403, "{what}: HTTP {status}");
    }
    assert_eq!(put(&body, true), 200);
    let got = http().get(&grant.download_url).send().unwrap();
    assert_eq!(got.bytes().unwrap().as_ref(), body.as_slice());
    // An argument reference resolves by object id.
    assert_eq!(s.get(&grant.object_id, 1 << 20).unwrap(), body);
}

#[test]
fn checksum_none_stores_but_grants_nothing() {
    let s = storage_or_skip!(&[("VGI_STORAGE_S3_CHECKSUM", "none".to_string())]);
    assert!(!s.issues_upload_grants());
    let id = s.put_object(b"no checksum").unwrap();
    assert_eq!(s.get(&id, 100).unwrap(), b"no checksum");
    let r = s.upload(b"result", Compression::None).unwrap();
    assert_eq!(
        http().get(&r.url).send().unwrap().bytes().unwrap().as_ref(),
        b"result"
    );
    assert!(s.generate_upload_url(6, &"a".repeat(64)).is_err());
}

#[test]
fn bucket_check_names_the_problem() {
    let missing = storage_or_skip!(&[(
        "VGI_STORAGE_S3_BUCKET",
        "vgi-no-such-bucket-4c1e".to_string()
    )]);
    let err = missing.verify().unwrap_err();
    assert!(err.message.contains("does not exist"), "{}", err.message);
    assert!(missing.put_object(b"x").is_err());
    let denied = storage_or_skip!(&[
        ("VGI_STORAGE_S3_ACCESS_KEY_ID", "AKIDWRONGWRONG".to_string()),
        (
            "VGI_STORAGE_S3_SECRET_ACCESS_KEY",
            "wrongwrongwrong".to_string()
        ),
        ("VGI_STORAGE_S3_SESSION_TOKEN", String::new()),
    ]);
    let err = denied.verify().unwrap_err();
    assert!(err.message.contains("access denied"), "{}", err.message);
    assert!(!err.message.contains("wrongwrongwrong"));
}

#[test]
fn public_endpoint_is_used_only_for_handed_out_urls() {
    // The worker reaches storage at the endpoint; clients get URLs on the
    // public endpoint (here: the same server under a different host name).
    let Some(endpoint) = env("VGI_TEST_S3_ENDPOINT") else {
        eprintln!("skipping: VGI_TEST_S3_ENDPOINT is not set");
        return;
    };
    let public = endpoint.replace("127.0.0.1", "localhost");
    let s = storage_or_skip!(&[("VGI_STORAGE_S3_PUBLIC_ENDPOINT", public.clone())]);
    let r = s.upload(b"public", Compression::None).unwrap();
    assert!(r.url.starts_with(&public), "{}", r.url);
    assert_eq!(
        http().get(&r.url).send().unwrap().bytes().unwrap().as_ref(),
        b"public"
    );
    let id = s.put_object(b"internal").unwrap();
    assert_eq!(s.get(&id, 100).unwrap(), b"internal");
}
