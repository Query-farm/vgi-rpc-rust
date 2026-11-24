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
    map.insert(
        "VGI_STORAGE_S3_PREFIX".into(),
        format!(
            "{}vgi-rust-test/",
            env("VGI_TEST_S3_PREFIX").unwrap_or_default()
        ),
    );
    map.insert("VGI_STORAGE_ALLOW_PLAIN_HTTP".into(), "1".into());
    if let Some(r) = env("VGI_TEST_S3_REGION") {
        map.insert("VGI_STORAGE_S3_REGION".into(), r);
    }
    if let Some(e) = env("VGI_TEST_S3_SESSION_EXPIRES") {
        map.insert("VGI_STORAGE_S3_SESSION_EXPIRES".into(), e);
    }
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
    let prefix = s.settings().prefix.clone();
    assert!(id.starts_with(&format!("{prefix}rpc/")), "{id}");
    assert_eq!(s.get(&id, 1 << 20).unwrap(), data);
    let err = s
        .get(&format!("{prefix}rpc/nope.bin"), 1 << 20)
        .unwrap_err();
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
    // A body with another digest is a checksum failure (400): the checksum is
    // a signed header, not an unsigned query parameter the store would ignore.
    assert_eq!(put(&flipped, true), 400, "flipped byte");
    // Storage refuses the rest (stores differ on 400 vs 403).
    for (what, status) in [
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
    // A bucket-scoped credential (R2 tokens) gets 403 for any other bucket.
    assert!(
        err.message.contains("does not exist") || err.message.contains("access denied"),
        "{}",
        err.message
    );
    assert!(missing.put_object(b"x").is_err());
    let denied = storage_or_skip!(&[
        (
            "VGI_STORAGE_S3_ACCESS_KEY_ID",
            "0123456789abcdef0123456789abcdef".to_string()
        ),
        (
            "VGI_STORAGE_S3_SECRET_ACCESS_KEY",
            "wrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwron".to_string()
        ),
        ("VGI_STORAGE_S3_SESSION_TOKEN", String::new()),
    ]);
    let err = denied.verify().unwrap_err();
    // RustFS/MinIO answer 403; R2 answers 400 for an unknown access key.
    assert!(
        err.message.contains("access denied") || err.message.contains("was refused"),
        "{}",
        err.message
    );
    assert!(!err.message.contains("wrongwrongwrong"));
}

#[test]
fn function_storage_deletes_are_best_effort() {
    let s = storage_or_skip!(&[]);
    let scope = s.fs_key(&format!("scope-{}/", uuid_like()));
    for name in ["a", "b", "c"] {
        s.put_key(
            &format!("{scope}{name}"),
            name.as_bytes(),
            "application/octet-stream",
            None,
        )
        .unwrap();
    }
    s.delete_key(&format!("{scope}a"));
    assert!(s.get_key(&format!("{scope}a"), 10).unwrap().is_none());
    s.delete_key(&format!("{scope}missing")); // no error
    s.delete_prefix(&scope);
    // VGI_TEST_S3_NO_LIST: a credential without ListBucket (an R2 object
    // token) cannot delete by prefix; best effort means no error either way.
    if env("VGI_TEST_S3_NO_LIST").is_none() {
        assert!(s.get_key(&format!("{scope}b"), 10).unwrap().is_none());
        assert!(s.get_key(&format!("{scope}c"), 10).unwrap().is_none());
    }
}

fn uuid_like() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

#[test]
fn public_endpoint_is_used_only_for_handed_out_urls() {
    // The worker reaches storage at the endpoint; clients get URLs on the
    // public endpoint (here: the same server under a different host name).
    let Some(endpoint) = env("VGI_TEST_S3_ENDPOINT") else {
        eprintln!("skipping: VGI_TEST_S3_ENDPOINT is not set");
        return;
    };
    if !endpoint.contains("127.0.0.1") {
        eprintln!("public-endpoint check needs a loopback endpoint; not applicable");
        return;
    }
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
