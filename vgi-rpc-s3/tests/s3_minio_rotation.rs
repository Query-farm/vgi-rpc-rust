//! Credential rotation through the standard AWS chain: a `credential_process`
//! profile that mints MinIO STS AssumeRole credentials and reports them as
//! expiring in about 5 minutes, so the worker refreshes on every call. Objects
//! stored under one set of temporary credentials resolve under the next.
//!
//! Skips unless `VGI_TEST_S3_ENDPOINT` and `VGI_TEST_S3_CREDENTIAL_PROCESS`
//! (the script; it appends a line to `$VGI_TEST_S3_CREDENTIAL_LOG` per call)
//! are set. Its own test binary: it sets process-wide `AWS_*` variables.
#![cfg(feature = "aws")]

use std::collections::HashMap;

use vgi_rpc::external::{Compression, ExternalStorage, ObjectStore};
use vgi_rpc_s3::s3::{S3Settings, S3Storage};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[test]
fn objects_survive_credential_rotation() {
    let (Some(endpoint), Some(bucket), Some(process), Some(log)) = (
        env("VGI_TEST_S3_ENDPOINT"),
        env("VGI_TEST_S3_BUCKET"),
        env("VGI_TEST_S3_CREDENTIAL_PROCESS"),
        env("VGI_TEST_S3_CREDENTIAL_LOG"),
    ) else {
        eprintln!("skipping: VGI_TEST_S3_ENDPOINT / VGI_TEST_S3_CREDENTIAL_PROCESS not set");
        return;
    };
    let dir = std::env::temp_dir().join(format!("vgi-s3-rotation-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config");
    std::fs::write(
        &config,
        format!("[profile vgi-rotation]\ncredential_process = {process}\nregion = us-east-1\n"),
    )
    .unwrap();
    for k in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("AWS_CONFIG_FILE", &config);
    std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", dir.join("none"));
    std::env::set_var("AWS_PROFILE", "vgi-rotation");
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    let _ = std::fs::remove_file(&log);

    let map: HashMap<&str, String> = HashMap::from([
        ("VGI_STORAGE_S3_ENDPOINT", endpoint),
        ("VGI_STORAGE_S3_BUCKET", bucket),
        ("VGI_STORAGE_S3_PREFIX", "vgi-rust-rotation/".to_string()),
        ("VGI_STORAGE_ALLOW_PLAIN_HTTP", "1".to_string()),
    ]);
    let settings = S3Settings::from_lookup(&|k| map.get(k).cloned()).unwrap();
    assert!(settings.explicit_credentials.is_none());
    let s = S3Storage::new(settings);

    let id = s.put_object(b"stored under the first credentials").unwrap();
    let result = s.upload(b"result", Compression::None).unwrap();
    let first: Vec<String> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    // Let the 5-minute refresh window pass the reported expiry.
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(
        s.get(&id, 1024).unwrap(),
        b"stored under the first credentials"
    );
    let calls: Vec<String> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert!(
        calls.len() > first.len(),
        "credentials were not refreshed: {} calls before, {} after",
        first.len(),
        calls.len()
    );
    assert_ne!(
        first.last(),
        calls.last(),
        "the refresh returned the same key"
    );
    // The URL handed out under the first credentials carries a session token
    // and is capped at their (reported) lifetime.
    let q: HashMap<String, String> = url::Url::parse(&result.url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    assert!(q.contains_key("X-Amz-Security-Token"));
    assert!(q["X-Amz-Expires"].parse::<u64>().unwrap() <= 300);
    std::fs::remove_dir_all(&dir).ok();
}
