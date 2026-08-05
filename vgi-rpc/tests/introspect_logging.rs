//! Guard: the subject credential never reaches a log record.
//!
//! The conformance group can only see responses, so a credential leaking into a
//! log line is invisible to it — and just as bad, because that is the copy that
//! ends up shipped to a log aggregator and retained for months.
//!
//! Deliberately the **only** test in this binary. `tracing` caches callsite
//! interest globally on first use, so a sibling test hitting these same log
//! statements while no subscriber is installed can leave the capture empty and
//! turn the assertion into a coin flip.

use std::sync::{Arc, Mutex};

use vgi_rpc::auth::introspect::{
    token_digest, TokenIdentity, TokenIntrospector, DEFAULT_INTROSPECT_RATE_LIMIT,
    DEFAULT_INTROSPECT_TTL_SECONDS,
};
use vgi_rpc::AuthContext;

const SUBJECT: &str = "opaque-subject-token";
const UNKNOWN: &str = "no-such-credential";
/// JWS-shaped *and* resolvable, so the shape guard is what refuses it — and so
/// the refusal's log line is one that has seen the credential.
const JWS: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";

/// Collects a subscriber's formatted output so the test can assert on what was
/// — and was not — written.
#[derive(Clone, Default)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureWriter {
    type Writer = CaptureWriter;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn the_credential_never_reaches_a_log_record() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(CaptureWriter(buf.clone()))
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let it = TokenIntrospector::new(
            Arc::new(|token: &str| {
                Ok((token == SUBJECT || token == JWS)
                    .then(|| TokenIdentity::new("subject@example")))
            }),
            ["proxy"],
            DEFAULT_INTROSPECT_TTL_SECONDS,
            DEFAULT_INTROSPECT_RATE_LIMIT,
        );
        let caller = AuthContext::for_principal("test", "proxy");
        // Every path that touches the token, because each has its own log call.
        for token in [SUBJECT, UNKNOWN, JWS] {
            let body = serde_json::json!({ "token": token }).to_string();
            it.introspect(&caller, body.as_bytes());
        }
    });
    let log = String::from_utf8(buf.lock().unwrap().clone()).expect("utf-8 log");

    for secret in [SUBJECT, UNKNOWN, JWS] {
        assert!(
            !log.contains(secret),
            "the credential reached the log: {log}"
        );
    }
    // Digested rather than dropped: a diagnostic that cannot correlate one
    // credential's failures across records is not worth emitting.
    for secret in [SUBJECT, UNKNOWN, JWS] {
        assert!(
            log.contains(&token_digest(secret)),
            "no digest for {secret} in: {log}"
        );
    }
}
