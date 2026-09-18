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

use vgi_rpc::token_identity::{token_digest, IdentityImpl, TokenIdentity};
use vgi_rpc::AuthContext;

const SUBJECT: &str = "opaque-subject-token";
const UNKNOWN: &str = "no-such-credential";
/// Resolvable only by a resolver that is down, so the outage path's log line —
/// the one written at `error`, and so the likeliest to be shipped — is one that
/// has seen the credential.
const OUTAGE: &str = "credential-during-an-outage";

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
        let identity = IdentityImpl::builder()
            .resolve_token(Arc::new(|token: &str| {
                if token == OUTAGE {
                    return Err(vgi_rpc::token_identity::identity_unavailable(
                        "token store unreachable",
                    ));
                }
                Ok((token == SUBJECT).then(|| TokenIdentity::new("subject@example")))
            }))
            .introspect_principals(["proxy"])
            .build();
        let caller = AuthContext::for_principal("test", "proxy");
        // Every path that reaches the resolver, because each has its own log
        // call: resolved, did not resolve, and could not find out.
        for token in [SUBJECT, UNKNOWN, OUTAGE] {
            let _ = identity.introspect_token(token, &caller);
        }
    });
    let log = String::from_utf8(buf.lock().unwrap().clone()).expect("utf-8 log");

    for secret in [SUBJECT, UNKNOWN, OUTAGE] {
        assert!(
            !log.contains(secret),
            "the credential reached the log: {log}"
        );
    }
    // Digested rather than dropped: a diagnostic that cannot correlate one
    // credential's failures across records is not worth emitting.
    for secret in [SUBJECT, UNKNOWN, OUTAGE] {
        assert!(
            log.contains(&token_digest(secret)),
            "no digest for {secret} in: {log}"
        );
    }
}
