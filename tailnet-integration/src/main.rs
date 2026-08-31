// © Copyright 2025-2026, Query.Farm LLC - https://query.farm
// SPDX-License-Identifier: Apache-2.0

//! Live-Tailnet qualification adapter for the Rust implementation.
//!
//! This binary exists only for cross-language conformance. It is not a
//! production proxy, ingress, or alternate worker API.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arrow_array::{RecordBatch, StringArray};
use arrow_schema::Schema;
use serde_json::Value;
use sha2::{Digest, Sha256};
use vgi_rpc::{
    peer_identity_primary, require_peer_identity, AuthContext, IdentityAssurance, PeerEvidenceSet,
    PeerIdentityStatus, SubjectKind, SubjectStability,
};

const PROVIDER: &str = "tailscale";

#[derive(Clone)]
struct Expectation {
    issuer: String,
    evidence_source: String,
    assurance: IdentityAssurance,
    subject_kind: SubjectKind,
    subject_stability: SubjectStability,
    capability: String,
    capability_target_kind: Option<String>,
    capability_target_value: Option<String>,
    tag: Option<String>,
    authenticated: bool,
    proxy_present: bool,
    spoofed_subject_fingerprint: Option<String>,
}

struct TailnetProbe {
    expected: Expectation,
}

#[vgi_rpc::service]
impl TailnetProbe {
    #[unary]
    fn echo_string(&self, ctx: &vgi_rpc::CallContext, value: String) -> vgi_rpc::Result<String> {
        validate_context(ctx, &self.expected)?;
        Ok(value)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("vgi-rpc-tailnet-rust: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("client-tcp") => run_tcp_client(&args[2..]),
        Some("client-http") => run_http_client(&args[2..]),
        Some("server-tcp") => run_tcp_server(&args[2..]),
        Some("server-http") => run_http_server(&args[2..]),
        _ => Err(
            "usage: vgi-rpc-tailnet-rust client-tcp|client-http|server-tcp|server-http [options]"
                .into(),
        ),
    }
}

fn run_tcp_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let host = required(args, "--host")?;
    let port = required(args, "--port")?.parse::<u16>()?;
    let mut client = if let Some(proxy) = optional(args, "--proxy") {
        let proxy = vgi_rpc_client::Socks5hProxy::parse(proxy)?;
        vgi_rpc_client::RpcClient::tcp_connect_socks5h(
            proxy,
            host,
            port,
            Duration::from_secs(20),
            Some(Duration::from_secs(20)),
        )?
    } else {
        vgi_rpc_client::RpcClient::tcp_connect(host, port)?
    };
    let expected = client_expectation(args)?;
    let mut first = None;
    for _ in 0..2 {
        let raw = call_snapshot_byte_stream(&mut client)?;
        let snapshot = validate_snapshot(&raw, &expected)?;
        if let Some(first) = &first {
            if first != &snapshot {
                return Err("Tailnet evidence changed within one TCP connection".into());
            }
        } else {
            first = Some(snapshot);
        }
    }
    client.close()?;
    println!("Rust TCP client Tailnet probe passed");
    Ok(())
}

fn run_http_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let url = required(args, "--url")?;
    let mut builder =
        vgi_rpc_client::HttpClient::connect(url).timeout(Some(Duration::from_secs(20)));
    if let Some(login) = optional(args, "--spoof-login") {
        builder = builder.header("Tailscale-User-Login", login)?;
    }
    let mut client = builder.build()?;
    let expected = client_expectation(args)?;
    let mut first = None;
    for _ in 0..2 {
        let params = empty_params()?;
        let (result, _) = client.call_unary("snapshot", &params, None)?;
        let raw = result
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("snapshot result was not a string")?
            .value(0);
        let snapshot = validate_snapshot(raw, &expected)?;
        if let Some(first) = &first {
            if first != &snapshot {
                return Err("Tailnet evidence changed between HTTP probe calls".into());
            }
        } else {
            first = Some(snapshot);
        }
    }
    println!("Rust HTTP client Tailnet probe passed");
    Ok(())
}

fn run_tcp_server(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = required(args, "--issuer")?;
    let socket =
        optional(args, "--localapi-socket").unwrap_or("/var/run/tailscale/tailscaled.sock");
    let expected = Expectation {
        issuer: issuer.into(),
        evidence_source: "localapi".into(),
        assurance: IdentityAssurance::LocalDaemon,
        subject_kind: SubjectKind::TaggedNode,
        subject_stability: SubjectStability::Stable,
        capability: required(args, "--expected-capability")?.into(),
        capability_target_kind: Some("destination_ip".into()),
        capability_target_value: None,
        tag: Some(required(args, "--expected-tag")?.into()),
        authenticated: true,
        proxy_present: false,
        spoofed_subject_fingerprint: None,
    };
    let provider = vgi_rpc::tailscale_localapi_provider(
        vgi_rpc::TailscaleLocalApiConfig::new(issuer)?.with_unix_socket(socket)?,
    )?;
    let identity = vgi_rpc::tcp::TcpIdentityOptions {
        providers: Arc::from([provider]),
        policy: Some(peer_identity_primary(PROVIDER)),
        ..Default::default()
    };
    let server = probe_server(expected);
    let shutdown = install_shutdown();
    let host = optional(args, "--host").unwrap_or("0.0.0.0");
    let port = optional(args, "--port").unwrap_or("19400").parse::<u16>()?;
    vgi_rpc::tcp::serve_tcp_with_identity(
        server,
        host,
        port,
        None,
        shutdown,
        identity,
        |bound_host, bound_port| println!("TCP:{bound_host}:{bound_port}"),
    )?;
    Ok(())
}

fn run_http_server(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = required(args, "--issuer")?;
    let trusted = [
        optional(args, "--trusted-proxy-ipv4").unwrap_or("127.0.0.1"),
        optional(args, "--trusted-proxy-ipv6").unwrap_or("::1"),
    ];
    let provider = vgi_rpc::tailscale_serve_header_provider(vgi_rpc::TailscaleServeConfig::new(
        issuer, trusted,
    )?)?;
    let expected = Expectation {
        issuer: issuer.into(),
        evidence_source: "serve_proxy".into(),
        assurance: IdentityAssurance::ConfiguredProxy,
        subject_kind: SubjectKind::Unknown,
        subject_stability: SubjectStability::None,
        capability: required(args, "--expected-capability")?.into(),
        capability_target_kind: None,
        capability_target_value: None,
        tag: None,
        authenticated: false,
        proxy_present: true,
        spoofed_subject_fingerprint: None,
    };
    let state = vgi_rpc::http::HttpState::builder()
        .server(probe_server(expected))
        .peer_identity_providers([provider])
        .peer_authentication_policy(require_peer_identity(PROVIDER))
        .build();
    let host = optional(args, "--host").unwrap_or("127.0.0.1");
    let port = optional(args, "--port").unwrap_or("18080").parse::<u16>()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind((host, port)).await?;
        println!("HTTP:{host}:{port}");
        vgi_rpc::http::serve_with_shutdown(state, listener).await
    })?;
    Ok(())
}

fn probe_server(expected: Expectation) -> Arc<vgi_rpc::RpcServer> {
    let mut server = vgi_rpc::RpcServer::builder()
        .protocol_name("ConformanceService")
        .protocol_version("2.0.0")
        .build();
    TailnetProbe::register_with(&mut server, Arc::new(TailnetProbe { expected }));
    Arc::new(server)
}

fn validate_context(ctx: &vgi_rpc::CallContext, expected: &Expectation) -> vgi_rpc::Result<()> {
    validate_evidence_and_auth(&ctx.peer_evidence, &ctx.auth, expected)
}

fn validate_evidence_and_auth(
    evidence: &PeerEvidenceSet,
    auth: &AuthContext,
    expected: &Expectation,
) -> vgi_rpc::Result<()> {
    if evidence.status(PROVIDER) != PeerIdentityStatus::Available {
        return Err(vgi_rpc::RpcError::permission_error(
            "Tailscale evidence was not available",
        ));
    }
    let identities = evidence.for_provider(PROVIDER).collect::<Vec<_>>();
    let [identity] = identities.as_slice() else {
        return Err(vgi_rpc::RpcError::permission_error(
            "expected exactly one Tailscale identity",
        ));
    };
    let tags = identity
        .attributes()
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let tag_ok = expected.tag.as_deref().is_none_or(|tag| tags.contains(tag));
    let target_ok = capability_target_matches(identity.attributes(), expected);
    let policy_auth = if expected.authenticated {
        peer_identity_primary(PROVIDER)(evidence, &AuthContext::anonymous())?
    } else {
        require_peer_identity(PROVIDER)(evidence, &AuthContext::anonymous())?
    };
    if identity.issuer() != expected.issuer
        || identity.evidence_source() != expected.evidence_source
        || identity.assurance() != expected.assurance
        || identity.subject_kind() != expected.subject_kind
        || identity.subject_stability() != expected.subject_stability
        || !identity.capabilities_verified()
        || !identity.capabilities().contains_key(&expected.capability)
        || identity.proxy_address().is_some() != expected.proxy_present
        || auth.authenticated != expected.authenticated
        || auth.domain != policy_auth.domain
        || auth.principal != policy_auth.principal
        || auth.claims != policy_auth.claims
        || !valid_binding(auth.claims.get("peer_evidence_binding"))
        || !target_ok
        || !tag_ok
    {
        return Err(vgi_rpc::RpcError::permission_error(
            "unexpected Tailscale identity or authentication context",
        ));
    }
    Ok(())
}

fn capability_target_matches(
    attributes: &std::collections::BTreeMap<String, Value>,
    expected: &Expectation,
) -> bool {
    let Some(expected_kind) = expected.capability_target_kind.as_deref() else {
        return !attributes.contains_key("capability_target");
    };
    let Some(target) = attributes
        .get("capability_target")
        .and_then(Value::as_object)
    else {
        return false;
    };
    if target.get("kind").and_then(Value::as_str) != Some(expected_kind) {
        return false;
    }
    match expected.capability_target_value.as_deref() {
        Some(value) => target.get("value").and_then(Value::as_str) == Some(value),
        None if expected_kind == "destination_ip" => target
            .get("value")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
            .is_some(),
        None => true,
    }
}

fn valid_binding(value: Option<&String>) -> bool {
    value.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn call_snapshot_byte_stream(
    client: &mut vgi_rpc_client::RpcClient,
) -> Result<String, Box<dyn std::error::Error>> {
    let params = empty_params()?;
    let (result, _) = client.call_unary("snapshot", &params, None)?;
    Ok(result
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or("snapshot result was not a string")?
        .value(0)
        .to_owned())
}

fn empty_params() -> Result<RecordBatch, Box<dyn std::error::Error>> {
    Ok(vgi_rpc::wire::empty_batch(&Schema::empty())?)
}

fn client_expectation(args: &[String]) -> Result<Expectation, Box<dyn std::error::Error>> {
    let authenticated = has_flag(args, "--expect-authenticated");
    Ok(Expectation {
        issuer: required(args, "--expected-issuer")?.into(),
        evidence_source: required(args, "--expected-evidence-source")?.into(),
        assurance: parse_assurance(required(args, "--expected-assurance")?)?,
        subject_kind: parse_subject_kind(required(args, "--expected-subject-kind")?)?,
        subject_stability: parse_stability(required(args, "--expected-subject-stability")?)?,
        capability: required(args, "--expected-capability")?.into(),
        capability_target_kind: optional(args, "--expected-target-kind").map(str::to_owned),
        capability_target_value: optional(args, "--expected-target-value").map(str::to_owned),
        tag: optional(args, "--expected-tag").map(str::to_owned),
        authenticated,
        proxy_present: has_flag(args, "--expect-proxy"),
        spoofed_subject_fingerprint: optional(args, "--spoof-login")
            .map(|login| sha256_hex(format!("login:{login}").as_bytes())),
    })
}

fn validate_snapshot(
    raw: &str,
    expected: &Expectation,
) -> Result<Value, Box<dyn std::error::Error>> {
    let value: Value = serde_json::from_str(raw)?;
    let statuses = value["provider_status"]
        .as_object()
        .ok_or("snapshot provider status was absent")?;
    let identities = value["identities"]
        .as_array()
        .ok_or("snapshot identities were absent")?;
    let identity = identities
        .first()
        .filter(|_| identities.len() == 1)
        .ok_or("snapshot did not contain exactly one identity")?;
    let capabilities = identity["capability_names"]
        .as_array()
        .ok_or("snapshot capabilities were absent")?;
    let subject_expected = expected.subject_stability != SubjectStability::None;
    let subject_fingerprint = identity["subject_fingerprint"].as_str();
    let target_matches = snapshot_target_matches(identity, expected);
    let expected_domain = expected.authenticated.then_some(PROVIDER);
    let actual_domain = value["auth"]["domain"].as_str();
    let principal_fingerprint = value["auth"]["principal_fingerprint"].as_str();
    let spoof_resistant = expected
        .spoofed_subject_fingerprint
        .as_deref()
        .is_none_or(|spoofed| subject_fingerprint != Some(spoofed));
    let matches = statuses.len() == 1
        && value["provider_status"][PROVIDER] == "available"
        && identity["provider"] == PROVIDER
        && identity["issuer"] == expected.issuer
        && identity["evidence_source"] == expected.evidence_source
        && identity["assurance"] == assurance_name(expected.assurance)
        && identity["subject_kind"] == subject_kind_name(expected.subject_kind)
        && identity["subject_stability"] == stability_name(expected.subject_stability)
        && identity["subject_verified"] == subject_expected
        && subject_fingerprint.is_some() == subject_expected
        && subject_fingerprint.is_none_or(is_sha256_hex)
        && identity["capabilities_verified"] == true
        && capabilities.iter().any(|item| item == &expected.capability)
        && identity["proxy_present"] == expected.proxy_present
        && value["auth"]["authenticated"] == expected.authenticated
        && actual_domain == expected_domain
        && principal_fingerprint.is_some() == expected.authenticated
        && principal_fingerprint.is_none_or(is_sha256_hex)
        && value["auth"]["principal_matches_identity"] == expected.authenticated
        && value["auth"]["peer_evidence_binding_present"] == true
        && target_matches
        && spoof_resistant;
    if !matches {
        return Err(format!("unexpected Tailnet snapshot: {raw}").into());
    }
    Ok(value)
}

fn snapshot_target_matches(identity: &Value, expected: &Expectation) -> bool {
    let Some(expected_kind) = expected.capability_target_kind.as_deref() else {
        return identity["capability_target"].is_null();
    };
    let target = &identity["capability_target"];
    if target["kind"] != expected_kind {
        return false;
    }
    match expected.capability_target_value.as_deref() {
        Some(value) => target["value"] == value,
        // The qualification service deliberately redacts destination IP values.
        None if expected_kind == "destination_ip" => target.get("value").is_none(),
        None => true,
    }
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn install_shutdown() -> Arc<AtomicBool> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    let _ = ctrlc::try_set_handler(move || signal.store(true, Ordering::Relaxed));
    shutdown
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    optional(args, name).ok_or_else(|| format!("required option is missing: {name}").into())
}

fn optional<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn parse_assurance(value: &str) -> Result<IdentityAssurance, Box<dyn std::error::Error>> {
    match value {
        "cryptographic_peer" => Ok(IdentityAssurance::CryptographicPeer),
        "local_daemon" => Ok(IdentityAssurance::LocalDaemon),
        "configured_proxy" => Ok(IdentityAssurance::ConfiguredProxy),
        _ => Err(format!("unknown assurance: {value}").into()),
    }
}

fn parse_subject_kind(value: &str) -> Result<SubjectKind, Box<dyn std::error::Error>> {
    match value {
        "user" => Ok(SubjectKind::User),
        "tagged_node" => Ok(SubjectKind::TaggedNode),
        "workload" => Ok(SubjectKind::Workload),
        "endpoint" => Ok(SubjectKind::Endpoint),
        "unknown" => Ok(SubjectKind::Unknown),
        _ => Err(format!("unknown subject kind: {value}").into()),
    }
}

fn parse_stability(value: &str) -> Result<SubjectStability, Box<dyn std::error::Error>> {
    match value {
        "stable" => Ok(SubjectStability::Stable),
        "login" => Ok(SubjectStability::Login),
        "none" => Ok(SubjectStability::None),
        _ => Err(format!("unknown subject stability: {value}").into()),
    }
}

fn assurance_name(value: IdentityAssurance) -> &'static str {
    match value {
        IdentityAssurance::CryptographicPeer => "cryptographic_peer",
        IdentityAssurance::LocalDaemon => "local_daemon",
        IdentityAssurance::ConfiguredProxy => "configured_proxy",
    }
}

fn subject_kind_name(value: SubjectKind) -> &'static str {
    match value {
        SubjectKind::User => "user",
        SubjectKind::TaggedNode => "tagged_node",
        SubjectKind::Workload => "workload",
        SubjectKind::Endpoint => "endpoint",
        SubjectKind::Unknown => "unknown",
    }
}

fn stability_name(value: SubjectStability) -> &'static str {
    match value {
        SubjectStability::Stable => "stable",
        SubjectStability::Login => "login",
        SubjectStability::None => "none",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use vgi_rpc::{PeerIdentity, PeerIdentityResult};

    use super::*;

    fn tcp_expectation() -> Expectation {
        Expectation {
            issuer: "tailnet:test".into(),
            evidence_source: "localapi".into(),
            assurance: IdentityAssurance::LocalDaemon,
            subject_kind: SubjectKind::TaggedNode,
            subject_stability: SubjectStability::Stable,
            capability: "query.farm/cap".into(),
            capability_target_kind: Some("destination_ip".into()),
            capability_target_value: None,
            tag: Some("tag:vgi-client".into()),
            authenticated: true,
            proxy_present: false,
            spoofed_subject_fingerprint: None,
        }
    }

    fn tcp_snapshot() -> Value {
        json!({
            "provider_status": {"tailscale": "available"},
            "identities": [{
                "provider": "tailscale",
                "issuer": "tailnet:test",
                "evidence_source": "localapi",
                "assurance": "local_daemon",
                "subject_kind": "tagged_node",
                "subject_stability": "stable",
                "subject_verified": true,
                "subject_fingerprint": "a".repeat(64),
                "tags": ["tag:vgi-client"],
                "capability_names": ["query.farm/cap"],
                "capabilities_verified": true,
                "capability_target": {"kind": "destination_ip"},
                "proxy_present": false
            }],
            "auth": {
                "authenticated": true,
                "domain": "tailscale",
                "principal_fingerprint": "b".repeat(64),
                "principal_matches_identity": true,
                "peer_evidence_binding_present": true
            }
        })
    }

    #[test]
    fn snapshot_requires_issuer_target_and_bound_primary_auth() {
        let expected = tcp_expectation();
        let snapshot = tcp_snapshot();
        validate_snapshot(&snapshot.to_string(), &expected).unwrap();

        for (path, replacement) in [
            (&["identities", "0", "issuer"][..], json!("tailnet:other")),
            (&["auth", "domain"][..], json!("bearer")),
            (&["auth", "principal_matches_identity"][..], json!(false)),
            (&["auth", "peer_evidence_binding_present"][..], json!(false)),
            (
                &["identities", "0", "capability_target", "kind"][..],
                json!("node"),
            ),
        ] {
            let mut invalid = snapshot.clone();
            *invalid
                .pointer_mut(&format!("/{}", path.join("/")))
                .unwrap() = replacement;
            assert!(validate_snapshot(&invalid.to_string(), &expected).is_err());
        }
    }

    #[test]
    fn snapshot_rejects_a_serve_subject_derived_from_spoofed_login() {
        let login = "attacker@example.invalid";
        let expected = Expectation {
            issuer: "tailnet:test".into(),
            evidence_source: "serve_proxy".into(),
            assurance: IdentityAssurance::ConfiguredProxy,
            subject_kind: SubjectKind::User,
            subject_stability: SubjectStability::Login,
            capability: "query.farm/cap".into(),
            capability_target_kind: None,
            capability_target_value: None,
            tag: None,
            authenticated: false,
            proxy_present: true,
            spoofed_subject_fingerprint: Some(sha256_hex(format!("login:{login}").as_bytes())),
        };
        let snapshot = json!({
            "provider_status": {"tailscale": "available"},
            "identities": [{
                "provider": "tailscale",
                "issuer": "tailnet:test",
                "evidence_source": "serve_proxy",
                "assurance": "configured_proxy",
                "subject_kind": "user",
                "subject_stability": "login",
                "subject_verified": true,
                "subject_fingerprint": sha256_hex(format!("login:{login}").as_bytes()),
                "capability_names": ["query.farm/cap"],
                "capabilities_verified": true,
                "capability_target": null,
                "proxy_present": true
            }],
            "auth": {
                "authenticated": false,
                "domain": null,
                "principal_fingerprint": null,
                "principal_matches_identity": false,
                "peer_evidence_binding_present": true
            }
        });
        assert!(validate_snapshot(&snapshot.to_string(), &expected).is_err());
    }

    #[test]
    fn server_requires_the_exact_primary_auth_derived_from_peer_evidence() {
        let expected = tcp_expectation();
        let identity = PeerIdentity::new(
            PROVIDER,
            "localapi",
            IdentityAssurance::LocalDaemon,
            "tailnet:test",
            "tcp",
        )
        .unwrap()
        .with_subject(
            SubjectKind::TaggedNode,
            "node:stable-id",
            SubjectStability::Stable,
            true,
        )
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("tags".into(), json!(["tag:vgi-client"])),
            (
                "capability_target".into(),
                json!({"kind": "destination_ip", "value": "100.64.0.9"}),
            ),
        ]))
        .unwrap()
        .with_capabilities(BTreeMap::from([("query.farm/cap".into(), json!([]))]), true)
        .unwrap();
        let evidence =
            PeerEvidenceSet::from_results([PeerIdentityResult::available(identity)]).unwrap();
        let auth = peer_identity_primary(PROVIDER)(&evidence, &AuthContext::anonymous()).unwrap();
        validate_evidence_and_auth(&evidence, &auth, &expected).unwrap();

        let mut wrong = auth;
        wrong.domain = "bearer".into();
        assert!(validate_evidence_and_auth(&evidence, &wrong, &expected).is_err());
    }
}
