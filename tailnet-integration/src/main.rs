// © Copyright 2025-2026, Query.Farm LLC - https://query.farm
// SPDX-License-Identifier: Apache-2.0

//! Live network-transport qualification adapter for the Rust implementation.
//!
//! This binary exists only for cross-language conformance. It is not a
//! production proxy, ingress, or alternate worker API.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vgi_rpc::{
    peer_identity_primary, require_peer_identity, AuthContext, IdentityAssurance, PeerEvidenceSet,
    PeerIdentityStatus, SubjectKind, SubjectStability,
};

const PROVIDER: &str = "tailscale";
const PROXY_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const MAX_IROH_ADDRESS_BYTES: u64 = 64 * 1024;
const MAX_PROXY_RELAY_CONNECTIONS: usize = 32;

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

struct IrohProbe {
    issuer: String,
}

#[vgi_rpc::service]
impl IrohProbe {
    #[unary]
    fn confirm_endpoint(
        &self,
        ctx: &vgi_rpc::CallContext,
        endpoint_id: String,
        expected_issuer: String,
    ) -> vgi_rpc::Result<String> {
        if expected_issuer != self.issuer {
            return Err(vgi_rpc::RpcError::permission_error(
                "Iroh qualification issuer did not match",
            ));
        }
        validate_iroh_context(ctx, &self.issuer, &endpoint_id)?;
        Ok(endpoint_id)
    }
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
        Some("iroh-client") => run_iroh_client(&args[2..]),
        Some("iroh-server") => run_iroh_server(&args[2..]),
        Some("proxy-v2-relay") => run_proxy_v2_relay(&args[2..]),
        _ => Err("usage: vgi-rpc-tailnet-rust client-tcp|client-http|server-tcp|server-http|iroh-client|iroh-server|proxy-v2-relay [options]".into()),
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
    let service_name = optional(args, "--service-name").map(str::to_owned);
    let socket =
        optional(args, "--localapi-socket").unwrap_or("/var/run/tailscale/tailscaled.sock");
    let expected = Expectation {
        issuer: issuer.into(),
        evidence_source: "localapi".into(),
        assurance: IdentityAssurance::LocalDaemon,
        subject_kind: SubjectKind::TaggedNode,
        subject_stability: SubjectStability::Stable,
        capability: required(args, "--expected-capability")?.into(),
        capability_target_kind: Some(if service_name.is_some() {
            "service".into()
        } else {
            "destination_ip".into()
        }),
        capability_target_value: service_name.clone(),
        tag: Some(required(args, "--expected-tag")?.into()),
        authenticated: true,
        proxy_present: has_flag(args, "--proxy-protocol-v2"),
        spoofed_subject_fingerprint: None,
    };
    let provider = vgi_rpc::tailscale_localapi_provider(
        vgi_rpc::TailscaleLocalApiConfig::new(issuer)?.with_unix_socket(socket)?,
    )?;
    let proxy_protocol_v2_required = has_flag(args, "--proxy-protocol-v2");
    let trusted_proxy_addresses = optional(args, "--trusted-proxy-address")
        .map(|value| value.parse::<IpAddr>())
        .transpose()?
        .into_iter()
        .collect();
    let identity = vgi_rpc::tcp::TcpIdentityOptions {
        proxy_protocol_v2_required,
        trusted_proxy_addresses,
        service_name,
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

fn run_iroh_server(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = required(args, "--issuer")?.to_owned();
    let address_file = required(args, "--address-file")?.to_owned();
    let relay_disabled = has_flag(args, "--disable-relay");
    let shutdown = install_shutdown();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut builder =
            Endpoint::builder(presets::N0).alpns(vec![vgi_rpc_iroh::VGI_IROH_ALPN.to_vec()]);
        if relay_disabled {
            builder = builder.relay_mode(RelayMode::Disabled);
        }
        let endpoint = builder.bind().await?;
        if !relay_disabled {
            tokio::time::timeout(Duration::from_secs(30), endpoint.online())
                .await
                .map_err(|_| "Iroh endpoint did not become relay-reachable within 30 seconds")?;
        }
        write_endpoint_address(Path::new(&address_file), &endpoint.addr())?;
        println!("IROH:{}", endpoint.id());

        let cancellation = vgi_rpc_iroh::CancellationToken::new();
        let cancellation_signal = cancellation.clone();
        tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            cancellation_signal.cancel();
        });

        let mut rpc = vgi_rpc::RpcServer::builder()
            .protocol_name("IrohQualification")
            .protocol_version("1.0.0")
            .build();
        IrohProbe::register_with(
            &mut rpc,
            Arc::new(IrohProbe {
                issuer: issuer.clone(),
            }),
        );
        let options = vgi_rpc_iroh::IrohServerOptions::default()
            .with_issuer(issuer)
            .with_policy(peer_identity_primary("iroh"))
            .with_max_active_connections_per_endpoint(8);
        vgi_rpc_iroh::IrohServer::with_options(Arc::new(rpc), options)
            .serve(endpoint, cancellation)
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

fn run_iroh_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let address = read_endpoint_address(Path::new(required(args, "--address-file")?))?;
    let issuer = required(args, "--expected-issuer")?.to_owned();
    let relay_disabled = has_flag(args, "--disable-relay");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut builder = Endpoint::builder(presets::N0);
        if relay_disabled {
            builder = builder.relay_mode(RelayMode::Disabled);
        }
        let endpoint = builder.bind().await?;
        let local_id = endpoint.id().to_string();
        let expected_remote = address.id;
        let transport = vgi_rpc_iroh::IrohTransport::connect_addr(
            endpoint.clone(),
            address,
            vgi_rpc_iroh::IrohClientOptions::default().with_rpc_timeout(Duration::from_secs(20)),
        )
        .await?;
        if transport.remote_id() != expected_remote {
            return Err("Iroh authenticated a different server endpoint".into());
        }
        let rpc_issuer = issuer.clone();
        let rpc_result = tokio::task::spawn_blocking(move || {
            let mut client = transport.into_client();
            for _ in 0..2 {
                let params = iroh_params(&local_id, &rpc_issuer)?;
                let (result, _) = client.call_unary("confirm_endpoint", &params, None)?;
                let echoed = result
                    .column(0)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .ok_or("Iroh qualification result was not a string")?
                    .value(0);
                if echoed != local_id {
                    return Err("Iroh worker did not confirm the client endpoint identity".into());
                }
            }
            client.close()?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await
        .map_err(|_| "Iroh qualification client task failed")?;
        rpc_result.map_err(|error| std::io::Error::other(error.to_string()))?;
        endpoint.close().await;
        println!("Rust Iroh bidirectional identity probe passed for issuer {issuer}");
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

fn validate_iroh_context(
    ctx: &vgi_rpc::CallContext,
    issuer: &str,
    expected_endpoint_id: &str,
) -> vgi_rpc::Result<()> {
    if ctx.peer_evidence.status("iroh") != PeerIdentityStatus::Available {
        return Err(vgi_rpc::RpcError::permission_error(
            "Iroh endpoint evidence was not available",
        ));
    }
    let identities = ctx.peer_evidence.for_provider("iroh").collect::<Vec<_>>();
    let [identity] = identities.as_slice() else {
        return Err(vgi_rpc::RpcError::permission_error(
            "expected exactly one Iroh endpoint identity",
        ));
    };
    let canonical = identity.canonical_principal()?;
    if identity.issuer() != issuer
        || identity.evidence_source() != "iroh_quic_handshake"
        || identity.assurance() != IdentityAssurance::CryptographicPeer
        || identity.transport() != "iroh"
        || identity.subject_kind() != SubjectKind::Endpoint
        || identity.subject_stability() != SubjectStability::Stable
        || !identity.subject_verified()
        || identity.subject_key() != Some(expected_endpoint_id)
        || !ctx.auth.authenticated
        || ctx.auth.domain != "iroh"
        || ctx.auth.principal != canonical
        || ctx.auth.claims.get("issuer").map(String::as_str) != Some(issuer)
        || ctx.auth.claims.get("subject").map(String::as_str) != Some(expected_endpoint_id)
        || ctx.auth.claims.get("subject_kind").map(String::as_str) != Some("endpoint")
        || ctx.auth.claims.get("assurance").map(String::as_str) != Some("cryptographic_peer")
        || ctx.auth.claims.get("evidence_source").map(String::as_str) != Some("iroh_quic_handshake")
        || !valid_binding(ctx.auth.claims.get("peer_evidence_binding"))
    {
        return Err(vgi_rpc::RpcError::permission_error(
            "unexpected Iroh identity or authentication context",
        ));
    }
    Ok(())
}

fn iroh_params(
    endpoint_id: &str,
    expected_issuer: &str,
) -> Result<RecordBatch, Box<dyn std::error::Error + Send + Sync>> {
    Ok(RecordBatch::try_new(
        Arc::new(Schema::new(vec![
            Field::new("endpoint_id", DataType::Utf8, false),
            Field::new("expected_issuer", DataType::Utf8, false),
        ])),
        vec![
            Arc::new(StringArray::from(vec![endpoint_id])),
            Arc::new(StringArray::from(vec![expected_issuer])),
        ],
    )?)
}

fn write_endpoint_address(
    path: &Path,
    address: &EndpointAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = path.with_extension("tmp");
    let payload = serde_json::to_vec(address)?;
    if payload.len() as u64 > MAX_IROH_ADDRESS_BYTES {
        return Err("Iroh endpoint address exceeded the qualification limit".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&payload)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn read_endpoint_address(path: &Path) -> Result<EndpointAddr, Box<dyn std::error::Error>> {
    let mut payload = Vec::new();
    File::open(path)?
        .take(MAX_IROH_ADDRESS_BYTES + 1)
        .read_to_end(&mut payload)?;
    if payload.len() as u64 > MAX_IROH_ADDRESS_BYTES {
        return Err("Iroh endpoint address exceeded the qualification limit".into());
    }
    Ok(serde_json::from_slice(&payload)?)
}

fn run_proxy_v2_relay(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let listen = required(args, "--listen-address")?.parse::<SocketAddr>()?;
    let backend = required(args, "--backend-address")?.parse::<SocketAddr>()?;
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    let shutdown = install_shutdown();
    let active = Arc::new(AtomicUsize::new(0));
    println!("PROXY_V2_RELAY:{}", listener.local_addr()?);
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, source)) => {
                let destination = client.local_addr()?;
                if active
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < MAX_PROXY_RELAY_CONNECTIONS).then_some(count + 1)
                    })
                    .is_err()
                {
                    continue;
                }
                let connection_active = Arc::clone(&active);
                let spawn_result = thread::Builder::new()
                    .name("vgi-proxy-v2-qualification".into())
                    .spawn(move || {
                        if let Err(error) = relay_proxy_v2(client, source, destination, backend) {
                            eprintln!("PROXY v2 qualification relay connection failed: {error}");
                        }
                        connection_active.fetch_sub(1, Ordering::Release);
                    });
                if let Err(error) = spawn_result {
                    active.fetch_sub(1, Ordering::Release);
                    return Err(error.into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn relay_proxy_v2(
    mut client: TcpStream,
    source: SocketAddr,
    destination: SocketAddr,
    backend: SocketAddr,
) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect_timeout(&backend, Duration::from_secs(5))?;
    for stream in [&client, &upstream] {
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    }
    upstream.write_all(&proxy_v2_header(source, destination)?)?;
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let forward = thread::Builder::new()
        .name("vgi-proxy-v2-forward".into())
        .spawn(move || {
            let result = std::io::copy(&mut client_reader, &mut upstream_writer);
            let _ = upstream_writer.shutdown(Shutdown::Write);
            result
        })?;
    let reverse = std::io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let forward = forward
        .join()
        .map_err(|_| std::io::Error::other("PROXY v2 relay task failed"))?;
    reverse?;
    forward?;
    Ok(())
}

fn proxy_v2_header(source: SocketAddr, destination: SocketAddr) -> std::io::Result<Vec<u8>> {
    let mut output = PROXY_V2_SIGNATURE.to_vec();
    output.push(0x21);
    let mut addresses = Vec::new();
    match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            output.push(0x11);
            addresses.extend_from_slice(&source.ip().octets());
            addresses.extend_from_slice(&destination.ip().octets());
            addresses.extend_from_slice(&source.port().to_be_bytes());
            addresses.extend_from_slice(&destination.port().to_be_bytes());
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            output.push(0x21);
            addresses.extend_from_slice(&source.ip().octets());
            addresses.extend_from_slice(&destination.ip().octets());
            addresses.extend_from_slice(&source.port().to_be_bytes());
            addresses.extend_from_slice(&destination.port().to_be_bytes());
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "PROXY v2 relay source and destination address families differ",
            ));
        }
    }
    output.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
    output.extend_from_slice(&addresses);
    Ok(output)
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

    #[test]
    fn qualification_relay_emits_exact_proxy_v2_ipv4_and_ipv6_addresses() {
        for (source, destination) in [
            ("100.64.0.8:32123", "100.64.0.9:19401"),
            ("[fd7a:115c:a1e0::8]:32123", "[fd7a:115c:a1e0::9]:19401"),
        ] {
            let source = source.parse::<SocketAddr>().unwrap();
            let destination = destination.parse::<SocketAddr>().unwrap();
            let header = proxy_v2_header(source, destination).unwrap();
            let parsed = vgi_rpc::proxy_protocol::parse_proxy_protocol_v2(&header, 536).unwrap();
            assert_eq!(parsed.source, source);
            assert_eq!(parsed.destination, destination);
        }
    }

    #[test]
    fn qualification_relay_rejects_mixed_address_families() {
        let source = "100.64.0.8:32123".parse::<SocketAddr>().unwrap();
        let destination = "[fd7a:115c:a1e0::9]:19401".parse::<SocketAddr>().unwrap();
        assert_eq!(
            proxy_v2_header(source, destination).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}
