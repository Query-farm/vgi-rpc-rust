use std::ffi::OsString;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use http::uri::Authority;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, RelayMode, RelayUrl, SecretKey};
use tracing_subscriber::EnvFilter;
use vgi_iroh_bridge::{
    HttpBridgeOptions, HttpBridgeProtocol, RawBridgeOptions, RawBridgeProtocol, RawUpstream,
    IROH_HTTP_ALPN, VGI_IROH_ALPN,
};

const SECRET_KEY_ENV: &str = "VGI_IROH_SECRET_KEY";
const MAX_SECRET_FILE_BYTES: u64 = 4096;

/// Identity-preserving Iroh ingress for ordinary VGI workers.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// File containing the persistent Iroh secret key.
    #[arg(long, value_name = "PATH", conflicts_with = "ephemeral")]
    secret_key_file: Option<PathBuf>,

    /// Generate a process-lifetime identity. Intended only for development.
    #[arg(long, conflicts_with = "secret_key_file")]
    ephemeral: bool,

    /// Raw VGI destination: tcp://host:port or unix:///absolute/path.
    #[arg(long, value_name = "URI")]
    raw_upstream: Option<String>,

    /// Fixed HTTP(S) worker, proxy, or load-balancer origin and base path.
    #[arg(long, value_name = "URL")]
    http_upstream: Option<String>,

    /// Raw upstream connect deadline in seconds.
    #[arg(long, value_name = "SECONDS", requires = "raw_upstream")]
    raw_connect_timeout: Option<NonZeroU64>,

    /// Deadline for the first raw mux stream on a connection, in seconds.
    #[arg(long, value_name = "SECONDS", requires = "raw_upstream")]
    raw_first_stream_timeout: Option<NonZeroU64>,

    /// Deadline while waiting for another raw mux stream, in seconds.
    #[arg(long, value_name = "SECONDS", requires = "raw_upstream")]
    raw_connection_idle_timeout: Option<NonZeroU64>,

    /// Maximum simultaneous raw Iroh connections.
    #[arg(long, value_name = "COUNT", requires = "raw_upstream")]
    raw_max_connections: Option<NonZeroUsize>,

    /// Maximum simultaneous raw connections from one EndpointId.
    #[arg(long, value_name = "COUNT", requires = "raw_upstream")]
    raw_max_connections_per_peer: Option<NonZeroUsize>,

    /// Maximum simultaneous raw mux streams across all connections.
    #[arg(long, value_name = "COUNT", requires = "raw_upstream")]
    raw_max_streams: Option<NonZeroUsize>,

    /// Maximum simultaneous raw mux streams on one Iroh connection.
    #[arg(long, value_name = "COUNT", requires = "raw_upstream")]
    raw_max_streams_per_connection: Option<NonZeroUsize>,

    /// Raw graceful-drain deadline in seconds.
    #[arg(long, value_name = "SECONDS", requires = "raw_upstream")]
    raw_drain_timeout: Option<NonZeroU64>,

    /// Maximum simultaneous HTTP connections from one EndpointId.
    #[arg(long, value_name = "COUNT", requires = "http_upstream")]
    http_max_connections_per_peer: Option<NonZeroUsize>,

    /// Maximum simultaneous HTTP connections across the bridge.
    #[arg(long, value_name = "COUNT", requires = "http_upstream")]
    http_max_total_connections: Option<NonZeroUsize>,

    /// HTTP connection idle deadline in seconds.
    #[arg(long, value_name = "SECONDS", requires = "http_upstream")]
    http_connection_idle_timeout: Option<NonZeroU64>,

    /// Maximum simultaneous HTTP requests across all connections.
    #[arg(long, value_name = "COUNT", requires = "http_upstream")]
    http_max_concurrency: Option<NonZeroUsize>,

    /// HTTP request and request-head deadline in seconds.
    #[arg(long, value_name = "SECONDS", requires = "http_upstream")]
    http_request_timeout: Option<NonZeroU64>,

    /// Maximum encoded HTTP request body bytes.
    #[arg(long, value_name = "BYTES", requires = "http_upstream")]
    http_max_request_body_bytes: Option<NonZeroUsize>,

    /// Maximum HTTP request-head bytes.
    #[arg(long, value_name = "BYTES", requires = "http_upstream")]
    http_max_header_bytes: Option<NonZeroUsize>,

    /// HTTP graceful-drain deadline in seconds.
    #[arg(long, value_name = "SECONDS", requires = "http_upstream")]
    http_drain_timeout: Option<NonZeroU64>,

    /// Disable Iroh relays and use direct paths only.
    #[arg(long, conflicts_with = "relay_url")]
    no_relay: bool,

    /// Replace the default Iroh relay set. May be repeated.
    #[arg(long = "relay-url", value_name = "URL")]
    relay_url: Vec<String>,

    /// Print directly dialable socket addresses after the EndpointId.
    /// Intended for deterministic same-host integration tests and discovery.
    #[arg(long)]
    print_direct_addresses: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if args.raw_upstream.is_none() && args.http_upstream.is_none() {
        bail!("configure at least one of --raw-upstream or --http-upstream");
    }

    let secret_key = load_secret_key(&args)?;
    let mut endpoint = Endpoint::builder(presets::N0).secret_key(secret_key);
    if args.no_relay {
        endpoint = endpoint.relay_mode(RelayMode::Disabled);
    } else if !args.relay_url.is_empty() {
        let relays = args
            .relay_url
            .iter()
            .map(|value| {
                RelayUrl::from_str(value).with_context(|| format!("invalid relay URL {value:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        endpoint = endpoint.relay_mode(RelayMode::custom(relays));
    }
    let endpoint = endpoint.bind().await.context("bind Iroh endpoint")?;
    let endpoint_id = endpoint.id();
    let direct_addresses = endpoint.addr().ip_addrs().copied().collect::<Vec<_>>();

    let mut router = Router::builder(endpoint);
    if let Some(value) = args.raw_upstream.as_deref() {
        let upstream = parse_raw_upstream(value)?;
        let protocol = RawBridgeProtocol::new(upstream, raw_bridge_options(&args))
            .context("configure raw VGI bridge")?;
        router = router.accept(VGI_IROH_ALPN, protocol);
    }
    if let Some(value) = args.http_upstream.as_deref() {
        let protocol = HttpBridgeProtocol::new(value, http_bridge_options(&args))
            .context("configure HTTP VGI bridge")?;
        router = router.accept(IROH_HTTP_ALPN, protocol);
    }
    let router = router.spawn();

    println!("{endpoint_id}");
    if args.print_direct_addresses {
        for address in direct_addresses {
            println!("DIRECT:{address}");
        }
    }
    tracing::info!(%endpoint_id, "VGI Iroh bridge ready");
    shutdown_signal().await?;
    router.shutdown().await.context("shut down Iroh router")?;
    Ok(())
}

fn raw_bridge_options(args: &Args) -> RawBridgeOptions {
    let mut options = RawBridgeOptions::default();
    if let Some(value) = args.raw_connect_timeout {
        options.connect_timeout = Duration::from_secs(value.get());
    }
    if let Some(value) = args.raw_first_stream_timeout {
        options.first_stream_timeout = Duration::from_secs(value.get());
    }
    if let Some(value) = args.raw_connection_idle_timeout {
        options.connection_idle_timeout = Duration::from_secs(value.get());
    }
    if let Some(value) = args.raw_max_connections {
        options.max_connections = value.get();
    }
    if let Some(value) = args.raw_max_connections_per_peer {
        options.max_connections_per_peer = value.get();
    }
    if let Some(value) = args.raw_max_streams {
        options.max_streams = value.get();
    }
    if let Some(value) = args.raw_max_streams_per_connection {
        options.max_streams_per_connection = value.get();
    }
    if let Some(value) = args.raw_drain_timeout {
        options.drain_timeout = Duration::from_secs(value.get());
    }
    options
}

fn http_bridge_options(args: &Args) -> HttpBridgeOptions {
    let mut options = HttpBridgeOptions::default();
    if let Some(value) = args.http_max_connections_per_peer {
        options.connection.max_connections_per_peer = value.get();
    }
    if let Some(value) = args.http_max_total_connections {
        options.connection.max_total_connections = value.get();
    }
    if let Some(value) = args.http_connection_idle_timeout {
        options.connection.connection_idle_timeout = Duration::from_secs(value.get());
    }
    if let Some(value) = args.http_max_concurrency {
        options.connection.max_concurrency = value.get();
    }
    if let Some(value) = args.http_request_timeout {
        options.connection.request_timeout = Some(Duration::from_secs(value.get()));
    }
    if let Some(value) = args.http_max_request_body_bytes {
        options.connection.max_request_body_wire_bytes = Some(value.get());
        options.connection.max_request_body_decoded_bytes = Some(value.get());
    }
    if let Some(value) = args.http_max_header_bytes {
        options.connection.max_header_size = value.get();
    }
    if let Some(value) = args.http_drain_timeout {
        options.connection.drain_timeout = Duration::from_secs(value.get());
    }
    options
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("wait for SIGINT")?;
            }
            _ = terminate.recv() => {}
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("wait for shutdown signal")?;
        Ok(())
    }
}

fn load_secret_key(args: &Args) -> Result<SecretKey> {
    let environment = std::env::var_os(SECRET_KEY_ENV);
    if args.ephemeral {
        if environment.is_some() {
            bail!("--ephemeral conflicts with {SECRET_KEY_ENV}");
        }
        return Ok(SecretKey::generate());
    }
    let encoded = match (&args.secret_key_file, environment) {
        (Some(_), Some(_)) => bail!("--secret-key-file conflicts with {SECRET_KEY_ENV}"),
        (Some(path), None) => read_secret_file(path)?,
        (None, Some(value)) => os_secret(value)?,
        (None, None) => bail!(
            "a stable identity is required: set --secret-key-file or {SECRET_KEY_ENV}; use --ephemeral only for development"
        ),
    };
    SecretKey::from_str(encoded.trim()).context("invalid Iroh secret key")
}

fn read_secret_file(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("inspect secret-key file {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_SECRET_FILE_BYTES {
        bail!(
            "secret-key file must be a regular file no larger than {MAX_SECRET_FILE_BYTES} bytes"
        );
    }
    std::fs::read_to_string(path)
        .with_context(|| format!("read secret-key file {}", path.display()))
}

fn os_secret(value: OsString) -> Result<String> {
    value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{SECRET_KEY_ENV} must be UTF-8"))
}

fn parse_raw_upstream(value: &str) -> Result<RawUpstream> {
    if let Some(authority) = value.strip_prefix("tcp://") {
        let parsed =
            Authority::from_str(authority).context("raw TCP upstream must be host:port")?;
        if parsed.as_str().contains('@') || parsed.port_u16().is_none() {
            bail!("raw TCP upstream must be host:port without userinfo");
        }
        if let Ok(address) = parsed.as_str().parse() {
            return Ok(RawUpstream::Tcp(address));
        }
        return Ok(RawUpstream::TcpAuthority(parsed.to_string()));
    }
    #[cfg(unix)]
    if let Some(path) = value.strip_prefix("unix://") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!("raw Unix upstream path must be absolute");
        }
        return Ok(RawUpstream::Unix(path));
    }
    bail!("raw upstream must use tcp://host:port or unix:///absolute/path")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_upstream_parser_accepts_ip_dns_and_absolute_unix() {
        assert!(matches!(
            parse_raw_upstream("tcp://127.0.0.1:9400").unwrap(),
            RawUpstream::Tcp(_)
        ));
        assert_eq!(
            parse_raw_upstream("tcp://workers.internal:9400").unwrap(),
            RawUpstream::TcpAuthority("workers.internal:9400".into())
        );
        #[cfg(unix)]
        assert!(matches!(
            parse_raw_upstream("unix:///tmp/vgi.sock").unwrap(),
            RawUpstream::Unix(_)
        ));
        for invalid in [
            "tcp://worker",
            "tcp://user@worker:9400",
            "unix://relative",
            "http://worker:9400",
        ] {
            assert!(parse_raw_upstream(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn cli_overrides_are_scoped_positive_and_preserve_transparency() {
        let args = Args::try_parse_from([
            "vgi-iroh-bridge",
            "--ephemeral",
            "--raw-upstream",
            "tcp://worker:9400",
            "--raw-max-connections",
            "7",
            "--raw-connect-timeout",
            "3",
            "--raw-connection-idle-timeout",
            "13",
            "--raw-max-connections-per-peer",
            "4",
            "--http-upstream",
            "https://worker.example/vgi",
            "--http-max-connections-per-peer",
            "5",
            "--http-max-total-connections",
            "17",
            "--http-connection-idle-timeout",
            "11",
            "--http-max-request-body-bytes",
            "4096",
            "--print-direct-addresses",
        ])
        .unwrap();

        let raw = raw_bridge_options(&args);
        assert_eq!(raw.max_connections, 7);
        assert_eq!(raw.max_connections_per_peer, 4);
        assert_eq!(raw.connect_timeout, Duration::from_secs(3));
        assert_eq!(raw.connection_idle_timeout, Duration::from_secs(13));

        let http = http_bridge_options(&args).connection;
        assert_eq!(http.max_connections_per_peer, 5);
        assert_eq!(http.max_total_connections, 17);
        assert_eq!(http.connection_idle_timeout, Duration::from_secs(11));
        assert_eq!(http.max_request_body_wire_bytes, Some(4096));
        assert_eq!(http.max_request_body_decoded_bytes, Some(4096));
        assert!(!http.decompression);
        assert!(args.print_direct_addresses);

        assert!(Args::try_parse_from([
            "vgi-iroh-bridge",
            "--ephemeral",
            "--raw-upstream",
            "tcp://worker:9400",
            "--raw-max-connections",
            "0",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "vgi-iroh-bridge",
            "--ephemeral",
            "--http-max-total-connections",
            "2",
        ])
        .is_err());
    }
}
