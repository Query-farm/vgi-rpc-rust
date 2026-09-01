use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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

    /// Disable Iroh relays and use direct paths only.
    #[arg(long, conflicts_with = "relay_url")]
    no_relay: bool,

    /// Replace the default Iroh relay set. May be repeated.
    #[arg(long = "relay-url", value_name = "URL")]
    relay_url: Vec<String>,
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

    let mut router = Router::builder(endpoint);
    if let Some(value) = args.raw_upstream.as_deref() {
        let upstream = parse_raw_upstream(value)?;
        let protocol = RawBridgeProtocol::new(upstream, RawBridgeOptions::default())
            .context("configure raw VGI bridge")?;
        router = router.accept(VGI_IROH_ALPN, protocol);
    }
    if let Some(value) = args.http_upstream.as_deref() {
        let protocol = HttpBridgeProtocol::new(value, HttpBridgeOptions::default())
            .context("configure HTTP VGI bridge")?;
        router = router.accept(IROH_HTTP_ALPN, protocol);
    }
    let router = router.spawn();

    println!("{endpoint_id}");
    tracing::info!(%endpoint_id, "VGI Iroh bridge ready");
    shutdown_signal().await?;
    router.shutdown().await.context("shut down Iroh router")?;
    Ok(())
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
        return Ok(());
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
}
