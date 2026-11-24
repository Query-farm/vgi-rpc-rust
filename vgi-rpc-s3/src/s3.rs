//! Direct S3 storage (feature `aws`): the worker signs its own URLs against
//! the operator's bucket — AWS S3 or any S3-compatible service (MinIO, Ceph,
//! Cloudflare R2's S3 API, Wasabi, Backblaze B2, LocalStack). No blob vendor.
//!
//! Implements direct-storage contract v1: [`S3Storage`] covers result
//! externalization (PUT + presigned GET), upload grants (presigned PUT signed
//! for the exact size and SHA-256), and the object store (`put_object` /
//! `get` for `StateRef` and argument references). Configure it from the
//! environment with [`S3Settings::from_env`]:
//!
//! | Variable | Meaning | Default |
//! |---|---|---|
//! | `VGI_STORAGE_S3_BUCKET` | bucket (required) | — |
//! | `VGI_STORAGE_S3_PREFIX` | key prefix, e.g. `vgi/` | empty |
//! | `VGI_STORAGE_S3_ENDPOINT` | custom endpoint (`https://` or `http://`) | AWS regional endpoint |
//! | `VGI_STORAGE_S3_REGION` | signing region (`auto` for R2) | `AWS_REGION`, `AWS_DEFAULT_REGION`, `us-east-1` |
//! | `VGI_STORAGE_S3_FORCE_PATH_STYLE` | bucket in the path | `true` with an endpoint, else `false` |
//! | `VGI_STORAGE_S3_PUBLIC_ENDPOINT` | endpoint for URLs handed to clients | the endpoint |
//! | `VGI_STORAGE_S3_CHECKSUM` | `sha256` or `none` | `sha256` |
//! | `VGI_STORAGE_URL_TTL_SECONDS` | presigned URL lifetime | 3600 |
//! | `VGI_STORAGE_S3_VERIFY` | `1`: HEAD the bucket at startup | off (checked on first use) |
//! | `VGI_STORAGE_S3_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` / `_SESSION_TOKEN` | explicit credentials | the AWS chain |
//!
//! # Credentials
//!
//! Explicit `VGI_STORAGE_S3_*` keys first, else the standard AWS chain via
//! `aws-config`: `AWS_*` environment, shared config / profile (with
//! `role_arn` + `source_profile`, `credential_process`, SSO), web identity
//! (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`), ECS / EKS Pod Identity
//! container credentials, then EC2 IMDSv2. Temporary credentials are refreshed
//! at least 5 minutes before they expire, and never cached past that.
//!
//! # URL lifetime
//!
//! A presigned URL dies with the credentials that signed it, so each URL's
//! lifetime is `min(VGI_STORAGE_URL_TTL_SECONDS, expiry − now − 60 s)`; the
//! worker refreshes first when that is below what the call needs (15 minutes
//! for an upload grant, 5 for a result URL, 2 for its own requests). Stored
//! objects are addressed by key, so `StateRef`s and argument references
//! survive rotation.
//!
//! # Keys and lifecycle
//!
//! Results, client uploads (upload grants), `StateRef` and argument objects
//! go under `<prefix>rpc/`, function-storage blobs under
//! `<prefix>fs/<scope>/`. Add lifecycle rules expiring `rpc/` after 1 day and
//! `fs/` after 2 days, as the vendor does. Only function storage deletes (best
//! effort, [`S3Storage::delete_key`] / [`S3Storage::delete_prefix`]).
//!
//! # Endpoints
//!
//! `http://` endpoints (and public endpoints) are refused unless
//! `VGI_STORAGE_ALLOW_PLAIN_HTTP=1` (the extension needs its own
//! `vgi_storage_allow_plain_http`). With `VGI_STORAGE_S3_PUBLIC_ENDPOINT`, the
//! worker must be able to reach the public endpoint too: request-upload
//! pointers are fetched by URL. Argument references and `StateRef`s go by
//! object id and use the endpoint.
//!
//! An explicit `VGI_STORAGE_S3_SESSION_TOKEN` has no known expiry: set
//! `VGI_STORAGE_S3_SESSION_EXPIRES` (RFC 3339 or epoch seconds) so URL
//! lifetimes are capped, or use `credential_process` / the standard chain.
//!
//! # Checksums
//!
//! With `VGI_STORAGE_S3_CHECKSUM=sha256` every PUT is signed with
//! `x-amz-checksum-sha256`, so storage refuses a body with another digest
//! (upload v2). `none` is for services that do not enforce it: the worker
//! sends no checksum header and issues no upload grants (see
//! [`S3Storage::issues_upload_grants`]); results and objects are still
//! stored, and verified by their readers.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_credential_types::Credentials;
use sha2::Digest as _;
use vgi_rpc::external::{
    object_missing_error, Compression, ExternalStorage, ObjectStore, UploadResult, UploadUrl,
    UploadUrlProvider, UrlValidator,
};
use vgi_rpc::{Result, RpcError};

use crate::transfer::{RetryPolicy, StorageClient, TransferTimeouts};
use crate::{redact_url, signed_get, signed_put};

/// Bucket name.
pub const ENV_BUCKET: &str = "VGI_STORAGE_S3_BUCKET";
/// Key prefix.
pub const ENV_PREFIX: &str = "VGI_STORAGE_S3_PREFIX";
/// Custom endpoint URL.
pub const ENV_ENDPOINT: &str = "VGI_STORAGE_S3_ENDPOINT";
/// Signing region.
pub const ENV_REGION: &str = "VGI_STORAGE_S3_REGION";
/// Path-style addressing.
pub const ENV_FORCE_PATH_STYLE: &str = "VGI_STORAGE_S3_FORCE_PATH_STYLE";
/// Endpoint for URLs handed to clients.
pub const ENV_PUBLIC_ENDPOINT: &str = "VGI_STORAGE_S3_PUBLIC_ENDPOINT";
/// `sha256` or `none`.
pub const ENV_CHECKSUM: &str = "VGI_STORAGE_S3_CHECKSUM";
/// Presigned URL lifetime in seconds.
pub const ENV_URL_TTL: &str = "VGI_STORAGE_URL_TTL_SECONDS";
/// `1` checks the bucket at startup.
pub const ENV_VERIFY: &str = "VGI_STORAGE_S3_VERIFY";
/// Explicit access key id.
pub const ENV_ACCESS_KEY_ID: &str = "VGI_STORAGE_S3_ACCESS_KEY_ID";
/// Explicit secret access key.
pub const ENV_SECRET_ACCESS_KEY: &str = "VGI_STORAGE_S3_SECRET_ACCESS_KEY";
/// Explicit session token.
pub const ENV_SESSION_TOKEN: &str = "VGI_STORAGE_S3_SESSION_TOKEN";
/// Expiry of the explicit session credentials (RFC 3339 or epoch seconds).
pub const ENV_SESSION_EXPIRES: &str = "VGI_STORAGE_S3_SESSION_EXPIRES";
/// `1` allows `http://` endpoints.
pub const ENV_ALLOW_PLAIN_HTTP: &str = "VGI_STORAGE_ALLOW_PLAIN_HTTP";

/// Default presigned URL lifetime.
pub const DEFAULT_URL_TTL: Duration = Duration::from_secs(3600);
/// SigV4's longest presigned URL lifetime (7 days).
const MAX_URL_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// Refresh temporary credentials at least this long before they expire.
const REFRESH_AHEAD: Duration = Duration::from_secs(300);
/// A URL must outlive its credentials by this margin (contract §4).
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);
/// The lifetime an upload grant needs (contract §4).
const GRANT_MIN: Duration = Duration::from_secs(900);
/// The lifetime a result download URL needs.
const RESULT_MIN: Duration = Duration::from_secs(300);
/// The lifetime the worker's own request URLs need.
const OWN_MIN: Duration = Duration::from_secs(120);

/// Whether PUTs carry `x-amz-checksum-sha256`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checksum {
    /// Sign every PUT with the body's SHA-256 (the default; upload v2).
    Sha256,
    /// No checksum header: no upload grants.
    None,
}

/// Direct S3 settings (contract §2, §3).
#[derive(Clone)]
pub struct S3Settings {
    /// Bucket.
    pub bucket: String,
    /// Key prefix (may be empty).
    pub prefix: String,
    /// Endpoint the worker uses; `None` = AWS regional endpoint.
    pub endpoint: Option<url::Url>,
    /// Endpoint for URLs handed to clients; `None` = [`endpoint`](Self::endpoint).
    pub public_endpoint: Option<url::Url>,
    /// Signing region.
    pub region: String,
    /// Bucket in the path instead of the host name.
    pub force_path_style: bool,
    /// Checksum mode.
    pub checksum: Checksum,
    /// Presigned URL lifetime (before the credential cap).
    pub url_ttl: Duration,
    /// HEAD the bucket at startup.
    pub verify_at_startup: bool,
    /// Explicit credentials (`VGI_STORAGE_S3_*`), else the AWS chain.
    pub explicit_credentials: Option<Credentials>,
    /// Transfer timeouts.
    pub timeouts: TransferTimeouts,
}

impl std::fmt::Debug for S3Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Settings")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field(
                "endpoint",
                &self.endpoint.as_ref().map(|u| redact_url(u.as_str())),
            )
            .field(
                "public_endpoint",
                &self
                    .public_endpoint
                    .as_ref()
                    .map(|u| redact_url(u.as_str())),
            )
            .field("region", &self.region)
            .field("force_path_style", &self.force_path_style)
            .field("checksum", &self.checksum)
            .field("url_ttl", &self.url_ttl)
            .field(
                "explicit_credentials",
                &self.explicit_credentials.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn trimmed(lookup: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    lookup(name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn parse_bool(lookup: &dyn Fn(&str) -> Option<String>, name: &str) -> Result<Option<bool>> {
    match trimmed(lookup, name).map(|v| v.to_ascii_lowercase()) {
        None => Ok(None),
        Some(v) if matches!(v.as_str(), "1" | "true" | "yes" | "on") => Ok(Some(true)),
        Some(v) if matches!(v.as_str(), "0" | "false" | "no" | "off") => Ok(Some(false)),
        Some(v) => Err(RpcError::value_error(format!(
            "{name} must be true or false, got {v:?}"
        ))),
    }
}

fn parse_endpoint(lookup: &dyn Fn(&str) -> Option<String>, name: &str) -> Result<Option<url::Url>> {
    let Some(raw) = trimmed(lookup, name) else {
        return Ok(None);
    };
    let url = url::Url::parse(&raw)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .filter(|u| u.username().is_empty() && u.password().is_none())
        .filter(|u| u.query().is_none() && u.fragment().is_none())
        .ok_or_else(|| {
            RpcError::value_error(format!(
                "{name} must be an absolute http(s) URL without credentials or query: {}",
                redact_url(&raw)
            ))
        })?;
    Ok(Some(url))
}

impl S3Settings {
    /// Settings from the process environment.
    ///
    /// # Errors
    ///
    /// If `VGI_STORAGE_S3_BUCKET` is unset or a variable is malformed.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(&|name| std::env::var(name).ok())
    }

    /// Settings from an explicit variable lookup.
    ///
    /// # Errors
    ///
    /// As [`from_env`](Self::from_env).
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        let bucket = trimmed(lookup, ENV_BUCKET).ok_or_else(|| {
            RpcError::value_error(format!("{ENV_BUCKET} is required for the s3 backend"))
        })?;
        let endpoint = parse_endpoint(lookup, ENV_ENDPOINT)?;
        let public_endpoint = parse_endpoint(lookup, ENV_PUBLIC_ENDPOINT)?;
        let allow_http = parse_bool(lookup, ENV_ALLOW_PLAIN_HTTP)?.unwrap_or(false);
        for (name, url) in [
            (ENV_ENDPOINT, &endpoint),
            (ENV_PUBLIC_ENDPOINT, &public_endpoint),
        ] {
            if url.as_ref().is_some_and(|u| u.scheme() == "http") && !allow_http {
                return Err(RpcError::value_error(format!(
                    "{name} is plain http; set {ENV_ALLOW_PLAIN_HTTP}=1 to allow it (test and \
                     private networks only)"
                )));
            }
        }
        let region = trimmed(lookup, ENV_REGION)
            .or_else(|| trimmed(lookup, "AWS_REGION"))
            .or_else(|| trimmed(lookup, "AWS_DEFAULT_REGION"))
            .unwrap_or_else(|| "us-east-1".to_string());
        let force_path_style =
            parse_bool(lookup, ENV_FORCE_PATH_STYLE)?.unwrap_or(endpoint.is_some());
        let checksum = match trimmed(lookup, ENV_CHECKSUM)
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("sha256") => Checksum::Sha256,
            Some("none") => Checksum::None,
            Some(other) => {
                return Err(RpcError::value_error(format!(
                    "{ENV_CHECKSUM} must be sha256 or none, got {other:?}"
                )))
            }
        };
        let url_ttl = match trimmed(lookup, ENV_URL_TTL) {
            None => DEFAULT_URL_TTL,
            Some(raw) => match raw.parse::<u64>() {
                Ok(n) if n >= 60 => Duration::from_secs(n).min(MAX_URL_TTL),
                _ => {
                    return Err(RpcError::value_error(format!(
                        "{ENV_URL_TTL} must be an integer number of seconds >= 60, got {raw:?}"
                    )))
                }
            },
        };
        let verify_at_startup = parse_bool(lookup, ENV_VERIFY)?.unwrap_or(false);
        let key = trimmed(lookup, ENV_ACCESS_KEY_ID);
        let secret = trimmed(lookup, ENV_SECRET_ACCESS_KEY);
        let token = trimmed(lookup, ENV_SESSION_TOKEN);
        let expires = match trimmed(lookup, ENV_SESSION_EXPIRES) {
            None => None,
            Some(raw) => Some(parse_expiry(&raw).ok_or_else(|| {
                RpcError::value_error(format!(
                    "{ENV_SESSION_EXPIRES} must be an RFC 3339 timestamp or epoch seconds, got {raw:?}"
                ))
            })?),
        };
        let explicit_credentials = match (key, secret) {
            (Some(k), Some(s)) => {
                if token.is_some() && expires.is_none() {
                    tracing::warn!(
                        "{ENV_SESSION_TOKEN} is set without {ENV_SESSION_EXPIRES}: presigned URL \
                         lifetimes cannot be capped at the credentials' expiry; set it, or use \
                         credential_process or the standard AWS chain"
                    );
                }
                Some(Credentials::new(k, s, token, expires, "VGI_STORAGE_S3"))
            }
            (None, None) => {
                if trimmed(lookup, ENV_SESSION_TOKEN).is_some() {
                    return Err(RpcError::value_error(format!(
                        "{ENV_SESSION_TOKEN} is set without {ENV_ACCESS_KEY_ID} and \
                         {ENV_SECRET_ACCESS_KEY}"
                    )));
                }
                None
            }
            _ => {
                return Err(RpcError::value_error(format!(
                    "set both {ENV_ACCESS_KEY_ID} and {ENV_SECRET_ACCESS_KEY}, or neither"
                )))
            }
        };
        let s = S3Settings {
            bucket,
            prefix: trimmed(lookup, ENV_PREFIX).unwrap_or_default(),
            endpoint,
            public_endpoint,
            region,
            force_path_style,
            checksum,
            url_ttl,
            verify_at_startup,
            explicit_credentials,
            timeouts: TransferTimeouts::from_lookup(lookup),
        };
        if !s.force_path_style && !is_dns_bucket(&s.bucket) {
            return Err(RpcError::value_error(format!(
                "bucket {:?} cannot be addressed virtual-hosted style; set {ENV_FORCE_PATH_STYLE}=true",
                s.bucket
            )));
        }
        Ok(s)
    }
}

/// An RFC 3339 timestamp or integer epoch seconds.
fn parse_expiry(raw: &str) -> Option<SystemTime> {
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
    }
    let t = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
    let secs = u64::try_from(t.timestamp()).ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

fn is_dns_bucket(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
        && !b.starts_with(['-', '.'])
        && !b.ends_with(['-', '.'])
}

/// Percent-encode an S3 key for a URL path (everything but unreserved
/// characters and `/`).
fn encode_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for b in key.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Temporary or static credentials, refreshed ahead of expiry.
struct CredentialCache {
    /// A given provider, or `None` for the default chain, built on first use
    /// (on the calling thread: building it blocks on the storage runtime, so
    /// it must never happen inside a provider future).
    provider: Option<SharedCredentialsProvider>,
    chain: std::sync::OnceLock<std::result::Result<SharedCredentialsProvider, String>>,
    cached: Mutex<Option<Credentials>>,
}

impl CredentialCache {
    fn remaining(c: &Credentials) -> Option<Duration> {
        c.expiry().map(|e| {
            e.duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
        })
    }

    /// Credentials good for at least `need` (plus the 60 s margin), and never
    /// within 5 minutes of expiry.
    fn get(&self, need: Duration) -> Result<Credentials> {
        let threshold = (need + EXPIRY_MARGIN).max(REFRESH_AHEAD);
        let mut cached = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = cached.as_ref() {
            match Self::remaining(c) {
                None => return Ok(c.clone()),
                Some(left) if left > threshold => return Ok(c.clone()),
                _ => {}
            }
        }
        let provider = match &self.provider {
            Some(p) => p.clone(),
            None => self
                .chain
                .get_or_init(|| default_chain().map_err(|e| e.message))
                .clone()
                .map_err(RpcError::runtime_error)?,
        };
        let fresh =
            crate::transfer::try_block_on(async move { provider.provide_credentials().await })
                .map_err(|()| RpcError::runtime_error("s3: the AWS credential provider failed"))?;
        match fresh {
            Ok(c) => {
                if let Some(left) = Self::remaining(&c) {
                    tracing::debug!("vgi_rpc_s3: refreshed temporary credentials, {left:?} left");
                }
                *cached = Some(c.clone());
                Ok(c)
            }
            Err(e) => {
                // Keep using the old credentials while they still cover the
                // call; never put the provider's message (which may name a
                // profile or file) together with secrets.
                if let Some(c) = cached.as_ref() {
                    if Self::remaining(c).is_some_and(|left| left > need + EXPIRY_MARGIN) {
                        tracing::warn!("vgi_rpc_s3: credential refresh failed, using the previous credentials: {e}");
                        return Ok(c.clone());
                    }
                }
                Err(RpcError::runtime_error(format!(
                    "s3: no usable AWS credentials: {e}"
                )))
            }
        }
    }
}

/// Build the standard AWS credential chain (env, profile, web identity,
/// container, IMDS). Its own HTTPS client (STS, SSO, IMDS, ECS, and the IMDS
/// region lookup) is rustls on ring with native roots, like the rest of this
/// crate.
fn default_chain() -> Result<SharedCredentialsProvider> {
    crate::transfer::try_block_on(async {
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let config = aws_config::provider_config::ProviderConfig::default().with_http_client(http);
        // The region STS calls use: AWS_REGION / AWS_DEFAULT_REGION, the
        // profile, IMDS (all through the client above), else us-east-1.
        let region = aws_config::meta::region::RegionProviderChain::first_try(
            aws_config::environment::region::EnvironmentVariableRegionProvider::new(),
        )
        .or_else(
            aws_config::profile::ProfileFileRegionProvider::builder()
                .configure(&config)
                .build(),
        )
        .or_else(
            aws_config::imds::region::ImdsRegionProvider::builder()
                .configure(&config)
                .build(),
        )
        .or_else(aws_config::Region::new("us-east-1"))
        .region()
        .await
        .unwrap_or_else(|| aws_config::Region::new("us-east-1"));
        let chain = aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
            .configure(config)
            .region(region)
            .build()
            .await;
        SharedCredentialsProvider::new(chain)
    })
    .map_err(|()| RpcError::runtime_error("s3: building the AWS credential chain failed"))
}

#[derive(Clone, Copy)]
enum Audience {
    /// URLs the worker itself requests.
    Worker,
    /// URLs handed to clients and the extension.
    Public,
}

/// Direct S3 [`ExternalStorage`], [`UploadUrlProvider`] and [`ObjectStore`].
pub struct S3Storage {
    settings: S3Settings,
    creds: CredentialCache,
    client: StorageClient,
    retry: RetryPolicy,
    verified: Mutex<bool>,
}

impl std::fmt::Debug for S3Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Storage")
            .field("settings", &self.settings)
            .finish()
    }
}

impl S3Storage {
    /// A storage for `settings`, with explicit credentials when the settings
    /// carry them and the standard AWS chain otherwise.
    pub fn new(settings: S3Settings) -> Self {
        let provider = settings
            .explicit_credentials
            .clone()
            .map(SharedCredentialsProvider::new);
        Self::build(settings, provider)
    }

    /// A storage signing with `provider` (any `aws-credential-types`
    /// provider, e.g. an STS assume-role provider).
    pub fn with_provider(settings: S3Settings, provider: SharedCredentialsProvider) -> Self {
        Self::build(settings, Some(provider))
    }

    fn build(settings: S3Settings, provider: Option<SharedCredentialsProvider>) -> Self {
        S3Storage {
            client: StorageClient::new(settings.timeouts),
            settings,
            creds: CredentialCache {
                provider,
                chain: std::sync::OnceLock::new(),
                cached: Mutex::new(None),
            },
            retry: RetryPolicy::default(),
            verified: Mutex::new(false),
        }
    }

    /// The settings.
    pub fn settings(&self) -> &S3Settings {
        &self.settings
    }

    /// Whether this storage vends upload grants (`VGI_STORAGE_S3_CHECKSUM`
    /// is `sha256`). With `none`, a server must not register it as an
    /// upload-URL provider nor advertise argument references.
    pub fn issues_upload_grants(&self) -> bool {
        self.settings.checksum == Checksum::Sha256
    }

    fn base(&self, audience: Audience) -> url::Url {
        let endpoint = match audience {
            Audience::Public => self
                .settings
                .public_endpoint
                .as_ref()
                .or(self.settings.endpoint.as_ref()),
            Audience::Worker => self.settings.endpoint.as_ref(),
        };
        let mut base = endpoint.cloned().unwrap_or_else(|| {
            url::Url::parse(&format!(
                "https://s3.{}.amazonaws.com",
                self.settings.region
            ))
            .expect("AWS endpoint")
        });
        if !self.settings.force_path_style {
            let host = format!(
                "{}.{}",
                self.settings.bucket,
                base.host_str().unwrap_or_default()
            );
            let _ = base.set_host(Some(&host));
        }
        base
    }

    /// The URL of `key` (empty: the bucket) as `audience` reaches it.
    fn object_url(&self, audience: Audience, key: &str) -> url::Url {
        let base = self.base(audience);
        let mut path = base.path().trim_end_matches('/').to_string();
        if self.settings.force_path_style {
            path.push('/');
            path.push_str(&encode_key(&self.settings.bucket));
        }
        path.push('/');
        path.push_str(&encode_key(key));
        let mut url = base;
        url.set_path(&path);
        url
    }

    /// A [`UrlValidator`] accepting only this bucket's URLs on the public
    /// endpoint (for inbound upload pointers).
    pub fn url_validator(&self) -> Result<UrlValidator> {
        let url = self.object_url(Audience::Public, "");
        let host = url.host_str().unwrap_or_default().to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let mut prefix = url.clone();
        prefix.set_query(None);
        crate::vendor::pinned_hosts_validator(
            &[format!("{host}:{port}")],
            url.scheme() == "http",
            &[prefix.to_string()],
        )
    }

    /// Credentials good for `need`, and the URL lifetime they allow.
    fn signing_credentials(&self, need: Duration) -> Result<(Credentials, Duration)> {
        let creds = self.creds.get(need)?;
        let ttl = match CredentialCache::remaining(&creds) {
            None => self.settings.url_ttl,
            Some(left) => self
                .settings
                .url_ttl
                .min(left.saturating_sub(EXPIRY_MARGIN)),
        };
        if ttl < Duration::from_secs(1) {
            return Err(RpcError::runtime_error(
                "s3: the AWS credentials expire too soon to sign a URL",
            ));
        }
        if ttl < need {
            tracing::warn!(
                "vgi_rpc_s3: presigned URL lifetime capped at {}s by the credential expiry",
                ttl.as_secs()
            );
        }
        Ok((creds, ttl))
    }

    /// SigV4 query-presign `method` on `url`, signing exactly `headers` (and
    /// `host`).
    fn presign(
        &self,
        creds: &Credentials,
        method: &str,
        url: &url::Url,
        headers: &[(&str, String)],
        ttl: Duration,
    ) -> Result<String> {
        use aws_sigv4::http_request::{
            sign, PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation,
            SigningSettings, UriPathNormalizationMode,
        };
        let fail = |what: &str| RpcError::runtime_error(format!("s3: presigning failed ({what})"));
        let identity: aws_smithy_runtime_api::client::identity::Identity = creds.clone().into();
        let mut settings = SigningSettings::default();
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(ttl);
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        // Content-Length is signed on purpose (upload v2): storage refuses a
        // body of any other length.
        settings.excluded_headers = Some(vec![
            std::borrow::Cow::Borrowed("authorization"),
            std::borrow::Cow::Borrowed("user-agent"),
        ]);
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.settings.region)
            .name("s3")
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|_| fail("parameters"))?
            .into();
        let signable = SignableRequest::new(
            method,
            url.as_str(),
            headers.iter().map(|(k, v)| (*k, v.as_str())),
            SignableBody::UnsignedPayload,
        )
        .map_err(|_| fail("request"))?;
        let (instructions, _) = sign(signable, &params)
            .map_err(|_| fail("signature"))?
            .into_parts();
        let mut req = http::Request::builder()
            .method(method)
            .uri(url.as_str())
            .body(())
            .map_err(|_| fail("url"))?;
        instructions.apply_to_request_http1x(&mut req);
        Ok(req.uri().to_string())
    }

    fn new_key(&self, area: &str, ext: &str) -> String {
        format!(
            "{}{area}/{}{ext}",
            self.settings.prefix,
            uuid::Uuid::new_v4()
        )
    }

    /// HEAD the bucket once (on first use, or at startup with
    /// `VGI_STORAGE_S3_VERIFY=1`), failing with an actionable message.
    ///
    /// # Errors
    ///
    /// Bucket missing, access denied, wrong region (naming the region the
    /// service reported), or storage unreachable.
    pub fn verify(&self) -> Result<()> {
        let mut verified = self.verified.lock().unwrap_or_else(|e| e.into_inner());
        if *verified {
            return Ok(());
        }
        let (creds, _) = self.signing_credentials(OWN_MIN)?;
        let url = self.object_url(Audience::Worker, "");
        let signed = self.presign(&creds, "HEAD", &url, &[], OWN_MIN)?;
        let bucket = &self.settings.bucket;
        let resp = self
            .client
            .send(reqwest::Method::HEAD, &signed, &[], None)
            .map_err(|e| {
                RpcError::runtime_error(format!(
                    "s3: cannot reach bucket {bucket:?} at {} ({e}); check {ENV_ENDPOINT}",
                    redact_url(url.as_str())
                ))
            })?;
        let status = resp.status().as_u16();
        let reported = resp
            .headers()
            .get("x-amz-bucket-region")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let region = &self.settings.region;
        let message = match status {
            200..=299 => {
                *verified = true;
                return Ok(());
            }
            301 | 400 if reported.as_deref().is_some_and(|r| r != region) => format!(
                "s3: bucket {bucket:?} is in region {:?}, not {region:?}; set {ENV_REGION}",
                reported.unwrap_or_default()
            ),
            404 => format!("s3: bucket {bucket:?} does not exist (HTTP 404); check {ENV_BUCKET}"),
            400 => format!(
                "s3: bucket check for {bucket:?} was refused (HTTP 400); check the credentials, \
                 {ENV_REGION} and {ENV_ENDPOINT}"
            ),
            401 | 403 => format!(
                "s3: access denied to bucket {bucket:?} (HTTP {status}); check the credentials and \
                 that they allow s3:ListBucket, s3:GetObject and s3:PutObject on it"
            ),
            other => format!("s3: bucket check for {bucket:?} failed: HTTP {other}"),
        };
        Err(RpcError::runtime_error(message))
    }

    /// Store `data` under `key` (the worker's own PUT), with the checksum
    /// header when enabled.
    ///
    /// # Errors
    ///
    /// On a storage failure.
    pub fn put_key(
        &self,
        key: &str,
        data: &[u8],
        content_type: &str,
        content_encoding: Option<&str>,
    ) -> Result<()> {
        self.verify()?;
        let (creds, ttl) = self.signing_credentials(OWN_MIN)?;
        let mut headers = vec![
            ("content-length", data.len().to_string()),
            ("content-type", content_type.to_string()),
        ];
        if let Some(enc) = content_encoding {
            headers.push(("content-encoding", enc.to_string()));
        }
        if self.settings.checksum == Checksum::Sha256 {
            headers.push(("x-amz-checksum-sha256", sha256_b64(data)));
        }
        let url = self.object_url(Audience::Worker, key);
        let signed = self.presign(&creds, "PUT", &url, &headers, ttl.min(OWN_MIN * 15))?;
        let send: Vec<(String, String)> = headers
            .iter()
            .filter(|(k, _)| *k != "content-length")
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect();
        signed_put(
            &self.client,
            &self.retry,
            "s3",
            &signed,
            &send,
            bytes::Bytes::copy_from_slice(data),
        )
    }

    /// Fetch `key` (the worker's own GET), at most `max_bytes`; `None` when
    /// it does not exist.
    ///
    /// # Errors
    ///
    /// On a storage failure or a body over the cap.
    pub fn get_key(&self, key: &str, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        self.verify()?;
        let (creds, ttl) = self.signing_credentials(OWN_MIN)?;
        let url = self.object_url(Audience::Worker, key);
        let signed = self.presign(&creds, "GET", &url, &[], ttl.min(OWN_MIN * 15))?;
        signed_get(&self.client, &self.retry, "s3", &signed, max_bytes)
    }

    /// The full key of a function-storage path (`<prefix>fs/<name>`).
    pub fn fs_key(&self, name: &str) -> String {
        format!("{}fs/{name}", self.settings.prefix)
    }

    /// Delete `key`, best effort: one attempt, failures ignored (a missing
    /// object is not an error). Lifecycle rules are the backstop.
    pub fn delete_key(&self, key: &str) {
        let Ok((creds, ttl)) = self.signing_credentials(OWN_MIN) else {
            return;
        };
        let url = self.object_url(Audience::Worker, key);
        if let Ok(signed) = self.presign(&creds, "DELETE", &url, &[], ttl.min(OWN_MIN * 15)) {
            if let Ok(resp) = self
                .client
                .send(reqwest::Method::DELETE, &signed, &[], None)
            {
                let _ = resp.read_capped(64 * 1024);
            }
        }
    }

    /// Delete every object under `prefix` (a full key prefix), best effort:
    /// ListObjectsV2 pages and one DELETE per key, failures ignored.
    pub fn delete_prefix(&self, prefix: &str) {
        let mut token: Option<String> = None;
        for _ in 0..100 {
            let Ok((creds, ttl)) = self.signing_credentials(OWN_MIN) else {
                return;
            };
            let mut url = self.object_url(Audience::Worker, "");
            {
                let mut q = url.query_pairs_mut();
                q.append_pair("list-type", "2");
                q.append_pair("prefix", prefix);
                if let Some(t) = &token {
                    q.append_pair("continuation-token", t);
                }
            }
            let Ok(signed) = self.presign(&creds, "GET", &url, &[], ttl.min(OWN_MIN * 15)) else {
                return;
            };
            let Ok(Some(body)) = signed_get(
                &self.client,
                &RetryPolicy::default(),
                "s3",
                &signed,
                8 << 20,
            ) else {
                return;
            };
            let text = String::from_utf8_lossy(&body);
            for key in xml_values(&text, "Key") {
                if key.starts_with(prefix) {
                    self.delete_key(&key);
                }
            }
            token = xml_values(&text, "NextContinuationToken")
                .into_iter()
                .next();
            if token.is_none() {
                return;
            }
        }
    }
}

/// The text of every `<tag>...</tag>` in `xml`, entity-decoded.
fn xml_values(xml: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        rest = &rest[i + open.len()..];
        let Some(j) = rest.find(&close) else { break };
        out.push(
            rest[..j]
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&amp;", "&"),
        );
        rest = &rest[j + close.len()..];
    }
    out
}

fn sha256_b64(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(data))
}

fn micros(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

impl ExternalStorage for S3Storage {
    fn upload(&self, ipc_bytes: &[u8], compression: Compression) -> Result<UploadResult> {
        let key = self.new_key("rpc", ".arrow");
        let encoding = match compression {
            Compression::None => None,
            Compression::Zstd(_) => Some("zstd"),
        };
        self.put_key(
            &key,
            ipc_bytes,
            "application/vnd.apache.arrow.stream",
            encoding,
        )?;
        let (creds, ttl) = self.signing_credentials(RESULT_MIN)?;
        let url = self.object_url(Audience::Public, &key);
        let download = self.presign(&creds, "GET", &url, &[], ttl)?;
        tracing::debug!(
            "Stored {} bytes as {}",
            ipc_bytes.len(),
            redact_url(&download)
        );
        Ok(UploadResult {
            url: download,
            sha256: String::new(),
        })
    }

    fn object_store(&self) -> Option<&dyn ObjectStore> {
        Some(self)
    }
}

impl UploadUrlProvider for S3Storage {
    fn generate_upload_url(&self, size: u64, sha256_hex: &str) -> Result<UploadUrl> {
        if !self.issues_upload_grants() {
            return Err(RpcError::runtime_error(format!(
                "s3: upload grants are disabled ({ENV_CHECKSUM}=none)"
            )));
        }
        if !vgi_rpc::external::is_sha256_hex(sha256_hex) {
            return Err(RpcError::value_error(
                "sha256 must be 64 lowercase hex characters",
            ));
        }
        self.verify()?;
        let checksum = vgi_rpc::external::sha256_hex_to_b64(sha256_hex)?;
        let key = self.new_key("rpc", ".arrow");
        let (creds, ttl) = self.signing_credentials(GRANT_MIN)?;
        let url = self.object_url(Audience::Public, &key);
        let put = self.presign(
            &creds,
            "PUT",
            &url,
            &[
                ("content-length", size.to_string()),
                ("x-amz-checksum-sha256", checksum.clone()),
            ],
            ttl,
        )?;
        let get = self.presign(&creds, "GET", &url, &[], ttl)?;
        Ok(UploadUrl {
            object_id: key,
            upload_url: put,
            download_url: get,
            expires_at_micros: micros(SystemTime::now() + ttl),
            headers: vec![("x-amz-checksum-sha256".to_string(), checksum)],
            argument_ref: Vec::new(),
        })
    }
}

/// The object API (`STATE_REF_V1.md` §10.1): `object_id` is the object key.
/// Objects are re-signed on every fetch, so they survive credential rotation.
impl ObjectStore for S3Storage {
    fn put_object(&self, data: &[u8]) -> Result<String> {
        let key = self.new_key("rpc", ".bin");
        self.put_key(&key, data, "application/octet-stream", None)?;
        Ok(key)
    }

    fn get(&self, object_id: &str, max_bytes: usize) -> Result<Vec<u8>> {
        if object_id.is_empty() || object_id.len() > 1024 {
            return Err(RpcError::value_error("s3: invalid object id"));
        }
        self.get_key(object_id, max_bytes)?
            .ok_or_else(|| object_missing_error("s3 object is gone"))
    }
}

/// Shared handle type for wiring.
pub type SharedS3Storage = Arc<S3Storage>;

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn storage(pairs: &[(&str, &str)]) -> S3Storage {
        let mut all = vec![
            (ENV_ACCESS_KEY_ID, "AKIDEXAMPLE"),
            (ENV_SECRET_ACCESS_KEY, "secretsecret"),
            (ENV_ALLOW_PLAIN_HTTP, "1"),
        ];
        all.extend_from_slice(pairs);
        S3Storage::new(S3Settings::from_lookup(&lookup(&all)).unwrap())
    }

    #[test]
    fn settings_defaults_and_errors() {
        let s = S3Settings::from_lookup(&lookup(&[(ENV_BUCKET, "bkt1")])).unwrap();
        assert_eq!(s.region, "us-east-1");
        assert!(!s.force_path_style);
        assert_eq!(s.checksum, Checksum::Sha256);
        assert_eq!(s.url_ttl, DEFAULT_URL_TTL);
        let s = S3Settings::from_lookup(&lookup(&[
            (ENV_BUCKET, "bkt1"),
            (ENV_ENDPOINT, "http://minio:9000"),
            (ENV_ALLOW_PLAIN_HTTP, "1"),
            ("AWS_DEFAULT_REGION", "eu-west-1"),
        ]))
        .unwrap();
        assert!(s.force_path_style);
        assert_eq!(s.region, "eu-west-1");
        let s = S3Settings::from_lookup(&lookup(&[
            (ENV_BUCKET, "bkt1"),
            (ENV_REGION, "auto"),
            ("AWS_REGION", "us-west-2"),
            (ENV_CHECKSUM, "NONE"),
            (ENV_URL_TTL, "999999999"),
        ]))
        .unwrap();
        assert_eq!(s.region, "auto");
        assert_eq!(s.checksum, Checksum::None);
        assert_eq!(s.url_ttl, MAX_URL_TTL);
        for bad in [
            vec![],
            vec![(ENV_BUCKET, "bkt1"), (ENV_CHECKSUM, "md5")],
            vec![(ENV_BUCKET, "bkt1"), (ENV_URL_TTL, "5")],
            vec![(ENV_BUCKET, "bkt1"), (ENV_ENDPOINT, "ftp://x")],
            vec![(ENV_BUCKET, "bkt1"), (ENV_ENDPOINT, "https://u:p@x")],
            vec![(ENV_BUCKET, "bkt1"), (ENV_ACCESS_KEY_ID, "a")],
            vec![(ENV_BUCKET, "bkt1"), (ENV_SESSION_TOKEN, "t")],
            vec![(ENV_BUCKET, "Bad_Bucket")],
            vec![(ENV_BUCKET, "bkt1"), (ENV_FORCE_PATH_STYLE, "maybe")],
            // Plain http needs the opt-in, for the endpoint and the public endpoint.
            vec![(ENV_BUCKET, "bkt1"), (ENV_ENDPOINT, "http://minio:9000")],
            vec![
                (ENV_BUCKET, "bkt1"),
                (ENV_PUBLIC_ENDPOINT, "http://s3.example.com"),
            ],
            vec![(ENV_BUCKET, "bkt1"), (ENV_SESSION_EXPIRES, "tomorrow")],
        ] {
            assert!(S3Settings::from_lookup(&lookup(&bad)).is_err(), "{bad:?}");
        }
        let debug = format!(
            "{:?}",
            S3Settings::from_lookup(&lookup(&[
                (ENV_BUCKET, "bkt1"),
                (ENV_ACCESS_KEY_ID, "AKIDSECRETID"),
                (ENV_SECRET_ACCESS_KEY, "SUPERSECRET"),
                (ENV_SESSION_TOKEN, "TOKENSECRET"),
            ]))
            .unwrap()
        );
        assert!(!debug.contains("SUPERSECRET") && !debug.contains("TOKENSECRET"));
    }

    #[test]
    fn explicit_session_expiry_caps_url_lifetime() {
        let in_20_min = SystemTime::now() + Duration::from_secs(1200);
        let epoch = in_20_min
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let rfc3339 = chrono::DateTime::<chrono::Utc>::from(in_20_min).to_rfc3339();
        for expires in [epoch, rfc3339] {
            let s = storage(&[
                (ENV_BUCKET, "bkt1"),
                (ENV_SESSION_TOKEN, "tok"),
                (ENV_SESSION_EXPIRES, expires.as_str()),
            ]);
            let (_, ttl) = s.signing_credentials(OWN_MIN).unwrap();
            assert!(
                ttl <= Duration::from_secs(1140) && ttl > Duration::from_secs(1130),
                "{ttl:?}"
            );
        }
        // Without an expiry the configured TTL applies (and a warning is logged).
        let s = storage(&[(ENV_BUCKET, "bkt1"), (ENV_SESSION_TOKEN, "tok")]);
        assert_eq!(s.signing_credentials(OWN_MIN).unwrap().1, DEFAULT_URL_TTL);
    }

    #[test]
    fn xml_listing_values() {
        let xml = "<ListBucketResult><Contents><Key>p/fs/a&amp;b</Key></Contents>\
                   <Contents><Key>p/fs/c</Key></Contents><NextContinuationToken>t+1</NextContinuationToken></ListBucketResult>";
        assert_eq!(xml_values(xml, "Key"), vec!["p/fs/a&b", "p/fs/c"]);
        assert_eq!(xml_values(xml, "NextContinuationToken"), vec!["t+1"]);
    }

    #[test]
    fn addressing_styles_and_public_endpoint() {
        let aws = storage(&[(ENV_BUCKET, "my-bucket"), (ENV_REGION, "eu-west-1")]);
        assert_eq!(
            aws.object_url(Audience::Public, "a b/c.bin").as_str(),
            "https://my-bucket.s3.eu-west-1.amazonaws.com/a%20b/c.bin"
        );
        let minio = storage(&[
            (ENV_BUCKET, "my-bucket"),
            (ENV_ENDPOINT, "http://minio:9000"),
            (ENV_PUBLIC_ENDPOINT, "https://s3.example.com"),
        ]);
        assert_eq!(
            minio.object_url(Audience::Worker, "k").as_str(),
            "http://minio:9000/my-bucket/k"
        );
        assert_eq!(
            minio.object_url(Audience::Public, "k").as_str(),
            "https://s3.example.com/my-bucket/k"
        );
        let validate = minio.url_validator().unwrap();
        assert!(
            validate("https://s3.example.com/my-bucket/vgi/rpc/x.arrow?X-Amz-Signature=1").is_ok()
        );
        assert!(validate("http://minio:9000/my-bucket/x").is_err());
        assert!(validate("https://s3.example.com/other-bucket/x").is_err());
        let r2 = storage(&[
            (ENV_BUCKET, "bkt"),
            (ENV_ENDPOINT, "https://acct.r2.cloudflarestorage.com"),
            (ENV_FORCE_PATH_STYLE, "false"),
            (ENV_REGION, "auto"),
        ]);
        assert_eq!(
            r2.object_url(Audience::Public, "k").as_str(),
            "https://bkt.acct.r2.cloudflarestorage.com/k"
        );
    }

    #[test]
    fn presigned_grant_signs_length_checksum_and_session_token() {
        let s = storage(&[
            (ENV_BUCKET, "bkt"),
            (ENV_ENDPOINT, "http://127.0.0.1:9000"),
            (ENV_SESSION_TOKEN, "tok/en+=="),
            (ENV_URL_TTL, "600"),
        ]);
        // Skip the bucket check: this test never talks to storage.
        *s.verified.lock().unwrap() = true;
        let sha = "a".repeat(64);
        let grant = s.generate_upload_url(42, &sha).unwrap();
        let u = url::Url::parse(&grant.upload_url).unwrap();
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(
            q["X-Amz-SignedHeaders"],
            "content-length;host;x-amz-checksum-sha256"
        );
        assert_eq!(q["X-Amz-Expires"], "600");
        assert_eq!(q["X-Amz-Security-Token"], "tok/en+==");
        assert!(q["X-Amz-Credential"].starts_with("AKIDEXAMPLE/"));
        assert!(q["X-Amz-Credential"].contains("/us-east-1/s3/aws4_request"));
        assert!(grant.object_id.starts_with("rpc/") && grant.object_id.ends_with(".arrow"));
        assert_eq!(grant.headers[0].0, "x-amz-checksum-sha256");
        assert!(!grant.upload_url.contains("secretsecret"));

        let none = storage(&[(ENV_BUCKET, "bkt"), (ENV_CHECKSUM, "none")]);
        assert!(!none.issues_upload_grants());
        assert!(none.generate_upload_url(42, &sha).is_err());
    }

    /// Temporary credentials are refreshed 5 minutes ahead of expiry and the
    /// URL lifetime is capped by the expiry.
    #[test]
    fn temporary_credentials_refresh_and_cap_ttl() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Debug)]
        struct Rotating(Arc<AtomicUsize>, Duration);
        impl ProvideCredentials for Rotating {
            fn provide_credentials<'a>(
                &'a self,
            ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
            where
                Self: 'a,
            {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                aws_credential_types::provider::future::ProvideCredentials::ready(Ok(
                    Credentials::new(
                        format!("AKID{n}"),
                        "s",
                        Some(format!("token{n}")),
                        Some(SystemTime::now() + self.1),
                        "test",
                    ),
                ))
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let settings = S3Settings::from_lookup(&lookup(&[(ENV_BUCKET, "bkt")])).unwrap();
        // 20 minutes left: fine for the worker's own 2-minute URLs, capped
        // to 19 minutes, but an upload grant (15 min) still fits.
        let s = S3Storage::with_provider(
            settings.clone(),
            SharedCredentialsProvider::new(Rotating(calls.clone(), Duration::from_secs(1200))),
        );
        let (c, ttl) = s.signing_credentials(OWN_MIN).unwrap();
        assert_eq!(c.access_key_id(), "AKID0");
        assert!(
            ttl <= Duration::from_secs(1140) && ttl > Duration::from_secs(1130),
            "{ttl:?}"
        );
        let (c, _) = s.signing_credentials(GRANT_MIN).unwrap();
        assert_eq!(c.access_key_id(), "AKID0");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // 6 minutes left: inside the 5-minute refresh window plus margin for
        // a grant, so every call refreshes.
        let calls = Arc::new(AtomicUsize::new(0));
        let s = S3Storage::with_provider(
            settings,
            SharedCredentialsProvider::new(Rotating(calls.clone(), Duration::from_secs(360))),
        );
        let (c0, _) = s.signing_credentials(OWN_MIN).unwrap();
        let (c1, ttl) = s.signing_credentials(GRANT_MIN).unwrap();
        assert_ne!(c0.access_key_id(), c1.access_key_id());
        assert!(ttl <= Duration::from_secs(300), "{ttl:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
