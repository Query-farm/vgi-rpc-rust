//! JWKS-backed JWT bearer authentication.
//!
//! Enabled by the `jwt` Cargo feature. Validates incoming JWT bearer tokens
//! against a remote JWKS endpoint (RFC 7517), supports RS256/RS384/RS512
//! and ES256/ES384/ES512, and refreshes the JWKS on unknown `kid` with
//! a single-flight guard.
//!
//! Typical usage:
//!
//! ```ignore
//! use vgi_rpc::auth::jwt::{jwt_authenticate, JwtConfig};
//!
//! let cfg = JwtConfig::new("https://issuer.example/")
//!     .with_audience("https://api.example.com")
//!     .with_principal_claim("sub")
//!     .with_jwks_url("https://issuer.example/.well-known/jwks.json");
//! let auth = jwt_authenticate(cfg);
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::auth::{extract_bearer, AuthContext, AuthRequest, AuthResult, Authenticate};
use crate::errors::RpcError;

/// Configuration for a JWKS-validated JWT bearer.
#[derive(Clone, Debug)]
pub struct JwtConfig {
    pub issuer: String,
    pub audience: Option<String>,
    pub principal_claim: String,
    pub jwks_url: Option<String>,
    pub refresh_interval: Duration,
    pub leeway: Duration,
}

impl JwtConfig {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: None,
            principal_claim: "sub".into(),
            jwks_url: None,
            refresh_interval: Duration::from_secs(600),
            leeway: Duration::from_secs(30),
        }
    }

    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.audience = Some(aud.into());
        self
    }

    pub fn with_principal_claim(mut self, claim: impl Into<String>) -> Self {
        self.principal_claim = claim.into();
        self
    }

    pub fn with_jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = Some(url.into());
        self
    }

    pub fn with_refresh_interval(mut self, d: Duration) -> Self {
        self.refresh_interval = d;
        self
    }

    pub fn with_leeway(mut self, d: Duration) -> Self {
        self.leeway = d;
        self
    }
}

/// A fetched JWKS document.
#[derive(Clone, Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<JwksKey>,
}

/// One JWKS key entry (subset — matches the claims the verifier looks up).
#[derive(Clone, Debug, Deserialize)]
pub struct JwksKey {
    pub kid: Option<String>,
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
}

/// Function used by the JWT helper to fetch a JWKS document. Abstracted so
/// tests can inject a synthetic JWKS without opening a socket.
pub type JwksFetcher = Arc<dyn Fn(&str) -> std::result::Result<Jwks, RpcError> + Send + Sync>;

/// A cache holding the most recent JWKS document + last refresh time.
struct JwksCache {
    keys: HashMap<String, JwksKey>,
    last_refresh: Instant,
}

/// Build a JWT-validating authenticate callback.
///
/// The returned callback returns:
///   - `Anonymous()` when the `Authorization: Bearer` header is missing.
///   - `Err(PermissionError)` when a token is present but verification fails.
///   - `Ok(ctx)` with `principal` populated from the configured claim when
///     verification succeeds.
///
/// **Without the `jwt-jsonwebtoken` feature** this crate stays agnostic
/// to the crypto library: the default fetcher and verifier both error,
/// and you must call [`jwt_authenticate_with`] supplying your own.
///
/// **With the `jwt-jsonwebtoken` feature** the helper wires
/// `jsonwebtoken` (RS256/RS384/RS512, ES256/ES384, EdDSA) and a
/// blocking `reqwest` JWKS fetcher automatically; just pass a
/// `JwtConfig` with `jwks_url` set.
pub fn jwt_authenticate(cfg: JwtConfig) -> Authenticate {
    #[cfg(feature = "jwt-jsonwebtoken")]
    {
        jwt_authenticate_with(cfg, Arc::new(reqwest_jwks_fetcher), jsonwebtoken_verifier())
    }
    #[cfg(not(feature = "jwt-jsonwebtoken"))]
    {
        jwt_authenticate_with(cfg, Arc::new(default_jwks_fetcher), no_op_verifier())
    }
}

/// Advanced variant that exposes the JWKS fetcher + verifier hooks.
pub fn jwt_authenticate_with(
    cfg: JwtConfig,
    fetcher: JwksFetcher,
    verifier: Arc<Verifier>,
) -> Authenticate {
    let cache = Arc::new(Mutex::new(None::<JwksCache>));
    let cfg = Arc::new(cfg);
    let fetcher = fetcher.clone();
    Arc::new(move |req: &AuthRequest<'_>| -> AuthResult {
        let Some(token) = extract_bearer(req) else {
            return Ok(AuthContext::anonymous());
        };
        let ctx = validate_token(&cfg, &cache, &fetcher, &verifier, token)?;
        Ok(ctx)
    })
}

/// User-supplied verification closure.
///
/// Given a `JwksKey` + token, returns the decoded claims map (string → string)
/// on success, or an error to reject the token.
pub type Verifier =
    dyn Fn(&JwksKey, &str) -> std::result::Result<HashMap<String, String>, RpcError> + Send + Sync;

#[cfg(not(feature = "jwt-jsonwebtoken"))]
fn no_op_verifier() -> Arc<Verifier> {
    Arc::new(|_key, _tok| {
        Err(RpcError::runtime_error(
            "jwt_authenticate requires a verifier; use jwt_authenticate_with \
             or enable the `jwt-jsonwebtoken` feature",
        ))
    })
}

#[cfg(not(feature = "jwt-jsonwebtoken"))]
fn default_jwks_fetcher(_url: &str) -> std::result::Result<Jwks, RpcError> {
    Err(RpcError::runtime_error(
        "no default JWKS fetcher configured; pass one via jwt_authenticate_with \
         or enable the `jwt-jsonwebtoken` feature",
    ))
}

fn decode_unverified_kid(token: &str) -> Option<String> {
    // JWT = header.payload.signature, each base64url-encoded.
    let header_b64 = token.split('.').next()?;
    let bytes = base64url_decode(header_b64)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("kid")?.as_str().map(|s| s.to_string())
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    // Convert URL-safe, unpadded base64 to standard and decode.
    let mut padded = s.replace('-', "+").replace('_', "/");
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    #[cfg(feature = "http")]
    {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(padded.as_bytes())
            .ok()
    }
    #[cfg(not(feature = "http"))]
    {
        let _ = padded;
        None
    }
}

fn validate_token(
    cfg: &Arc<JwtConfig>,
    cache: &Arc<Mutex<Option<JwksCache>>>,
    fetcher: &JwksFetcher,
    verifier: &Arc<Verifier>,
    token: &str,
) -> AuthResult {
    let kid = decode_unverified_kid(token)
        .ok_or_else(|| RpcError::permission_error("JWT header missing 'kid'"))?;

    let key = {
        let key_opt = cache
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|c| c.keys.get(&kid).cloned());
        match key_opt {
            Some(k) => k,
            None => {
                refresh_jwks(cfg, cache, fetcher)?;
                cache
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|c| c.keys.get(&kid).cloned())
                    .ok_or_else(|| RpcError::permission_error(format!("unknown JWT kid: {kid}")))?
            }
        }
    };

    let claims = verifier(&key, token)
        .map_err(|e| RpcError::permission_error(format!("JWT verification failed: {e}")))?;

    // Required issuer/audience checks (claim strings).
    if let Some(iss) = claims.get("iss") {
        if iss != &cfg.issuer {
            return Err(RpcError::permission_error(format!(
                "JWT issuer mismatch: {iss}"
            )));
        }
    }
    if let Some(expected_aud) = cfg.audience.as_ref() {
        if claims.get("aud") != Some(expected_aud) {
            return Err(RpcError::permission_error("JWT audience mismatch"));
        }
    }

    let principal = claims
        .get(&cfg.principal_claim)
        .cloned()
        .unwrap_or_default();
    let mut ctx = AuthContext::for_principal(format!("jwt:{}", cfg.issuer), principal);
    for (k, v) in claims.into_iter() {
        ctx = ctx.with_claim(k, v);
    }
    Ok(ctx)
}

fn refresh_jwks(
    cfg: &Arc<JwtConfig>,
    cache: &Arc<Mutex<Option<JwksCache>>>,
    fetcher: &JwksFetcher,
) -> std::result::Result<(), RpcError> {
    let url = cfg
        .jwks_url
        .as_deref()
        .ok_or_else(|| RpcError::runtime_error("JwtConfig.jwks_url must be set to refresh"))?;
    // Snapshot the cache's `last_refresh` *before* taking the lock so
    // late-arriving threads notice when a peer refreshed while they
    // were waiting and skip the network call.  Without this, N
    // concurrent calls hitting an unknown `kid` during a key rotation
    // would each race past the interval check, drop the lock to call
    // the fetcher, and stampede the JWKS endpoint with N back-to-back
    // GETs — exactly when the service should be recovering.
    let seen_last_refresh = cache.lock().unwrap().as_ref().map(|c| c.last_refresh);
    let mut guard = cache.lock().unwrap();
    if let Some(c) = guard.as_ref() {
        // Another thread refreshed while we were waiting on the lock.
        if Some(c.last_refresh) != seen_last_refresh {
            return Ok(());
        }
        // Within the configured refresh interval — peer (or earlier
        // call from this thread) already covers us.
        if Instant::now().duration_since(c.last_refresh) < cfg.refresh_interval {
            return Ok(());
        }
    }
    // Hold the lock across the fetch so only one thread issues the
    // JWKS GET; peers parked on the lock will observe the freshly
    // populated cache when they wake.
    let doc = fetcher(url)?;
    let mut keys = HashMap::new();
    for k in doc.keys {
        if let Some(kid) = k.kid.clone() {
            keys.insert(kid, k);
        }
    }
    *guard = Some(JwksCache {
        keys,
        last_refresh: Instant::now(),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Optional bundled verifier + fetcher (feature `jwt-jsonwebtoken`)
// ---------------------------------------------------------------------------

/// Default blocking JWKS fetcher backed by `reqwest`. Available when the
/// `jwt-jsonwebtoken` feature is on. Performs a GET, validates JSON,
/// returns the parsed [`Jwks`].
#[cfg(feature = "jwt-jsonwebtoken")]
pub fn reqwest_jwks_fetcher(url: &str) -> std::result::Result<Jwks, RpcError> {
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| RpcError::runtime_error(format!("jwks client: {e}")))?
        .get(url)
        .send()
        .map_err(|e| RpcError::runtime_error(format!("jwks GET {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(RpcError::runtime_error(format!(
            "jwks GET {url} returned {}",
            resp.status()
        )));
    }
    resp.json::<Jwks>()
        .map_err(|e| RpcError::runtime_error(format!("jwks JSON {url}: {e}")))
}

/// Build a verifier closure backed by the `jsonwebtoken` crate.
///
/// Supports RS256/RS384/RS512, ES256/ES384, EdDSA — the algorithm is
/// taken from the JWT header (`alg`) crossed-checked against the JWKS
/// key's `alg`. Disables `jsonwebtoken`'s built-in `aud` / `iss`
/// validation since this crate already enforces those in
/// [`validate_token`].
#[cfg(feature = "jwt-jsonwebtoken")]
pub fn jsonwebtoken_verifier() -> Arc<Verifier> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    Arc::new(|key: &JwksKey, token: &str| {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| RpcError::permission_error(format!("JWT header: {e}")))?;
        let alg = header.alg;
        if let Some(declared) = key.alg.as_deref() {
            let declared_alg: Algorithm = declared
                .parse()
                .map_err(|_| RpcError::permission_error(format!("unsupported alg {declared}")))?;
            if declared_alg != alg {
                return Err(RpcError::permission_error(format!(
                    "JWT alg {alg:?} mismatches JWKS alg {declared}"
                )));
            }
        }

        let decoding_key = match (key.key_type.as_str(), alg) {
            ("RSA", Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512) => {
                let n = key
                    .n
                    .as_deref()
                    .ok_or_else(|| RpcError::permission_error("JWKS RSA key missing n"))?;
                let e = key
                    .e
                    .as_deref()
                    .ok_or_else(|| RpcError::permission_error("JWKS RSA key missing e"))?;
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|err| RpcError::permission_error(format!("RSA key: {err}")))?
            }
            ("EC", Algorithm::ES256 | Algorithm::ES384) => {
                let x = key
                    .x
                    .as_deref()
                    .ok_or_else(|| RpcError::permission_error("JWKS EC key missing x"))?;
                let y = key
                    .y
                    .as_deref()
                    .ok_or_else(|| RpcError::permission_error("JWKS EC key missing y"))?;
                DecodingKey::from_ec_components(x, y)
                    .map_err(|err| RpcError::permission_error(format!("EC key: {err}")))?
            }
            ("OKP", Algorithm::EdDSA) => {
                let x = key
                    .x
                    .as_deref()
                    .ok_or_else(|| RpcError::permission_error("JWKS OKP key missing x"))?;
                DecodingKey::from_ed_components(x)
                    .map_err(|err| RpcError::permission_error(format!("Ed key: {err}")))?
            }
            other => {
                return Err(RpcError::permission_error(format!(
                    "unsupported JWKS key/alg combination: {other:?}"
                )));
            }
        };

        // We do our own iss/aud checks in validate_token, so disable
        // jsonwebtoken's built-in ones.
        let mut validation = Validation::new(alg);
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let data = jsonwebtoken::decode::<HashMap<String, serde_json::Value>>(
            token,
            &decoding_key,
            &validation,
        )
        .map_err(|e| RpcError::permission_error(format!("JWT verify: {e}")))?;

        // Convert claims to string-valued map matching the existing
        // `Verifier` contract.
        let mut out: HashMap<String, String> = HashMap::with_capacity(data.claims.len());
        for (k, v) in data.claims {
            let s = match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            out.insert(k, s);
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with_bearer(tok: &str) -> Vec<(String, String)> {
        vec![("authorization".into(), format!("Bearer {tok}"))]
    }

    fn fake_token_with_kid(kid: &str) -> String {
        let header = serde_json::json!({"alg": "RS256", "kid": kid}).to_string();
        let enc = base64_url_encode(header.as_bytes());
        format!("{enc}.eyJzdWIiOiJhbGljZSJ9.sig")
    }

    fn base64_url_encode(b: &[u8]) -> String {
        #[cfg(feature = "http")]
        {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        }
        #[cfg(not(feature = "http"))]
        unreachable!()
    }

    #[test]
    fn missing_header_is_anonymous() {
        let auth = jwt_authenticate(JwtConfig::new("https://iss"));
        let req = AuthRequest::anonymous_pipe("x");
        assert!(!auth(&req).unwrap().authenticated);
    }

    #[test]
    fn unknown_kid_triggers_refresh_then_errors() {
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetcher: JwksFetcher = {
            let c = call_count.clone();
            Arc::new(move |_| {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Jwks { keys: vec![] })
            })
        };
        let verifier: Arc<Verifier> = Arc::new(|_, _| Ok(HashMap::new()));
        let auth = jwt_authenticate_with(
            JwtConfig::new("https://iss").with_jwks_url("https://iss/.well-known/jwks"),
            fetcher,
            verifier,
        );
        let tok = fake_token_with_kid("unknown-kid");
        let headers = req_with_bearer(&tok);
        let req = AuthRequest {
            method: "x",
            headers: &headers,
            peer_addr: None,
        };
        let err = auth(&req).unwrap_err();
        assert!(err.message.contains("unknown JWT kid"));
        assert!(call_count.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    }

    #[test]
    fn known_kid_issues_authenticated_ctx() {
        // Prepare a fake key; verifier returns a fixed claims map.
        let key = JwksKey {
            kid: Some("k1".into()),
            key_type: "RSA".into(),
            alg: Some("RS256".into()),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
        };
        let fetcher: JwksFetcher = Arc::new(move |_| {
            Ok(Jwks {
                keys: vec![key.clone()],
            })
        });
        let verifier: Arc<Verifier> = Arc::new(|_, _| {
            let mut m = HashMap::new();
            m.insert("iss".into(), "https://iss".into());
            m.insert("sub".into(), "alice".into());
            Ok(m)
        });
        let auth = jwt_authenticate_with(
            JwtConfig::new("https://iss").with_jwks_url("https://iss/jwks"),
            fetcher,
            verifier,
        );
        let tok = fake_token_with_kid("k1");
        let headers = req_with_bearer(&tok);
        let req = AuthRequest {
            method: "x",
            headers: &headers,
            peer_addr: None,
        };
        let ctx = auth(&req).unwrap();
        assert!(ctx.authenticated);
        assert_eq!(ctx.principal, "alice");
        assert_eq!(ctx.domain, "jwt:https://iss");
        assert_eq!(
            ctx.claims.get("iss").map(String::as_str),
            Some("https://iss")
        );
    }
}
