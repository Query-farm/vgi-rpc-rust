//! High-level OAuth 2.0 + PKCE browser flow built on the primitives in
//! [`crate::auth::pkce`].
//!
//! Enabled by the `oauth-pkce-server` Cargo feature (pulls in `reqwest`
//! for the token-exchange POST and `urlencoding` for query-string
//! handling).
//!
//! Mounts three routes under `{prefix}/_oauth/`:
//!
//! - `GET /_oauth/start?return_to=URL` — generates a PKCE pair, sets a
//!   short-lived session cookie carrying the verifier, and redirects to
//!   the configured `authorization_endpoint`.
//! - `GET /_oauth/callback?code=...&state=...` — verifies the session
//!   cookie, exchanges the code for an ID token at `token_endpoint`,
//!   sets the auth cookie, and redirects to `return_to`.
//! - `GET /_oauth/logout` — clears the auth cookie and redirects.
//!
//! Mirrors the Python canonical at
//! `vgi_rpc/http/_oauth_pkce.py` in shape, not byte-for-byte: cookie
//! formats, allowed-origin checks, and the visible HTML are
//! Rust-specific. Refresh-token / external-frontend redirect-with-token
//! support is intentionally omitted from this MVP — open an issue if
//! you need it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::auth::pkce::{
    generate_pkce_pair, is_allowed_return_origin, new_state_cookie, verify_state_cookie,
};
use crate::auth::{AuthContext, AuthRequest, AuthResult, Authenticate};
use crate::errors::RpcError;

/// Cookie carrying the PKCE session (verifier + state nonce + return_to).
/// Short-lived; cleared on callback.
pub const PKCE_SESSION_COOKIE: &str = "_vgi_pkce";

/// Lifetime of a PKCE session cookie — the window between `/_oauth/start`
/// and the IdP redirecting back to `/_oauth/callback`. Bound into the
/// cookie's signature (`created_at`) and enforced on the callback, so a
/// captured cookie cannot be replayed past this window.
const PKCE_STATE_TTL: Duration = Duration::from_secs(600);

/// Cookie carrying the authenticated user's ID token (JWT). Long-lived
/// up to the token's `exp` claim.
pub const AUTH_COOKIE_NAME: &str = "_vgi_auth";

/// JS-readable display-identity cookie for the shared VGI landing page.
/// Derived from the OIDC id_token at the callback (display-only; the
/// validated bearer in `_vgi_auth` remains the security boundary) so the
/// page shows the signed-in email/name regardless of whether the bearer is
/// an access or id token. Value is `base64url(JSON)` of the claims below.
/// Mirrors `_IDENTITY_COOKIE_NAME` in the Python `_oauth_pkce.py`.
pub const IDENTITY_COOKIE_NAME: &str = "_vgi_identity";

/// Display-identity claims surfaced in the `_vgi_identity` cookie.
const IDENTITY_CLAIMS: &[&str] = &["sub", "email", "preferred_username", "name", "picture"];

/// Best-effort decode of a JWT payload (no signature verification). Used only
/// to derive the display-identity cookie; the token itself was already
/// validated by the IdP token exchange.
fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// `base64url(JSON)` of the display-identity claims from an id_token, or
/// `None` when the token carries none. Mirrors `_identity_cookie_value` in
/// the Python reference.
fn identity_cookie_value(id_token: &str) -> Option<String> {
    use base64::Engine;
    let claims = decode_jwt_payload(id_token)?;
    let obj = claims.as_object()?;
    let mut ident = serde_json::Map::new();
    for key in IDENTITY_CLAIMS {
        if let Some(v) = obj.get(*key) {
            if !v.is_null() {
                ident.insert((*key).to_string(), v.clone());
            }
        }
    }
    if ident.is_empty() {
        return None;
    }
    let raw = serde_json::to_vec(&serde_json::Value::Object(ident)).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// Config for the OAuth/PKCE browser flow.
///
/// Field meanings mirror the OAuth 2.0 + OIDC RFC names. `signing_key`
/// MUST be the same across all workers serving the same callback path
/// (state cookies are HMAC-signed with it).
#[derive(Clone)]
pub struct OAuthPkceConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scope: String,
    pub signing_key: Vec<u8>,
    /// URL prefix the routes are mounted under (e.g. `/v1`). Default empty.
    pub prefix: String,
    /// Allowed return-to origins for the post-login redirect. Empty list
    /// means same-origin only (relative paths).
    pub allowed_return_origins: Vec<String>,
    /// Whether to set the `Secure` flag on the auth cookie. Should be
    /// `true` in production (HTTPS) and `false` for local dev.
    pub secure_cookie: bool,
}

impl OAuthPkceConfig {
    /// Build a router exposing the three OAuth routes. Compose with the
    /// main HTTP router via `Router::merge` or `Router::nest`.
    pub fn router(self) -> Router {
        use axum::routing::post;
        let state = Arc::new(self);
        let api = Router::new()
            .route("/_oauth/start", get(handle_start))
            .route("/_oauth/callback", get(handle_callback))
            .route("/_oauth/logout", get(handle_logout))
            .route("/_oauth/refresh", post(handle_refresh))
            .with_state(state.clone());
        if state.prefix.is_empty() {
            api
        } else {
            Router::new().nest(&state.prefix, api)
        }
    }
}

#[derive(Deserialize)]
struct StartParams {
    /// URL to redirect to after a successful login. Must match
    /// `allowed_return_origins` when absolute; relative paths always
    /// allowed.
    return_to: Option<String>,
}

async fn handle_start(
    State(cfg): State<Arc<OAuthPkceConfig>>,
    Query(params): Query<StartParams>,
) -> Response {
    let return_to = sanitize_return_to(params.return_to.as_deref(), &cfg.allowed_return_origins);
    // External-frontend mode: an absolute return_to to a different
    // origin signals the redirect-with-token flow (login from an SPA
    // that wants the JWT in a URL fragment, not a cookie).
    let is_external_frontend = is_absolute_url(&return_to);
    let pair = generate_pkce_pair();
    let pkce = new_state_cookie(&cfg.signing_key, &return_to, &pair);

    // Build the authorize URL. The `state` parameter is the opaque
    // random nonce only — **not** the cookie — so the `code_verifier`
    // inside the signed cookie never travels to the IdP. For external
    // frontends, request a refresh token (`access_type=offline&
    // prompt=consent`) so the SPA can rotate without bouncing the user
    // through the IdP again.
    let mut qs_pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", cfg.client_id.as_str()),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("code_challenge", pair.challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", pkce.state.as_str()),
        ("scope", cfg.scope.as_str()),
    ];
    if is_external_frontend {
        qs_pairs.push(("access_type", "offline"));
        qs_pairs.push(("prompt", "consent"));
    }
    let qs = encode_query(&qs_pairs);
    let authorize_url = format!("{}?{}", cfg.authorization_endpoint, qs);

    let cookie = build_cookie(
        PKCE_SESSION_COOKIE,
        &pkce.cookie,
        Some(PKCE_STATE_TTL.as_secs() as u32),
        &cfg.prefix,
        cfg.secure_cookie,
    );
    redirect_with_cookie(&authorize_url, cookie)
}

fn is_absolute_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn handle_callback(
    State(cfg): State<Arc<OAuthPkceConfig>>,
    Query(params): Query<CallbackParams>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Some(err) = params.error.as_deref() {
        let detail = params.error_description.unwrap_or_default();
        return error_page(&format!("Authorization failed: {err}"), &detail);
    }
    let Some(code) = params.code else {
        return error_page("Missing authorization code", "");
    };
    let Some(state_param) = params.state else {
        return error_page("Missing state parameter", "");
    };

    // Verify the session cookie, then check the state nonce it carries
    // matches the one the IdP echoed back. The cookie is signed +
    // freshness-checked; the verifier is read from it (never from the
    // query string).
    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let Some(cookie_value) = cookies.get(PKCE_SESSION_COOKIE) else {
        return error_page("Missing session cookie", "");
    };
    let (state_nonce, return_to, verifier) =
        match verify_state_cookie(&cfg.signing_key, cookie_value, PKCE_STATE_TTL) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(target: "vgi_rpc.oauth", error = %e, "PKCE session cookie rejected");
                return error_page(
                    "Invalid session",
                    "your login session is invalid or has expired",
                );
            }
        };
    if state_nonce != state_param {
        return error_page(
            "State mismatch",
            "your login session does not match the returned state",
        );
    }

    // Token-exchange POST to the IdP.
    let tokens = match exchange_code_for_token(&cfg, &code, &verifier).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(target: "vgi_rpc.oauth", error = %e, "OAuth token exchange failed");
            return error_page(
                "Token exchange failed",
                "could not complete login with the identity provider",
            );
        }
    };

    let clear_session = build_clear_cookie(PKCE_SESSION_COOKIE, &cfg.prefix, cfg.secure_cookie);
    let mut response_headers = axum::http::HeaderMap::new();
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session).unwrap(),
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );

    if is_absolute_url(&return_to) {
        // External-frontend redirect: pass the token in a URL fragment
        // so the SPA can pick it up via `window.location.hash` without
        // it appearing in server logs / Referer headers. Refresh token
        // is included when the IdP returned one.
        let mut frag_pairs: Vec<(&str, &str)> = Vec::with_capacity(3);
        frag_pairs.push(("token", tokens.id_or_access.as_str()));
        if let Some(rt) = tokens.refresh.as_deref() {
            frag_pairs.push(("refresh_token", rt));
        }
        if let Some(exp) = tokens.expires_in.as_deref() {
            frag_pairs.push(("expires_in", exp));
        }
        let frag = encode_query(&frag_pairs);
        let separator = if return_to.contains('#') { "&" } else { "#" };
        let location = format!("{return_to}{separator}{frag}");
        response_headers.insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
        return (StatusCode::FOUND, response_headers).into_response();
    }

    // Same-origin login: stash the token in a cookie and redirect.
    let auth_cookie = build_cookie(
        AUTH_COOKIE_NAME,
        &tokens.id_or_access,
        None, // session cookie; relies on JWT exp
        "",
        cfg.secure_cookie,
    );
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&auth_cookie).unwrap(),
    );
    // Display-identity cookie for the shared landing page (JS-readable). Set
    // from the id_token so the page shows email/name even when the bearer is
    // an access token that carries no profile claims.
    if let Some(identity) = identity_cookie_value(&tokens.id_or_access) {
        let identity_cookie =
            build_js_cookie(IDENTITY_COOKIE_NAME, &identity, None, "", cfg.secure_cookie);
        if let Ok(hv) = HeaderValue::from_str(&identity_cookie) {
            response_headers.append(header::SET_COOKIE, hv);
        }
    }
    let location = if return_to.is_empty() {
        "/".to_string()
    } else {
        return_to
    };
    response_headers.insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
    (StatusCode::FOUND, response_headers).into_response()
}

async fn handle_logout(State(cfg): State<Arc<OAuthPkceConfig>>) -> Response {
    let clear_auth = build_clear_cookie(AUTH_COOKIE_NAME, "", cfg.secure_cookie);
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_auth).unwrap(),
    );
    // Clear the JS-readable display-identity cookie too.
    let clear_identity = build_clear_cookie(IDENTITY_COOKIE_NAME, "", cfg.secure_cookie);
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_identity).unwrap(),
    );
    headers.insert(header::LOCATION, HeaderValue::from_static("/"));
    (StatusCode::FOUND, headers).into_response()
}

/// Tokens returned by the IdP token endpoint.
#[derive(Clone, Debug)]
struct TokenSet {
    /// Prefers `id_token` (OIDC); falls back to `access_token`.
    id_or_access: String,
    /// `refresh_token` if the IdP returned one (only when
    /// `access_type=offline` was requested).
    refresh: Option<String>,
    /// `expires_in` (seconds) as returned by the IdP, surfaced to
    /// external-frontend SPAs so they know when to call `/refresh`.
    expires_in: Option<String>,
}

async fn exchange_code_for_token(
    cfg: &OAuthPkceConfig,
    code: &str,
    verifier: &str,
) -> Result<TokenSet, RpcError> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = cfg.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let form_owned: Vec<(String, String)> = form
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    post_token_endpoint(&cfg.token_endpoint, form_owned).await
}

/// Refresh-grant exchange. Used by [`handle_refresh`].
async fn exchange_refresh_token(
    cfg: &OAuthPkceConfig,
    refresh_token: &str,
) -> Result<TokenSet, RpcError> {
    let mut form: Vec<(String, String)> = vec![
        ("grant_type".into(), "refresh_token".into()),
        ("refresh_token".into(), refresh_token.into()),
        ("client_id".into(), cfg.client_id.clone()),
    ];
    if let Some(secret) = cfg.client_secret.as_deref() {
        form.push(("client_secret".into(), secret.to_string()));
    }
    post_token_endpoint(&cfg.token_endpoint, form).await
}

async fn post_token_endpoint(
    endpoint: &str,
    form: Vec<(String, String)>,
) -> Result<TokenSet, RpcError> {
    let endpoint = endpoint.to_string();
    let resp = tokio::task::spawn_blocking(move || {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| RpcError::runtime_error(format!("token client: {e}")))?
            .post(&endpoint)
            .form(&form)
            .send()
            .map_err(|e| RpcError::runtime_error(format!("token POST: {e}")))?
            .error_for_status()
            .map_err(|e| RpcError::permission_error(format!("token POST: {e}")))?
            .json::<serde_json::Value>()
            .map_err(|e| RpcError::runtime_error(format!("token JSON: {e}")))
    })
    .await
    .map_err(|e| RpcError::runtime_error(format!("token join: {e}")))??;

    let id_or_access = resp
        .get("id_token")
        .and_then(|v| v.as_str())
        .or_else(|| resp.get("access_token").and_then(|v| v.as_str()))
        .ok_or_else(|| RpcError::runtime_error("token response missing id_token / access_token"))?
        .to_string();
    let refresh = resp
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let expires_in = resp.get("expires_in").map(|v| match v {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    });
    Ok(TokenSet {
        id_or_access,
        refresh,
        expires_in,
    })
}

#[derive(Deserialize)]
struct RefreshParams {
    refresh_token: Option<String>,
}

#[derive(serde::Serialize)]
struct RefreshResponse {
    token: String,
    refresh_token: Option<String>,
    expires_in: Option<String>,
}

/// `POST /_oauth/refresh` — accepts a refresh token (form-encoded or
/// JSON), exchanges it at the IdP, returns a JSON object with the
/// fresh `token` (id/access), optionally a rotated `refresh_token`,
/// and `expires_in`. Designed for SPAs holding the refresh token in
/// `sessionStorage` after the external-frontend login flow.
async fn handle_refresh(
    State(cfg): State<Arc<OAuthPkceConfig>>,
    Query(query): Query<RefreshParams>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let refresh_token = query.refresh_token.or_else(|| {
        // Fall back to the request body — JSON `{"refresh_token":"..."}` or
        // form-encoded.
        let ct = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.starts_with("application/json") {
            let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
            v.get("refresh_token")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        } else {
            let s = std::str::from_utf8(&body).ok()?;
            s.split('&')
                .find_map(|p| p.strip_prefix("refresh_token="))
                .map(|raw| {
                    urlencoding::decode(raw)
                        .map(|c| c.into_owned())
                        .unwrap_or_else(|_| raw.to_string())
                })
        }
    });
    let Some(rt) = refresh_token else {
        return error_page("Missing refresh_token", "");
    };
    let tokens = match exchange_refresh_token(&cfg, &rt).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(target: "vgi_rpc.oauth", error = %e, "OAuth refresh-token exchange failed");
            return error_page(
                "Refresh failed",
                "could not refresh the session with the identity provider",
            );
        }
    };
    let body = RefreshResponse {
        token: tokens.id_or_access,
        refresh_token: tokens.refresh,
        expires_in: tokens.expires_in,
    };
    let json = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    (StatusCode::OK, h, json).into_response()
}

/// Build an `Authenticate` callback that extracts the JWT from the
/// `_vgi_auth` cookie and delegates to a user-supplied JWT validator.
///
/// The validator gets the raw token string and returns an
/// [`AuthContext`] (or `Err` to reject). Combine with the `jwt`
/// helpers in [`crate::auth::jwt`] for full JWT verification.
pub fn cookie_authenticate<F>(validator: F) -> Authenticate
where
    F: Fn(&str) -> AuthResult + Send + Sync + 'static,
{
    Arc::new(move |req: &AuthRequest<'_>| -> AuthResult {
        let Some(raw) = req.header("cookie") else {
            return Ok(AuthContext::anonymous());
        };
        let cookies = parse_cookies(Some(raw));
        let Some(token) = cookies.get(AUTH_COOKIE_NAME) else {
            return Ok(AuthContext::anonymous());
        };
        validator(token)
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_cookies(raw: Option<&str>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(raw) = raw else { return out };
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

fn build_cookie(name: &str, value: &str, max_age: Option<u32>, path: &str, secure: bool) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let mut s = format!("{name}={value}; Path={path}; HttpOnly; SameSite=Lax");
    if secure {
        s.push_str("; Secure");
    }
    if let Some(age) = max_age {
        s.push_str(&format!("; Max-Age={age}"));
    }
    s
}

/// Like [`build_cookie`] but JS-readable (no `HttpOnly`) — for the display
/// identity cookie the shared landing page reads via `document.cookie`.
fn build_js_cookie(
    name: &str,
    value: &str,
    max_age: Option<u32>,
    path: &str,
    secure: bool,
) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let mut s = format!("{name}={value}; Path={path}; SameSite=Lax");
    if secure {
        s.push_str("; Secure");
    }
    if let Some(age) = max_age {
        s.push_str(&format!("; Max-Age={age}"));
    }
    s
}

fn build_clear_cookie(name: &str, path: &str, secure: bool) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let mut s = format!(
        "{name}=; Path={path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    if secure {
        s.push_str("; Secure");
    }
    s
}

fn redirect_with_cookie(location: &str, cookie: String) -> Response {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::LOCATION, HeaderValue::from_str(location).unwrap());
    headers.append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    (StatusCode::FOUND, headers).into_response()
}

fn encode_query(params: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&urlencoding::encode(k));
        out.push('=');
        out.push_str(&urlencoding::encode(v));
    }
    out
}

fn sanitize_return_to(raw: Option<&str>, allowed: &[String]) -> String {
    let Some(raw) = raw else { return String::new() };
    if raw.starts_with('/') && !raw.starts_with("//") {
        return raw.to_string();
    }
    let allowed_refs: Vec<&str> = allowed.iter().map(String::as_str).collect();
    if is_allowed_return_origin(raw, &allowed_refs) {
        raw.to_string()
    } else {
        String::new()
    }
}

fn error_page(title: &str, detail: &str) -> Response {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>OAuth error</title></head>\
         <body><h1>{}</h1><p>{}</p></body></html>",
        html_escape(title),
        html_escape(detail)
    );
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    (StatusCode::BAD_REQUEST, headers, body).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OAuthPkceConfig {
        OAuthPkceConfig {
            authorization_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            client_id: "client-abc".into(),
            client_secret: None,
            redirect_uri: "https://app.example/_oauth/callback".into(),
            scope: "openid email".into(),
            signing_key: vec![7u8; 32],
            prefix: String::new(),
            allowed_return_origins: vec!["https://app.example".into()],
            secure_cookie: false,
        }
    }

    #[test]
    fn sanitize_return_to_accepts_relative() {
        assert_eq!(sanitize_return_to(Some("/dashboard"), &[]), "/dashboard");
    }

    #[test]
    fn sanitize_return_to_rejects_protocol_relative() {
        assert_eq!(sanitize_return_to(Some("//evil.example/x"), &[]), "");
    }

    #[test]
    fn sanitize_return_to_allows_listed_origin() {
        let allow = vec!["https://app.example".to_string()];
        assert_eq!(
            sanitize_return_to(Some("https://app.example/welcome"), &allow),
            "https://app.example/welcome"
        );
    }

    #[test]
    fn sanitize_return_to_rejects_unlisted_origin() {
        let allow = vec!["https://app.example".to_string()];
        assert_eq!(
            sanitize_return_to(Some("https://evil.example/x"), &allow),
            ""
        );
    }

    #[test]
    fn identity_cookie_encodes_display_claims_from_jwt() {
        use base64::Engine;
        // A JWT payload carrying display claims plus an ignored one (`exp`).
        let payload = serde_json::json!({
            "sub": "user-123",
            "email": "alice@example.com",
            "name": "Alice",
            "exp": 9999999999u64,
        });
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("header.{b64}.sig");

        let cookie = identity_cookie_value(&token).expect("identity cookie");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&cookie)
            .expect("base64url");
        let claims: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(claims["sub"], "user-123");
        assert_eq!(claims["email"], "alice@example.com");
        assert_eq!(claims["name"], "Alice");
        // Non-display claims are not surfaced.
        assert!(claims.get("exp").is_none());
    }

    #[test]
    fn identity_cookie_none_when_no_display_claims() {
        use base64::Engine;
        let payload = serde_json::json!({ "exp": 123, "aud": "x" });
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        assert!(identity_cookie_value(&format!("h.{b64}.s")).is_none());
        // A non-JWT string yields nothing rather than panicking.
        assert!(identity_cookie_value("not-a-jwt").is_none());
    }

    #[test]
    fn js_cookie_is_not_http_only() {
        let s = build_js_cookie(IDENTITY_COOKIE_NAME, "v", None, "", false);
        assert!(
            !s.contains("HttpOnly"),
            "identity cookie must be JS-readable"
        );
        assert!(s.contains("_vgi_identity=v"));
    }

    #[test]
    fn cookie_carries_secure_only_when_requested() {
        let s = build_cookie("k", "v", Some(60), "/x", false);
        assert!(!s.contains("Secure"));
        let s = build_cookie("k", "v", Some(60), "/x", true);
        assert!(s.contains("Secure"));
    }

    #[test]
    fn cookie_authenticate_extracts_token_from_cookie_header() {
        let validator = |tok: &str| -> AuthResult {
            assert_eq!(tok, "abc.def.ghi");
            Ok(AuthContext::for_principal("oauth", "alice"))
        };
        let cb = cookie_authenticate(validator);
        let headers = vec![(
            "cookie".to_string(),
            "_vgi_auth=abc.def.ghi; foo=bar".into(),
        )];
        let req = AuthRequest {
            method: "x",
            headers: &headers,
            peer_addr: None,
        };
        let ctx = cb(&req).unwrap();
        assert!(ctx.authenticated);
        assert_eq!(ctx.principal, "alice");
    }

    #[test]
    fn cookie_authenticate_anonymous_without_cookie() {
        let cb = cookie_authenticate(|_| Ok(AuthContext::for_principal("oauth", "x")));
        let req = AuthRequest::anonymous_pipe("x");
        assert!(!cb(&req).unwrap().authenticated);
    }

    #[tokio::test]
    async fn start_redirects_to_authorize_url_with_state_cookie() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let app = cfg().router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/_oauth/start?return_to=/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://idp.example/authorize?"));
        assert!(location.contains("response_type=code"));
        assert!(location.contains("code_challenge_method=S256"));
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.starts_with("_vgi_pkce="));
    }

    #[tokio::test]
    async fn start_with_external_return_to_requests_refresh_token() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let app = cfg().router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/_oauth/start?return_to=https%3A%2F%2Fapp.example%2Fdash")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.contains("access_type=offline"),
            "absolute return_to must request a refresh token: {location}"
        );
        assert!(location.contains("prompt=consent"));
    }

    #[tokio::test]
    async fn start_with_relative_return_to_does_not_request_refresh_token() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let app = cfg().router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/_oauth/start?return_to=/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            !location.contains("access_type=offline"),
            "same-origin login should not request offline access"
        );
    }

    #[tokio::test]
    async fn refresh_endpoint_rejects_missing_token() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let app = cfg().router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/_oauth/refresh")
                    .method("POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn callback_rejects_state_mismatch() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let app = cfg().router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/_oauth/callback?code=foo&state=mismatched")
                    .header(header::COOKIE, "_vgi_pkce=different-cookie")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
