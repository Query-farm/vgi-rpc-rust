//! OAuth 2.0 Protected Resource Metadata (RFC 9728).
//!
//! Servers advertise their resource identifier, supported authorization
//! servers, scopes, and bearer methods at a well-known URL.
//! [`OAuthResourceMetadata::well_known_path`] returns the canonical
//! `/.well-known/oauth-protected-resource` path used by the HTTP wiring.

use serde::Serialize;

/// RFC 9728 metadata document.
///
/// Fields match the RFC-defined names; see
/// <https://datatracker.ietf.org/doc/html/rfc9728#section-2>.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OAuthResourceMetadata {
    /// Canonical resource URL (required). Must be absolute.
    pub resource: String,
    /// Authorization server issuer URLs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    /// Human-readable resource name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    /// Scopes this resource accepts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// Supported bearer methods ("header", "body", "query").
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bearer_methods_supported: Vec<String>,
    /// URL to documentation for the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
    /// Optional client ID used by browser PKCE login (non-RFC, used by
    /// the [`crate::auth::pkce`] flow when enabled).
    #[serde(skip_serializing)]
    pub client_id: String,
    /// When `true`, the PKCE flow uses the OIDC `id_token` as the
    /// bearer token (for audience-scoped APIs). Defaults to access_token.
    #[serde(skip_serializing)]
    pub use_id_token_as_bearer: bool,
    /// Optional client secret for confidential PKCE clients.
    #[serde(skip_serializing)]
    pub client_secret: String,
}

impl OAuthResourceMetadata {
    /// Create new metadata with only the required `resource` set.
    pub fn new(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            ..Default::default()
        }
    }

    pub fn with_authorization_server(mut self, url: impl Into<String>) -> Self {
        self.authorization_servers.push(url.into());
        self
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes_supported.push(scope.into());
        self
    }

    pub fn with_bearer_methods(mut self, methods: impl IntoIterator<Item = String>) -> Self {
        self.bearer_methods_supported.extend(methods);
        self
    }

    pub fn with_resource_name(mut self, name: impl Into<String>) -> Self {
        self.resource_name = Some(name.into());
        self
    }

    pub fn with_client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = id.into();
        self
    }

    /// RFC 9728 section 3: the well-known URL path where the metadata is served.
    pub fn well_known_path() -> &'static str {
        "/.well-known/oauth-protected-resource"
    }

    /// JSON representation of the metadata document.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    /// Build a `WWW-Authenticate` header value for 401 responses.
    ///
    /// Example output:
    /// `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`.
    pub fn www_authenticate(&self) -> String {
        // The metadata URL is derived from the resource; we append the
        // well-known path so the client can fetch it.
        let mut v = String::from("Bearer");
        if !self.resource.is_empty() {
            let url = metadata_url_from_resource(&self.resource);
            v.push_str(&format!(" resource_metadata=\"{url}\""));
        }
        if !self.scopes_supported.is_empty() {
            v.push_str(&format!(" scope=\"{}\"", self.scopes_supported.join(" ")));
        }
        v
    }

    /// Basic validation: `resource` must be absolute and use http(s).
    pub fn validate(&self) -> Result<(), String> {
        if self.resource.is_empty() {
            return Err("resource must be set".into());
        }
        if !(self.resource.starts_with("http://") || self.resource.starts_with("https://")) {
            return Err("resource must be absolute http(s) URL".into());
        }
        Ok(())
    }
}

fn metadata_url_from_resource(resource: &str) -> String {
    let trimmed = resource.trim_end_matches('/');
    format!("{trimmed}{}", OAuthResourceMetadata::well_known_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_keeps_known_fields() {
        let m = OAuthResourceMetadata::new("https://api.example.com")
            .with_authorization_server("https://issuer.example/")
            .with_scope("rpc");
        let j = m.to_json();
        assert!(j.contains("\"resource\":\"https://api.example.com\""));
        assert!(j.contains("\"authorization_servers\":[\"https://issuer.example/\"]"));
        assert!(j.contains("\"scopes_supported\":[\"rpc\"]"));
    }

    #[test]
    fn www_authenticate_includes_metadata_url() {
        let m = OAuthResourceMetadata::new("https://api.example.com/v1/");
        let v = m.www_authenticate();
        assert!(v.contains(
            "resource_metadata=\"https://api.example.com/v1/.well-known/oauth-protected-resource\""
        ));
    }

    #[test]
    fn validate_rejects_relative_url() {
        let m = OAuthResourceMetadata::new("not-a-url");
        assert!(m.validate().is_err());
    }
}
