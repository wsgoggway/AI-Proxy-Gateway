use crate::forward;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Planned for full OIDC integration (Sprint 1.4)
pub struct OidcClaims {
    pub sub: String,
    pub exp: usize,
    pub iss: String,
    pub aud: String,
    pub preferred_username: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub client_id: String,
    pub issuer_url: String,
    pub redirect_uri: String,
}

impl OidcConfig {
    pub fn auth_url(&self, state: &str) -> Result<String, String> {
        let mut url = Url::parse(&format!("{}/protocol/openid-connect/auth", self.issuer_url))
            .map_err(|e| format!("invalid issuer URL: {e}"))?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile email")
            .append_pair("state", state);
        Ok(url.to_string())
    }

    #[allow(dead_code)] // Planned for full OIDC token exchange
    pub fn token_url(&self) -> String {
        format!("{}/protocol/openid-connect/token", self.issuer_url)
    }
}

// validate_id_token removed — was dead code with hardcoded "insecure-mvp-key".
// Full OIDC integration requires proper JWKS key discovery (Sprint 1.4).

pub fn build_redirect_response(auth_url: &str) -> forward::ProxyResponse {
    hyper::Response::builder()
        .status(307)
        .header("Location", auth_url)
        .body(forward::str_body(
            "Redirecting to authentication...".to_string(),
        ))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_url() {
        let config = OidcConfig {
            client_id: "ai-proxy".into(),
            issuer_url: "https://keycloak.local/realms/corp".into(),
            redirect_uri: "https://proxy.local/callback".into(),
        };
        let url = config.auth_url("state123").unwrap();
        assert!(url.contains("client_id=ai-proxy"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fproxy.local%2Fcallback"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("scope=openid+profile+email"));
    }

    #[test]
    fn test_build_redirect_response() {
        let resp = build_redirect_response("https://keycloak/auth");
        assert_eq!(resp.status(), 307);
        assert_eq!(
            resp.headers().get("Location").unwrap(),
            "https://keycloak/auth"
        );
    }
}
