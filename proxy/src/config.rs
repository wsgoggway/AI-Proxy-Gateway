use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub targets: Vec<TargetConfig>,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    #[serde(default)]
    pub redis: Option<RedisConfig>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub semantic: Option<SemanticConfig>,
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Absolute path to the config file (set at load time, not from TOML)
    #[serde(skip)]
    pub config_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    pub client_id: String,
    pub issuer_url: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// Directory for CA certificate storage. Default: 'certs/' relative to config.
    #[serde(default)]
    pub ca_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
}

const fn default_port() -> u16 {
    443
}

const fn default_true() -> bool {
    true
}

fn default_mode() -> String {
    "reverse".to_string()
}

// ─── Auth configuration ────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_auth_backend")]
    pub backend: String, // "file" | "keycloak"
    /// Basic auth realm string (shown in 407 header).
    #[serde(default = "default_auth_realm")]
    pub realm: String,
    #[serde(default)]
    pub require_auth: Option<bool>,
    /// When false, CONNECT without Proxy-Authorization is allowed (anonymous).
    /// Default: true (auth required when backend is configured).
    #[serde(default)]
    pub file: Option<FileAuthConfig>,
    #[serde(default)]
    pub db: Option<DbAuthConfig>,
    #[serde(default)]
    pub jwt: Option<JwtConfig>,
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    #[serde(default)]
    pub keycloak: Option<KeycloakAuthConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Brute-force protection for CONNECT auth.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rl_fails_user")]
    pub fails_per_user: u32,
    #[serde(default = "default_rl_window_user")]
    pub window_secs: u64,
    #[serde(default = "default_rl_fails_ip")]
    pub fails_per_ip: u32,
    #[serde(default = "default_rl_window_ip")]
    pub window_secs_ip: u64,
}

fn default_rl_fails_user() -> u32 {
    5
}
fn default_rl_window_user() -> u64 {
    30
}
fn default_rl_fails_ip() -> u32 {
    20
}
fn default_rl_window_ip() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize)]
pub struct DbAuthConfig {
    pub url: String,
    #[serde(default = "default_db_max_conn")]
    pub max_connections: u32,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_db_max_conn() -> u32 {
    4
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    #[serde(default = "default_jwt_ttl")]
    pub token_ttl_days: i64,
}

fn default_jwt_ttl() -> i64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AdminConfig {
    pub bind: String,
    #[serde(default)]
    pub token: Option<String>,
}

#[allow(dead_code)]
fn default_admin_bind() -> String {
    "127.0.0.1:8444".into()
}

fn default_auth_backend() -> String {
    "file".into()
}
fn default_auth_realm() -> String {
    "AI Proxy".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileAuthConfig {
    #[serde(default)]
    pub users: Vec<FileUser>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileUser {
    pub username: String,
    /// sha256:salt:hash of the password.
    /// Generate with: apx hash-password user password
    pub pw: String,
    /// Display name for the user (defaults to username).
    #[serde(default)]
    pub display: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct KeycloakAuthConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    #[serde(default = "default_jwks_ttl")]
    pub jwks_ttl: u64,
}

fn default_cache_ttl() -> u64 {
    300
}
fn default_jwks_ttl() -> u64 {
    3600
}

// ─── Semantic validation configuration ─────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SemanticConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_semantic_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_semantic_model")]
    pub model: String,
    #[serde(default = "default_semantic_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_semantic_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_semantic_cache")]
    pub cache_size: usize,
    #[serde(default = "default_semantic_cb_failures")]
    pub circuit_breaker_failures: u32,
    #[serde(default = "default_semantic_cb_cooldown")]
    pub circuit_breaker_cooldown_sec: u64,
}

fn default_semantic_endpoint() -> String {
    "http://localhost:11434".into()
}
fn default_semantic_model() -> String {
    "qwen2.5:0.5b".into()
}
const fn default_semantic_timeout() -> u64 {
    3000
}
const fn default_semantic_concurrency() -> usize {
    2
}
const fn default_semantic_cache() -> usize {
    1000
}
const fn default_semantic_cb_failures() -> u32 {
    5
}
const fn default_semantic_cb_cooldown() -> u64 {
    300
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;
        // Resolve config_dir to the directory containing the config file
        config.config_dir = Path::new(path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(config)
    }

    /// Absolute path to the CA certificate directory.
    /// Resolves 'ca_dir' from config relative to config file location.
    pub fn ca_absolute_dir(&self) -> PathBuf {
        let rel = self.server.ca_dir.as_deref().unwrap_or(Path::new("certs"));
        if rel.is_absolute() {
            rel.to_path_buf()
        } else {
            self.config_dir.join(rel)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse() {
        let toml_str = r#"
[server]
host = "127.0.0.1"
port = 8443
cert_path = "certs/server.pem"
key_path = "certs/server.key"

[[targets]]
host = "api.deepseek.com"

[[targets]]
host = "api.openai.com"
port = 8443
"#;
        let mut config: Config = toml::from_str(toml_str).expect("parse config");
        config.config_dir = PathBuf::from(".");
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8443);
        assert_eq!(
            config.server.cert_path,
            Some(PathBuf::from("certs/server.pem"))
        );
        assert!(config.server.ca_cert_path.is_none());
        assert_eq!(config.targets.len(), 2);
        assert_eq!(config.targets[0].host, "api.deepseek.com");
        assert_eq!(config.targets[0].port, 443);
        assert!(config.targets[0].tls); // default tls
        assert_eq!(config.targets[1].port, 8443);
    }

    #[test]
    fn test_config_missing_targets() {
        let toml_str = r#"
[server]
host = "0.0.0.0"
port = 8443
cert_path = "certs/server.pem"
key_path = "certs/server.key"
"#;
        let config: Config = toml::from_str(toml_str).expect("parse config");
        assert!(config.targets.is_empty());
    }

    #[test]
    fn test_config_parse_error() {
        let result: Result<Config, _> = toml::from_str("invalid = [");
        assert!(result.is_err());
    }
}
