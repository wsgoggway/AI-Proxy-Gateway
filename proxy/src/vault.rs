//! Module: Redis-backed reversible vault
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use tracing::{info, warn};

use crate::session::SessionId;

const SESSION_TTL: i64 = 2_592_000; // 30 days — tokens must persist as long as AI context references them

#[derive(Clone)]
pub struct Vault {
    conn: Option<MultiplexedConnection>,
}

impl Vault {
    pub fn new_disconnected() -> Self {
        Self { conn: None }
    }

    pub async fn connect(redis_url: &str) -> Result<Self, String> {
        let client = redis::Client::open(redis_url).map_err(|e| format!("Redis: {}", e))?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connect: {}", e))?;
        info!("vault_connected");
        Ok(Self { conn: Some(conn) })
    }

    pub async fn store(&self, session: &SessionId, token: &str, value: &str) -> Result<(), String> {
        let conn = self
            .conn
            .as_ref()
            .ok_or("Redis Vault: not connected".to_string())?;
        let mut conn = conn.clone();

        // Global key: always resolvable regardless of session/domain changes.
        let _: bool = conn
            .hset("map:tokens", token, value)
            .await
            .map_err(|e| format!("Vault HSET global: {}", e))?;
        let _: () = conn
            .expire("map:tokens", SESSION_TTL)
            .await
            .map_err(|e| format!("Vault EXPIRE global: {}", e))?;


        // Session-scoped key: for backwards compatibility with older binaries.
        let skey = session.to_redis_key();
        let _: bool = conn
            .hset(&skey, token, value)
            .await
            .map_err(|e| format!("Vault HSET session: {}", e))?;
        let _: () = conn
            .expire(&skey, SESSION_TTL)
            .await
            .map_err(|e| format!("Vault EXPIRE session: {}", e))?;

        Ok(())
    }

    pub async fn get(&self, session: &SessionId, token: &str) -> Result<Option<String>, String> {
        let conn = self
            .conn
            .as_ref()
            .ok_or("Redis Vault: not connected".to_string())?;
        let mut conn = conn.clone();

        // Try global key first (covers cross-session, cross-domain lookups).
        let value: Option<String> = conn
            .hget("map:tokens", token)
            .await
            .map_err(|e| format!("Vault HGET global: {}", e))?;

        if value.is_some() {
            // Refresh TTL on access.
            let _: () = conn
                .expire("map:tokens", SESSION_TTL)
                .await
                .map_err(|e| warn!("vault_expire_error error={}", e))
                .unwrap_or(());
            return Ok(value);
        }

        // Fallback: session-scoped key (for tokens stored by older binaries).
        let skey = session.to_redis_key();
        let value: Option<String> = conn
            .hget(&skey, token)
            .await
            .map_err(|e| format!("Vault HGET session: {}", e))?;

        if value.is_some() {
            let _: () = conn
                .expire(&skey, SESSION_TTL)
                .await
                .map_err(|e| warn!("vault_expire_error error={}", e))
                .unwrap_or(());
        }

        Ok(value)
    }


    pub fn is_connected(&self) -> bool {
        self.conn.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vault_new_disconnected() {
        let vault = Vault::new_disconnected();
        assert!(!vault.is_connected());
    }

    #[tokio::test]
    async fn test_vault_store_disconnected() {
        let vault = Vault::new_disconnected();
        let session = SessionId::new(Some("u"), "d");
        let result = vault.store(&session, "[KEY_abc]", "secret").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not connected"));
    }

    #[tokio::test]
    async fn test_vault_get_disconnected() {
        let vault = Vault::new_disconnected();
        let session = SessionId::new(Some("u"), "d");
        let result = vault.get(&session, "[KEY_abc]").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fail_closed_roundtrip() {
        let vault = Vault::new_disconnected();
        let session = SessionId::new(Some("user1"), "api.deepseek.com");

        // Store → Err
        let store_result = vault.store(&session, "[KEY_xyz]", "sk-secret").await;
        assert!(store_result.is_err(), "Store must fail when disconnected");

        // Get → Err
        let get_result = vault.get(&session, "[KEY_xyz]").await;
        assert!(get_result.is_err(), "Get must fail when disconnected");

        // is_connected → false
        assert!(!vault.is_connected(), "Must report disconnected");
    }
}
