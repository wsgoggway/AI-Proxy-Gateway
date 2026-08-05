use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

pub struct RevocationChecker {
    redis_conn: Option<MultiplexedConnection>,
    cache: Arc<Mutex<lru::LruCache<String, (Instant, bool)>>>,
    cache_ttl: Duration,
}

impl RevocationChecker {
    pub fn new(_redis_url: Option<&str>) -> Self {
        let redis_conn = None; // Will be set later via connect()
        let cache = lru::LruCache::new(std::num::NonZeroUsize::new(10_000).unwrap());

        Self {
            redis_conn,
            cache: Arc::new(Mutex::new(cache)),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    pub async fn connect(&mut self, redis_url: &str) -> Result<(), String> {
        let client = redis::Client::open(redis_url).map_err(|e| format!("Redis: {}", e))?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connect: {}", e))?;
        self.redis_conn = Some(conn);
        Ok(())
    }

    /// Check if a user is revoked. Fail-closed: Redis errors → assume revoked.
    pub async fn is_revoked(&self, user_id: &str) -> bool {
        // Check cache first
        {
            let mut cache = self.cache.lock().await;
            if let Some((ts, revoked)) = cache.get(user_id)
                && ts.elapsed() < self.cache_ttl
            {
                return *revoked;
            }
        }

        // Check Redis
        let revoked = match &self.redis_conn {
            Some(conn) => match self.check_redis(conn, user_id).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        "revocation_check_redis_error user={user_id} error={e} — assuming revoked (fail-closed)"
                    );
                    true
                }
            },
            None => {
                debug!("revocation_no_redis user={user_id} — assuming not revoked (no backend)");
                false
            }
        };

        // Update cache
        {
            let mut cache = self.cache.lock().await;
            cache.put(user_id.to_string(), (Instant::now(), revoked));
        }

        revoked
    }

    async fn check_redis(
        &self,
        conn: &MultiplexedConnection,
        user_id: &str,
    ) -> Result<bool, String> {
        let mut conn = conn.clone();
        let key = format!("revoked:{}", user_id);
        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| format!("Redis EXISTS: {}", e))?;
        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_revocation_checker_no_redis() {
        let checker = RevocationChecker::new(None);
        assert!(!checker.is_revoked("test_user").await);
    }

    #[tokio::test]
    async fn test_cache_behavior() {
        let checker = RevocationChecker::new(None);
        assert!(!checker.is_revoked("user1").await);
        assert!(!checker.is_revoked("user1").await);
    }
}
