//! Module: session identifiers
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId {
    pub user_id: Option<String>,
    pub domain: String,
}

impl SessionId {
    pub fn new(user_id: Option<&str>, domain: &str) -> Self {
        Self {
            user_id: user_id.map(|s| s.to_string()),
            domain: domain.to_string(),
        }
    }

    pub fn to_redis_key(&self) -> String {
        let uid = self.user_id.as_deref().unwrap_or("anon");
        format!("map:session:{}:{}", uid, self.domain)
    }

    #[allow(dead_code)] // Planned for mTLS header-based user extraction
    pub fn from_headers(user_id: Option<&str>, host: &str) -> Self {
        Self::new(user_id, host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_with_user() {
        let sid = SessionId::new(Some("user123"), "api.deepseek.com");
        assert_eq!(sid.user_id, Some("user123".to_string()));
        assert_eq!(sid.domain, "api.deepseek.com");
        assert!(sid.to_redis_key().contains("user123"));
        assert!(sid.to_redis_key().contains("api.deepseek.com"));
    }

    #[test]
    fn test_session_id_without_user() {
        let sid = SessionId::new(None, "api.openai.com");
        assert_eq!(sid.user_id, None);
        assert!(sid.to_redis_key().contains("anon"));
    }

    #[test]
    fn test_redis_key_format() {
        let sid = SessionId::new(Some("user456"), "api.qwen.ai");
        assert_eq!(sid.to_redis_key(), "map:session:user456:api.qwen.ai");
    }

    #[test]
    fn test_redis_key_different_users() {
        let a = SessionId::new(Some("alice"), "api.deepseek.com");
        let b = SessionId::new(Some("bob"), "api.deepseek.com");
        assert_ne!(a.to_redis_key(), b.to_redis_key());
    }

    #[test]
    fn test_redis_key_different_domains() {
        let a = SessionId::new(Some("alice"), "api.deepseek.com");
        let b = SessionId::new(Some("alice"), "api.openai.com");
        assert_ne!(a.to_redis_key(), b.to_redis_key());
    }

    #[test]
    fn test_from_request_context() {
        let sid = SessionId::from_headers(Some("user99"), "api.deepseek.com");
        assert_eq!(sid.user_id, Some("user99".to_string()));
        assert_eq!(sid.domain, "api.deepseek.com");
    }
}
