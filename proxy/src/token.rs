//! JWT token issue/verify for session auth (30-day expiry).
//! Token contains: sub (user_id), role, display, exp.

use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,     // user_id (uuid string)
    pub role: String,    // "admin" | "user"
    pub display: String, // display name
    pub exp: usize,      // expiry timestamp (seconds)
}

pub struct TokenManager {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl_days: i64,
}

impl TokenManager {
    pub fn new(secret: &str, ttl_days: i64) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            ttl_days,
        }
    }

    pub fn issue(&self, user_id: &str, role: &str, display: &str) -> anyhow::Result<String> {
        let exp = (Utc::now() + Duration::days(self.ttl_days)).timestamp() as usize;
        let claims = Claims {
            sub: user_id.to_string(),
            role: role.to_string(),
            display: display.to_string(),
            exp,
        };
        Ok(encode(&Header::default(), &claims, &self.encoding)?)
    }

    pub fn verify(&self, token: &str) -> anyhow::Result<Claims> {
        let data = decode::<Claims>(token, &self.decoding, &Validation::default())?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_and_verify() {
        let tm = TokenManager::new("test-secret-key", 30);
        let token = tm.issue("user-uuid-123", "admin", "Alice").unwrap();
        let claims = tm.verify(&token).unwrap();
        assert_eq!(claims.sub, "user-uuid-123");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.display, "Alice");
    }

    #[test]
    fn test_verify_wrong_secret() {
        let tm1 = TokenManager::new("secret-a", 30);
        let tm2 = TokenManager::new("secret-b", 30);
        let token = tm1.issue("u1", "user", "Bob").unwrap();
        assert!(tm2.verify(&token).is_err());
    }

    #[test]
    fn test_verify_expired() {
        let tm = TokenManager::new("secret", -1); // already expired
        let token = tm.issue("u1", "user", "Bob").unwrap();
        assert!(tm.verify(&token).is_err());
    }

    #[test]
    fn test_verify_garbage() {
        let tm = TokenManager::new("secret", 30);
        assert!(tm.verify("not.a.jwt").is_err());
        assert!(tm.verify("").is_err());
    }
}
