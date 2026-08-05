//! RBAC: role-based access control (Casbin-compatible model).
//! 2 roles: admin (full access), user (self-service only).

use crate::user_store::UserStore;
use std::collections::HashMap;
use std::sync::Mutex;

/// Static policies: (role, path_pattern, method | "*")
fn policies() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("admin", "/api/users", "*"),
        ("admin", "/api/users/*", "*"),
        ("admin", "/api/metrics", "*"),
        ("admin", "/api/metrics/*", "*"),
        ("admin", "/api/roles/*", "*"),
        ("admin", "/api/quota/self", "GET"),
        ("user", "/api/quota/self", "GET"),
        ("user", "/api/metrics/self", "GET"),
    ]
}

pub struct Rbac {
    roles: Mutex<HashMap<String, String>>,
}

impl Rbac {
    pub fn new() -> Self {
        Self {
            roles: Mutex::new(HashMap::new()),
        }
    }

    pub fn assign_role(&self, user_id: &str, role: &str) {
        self.roles
            .lock()
            .unwrap()
            .insert(user_id.to_string(), role.to_string());
    }

    pub fn set_role(&self, user_id: &str, role: &str) {
        if role.is_empty() {
            self.roles.lock().unwrap().remove(user_id);
        } else {
            self.assign_role(user_id, role);
        }
    }

    pub fn get_role(&self, user_id: &str) -> String {
        self.roles
            .lock()
            .unwrap()
            .get(user_id)
            .cloned()
            .unwrap_or_else(|| "user".into())
    }

    fn key_match(pattern: &str, path: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix("/*") {
            return path == prefix || path.starts_with(&format!("{prefix}/"));
        }
        pattern == path
    }

    pub fn enforce(&self, user_id: &str, path: &str, method: &str) -> bool {
        let role = self.get_role(user_id);
        for (p_role, p_pattern, p_method) in policies() {
            if p_role == role.as_str()
                && Self::key_match(p_pattern, path)
                && (p_method == "*" || p_method == method)
            {
                return true;
            }
        }
        false
    }

    pub async fn reload_from_db(&self, store: &UserStore) -> Result<(), anyhow::Error> {
        let users = store.list_users().await?;
        let mut roles = self.roles.lock().unwrap();
        roles.clear();
        for u in users {
            roles.insert(u.id.to_string(), u.role);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_match_exact() {
        assert!(Rbac::key_match("/api/users", "/api/users"));
        assert!(!Rbac::key_match("/api/users", "/api/metrics"));
    }

    #[test]
    fn test_key_match_wildcard() {
        assert!(Rbac::key_match("/api/users/*", "/api/users/123"));
        assert!(Rbac::key_match("/api/users/*", "/api/users"));
        assert!(!Rbac::key_match("/api/users/*", "/api/usersX"));
    }

    #[test]
    fn test_enforce_admin() {
        let r = Rbac::new();
        r.assign_role("u1", "admin");
        assert!(r.enforce("u1", "/api/users", "GET"));
        assert!(r.enforce("u1", "/api/users/123/quota", "PUT"));
        assert!(r.enforce("u1", "/api/metrics/system", "GET"));
    }

    #[test]
    fn test_enforce_user() {
        let r = Rbac::new();
        r.assign_role("u2", "user");
        // user can see own quota
        assert!(r.enforce("u2", "/api/quota/self", "GET"));
        assert!(r.enforce("u2", "/api/metrics/self", "GET"));
        // user CANNOT manage users
        assert!(!r.enforce("u2", "/api/users", "GET"));
        assert!(!r.enforce("u2", "/api/users/123/disable", "POST"));
        assert!(!r.enforce("u2", "/api/metrics/system", "GET"));
    }

    #[test]
    fn test_enforce_unknown_user_defaults_to_user_role() {
        let r = Rbac::new();
        assert!(!r.enforce("nobody", "/api/users", "GET"));
        assert!(r.enforce("nobody", "/api/quota/self", "GET"));
    }

    #[test]
    fn test_set_role_overrides() {
        let r = Rbac::new();
        r.set_role("u3", "admin");
        assert!(r.enforce("u3", "/api/users", "GET"));
        r.set_role("u3", "user");
        assert!(!r.enforce("u3", "/api/users", "GET"));
    }

    #[test]
    fn test_method_restriction() {
        let r = Rbac::new();
        r.assign_role("u4", "user");
        // /api/quota/self is GET-only
        assert!(r.enforce("u4", "/api/quota/self", "GET"));
        assert!(!r.enforce("u4", "/api/quota/self", "POST"));
    }
}
