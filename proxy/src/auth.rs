//! Proxy auth: file backend or PostgreSQL user store (PBKDF2), rate limiting.
//! Cred cache: LRU + TTL (60s default for db backend — admin changes propagate fast).

use crate::config::{AuthConfig, FileUser, KeycloakAuthConfig};
use crate::user_store::{self, UserRow, UserStore};
use base64::Engine as _;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Uid {
    pub id: String,
    pub disp: String,
}

impl Uid {
    pub fn new(id: impl Into<String>, disp: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            disp: disp.into(),
        }
    }
    pub fn label(&self) -> String {
        self.disp.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthErr {
    InvalidCreds,
    QuotaExceeded(String),
    RateLimited,
    Internal,
}

impl std::fmt::Display for AuthErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthErr::InvalidCreds => write!(f, "invalid credentials"),
            AuthErr::QuotaExceeded(lim) => write!(f, "quota exceeded: {lim}"),
            AuthErr::RateLimited => write!(f, "rate limited"),
            AuthErr::Internal => write!(f, "internal auth error"),
        }
    }
}

// ─── Cache ──────────────────────────────────────────────

struct CacheEnt {
    au: AuthUser,
    exp: Instant,
}

struct CredCache {
    inner: Mutex<LruCache<String, CacheEnt>>,
    ttl: Duration,
}

impl CredCache {
    fn new(ttl_secs: u64, cap: usize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(NonZeroUsize::new(cap).unwrap())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }
    fn key(user: &str, pass: &str) -> String {
        let mut h = Sha256::new();
        h.update(user.as_bytes());
        h.update(b":");
        h.update(pass.as_bytes());
        hex::encode(h.finalize())
    }
    fn get(&self, key: &str) -> Option<AuthUser> {
        let mut c = self.inner.lock().unwrap();
        if let Some(ent) = c.get(key) {
            if ent.exp > Instant::now() {
                return Some(ent.au.clone());
            }
            c.pop(key);
        }
        None
    }
    fn remove(&self, key: &str) {
        let mut c = self.inner.lock().unwrap();
        c.pop(key);
    }
    fn put(&self, key: String, au: AuthUser) {
        let mut c = self.inner.lock().unwrap();
        c.put(
            key,
            CacheEnt {
                au,
                exp: Instant::now() + self.ttl,
            },
        );
    }
}

// ─── Rate limiter ───────────────────────────────────────

struct RateState {
    fails: u32,
    locked_until: Option<Instant>,
}

/// In-memory rate limiter: 5 fails / 30s per username, 20 / 5min per IP.
pub struct RateLimiter {
    by_user: Mutex<HashMap<String, RateState>>,
    by_ip: Mutex<HashMap<String, RateState>>,
    fails_per_user: u32,
    lock_user: Duration,
    fails_per_ip: u32,
    lock_ip: Duration,
}

impl RateLimiter {
    fn new(fails_per_user: u32, lock_user: Duration, fails_per_ip: u32, lock_ip: Duration) -> Self {
        Self {
            by_user: Mutex::new(HashMap::new()),
            by_ip: Mutex::new(HashMap::new()),
            fails_per_user,
            lock_user,
            fails_per_ip,
            lock_ip,
        }
    }

    fn check(&self, user: &str, ip: &str) -> Result<(), ()> {
        let now = Instant::now();
        // user lock
        {
            let m = self.by_user.lock().unwrap();
            if m.get(user)
                .and_then(|st| st.locked_until)
                .is_some_and(|u| u > now)
            {
                return Err(());
            }
        }
        // ip lock
        {
            let m = self.by_ip.lock().unwrap();
            if m.get(ip)
                .and_then(|st| st.locked_until)
                .is_some_and(|u| u > now)
            {
                return Err(());
            }
        }
        Ok(())
    }

    fn fail(&self, user: &str, ip: &str) {
        let now = Instant::now();
        {
            let mut m = self.by_user.lock().unwrap();
            let st = m.entry(user.to_string()).or_insert(RateState {
                fails: 0,
                locked_until: None,
            });
            if let Some(until) = st.locked_until {
                if until > now {
                    return;
                }
                st.locked_until = None;
            }
            st.fails += 1;
            if st.fails >= self.fails_per_user {
                st.locked_until = Some(now + self.lock_user);
                st.fails = 0;
            }
        }
        {
            let mut m = self.by_ip.lock().unwrap();
            let st = m.entry(ip.to_string()).or_insert(RateState {
                fails: 0,
                locked_until: None,
            });
            if let Some(until) = st.locked_until {
                if until > now {
                    return;
                }
                st.locked_until = None;
            }
            st.fails += 1;
            if st.fails >= self.fails_per_ip {
                st.locked_until = Some(now + self.lock_ip);
                st.fails = 0;
            }
        }
    }

    fn ok(&self, user: &str, ip: &str) {
        let mut m = self.by_user.lock().unwrap();
        m.remove(user);
        let mut m = self.by_ip.lock().unwrap();
        m.remove(ip);
    }
}

// ─── Backend ────────────────────────────────────────────

enum Backend {
    File(Vec<FileUser>),
    Db(std::sync::Arc<UserStore>),
    Keycloak(KeycloakAuthConfig),
}

pub struct Auth {
    backend: Backend,
    cache: CredCache,
    rate: RateLimiter,
    realm: String,
    req_auth: bool,
}

/// Authenticated user context (also carries quota snapshot for checks).
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub uid: Uid,
    #[allow(dead_code)]
    pub db_row: Option<UserRow>,
}

impl Auth {
    pub async fn from_cfg(cfg: &AuthConfig) -> anyhow::Result<Self> {
        let backend = match cfg.backend.as_str() {
            "db" => {
                let db = cfg
                    .db
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("[auth.db] required for db backend"))?;
                let store =
                    std::sync::Arc::new(UserStore::connect(&db.url, db.max_connections).await?);
                store.migrate().await?;
                Backend::Db(store)
            }
            "keycloak" => {
                let kc = cfg
                    .keycloak
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("[auth.keycloak] required"))?;
                Backend::Keycloak(kc.clone())
            }
            _ => {
                let users = cfg
                    .file
                    .as_ref()
                    .map(|f| f.users.clone())
                    .unwrap_or_default();
                Backend::File(users)
            }
        };
        let ttl = match &backend {
            Backend::Db(_) => cfg.db.as_ref().map(|d| d.cache_ttl_secs).unwrap_or(60),
            Backend::Keycloak(k) => k.cache_ttl,
            Backend::File(_) => 300,
        };
        Ok(Self {
            backend,
            cache: CredCache::new(ttl, 256),
            rate: {
                let rl = cfg
                    .rate_limit
                    .clone()
                    .unwrap_or(crate::config::RateLimitConfig {
                        fails_per_user: 5,
                        window_secs: 30,
                        fails_per_ip: 20,
                        window_secs_ip: 300,
                    });
                RateLimiter::new(
                    rl.fails_per_user,
                    Duration::from_secs(rl.window_secs),
                    rl.fails_per_ip,
                    Duration::from_secs(rl.window_secs_ip),
                )
            },
            realm: cfg.realm.clone(),
            req_auth: cfg.require_auth.unwrap_or(true),
        })
    }

    /// Verify Basic credentials; returns user + optional db row (for quota checks).
    pub async fn verify(
        &self,
        user: &str,
        pass: &str,
        client_ip: &str,
    ) -> Result<AuthUser, AuthErr> {
        // Rate limit first
        if self.rate.check(user, client_ip).is_err() {
            warn!("rate_limited user={user} client={client_ip}");
            return Err(AuthErr::RateLimited);
        }

        let ck = CredCache::key(user, pass);
        if let Some(au) = self.cache.get(&ck) {
            debug!("auth_cache_hit user={user}");
            self.rate.ok(user, client_ip);
            // Re-check quota on cache hits: reload the user row for fresh
            // quota limits (admin may have updated them) and current usage.
            if let Some(store) = self.store() {
                match store.get_user(user).await {
                    Ok(Some(row)) => {
                        let usage = store.get_usage(row.id).await.unwrap_or_default();
                        match user_store::check_quota(&row, &usage) {
                            user_store::QuotaStatus::Ok => {}
                            user_store::QuotaStatus::Exceeded(lim) => {
                                return Err(AuthErr::QuotaExceeded(lim));
                            }
                        }
                    }
                    Ok(None) => {
                        self.cache.remove(&ck);
                        return Err(AuthErr::InvalidCreds);
                    }
                    Err(e) => {
                        warn!("db_error error={e}");
                        return Err(AuthErr::Internal);
                    }
                }
            }
            return Ok(au);
        }

        let result = match &self.backend {
            Backend::File(users) => {
                let uid = verify_file(user, pass, users)?;
                Ok(AuthUser { uid, db_row: None })
            }
            Backend::Db(store) => verify_db(store, user, pass).await,
            Backend::Keycloak(_kc) => {
                warn!("keycloak_not_implemented");
                Err(AuthErr::Internal)
            }
        };

        match result {
            Ok(au) => {
                self.cache.put(ck, au.clone());
                self.rate.ok(user, client_ip);
                debug!("auth_ok user={user} display={}", au.uid.label());
                Ok(au)
            }
            Err(e) => {
                self.rate.fail(user, client_ip);
                Err(e)
            }
        }
    }

    /// Invalidate a cached user (after admin disable/reset).
    #[allow(dead_code)]
    pub fn invalidate(&self, _user: &str) {
        // Cache key is sha256(user:pass) — can't reverse it. Clear the whole
        // cache on admin mutations (simple, rare; admin changes also expire
        // within the 60s TTL anyway).
        let mut c = self.cache.inner.lock().unwrap();
        c.clear();
    }

    pub fn required(&self) -> bool {
        self.req_auth
    }

    /// Access to the underlying PostgreSQL store (db backend only).
    pub fn store(&self) -> Option<std::sync::Arc<UserStore>> {
        match &self.backend {
            Backend::Db(s) => Some(s.clone()),
            _ => None,
        }
    }

    pub fn parse_basic(headers: &[u8]) -> Option<(String, String)> {
        let s = std::str::from_utf8(headers).ok()?;
        for line in s.lines() {
            let l = line.trim();
            let colon_pos = l.find(':')?;
            let name = &l[..colon_pos];
            if !name.eq_ignore_ascii_case("proxy-authorization") {
                continue;
            }
            let val = l[colon_pos + 1..].trim();
            if val.len() < 6 || !val[..6].eq_ignore_ascii_case("basic ") {
                continue;
            }
            let b64 = val[6..].trim();
            let dec = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            let ds = std::str::from_utf8(&dec).ok()?;
            if let Some((u, p)) = ds.split_once(':') {
                return Some((u.to_string(), p.to_string()));
            }
        }
        None
    }

    pub fn resp_407(&self) -> hyper::Response<String> {
        let body = "Proxy authentication required";
        hyper::Response::builder()
            .status(407)
            .header(
                "Proxy-Authenticate",
                format!("Basic realm=\"{}\"", self.realm),
            )
            .header("Content-Type", "text/plain")
            .header("Content-Length", body.len())
            .body(body.to_string())
            .unwrap()
    }

    pub fn resp_quota(&self, limit: &str) -> hyper::Response<String> {
        let body = format!("{{\"error\":\"quota_exceeded\",\"limit\":\"{limit}\"}}");
        hyper::Response::builder()
            .status(429)
            .header("Content-Type", "application/json")
            .header("Content-Length", body.len())
            .body(body)
            .unwrap()
    }
}

// ─── File backend ───────────────────────────────────────

fn verify_file(user: &str, pass: &str, users: &[FileUser]) -> Result<Uid, AuthErr> {
    let ent = users
        .iter()
        .find(|u| u.username == user)
        .ok_or(AuthErr::InvalidCreds)?;
    if !user_store::verify_password(pass, &ent.pw) {
        return Err(AuthErr::InvalidCreds);
    }
    Ok(Uid::new(
        ent.user_id.clone().unwrap_or_else(|| ent.username.clone()),
        ent.display.clone().unwrap_or_else(|| ent.username.clone()),
    ))
}

// ─── DB backend ─────────────────────────────────────────

async fn verify_db(store: &UserStore, user: &str, pass: &str) -> Result<AuthUser, AuthErr> {
    let row = store.get_user(user).await.map_err(|e| {
        warn!("db_error error={e}");
        AuthErr::Internal
    })?;
    let row = match row {
        Some(r) => r,
        None => return Err(AuthErr::InvalidCreds), // no user enumeration
    };
    if row.status != "active" {
        return Err(AuthErr::InvalidCreds);
    }
    if !user_store::verify_password(pass, &row.pw_hash) {
        // record failed login
        let _ = store.record_login(row.id, false).await;
        return Err(AuthErr::InvalidCreds);
    }
    let _ = store.record_login(row.id, true).await;

    // Quota check at CONNECT time
    let usage = store.get_usage(row.id).await.unwrap_or_default();
    match user_store::check_quota(&row, &usage) {
        user_store::QuotaStatus::Ok => {}
        user_store::QuotaStatus::Exceeded(lim) => {
            return Err(AuthErr::QuotaExceeded(lim));
        }
    }

    let uid = Uid::new(
        row.id.to_string(),
        row.display.clone().unwrap_or_else(|| row.username.clone()),
    );
    Ok(AuthUser {
        uid,
        db_row: Some(row),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileAuthConfig;

    fn hash_pw(_user: &str, pass: &str) -> String {
        // PBKDF2 via user_store (fast iterations for tests are fine at default)
        user_store::hash_password(pass)
    }

    fn mk_users(pass: &str) -> Vec<FileUser> {
        vec![FileUser {
            username: "alice".into(),
            pw: hash_pw("alice", pass),
            user_id: Some("alice-uid".into()),
            display: None,
        }]
    }

    #[test]
    fn t_parse_basic() {
        let (u, p) = Auth::parse_basic(b"proxy-authorization: Basic dXNlcjpwYXNz\r\n").unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
    }
    #[test]
    fn t_parse_title() {
        let (u, p) = Auth::parse_basic(b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n").unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
    }
    #[test]
    fn t_parse_none() {
        assert!(Auth::parse_basic(b"Host: x\r\n").is_none());
    }
    #[test]
    fn t_parse_bearer() {
        assert!(Auth::parse_basic(b"proxy-authorization: Bearer x\r\n").is_none());
    }
    #[test]
    fn t_file_ok() {
        let u = verify_file("alice", "secret", &mk_users("secret")).unwrap();
        assert_eq!(u.id, "alice-uid");
    }
    #[test]
    fn t_file_bad() {
        assert_eq!(
            verify_file("alice", "wrong", &mk_users("secret")).unwrap_err(),
            AuthErr::InvalidCreds
        );
    }
    #[test]
    fn t_file_unk() {
        assert_eq!(
            verify_file("bob", "secret", &mk_users("secret")).unwrap_err(),
            AuthErr::InvalidCreds
        );
    }
    #[test]
    fn t_uid_lbl() {
        assert_eq!(Uid::new("x", "alice").label(), "alice");
    }

    #[tokio::test]
    async fn t_auth_file_verify() {
        let pw_hash = user_store::hash_password("secret");
        let cfg = AuthConfig {
            backend: "file".into(),
            realm: "T".into(),
            require_auth: Some(true),
            file: Some(FileAuthConfig {
                users: vec![FileUser {
                    username: "dev".into(),
                    pw: pw_hash,
                    user_id: Some("d-uid".into()),
                    display: None,
                }],
            }),
            db: None,
            admin: None,
            jwt: None,
            keycloak: None,
            rate_limit: None,
        };
        let a = Auth::from_cfg(&cfg).await.unwrap();
        let au = a.verify("dev", "secret", "127.0.0.1").await.unwrap();
        assert_eq!(au.uid.id, "d-uid");
    }

    #[tokio::test]
    async fn t_auth_cache() {
        let pw_hash = user_store::hash_password("pw");
        let cfg = AuthConfig {
            backend: "file".into(),
            realm: "X".into(),
            require_auth: Some(true),
            file: Some(FileAuthConfig {
                users: vec![FileUser {
                    username: "u".into(),
                    pw: pw_hash,
                    user_id: None,
                    display: None,
                }],
            }),
            db: None,
            admin: None,
            jwt: None,
            keycloak: None,
            rate_limit: None,
        };
        let a = Auth::from_cfg(&cfg).await.unwrap();
        let u1 = a.verify("u", "pw", "127.0.0.1").await.unwrap();
        let u2 = a.verify("u", "pw", "127.0.0.1").await.unwrap();
        assert_eq!(u1.uid.id, u2.uid.id);
    }

    #[tokio::test]
    async fn t_auth_bad() {
        let pw_hash = user_store::hash_password("good");
        let cfg = AuthConfig {
            backend: "file".into(),
            realm: "Z".into(),
            require_auth: Some(true),
            file: Some(FileAuthConfig {
                users: vec![FileUser {
                    username: "x".into(),
                    pw: pw_hash,
                    user_id: None,
                    display: None,
                }],
            }),
            db: None,
            admin: None,
            jwt: None,
            keycloak: None,
            rate_limit: None,
        };
        assert_eq!(
            Auth::from_cfg(&cfg)
                .await
                .unwrap()
                .verify("x", "bad", "127.0.0.1")
                .await
                .unwrap_err(),
            AuthErr::InvalidCreds
        );
    }

    #[tokio::test]
    async fn t_not_req() {
        let cfg = AuthConfig {
            backend: "file".into(),
            realm: "R".into(),
            require_auth: Some(false),
            file: Some(FileAuthConfig { users: vec![] }),
            db: None,
            admin: None,
            jwt: None,
            keycloak: None,
            rate_limit: None,
        };
        assert!(!Auth::from_cfg(&cfg).await.unwrap().required());
    }

    #[test]
    fn t_rate_limiter() {
        let rl = RateLimiter::new(5, Duration::from_secs(30), 20, Duration::from_secs(300));
        // 5 fails → locked
        for _ in 0..5 {
            rl.fail("u", "1.1.1.1");
        }
        assert!(rl.check("u", "1.1.1.1").is_err());
        // different ip not locked by user lock? user lock applies per user.
        assert!(rl.check("u", "2.2.2.2").is_err());
        assert!(rl.check("v", "1.1.1.1").is_ok());
    }

    #[test]
    fn t_rate_limiter_ok_resets() {
        let rl = RateLimiter::new(5, Duration::from_secs(30), 20, Duration::from_secs(300));
        rl.fail("u", "1.1.1.1");
        rl.ok("u", "1.1.1.1");
        assert!(rl.check("u", "1.1.1.1").is_ok());
    }
}
