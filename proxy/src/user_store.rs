//! PostgreSQL user store: users CRUD, PBKDF2 hashing, quotas, usage counters.
//! Uses runtime sqlx API (no compile-time DATABASE_URL macros).

use anyhow::Context as _;
use chrono::{DateTime, Utc};
use pbkdf2::pbkdf2_hmac;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;

pub const PBKDF2_ITER: u32 = 600_000;

// ─── Row types ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRow {
    pub id: uuid::Uuid,
    pub username: String,
    pub pw_hash: String,
    pub display: Option<String>,
    pub status: String,
    pub role: String,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub login_ok: i64,
    pub login_fail: i64,
    pub quota_req_day: Option<i64>,
    pub quota_tok_in: Option<i64>,
    pub quota_tok_out: Option<i64>,
    pub quota_bytes_in: Option<i64>,
    pub quota_bytes_out: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageRow {
    pub req: i64,
    pub tok_in: i64,
    pub tok_out: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
}

// ─── Quota ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaStatus {
    Ok,
    Exceeded(String),
}

pub fn check_quota(u: &UserRow, usage: &UsageRow) -> QuotaStatus {
    if u.quota_req_day.is_some_and(|lim| usage.req >= lim) {
        return QuotaStatus::Exceeded("req_day".into());
    }
    if u.quota_tok_in.is_some_and(|lim| usage.tok_in >= lim) {
        return QuotaStatus::Exceeded("tok_in".into());
    }
    if u.quota_tok_out.is_some_and(|lim| usage.tok_out >= lim) {
        return QuotaStatus::Exceeded("tok_out".into());
    }
    if u.quota_bytes_in.is_some_and(|lim| usage.bytes_in >= lim) {
        return QuotaStatus::Exceeded("bytes_in".into());
    }
    if u.quota_bytes_out.is_some_and(|lim| usage.bytes_out >= lim) {
        return QuotaStatus::Exceeded("bytes_out".into());
    }
    QuotaStatus::Ok
}

// ─── Store ─────────────────────────────────────────────

#[derive(Clone)]
pub struct UserStore {
    pool: Arc<PgPool>,
}

const SELECT_COLS: &str = "id, username, pw_hash, display, status, role, note, created_at, \
    last_login_at, login_ok, login_fail, \
    quota_req_day, quota_tok_in, quota_tok_out, quota_bytes_in, quota_bytes_out";

fn row_to_user(r: &sqlx::postgres::PgRow) -> UserRow {
    UserRow {
        id: r.get("id"),
        username: r.get("username"),
        pw_hash: r.get("pw_hash"),
        display: r.get("display"),
        status: r.get("status"),
        role: r.get("role"),
        note: r.get("note"),
        created_at: r.get("created_at"),
        last_login_at: r.get("last_login_at"),
        login_ok: r.get("login_ok"),
        login_fail: r.get("login_fail"),
        quota_req_day: r.get("quota_req_day"),
        quota_tok_in: r.get("quota_tok_in"),
        quota_tok_out: r.get("quota_tok_out"),
        quota_bytes_in: r.get("quota_bytes_in"),
        quota_bytes_out: r.get("quota_bytes_out"),
    }
}

impl UserStore {
    pub async fn connect(url: &str, max_conn: u32) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_conn)
            .connect(url)
            .await
            .context("connect postgres")?;
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        // Embedded migration as separate statements (sqlx cannot batch multiple
        // commands in one prepared statement).
        let statements = [
            r#"CREATE TABLE IF NOT EXISTS schema_migrations (
                   version INTEGER PRIMARY KEY,
                   applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
               )"#,
            r#"CREATE EXTENSION IF NOT EXISTS "uuid-ossp""#,
            r#"CREATE TABLE IF NOT EXISTS users (
                   id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                   username TEXT NOT NULL UNIQUE,
                   pw_hash TEXT NOT NULL,
                   display TEXT,
                   status TEXT NOT NULL DEFAULT 'active',
                   note TEXT,
                   created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                   last_login_at TIMESTAMPTZ,
                   login_ok BIGINT NOT NULL DEFAULT 0,
                   login_fail BIGINT NOT NULL DEFAULT 0,
                   quota_req_day BIGINT, quota_tok_in BIGINT, quota_tok_out BIGINT,
                   quota_bytes_in BIGINT, quota_bytes_out BIGINT
               )"#,
            r#"ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'"#,
            r#"CREATE TABLE IF NOT EXISTS usage (
                   user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                   day DATE NOT NULL DEFAULT CURRENT_DATE,
                   req BIGINT NOT NULL DEFAULT 0,
                   tok_in BIGINT NOT NULL DEFAULT 0,
                   tok_out BIGINT NOT NULL DEFAULT 0,
                   bytes_in BIGINT NOT NULL DEFAULT 0,
                   bytes_out BIGINT NOT NULL DEFAULT 0,
                   PRIMARY KEY (user_id, day)
               )"#,
            r#"CREATE TABLE IF NOT EXISTS audit_events (
                   id BIGSERIAL PRIMARY KEY,
                   created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                   user_id TEXT NOT NULL,
                   violation_type TEXT NOT NULL,
                   resource TEXT NOT NULL,
                   masked_context TEXT NOT NULL,
                   token TEXT NOT NULL,
                   request_path TEXT
               )"#,
            r#"CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at)"#,
            r#"CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id)"#,
            r#"CREATE INDEX IF NOT EXISTS idx_audit_violation_type ON audit_events(violation_type)"#,
        ];
        for stmt in statements {
            sqlx::query(stmt)
                .execute(&*self.pool)
                .await
                .context("run migration")?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // ─── CRUD ──────────────────────────────

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        display: Option<&str>,
        note: Option<&str>,
    ) -> anyhow::Result<UserRow> {
        let hash = hash_password(password);
        let row = sqlx::query(&format!(
            "INSERT INTO users (username, pw_hash, display, note) \
             VALUES ($1, $2, $3, $4) RETURNING {SELECT_COLS}"
        ))
        .bind(username)
        .bind(hash)
        .bind(display)
        .bind(note)
        .fetch_one(&*self.pool)
        .await?;
        Ok(row_to_user(&row))
    }

    pub async fn get_user(&self, username: &str) -> anyhow::Result<Option<UserRow>> {
        let row = sqlx::query(&format!(
            "SELECT {SELECT_COLS} FROM users WHERE username = $1"
        ))
        .bind(username)
        .fetch_optional(&*self.pool)
        .await?;
        Ok(row.map(|r| row_to_user(&r)))
    }

    pub async fn get_user_by_id(&self, id: uuid::Uuid) -> anyhow::Result<Option<UserRow>> {
        let row = sqlx::query(&format!("SELECT {SELECT_COLS} FROM users WHERE id = $1"))
            .bind(id)
            .fetch_optional(&*self.pool)
            .await?;
        Ok(row.map(|r| row_to_user(&r)))
    }

    pub async fn list_users(&self) -> anyhow::Result<Vec<UserRow>> {
        let rows = sqlx::query(&format!(
            "SELECT {SELECT_COLS} FROM users ORDER BY username"
        ))
        .fetch_all(&*self.pool)
        .await?;
        Ok(rows.iter().map(row_to_user).collect())
    }

    pub async fn set_role(&self, id: uuid::Uuid, role: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
            .bind(role)
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_status(&self, id: uuid::Uuid, status: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET status = $1 WHERE id = $2")
            .bind(status)
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_password(&self, id: uuid::Uuid, password: &str) -> anyhow::Result<()> {
        let hash = hash_password(password);
        sqlx::query("UPDATE users SET pw_hash = $1 WHERE id = $2")
            .bind(hash)
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_user(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_quota(&self, id: uuid::Uuid, q: &QuotaLimits) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE users SET
                 quota_req_day = $1, quota_tok_in = $2, quota_tok_out = $3,
                 quota_bytes_in = $4, quota_bytes_out = $5
               WHERE id = $6"#,
        )
        .bind(q.quota_req_day)
        .bind(q.quota_tok_in)
        .bind(q.quota_tok_out)
        .bind(q.quota_bytes_in)
        .bind(q.quota_bytes_out)
        .bind(id)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    // ─── Login bookkeeping ──────────────────

    pub async fn record_login(&self, id: uuid::Uuid, ok: bool) -> anyhow::Result<()> {
        if ok {
            sqlx::query(
                "UPDATE users SET last_login_at = now(), login_ok = login_ok + 1 WHERE id = $1",
            )
            .bind(id)
            .execute(&*self.pool)
            .await?;
        } else {
            sqlx::query("UPDATE users SET login_fail = login_fail + 1 WHERE id = $1")
                .bind(id)
                .execute(&*self.pool)
                .await?;
        }
        Ok(())
    }

    // ─── Usage / quota counters ─────────────

    pub async fn get_usage(&self, user_id: uuid::Uuid) -> anyhow::Result<UsageRow> {
        let row = sqlx::query(
            "SELECT req, tok_in, tok_out, bytes_in, bytes_out \
             FROM usage WHERE user_id = $1 AND day = CURRENT_DATE",
        )
        .bind(user_id)
        .fetch_optional(&*self.pool)
        .await?;
        Ok(match row {
            Some(r) => UsageRow {
                req: r.get("req"),
                tok_in: r.get("tok_in"),
                tok_out: r.get("tok_out"),
                bytes_in: r.get("bytes_in"),
                bytes_out: r.get("bytes_out"),
            },
            None => UsageRow::default(),
        })
    }

    /// All-time total usage across all days (for metrics display).
    pub async fn get_usage_total(&self, user_id: uuid::Uuid) -> anyhow::Result<UsageRow> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(req), 0)::bigint AS req, \
             COALESCE(SUM(tok_in), 0)::bigint AS tok_in, \
             COALESCE(SUM(tok_out), 0)::bigint AS tok_out, \
             COALESCE(SUM(bytes_in), 0)::bigint AS bytes_in, \
             COALESCE(SUM(bytes_out), 0)::bigint AS bytes_out \
             FROM usage WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&*self.pool)
        .await?;
        Ok(UsageRow {
            req: row.get("req"),
            tok_in: row.get("tok_in"),
            tok_out: row.get("tok_out"),
            bytes_in: row.get("bytes_in"),
            bytes_out: row.get("bytes_out"),
        })
    }

    /// Atomically check quota and record usage in a single transaction.
    /// Returns Ok(true) if usage was recorded, Ok(false) if quota exceeded.
    pub async fn try_add_usage(
        &self,
        user_id: uuid::Uuid,
        req: i64,
        tok_in: i64,
        tok_out: i64,
        bytes_in: i64,
        bytes_out: i64,
    ) -> anyhow::Result<bool> {
        let mut tx = self.pool.begin().await?;

        // Lock and read current usage
        let current = sqlx::query(
            "SELECT req, tok_in, tok_out, bytes_in, bytes_out FROM usage \
             WHERE user_id = $1 AND day = CURRENT_DATE FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        let (cur_req, cur_ti, cur_to, cur_bi, cur_bo) = match current {
            Some(r) => (
                r.get::<i64, _>("req"),
                r.get::<i64, _>("tok_in"),
                r.get::<i64, _>("tok_out"),
                r.get::<i64, _>("bytes_in"),
                r.get::<i64, _>("bytes_out"),
            ),
            None => (0i64, 0i64, 0i64, 0i64, 0i64),
        };

        // Read quota limits
        let quota = sqlx::query(
            "SELECT quota_req_day, quota_tok_in, quota_tok_out, quota_bytes_in, quota_bytes_out \
             FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        // Check quotas (None = unlimited)
        if let Some(q) = quota {
            if let Some(limit) = q.try_get::<Option<i64>, _>("quota_req_day").unwrap_or(None)
                && cur_req + req > limit
            {
                return Ok(false);
            }
            if let Some(limit) = q.try_get::<Option<i64>, _>("quota_tok_in").unwrap_or(None)
                && cur_ti + tok_in > limit
            {
                return Ok(false);
            }
            if let Some(limit) = q.try_get::<Option<i64>, _>("quota_tok_out").unwrap_or(None)
                && cur_to + tok_out > limit
            {
                return Ok(false);
            }
            if let Some(limit) = q
                .try_get::<Option<i64>, _>("quota_bytes_in")
                .unwrap_or(None)
                && cur_bi + bytes_in > limit
            {
                return Ok(false);
            }
            if let Some(limit) = q
                .try_get::<Option<i64>, _>("quota_bytes_out")
                .unwrap_or(None)
                && cur_bo + bytes_out > limit
            {
                return Ok(false);
            }
        }

        // Record usage
        sqlx::query(
            r#"INSERT INTO usage (user_id, day, req, tok_in, tok_out, bytes_in, bytes_out)
               VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, $6)
               ON CONFLICT (user_id, day) DO UPDATE SET
                 req = usage.req + $2, tok_in = usage.tok_in + $3,
                 tok_out = usage.tok_out + $4, bytes_in = usage.bytes_in + $5,
                 bytes_out = usage.bytes_out + $6"#,
        )
        .bind(user_id)
        .bind(req)
        .bind(tok_in)
        .bind(tok_out)
        .bind(bytes_in)
        .bind(bytes_out)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    #[allow(dead_code)]
    pub async fn add_usage(
        &self,
        user_id: uuid::Uuid,
        req: i64,
        tok_in: i64,
        tok_out: i64,
        bytes_in: i64,
        bytes_out: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO usage (user_id, day, req, tok_in, tok_out, bytes_in, bytes_out)
               VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, $6)
               ON CONFLICT (user_id, day) DO UPDATE SET
                 req = usage.req + $2, tok_in = usage.tok_in + $3,
                 tok_out = usage.tok_out + $4, bytes_in = usage.bytes_in + $5,
                 bytes_out = usage.bytes_out + $6"#,
        )
        .bind(user_id)
        .bind(req)
        .bind(tok_in)
        .bind(tok_out)
        .bind(bytes_in)
        .bind(bytes_out)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Batch-insert audit events for durability.
    pub async fn insert_audit_batch(
        &self,
        events: &[crate::violation_event::ViolationEvent],
    ) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for ev in events {
            sqlx::query(
                "INSERT INTO audit_events (user_id, resource, violation_type, masked_context, token, request_path) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&ev.user_id)
            .bind(&ev.resource)
            .bind(&ev.violation_type)
            .bind(&ev.masked_context)
            .bind(&ev.token)
            .bind(&ev.request_path)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

// ─── Quota limits (admin settable) ─────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct QuotaLimits {
    pub quota_req_day: Option<i64>,
    pub quota_tok_in: Option<i64>,
    pub quota_tok_out: Option<i64>,
    pub quota_bytes_in: Option<i64>,
    pub quota_bytes_out: Option<i64>,
}

// ─── PBKDF2 hashing ────────────────────────────────────

/// Format: pbkdf2:sha256:600000:<salt_hex>:<hash_hex>
pub fn hash_password(password: &str) -> String {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITER, &mut hash);
    format!(
        "pbkdf2:sha256:{}:{}:{}",
        PBKDF2_ITER,
        hex::encode(salt),
        hex::encode(hash)
    )
}

/// Verify password against stored hash (pbkdf2 or legacy sha256).
pub fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split(':').collect();
    match parts.as_slice() {
        ["pbkdf2", "sha256", iter_str, salt_hex, hash_hex] => {
            let iter: u32 = iter_str.parse().unwrap_or(PBKDF2_ITER);
            let salt = match hex::decode(salt_hex) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let want = match hex::decode(hash_hex) {
                Ok(h) => h,
                Err(_) => return false,
            };
            let mut got = vec![0u8; want.len()];
            pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iter, &mut got);
            use subtle::ConstantTimeEq;
            got.ct_eq(&want).into()
        }
        [salt_hex, hash_hex] => {
            let salt = match hex::decode(salt_hex) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let mut h = Sha256::new();
            h.update(&salt);
            h.update(password.as_bytes());
            hex::encode(h.finalize()) == *hash_hex
        }
        _ => false,
    }
}

/// Generate a strong random password (20 chars, unambiguous alnum).
pub fn generate_password() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = OsRng;
    let mut buf = [0u8; 20];
    rng.fill_bytes(&mut buf);
    buf.iter()
        .map(|&b| CHARS[(b as usize) % CHARS.len()] as char)
        .collect()
}

// ─── Tests ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_roundtrip() {
        let h = hash_password("secret123");
        assert!(h.starts_with("pbkdf2:sha256:600000:"));
        assert!(verify_password("secret123", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn test_legacy_hash() {
        let salt = [0xABu8; 16];
        let mut h = Sha256::new();
        h.update(salt);
        h.update(b"pass");
        let stored = format!("{}:{}", hex::encode(salt), hex::encode(h.finalize()));
        assert!(verify_password("pass", &stored));
        assert!(!verify_password("nope", &stored));
    }

    #[test]
    fn test_generate_password() {
        let p1 = generate_password();
        let p2 = generate_password();
        assert_eq!(p1.len(), 20);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_quota_check() {
        let u = UserRow {
            id: uuid::Uuid::new_v4(),
            username: "u".into(),
            pw_hash: "x".into(),
            display: None,
            status: "active".into(),
            role: "user".into(),
            note: None,
            created_at: Utc::now(),
            last_login_at: None,
            login_ok: 0,
            login_fail: 0,
            quota_req_day: Some(10),
            quota_tok_in: None,
            quota_tok_out: None,
            quota_bytes_in: None,
            quota_bytes_out: None,
        };
        let usage = UsageRow {
            req: 5,
            ..Default::default()
        };
        assert_eq!(check_quota(&u, &usage), QuotaStatus::Ok);
        let usage = UsageRow {
            req: 10,
            ..Default::default()
        };
        assert_eq!(
            check_quota(&u, &usage),
            QuotaStatus::Exceeded("req_day".into())
        );
    }
}
