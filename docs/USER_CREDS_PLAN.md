# User Credentials Store — Plan

Status: **plan, not implemented.** Companion to `AUTH_BILLING_DESIGN.md`.
Decisions recorded (2025-08-03): PostgreSQL, LRU-60s, no Redis, quotas, separate admin port.

---

## 1. Goals

1. **Managed user store** — users in PostgreSQL, not in `config.toml`.
2. **Admin operations** — create, list, disable, enable, delete, reset $KEY_d9c8ea$ **Quotas per account** — requests/day, tokens in/out, bytes; enforced at CONNECT time.
4. **Distribution UX** — `apx user add` prints one-time $KEY_66b1bf$ **Security** — PBKDF2 hashes (600k iter), rate limiting, admin API token, no plaintext
   passwords in logs/config/repo/DB.
6. **Compatibility** — existing `backend = "file"` keeps working; `db` is opt-in.

---

## 2. Current state

| Area | Today | Gap |
|---|---|---|
| User storage | `[auth.file]` users in `config.toml` (SHA256:salt) | no add/revoke without edit + restart |
| Verification | `auth.rs::verify_file` — in-memory, LRU cache | no rate limit, no last_login, no status, no quota |
| Admin | none | need create/disable/reset/audit workflow |
| Distribution | `apx login` only consumes creds | no way to generate creds for test users |
| Hashing | `sha256(salt + user + ":" + pass)` | fast — brute-forceable; use PBKDF2 |
| Quotas | none | per-user limits on requests/tokens/bytes |

---

## 3. Architecture

```
                  ┌──────────────────────────────────────────────────┐
  apx user add    │  Proxy (Rust)                                    │
  apx user list → │    :8443  — proxy (MITM)                        │
  apx user passwd │    :8444  — admin API (loopback, token)         │
                  │        │                                         │
                  │        ▼                                         │
                  │  AdminHandler (X-Admin-Token → CRUD + quota mgmt)│
                  │        │                                         │
                  │        ▼                                         │
                  │  UserStore (PostgreSQL via sqlx)                  │
                  │        │  ┌──────────────┐                       │
                  │        ├──│ users table  │  (username, pw_hash, │
                  │        │  │              │   status, display,    │
                  │        │  │              │   last_login, quotas) │
                  │        │  ├──────────────┤                       │
                  │        └──│ usage table  │  (quota counters per │
                  │           │              │   user + time window) │
                  │           └──────────────┘                       │
                  │        ▲                                         │
  CONNECT auth ───┼──▶ Auth::verify(u,p) ──┘                         │
  (Proxy-Auth)    │    LRU cache (60s TTL)                           │
                  │     → miss → DB query (SELECT pw_hash,status,    │
                  │       quotas, usage)                             │
                  │     → hit → cached Uid (no DB round-trip)        │
                  │     → expired 60s → re-query DB                  │
                  └──────────────────────────────────────────────────┘
```

**Key decisions:**
- **PostgreSQL** — `sqlx` crate with `postgres` feature. No SQLite, no Redis.
- **LRU cache in proxy memory** — TTL 60 seconds. On expiry: re-query DB.
  Short TTL means admin changes (disable/reset) take effect within 1 minute.
- **Separate admin port** — `127.0.0.1:8444`, protected by `X-Admin-Token`.
  All admin operations + quota management go through this endpoint.
- **No Redis** for user store — removed from this plan. Redis still used for
  vault/revocation but those are separate (and can be removed later).

---

## 4. Dependencies

Add to `Cargo.toml`:
```toml
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "postgres", "chrono", "migrate"] }
pbkdf2 = "0.12"
hmac = "0.12"     # transitive via pbkdf2
sha2 = "0.10"     # already present
rand_core = "0.6" # salt generation
```

No new crate for quotas — same DB connection, no separate store.

---

## 5. Database schema

```sql
-- Extension for uuid generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      TEXT NOT NULL UNIQUE,
    pw_hash       TEXT NOT NULL,         -- pbkdf2:sha256:600000:salt_hex:hash_hex
    display       TEXT,                  -- optional human name
    status        TEXT NOT NULL DEFAULT 'active',   -- active | disabled
    note          TEXT,                  -- purpose / owner / test scope
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    login_ok      BIGINT NOT NULL DEFAULT 0,
    login_fail    BIGINT NOT NULL DEFAULT 0,

    -- Quotas (null = unlimited)
    quota_req_day   BIGINT,             -- max requests per calendar day
    quota_tok_in    BIGINT,             -- max input (prompt) tokens per day
    quota_tok_out   BIGINT,             -- max output (completion) tokens per day
    quota_bytes_in  BIGINT,             -- max request bytes per day
    quota_bytes_out BIGINT              -- max response bytes per day
);
CREATE UNIQUE INDEX idx_users_username ON users(username);

-- Usage counters (current consumption, reset daily)
CREATE TABLE usage (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day        DATE NOT NULL DEFAULT CURRENT_DATE,  -- UTC day
    req        BIGINT NOT NULL DEFAULT 0,           -- requests today
    tok_in     BIGINT NOT NULL DEFAULT 0,
    tok_out    BIGINT NOT NULL DEFAULT 0,
    bytes_in   BIGINT NOT NULL DEFAULT 0,
    bytes_out  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);

-- Migrations
CREATE TABLE _migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Quota check is performed at CONNECT time (before forwarding):
1. Load user + quota limits from the cached `Uid` (or re-query DB if
   cache miss / 60s expired).
2. Check `usage` counters for `(user_id, CURRENT_DATE)`.
3. If ANY counter exceeds its corresponding `quota_*` limit → `429 Too Many
   Requests` (the proxy returns `407` with a custom error body indicating
   quota exceeded, so the client can distinguish auth-fail from quota-fail).
4. If OK → proceed to forward.

Quota counters are **incremented in the DB** (not in memory to survive
restarts). The billing module (P3 from `AUTH_BILLING_DESIGN.md`) writes
usage records; the same points increment the `usage` counters via
`UPDATE usage SET req = req + 1, tok_in = tok_in + $1, ... WHERE user_id = $2 AND day = CURRENT_DATE`.

---

## 6. Configuration (config.toml)

```toml
[auth]
backend = "db"          # file (legacy) | db | keycloak (stub)
realm = "AI Proxy"
require_auth = true

[auth.db]
url = "${DATABASE_URL}"        # postgres://user:pass@host:5432/ai_proxy
max_connections = 4            # low — the proxy is single-threaded per connection
cache_ttl_secs = 60            # LRU cache TTL before re-query

[auth.admin]
token = "${AI_PROXY_ADMIN_TOKEN}"   # from env, never in repo
bind  = "127.0.0.1:8444"            # separate admin listener, loopback only

[quota]
enabled = true
# Default limits for new users (null in users table = apply default).
default_req_day   = 10000
default_tok_in    = 10_000_000
default_tok_out   = 10_000_000
default_bytes_in  = 1_000_000_000
default_bytes_out = 1_000_000_000
```

`DATABASE_URL` comes from environment — never in the repo.

---

## 7. Admin API (JSON, port 8444)

Auth: every request requires `X-Admin-Token: <token>` header.
All responses `application/json`. All mutations emit `evt="admin.user.*"`
structured log events.

| Method | Path | Body | Result |
|---|---|---|---|
| GET  | `/admin/users` | — | `[{id, username, display, status, note, last_login_at}]` |
| POST | `/admin/users` | `{username, display?, note?}` | `{id, username, password}` — **plaintext once** |
| GET  | `/admin/users/{id}` | — | full record, no hash, includes quota limits + current usage |
| POST | `/admin/users/{id}/passwd` | — | `{password}` — new plaintext once |
| POST | `/admin/users/{id}/disable` | — | `{status: "disabled"}` |
| POST | `/admin/users/{id}/enable` | — | `{status: "active"}` |
| DELETE | `/admin/users/{id}` | — | `{deleted: true}` (cascade usage) |
| PUT  | `/admin/users/{id}/quota` | `{quota_req_day?, quota_tok_in?, quota_tok_out?, ...}` | updated quota |
| GET  | `/admin/users/{id}/quota` | — | current quota + today's usage counters |

---

## 8. CLI (apx)

New `apx user` subcommands. Admin token from `AI_PROXY_ADMIN_TOKEN` env.

```
apx user add USER [--display D] [--note N]      # one-time password on stdout
apx user list [--disabled]                       # table
apx user show USER                               # details + quotas + today's usage
apx user passwd USER                             # reset → one-time password
apx user disable USER | enable USER
apx user delete USER
apx user quota USER                               # show current quotas + usage
apx user quota USER --req-day 5000 --tok-in 1000000  # set quotas
```

Distribution flow:
1. Admin: `apx user add test-user-01 --note "QA sprint"` → prints
   `test-user-01 <one-time-$KEY_e86db5$ Securely shares with test user.
3. Test user: `apx login --user test-user-01 ...` — works.

The generated password uses a CSPRNG, 20 chars alphanumeric, and is NOT
stored in the DB (only PBKDF2 hash). Printed once to stdout.

---

## 9. Auth flow changes (`auth.rs`)

`Backend::Db(PgPool)`:

```rust
// Verification (called from handle_connect / handle_plain_http)
fn verify_basic(&self, user: &str, pass: &str) -> Result<Uid, AuthErr> {
    // 1. Rate-limit check (in-memory, per username + per IP)
    rate_limiter.check(user, client_ip)?;

    // 2. Cache hit (60s TTL LRU)
    if let Some(cached) = self.cache.get(user) {
        // still PBKDF2 verify (cache stores user_id, quotas — NOT hash)
        if self.hash_verify(pass, &cached.pw_hash)? {
            return Ok(cached.uid.clone());
        }
    }

    // 3. Cache miss → DB query
    let row = sqlx::query_as!(UserRow,
        "SELECT pw_hash, status, ... FROM users WHERE username = $1", user
    ).fetch_optional(&self.pool).await?;

    let row = row.ok_or(AuthErr::InvalidCreds)?;  // no user enumeration
    if row.status != "active" { return Err(AuthErr::InvalidCreds); }

    // 4. Check quotas (can be done here or deferred to forward_request)
    let usage = sqlx::query_as!(UsageRow, "SELECT ... FROM usage WHERE user_id = $1 AND day = CURRENT_DATE", row.id).fetch_optional(&self.pool).await?;
    if quota_exceeded(&row.quotas, &usage) { return Err(AuthErr::QuotaExceeded); }

    // 5. PBKDF2 verify
    self.hash_verify(pass, &row.pw_hash)?;

    // 6. Cache, update last_login, return
    self.cache.put(user, row.into_uid());
    Ok(uid)
}
```

`AuthErr::QuotaExceeded` is new — returns 407 with body `{"error":"quota_exceeded","limit":"req_day"}`.

**PBKDF2 format:** `pbkdf2:sha256:600000:<salt_hex>:<hash_hex>`
- `salt_hex` = 32 hex chars (16 bytes)
- `hash_hex` = 64 hex chars (32 bytes SHA256 output)
- 600,000 iterations (OWASP recommendation)

**Rate limiter:**
- Per username: 5 failed attempts → 30 s lock
- Per IP: 20 failed attempts → 5 min lock
- In-memory (hashmap), reset on proxy restart — acceptable for corp proxy

---

## 10. Connection pool & startup

```rust
// main.rs
if config.auth.backend == "db" {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.auth.db.max_connections) // e.g. 4
        .connect(&config.auth.db.url)
        .await?;
    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;
    let auth = Auth::new(Backend::Db(pool), CacheConfig { ttl: 60, cap: 256 });
}
```

Migrations live in `proxy/migrations/` (reintroduced):
```
proxy/migrations/
  001_users.sql
  002_usage.sql
```

---

## 11. Quota enforcement flow

```
CONNECT → handle_connect → auth.verify(user, pass)
  → DB: SELECT pw_hash, status, quota_* FROM users
  → DB: SELECT COALESCE(req,0), ... FROM usage WHERE user_id=$1 AND day=CURRENT_DATE
  → For each quota kind:
      if quota_req_day IS NOT NULL AND usage.req >= quota_req_day → QuotaExceeded
      if quota_tok_in IS NOT NULL AND usage.tok_in >= quota_tok_in → QuotaExceeded
      ...
  → PBKDF2 verify → OK → proceed

After response ← forward_request completes:
  → DB: INSERT INTO usage (user_id, day, req, tok_in, tok_out, bytes_in, bytes_out)
         VALUES ($1, CURRENT_DATE, 1, $2, $3, $4, $5)
         ON CONFLICT (user_id, day)
         DO UPDATE SET req = usage.req + 1,
                       tok_in = usage.tok_in + $2,
                       tok_out = usage.tok_out + $3,
                       bytes_in = usage.bytes_in + $4,
                       bytes_out = usage.bytes_out + $5
```

Note: usage increment happens **after** the response (like billing record
emission in the billing module). Token counts come from the
`usage.rs`/`$KEY_9e10ea$` module (already created, not wired). Bytes from
`log_final`. If a user sends 10 requests in parallel before the first
finishes, they may briefly exceed the quota. This is acceptable (eventual
consistency); a strict enforcement would need a distributed counter.

---

## 12. Security

| Threat | Mitigation |
|---|---|
| Brute force | per-user 5 fails → 30s lock; per-IP 20 fails → 5min |
| Fast hash | PBKDF2-SHA256, 600k iterations |
| Password leak | never logged; returned once by admin API; hash only in DB |
| SQL injection | parameterized queries (`sqlx::query_as!`) |
| Admin API exposed | `127.0.0.1:8444` + token header |
| User enumeration | identical 407 for missing/bad password/disabled/quota |
| Quota bypass | checked at CONNECT; granular per-request counters in DB |
| DB secrets | `DATABASE_URL` from env, `.gitignore`d |

---

## 13. Testing

Unit (proxy):
- `verify_basic` happy path, wrong pass, disabled, quota exceeded
- PBKDF2 hash/verify round-trip
- Rate limiter: lock + expiry
- Admin API CRUD (with testcontainers or in-memory pg)
- Quota increment + enforcement

E2E (CI):
- `apx user add alice` → captures password → `curl` with creds → 200
- Set quota 1 req/day → `curl` once (ok), twice (quota exceeded)
- `apx user disable` → 407
- `apx user passwd` → old fails, new ok

CI needs a PostgreSQL instance. Options:
1. GitHub Actions `services: postgres:16` container
2. Embedded `pg_tmp` / `pg_virtualenv` (testcontainers-rust in CI)

Recommend: GitHub Actions service container (simplest, no testcontainers dep).

---

## 14. Phasing

| Phase | Scope | Status |
|---|---|---|
| **P0** | `sqlx` + schema + migrations, `Backend::Db`, PBKDF2 verify, cache 60s, rate limiter | **Done** (`815316e`) |
| **P1** | Admin API (port 8444, token, user CRUD) | **Done** (`a674534`) |
| **P2** | `apx user` CLI (add/list/show/passwd/disable/quota) | **Done** |
| **P3** | Quotas: schema, checks at CONNECT + cache-hit, increment after response, admin endpoints | **Done** (`414e038`, `6ec3a3d`) |
| **P4** | CI with PostgreSQL service container | **Done** (workflow `users-db-e2e`) |
| **P5** | (future) groups, group-scoped quotas, ACL per `AUTH_BILLING_DESIGN` | design only |

### Implementation notes

- DB backend uses runtime `sqlx::query` (no compile-time DATABASE_URL macros)
- `migrate()` runs embedded DDL as separate statements (sqlx cannot batch)
- `Auth::from_cfg` is async (connects + migrates on startup)
- `RequestContext.user_db_id` carries the UUID for usage accounting
- `record_usage()` in `forward.rs` increments `usage` after each response
  (fire-and-forget; DB errors logged, never block)
- Quota re-checked on cache hits (usage may change within the 60s TTL)
