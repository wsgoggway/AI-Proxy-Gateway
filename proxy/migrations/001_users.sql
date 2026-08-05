-- Users with quotas (PostgreSQL)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      TEXT NOT NULL UNIQUE,
    pw_hash       TEXT NOT NULL,                 -- pbkdf2:sha256:600000:salt_hex:hash_hex
    display       TEXT,
    status        TEXT NOT NULL DEFAULT 'active', -- active | disabled
    note          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    login_ok      BIGINT NOT NULL DEFAULT 0,
    login_fail    BIGINT NOT NULL DEFAULT 0,

    -- Quotas (null = unlimited)
    quota_req_day   BIGINT,
    quota_tok_in    BIGINT,
    quota_tok_out   BIGINT,
    quota_bytes_in  BIGINT,
    quota_bytes_out BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS usage (
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day       DATE NOT NULL DEFAULT CURRENT_DATE,
    req       BIGINT NOT NULL DEFAULT 0,
    tok_in    BIGINT NOT NULL DEFAULT 0,
    tok_out   BIGINT NOT NULL DEFAULT 0,
    bytes_in  BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);
