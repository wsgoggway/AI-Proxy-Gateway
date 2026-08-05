-- Audit events for compliance and security monitoring
CREATE TABLE IF NOT EXISTS audit_events (
    id            BIGSERIAL PRIMARY KEY,
    user_id       TEXT,
    resource      TEXT NOT NULL,
    violation_type TEXT NOT NULL,  -- SECRET | PII_FIO | PII_PHONE | PII_EMAIL | PII_COMPANY
    masked_context TEXT,           -- human-readable masked description
    token         TEXT,            -- $PREFIX_hash$ token for cross-referencing
    request_path  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_type     ON audit_events(violation_type);
