#!/usr/bin/env bash
# E2E: PostgreSQL user store + JWT auth + RBAC + quotas.
# Requires: DATABASE_URL, ADMIN_SECRET (JWT secret for token signing).
set -euo pipefail

DB_URL="${DATABASE_URL:?DATABASE_URL required}"
JWT_SECRET="${ADMIN_SECRET:?ADMIN_SECRET required}"
PROXY_PORT="${PROXY_PORT:-18445}"
ADMIN_PORT="${ADMIN_PORT:-18446}"
WORK_DIR="$(mktemp -d)"
PROXY_BIN="${PROXY_BIN:-target/release/ai-proxy}"

cleanup() {
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

cat > "$WORK_DIR/config.toml" << EOF
mode = "mitm"

[server]
host = "127.0.0.1"
port = ${PROXY_PORT}

[[targets]]
host = "api.deepseek.com"
port = 443

[auth]
backend = "db"
realm = "AI Proxy"
require_auth = true

[auth.db]
url = "${DB_URL}"
max_connections = 4
cache_ttl_secs = 60

[auth.jwt]
secret = "${JWT_SECRET}"
token_ttl_days = 30

[auth.admin]
bind = "127.0.0.1:${ADMIN_PORT}"
EOF

API="http://127.0.0.1:${ADMIN_PORT}/api"
PROXY="http://127.0.0.1:${PROXY_PORT}"

echo "[1/6] Starting proxy with db + jwt backend..."
AI_PROXY_CONFIG="$WORK_DIR/config.toml" RUST_LOG=info "$PROXY_BIN" >"$WORK_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 3

echo "[2/6] Create admin user directly in DB..."
# Insert admin with known password via SQL (PBKDF2 hash computed by python3)
ADMIN_HASH=$(python3 -c "
import hashlib, os, binascii
salt = os.urandom(16)
pw = 'admin_pass_123'
h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 600000)
print(f'pbkdf2:sha256:600000:{binascii.hexlify(salt).decode()}:{binascii.hexlify(h).decode()}')
")
psql "$DB_URL" -c "DELETE FROM users WHERE username IN ('admin','e2euser')" >/dev/null 2>&1 || true
psql "$DB_URL" -c "INSERT INTO users (username, pw_hash, status, role, note) VALUES ('admin', '$ADMIN_HASH', 'active', 'admin', 'e2e admin')" >/dev/null

echo "[3/6] JWT login as admin..."
LOGIN=$(curl -sf -X POST "$API/login" -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin_pass_123"}') || { echo "FAIL: login"; tail -30 "$WORK_DIR/proxy.log"; exit 1; }
TOKEN=$(echo "$LOGIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
echo "  -> token obtained (len=${#TOKEN})"

echo "[4/6] Create user via API (admin role)..."
CREATE=$(curl -sf -X POST "$API/users" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"username":"e2euser","note":"ci"}') || { echo "FAIL: create user"; tail -30 "$WORK_DIR/proxy.log"; exit 1; }
PASS=$(echo "$CREATE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["password"])')
echo "  -> user created, password=$PASS"

echo "[5/6] Auth through proxy (valid creds) -> expect 401 from DeepSeek..."
CODE=$(curl -sk -o /dev/null -w "%{http_code}" -x "http://e2euser:${PASS}@127.0.0.1:${PROXY_PORT}" \
    --max-time 10 https://api.deepseek.com/v1/models || true)
echo "  -> HTTP $CODE"
[ "$CODE" = "401" ] || { echo "FAIL: expected 401, got $CODE"; tail -30 "$WORK_DIR/proxy.log"; exit 1; }

echo "[6/6] Quota enforcement (admin sets 1 req/day -> 429)..."
USER_ID=$(curl -sf "$API/users" -H "Authorization: Bearer $TOKEN" | python3 -c "
import json,sys
for u in json.load(sys.stdin):
    if u['username']=='e2euser': print(u['id'])")
curl -sf -X PUT "$API/users/${USER_ID}/quota" -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" -d '{"req_day":1}' >/dev/null
sleep 1
ERR=$(curl -skv -o /dev/null -x "http://e2euser:${PASS}@127.0.0.1:${PROXY_PORT}" \
    --max-time 10 https://api.deepseek.com/v1/models 2>&1 || true)
echo "  -> $(echo "$ERR" | grep -o 'response [0-9]*' | head -1 || true) (expect 429)"
echo "$ERR" | grep -q "response 429" || { echo "FAIL: expected 429"; tail -30 "$WORK_DIR/proxy.log"; exit 1; }

echo "ALL PASS"
