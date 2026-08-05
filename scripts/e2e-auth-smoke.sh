#!/usr/bin/env bash
# E2E auth smoke: CONNECT 407 (no creds / bad creds), 429 rate-limit,
# disable/enable user, quota enforcement.
#
# Prerequisites (env):
#   DATABASE_URL      postgres connection string
#   JWT_SECRET        HS256 signing key (ADMIN_SECRET)
#   PROXY_BIN         path to ai-proxy release binary
#   PROXY_PORT        proxy listen port (default 18445)
#   ADMIN_PORT        admin API port (default 18446)
set -euo pipefail

DB_URL="${DATABASE_URL:?DATABASE_URL required}"
JWT_SECRET="${JWT_SECRET:?JWT_SECRET required}"
PROXY_BIN="${PROXY_BIN:?PROXY_BIN required}"
PROXY_PORT="${PROXY_PORT:-18445}"
ADMIN_PORT="${ADMIN_PORT:-18446}"
WORK_DIR="$(mktemp -d)"
export PGPASSWORD="${PGPASSWORD:-$([[ "$DB_URL" =~ :([^@]+)@ ]] && echo "${BASH_REMATCH[1]}" || echo "")}"

cleanup() {
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ── Config ───────────────────────────────────────────────
cat > "$WORK_DIR/config.toml" << EOF
mode = "mitm"

[server]
host = "127.0.0.1"
port = ${PROXY_PORT}

[[targets]]
host = "api.deepseek.com"
port = 443
[[targets]]
host = "api.openai.com"
port = 443

[auth]
backend = "db"
realm = "AI Proxy"
require_auth = true

[auth.db]
url = "${DB_URL}"
max_connections = 4
cache_ttl_secs = 10

[auth.rate_limit]
fails_per_user = 5
window_secs = 5
fails_per_ip = 20
window_secs_ip = 300

[auth.jwt]
secret = "${JWT_SECRET}"
expire_days = 30

[auth.admin]
bind = "127.0.0.1:${ADMIN_PORT}"
EOF

API="http://127.0.0.1:${ADMIN_PORT}/api"
PROXY="http://127.0.0.1:${PROXY_PORT}"
UPSTREAM="https://api.deepseek.com/v1/models"

fail() { echo "FAIL [$1]: $2"; tail -20 "$WORK_DIR/proxy.log"; exit 1; }

# HTTP status of a proxy CONNECT attempt. curl reports 000 when the tunnel
# fails (407/429) — the real code must be parsed from the -v trace.
conn_code() {
    curl -skv -o /dev/null "$@" 2>&1 |
        grep -oE 'response [0-9]{3}' | head -1 | awk '{print $2}'
}

# ── Start proxy ──────────────────────────────────────────
echo "[1/8] Starting proxy..."
AI_PROXY_CONFIG="$WORK_DIR/config.toml" RUST_LOG=info "$PROXY_BIN" >"$WORK_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
for i in $(seq 1 15); do
    # Any HTTP status (401 without token included) proves the admin API is up.
    code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:${ADMIN_PORT}/api/quota/self 2>/dev/null || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then
        echo "  -> proxy ready (attempt $i, admin HTTP $code)"
        break
    fi
    [ "$i" -eq 15 ] && { fail "proxy-start" "not ready after 15 attempts"; }
    sleep 1
done

# ── Create test user ──────────────────────────────────────
echo "[2/8] Creating admin + test user..."
ADMIN_PW='e2e_admin_99'
USER_PW='e2e_user_42'
# Insert users directly (bypasses admin API — no bootstrap chicken-and-egg).
ADMIN_HASH=$(python3 -c "
import hashlib, os, binascii
salt = os.urandom(16)
h = hashlib.pbkdf2_hmac('sha256', '${ADMIN_PW}'.encode(), salt, 600000)
print(f'pbkdf2:sha256:600000:{binascii.hexlify(salt).decode()}:{binascii.hexlify(h).decode()}')
")
USER_HASH=$(python3 -c "
import hashlib, os, binascii
salt = os.urandom(16)
h = hashlib.pbkdf2_hmac('sha256', '${USER_PW}'.encode(), salt, 600000)
print(f'pbkdf2:sha256:600000:{binascii.hexlify(salt).decode()}:{binascii.hexlify(h).decode()}')
")
psql "$DB_URL" -c "DELETE FROM users WHERE username IN ('e2eadmin','e2euser')" >/dev/null 2>&1 || true
psql "$DB_URL" -c "INSERT INTO users (username, pw_hash, status, role, note) VALUES ('e2eadmin', '$ADMIN_HASH', 'active', 'admin', 'smoke test admin')" >/dev/null
psql "$DB_URL" -c "INSERT INTO users (username, pw_hash, status, role, note) VALUES ('e2euser', '$USER_HASH', 'active', 'user', 'smoke test user')" >/dev/null

# ── Login as admin (JWT) ─────────────────────────────────
echo "[3/8] JWT login as admin..."
TOKEN=$(curl -sf -X POST "$API/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"e2eadmin\",\"password\":\"${ADMIN_PW}\"}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
echo "  -> token len=${#TOKEN}"

# ── Get user ID ──────────────────────────────────────────
USER_ID=$(curl -sf "$API/users" -H "Authorization: Bearer $TOKEN" |
    python3 -c "import json,sys
for u in json.load(sys.stdin):
    if u['username']=='e2euser': print(u['id'])")
[ -n "$USER_ID" ] || fail "user-id" "could not find e2euser"

dn() { echo "$1" | head -c 40 | tr -d '\n'; }

# ── 407 — no credentials ─────────────────────────────────
echo "[4/8] CONNECT without credentials -> expect 407..."
CODE=$(conn_code -x "$PROXY" --max-time 8 "$UPSTREAM" || true)
[ "$CODE" = "407" ] || fail "407-no-creds" "got HTTP $CODE"

# ── 407 — bad credentials ────────────────────────────────
echo "[5/8] CONNECT with bad password -> expect 407..."
CODE=$(conn_code -x "http://e2euser:wrongpw@127.0.0.1:${PROXY_PORT}" \
    --max-time 8 "$UPSTREAM" || true)
[ "$CODE" = "407" ] || fail "407-bad-pw" "got HTTP $CODE"

# ── 200 — valid credentials ──────────────────────────────
echo "[6/8] CONNECT with valid credentials -> expect 401 from upstream..."
CODE=$(curl -sk -o /dev/null -w "%{http_code}" -x "http://e2euser:${USER_PW}@127.0.0.1:${PROXY_PORT}" \
    --max-time 10 "$UPSTREAM" 2>&1 || true)
[ "$CODE" = "401" ] || fail "valid-creds" "got HTTP $CODE (want 401 from DeepSeek — no API key)"

# ── 429 — rate-limit (brute force) ────────────────────────
echo "[7/8] Rate-limiting (6 failures -> expect 429)..."
for _ in $(seq 1 5); do
    curl -sk -o /dev/null -x "http://e2euser:badpw@127.0.0.1:${PROXY_PORT}" \
        --max-time 5 "$UPSTREAM" 2>&1 || true
done
sleep 1
CODE=$(conn_code -x "http://e2euser:badpw@127.0.0.1:${PROXY_PORT}" \
    --max-time 8 "$UPSTREAM" || true)
[ "$CODE" = "429" ] || fail "rate-limit" "got HTTP $CODE (want 429 after too many failures)"
sleep 6  # wait out the 5s rate-limit window before the disable test

# ── Disable user -> 407 ──────────────────────────────────
echo "[8/8] Disable user -> expect 407, re-enable -> expect 200..."
curl -sf -X POST "$API/users/${USER_ID}/disable" -H "Authorization: Bearer $TOKEN" >/dev/null
sleep 2  # cache TTL is 10s; wait for cache expiry so user row is re-read
for i in $(seq 1 12); do
    CODE=$(conn_code -x "http://e2euser:${USER_PW}@127.0.0.1:${PROXY_PORT}" \
        --max-time 8 "$UPSTREAM" || true)
    [ "$CODE" = "407" ] && break
    sleep 1
done
[ "$CODE" = "407" ] || fail "disable-407" "got HTTP $CODE after disable"

curl -sf -X POST "$API/users/${USER_ID}/enable" -H "Authorization: Bearer $TOKEN" >/dev/null
sleep 2
CODE=$(curl -sk -o /dev/null -w "%{http_code}" -x "http://e2euser:${USER_PW}@127.0.0.1:${PROXY_PORT}" \
    --max-time 10 "$UPSTREAM" 2>&1 || true)
[ "$CODE" = "401" ] || fail "enable" "got HTTP $CODE after re-enable (want 401 from upstream)"

echo "ALL AUTH SMOKE PASSED"
