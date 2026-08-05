# Auth & Billing — Design Document

Status: **P0 implemented** (2025-08-03). P1–P5 remain design-only.
Audience: maintainers of the Rust proxy + `apx` client.

## Implementation status

| Phase | Status | Commit |
|---|---|---|
| P0 — Basic auth + CONNECT check + user_id plumbing | **Done** | `fb97f4d` + `06c3f55` |
| P1 — $KEY_2eedf9$ validation + apx device flow | Design, not implemented | — |
| P2 — Metrics with user labels | Design, not implemented | — |
| P3 — Billing ledger + token counting | Design, not implemented | — |
| P4 — SSE token aggregation | Design, not implemented | — |
| P5 — ACL (group x target) | Design, not implemented | — |

### P0 details (implemented)

- `proxy/src/auth.rs` — Basic auth with file backend (SHA256:salt:hash), LRU cred cache,
  `Proxy-Authorization: Basic` parsing, 407 response, 12 unit tests
- `proxy/src/mitm.rs` — CONNECT auth check in `handle_connect`, user_id threaded
  through `RequestContext` to `forward_request`
- `cli/main.go` — `apx login` (verify via CONNECT + save to env.conf 0600),
  `apx logout`, `apx whoami`, `setProxyEnv` injects `http://user:pass@host`
- `proxy/config.toml` — `[auth]` section with `require_auth`, `[auth.file]` users
- `proxy/src/config.rs` — `AuthConfig`, `FileUser`, `KeycloakAuthConfig` structs
- `proxy/src/billing.rs` — module created, not wired (P3)
- `proxy/src/usage.rs` — module created, not wired (P3)

## Original design (unchanged)

---

## 1. Goals

1. **Access control** for a forward MITM proxy used as `HTTPS_PROXY=http://proxy.lan:8443`.
   Non-interactive clients (curl, claude code, aider, codex, npm, pip) must authenticate.
2. **Identity source** = corporate Keycloak. No local user table; Keycloak is the single
   source of truth for users, passwords, groups.
3. **Accounting**: bytes in/out, tokens in/out, per user + per target/model.
4. **Observability**: Prometheus exposes system metrics + general per-user aggregates.
5. **Billing**: a separate durable store (not Prometheus) holds the usage ledger.

---

## 2. Current state (gap analysis)

| Area | Current | Gap |
|---|---|---|
| MITM `CONNECT` | `handle_connect` reads request headers into `header_buf` and **discards** them | `Proxy-Authorization` not parsed; anonymous access |
| Reverse mode | mTLS (`extract_user_id_from_cert`) OR OIDC browser redirect | OIDC is a browser flow, **unusable** for proxy CONNECT clients |
| `oidc.rs::validate_id_token` | dead code; HS256 with `insecure-mvp-key` | no real signature validation against Keycloak JWKS |
| `oidc.rs::handle_oidc_callback` | stub; sets cookie `mvp-session-{code}` without token verification | security not enforced |
| `metrics.rs::BYTES_TOTAL` | labels `{direction}` only | no `user` label → cannot attribute traffic |
| `metrics.rs::REQUESTS_TOTAL` | labels `{method,target,dpi}` | no `user` label |
| Token counting | none | bodies already parsed as JSON for DPI; token counts are a free byproduct |
| `forward.rs` byte counting | lines ~572 (req), ~709 (resp) increment `BYTES_TOTAL` | need `user` label + structured ledger record |
| HTTP client to Keycloak | none (`reqwest` not in `Cargo.toml`) | must add an outbound HTTP client |
| `apx` login | none (only CA install / keychain) | needs device-flow login + Bearer injection |

**Key insight**: the existing browser-redirect OIDC cannot authenticate proxy clients. A
`CONNECT api.openai.com:443` carries at most `Proxy-Authorization` — there is no browser to
follow a 307 or to store a cookie. Keycloak is still the right IdP; we call it differently.

---

## 3. Architecture

```
                    ┌──────────────────────────────────────────────┐
   agent (curl,     │  Proxy (Rust, :8443)                         │
   claude, apx)     │                                              │
        │           │   CONNECT + Proxy-Authorization              │
        │  HTTPS_   │   ┌────────────┐                             │
        │  PROXY ───┼──▶│ auth.rs    │── verify ──┐                │
        │           │   └────────────┘            │                │
        │           │        │ ok (user_id)       ▼                │
        │           │        ▼              ┌───────────────┐      │
        │           │   SSL bump + DPI      │  Keycloak     │      │
        │           │   forward_request ───▶│  (realm)      │      │
        │           │        │              │  JWKS / token │      │
        │           │        ▼              └───────────────┘      │
        │           │   ┌────────────┐                            │
        │           │   │ metrics.rs │──▶ /metrics (Prometheus)   │
        │           │   │ billing.rs │──▶ ledger (Redis/SQL)      │
        │           │   └────────────┘                            │
        └───────────┴──────────────────────────────────────────────┘
```

Two coexisting auth modes, one Keycloak realm, one `auth.rs` resolver:

| Mode | Client UX | Credential | Validation |
|---|---|---|---|
| **A. Basic** (ROPC) | `http://user:pass@proxy.lan:8443` | `Proxy-Authorization: Basic base64(user:pass)` | proxy → Keycloak token endpoint, `grant_type=password` |
| **B. Bearer** (device flow) | `apx login` (browser), then `apx run` | `Proxy-Authorization: Bearer <jwt>` | proxy validates RS256 against Keycloak JWKS |

Both resolve to a `user_id` (Keycloak `preferred_username` or `sub`) that threads through
the connection and labels all accounting. Decision: **A + B both** (see §13 phasing).

---

## 4. Identity: Keycloak

- One realm, e.g. `ai-proxy`. Clients: `ai-proxy-ropc` (confidential, Direct Access Grants
  enabled) and `ai-proxy-cli` (public, device-flow enabled).
- Groups/roles drive the future ACL (§6).
- Test realm is separate (see §12). Production Keycloak lives inside the network perimeter;
  the proxy reaches it directly (`NO_PROXY` must cover the issuer to avoid self-loop).

User identity attributes used:
- `sub` — stable identifier for the ledger
- `preferred_username` — human-readable label for metrics
- `groups` / `roles` (realm or client) — ACL input (phase 2)

---

## 5. Client authentication

### 5.1 Mode A — Basic (ROPC)

Flow (per CONNECT):
1. Client opens TCP, sends `CONNECT host:443` + `Proxy-Authorization: Basic <b64>`.
2. `mitm.rs` extracts the header from `header_buf` (currently discarded).
3. `auth.rs::verify_basic(user, pass)`:
   - Check credential cache (`(user, sha256(pass)) → (user_id, expiry)`, TTL ~5 min, LRU).
   - On miss: POST Keycloak token endpoint `grant_type=password`, `client_id`,
     `client_secret`, `username`, `password`. Accept → `user_id` from token claims; cache.
   - On reject → `AuthError`.
4. Result propagates: ok → proceed to SSL bump with `user_id`; reject → `407` and close.

HTTP-target requests (`handle_plain_http`) carry `Proxy-Authorization` on the actual
request and are validated the same way (connection-scoped cache).

Wire on failure:
```
HTTP/1.1 407 Proxy Authentication Required\r\n
Proxy-Authenticate: Basic realm="AI Proxy"\r\n
\r\n
```

Approved: ROPC is acceptable inside the perimeter despite OAuth 2.1 deprecation.
Trade-off: password transits the proxy (mitigated by TLS termination on the LAN; the proxy
never stores passwords, only the validation result).

### 5.2 Mode B — Bearer (device flow via `apx`)

Client side (`apx login`, once):
1. `apx login` POSTs Keycloak device-authorization endpoint → receives
   `device_code`, `user_code`, `verification_uri`.
2. Opens `verification_uri` in the user's browser, polls the token endpoint until the user
   completes browser login.
3. Stores `access_token` + `refresh_token` in the OS keyring (same store as CA today).

Client side (`apx run <cmd>`):
- Injects `Proxy-Authorization: Bearer <access_token>` into the env/proxy handshake.
- On `401`/exp: silently refreshes via `refresh_token`; if that fails, prompts `apx login`.

Proxy side (`auth.rs::verify_bearer(jwt)`):
1. Decode header `kid`, look up in cached JWKS (Keycloak `/protocol/openid-connect/certs`,
   refresh on unknown kid / periodic TTL).
2. Validate RS256 signature, `exp`, `iss`, `aud`. Extract `sub`/`preferred_username`.
3. No per-request Keycloak round trip (offline JWT validation) → fast, scales.

### 5.3 What changes in code (per file)

- **`Cargo.toml`**: add `reqwest` (rustls-tls, json), `jsonwebtoken` (present) for RS256,
  wiremock dev-dep for tests.
- **`auth.rs` (new)**: `Authenticator`, `verify_basic`, `verify_bearer`, cred cache,
  JWKS cache, `AuthError`, `proxy_auth_response`. Replaces the dead `oidc.rs` functions.
- **`config.rs`**: `[auth]` table (see §11).
- **`mitm.rs::handle_connect`**: parse `Proxy-Authorization` from `header_buf`; on
  missing/invalid → 407; on ok → carry `user_id` into the bumped connection's request
  service. Same in `handle_plain_http`.
- **`main.rs`**: construct `Authenticator` at startup (fetch JWKS), pass `Arc` into both
  modes; delete the browser OIDC redirect/callback path (or keep for an admin UI only).
- **`forward.rs`**: `RequestContext` already has `user_id`; MITM mode now populates it.

---

## 6. Authorisation / ACL (phase 2, not built now)

Decisions recorded: **ACL needed, deferred.** Target design:

- Keycloak groups/roles map to access policies, e.g. group `openai-users` → may reach
  `api.openai.com`; group `blocked` → deny all; per-target rate/quotas.
- Evaluated in `auth.rs` after identity resolves, before SSL bump. Fail → `403`.
- Config expresses rules declaratively (allow/deny by group × target), evaluated against the
  token's `groups`/`realm_access.roles` claims.
- Quota enforcement (tokens/day per user) integrates with the billing ledger (§9) as a
  read-check before forwarding.

---

## 7. Traffic accounting: bytes in/out

Already counted in `forward.rs` (~line 572 request bytes, ~line 709 response bytes) via
`metrics::BYTES_TOTAL{direction}`. Changes:
- Add `user` label.
- Emit a structured record to the billing ledger (§9) with the same numbers.

Byte semantics:
- **in** = request body bytes the client sent (client → proxy → upstream).
- **out** = response body bytes upstream returned (upstream → proxy → client).
- Header bytes excluded (bodies dominate; headers tracked separately as a system metric if
  needed). Documented explicitly to avoid billing disputes.

Note: after SSL bump the proxy sees decrypted bodies, so counts are **content bytes**, not
TLS frame bytes. This is the meaningful billing quantity.

---

## 8. Metrics (Prometheus) — system + general per-user

Decision: **Prometheus carries system metrics + general per-user aggregates; the durable
ledger is separate (§9).** Per-user labels are acceptable at corporate scale (dozens–hundreds
of users), not for public SaaS cardinality.

### 8.1 System metrics (unchanged or relabeled)
```
ai_proxy_active_connections            (gauge)
ai_proxy_cert_cache_entries            (gauge)
ai_proxy_vault_connected               (gauge)
ai_proxy_upstream_errors_total{target} (counter)
ai_proxy_request_duration_seconds{target}          (histogram)
ai_proxy_auth_total{mode, result}                   (counter)   # NEW: mode=basic|bearer, result=ok|deny
ai_proxy_jwks_fetch_total{result}                  (counter)   # NEW
ai_proxy_auth_cache_size                           (gauge)     # NEW
```

### 8.2 Per-user general metrics (relabeled)
```
ai_proxy_requests_total{user, method, target, dpi}
ai_proxy_bytes_total{user, direction}              # in | out
ai_proxy_tokens_total{user, target, direction, model}   # NEW — see §10
ai_proxy_violations_total{type, target}            # unchanged (no user: privacy — secrets are masked)
```

`user` = Keycloak `preferred_username`; falls back to `sub` if absent. Low cardinality by
design. `violation` metrics intentionally omit `user` to avoid correlating who leaked what
in a scrape; user correlation lives in the audit stream (already keyed by user_id).

---

## 9. Billing (separate durable system)

Decision: **billing is separate from Prometheus.** Prometheus is for alerting/dashboards,
not for invoicing. A ledger sink captures authoritative usage records.

Design (mirrors the existing `audit.rs` batching pattern — unbounded mpsc → batch flush):
- New module `billing.rs`: `BillingChannel` + background flusher (5 s window, like audit).
- Record schema (emitted once per completed forward, in `forward.rs::log_final`):
  ```
  { ts, user_id, target, model, path, status,
    bytes_in, bytes_out, prompt_tokens, completion_tokens,
    streaming: bool }
  ```
- Sinks (pluggable, choose one per deployment):
  1. **Redis** (already a dependency) — `LPUSH billing:events <json>`, plus aggregated
     hashes `billing:user:<id>:<yyyymm>` counters. Simplest, in-process.
  2. **SQL** (Postgres/ClickHouse) — append-only `usage_events` table; ClickHouse preferred
     for volume. Needs a pool (`sqlx`); migrations live under `migrations/` (re-introduce).
- Decoupling: the flusher is fire-and-forget; a Redis/DB outage degrades to Prometheus-only
  (warn, do not block forwarding). This matches the `vault` fail-open behavior already in
  `main.rs`.

Recommendation: Redis as the default sink (no new infra), ClickHouse as the upgrade path.

---

## 10. Token counting in/out

Bodies are already parsed as JSON for DPI, so counts are nearly free. New module
`token_usage.rs`:

### 10.1 Response (authoritative) — `usage` field
OpenAI / DeepSeek / Qwen / Anthropic all return a `usage` object on chat completions:
- OpenAI-compatible: `usage.{prompt_tokens, completion_tokens, total_tokens}`, `model`.
- Anthropic: `usage.{input_tokens, output_tokens}` in `message_start`/`message_delta`.
- Map to ledger: `prompt_tokens` → direction `in`, `completion_tokens` → direction `out`.

### 10.2 Request (estimate) — `messages`
- If client sent a `max_tokens`/estimate, trust it; otherwise heuristic `len(messages)/4`
  (rough char→token; documented as estimate). Authoritative `in` comes from the response's
  `usage.prompt_tokens`.

### 10.3 Streaming (SSE) — the hard part
- Non-streaming JSON response: parse `usage` directly.
- Streaming `text/event-stream`: aggregate `data: {…}` frames:
  - OpenAI: final chunk carries `usage` if `stream_options:{include_usage:true}`; else sum
    deltas or fall back to response-side estimate.
  - Anthropic: `message_start.usage.input_tokens` + `message_delta.usage.output_tokens`.
- Strategy: buffer SSE frames cheaply, extract usage fields by provider; if absent, record
  `tokens_total` as null and rely on bytes + heuristic. Never block the stream.

### 10.4 Provider detection
- By target host (already known via `resolve_target`) and/or response `Content-Type`.
- Provider adapters kept in `token_usage.rs` (openai, anthropic, generic-fallback).

---

## 11. Configuration

```toml
mode = "mitm"

[server]
host = "0.0.0.0"
port = 8443

[[targets]]
host = "api.openai.com"

[auth]
provider    = "keycloak"
issuer_url  = "https://keycloak.lan/realms/ai-proxy"
client_id   = "ai-proxy-ropc"        # confidential, used for ROPC token exchange
client_secret = "${AI_PROXY_CLIENT_SECRET}"   # env interpolation
device_client_id = "ai-proxy-cli"    # public client for device flow (proxy side: JWKS only)
modes       = ["basic", "bearer"]    # enable A and B
cache_ttl   = 300                    # credential cache seconds
jwks_ttl    = 3600                   # JWKS cache seconds

[redis]
url = "redis://127.0.0.1:6379"

[billing]
sink        = "redis"                # redis | sql
flush_secs  = 5
```

Secrets via env (never in the repo). `config.rs` gains `[auth]` and `[billing]` structs.

---

## 12. Keycloak: prod vs test

Decision: **production Keycloak inside the network perimeter; a separate test realm/instance
for CI.**

- Prod: the proxy resolves the issuer over the LAN; `NO_PROXY` must include the issuer host
  so the proxy's own outbound calls do not route through itself.
- Test: a dedicated Keycloak (container in CI / `infra/`) with a `ai-proxy-test` realm, seed
  users, pre-rotated test JWKS. Integration tests use it for `verify_basic`/`verify_bearer`
  end-to-end. CI spins it up; no real credentials ever touch the repo.
- `apx login` takes `--issuer` to pick prod vs test.

---

## 13. Implementation phasing

| Phase | Scope | Outcome |
|---|---|---|
| **P0** | `auth.rs` (Basic/ROPC + cred cache), parse `Proxy-Authorization` in `handle_connect`/`handle_plain_http`, 407 path, `user_id` plumbing | Anonymous access closed; `http://user:pass@proxy` works |
| **P1** | JWKS Bearer validation (`verify_bearer`, RS256), delete dead `validate_id_token`; `apx login` device flow + keyring | Mode B works |
| **P2** | Metrics relabel (`user`), `ai_proxy_tokens_total`, `ai_proxy_auth_total` | Per-user dashboards |
| **P3** | `billing.rs` sink (Redis default), `token_usage.rs` (non-streaming first) | Durable usage ledger |
| **P4** | SSE token aggregation, provider adapters | Accurate streaming billing |
| **P5** | ACL (group × target), quota checks against ledger | Authorization |

Each phase is independently shippable and independently testable. P0 unblocks all accounting
because every later phase needs a stable `user_id`.

---

## 14. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Keycloak outage blocks all traffic | cred cache absorbs short outages; on cache miss fail **closed** (deny) by default, with a config flag to fail open for trusted LAN |
| Proxy's own Keycloak calls loop through itself | `NO_PROXY` for issuer; documented startup check |
| High per-user metric cardinality | documented corporate-scale assumption; user = preferred_username (bounded) |
| SSE usage absent → under-billing | record null, surface `ai_proxy_token_usage_missing_total{provider}`; never block stream |
| ROPC deprecation | isolate behind `auth.rs`; Mode B is the migration path |
| Password transit (Mode A) | TLS on LAN, no storage, cache hashes only |

---

## 15. Open follow-ups (after this doc)

- Decide billing sink default (Redis vs SQL) before P3.
- Quota model details (tokens/day? bytes/month?) deferred to P5.
- Admin UI: whether the browser OIDC redirect path is repurposed for an admin console or
  removed.
