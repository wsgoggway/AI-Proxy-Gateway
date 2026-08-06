# AI Proxy — secure corporate AI gateway

MITM proxy with DPI (deep packet inspection): routes AI-agent traffic (Claude Code, Pi, aider, codex, curl, ...) through a zero-root-install client, masks secrets and personal data before they leave the network, and enforces an allowlist of upstream AI providers.

## Components

| Path | Description |
|---|---|
| `proxy/` | Rust MITM proxy: TLS bump, DPI engine (secrets + PII tokenization), semantic validation (local Ollama), Redis vault (reversible), axum admin API, audit, PAC, Prometheus metrics |
| `cli/` | `apx` — zero-root Go client (Cobra + lipgloss + tablewriter + survey): install, CA bundle, keychain trust (macOS), bwrap sandbox, proxy env runner |
| `ansible/` | Deployment playbooks (systemd unit, config templates) |

## Architecture

```
Agent → apx run → MITM proxy (TLS bump) → DPI scan → tokenize secrets → AI API
                                                          ↓
Agent ← detokenize ← SSE stream ← AI API response ←──────┘
```

Secrets are replaced with `[KEY_d51b3f]` placeholders (pure ASCII, deterministic SHA256). The proxy stores the original↔token mapping in Redis (30-day TTL) and restores originals in the response. Tokens never reach the AI provider; originals never leak back to the agent.

## Quick start (client)

```sh
curl -sS http://proxy.example.com:8443/install.sh | bash
apx login --host proxy.example.com --user <your-user>
apx check            # verify readiness
apx run claude       # run an agent through the proxy
apx shell            # interactive shell with proxy env
apx uninstall        # remove all proxy files (CA, config, bundle)
apx uninstall --purge  # also remove the apx binary
```

No root, no system trust store changes. CA is saved to `~/.config/ai-proxy/`.

### Tokenization

```
Request:  sk-abc123 → [KEY_b7e548]  (AI never sees the real key)
Response: [KEY_b7e548] → sk-abc123  (agent gets the original back)
```

Token format: `[TYPE_hash6]` where TYPE is KEY (secret), FIO (name), EML (email), PHN (phone), ORG (company). The detokenization scanner matches all historical formats (Unicode `‹›`, `q_..._q`, JSON-escaped, bare) to ensure no token ever leaks unresolved.

### Sandboxed execution

`apx run <cmd>` launches apps in a bubblewrap sandbox (Linux) or with keychain trust (macOS). Proxy credentials and CA settings are scoped to that process tree only — never system-wide.

```sh
apx run --sandbox codex    # Rust/Electron agents (bwrap on Linux)
apx run --no-sandbox pi    # env-only (no filesystem isolation)
```

## Admin API

| Command | Description |
|---|---|
| `apx login` | Authenticate (JWT, saved to `~/.config/ai-proxy/env.conf`) |
| `apx whoami` | Show current user + role |
| `apx user add/list/delete` | User management (admin only, hidden from non-admins) |
| `apx metrics` | All-time usage statistics |
| `apx quota` | Per-user daily quotas |
| `apx env` | Print export lines for `eval "$(apx env)"` |

Admin commands are automatically hidden from non-admin users in `--help` output (JWT role-based).

## Build

```sh
just build        # cli/dist/* (4 platforms) + proxy release binary
just test         # cargo tests (167 tests)
just lint         # clippy -D warnings
```

## Deploy

```sh
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml
```

## Docs

- `docs/ARCHITECTURE.md` — end-to-end request flow, token lifecycle, DPI filters
- `docs/dpi.md` — DPI engine design: secret/PII detection patterns
- `docs/portal.html` — landing page served by the proxy at `/`
