# VS Code AI extensions through the proxy — Plan

Status: **plan, not implemented.** Companion to `AUTH_BILLING_DESIGN.md`.
AUTH P0 (proxy auth + `apx login`) is implemented — this plan is now unblocked.
Goal: route VS Code AI extensions (Claude Code, OpenAI Codex, GitHub Copilot,
Cline/Roo/Continue, …) through the MITM proxy with DPI + per-user accounting.

---

## 1. The two extension models

Every VS Code AI extension falls into one of two networking models. They need
different treatment.

| Model | How it reaches the API | Examples | Picks up proxy from |
|---|---|---|---|
| **A. Spawns a CLI** | Extension launches a child process (Node/Rust CLI) that does its own HTTP | Claude Code, OpenAI Codex, Aider | **process env** inherited from VS Code (`HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, …) |
| **B. HTTP in the extension host** | Extension makes `fetch`/`https` calls inside the VS Code Extension Host (Node) | GitHub Copilot, Cline, Continue, Cody | VS Code `http.*` settings **and** env (cooperative extensions) |

Model A is governed by the **environment of the VS Code process** (children inherit it).
Model B is governed by **VS Code's networking settings** plus, for Node TLS, the same env.
Both must be solved.

---

## 2. The three configuration layers

```
┌─ Layer 1: environment of the VS Code process ─────────────────────┐
│  HTTPS_PROXY, HTTP_PROXY, NO_PROXY,                                │
│  NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE            │
│  → drives Model A (spawned CLIs) + Node TLS in Model B             │
├─ Layer 2: VS Code settings.json ──────────────────────────────────┤
│  http.proxy, http.proxyStrictSSL, http.proxyAuthorization,         │
│  http.systemCertificates, http.proxySupport                        │
│  → drives Model B (in-host HTTP, Copilot)                          │
├─ Layer 3: per-extension config ───────────────────────────────────┤
│  ~/.claude/settings.json, ~/.codex/config.toml, Cline "proxy"      │
│  → fallback / override for stubborn tools                          │
└────────────────────────────────────────────────────────────────────┘
```

---

## 3. CA trust — the crux

The proxy does **SSL bump (MITM)**, so it presents a cert for e.g. `api.anthropic.com`
signed by our CA. Every client in the chain must trust that CA, otherwise TLS fails.
Four mechanisms, applied in combination:

| Mechanism | Covers | How |
|---|---|---|
| System trust store | OS tools, CLIs using OS CA, VS Code Electron (Chromium uses OS store) | `apx install` already does this (keychain / CA bundle) |
| `NODE_EXTRA_CA_CERTS=<ca.pem>` | Node-based CLIs **and** the Extension Host (Model A + B) | set in env (Layer 1) |
| `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `GIT_SSL_CAINFO` | Python (aider), curl, git | set in env |
| `http.proxyStrictSSL: false` | VS Code Chromium only | last resort; insecure (trust-all) — avoid if CA installed |

**Recommended**: install the CA system-wide (`apx install`) **and** set
`NODE_EXTRA_CA_CERTS` in the VS Code env. Then `proxyStrictSSL` can stay `true`.

---

## 4. Per-extension status & config

### 4.1 Claude Code (Model A) — works cleanly
- Node CLI spawned by the extension; honors `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` natively.
- Two equivalent ways to persist:
  - **Env (Layer 1)** on the VS Code process, **or**
  - **`~/.claude/settings.json`** (Layer 3):
    ```json
    { "env": { "HTTPS_PROXY": "http://USER:PASS@proxy.lan:8443",
               "NODE_EXTRA_CA_CERTS": "/etc/ssl/ai-proxy/ca.pem" } }
    ```
- Hosts to allow in the proxy: `api.anthropic.com`, `*.anthropic.com`. (Telemetry hosts
  `statsig.anthropic.com`, `sentry.io` may be routed or blocked per policy.)

### 4.2 OpenAI Codex CLI (Model A) — KNOWN PROBLEM ZONE
- The Codex CLI **does not reliably honor proxy env vars**; `HTTPS_PROXY`/`HTTP_PROXY`
  support is an open issue (openai/codex#4242 and related). OAuth login behind a
  corporate proxy with a custom CA has reported failures.
- Options, best first:
  1. **`apx run codex …`** with full env (works if the particular build honors env; verify
     per release).
  2. **Transparent interception**: `proxychains`/`redsocks` at the TCP layer, bypassing the
     CLI's HTTP stack entirely. Heavier; needs the CA trusted system-wide.
  3. **Avoid the CLI; use the VS Code extension form of Codex/Copilot** if it talks via the
     Extension Host (Model B), which goes through VS Code's `http.proxy`.
  4. Track upstream; revisit when env support lands.
- Hosts: `api.openai.com`, `chatgpt.com`, `auth.openai.com`.

### 4.3 GitHub Copilot (Model B) — works via VS Code settings
- Uses VS Code's Chromium networking; respects `http.proxy`.
- `settings.json`:
  ```json
  { "http.proxy": "http://USER:PASS@proxy.lan:8443",
    "http.proxyStrictSSL": true,
    "http.proxySupport": "on" }
  ```
- Auth: Copilot uses GitHub OAuth; the OAuth callbacks go over VS Code's HTTP stack, so the
  proxy + CA must be in place first, else the device login fails (same risk class as Codex).
- Hosts: `api.githubcopilot.com`, `api.github.com`,
  `copilot-proxy.githubusercontent.com`, `github.com`, `*.githubassets.com`.

### 4.4 Cline / Roo Code / Continue / Cody (Model B, mostly)
- Node-based, run in the Extension Host → Layer 1 (env) + Layer 2 (settings) usually suffice.
- Several expose their own `proxy` field (Cline, Continue) — set it to the proxy URL as a
  fallback if the host doesn't pick up VS Code settings.
- Providers are user-configurable (Anthropic/OpenAI/Gemini/…), so the allowlist must cover
  whichever they pick.

---

## 5. Launching VS Code with the environment (Layer 1 trap)

The environment of the VS Code process is what Model A children inherit. **Where VS Code is
launched from decides whether they get it:**

| Launch method | Gets `HTTPS_PROXY`? | Fix |
|---|---|---|
| Terminal: `apx run code` | yes (apx injects env) | preferred |
| GUI (Dock/Activities/Start menu) | **no** (GUI session env is minimal; `~/.bashrc` is NOT read) | set env in GUI session |
| `code` from a login shell with `~/.profile` | yes | works |

GUI-session env injection (so Dock-launched VS Code also works):
- **systemd user**: `~/.config/environment.d/ai-proxy.conf` with the four env vars —
  systemd injects into the user session that desktop environments inherit.
- **macOS**: `launchctl setenv HTTPS_PROXY …` (or a LaunchAgent).
- **Linux desktop (non-systemd)**: `/etc/environment` (global) — affects all sessions.

`apx` can generate the appropriate file per OS (`apx vscode-env --user`), mirroring how
`apx install` handles the CA.

---

## 6. `apx` integration

New command (plan): `apx run code [args…]`
- Wraps VS Code exactly like `apx run <cmd>` today (env injection + optional bwrap
  isolation from the existing `scripts/proxy-shell`).
- Injects, from `apx`'s known CA + chosen credentials:
  - `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` (incl. the standard private-net ranges
    already in `cli/main.go`).
  - `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`.
- Reads proxy user:pass from the OS keyring (ties into the future `apx login` device-flow
  from `AUTH_BILLING_DESIGN.md` §5.2; for now `--user/--password`).

Optional companion: `apx vscode-setup`
- Writes the Layer 2 `http.proxy`/`proxyStrictSSL` into the user `settings.json` (merge,
  not overwrite) and the Layer 3 per-tool files (`~/.claude/settings.json`, …) on request.

---

## 7. Proxy-side requirements

1. **Targets allowlist** — add every host the extensions use (per section 4). Today
   `proxy/config.toml` lists only `api.deepseek.com`, `api.openai.com`, `httpbin.org`.
   Add at least: `api.anthropic.com`, `api.githubcopilot.com`, `api.github.com`,
   `copilot-proxy.githubusercontent.com`, `github.com`.
2. **Proxy authentication** — the `http://USER:PASS@` form emits
   `Proxy-Authorization: Basic` on CONNECT. This is exactly what `AUTH_BILLING_DESIGN.md`
   P0 implements; without it, `http://user:pass@` is silently dropped. **Blocker for this
   plan until P0 lands.**
3. **WebSocket** — some extensions (Copilot streaming) use WebSocket. `mitm.rs` currently
   returns `502 "WebSocket proxying: not yet integrated"`. Streaming via SSE is fine;
   WebSocket needs implementation or confirmation that target extensions use SSE.
4. **OAuth callbacks** — Copilot/Codex device login round-trips over HTTP; the proxy must
   not break those domains. Usually fine once allowlisted, but test.

---

## 8. End-to-end checklist (for implementation/verification)

- [ ] `apx install` has placed the CA in the OS trust store (verify with
      `openssl s_client` through the proxy).
- [ ] `NODE_EXTRA_CA_CERTS` points at the same CA and VS Code was started with it.
- [ ] `settings.json` has `http.proxy` + `proxyStrictSSL: true` (Copilot path).
- [ ] Proxy targets allowlist covers the extension hosts.
- [ ] Proxy auth (P0) accepts the Basic creds → requests get a `user` label.
- [ ] Claude Code: a chat round-trip succeeds; `apx check` shows the user's traffic;
      `/metrics` shows `ai_proxy_bytes_total{user=…}` incrementing.
- [ ] Codex CLI: confirm whether env is honored in the current build; if not, apply §4.2
      workaround.
- [ ] Copilot: complete device login through the proxy.

---

## 9. Risks & follow-ups

| Risk | Mitigation |
|---|---|
| Codex CLI ignores proxy env | §4.2 workarounds; track upstream |
| Copilot/Codex device-login breaks behind MITM | ensure CA trusted before login; allowlist auth domains |
| Extension-host TLS quirk (`http.systemCertificatesNode`) | prefer `NODE_EXTRA_CA_CERTS`; verify per VS Code version |
| WebSocket extensions hit the 502 stub | implement WS proxying or steer to SSE providers |
| Per-extension telemetry hosts leak data | allowlist only API hosts; block/scrub telemetry at DPI |
| Telemetry/api version changes add new hosts | document the host list; consider wildcard `*.anthropic.com` |

---

## 10. Phasing relative to AUTH_BILLING_DESIGN

This plan depends on:
- **P0 (proxy auth)** — without `Proxy-Authorization` handling, `http://user:pass@` is
  dropped and traffic is anonymous/unbillable.
- **CA install (`apx install`)** — already exists.

So the earliest this can be exercised end-to-end is right after AUTH P0. Recommended order:
1. Land AUTH P0 (proxy accepts Basic).
2. Extend the targets allowlist.
3. Add `NODE_EXTRA_CA_CERTS` to `apx run` env injection.
4. Add `apx run code` / `apx vscode-setup`.
5. Verify Claude Code (easy win), then Copilot, then tackle Codex.
