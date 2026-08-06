# AI Proxy — secure corporate AI gateway

MITM proxy with DPI (deep packet inspection): routes AI-agent traffic (Claude Code, Pi, aider, codex, curl, ...) through a zero-root-install client, masks secrets and personal data before they leave the network, and enforces an allowlist of upstream AI providers.

## Components

| Path | Description |
|---|---|
| `proxy/` | Rust MITM proxy: TLS bump, DPI engine (secrets + PII masking), audit, PAC, Prometheus metrics |
| `cli/` | `apx` — zero-root Go client: install, CA bundle, keychain trust (macOS), proxy env runner |
| `ansible/` | Deployment playbooks (systemd unit, config templates) |
| `.github/workflows/ci.yml` | CI: Rust build/test, apx smoke on Linux + macOS (Intel/ARM), installer E2E on macOS |

## Quick start (client)

```sh
curl -sS http://proxy.example.com:8443/install.sh | bash
apx check            # verify 7 readiness checks
apx run claude       # run an agent through the proxy
apx shell            # interactive shell with proxy env
apx uninstall        # remove all proxy files (CA, config, bundle)
```

No root, no system trust store changes. On macOS the CA is added to the user login keychain; on Linux per-process isolation via env vars (or bwrap sandbox).

### Running agents in a sandbox (recommended)

`apx run --bwrap <cmd>` starts the command in a bubblewrap sandbox so proxy
credentials and CA settings are scoped to that process tree only — never to
the whole system or PTY:

```sh
apx run --bwrap opencode    # sandboxed, clean env, proxy creds inside only
apx run opencode            # same scoping, no filesystem isolation
```

The sandbox starts from an empty environment (`--clearenv`): only PATH, HOME,
TERM and the proxy/CA variables are injected. The agent cannot read unrelated
host secrets (AWS keys, SSH keys) from the shell, and proxy credentials do not
leak into other applications. `~` is bind-mounted read-write so agent config
and caches work.

`apx login` saves credentials to `~/.config/ai-proxy/env.conf` (chmod 600).
Proxy env vars are **never** set system-wide — use `apx run <command>` to launch
individual apps through the proxy, or `eval "$(apx env)"` for a terminal session.

## Build

```sh
just build        # cli/dist/* + proxy release binary
just test         # cargo tests
just lint         # clippy -D warnings
```

## Deploy

```sh
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml
```

`inventory.ini` is a placeholder — point it at your server.

## Docs

- `docs/ARCHITECTURE.md` — end-to-end request flow
- `docs/dpi.md` — DPI engine design
- `docs/portal.html` — landing page served by the proxy itself
