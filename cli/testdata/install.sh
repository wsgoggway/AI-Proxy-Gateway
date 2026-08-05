#!/bin/bash
# ══════════════════════════════════════════════════════════════════════
# AI Proxy — Unified Installer (NO root required)
# ══════════════════════════════════════════════════════════════════════
#
# This script:
#   1. Detects your OS and architecture
#   2. Downloads the correct 'apx' binary to ~/.local/bin
#   3. Runs 'apx install' which:
#      - Downloads the CA certificate
#      - Builds a CA bundle (system roots + our CA)
#      - Writes config to ~/.config/ai-proxy/env.conf
#      - On macOS: adds CA to user login keychain (no sudo)
#   4. Prints next steps
#
# The system trust store is NEVER modified. No sudo. No root.
#
# Usage:
#   curl -sS http://127.0.0.1:18445/install.sh | bash
#
# After install, run any AI agent through the proxy:
#   apx run pi              # Pi agent
#   apx run claude          # Claude Code
#   apx run opencode        # OpenCode
#   apx run --sandbox codex # Codex CLI (needs bwrap on Linux)
#   apx shell               # Interactive shell with proxy env
#
# Verify everything is set up:
#   apx check               # 7 mandatory system checks
#
# Auto-completion for your shell:
#   eval "$(apx completion bash)"   # or zsh, fish
#
# Shell wrapper functions (run agents without 'apx run'):
#   apx aliases --install    # adds pi() { apx run pi "$@"; } etc. to rc
#
# Full docs: http://127.0.0.1:18445/  (open in browser)
# ══════════════════════════════════════════════════════════════════════
set -e
set -o pipefail

# Unset proxy env vars so inner requests don't loop through the proxy.
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy 2>/dev/null || true

HOST="127.0.0.1:18445"
HOST_ONLY="127.0.0.1"
PORT="18445"
BASE="http://${HOST}"
BIN="${HOME}/.local/bin"

echo "╔══════════════════════════════════════════════╗"
echo "║     AI Proxy — Unified Installer             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ─── Detect OS and architecture ──────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Normalize architecture names
case "${ARCH}" in
    x86_64|amd64)  ARCH="amd64"  ;;
    aarch64|arm64) ARCH="arm64"  ;;
    i386|i486|i686) ARCH="386"   ;;
    *) echo "ERROR: Unsupported architecture: ${ARCH}"; exit 1 ;;
esac

# Normalize OS names
case "${OS}" in
    linux)         OS="linux"   ;;
    darwin)        OS="darwin"  ;;
    *) echo "ERROR: Unsupported OS: ${OS}"
       echo "Supported: Linux, macOS"
       exit 1 ;;
esac

echo "  Detected: ${OS}/${ARCH}"
echo "  Proxy:    ${HOST}"
echo ""

# ─── Download the correct binary ─────────────────────────────────────
BINARY_NAME="apx-${OS}-${ARCH}"
BINARY_URL="${BASE}/cli/${BINARY_NAME}"
APX_PATH="${BIN}/apx"

echo "[1/2] Downloading apx (${OS}/${ARCH})..."
mkdir -p "${BIN}"
# Download to a temp file then atomically rename. Overwriting in place
# fails with ETXTBSY ('Text file busy') if a previous apx process is still
# running from that path — which breaks curl with error 23.
APX_TMP="${APX_PATH}.tmp.$$";
curl --noproxy '*' -fsS "${BINARY_URL}" -o "${APX_TMP}" </dev/null
chmod +x "${APX_TMP}"
mv -f "${APX_TMP}" "${APX_PATH}"
rm -f "${APX_TMP}" 2>/dev/null || true
echo "  Saved: ${APX_PATH}"
echo ""

# ─── Run apx install ─────────────────────────────────────────────────
echo "[2/2] Running apx install..."
# Redirect stdin from /dev/null so the parent curl pipe does not fill up
# when this script is invoked as 'curl ... | bash'.
"${APX_PATH}" --host "${HOST_ONLY}" --port "${PORT}" install </dev/null
