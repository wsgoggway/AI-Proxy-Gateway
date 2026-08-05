#![allow(clippy::too_many_arguments)]
use hyper::Request;
/// MITM proxy: CONNECT + SSL Bump for HTTPS, plain HTTP forwarding for HTTP targets.
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::cert_cache::CertCache;
use crate::config;
use crate::forward;
use crate::session::SessionId;
use crate::vault::Vault;

/// User-space CA wrappers shipped from the repo so the binary and the on-disk
/// scripts cannot drift apart. Served verbatim at /scripts/<name>.
const PROXY_ENV: &str = include_str!("../../scripts/proxy-env");
const WITH_PROXY: &str = include_str!("../../scripts/with-proxy");
const PROXY_SHELL: &str = include_str!("../../scripts/proxy-shell");

/// Go CLI binary (apx) — cross-compiled for all supported platforms.
/// Served at /cli/apx-{os}-{arch} for download by the unified installer.
const APX_LINUX_AMD64: &[u8] = include_bytes!("../../cli/dist/apx-linux-amd64");
const APX_LINUX_ARM64: &[u8] = include_bytes!("../../cli/dist/apx-linux-arm64");
const APX_DARWIN_AMD64: &[u8] = include_bytes!("../../cli/dist/apx-darwin-amd64");
const APX_DARWIN_ARM64: &[u8] = include_bytes!("../../cli/dist/apx-darwin-arm64");

/// Peek at first bytes to detect CONNECT vs plain HTTP.
async fn is_connect(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 8];
    match stream.peek(&mut buf).await {
        Ok(n) if n >= 7 => buf.starts_with(b"CONNECT"),
        _ => false,
    }
}

/// Read first line byte-by-byte (consumes bytes from stream).
async fn read_first_line(stream: &mut TcpStream) -> Option<String> {
    let mut line = String::new();
    let mut buf = [0u8; 1];
    loop {
        if stream.read_exact(&mut buf).await.is_err() {
            return if line.is_empty() { None } else { Some(line) };
        }
        line.push(buf[0] as char);
        if line.ends_with("\r\n") {
            break;
        }
        if line.len() > 8192 {
            return Some(line);
        }
    }
    Some(line.trim_end().to_string())
}

/// Handle one TCP connection: CONNECT (HTTPS) or plain HTTP forwarding.
// Context structs (RequestContext) would help, but connection handlers need
// many shared dependencies — keeping explicit params for now.
#[allow(clippy::too_many_arguments)]
pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    auth: Option<std::sync::Arc<crate::auth::Auth>>,
    store: Option<std::sync::Arc<crate::user_store::UserStore>>,
    config: Arc<config::Config>,
    upstream_connector: Arc<tokio_rustls::TlsConnector>,
    vault: Arc<Vault>,
    audit_sender: Arc<crate::audit::AuditChannel>,
    cert_cache: Arc<CertCache>,
    ca_pem: &str,
) {
    if is_connect(&stream).await {
        // HTTPS: CONNECT + SSL Bump
        let first_line = match read_first_line(&mut stream).await {
            Some(l) => l,
            None => return,
        };
        handle_connect(
            stream,
            &first_line,
            peer_addr,
            config,
            upstream_connector,
            vault,
            audit_sender,
            cert_cache,
            auth.clone(),
            store.clone(),
        )
        .await;
    } else {
        // Plain HTTP: serve static files or forward to target
        handle_plain_http(
            stream,
            peer_addr,
            config,
            upstream_connector,
            vault,
            audit_sender,
            ca_pem,
            auth.clone(),
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connect(
    stream: TcpStream,
    first_line: &str,
    peer_addr: SocketAddr,
    config: Arc<config::Config>,
    upstream_connector: Arc<tokio_rustls::TlsConnector>,
    vault: Arc<Vault>,
    audit_sender: Arc<crate::audit::AuditChannel>,
    cert_cache: Arc<CertCache>,
    auth: Option<std::sync::Arc<crate::auth::Auth>>,
    store: Option<std::sync::Arc<crate::user_store::UserStore>>,
) {
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let target = parts[1];
    let (host, port) = match target.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (target.to_string(), 443u16),
    };

    // For loopback targets: direct TCP tunnel (no SSL bump, no DPI).
    // Local services (Ollama, MCP, etc.) are trusted and pass through transparently.
    if forward::is_loopback(&host) {
        debug!(
            "connect_loopback host={} port={} client={}",
            host, port, peer_addr
        );

        // Read remaining headers until empty line
        let mut header_buf = vec![0u8; 8192];
        let mut header_len = 0;
        let mut stream = stream;
        loop {
            if header_len + 1 > header_buf.len() {
                return;
            }
            if stream
                .read_exact(&mut header_buf[header_len..header_len + 1])
                .await
                .is_err()
            {
                return;
            }
            header_len += 1;
            if header_len >= 4 && &header_buf[header_len - 4..header_len] == b"\r\n\r\n" {
                break;
            }
        }

        // Respond 200 and tunnel directly to the local service
        if stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        tunnel_tcp(stream, &host, port).await;
        return;
    }

    // Read remaining headers until empty line
    let mut header_buf = vec![0u8; 8192];
    let mut header_len = 0;
    let mut stream = stream;
    loop {
        if header_len + 1 > header_buf.len() {
            return;
        }
        if stream
            .read_exact(&mut header_buf[header_len..header_len + 1])
            .await
            .is_err()
        {
            return;
        }
        header_len += 1;
        if header_len >= 4 && &header_buf[header_len - 4..header_len] == b"\r\n\r\n" {
            break;
        }
    }

    // ── Proxy-Authorization check ─────────────────────────
    let mut user_db_id: Option<uuid::Uuid> = None;
    let user_id: Option<String> = if let Some(ref a) = auth {
        if let Some((u, p)) = crate::auth::Auth::parse_basic(&header_buf[..header_len]) {
            let client_ip = peer_addr.ip().to_string();
            match a.verify(&u, &p, &client_ip).await {
                Ok(au) => {
                    tracing::debug!("auth_ok user={} client={}", au.uid.label(), peer_addr);
                    user_db_id = au.db_row.as_ref().map(|r| r.id);
                    Some(au.uid.label())
                }
                Err(crate::auth::AuthErr::RateLimited) => {
                    tracing::warn!("auth_rate_limited user={} client={}", u, peer_addr);
                    let resp = a.resp_quota("rate limit exceeded, try again later");
                    let resp_str = format!(
                        "HTTP/1.1 {} Too Many Requests\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        429,
                        resp.body().len(),
                        resp.body()
                    );
                    let _ = stream.write_all(resp_str.as_bytes()).await;
                    return;
                }
                Err(crate::auth::AuthErr::QuotaExceeded(lim)) => {
                    tracing::warn!("auth_quota user={} limit={} client={}", u, lim, peer_addr);
                    let resp = a.resp_quota(&lim);
                    let resp_str = format!(
                        "HTTP/1.1 {} Too Many Requests\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        429,
                        resp.body().len(),
                        resp.body()
                    );
                    let _ = stream.write_all(resp_str.as_bytes()).await;
                    return;
                }
                Err(e) => {
                    tracing::warn!("auth_deny client={} error={}", peer_addr, e);
                    // Send 407
                    let resp = a.resp_407();
                    let resp_str = format!(
                        "HTTP/1.1 {} Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"{}\"\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        407,
                        a.resp_407()
                            .headers()
                            .get("Proxy-Authenticate")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("Basic realm=\"AI Proxy\""),
                        resp.body().len(),
                        resp.body()
                    );
                    let _ = stream.write_all(resp_str.as_bytes()).await;
                    return;
                }
            }
        } else if a.required() {
            // No Proxy-Authorization but auth is required → 407
            tracing::warn!("auth_missing client={}", peer_addr);
            let body = "Proxy authentication required";
            let resp = format!(
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"AI Proxy\"\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        } else {
            None // auth not required, allow anonymous
        }
    } else {
        None // no auth configured
    };

    // Rate-limited MITM CONNECT log: info only once per 60s per domain
    let connect_key = format!("connect:{}", host);
    if forward::should_warn(&connect_key, 60) {
        info!("connect host={} port={} client={}", host, port, peer_addr);
    } else {
        debug!("connect host={} port={} client={}", host, port, peer_addr);
    }

    // Respond 200 Connection Established
    if stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }

    // SSL Bump: generate per-domain certificate (graceful on error)
    let cert = match cert_cache.get_or_sign(&host).await {
        Ok(c) => c,
        Err(e) => {
            error!("cert_gen_failed host={} error={}", host, e);
            return;
        }
    };
    let mut server_config = match rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert.0.clone(), cert.1.clone_key())
    {
        Ok(c) => c,
        Err(e) => {
            error!("server_config_failed host={} error={}", host, e);
            return;
        }
    };
    // Force HTTP/1.1 ALPN — proxy only supports HTTP/1.1 after SSL bump
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            // Rate-limit SSL bump warnings: once per 60s per domain
            let bump_key = format!("sslbump:{}", host);
            if forward::should_warn(&bump_key, 60) {
                warn!("ssl_bump host={} error={}", host, e);
            } else {
                debug!("ssl_bump host={} error={}", host, e);
            }
            return;
        }
    };

    let io = TokioIo::new(tls_stream);
    let session_id = SessionId::new(None, &host);

    serve_http(
        io,
        peer_addr,
        config,
        upstream_connector,
        vault,
        audit_sender,
        session_id,
        user_id,
        user_db_id,
        store,
    )
    .await;
}

/// Plain HTTP handler: serve static files or forward requests through DPI pipeline.
#[allow(clippy::too_many_arguments)]
async fn handle_plain_http(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<config::Config>,
    upstream_connector: Arc<tokio_rustls::TlsConnector>,
    vault: Arc<Vault>,
    audit_sender: Arc<crate::audit::AuditChannel>,
    ca_pem: &str,
    _auth: Option<std::sync::Arc<crate::auth::Auth>>,
) {
    let io = TokioIo::new(stream);
    let ca_pem = ca_pem.to_string();
    let portal_html: String = include_str!("../../docs/portal.html").to_string();

    let svc = service_fn(move |req: Request<Incoming>| {
        let path = req.uri().path().to_string();

        // Serve portal on root
        if path == "/" || path == "/index.html" {
            let body = portal_html.clone();
            return Box::pin(async move {
                Ok(hyper::Response::builder()
                    .status(200)
                    .header("Content-Type", "text/html; charset=utf-8")
                    .body(forward::str_body(body))
                    .unwrap())
            })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = Result<forward::ProxyResponse, hyper::Error>,
                            > + Send,
                    >,
                >;
        }

        // Serve static files for proxy management
        // /ca.pem, /cert/pem, /cert — all serve the CA certificate
        if path == "/ca.pem" || path == "/cert/pem" || path == "/cert" {
            let body = ca_pem.clone();
            return Box::pin(async move {
                Ok(hyper::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/x-pem-file")
                    .body(forward::str_body(body))
                    .unwrap())
            })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = Result<forward::ProxyResponse, hyper::Error>,
                            > + Send,
                    >,
                >;
        }
        // Serve install.sh — unified installer that detects OS/arch,
        // downloads the right apx binary, and runs `apx install`.
        // No root, no system trust store changes.
        // (Also served at /install-user.sh for backward compatibility.)
        if path == "/install.sh" || path == "/install-user.sh" {
            let host = req
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost:8443");
            let body = generate_install_script(host);
            return Box::pin(async move {
                Ok(hyper::Response::builder()
                    .status(200)
                    .header("Content-Type", "text/plain")
                    .body(forward::str_body(body))
                    .unwrap())
            });
        }

        // Serve the user-space wrapper scripts (verbatim from the repo).
        if path == "/scripts/proxy-env"
            || path == "/scripts/with-proxy"
            || path == "/scripts/proxy-shell"
        {
            let body = match path.as_str() {
                "/scripts/proxy-env" => PROXY_ENV,
                "/scripts/with-proxy" => WITH_PROXY,
                _ => PROXY_SHELL,
            }
            .to_string();
            return Box::pin(async move {
                Ok(hyper::Response::builder()
                    .status(200)
                    .header("Content-Type", "text/plain")
                    .body(forward::str_body(body))
                    .unwrap())
            });
        }

        // Serve the Go CLI binary (apx) — cross-compiled per platform.
        // The unified installer downloads the right one based on OS/arch.
        if path.starts_with("/cli/apx-") {
            let binary: &[u8] = match path.as_str() {
                "/cli/apx-linux-amd64" => APX_LINUX_AMD64,
                "/cli/apx-linux-arm64" => APX_LINUX_ARM64,
                "/cli/apx-darwin-amd64" => APX_DARWIN_AMD64,
                "/cli/apx-darwin-arm64" => APX_DARWIN_ARM64,
                _ => &[],
            };
            if binary.is_empty() {
                return Box::pin(async move {
                    Ok(hyper::Response::builder()
                        .status(404)
                        .header("Content-Type", "text/plain")
                        .body(forward::str_body(format!("Unknown platform: {path}")))
                        .unwrap())
                });
            }
            // Safety: binary bytes are preserved as a String for hyper's body;
            // the Content-Type header marks it as octet-stream.
            let body: String = unsafe { String::from_utf8_unchecked(binary.to_vec()) };
            return Box::pin(async move {
                Ok(hyper::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/octet-stream")
                    .body(forward::str_body(body))
                    .unwrap())
            });
        }

        // Prometheus metrics endpoint
        if path == "/metrics" {
            let body = crate::metrics::render();
            return Box::pin(async move {
                Ok(hyper::Response::builder()
                    .status(200)
                    .header("Content-Type", "text/plain; version=0.0.4")
                    .body(forward::str_body(body))
                    .unwrap())
            });
        }

        // Serve PAC file (Proxy Auto-Configuration) — generated from config targets
        if path == "/proxy.pac" {
            let cfg = config.clone();
            let host = req
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost:8443");
            let proxy_addr = host.rsplit_once(':').map(|x| x.0).unwrap_or("localhost");
            let proxy_port: u16 = host
                .rsplit(':')
                .next()
                .unwrap_or("8443")
                .parse()
                .unwrap_or(8443);
            let pac = crate::pac::generate_pac(proxy_addr, proxy_port, &cfg.targets);
            return Box::pin(async move {
                Ok(hyper::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/x-ns-proxy-autoconfig")
                    .body(forward::str_body(pac))
                    .unwrap())
            });
        }

        // Forward to target through DPI pipeline
        let config = config.clone();
        let upstream_connector = upstream_connector.clone();
        let vault = vault.clone();
        let audit_sender = audit_sender.clone();

        // Determine target host from absolute URL or Host header
        let host = if let Some(host_str) = req.uri().host() {
            host_str.to_string()
        } else {
            req.headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
                .unwrap_or_default()
        };

        let session_id = SessionId::new(None, &host);

        Box::pin(async move {
            let ctx = crate::RequestContext {
                user_id: None,
                user_db_id: None,
                client_addr: peer_addr,
            };
            forward::forward_request(
                req,
                ctx,
                config,
                &upstream_connector,
                Some(&audit_sender),
                if vault.is_connected() {
                    Some(vault.as_ref())
                } else {
                    None
                },
                Some(&session_id),
                None,
                crate::semantic::get(),
            )
            .await
        })
    });

    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
        warn!("http_error client={} error={}", peer_addr, e);
    }
}

/// Serve HTTP with DPI/tokenization on a given IO stream.
/// Used by both MITM (after SSL bump) and plain HTTP proxy.
#[allow(clippy::too_many_arguments)]
async fn serve_http<S>(
    io: S,
    peer_addr: SocketAddr,
    config: Arc<config::Config>,
    upstream_connector: Arc<tokio_rustls::TlsConnector>,
    vault: Arc<Vault>,
    audit_sender: Arc<crate::audit::AuditChannel>,
    session_id: SessionId,
    user_id: Option<String>,
    user_db_id: Option<uuid::Uuid>,
    store: Option<std::sync::Arc<crate::user_store::UserStore>>,
) where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let _uid = user_id;
    let store_ref = store.clone();
    let svc = service_fn(move |req: Request<Incoming>| {
        let config = config.clone();
        let upstream_connector = upstream_connector.clone();
        let vault = vault.clone();
        let audit_sender = audit_sender.clone();
        let session_id = session_id.clone();
        let uid = _uid.clone();
        let store_here = store_ref.clone();

        async move {
            let ctx = crate::RequestContext {
                user_id: uid,
                user_db_id,
                client_addr: peer_addr,
            };
            forward::forward_request(
                req,
                ctx,
                config,
                &upstream_connector,
                Some(&audit_sender),
                if vault.is_connected() {
                    Some(vault.as_ref())
                } else {
                    None
                },
                Some(&session_id),
                store_here.as_deref(),
                crate::semantic::get(),
            )
            .await
        }
    });

    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
        warn!("http_error client={} error={}", peer_addr, e);
    }
}

/// Bidirectional TCP tunnel: pipe bytes between client and upstream.
/// Used for loopback CONNECT targets where SSL bump is not needed.
async fn tunnel_tcp(mut client: TcpStream, host: &str, port: u16) {
    let upstream_addr = format!("{}:{}", host, port);
    let upstream = match TcpStream::connect(&upstream_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!("tunnel_connect_failed target={} error={}", upstream_addr, e);
            return;
        }
    };
    let (mut client_rd, mut client_wr) = client.split();
    let (mut upstream_rd, mut upstream_wr) = upstream.into_split();
    // Pipe both directions concurrently; exit when either side closes
    tokio::select! {
        res = tokio::io::copy(&mut client_rd, &mut upstream_wr) => {
            if let Err(e) = res { debug!("tunnel_error direction=client_to_upstream error={}", e); }
        }
        res = tokio::io::copy(&mut upstream_rd, &mut client_wr) => {
            if let Err(e) = res { debug!("tunnel_error direction=upstream_to_client error={}", e); }
        }
    }
}

/// Generate the unified installer served at /install.sh.
/// Detects OS/arch, downloads the correct apx binary, and runs `apx install`.
/// No root, no system trust store changes. Works on Linux and macOS.
fn generate_install_script(proxy_host: &str) -> String {
    let (host_only, port) = match proxy_host.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p),
        _ => (proxy_host, "8443"),
    };
    format!(
        r##"#!/bin/bash
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
#   curl -sS http://{host}/install.sh | bash
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
#   apx aliases --install    # adds pi() {{ apx run pi "$@"; }} etc. to rc
#
# Full docs: http://{host}/  (open in browser)
# ══════════════════════════════════════════════════════════════════════
set -e
set -o pipefail

# Unset proxy env vars so inner requests don't loop through the proxy.
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy 2>/dev/null || true

HOST="{host}"
HOST_ONLY="{host_only}"
PORT="{port}"
BASE="http://${{HOST}}"
BIN="${{HOME}}/.local/bin"

echo "╔══════════════════════════════════════════════╗"
echo "║     AI Proxy — Unified Installer             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ─── Detect OS and architecture ──────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Normalize architecture names
case "${{ARCH}}" in
    x86_64|amd64)  ARCH="amd64"  ;;
    aarch64|arm64) ARCH="arm64"  ;;
    i386|i486|i686) ARCH="386"   ;;
    *) echo "ERROR: Unsupported architecture: ${{ARCH}}"; exit 1 ;;
esac

# Normalize OS names
case "${{OS}}" in
    linux)         OS="linux"   ;;
    darwin)        OS="darwin"  ;;
    *) echo "ERROR: Unsupported OS: ${{OS}}"
       echo "Supported: Linux, macOS"
       exit 1 ;;
esac

echo "  Detected: ${{OS}}/${{ARCH}}"
echo "  Proxy:    ${{HOST}}"
echo ""

# ─── Download the correct binary ─────────────────────────────────────
BINARY_NAME="apx-${{OS}}-${{ARCH}}"
BINARY_URL="${{BASE}}/cli/${{BINARY_NAME}}"
APX_PATH="${{BIN}}/apx"

echo "[1/2] Downloading apx (${{OS}}/${{ARCH}})..."
mkdir -p "${{BIN}}"
# Download to a temp file then atomically rename. Overwriting in place
# fails with ETXTBSY ('Text file busy') if a previous apx process is still
# running from that path — which breaks curl with error 23.
APX_TMP="${{APX_PATH}}.tmp.$$";
curl --noproxy '*' -fsS "${{BINARY_URL}}" -o "${{APX_TMP}}" </dev/null
chmod +x "${{APX_TMP}}"
mv -f "${{APX_TMP}}" "${{APX_PATH}}"
rm -f "${{APX_TMP}}" 2>/dev/null || true
echo "  Saved: ${{APX_PATH}}"
echo ""

# ─── Run apx install ─────────────────────────────────────────────────
echo "[2/2] Running apx install..."
# Redirect stdin from /dev/null so the parent curl pipe does not fill up
# when this script is invoked as 'curl ... | bash'.
"${{APX_PATH}}" --host "${{HOST_ONLY}}" --port "${{PORT}}" install </dev/null
"##,
        host = proxy_host,
        host_only = host_only,
        port = port,
    )
}

#[cfg(test)]
mod tests {
    use super::generate_install_script;

    /// The installer served at /install.sh must match the committed CI
    /// fixture (cli/testdata/install.sh) used by the macOS runner job.
    /// Regenerate the fixture with: cargo run --release (MITM mode) then
    /// curl -sS -H 'Host: 127.0.0.1:18445' http://127.0.0.1:18445/install.sh
    ///   -o cli/testdata/install.sh
    #[test]
    fn install_script_matches_fixture() {
        let expected = include_str!("../../cli/testdata/install.sh");
        assert_eq!(generate_install_script("127.0.0.1:18445"), expected);
    }
}
