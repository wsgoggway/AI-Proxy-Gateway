mod admin;
mod audit;
mod auth;
mod ca;
mod cert_cache;
mod config;
mod dpi;
mod file_scanner;
mod forward;
mod metrics;
mod mitm;
mod names_dict;
mod oidc;
mod pac;
mod rbac;
mod revocation;
mod semantic;
mod session;
mod tls;
mod token;
mod usage;
mod user_store;
mod vault;
mod violation_event;

use anyhow::Context;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Request context (extracted during TLS/auth phase)
#[derive(Clone)]
pub struct RequestContext {
    pub user_id: Option<String>,
    pub user_db_id: Option<uuid::Uuid>,
    pub client_addr: SocketAddr,
}

/// MITM mode: plain TCP listener → CONNECT → SSL bump → DPI → forward
async fn run_mitm_mode(config: Arc<config::Config>) -> anyhow::Result<()> {
    // CA for SSL Bump — uses config.ca_absolute_dir() from config file location
    let ca_dir = config.ca_absolute_dir();
    std::fs::create_dir_all(&ca_dir).ok();
    let ca =
        ca::CertificateAuthority::load_or_generate(&ca_dir.join("ca.pem"), &ca_dir.join("ca.key"))?;
    info!("ca_dir path={}", ca_dir.display());
    info!(
        "Install CA: sudo cp {} /etc/ca-certificates/trust-source/anchors/ai-proxy-ca.crt && sudo trust extract-compat",
        ca_dir.join("ca.pem").display()
    );

    let ca_pem = ca.ca_pem.clone();
    let cert_cache = Arc::new(cert_cache::CertCache::new(Arc::new(ca)));
    let upstream_connector = Arc::new(forward::make_tls_connector());

    // Semantic validation (LLM-based false-positive filter)
    semantic::init(&config);

    // Vault (Redis)
    // Vault (Redis) — must connect if configured, else fail-closed
    let vault = Arc::new({
        match config.redis.as_ref().map(|r| r.url.clone()) {
            Some(url) => match vault::Vault::connect(&url).await {
                Ok(v) => v,
                Err(e) => {
                    anyhow::bail!("vault_connect_failed url={url} error={e}");
                }
            },
            None => vault::Vault::new_disconnected(),
        }
    });
    crate::metrics::VAULT_CONNECTED.set(if vault.is_connected() { 1 } else { 0 });
    // ── Auth ───────────────────────────────────────
    let auth: Option<std::sync::Arc<crate::auth::Auth>> = match config.auth.as_ref() {
        Some(ac) => Some(std::sync::Arc::new(
            crate::auth::Auth::from_cfg(ac).await.expect("auth config"),
        )),
        None => None,
    };
    if auth.is_some() {
        info!(
            "auth_enabled backend={}",
            config.auth.as_ref().unwrap().backend
        );
    }

    // ── Admin API (JWT auth + Casbin RBAC) ───────────────
    if let (Some(auth_ref), Some(jwt_cfg)) = (
        auth.as_ref(),
        config.auth.as_ref().and_then(|a| a.jwt.as_ref()),
    ) {
        if let Some(store) = auth_ref.store() {
            // Initialize JWT token manager
            let tokens = Arc::new(crate::token::TokenManager::new(
                &jwt_cfg.secret,
                jwt_cfg.token_ttl_days,
            ));
            // Initialize Casbin RBAC + load roles from DB
            let rbac = Arc::new(crate::rbac::Rbac::new());
            if let Err(e) = rbac.reload_from_db(&store).await {
                warn!("rbac_reload_error error={e}");
            }
            // Admin bind: from [auth.admin] bind, or default 127.0.0.1:8444
            let admin_bind = config
                .auth
                .as_ref()
                .and_then(|a| a.admin.as_ref())
                .map(|a| a.bind.clone())
                .unwrap_or_else(|| "127.0.0.1:8444".into());
            let srv = crate::admin::AdminServer {
                bind: admin_bind,
                store,
                auth: auth.clone(),
                tokens,
                rbac,
            };
            tokio::spawn(async move {
                let _ = crate::admin::run_admin_server(srv).await;
            });
        } else {
            warn!("admin_api_skipped reason=no_db_backend");
        }
    } else {
        warn!("admin_api_skipped reason=no_jwt_or_db");
    }

    // Audit channel — batched aggregation to avoid log spam, persisted to DB
    let (audit_sender, mut audit_receiver) = audit::audit_channel();
    let audit_store = auth.as_ref().and_then(|a| a.store());
    tokio::spawn(async move {
        use std::collections::HashMap;
        use tokio::time::{Duration, interval};
        let mut batch: HashMap<(String, String, String), u32> = HashMap::new();
        let mut events: Vec<crate::violation_event::ViolationEvent> = Vec::new();
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                Some(event) = audit_receiver.recv() => {
                    let key = (event.violation_type.clone(), event.resource.clone(),
                               event.user_id.clone().unwrap_or_else(|| "anon".into()));
                    *batch.entry(key).or_insert(0) += 1;
                    events.push(event.clone());
                    debug!("audit type={} context={} target={} user={:?}",
                        event.violation_type, event.masked_context,
                        event.resource, event.user_id);
                }
                _ = ticker.tick() => {
                    if batch.is_empty() && events.is_empty() { continue; }
                    let total: u32 = batch.values().sum();
                    let summary: Vec<String> = batch.iter()
                        .map(|((vt, res, _user), n)| format!("{}={}({})", vt, n, res))
                        .collect();
                    info!("audit_batch count={} window=5s summary={}",
                        total, summary.join(", "));
                    // Persist to DB (fire-and-forget, errors logged)
                    if let Some(ref store) = audit_store
                        && !events.is_empty()
                            && let Err(e) = store.insert_audit_batch(&events).await {
                                warn!("audit_db_error error={e}");
                            }
                    batch.clear();
                    events.clear();
                }
            }
        }
    });
    let audit_sender = Arc::new(audit_sender);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .context("Invalid address")?;
    let listener = TcpListener::bind(addr).await?;
    info!("proxy_listening addr={} mode=mitm", addr);
    info!(
        "Use 'apx run <command>' to launch apps through the proxy (per-process, not system-wide)."
    );

    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("shutdown_signal_received");
        shutdown_clone.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let accept_fut = listener.accept();
        tokio::select! {
            result = accept_fut => {
                match result {
                    Ok((stream, peer_addr)) => {
                        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                            break;
                        }
                        let config = config.clone();
                        let upstream_connector = upstream_connector.clone();
                        let vault = vault.clone();
                        let audit_sender = audit_sender.clone();
                        let cert_cache = cert_cache.clone();
                        let ca_pem = ca_pem.clone();

                        let auth2 = auth.clone();
                        let store2 = auth.as_ref().and_then(|a| a.store());
                        tokio::spawn(async move {
                            crate::metrics::ACTIVE_CONNECTIONS.inc();
                            mitm::handle_connection(
                                stream,
                                peer_addr,
                                auth2,
                                store2,
                                config,
                                upstream_connector,
                                vault,
                                audit_sender,
                                cert_cache,
                                &ca_pem,
                            )
                            .await;
                            crate::metrics::ACTIVE_CONNECTIONS.dec();
                        });
                    }
                    Err(e) => warn!("accept_error error={}", e),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
                info!("shutdown_signal_received");
                break;
            }
        }
    }

    // Drain active connections with timeout
    info!("shutdown_draining active_connections");
    let drain_start = tokio::time::Instant::now();
    loop {
        let active = crate::metrics::ACTIVE_CONNECTIONS.get();
        if active == 0 {
            break;
        }
        if drain_start.elapsed() > tokio::time::Duration::from_secs(30) {
            warn!("shutdown_drain_timeout remaining_active={}", active);
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    info!("shutdown_complete");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --version
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("ai-proxy {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to initialize ring crypto provider");

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ai_proxy=info".into()),
        )
        .init();

    info!("ai_proxy_start version={}", env!("CARGO_PKG_VERSION"));
    let config_path =
        std::env::var("AI_PROXY_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config =
        Arc::new(config::Config::from_file(&config_path).context("Failed to load config")?);

    // Mode selection: MITM vs reverse proxy
    if config.mode == "mitm" {
        return run_mitm_mode(config).await;
    }

    // ─── Reverse proxy mode ──────────────────────

    let mtls_enabled = config.server.ca_cert_path.is_some();
    let oidc_enabled = config.oidc.is_some();

    // Vault (Redis) — must connect if configured, else fail-closed
    let vault = Arc::new({
        let redis_url = config.redis.as_ref().map(|r| r.url.clone());
        match redis_url {
            Some(ref url) => match vault::Vault::connect(url).await {
                Ok(v) => v,
                Err(e) => {
                    anyhow::bail!("vault_connect_failed url={url} error={e}");
                }
            },
            None => vault::Vault::new_disconnected(),
        }
    });

    // Initialize RevocationChecker (blacklist — separate from Vault)
    let revocation_checker = Arc::new({
        let redis_url = config.redis.as_ref().map(|r| r.url.clone());
        let mut checker = revocation::RevocationChecker::new(redis_url.as_deref());
        if let Some(ref url) = redis_url {
            if let Err(e) = checker.connect(url).await {
                warn!("revocation_connect_error error={}", e);
            } else {
                info!("revocation_connected");
            }
        }
        checker
    });

    let upstream_connector = Arc::new(forward::make_tls_connector());

    // Semantic validation (optional LLM-based false-positive filter)
    let semantic_checker: Option<Arc<semantic::SemanticChecker>> = config
        .semantic
        .as_ref()
        .filter(|s| s.enabled)
        .map(|s| {
            info!("semantic_validation_enabled model={}", s.model);
            Arc::new(semantic::SemanticChecker::new(s))
        });

    let (audit_sender, mut audit_receiver) = audit::audit_channel();
    tokio::spawn(async move {
        use std::collections::HashMap;
        use tokio::time::{Duration, interval};
        let mut batch: HashMap<(String, String, String), u32> = HashMap::new();
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                Some(event) = audit_receiver.recv() => {
                    let key = (event.violation_type.clone(), event.resource.clone(),
                               event.user_id.clone().unwrap_or_else(|| "anon".into()));
                    *batch.entry(key).or_insert(0) += 1;
                    debug!(
                        "audit type={} context={} target={} user={:?}",
                        event.violation_type, event.masked_context, event.resource, event.user_id
                    );
                }
                _ = ticker.tick() => {
                    if batch.is_empty() { continue; }
                    let total: u32 = batch.values().sum();
                    let summary: Vec<String> = batch.iter()
                        .map(|((vt, res, _user), n)| format!("{}={}({})", vt, n, res))
                        .collect();
                    info!("audit_batch count={} window=5s summary={}",
                        total, summary.join(", "));
                    batch.clear();
                }
            }
        }
    });
    let audit_sender = Arc::new(audit_sender);

    info!("tls_load_start");
    let default_cert = PathBuf::from("certs/server.pem");
    let default_key = PathBuf::from("certs/server.key");
    let server_config = tls::load_server_config(
        config.server.cert_path.as_ref().unwrap_or(&default_cert),
        config.server.key_path.as_ref().unwrap_or(&default_key),
        config.server.ca_cert_path.as_deref(),
    )?;
    let acceptor: TlsAcceptor = tls::build_acceptor(server_config);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .context("Invalid address сервера")?;
    let listener = TcpListener::bind(addr).await?;
    info!("proxy_listening addr={} mode=reverse", addr);

    let shutdown_rev = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_rev_clone = shutdown_rev.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("shutdown_signal_received");
        shutdown_rev_clone.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    loop {
        if shutdown_rev.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let accept_fut = listener.accept();
        tokio::select! {
            result = accept_fut => {
                match result {
                    Ok((stream, peer_addr)) => {
                        if shutdown_rev.load(std::sync::atomic::Ordering::SeqCst) {
                            break;
                        }
                        let acceptor = acceptor.clone();
                let config = config.clone();
                let upstream_connector = upstream_connector.clone();
                let vault = vault.clone();
                let revocation_checker = revocation_checker.clone();
                let audit_sender = audit_sender.clone();
                let semantic_checker = semantic_checker.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let (_io, conn) = tls_stream.get_ref();
                            let user_id = conn
                                .peer_certificates()
                                .and_then(|certs| certs.first())
                                .and_then(tls::extract_user_id_from_cert);

                            let needs_oidc = mtls_enabled && user_id.is_none();

                            let ctx = RequestContext {
                                user_id: user_id.clone(),
                                user_db_id: None,
                                client_addr: peer_addr,
                            };

                            let io = TokioIo::new(tls_stream);
                            let config = config.clone();
                            let upstream_connector = upstream_connector.clone();
                            let vault = vault.clone();
                            let revocation_checker = revocation_checker.clone();
                            let audit_sender = audit_sender.clone();
                            let semantic_checker = semantic_checker.clone();
                            let ctx = ctx.clone();

                            let svc = service_fn(move |req: Request<Incoming>| {
                                let config = config.clone();
                                let upstream_connector = upstream_connector.clone();
                                let vault = vault.clone();
                                let revocation_checker = revocation_checker.clone();
                                let audit_sender = audit_sender.clone();
                                let ctx = ctx.clone();
                                let semantic_checker = semantic_checker.clone();
                                let needs_oidc = needs_oidc;

                                async move {
                                    let path = req.uri().path().to_string();

                                    // PAC file
                                    if path == "/proxy.pac" {
                                        let pac_content = pac::generate_pac(
                                            &config.server.host,
                                            config.server.port,
                                            &config.targets,
                                        );
                                        return Ok(Response::builder()
                                            .status(200)
                                            .header(
                                                "Content-Type",
                                                "application/x-ns-proxy-autoconfig",
                                            )
                                            .body(forward::str_body(pac_content))
                                            .unwrap());
                                    }

                                    // OIDC callback
                                    if path == "/oidc/callback" && oidc_enabled {
                                        return handle_oidc_callback(&req, &config);
                                    }

                                    if needs_oidc
                                        && oidc_enabled
                                        && let Some(ref oidc_cfg) = config.oidc
                                    {
                                        let state = uuid::Uuid::new_v4().to_string();
                                        let auth_url = match (oidc::OidcConfig {
                                            client_id: oidc_cfg.client_id.clone(),
                                            issuer_url: oidc_cfg.issuer_url.clone(),
                                            redirect_uri: oidc_cfg.redirect_uri.clone(),
                                        })
                                        .auth_url(&state) {
                                            Ok(url) => url,
                                            Err(e) => return Ok(forward::err_resp(StatusCode::INTERNAL_SERVER_ERROR, e)),
                                        };
                                        return Ok(oidc::build_redirect_response(&auth_url));
                                    }

                                    if let Some(ref uid) = ctx.user_id
                                        && revocation_checker.is_revoked(uid).await
                                    {
                                        warn!(
                                            "revoked_user user={} client={}",
                                            uid, ctx.client_addr
                                        );
                                        return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .header("Content-Type", "application/json")
                                            .body(forward::str_body(r#"{"error":"session_revoked"}"#.to_string()))
                                            .unwrap());
                                    }

                                    let is_websocket = req
                                        .headers()
                                        .get("upgrade")
                                        .and_then(|v| v.to_str().ok())
                                        .map(|v| v.to_lowercase() == "websocket")
                                        .unwrap_or(false);

                                    if is_websocket {
                                        info!("websocket client={}", ctx.client_addr);
                                        return Ok(Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .body(forward::str_body(
                                                "WebSocket proxying: not yet integrated"
                                                    .to_string()),
                                            )
                                            .unwrap());
                                    }

                                    // Determine session_id and effective_vault
                                    let target_host = req
                                        .headers()
                                        .get("host")
                                        .and_then(|h| h.to_str().ok())
                                        .unwrap_or("unknown");
                                    let session_id = crate::session::SessionId::new(
                                        ctx.user_id.as_deref(),
                                        target_host,
                                    );
                                    let effective_vault = if vault.is_connected() {
                                        Some(vault.as_ref())
                                    } else {
                                        None
                                    };

                                    forward::forward_request(
                                        req,
                                        ctx,
                                        config,
                                        &upstream_connector,
                                        Some(&audit_sender),
                                        effective_vault,
                                        Some(&session_id),
                                        None,
                                        semantic_checker.as_deref(),
                                    )
                                    .await
                                }
                            });

                            if let Err(err) = http1::Builder::new().serve_connection(io, svc).await
                            {
                                warn!("http_error client={} error={}", peer_addr, err);
                            }
                        }
                        Err(err) => {
                            if mtls_enabled {
                                warn!("mtls_failed client={} error={}", peer_addr, err);
                            } else {
                                warn!("tls_error client={} error={}", peer_addr, err);
                            }
                        }
                    }
                });
            }
                        Err(err) => warn!("accept_error error={}", err),
                    }
                }
            _ = tokio::signal::ctrl_c() => {
                shutdown_rev.store(true, std::sync::atomic::Ordering::SeqCst);
                info!("shutdown_signal_received");
                break;
            }
        }
    }

    info!("shutdown_draining active_connections reverse");
    let drain_start = tokio::time::Instant::now();
    loop {
        let active = crate::metrics::ACTIVE_CONNECTIONS.get();
        if active == 0 {
            break;
        }
        if drain_start.elapsed() > tokio::time::Duration::from_secs(30) {
            warn!("shutdown_drain_timeout remaining_active={}", active);
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    info!("shutdown_complete reverse");
    Ok(())
}

fn handle_oidc_callback(
    req: &Request<Incoming>,
    config: &config::Config,
) -> Result<forward::ProxyResponse, hyper::Error> {
    let _oidc_cfg = match &config.oidc {
        Some(c) => c,
        None => {
            return Ok(Response::builder()
                .status(500)
                .body(forward::str_body("OIDC not configured".to_string()))
                .unwrap());
        }
    };

    let query = req.uri().query().unwrap_or("");
    let code = query
        .split('&')
        .find(|p| p.starts_with("code="))
        .map(|p| &p[5..])
        .unwrap_or("");

    if code.is_empty() {
        return Ok(Response::builder()
            .status(400)
            .body(forward::str_body("Missing authorization code".to_string()))
            .unwrap());
    }

    let cookie = format!(
        "ai_proxy_session=mvp-session-{}; HttpOnly; Secure; Path=/; SameSite=Lax",
        code
    );

    Ok(Response::builder()
        .status(302)
        .header("Location", "/")
        .header("Set-Cookie", &cookie)
        .body(forward::str_body(
            "Authentication successful. You may close this page.".to_string(),
        ))
        .unwrap())
}
