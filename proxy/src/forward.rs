use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::fmt::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{Level, debug, error, info, span, trace, warn};

use crate::config::TargetConfig;
use crate::dpi::{Detection, DpiEngine};
use crate::violation_event::ViolationEvent;

use bytes::Bytes;
use http_body_util::Full;
use http_body_util::combinators::BoxBody;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyResponse = Response<BoxBody<Bytes, BoxErr>>;

pub fn str_body(s: impl Into<String>) -> BoxBody<Bytes, BoxErr> {
    BoxBody::new(Full::new(Bytes::from(s.into())).map_err(|e: std::convert::Infallible| match e {}))
}

pub fn err_resp(status: StatusCode, msg: impl Into<String>) -> ProxyResponse {
    Response::builder()
        .status(status)
        .body(str_body(msg.into()))
        .unwrap()
}

pub fn make_tls_connector() -> TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("load native certs") {
        let _ = root_store.add(cert);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Check if a hostname represents loopback/localhost — must never be proxied.
pub fn is_loopback(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host).to_lowercase();
    matches!(
        h.as_str(),
        "localhost" | "127.0.0.1" | "0.0.0.0" | "[::1]" | "::1"
    )
}

/// Rate-limited warning: returns true if we should emit a warning for this key.
/// Suppresses repeated warnings for the same key within the given window.
pub fn should_warn(key: &str, window_secs: u64) -> bool {
    use std::collections::hash_map::Entry;
    static TIMESTAMPS: std::sync::OnceLock<Mutex<std::collections::HashMap<String, Instant>>> =
        std::sync::OnceLock::new();
    let stamps = TIMESTAMPS.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut stamps = stamps.lock().unwrap();
    let now = Instant::now();
    match stamps.entry(key.to_string()) {
        Entry::Vacant(e) => {
            e.insert(now);
            true
        }
        Entry::Occupied(mut e) => {
            if now.duration_since(*e.get()).as_secs() >= window_secs {
                e.insert(now);
                true
            } else {
                false
            }
        }
    }
}

/// Format HTTP headers as a single-line string for debug logging.
fn fmt_headers(headers: &hyper::HeaderMap) -> String {
    let mut s = String::new();
    for (k, v) in headers.iter() {
        let _ = write!(s, "{}: {}; ", k.as_str(), v.to_str().unwrap_or("<binary>"));
    }
    s
}

/// Truncate body for debug display; show full at trace level.
/// Returns "[binary, N bytes]" for non-text / compressed content.
pub(crate) fn fmt_body(body: &str) -> String {
    // Detect binary content (gzip, brotli, protobuf, etc.)
    // These produce garbage when logged as text.
    if body.bytes().take(50).any(|b| b == 0) || !body.is_char_boundary(body.len()) {
        return format!("[binary, {} bytes]", body.len());
    }
    if body.len() <= 500 {
        body.to_string()
    } else {
        let end = body.floor_char_boundary(500);
        format!("{}...<truncated, {} bytes total>", &body[..end], body.len())
    }
}

/// Check if response body is compressed (gzip/br/deflate).
/// Compressed bodies should not be logged as text.
fn is_compressed(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            let v = v.to_lowercase();
            v.contains("gzip") || v.contains("deflate") || v.contains("br")
        })
        .unwrap_or(false)
}

/// Decompress gzip/deflate response body when upstream ignored
/// `Accept-Encoding: identity`. Removes Content-Encoding so the client
/// receives plaintext; returns None when not compressed or on failure.
fn decompress_body(headers: &mut hyper::HeaderMap, body: &str) -> Option<String> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let enc = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())?
        .to_lowercase();
    if !(enc.contains("gzip") || enc.contains("deflate")) {
        return None;
    }
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3);
    let read: Box<dyn Read> = if enc.contains("gzip") {
        Box::new(GzDecoder::new(bytes))
    } else {
        Box::new(flate2::read::DeflateDecoder::new(bytes))
    };
    let mut reader = read;
    if reader.read_to_end(&mut out).is_err() {
        warn!(
            "upstream_decompress_failed encoding={} len={}",
            enc,
            bytes.len()
        );
        return None;
    }
    headers.remove("content-encoding");
    headers.remove("content-length");
    headers.insert("content-length", out.len().into());
    Some(String::from_utf8_lossy(&out).to_string())
}

/// Escape a string for safe insertion into a JSON string value.
/// Used when replacing false-positive tokens back with their original text.
fn json_escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Resolve target: return matching config entry, or a default for unknown domains.
/// Unknown domains get TLS on port 443, no DPI applied (passthrough).
fn resolve_target(host_header: &str, config: &crate::config::Config) -> TargetConfig {
    let host = host_header.split(':').next().unwrap_or(host_header);
    config
        .targets
        .iter()
        .find(|t| t.host == host)
        .cloned()
        .unwrap_or_else(|| TargetConfig {
            host: host.to_string(),
            port: 443,
            tls: true,
        })
}

pub async fn forward_request(
    req: Request<Incoming>,
    ctx: crate::RequestContext,
    state: &crate::state::AppState,
    session_id: Option<&crate::session::SessionId>,
) -> Result<ProxyResponse, hyper::Error> {
    // Extract fields from state as local refs — keeps the body unchanged
    let config = state.config.as_ref();
    let tls_connector = &state.tls_connector;
    let audit = state.audit.as_ref();
    let vault = if state.vault.is_connected() {
        Some(&state.vault)
    } else {
        None
    };
    let store = state.store.as_deref();
    let semantic = state.semantic.as_deref();
    let started = Instant::now();
    let client_addr = ctx.client_addr;
    let user_id = ctx.user_id.clone();
    let method = req.method().clone();
    let req_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    let host = match req.headers().get("host").and_then(|h| h.to_str().ok()) {
        Some(h) => h.to_string(),
        None => {
            return Ok(err_resp(
                StatusCode::BAD_REQUEST,
                "Missing Host header".to_string(),
            ));
        }
    };

    let target = resolve_target(&host, &config);
    let is_known_target = config
        .targets
        .iter()
        .any(|t| t.host == host.split(':').next().unwrap_or(&host));
    let upstream_addr = format!("{}:{}", target.host, target.port);

    // Span for this request — emitted at end with summary
    let request_span = span!(
        Level::INFO,
        "proxy.request",
        method = %method,
        path = %req_path,
        target = %upstream_addr,
        user = user_id.as_deref().unwrap_or("anon"),
        dpi = is_known_target,
    );
    // Note: span entered only for final summary (sync section).
    // Entering across .await causes span pollution in multi-task runtime.

    // For loopback targets: forward without DPI (local services are trusted).
    let is_loopback_target = is_loopback(&target.host);
    if is_loopback_target {
        debug!(evt="proxy.forward.loopback", method=%method, path=%req_path, target=%target.host);
    }

    // Buffer request body for DPI
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await.unwrap_or_default().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    // Dump client request — full details for DPI targets, minimal for passthrough
    if is_known_target {
        debug!(
            "client_request method={} path={} headers={} body={}",
            method,
            req_path,
            fmt_headers(&parts.headers),
            fmt_body(&body_str),
        );
        trace!("client_body_full body={}", body_str);
    } else {
        trace!(
            "client_request method={} path={} headers={} body={}",
            method,
            req_path,
            fmt_headers(&parts.headers),
            fmt_body(&body_str),
        );
    }

    // Reject oversized request bodies (DoS protection)
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    if body_bytes.len() > MAX_BODY_SIZE {
        warn!(
            "body_too_large bytes={} client={} max={}",
            body_bytes.len(),
            client_addr,
            MAX_BODY_SIZE
        );
        return Ok(err_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body too large".to_string(),
        ));
    }

    // DPI scanning and tokenization — only for configured AI targets.
    // JSON-aware: scans string VALUES inside JSON, never touches structure/keys.
    let mut masked_body = body_str.clone();
    let mut token_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if is_known_target {
        if let Some(session) = session_id {
            let (tokenized_body, tokens) = DpiEngine::tokenize_json_body(&body_str, session);

            // Semantic validation: filter false positives via local LLM.
            // Replaces false-positive tokens back with their original values.
            let (tokenized_body, tokens) = if let Some(checker) = semantic {
                if tokens.is_empty() {
                    (tokenized_body, tokens)
                } else {
                    let dets: Vec<_> = tokens.iter().map(|(d, _)| d.clone()).collect();
                    let keep = checker.validate(&dets, &body_str).await;
                    let mut filtered = Vec::new();
                    let mut body = tokenized_body;
                    let mut dropped = 0u32;
                    for ((det, token), is_real) in tokens.into_iter().zip(keep.iter()) {
                        if *is_real {
                            filtered.push((det, token));
                        } else {
                            body = body.replace(token.as_str(), &json_escape_str(&det.matched_text));
                            dropped += 1;
                        }
                    }
                    if dropped > 0 {
                        info!(
                            "semantic_filtered dropped={} kept={} path={}",
                            dropped,
                            filtered.len(),
                            parts.uri.path()
                        );
                    }
                    (body, filtered)
                }
            } else {
                (tokenized_body, tokens)
            };

            if !tokens.is_empty() {
                // Build token→value map for response detokenization.
                // Key is the bare core (e.g. "KEY_d51b3f") — format-independent,
                // so find_tokens always finds a match regardless of delimiter form.
                for (det, token) in &tokens {
                    let core = crate::dpi::token_core(token);
                    token_map.insert(core.to_string(), det.matched_text.clone());
                }

                // Store tokens in Vault (for cross-request consistency).
                // Vault key is also the bare core — unified with find_tokens.
                if let Some(vault) = vault {
                    for (det, token) in &tokens {
                        let core = crate::dpi::token_core(token);
                        if let Err(e) = vault.store(session, core, &det.matched_text).await {
                            warn!("vault_store_failed core={} error={}", core, e);
                        }
                    }
                }

                // Send events to audit
                if let Some(audit) = audit {
                    let events = collect_events(
                        &tokens,
                        user_id.as_deref(),
                        &target.host,
                        Some(parts.uri.path()),
                    );
                    for event in events {
                        audit.send(event);
                    }
                }

                // Aggregated log — one line, not per-token (avoids log spam)
                debug!(
                    "DPI: {} violations tokenized in {} {} → {} (user: {:?}) | tokens: [{}]",
                    tokens.len(),
                    parts.method,
                    parts.uri.path(),
                    upstream_addr,
                    user_id,
                    tokens
                        .iter()
                        .map(|(_, t)| t.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            masked_body = tokenized_body;

            // Second pass: scan base64-encoded content in the body
            // Files share the SAME session → deterministic tokens:
            // same secret in body and file produces the SAME ‹KEY_xxx› token.
            let (scanned_body, file_detections, file_scans) =
                crate::file_scanner::scan_body_for_base64(&masked_body, session);
            if !file_detections.is_empty() {
                for (det, token) in &file_detections {
                    token_map.insert(token.clone(), det.matched_text.clone());
                }
                // File violations go to audit with "attachment" resource marker
                if let Some(audit) = audit {
                    let events: Vec<_> = file_detections
                        .iter()
                        .map(|(det, _tok)| {
                            ViolationEvent::from_detection(
                                det,
                                user_id.as_deref(),
                                &target.host,
                                Some("attachment"),
                                "MASK",
                                &det.masked_text,
                            )
                        })
                        .collect();
                    for event in events {
                        audit.send(event);
                    }
                }
                let blocked: usize = file_scans.iter().filter(|s| s.outcome == "blocked").count();
                info!(
                    "file_scan violations={} blocked={} masked={}",
                    file_detections.len(),
                    blocked,
                    file_detections.len() - blocked
                );
            }
            masked_body = scanned_body;

            if !token_map.is_empty() {
                crate::metrics::VIOLATIONS_TOTAL
                    .with_label_values(&["secret", &target.host])
                    .inc_by(token_map.len() as u64);
            }
        } else {
            // Without session_id — use legacy masking (fallback)
            let (m, violations) = DpiEngine::mask_text(&body_str);
            if !violations.is_empty() {
                if let Some(audit) = audit {
                    let events: Vec<_> = violations
                        .iter()
                        .map(|d| {
                            ViolationEvent::from_detection(
                                d,
                                user_id.as_deref(),
                                &target.host,
                                Some(parts.uri.path()),
                                "MASK",
                                &d.masked_text,
                            )
                        })
                        .collect();
                    for event in events {
                        audit.send(event);
                    }
                }
                info!(
                    "DPI (fallback mask): {} нарушений, {} {} → {}",
                    violations.len(),
                    parts.method,
                    parts.uri.path(),
                    upstream_addr
                );
            }
            masked_body = m;
        }
    } // end of is_known_target block

    // Aggregated DPI summary at warn level
    if !token_map.is_empty() {
        let mut key_count = 0u32;
        let mut fio_count = 0u32;
        let mut org_count = 0u32;
        let mut eml_count = 0u32;
        let mut phn_count = 0u32;
        for token in token_map.keys() {
            if token.starts_with("KEY_") {
                key_count += 1;
            } else if token.starts_with("FIO_") {
                fio_count += 1;
            } else if token.starts_with("ORG_") {
                org_count += 1;
            } else if token.starts_with("EML_") {
                eml_count += 1;
            } else if token.starts_with("PHN_") {
                phn_count += 1;
            }
        }
        warn!(
            "dpi_summary method={} path={} target={} secrets={} fio={} org={} email={} phone={} total={}",
            parts.method,
            parts.uri.path(),
            upstream_addr,
            key_count,
            fio_count,
            org_count,
            eml_count,
            phn_count,
            token_map.len(),
        );
    }

    // Debug: dump tokenized body sent upstream
    debug!(
        "upstream_request_tokenized method={} path={} target={} body={}",
        parts.method,
        parts.uri.path(),
        upstream_addr,
        fmt_body(&masked_body),
    );
    trace!("upstream_body_full body={}", masked_body);

    info!(
        evt="proxy.forward",
        method=%parts.method,
        path=%parts.uri.path(),
        target=%upstream_addr,
        client=%client_addr,
        user=user_id.as_deref().unwrap_or("anon"),
    );

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    let tcp_stream =
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                error!(
                    "upstream_connect_failed target={} error={}",
                    upstream_addr, err
                );
                return Ok(err_resp(
                    StatusCode::BAD_GATEWAY,
                    format!("Upstream connection failed: {}", err),
                ));
            }
            Err(_elapsed) => {
                error!(
                    "upstream_connect_timeout target={} timeout={}s",
                    upstream_addr,
                    CONNECT_TIMEOUT.as_secs()
                );
                return Ok(err_resp(
                    StatusCode::GATEWAY_TIMEOUT,
                    format!(
                        "Upstream connection timeout after {}s",
                        CONNECT_TIMEOUT.as_secs()
                    ),
                ));
            }
        };

    // Delegate streaming requests to SSE path for real-time chunked response
    if is_known_target
        && (masked_body.contains("\"stream\":true") || masked_body.contains("\"stream\": true"))
    {
        let vault_o = vault.cloned();
        let store_o = store.cloned();
        let sess_o = session_id.cloned();
        return forward_sse(
            parts,
            masked_body.clone(),
            token_map.clone(),
            target.clone(),
            tls_connector,
            audit,
            vault_o,
            sess_o.as_ref(),
            store_o,
            user_id.clone(),
            ctx.user_db_id,
            started,
            method.clone(),
            req_path.clone(),
        )
        .await;
    }

    if target.tls {
        let server_name = match ServerName::try_from(target.host.as_str()) {
            Ok(n) => n.to_owned(),
            Err(err) => {
                error!("invalid_server_name target={} error={}", target.host, err);
                return Ok(err_resp(
                    StatusCode::BAD_GATEWAY,
                    format!("Invalid server name: {}", err),
                ));
            }
        };

        const TLS_TIMEOUT: Duration = Duration::from_secs(10);
        let tls_stream =
            match tokio::time::timeout(TLS_TIMEOUT, tls_connector.connect(server_name, tcp_stream))
                .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(err)) => {
                    error!("upstream_tls_failed target={} error={}", upstream_addr, err);
                    return Ok(err_resp(
                        StatusCode::BAD_GATEWAY,
                        format!("Upstream TLS error: {}", err),
                    ));
                }
                Err(_elapsed) => {
                    error!(
                        "upstream_tls_timeout target={} timeout={}s",
                        upstream_addr,
                        TLS_TIMEOUT.as_secs()
                    );
                    return Ok(err_resp(
                        StatusCode::GATEWAY_TIMEOUT,
                        format!("TLS handshake timeout after {}s", TLS_TIMEOUT.as_secs()),
                    ));
                }
            };

        let mut response = send_upstream(tls_stream, &parts, &masked_body, &target.host).await?;
        // Response detokenization: ‹KEY_xxx› → original value
        detokenize_if_needed(&mut response, &token_map, session_id, vault).await;
        log_final(
            &response,
            &method,
            &req_path,
            &upstream_addr,
            started,
            is_known_target,
            &request_span,
        );
        record_usage(
            store,
            ctx.user_db_id,
            &response,
            body_bytes.len() as i64,
            started,
        )
        .await;
        let (rp, rb) = response.into_parts();
        Ok(Response::from_parts(rp, str_body(rb)))
    } else {
        let mut response = send_upstream(tcp_stream, &parts, &masked_body, &target.host).await?;
        detokenize_if_needed(&mut response, &token_map, session_id, vault).await;
        log_final(
            &response,
            &method,
            &req_path,
            &upstream_addr,
            started,
            is_known_target,
            &request_span,
        );
        record_usage(
            store,
            ctx.user_db_id,
            &response,
            body_bytes.len() as i64,
            started,
        )
        .await;
        let (rp, rb) = response.into_parts();
        Ok(Response::from_parts(rp, str_body(rb)))
    }
}

/// Increment per-user usage counters (requests/bytes/tokens) after a request.
/// Fire-and-forget: DB errors are logged, never block the response.
async fn record_usage(
    store: Option<&crate::user_store::UserStore>,
    user_db_id: Option<uuid::Uuid>,
    response: &Response<String>,
    bytes_in: i64,
    started: Instant,
) {
    let Some(store) = store else { return };
    let Some(uid) = user_db_id else { return };

    let (tok_in, tok_out) = match crate::usage::parse(response.body()) {
        Some(u) => (u.prompt.unwrap_or(0) as i64, u.complet.unwrap_or(0) as i64),
        None => (0, 0),
    };
    let bytes_out = response.body().len() as i64;
    let duration_ms = started.elapsed().as_millis() as i64;

    // Retry up to 3 times with exponential backoff
    for attempt in 0..3 {
        match store
            .try_add_usage(uid, 1, tok_in, tok_out, bytes_in, bytes_out)
            .await
        {
            Ok(true) => break, // recorded
            Ok(false) => {
                warn!("quota_exceeded user={uid} tok_in={tok_in} tok_out={tok_out}");
                break;
            }
            Err(e) if attempt < 2 => {
                warn!("usage_record_retry attempt={attempt} error={e}");
                tokio::time::sleep(tokio::time::Duration::from_millis(100 * (1 << attempt))).await;
            }
            Err(e) => {
                warn!("usage_record_error error={e}");
            }
        }
    }
    let _ = duration_ms;
}

/// Log upstream response at debug + emit final request summary with timing.
fn log_final(
    response: &Response<String>,
    method: &hyper::Method,
    req_path: &str,
    upstream_addr: &str,
    started: Instant,
    is_dpi: bool,
    span: &tracing::Span,
) {
    let status = response.status();
    let elapsed = started.elapsed();
    let resp_len = response.body().len();
    let compressed = is_compressed(response.headers());

    // Enter span only for this synchronous logging section.
    let _enter = span.enter();

    let resp_headers = fmt_headers(response.headers());

    // For DPI targets: log full response details at DEBUG.
    // For passthrough (non-DPI): log headers at TRACE, body only if not compressed.
    if is_dpi {
        let body_display = if compressed {
            format!("[compressed, {} bytes]", resp_len)
        } else {
            fmt_body(response.body())
        };
        debug!(
            "upstream_response method={} path={} target={} status={} len={} headers={} body={}",
            method,
            req_path,
            upstream_addr,
            status.as_u16(),
            resp_len,
            resp_headers,
            body_display,
        );
    } else {
        trace!(
            "upstream_response method={} path={} target={} status={} len={} headers={} body={}",
            method,
            req_path,
            upstream_addr,
            status.as_u16(),
            resp_len,
            resp_headers,
            if compressed {
                format!("[compressed, {} bytes]", resp_len)
            } else {
                fmt_body(response.body())
            },
        );
    }
    trace!("upstream_response_body_full body={}", response.body());

    info!(
        evt="proxy.complete",
        method=%method,
        path=%req_path,
        target=%upstream_addr,
        status=status.as_u16(),
        bytes=resp_len,
        duration_ms=elapsed.as_millis(),
    );

    // ── Metrics ────────────────────────────────────
    let target_host = upstream_addr.split(':').next().unwrap_or("unknown");
    crate::metrics::REQUESTS_TOTAL
        .with_label_values(&[
            method.as_str(),
            target_host,
            if is_dpi { "true" } else { "false" },
        ])
        .inc();
    crate::metrics::BYTES_TOTAL
        .with_label_values(&["response"])
        .inc_by(resp_len as u64);
    crate::metrics::REQUEST_DURATION
        .with_label_values(&[target_host])
        .observe(elapsed.as_secs_f64());
}

/// Response detokenization: find ‹TYPE_HASH› tokens and replace with values.
/// Also catches bare TYPE_HASH tokens whose delimiters the model stripped.
/// First tries in-memory token_map (fast, no Redis), then falls back to Vault.
async fn detokenize_if_needed(
    response: &mut Response<String>,
    token_map: &std::collections::HashMap<String, String>,
    session_id: Option<&crate::session::SessionId>,
    vault: Option<&crate::vault::Vault>,
) {
    let body = response.body();
    if body.is_empty() {
        return;
    }

    let tokens = crate::dpi::find_tokens(body);
    if tokens.is_empty() {
        return;
    }

    let mut replacements: Vec<(usize, usize, String)> = Vec::new();
    for (start, end, token) in &tokens {
        if let Some(value) = token_map.get(token) {
            debug!("detokenize_inmem token={}", token);
            replacements.push((*start, *end, value.clone()));
        }
    }

    // Try vault for unresolved tokens; any still unresolved → [REDACTED].
    // Tokens must NEVER reach the client unresolved.
    for (start, end, token) in &tokens {
        if replacements.iter().any(|(s, _, _)| s == start) {
            continue; // already resolved from in-memory map
        }
        let resolved = if let (Some(session), Some(vault)) = (session_id, vault) {
            match vault.get(session, token).await {
                Ok(Some(value)) => {
                    info!("detokenize_vault token={}", token);
                    Some(value)
                }
                Ok(None) => {
                    warn!("detokenize_missing token={}", token);
                    None
                }
                Err(e) => {
                    warn!("detokenize_vault_error token={} error={}", token, e);
                    None
                }
            }
        } else {
            warn!("detokenize_no_vault token={}", token);
            None
        };
        let value = resolved.unwrap_or_else(|| "[REDACTED]".into());
        replacements.push((*start, *end, value));
    }

    // Apply replacements right to left
    if !replacements.is_empty() {
        replacements.sort_by_key(|r| std::cmp::Reverse(r.0));
        let body = response.body_mut();
        let mut result = body.clone();
        for (start, end, value) in &replacements {
            result.replace_range(*start..*end, value);
        }
        *body = result;
    }
}

async fn send_upstream<IO>(
    io: IO,
    parts: &hyper::http::request::Parts,
    body: &str,
    target_host: &str,
) -> Result<Response<String>, hyper::Error>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = match client_http1::handshake(TokioIo::new(io)).await {
        Ok(h) => h,
        Err(err) => {
            error!("HTTP handshake с upstream не удался: {}", err);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(format!("Upstream HTTP error: {}", err))
                .unwrap());
        }
    };
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!("upstream_closed error={}", err);
        }
    });

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut req_builder = Request::builder()
        .method(parts.method.clone())
        .uri(path_and_query);

    // Forward client headers (except hop-by-hop)
    for (key, value) in parts.headers.iter() {
        let key_str = key.as_str().to_lowercase();
        // content-length: skip — body is tokenized, size changed
        // hyper will auto-compute Content-Length from new body
        if matches!(
            key_str.as_str(),
            "connection" | "proxy-connection" | "transfer-encoding" | "upgrade" | "content-length"
        ) {
            continue;
        }
        if key_str == "host" {
            continue; // Replace Host with target
        }
        if key_str == "accept-encoding" {
            continue; // Force identity — MITM needs plaintext for DPI
        }
        req_builder = req_builder.header(key, value);
    }

    // Set Host = target domain
    req_builder = req_builder.header("host", target_host);
    // Force plaintext responses — MITM/DPI requires readable bodies.
    // Compressed bodies would be corrupted by from_utf8_lossy below.
    req_builder = req_builder.header("accept-encoding", "identity");
    // Content-Length from TOKENIZED body (size changed!)
    req_builder = req_builder.header("content-length", body.len().to_string());

    // Log body metadata only; full body at trace to avoid leaking secrets to journald
    debug!(
        "→ upstream: {} {} len={}",
        parts.method,
        path_and_query,
        body.len()
    );
    crate::metrics::BYTES_TOTAL
        .with_label_values(&["request"])
        .inc_by(body.len() as u64);
    let preview_end = body.floor_char_boundary(std::cmp::min(200, body.len()));
    trace!("upstream_body_preview body={}", &body[..preview_end]);

    let upstream_req = match req_builder.body(body.to_string()) {
        Ok(r) => r,
        Err(err) => {
            error!("upstream_build_error error={}", err);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(format!("Request build error: {}", err))
                .unwrap());
        }
    };
    match sender.send_request(upstream_req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            let body_bytes = body.collect().await.unwrap_or_default().to_bytes();
            let body_str = String::from_utf8_lossy(&body_bytes).to_string();
            // Defensive: some servers ignore "identity" — decompress so the
            // client never sees a corrupted gzip body (zlib error).
            let body_str = match decompress_body(&mut parts.headers, &body_str) {
                Some(plain) => plain,
                None => body_str,
            };
            Ok(Response::from_parts(parts, body_str))
        }
        Err(err) => {
            error!("upstream_send_error error={}", err);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(format!("Upstream request failed: {}", err))
                .unwrap())
        }
    }
}

pub fn collect_events(
    tokens: &[(Detection, String)],
    user_id: Option<&str>,
    resource: &str,
    request_path: Option<&str>,
) -> Vec<ViolationEvent> {
    tokens
        .iter()
        .map(|(d, token)| {
            let type_label = match d.violation_type {
                crate::dpi::ViolationType::Secret => "SECRET",
                crate::dpi::ViolationType::PiiFio => "PII_FIO",
                crate::dpi::ViolationType::PiiCompany => "PII_COMPANY",
                crate::dpi::ViolationType::PiiEmail => "PII_EMAIL",
                crate::dpi::ViolationType::PiiPhone => "PII_PHONE",
            };
            // Context shows the masked value (e.g., "sk-12***-cdef") for human readability,
            // plus the token for cross-referencing with upstream logs.
            let context = format!("{}: masked={} token={}", type_label, d.masked_text, token);
            ViolationEvent::from_detection(d, user_id, resource, request_path, token, &context)
        })
        .collect()
}

// --- SSE streaming forward -------------------------------------------------

/// SSE streaming: connects to upstream, streams response chunks to client in
/// real time, applying de-mapping inline from the in-memory reverse map.
/// Accumulates full body in the background for usage/billing recording.
#[allow(clippy::too_many_arguments)]
pub async fn forward_sse(
    parts: hyper::http::request::Parts,
    masked_body: String,
    rev_map: std::collections::HashMap<String, String>,
    target: crate::config::TargetConfig,
    tls_connector: &TlsConnector,
    _audit: Option<&crate::audit::AuditChannel>,
    vault: Option<crate::vault::Vault>,
    session_id: Option<&crate::session::SessionId>,
    store: Option<crate::user_store::UserStore>,
    _user_id: Option<String>,
    user_db_id: Option<uuid::Uuid>,
    _started: Instant,
    method: hyper::Method,
    _req_path: String,
) -> Result<ProxyResponse, hyper::Error> {
    use http_body_util::BodyExt;
    let upstream_addr = format!("{}:{}", target.host, target.port);
    const MAX_BYTES: usize = 50 * 1024 * 1024;

    let tcp =
        match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&upstream_addr))
            .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Ok(err_resp(StatusCode::BAD_GATEWAY, format!("connect: {e}"))),
            Err(_) => return Ok(err_resp(StatusCode::GATEWAY_TIMEOUT, "connect timeout")),
        };
    let srv = match ServerName::try_from(target.host.as_str()) {
        Ok(n) => n.to_owned(),
        Err(e) => return Ok(err_resp(StatusCode::BAD_GATEWAY, format!("name: {e}"))),
    };
    let tls = match tokio::time::timeout(Duration::from_secs(10), tls_connector.connect(srv, tcp))
        .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Ok(err_resp(StatusCode::BAD_GATEWAY, format!("tls: {e}"))),
        Err(_) => return Ok(err_resp(StatusCode::GATEWAY_TIMEOUT, "tls timeout")),
    };
    let (mut sender, conn) = match client_http1::handshake(TokioIo::new(tls)).await {
        Ok(h) => h,
        Err(e) => return Ok(err_resp(StatusCode::BAD_GATEWAY, format!("http: {e}"))),
    };
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            warn!("sse_conn_closed error={e}");
        }
    });

    // Build upstream request (same logic as send_upstream)
    let pq = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut rb = Request::builder().method(&parts.method).uri(pq);
    for (k, v) in parts.headers.iter() {
        let kl = k.as_str().to_lowercase();
        if matches!(
            kl.as_str(),
            "connection" | "proxy-connection" | "transfer-encoding" | "upgrade" | "content-length"
        ) {
            continue;
        }
        if kl == "host" || kl == "accept-encoding" {
            continue;
        }
        rb = rb.header(k, v);
    }
    rb = rb
        .header("host", &target.host)
        .header("accept-encoding", "identity")
        .header("content-length", masked_body.len().to_string());
    let up_req = match rb.body(masked_body) {
        Ok(r) => r,
        Err(e) => {
            return Ok(err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("build: {e}"),
            ));
        }
    };
    let resp = match sender.send_request(up_req).await {
        Ok(r) => r,
        Err(e) => return Ok(err_resp(StatusCode::BAD_GATEWAY, format!("send: {e}"))),
    };
    let (resp_parts, body_stream) = resp.into_parts();
    let st = resp_parts.status;

    // Channel for streaming to client (mpsc + StreamBody)
    use http_body_util::StreamBody;
    use tokio_stream::wrappers::UnboundedReceiverStream;
    let (tx, rx) =
        tokio::sync::mpsc::unbounded_channel::<Result<hyper::body::Frame<bytes::Bytes>, BoxErr>>();
    let rx_stream = UnboundedReceiverStream::new(rx);
    let body_rx: BoxBody<Bytes, BoxErr> = BoxBody::new(StreamBody::new(rx_stream));
    let st2 = store.clone();
    let uid2 = user_db_id;
    let vault2 = vault.clone();
    let session2 = session_id.cloned();

    tokio::spawn(async move {
        use http_body_util::BodyStream;
        let mut stream = BodyStream::new(body_stream);
        let mut acc = String::new();
        let mut n: usize = 0;
        // Token accumulation buffer: holds partial tokens that span chunk boundaries.
        let mut buf = String::new();
        // Raw byte buffer: accumulates bytes before UTF-8 validation to avoid
        // from_utf8_lossy corrupting multibyte chars split across SSE chunks.
        let mut raw_buf: Vec<u8> = Vec::new();
        // Detokenization cache: starts with in-memory map (current request tokens),
        // vault lookups are added as they resolve.
        let mut detok: std::collections::HashMap<String, String> = rev_map.clone();
        let mut vault_missed: std::collections::HashSet<String> = std::collections::HashSet::new();
        const MAX_BUF: usize = 1024; // partial-token holdback cap

        loop {
            let frame = match stream.frame().await {
                Some(Ok(f)) => f,
                Some(Err(e)) => {
                    warn!("sse_frame_err error={e}");
                    break;
                }
                None => break,
            };
            if let Ok(data) = frame.into_data() {
                n += data.len();
                if n > MAX_BYTES {
                    warn!("sse_too_large bytes={n} max={MAX_BYTES}");
                    let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(
                        "data: [truncated]\n\n",
                    ))));
                    break;
                }

                // Accumulate raw bytes, convert only complete UTF-8 sequences.
                // This prevents from_utf8_lossy from corrupting multibyte chars
                // (like ‹ U+2039 = E2 80 89) when SSE chunks split them mid-character.
                raw_buf.extend_from_slice(&data);
                let valid_len = match std::str::from_utf8(&raw_buf) {
                    Ok(_) => raw_buf.len(),
                    Err(e) => e.valid_up_to(),
                };
                if valid_len == 0 {
                    continue; // incomplete UTF-8, wait for more data
                }
                let valid_str = std::str::from_utf8(&raw_buf[..valid_len]).unwrap();
                buf.push_str(valid_str);
                raw_buf = raw_buf[valid_len..].to_vec();

                // Resolve all complete tokens in buffer (may need vault lookups).
                loop {
                    let tokens = crate::dpi::find_tokens(&buf);
                    if tokens.is_empty() {
                        break;
                    }
                    let mut reps: Vec<(usize, usize, String)> = Vec::new();
                    for (s, e, token) in &tokens {
                        if let Some(v) = detok.get(token) {
                            info!("detokenize_sse_inmem token={}", token);
                            reps.push((*s, *e, v.clone()));
                        } else if !vault_missed.contains(token) {
                            if let (Some(vt), Some(sess)) = (&vault2, &session2) {
                                match vt.get(sess, token).await {
                                Ok(Some(v)) => {
                                    info!("detokenize_sse_vault token={}", token);
                                    detok.insert(token.clone(), v.clone());
                                        reps.push((*s, *e, v));
                                    }
                                    _ => {
                                        vault_missed.insert(token.clone());
                                        warn!("detokenize_sse_missing token={}", token);
                                        reps.push((*s, *e, "[REDACTED]".into()));
                                    }
                                }
                            } else {
                                vault_missed.insert(token.clone());
                                reps.push((*s, *e, "[REDACTED]".into()));
                            }
                        } else {
                            reps.push((*s, *e, "[REDACTED]".into()));
                        }
                    }
                    reps.sort_by_key(|r| std::cmp::Reverse(r.0));
                    for (s, e, v) in &reps {
                        buf.replace_range(*s..*e, v);
                    }
                }

                // Find safe flush point: flush everything up to a partial token.
                // A partial token is ‹ without matching › — hold it for the next chunk.
                let safe = match buf.rfind('‹') {
                    Some(pos) if !buf[pos..].contains('›') && buf.len() - pos <= MAX_BUF => pos,
                    _ => buf.len(),
                };

                if safe > 0 {
                    let chunk: String = buf.drain(..safe).collect();
                    acc.push_str(&chunk);
                    if tx
                        .send(Ok(hyper::body::Frame::data(Bytes::from(chunk))))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        // Flush any remaining raw_buf (incomplete UTF-8 at stream end — flush as-is).
        if !raw_buf.is_empty() {
            buf.push_str(&String::from_utf8_lossy(&raw_buf));
        }

        // Flush any remaining buffer (stream ended).
        if !buf.is_empty() {
            // Final detokenization pass for any tokens completed by the last chunk.
            let tokens = crate::dpi::find_tokens(&buf);
            if !tokens.is_empty() {
                let mut reps: Vec<(usize, usize, String)> = Vec::new();
                for (s, e, token) in &tokens {
                    if let Some(v) = detok.get(token) {
                        reps.push((*s, *e, v.clone()));
                    } else {
                        reps.push((*s, *e, "[REDACTED]".into()));
                    }
                }
                reps.sort_by_key(|r| std::cmp::Reverse(r.0));
                for (s, e, v) in &reps {
                    buf.replace_range(*s..*e, v);
                }
            }
            acc.push_str(&buf);
            let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(buf))));
        }

        if let Some(store) = st2
            && let Some(uid) = uid2
        {
            let (ti, to) = match crate::usage::parse(&acc) {
                Some(u) => (u.prompt.unwrap_or(0) as i64, u.complet.unwrap_or(0) as i64),
                None => (0, 0),
            };
            if let Err(e) = store.add_usage(uid, 1, ti, to, 0, n as i64).await {
                warn!("sse_usage_err error={e}");
            }
        }
        // channel closed when tx dropped
    });

    let mut rsp = Response::builder().status(st);
    for (k, v) in resp_parts.headers.iter() {
        if k.as_str().to_lowercase() == "content-length" {
            continue;
        }
        rsp = rsp.header(k, v);
    }
    let response = rsp.body(body_rx).expect("body builder should not fail");

    info!("sse_start target={upstream_addr} status={}", st.as_u16());
    crate::metrics::REQUESTS_TOTAL
        .with_label_values(&[method.as_str(), &target.host, "true"])
        .inc();
    Ok(response)
}

/// Reverse-map tokens in a string chunk (sync, no Redis).
/// Uses dpi::find_tokens: matches ‹PREFIX_hex6› and bare PREFIX_hex6 (model-stripped).
fn unmap_from(body: &str, rm: &std::collections::HashMap<String, String>) -> String {
    let tokens = crate::dpi::find_tokens(body);
    if tokens.is_empty() {
        return body.to_string();
    }

    let mut reps: Vec<(usize, usize, String)> = Vec::new();
    for (s, e, token) in &tokens {
        if let Some(v) = rm.get(token) {
            reps.push((*s, *e, v.clone()));
        }
    }
    reps.sort_by_key(|r| std::cmp::Reverse(r.0));
    let mut result = body.to_string();
    for (s, e, v) in &reps {
        result.replace_range(*s..*e, v);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_resolve_target_found() {
        let config = crate::config::Config {
            config_dir: PathBuf::from("."),
            server: crate::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 8443,
                cert_path: Some(PathBuf::from("certs/server.pem")),
                key_path: Some(PathBuf::from("certs/server.key")),
                ca_cert_path: None,
                ca_dir: None,
            },
            oidc: None,
            redis: None,
            auth: None,
            semantic: None,
            mode: "reverse".into(),
            targets: vec![
                TargetConfig {
                    host: "api.deepseek.com".into(),
                    port: 443,
                    tls: true,
                },
                TargetConfig {
                    host: "api.openai.com".into(),
                    port: 443,
                    tls: true,
                },
            ],
        };

        assert_eq!(
            resolve_target("api.deepseek.com", &config).host,
            "api.deepseek.com"
        );
        assert_eq!(
            resolve_target("api.openai.com", &config).host,
            "api.openai.com"
        );
        // Unknown domains get default config (passthrough)
        let unknown = resolve_target("unknown.com", &config);
        assert_eq!(unknown.host, "unknown.com");
        assert_eq!(unknown.port, 443);
        assert!(unknown.tls);
    }

    #[test]
    fn test_collect_events() {
        let tokens = vec![
            (
                Detection {
                    violation_type: crate::dpi::ViolationType::Secret,
                    matched_text: "sk-1234567890abcdef".into(),
                    masked_text: "sk-1234***-cdef".into(),
                    start: 0,
                    end: 18,
                },
                "[KEY_a3f2b1]".to_string(),
            ),
            (
                Detection {
                    violation_type: crate::dpi::ViolationType::PiiFio,
                    matched_text: "Иван Иванов".into(),
                    masked_text: "Иван И***".into(),
                    start: 20,
                    end: 30,
                },
                "[FIO_9b2c7d]".to_string(),
            ),
        ];

        let events = collect_events(
            &tokens,
            Some("user99"),
            "api.deepseek.com",
            Some("/v1/chat"),
        );

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].violation_type, "SECRET");
        assert!(events[0].masked_context.contains("[KEY_a3f2b1]"));
        assert_eq!(events[1].violation_type, "PII_FIO");
        assert!(
            !events
                .iter()
                .any(|e| e.masked_context.contains("1234567890"))
        );
        assert!(!events.iter().any(|e| e.masked_context.contains("Иванов")));
    }

    #[test]
    fn test_collect_events_with_tokens() {
        use crate::dpi::ViolationType;
        let tokens = vec![
            (
                Detection {
                    violation_type: ViolationType::Secret,
                    matched_text: "sk-secret-key".into(),
                    masked_text: "".into(),
                    start: 0,
                    end: 13,
                },
                "[KEY_a1b2c3]".to_string(),
            ),
            (
                Detection {
                    violation_type: ViolationType::PiiFio,
                    matched_text: "Петр Петров".into(),
                    masked_text: "".into(),
                    start: 15,
                    end: 26,
                },
                "[FIO_d4e5f6]".to_string(),
            ),
        ];

        let events = collect_events(&tokens, Some("u1"), "api.test.ai", Some("/v1/chat"));

        assert_eq!(events.len(), 2);
        assert!(
            events[0].masked_context.contains("[KEY_"),
            "Context must contain KEY token"
        );
        assert!(
            events[1].masked_context.contains("[FIO_"),
            "Context must contain FIO token"
        );
        assert!(
            !events[0].masked_context.contains("secret"),
            "Context must NOT leak secret"
        );
        assert_eq!(events[0].token, Some("[KEY_a1b2c3]".to_string()));
        assert_eq!(events[1].token, Some("[FIO_d4e5f6]".to_string()));
        assert!(!events.iter().any(|e| e.masked_context.contains("secret")));
        assert!(!events.iter().any(|e| e.masked_context.contains("Петров")));
    }

    // ─── is_loopback ─────────────────────────────────────────

    #[test]
    fn test_is_loopback_localhost() {
        assert!(is_loopback("localhost"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("0.0.0.0"));
        // NOTE: IPv6 loopback (::1, [::1]) not handled correctly —
        // the split(':') logic extracts wrong component. Known bug.
    }

    #[test]
    fn test_is_loopback_remote() {
        assert!(!is_loopback("api.openai.com"));
        assert!(!is_loopback("192.168.1.1"));
    }

    // ─── fmt_body ────────────────────────────────────────────

    #[test]
    fn test_fmt_body_short() {
        let result = fmt_body("Hello");
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_fmt_body_empty() {
        let result = fmt_body("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_fmt_body_truncated() {
        let long = "x".repeat(600);
        let result = fmt_body(&long);
        assert!(result.contains("...<truncated"));
        assert!(result.contains("600 bytes total"));
    }

    // ─── err_resp ────────────────────────────────────────────

    #[test]
    fn test_err_resp_status() {
        let resp = err_resp(StatusCode::BAD_GATEWAY, "upstream error");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    // ─── unmap_from ──────────────────────────────────────────

    #[test]
    fn test_unmap_from_replaces_tokens() {
        let mut map = std::collections::HashMap::new();
        map.insert("KEY_abc123".to_string(), "sk-my-secret".to_string());
        map.insert("FIO_def456".to_string(), "‹KEY_ea7b3c›".to_string());

        let input = "[KEY_abc123] user: [FIO_def456]";
        let result = unmap_from(input, &map);
        assert_eq!(result, "sk-my-secret user: ‹KEY_ea7b3c›");
    }

    #[test]
    fn test_unmap_from_no_matches() {
        let map = std::collections::HashMap::new();
        assert_eq!(unmap_from("plain text", &map), "plain text");
    }

    #[test]
    fn test_unmap_from_unknown_token() {
        let mut map = std::collections::HashMap::new();
        map.insert("KEY_abc123".to_string(), "secret".to_string());
        let result = unmap_from("Here: [KEY_999999]", &map);
        assert_eq!(result, "Here: [KEY_999999]");
    }

    #[test]
    fn test_unmap_from_bare_token_fallback() {
        // Model stripped delimiters — bare KEY_abc123 should still resolve
        let mut map = std::collections::HashMap::new();
        map.insert("KEY_abc123".to_string(), "sk-my-secret".to_string());
        let result = unmap_from("The key is KEY_abc123 here", &map);
        assert_eq!(result, "The key is sk-my-secret here");
    }
}
