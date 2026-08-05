//! Prometheus metrics for observability.
//! All metrics are registered once via lazy_static and updated from hot paths.

use once_cell::sync::Lazy;
use prometheus::{
    HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, register_histogram_vec,
    register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
};

// ─── Counters ───────────────────────────────────────

/// Total requests proxied, labeled by method/target/dpi.
pub static REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "ai_proxy_requests_total",
        "Total requests proxied",
        &["method", "target", "dpi"]
    )
    .expect("register requests_total")
});

/// DPI violations detected, labeled by type/target.
pub static VIOLATIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "ai_proxy_violations_total",
        "DPI violations detected",
        &["type", "target"]
    )
    .expect("register violations_total")
});

/// Upstream connection/TLS errors.
#[allow(dead_code)] // used when upstream error handling is added
pub static UPSTREAM_ERRORS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "ai_proxy_upstream_errors_total",
        "Upstream connection errors",
        &["target"]
    )
    .expect("register upstream_errors_total")
});

/// Total bytes proxied (request + response).
pub static BYTES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "ai_proxy_bytes_total",
        "Total bytes proxied",
        &["direction"]
    )
    .expect("register bytes_total")
});

// ─── Gauges ─────────────────────────────────────────

/// Active TCP connections.
pub static ACTIVE_CONNECTIONS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("ai_proxy_active_connections", "Active TCP connections")
        .expect("register active_connections")
});

/// Entries in LRU certificate cache.
pub static CERT_CACHE_ENTRIES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("ai_proxy_cert_cache_entries", "Entries in LRU cert cache")
        .expect("register cert_cache_entries")
});

/// Vault (Redis) connection state: 1=connected, 0=disconnected.
pub static VAULT_CONNECTED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "ai_proxy_vault_connected",
        "Vault Redis connection: 1=up, 0=down"
    )
    .expect("register vault_connected")
});

/// Unique users seen (from mTLS / OIDC).
#[allow(dead_code)] // populated in reverse proxy mode
pub static ACTIVE_USERS: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "ai_proxy_active_users",
        "Active users by source",
        &["source"]
    )
    .expect("register active_users")
});

/// File attachment scans by format and result.
pub static FILE_SCAN_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "ai_proxy_file_scan_total",
        "Attachment scans by format and result",
        &["format", "result"] // result: pass|masked|blocked
    )
    .expect("register file_scan_total")
});

// ─── Histograms ─────────────────────────────────────

/// Request end-to-end latency in seconds.
pub static REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "ai_proxy_request_duration_seconds",
        "Request end-to-end latency",
        &["target"],
        // Buckets: 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s, 10s, 30s
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0]
    )
    .expect("register request_duration")
});

/// Render all metrics in Prometheus exposition format.
pub fn render() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::new();
    encoder
        .encode(&metric_families, &mut buf)
        .expect("encode metrics");
    String::from_utf8(buf).expect("metrics utf8")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_metrics_render_does_not_panic() {
        // Register some metrics first so render() has data
        REQUESTS_TOTAL
            .with_label_values(&["GET", "test", "true"])
            .inc();
        BYTES_TOTAL.with_label_values(&["response"]).inc_by(100);
        let output = render();
        assert!(!output.is_empty());
        assert!(output.contains("ai_proxy_"));
    }

    #[test]
    fn test_metrics_registration_no_panics() {
        // All lazy_static metrics are registered on first access.
        // Just accessing them proves they register without panic.
        REQUESTS_TOTAL
            .with_label_values(&["GET", "test", "true"])
            .inc();
        VIOLATIONS_TOTAL
            .with_label_values(&["secret", "test"])
            .inc();
        BYTES_TOTAL.with_label_values(&["response"]).inc_by(100);
        ACTIVE_CONNECTIONS.inc();
        CERT_CACHE_ENTRIES.set(42);
        VAULT_CONNECTED.set(1);
        ACTIVE_USERS.with_label_values(&["test-user"]).set(1);
        FILE_SCAN_TOTAL.with_label_values(&["text", "masked"]).inc();
        REQUEST_DURATION.with_label_values(&["test"]).observe(0.5);

        // Render after mutation — should not panic
        let output = render();
        assert!(output.contains("ai_proxy_requests_total"));
        assert!(output.contains("ai_proxy_violations_total"));
        assert!(output.contains("ai_proxy_bytes_total"));
    }
}
