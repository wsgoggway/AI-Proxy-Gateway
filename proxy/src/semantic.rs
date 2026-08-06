//! LLM-based false-positive validation for DPI detections.
//!
//! After regex DPI finds potential secrets/PII, this module sends the detections
//! (with context) to a **local** Ollama instance for semantic validation.
//! The LLM decides whether each detection is a real secret/PII (keep) or a
//! false positive (code identifier, documentation, variable name — drop).
//!
//! Fail-open: on any error (Ollama down, timeout, parse failure, circuit open)
//! all detections are kept (return all-true).  This is the safe default — it is
//! better to over-tokenize than to leak a real secret.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::OnceLock;

/// Global instance — set once at startup, read in forward_request.
/// Avoids threading Option<Arc<SemanticChecker>> through 3 function layers.
static SEMANTIC: OnceLock<Option<Arc<SemanticChecker>>> = OnceLock::new();

/// Initialise the global SemanticChecker from config.  Called once at startup.
pub fn init(cfg: &crate::config::Config) {
    let checker = cfg.semantic.as_ref().filter(|s| s.enabled).map(|s| {
        tracing::info!("semantic_validation_enabled model={}", s.model);
        Arc::new(SemanticChecker::new(s))
    });
    let _ = SEMANTIC.set(checker);
}

/// Clone of the global SemanticChecker (if initialised and enabled).
/// Returns an owned Arc for use in AppState.
pub fn get() -> Option<std::sync::Arc<SemanticChecker>> {
    SEMANTIC.get().and_then(|opt| opt.clone())
}

use lru::LruCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};

use crate::config::SemanticConfig;
use crate::dpi::{Detection, ViolationType};

/// LLM-based false-positive validator backed by local Ollama.
pub struct SemanticChecker {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    timeout: Duration,
    semaphore: Arc<Semaphore>,
    cache: Arc<Mutex<LruCache<[u8; 32], Vec<bool>>>>,
    cb_state: Arc<Mutex<CircuitBreaker>>,
}

/// Circuit breaker — after N consecutive failures, disable for a cooldown.
struct CircuitBreaker {
    failures: u32,
    threshold: u32,
    cooldown: Duration,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    fn new(threshold: u32, cooldown_sec: u64) -> Self {
        Self {
            failures: 0,
            threshold,
            cooldown: Duration::from_secs(cooldown_sec),
            open_until: None,
        }
    }

    fn is_open(&self) -> bool {
        match self.open_until {
            Some(deadline) if Instant::now() < deadline => true,
            _ => false,
        }
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        if self.failures >= self.threshold {
            self.open_until = Some(Instant::now() + self.cooldown);
            info!(
                "semantic_circuit_open failures={} cooldown_secs={}",
                self.failures,
                self.cooldown.as_secs()
            );
        }
    }

    fn record_success(&mut self) {
        self.failures = 0;
        self.open_until = None;
    }
}

impl SemanticChecker {
    pub fn new(cfg: &SemanticConfig) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(cfg.timeout_ms))
                .no_proxy() // Ollama is local — never route through ourselves
                .build()
                .expect("reqwest client"),
            endpoint: cfg.endpoint.clone(),
            model: cfg.model.clone(),
            timeout: Duration::from_millis(cfg.timeout_ms),
            semaphore: Arc::new(Semaphore::new(cfg.concurrency)),
            cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(cfg.cache_size.max(1)).unwrap(),
            ))),
            cb_state: Arc::new(Mutex::new(CircuitBreaker::new(
                cfg.circuit_breaker_failures,
                cfg.circuit_breaker_cooldown_sec,
            ))),
        }
    }

    /// Validate detections against the original body text.
    ///
    /// Returns `Vec<bool>` — `true` = keep (real secret/PII), `false` = drop
    /// (false positive).  Length always equals `detections.len()`.
    ///
    /// Fail-open: on any error returns all-`true`.
    pub async fn validate(&self, detections: &[Detection], body: &str) -> Vec<bool> {
        let n = detections.len();
        if n == 0 {
            return Vec::new();
        }

        // ── Pre-filter: SECRET detections are always kept. ──────────────
        // The regex pipeline already filters for high-confidence patterns
        // (sk-*, AKIA*, Bearer *, etc).  Asking a 0.5B model to second-guess
        // these produces false drops — it sees "m***" and says "not real".
        let mut results = vec![true; n];
        let pii_indices: Vec<usize> = detections
            .iter()
            .enumerate()
 .filter(|(_, d)| {
                !matches!(d.violation_type, ViolationType::Secret)
            })
            .map(|(i, _)| i)
            .collect();

        // Nothing to validate via LLM — all were SECRET.
        if pii_indices.is_empty() {
            debug!("semantic_all_secrets items={} (skipped LLM)", n);
            return results;
        }

        // Batch guard: too many items → small model can't handle it.
        // Keep all (fail-open).
        if pii_indices.len() > 10 {
            debug!("semantic_skip_batch items={} (too many for LLM)", pii_indices.len());
            return results;
        }

        // Circuit breaker
        if self.cb_state.lock().await.is_open() {
            debug!("semantic_skip_circuit_open");
            return results;
        }

        // Build prompt for PII items only
        let pii_dets: Vec<&Detection> = pii_indices.iter().map(|&i| &detections[i]).collect();
        let prompt = build_prompt(&pii_dets, body);
        let cache_key = hash_str(&prompt);

        // Cache hit
        if let Some(cached) = self.cache.lock().await.get(&cache_key) {
            debug!("semantic_cache_hit items={}", pii_indices.len());
            let verdicts = apply_len(cached.clone(), pii_indices.len());
            for (k, &idx) in pii_indices.iter().enumerate() {
                results[idx] = verdicts[k];
            }
            return results;
        }

        // Acquire semaphore (backpressure)
        let _permit = match self.semaphore.acquire().await {
            Ok(p) => p,
            Err(_) => {
                warn!("semantic_skip_semaphore items={}", pii_indices.len());
                return results;
            }
        };

        // Call Ollama
        let start = Instant::now();
        match self.call_ollama(&prompt).await {
            Ok(verdicts) => {
                let elapsed = start.elapsed();
                let verdicts = apply_len(verdicts, pii_indices.len());
                let kept = verdicts.iter().filter(|&&v| v).count();
                let dropped = pii_indices.len() - kept;
                debug!(
                    "semantic_ok pii_items={} kept={} dropped={} elapsed_ms={}",
                    pii_indices.len(),
                    kept,
                    dropped,
                    elapsed.as_millis()
                );
                self.cache.lock().await.put(cache_key, verdicts.clone());
                self.cb_state.lock().await.record_success();
                for (k, &idx) in pii_indices.iter().enumerate() {
                    results[idx] = verdicts[k];
                }
                results
            }
            Err(e) => {
                warn!("semantic_error items={} error={}", pii_indices.len(), e);
                self.cb_state.lock().await.record_failure();
                results
            }
        }
    }

    /// Call Ollama `/api/chat` and parse the verdicts.
    async fn call_ollama(&self, prompt: &str) -> Result<Vec<bool>, String> {
        let req = OllamaRequest {
            model: &self.model,
            stream: false,
            options: OllamaOptions {
                temperature: 0.0,
                num_predict: 256,
            },
            messages: vec![OllamaMessage {
                role: "user",
                content: prompt,
            }],
        };

        let resp = self
            .client
            .post(format!("{}/api/chat", self.endpoint))
            .json(&req)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| format!("ollama_request: {e}"))?;

        let body: OllamaResponse = resp
            .json()
            .await
            .map_err(|e| format!("ollama_parse: {e}"))?;

        parse_verdicts(&body.message.content, /* expected */ 0)
    }
}

/// Truncate or pad verdicts to match detection count.
fn apply_len(verdicts: Vec<bool>, n: usize) -> Vec<bool> {
    if verdicts.len() == n {
        verdicts
    } else if verdicts.len() > n {
        verdicts[..n].to_vec()
    } else {
        let mut v = verdicts;
        v.resize(n, true); // pad with keep
        v
    }
}

fn build_prompt(detections: &[&Detection], body: &str) -> String {
    let mut out = String::with_capacity(1024 + detections.len() * 200);

    out.push_str(
        "Task: classify each item as REAL personal data (1) or false positive (0).\n\
         REAL (1): actual names of real people, real company names, real email addresses, real phone numbers.\n\
         FALSE (0): code identifiers, variable names, function names, URLs, paths, example/placeholder data, generic words.\n\n",
    );

    for (i, det) in detections.iter().enumerate() {
        let ctx = context_around(body, &det.matched_text, 50);
        let label = match det.violation_type {
            ViolationType::PiiFio => "PERSON_NAME",
            ViolationType::PiiCompany => "COMPANY_NAME",
            ViolationType::PiiEmail => "EMAIL",
            ViolationType::PiiPhone => "PHONE",
            _ => "OTHER",
        };
        out.push_str(&format!(
            "{}. [{}] \"{}\" — context: {}\n",
            i + 1,
            label,
            det.matched_text,
            ctx,
        ));
    }

    out.push_str("\nAnswer with ONLY comma-separated 1 or 0. Example: 1,0,1");
    out
}

fn hash_str(s: &str) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

/// Extract ±radius chars of context around the first occurrence of needle.
fn context_around(haystack: &str, needle: &str, radius: usize) -> String {
    match haystack.find(needle) {
        Some(pos) => {
            let mut start = pos.saturating_sub(radius);
            let mut end = (pos + needle.len() + radius).min(haystack.len());
            // find() returns a byte index; start/end may land mid-codepoint
            // on multibyte UTF-8 (e.g. Cyrillic). Snap to char boundaries
            // to avoid slicing panics.
            while start < end && start < haystack.len() && !haystack.is_char_boundary(start) {
                start += 1;
            }
            while end > start && !haystack.is_char_boundary(end) {
                end -= 1;
            }
            let snippet = &haystack[start..end];
            snippet.replace(needle, "[DETECTED]")
        }
        None => "[context unavailable]".into(),
    }
}
/// Parse the LLM response into booleans.
/// Handles: "1,0,1", "1, 0, 1", "1\n0\n1", "[1, 0, 1]", etc.
fn parse_verdicts(raw: &str, _expected: usize) -> Result<Vec<bool>, String> {
    // Reject prose: response must start with a digit or bracket.
    let first = raw.trim_start().chars().next();
    if !matches!(first, Some('0') | Some('1') | Some('[') | Some('{')) {
        return Err(format!("response not verdicts: {raw}"));
    }

    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == ',' || *c == '\n' || *c == ' ')
        .collect();

    let verdicts: Vec<bool> = cleaned
        .split([',', '\n', ' '])
        .filter_map(|s| {
            let t = s.trim();
            match t {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            }
        })
        .collect();

    if verdicts.is_empty() {
        Err(format!("no verdicts in response: {raw}"))
    } else {
        Ok(verdicts)
    }
}

// ─── Ollama API types ──────────────────────────────

#[derive(Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    stream: bool,
    options: OllamaOptions,
    messages: Vec<OllamaMessage<'a>>,
}

#[derive(Serialize)]
struct OllamaOptions {
    temperature: f64,
    num_predict: u32,
}

#[derive(Serialize)]
struct OllamaMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaRespMessage,
}

#[derive(Deserialize)]
struct OllamaRespMessage {
    content: String,
}

// ─── Tests ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn det(vt: ViolationType, text: &str) -> Detection {
        Detection {
            violation_type: vt,
            matched_text: text.into(),
            masked_text: "m***".into(),
            start: 0,
            end: text.len(),
        }
    }

    #[test]
    fn test_parse_verdicts_comma() {
        assert_eq!(parse_verdicts("1,0,1", 3).unwrap(), vec![true, false, true]);
    }

    #[test]
    fn test_parse_verdicts_spaces() {
        assert_eq!(parse_verdicts("1, 0, 1", 3).unwrap(), vec![true, false, true]);
    }

    #[test]
    fn test_parse_verdicts_newlines() {
        assert_eq!(parse_verdicts("0\n1\n0", 3).unwrap(), vec![false, true, false]);
    }

    #[test]
    fn test_parse_verdicts_garbage() {
        assert!(parse_verdicts("I think item 1 is real", 1).is_err());
    }

    #[test]
    fn test_apply_len_pad() {
        assert_eq!(apply_len(vec![true, false], 4), vec![true, false, true, true]);
    }

    #[test]
    fn test_apply_len_truncate() {
        assert_eq!(apply_len(vec![true, false, true], 2), vec![true, false]);
    }

    #[test]
    fn test_context_around() {
        let body = "prefix sk-abc123def456 suffix";
        let ctx = context_around(body, "sk-abc123def456", 10);
        assert!(ctx.contains("[DETECTED]"));
        assert!(ctx.contains("prefix"));
        assert!(ctx.contains("suffix"));
    }

    #[test]
    fn test_context_not_found() {
        assert_eq!(context_around("hello", "missing", 10), "[context unavailable]");
    }

    #[test]
    fn test_context_around_cyrillic_boundary() {
        // Cyrillic chars are 2 bytes; radius must not land mid-codepoint.
        let body = "а".repeat(100) + "sk-secret123" + &"б".repeat(100);
        let ctx = context_around(&body, "sk-secret123", 50);
        assert!(ctx.contains("[DETECTED]"));
    }

    #[test]
    fn test_build_prompt_structure() {
        let d1 = det(ViolationType::PiiEmail, "‹EML_c54971›");
        let d2 = det(ViolationType::PiiCompany, "Acme Corp");
        let dets: Vec<&Detection> = vec![&d1, &d2];
        let body = "contact ‹EML_c54971› at Acme Corp for details";
        let prompt = build_prompt(&dets, body);
        assert!(prompt.contains("EMAIL"));
        assert!(prompt.contains("COMPANY_NAME"));
        assert!(prompt.contains("[DETECTED]"));
        assert!(prompt.contains("comma-separated"));
    }

    #[test]
    fn test_circuit_breaker() {
        let mut cb = CircuitBreaker::new(3, 60);
        assert!(!cb.is_open());
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_open()); // threshold not reached
        cb.record_failure();
        assert!(cb.is_open()); // 3 failures → open
        cb.record_success();
        assert!(!cb.is_open()); // reset
    }
}
