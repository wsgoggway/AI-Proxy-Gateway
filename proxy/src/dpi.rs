/// DPI engine: detect secrets and PII in request text
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::session::SessionId;

/// Violation types detected by DPI
#[derive(Debug, Clone, PartialEq)]
pub enum ViolationType {
    Secret,
    PiiFio,
    PiiCompany,
    PiiEmail,
    PiiPhone,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub violation_type: ViolationType,
    pub matched_text: String,
    pub masked_text: String,
    pub start: usize,
    pub end: usize,
}

// ─── Secret patterns ───────────────────────────

/// Secret prefix keywords — format-specific only.
/// Generic words ("token", "password", "bearer") were removed: they matched
/// everywhere in code/config text causing massive false positives. KV detection
/// via SECRET_KV_REGEX handles `password: <value>` and `token: <value>` patterns
/// with proper value-length requirements (12+ chars).
static SECRET_PREFIXES: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build([
            "sk-",             // OpenAI / DeepSeek API key prefix
            "pk-",             // Stripe public key prefix
            "authorization:",  // Authorization: Bearer xxx
            "x-api-key:",      // X-API-Key: xxx
        ])
        .expect("build secret prefixes AC")
});

/// Regex for secret key-value pairs.
/// Requires value of 12+ chars to reduce false positives on short words.
static SECRET_KV_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(api_key|apikey|api-key|access_token|access-token|token|secret|password|bearer)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{12,})"#,
    )
    .expect("secret kv regex")
});

/// Regex for API keys (sk-... / pk-...)
/// Strict: requires sk- or pk- prefix, then 20+ alphanumeric chars with dashes.
/// No more 'api-' prefix (caused false positives like 'api-reference').
static API_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:sk|pk)-(?:[a-zA-Z0-9]{20,}|[a-zA-Z0-9]{4,}-[a-zA-Z0-9]{16,})"#)
        .expect("api key regex")
});

// ─── PII patterns ──────────────────────────────

/// Russian full name patterns
static PII_FIO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+)?)"#).expect("pii fio regex")
});

/// Email address patterns
static PII_EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"#).expect("pii email regex")
});

/// Company name patterns (LLC/JSC/...)
static PII_COMPANY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:ООО|ЗАО|ОАО|АО|ИП|ПАО|НКО)\s+["«]?[А-ЯЁA-Z][\w\s\-\.]{1,40}"#)
        .expect("pii company regex")
});

/// Russian phone patterns
static PII_PHONE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:\+7|8)\s*[\(]?\d{3}[\)]?\s*\d{3}[\s-]?\d{2}[\s-]?\d{2}"#)
        .expect("pii phone regex")
});


/// Service usernames — emails with these local parts are NOT personal data.
/// Only MACHINE accounts (never used as real human contact): root, daemon, etc.
/// Ambiguous ones (info@, support@, contact@) are intentionally EXCLUDED.
const SERVICE_USERS: &[&str] = &[
    "root", "admin", "administrator", "www", "web", "mail", "smtp",
    "imap", "pop", "pop3", "postmaster", "postgres", "mysql", "redis",
    "mongodb", "node", "python", "java", "ruby", "php", "nginx", "apache",
    "daemon", "bin", "sys", "sysadmin", "operator", "sshd",
    "git", "gitlab", "jenkins", "build", "ci", "deploy",
    "ubuntu", "debian", "centos", "fedora", "alpine", "arch",
    "grafana", "prometheus", "elastic", "kibana", "logstash",
    "nobody", "ftp", "sftp", "ldap", "dns", "dhcp",
    "ai_proxy", "proxy", "gateway", "vault", "certbot", "acme",
];

/// Returns true if the matched "email" is actually a service address,
/// connection string component, or machine identifier — not personal data.
fn is_service_address(email: &str, text: &str, start: usize) -> bool {
    let (local, domain) = match email.split_once('@') {
        Some(parts) => parts,
        None => return false,
    };

    // Service username (root@, admin@, postgres@, git@, ...)
    if SERVICE_USERS.contains(&local.to_lowercase().as_str()) {
        return true;
    }

    // IP address as domain (user@127.0.0.1, admin@10.0.0.1, ...)
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    // Connection string: preceded by "://" within 60 chars (URL like redis://:pass@host)
    let lookback = start.saturating_sub(60);
    let before = text.get(lookback..start).unwrap_or("");
    if before.contains("://") {
        return true;
    }

    // SSH-style: `‹EML_2a61db›` preceded by `ssh` or `git clone`
    if before.ends_with("ssh ") || before.ends_with("git@") || before.contains("git clone ") {
        return true;
    }

    false
}
/// DPI detector: finds secrets and PII in text
pub struct DpiEngine;

impl DpiEngine {
    /// Scan text and return all detected violations
    pub fn scan(text: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        Self::scan_secrets(text, &mut detections);

        Self::scan_pii(text, &mut detections);

        detections.sort_by_key(|d| d.start);
        Self::deduplicate(&mut detections);

        detections
    }

    fn scan_secrets(text: &str, detections: &mut Vec<Detection>) {
        for mat in SECRET_PREFIXES.find_iter(text) {
            let prefix = &text[mat.start()..mat.end()];
            let after = &text[mat.end()..];
            let value_end = after
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                .unwrap_or(after.len().min(64));
            let value = &after[..value_end];

            if value.len() >= 16 {
                let matched = format!("{}{}", prefix, value);
                let start = mat.start();
                let end = start + matched.len();
                let masked = mask_secret(&matched);

                if !detections.iter().any(|d| d.start < end && d.end > start) {
                    detections.push(Detection {
                        violation_type: ViolationType::Secret,
                        matched_text: matched,
                        masked_text: masked,
                        start,
                        end,
                    });
                }
            }
        }

        for cap in SECRET_KV_REGEX.captures_iter(text) {
            if let Some(m) = cap.get(0) {
                let start = m.start();
                let end = m.end();
                if !detections.iter().any(|d| d.start < end && d.end > start) {
                    detections.push(Detection {
                        violation_type: ViolationType::Secret,
                        matched_text: m.as_str().to_string(),
                        masked_text: mask_secret_kv(m.as_str()),
                        start,
                        end,
                    });
                }
            }
        }

        for cap in API_KEY_REGEX.captures_iter(text) {
            if let Some(m) = cap.get(0) {
                let start = m.start();
                let end = m.end();
                if !detections.iter().any(|d| d.start < end && d.end > start) {
                    detections.push(Detection {
                        violation_type: ViolationType::Secret,
                        matched_text: m.as_str().to_string(),
                        masked_text: mask_secret(m.as_str()),
                        start,
                        end,
                    });
                }
            }
        }
    }

    fn scan_pii(text: &str, detections: &mut Vec<Detection>) {
        for cap in PII_FIO_REGEX.captures_iter(text) {
            if let Some(m) = cap.get(0) {
                let matched = m.as_str();
                // Check if first OR second word is a known Russian first name.
                // Russian names can be in order "Name Surname" or "Surname Name".
                // This filters out false positives like "Обзор Личного",
                // "Описание Статуса", "Действие К..." etc.
                let words: Vec<&str> = matched.split_whitespace().collect();
                let is_name = words
                    .iter()
                    .take(2)
                    .any(|w| crate::names_dict::is_russian_first_name(w));
                if !is_name {
                    continue;
                }
                let start = m.start();
                let end = m.end();
                if !detections.iter().any(|d| d.start < end && d.end > start) {
                    detections.push(Detection {
                        violation_type: ViolationType::PiiFio,
                        matched_text: matched.to_string(),
                        masked_text: mask_fio(matched),
                        start,
                        end,
                    });
                }
            }
        }

        // Email — skip service addresses (root@host, postgres@127.0.0.1, etc.)
        for cap in PII_EMAIL_REGEX.captures_iter(text) {
            if let Some(m) = cap.get(0) {
                let start = m.start();
                let end = m.end();
                if !detections.iter().any(|d| d.start < end && d.end > start)
                    && !is_service_address(m.as_str(), text, start)
                {
                    detections.push(Detection {
                        violation_type: ViolationType::PiiEmail,
                        matched_text: m.as_str().to_string(),
                        masked_text: mask_email(m.as_str()),
                        start,
                        end,
                    });
                }
            }
        }


        for cap in PII_PHONE_REGEX.captures_iter(text) {
            if let Some(m) = cap.get(0) {
                let matched = m.as_str();
                // Validate against Russian phone number rules — filters out
                // INN, account numbers, dates, and other numeric IDs.
                if !is_valid_russian_phone(matched) {
                    continue;
                }
                let start = m.start();
                let end = m.end();
                if !detections.iter().any(|d| d.start < end && d.end > start) {
                    detections.push(Detection {
                        violation_type: ViolationType::PiiPhone,
                        matched_text: matched.to_string(),
                        masked_text: mask_phone(matched),
                        start,
                        end,
                    });
                }
            }
        }
    }

    /// Remove overlapping matches (keep first by priority)
    fn deduplicate(detections: &mut Vec<Detection>) {
        let mut i = 0;
        while i < detections.len() {
            let mut j = i + 1;
            while j < detections.len() {
                if detections[i].start < detections[j].end
                    && detections[i].end > detections[j].start
                {
                    detections.remove(j);
                } else {
                    j += 1;
                }
            }
            i += 1;
        }
    }

    /// Apply masking to entire text
    pub fn mask_text(text: &str) -> (String, Vec<Detection>) {
        let detections = Self::scan(text);
        let mut result = text.to_string();

        for det in detections.iter().rev() {
            result.replace_range(det.start..det.end, &det.masked_text);
        }

        (result, detections)
    }

    /// Apply tokenization (v2.0): replace values with ‹TYPE_hash› placeholders.
    pub fn tokenize_text(text: &str, session: &SessionId) -> (String, Vec<(Detection, String)>) {
        let detections = Self::scan(text);
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        for det in detections.iter() {
            let token = generate_token(&det.matched_text, &det.violation_type, session);
            tokens.push((det.clone(), token));
        }
        for (det, token) in tokens.iter().rev() {
            result.replace_range(det.start..det.end, token);
        }

        (result, tokens)
    }

    /// JSON-aware tokenization: parse body as JSON, tokenize only string VALUES.
    /// Never touches JSON keys, structure, or non-string types.
    /// Falls back to raw tokenize_text if body is not valid JSON.
    pub fn tokenize_json_body(
        body: &str,
        session: &SessionId,
    ) -> (String, Vec<(Detection, String)>) {
        match serde_json::from_str::<serde_json::Value>(body) {
            Ok(mut json) => {
                let mut all_tokens = Vec::new();
                Self::tokenize_json_value(&mut json, session, &mut all_tokens);
                (
                    serde_json::to_string(&json).unwrap_or_else(|_| body.to_string()),
                    all_tokens,
                )
            }
            Err(_) => {
                // Not valid JSON (e.g., form-encoded, text/plain) — use raw tokenization
                Self::tokenize_text(body, session)
            }
        }
    }

    /// Recursively walk JSON value and tokenize string nodes.
    fn tokenize_json_value(
        value: &mut serde_json::Value,
        session: &SessionId,
        all_tokens: &mut Vec<(Detection, String)>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (_, v) in map.iter_mut() {
                    Self::tokenize_json_value(v, session, all_tokens);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr.iter_mut() {
                    Self::tokenize_json_value(v, session, all_tokens);
                }
            }
            serde_json::Value::String(s) => {
                let (tokenized, tokens) = Self::tokenize_text(s, session);
                if !tokens.is_empty() {
                    all_tokens.extend(tokens);
                    *s = tokenized;
                }
            }
            _ => {}
        }
    }
}

// ─── Tokenization (new v2.0 functions) ──────────

/// Type prefixes for tokenization placeholders
const TYPE_PREFIX: &[(&str, ViolationType)] = &[
    ("KEY", ViolationType::Secret),
    ("FIO", ViolationType::PiiFio),
    ("ORG", ViolationType::PiiCompany),
    ("EML", ViolationType::PiiEmail),
    ("PHN", ViolationType::PiiPhone),
];

/// Token placeholder delimiters.
/// Uses Unicode single guillemets (U+2039 / U+203A): ‹KEY_a3f2b1›
/// AI models treat these as literal text.  The previous $...$ delimiters were
/// abandoned because models interpret $...$ as LaTeX inline-math and strip the
/// dollar signs from their output, breaking detokenization.
pub const TOKEN_OPEN: &str = "\u{2039}"; // ‹
pub const TOKEN_CLOSE: &str = "\u{203a}"; // ›

/// Regex matching a fully-delimited token: ‹TYPE_hex6›
pub static TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\u{2039}([A-Z]+_[a-f0-9]{6})\u{203a}").expect("token regex"));

/// Regex matching a bare token whose delimiters were stripped by the model:
/// KEY_a3f2b1 (without ‹ ›).  Restricted to known type prefixes to avoid
/// false positives; the token_map lookup is the ultimate guard.
pub static TOKEN_BARE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:KEY|FIO|ORG|EML|PHN)_[a-f0-9]{6}").expect("bare token regex")
});

/// Scan *body* for token placeholders, returning `(byte_start, byte_end,
/// full_token_with_delimiters)` triples sorted left-to-right.
/// Primary matches use ‹…› delimiters; a fallback also catches bare tokens
/// whose delimiters the model stripped, skipping any that sit inside a
/// primary match to avoid double-processing.
pub fn find_tokens(body: &str) -> Vec<(usize, usize, String)> {
    let mut out: Vec<(usize, usize, String)> = Vec::new();

    // Primary: ‹TYPE_hex6›
    for cap in TOKEN_RE.captures_iter(body) {
        if let Some(m) = cap.get(0) {
            out.push((m.start(), m.end(), m.as_str().to_string()));
        }
    }

    // Fallback: bare TYPE_hex6 not already covered by a primary match
    for cap in TOKEN_BARE_RE.captures_iter(body) {
        if let Some(m) = cap.get(0) {
            let (s, e) = (m.start(), m.end());
            let covered = out.iter().any(|(ps, pe, _)| *ps <= s && e <= *pe);
            if !covered {
                let full = format!("{}{}{}", TOKEN_OPEN, m.as_str(), TOKEN_CLOSE);
                out.push((s, e, full));
            }
        }
    }

    out.sort_by_key(|(s, _, _)| *s);
    out
}

/// Get prefix for violation type
fn prefix_for_type(vt: &ViolationType) -> &'static str {
    TYPE_PREFIX
        .iter()
        .find(|(_, t)| t == vt)
        .map(|(p, _)| *p)
        .unwrap_or("UNK")
}

/// Generate deterministic token for a value.
/// Format: ‹TYPE_HASH› (Unicode guillemet-delimited).
/// AI models treat ‹› as literal text, preserving the token intact.
pub fn generate_token(value: &str, violation_type: &ViolationType, session: &SessionId) -> String {
    let prefix = prefix_for_type(violation_type);
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher.update(session.to_redis_key().as_bytes());
    let hash = hex::encode(hasher.finalize());
    let short_hash = &hash[..6];
    format!("{}{}_{}{}", TOKEN_OPEN, prefix, short_hash, TOKEN_CLOSE)
}

// ─── Masking functions ─────────────────────────

/// Secret masking: sk-abc123xyz → sk-***-xyz
pub fn mask_secret(s: &str) -> String {
    let len = s.chars().count();
    if len <= 4 {
        return "***".to_string();
    }
    // Find separator (prefix ends with - or :)
    let prefix_end = s.find(['-', ':']).unwrap_or(0);
    let prefix = &s[..=prefix_end];
    let value = &s[prefix_end + 1..];

    if value.len() <= 8 {
        format!("{}***", prefix)
    } else {
        let first4: String = value.chars().take(4).collect();
        let last4: String = value
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{}{}***-{}", prefix, first4, last4)
    }
}

/// KV masking: api_key=secret123 → api_key=***-t123
fn mask_secret_kv(s: &str) -> String {
    if let Some(pos) = s.find(['=', ':']) {
        let key = &s[..=pos];
        let val = s[pos + 1..].trim_matches(|c: char| c == '"' || c == '\'' || c == ' ');
        let masked = mask_secret(val);
        format!("{}{}", key, masked)
    } else {
        mask_secret(s)
    }
}

/// Name masking: Ivan Ivanov → Ivan I***
pub fn mask_fio(s: &str) -> String {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() {
        return "***".to_string();
    }
    let masked: Vec<String> = parts
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if i == 0 {
                p.to_string()
            } else {
                let first_char = p.chars().next().unwrap_or('*');
                format!("{}***", first_char)
            }
        })
        .collect();
    masked.join(" ")
}

/// Email masking: user@company.com → u***@c***.com
pub fn mask_email(s: &str) -> String {
    if let Some(at) = s.find('@') {
        let local = &s[..at];
        let domain = &s[at + 1..];
        let masked_local = if local.len() <= 2 {
            "***".to_string()
        } else {
            // Use chars — email local is ASCII but be defensive.
            let first: String = local.chars().take(1).collect();
            format!("{}***", first)
        };
        let masked_domain = if let Some(dot) = domain.rfind('.') {
            let dom = &domain[..dot];
            let tld = &domain[dot..];
            format!("{}***{}", &dom[..1.min(dom.len())], tld)
        } else {
            format!("{}***", &domain[..1.min(domain.len())])
        };
        format!("{}@{}", masked_local, masked_domain)
    } else {
        "***@***".to_string()
    }
}

/// Company masking: LLC Romashka → LLC R***, ООО «Ромашка» → ООО «Р***
pub fn mask_company(s: &str) -> String {
    let parts: Vec<&str> = s.splitn(2, [' ', '"', '«']).collect();
    if parts.len() >= 2 {
        let legal = parts[0];
        let name = parts[1].trim_matches(|c: char| c == '"' || c == '«' || c == '»');
        // Use literal quote strings — &parts[1][..1] panics on '«' (2-byte UTF-8).
        let quote = if parts[1].starts_with('"') {
            "\""
        } else if parts[1].starts_with('«') {
            "«"
        } else {
            ""
        };
        let first_char = name.chars().next().unwrap_or('*');
        format!("{} {}{}{}***", legal, quote, first_char, "")
    } else {
        // Take first 4 chars, not bytes — Cyrillic chars are 2 bytes each.
        let prefix: String = s.chars().take(4).collect();
        format!("{}***", prefix)
    }
}

/// Validate a text match as a real Russian phone number.
/// Rules:
/// - Exactly 11 digits (8/+7 prefix + 10 digit number)
/// - Area code must be valid: 9XX (mobile) or known 3-digit landline code
/// - Rejects 1XX area codes (no such codes in Russia)
/// - Rejects INN, account numbers, dates that look like phone numbers
fn is_valid_russian_phone(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();

    // Russian phone numbers are always 11 digits
    if digits.len() != 11 {
        return false;
    }

    // Must start with 8 (trunk) or 7 (country code)
    if !digits.starts_with('8') && !digits.starts_with('7') {
        return false;
    }

    // Extract area code (3 digits after prefix)
    let area_code = &digits[1..4];

    // Mobile: 9XX (900-999) — all valid
    if area_code.starts_with('9') {
        return true;
    }

    // Known Russian landline area codes (3-digit ABC codes).
    // Source: https://ru.wikipedia.org/wiki/Телефонные_коды_России
    const LANDLINE_CODES: &[&str] = &[
        "301", "302", "302", "309", "341", "342", "343", "345", "346", "347", "349", "350", "351",
        "352", "353", "354", "355", "356", "357", "358", "359", "365", "366", "367", "381", "382",
        "383", "384", "385", "387", "388", "390", "391", "394", "395", "398", "401", "411", "413",
        "415", "416", "421", "423", "424", "426", "427", "434", "435", "442", "475", "472", "473",
        "474", "481", "482", "483", "484", "485", "486", "487", "491", "492", "493", "494", "495",
        "496", "498", "499", "811", "812", "813", "814", "815", "816", "817", "818", "820", "821",
        "822", "823", "824", "826", "831", "833", "834", "835", "836", "841", "842", "843", "844",
        "845", "846", "847", "848", "849", "851", "852", "855", "861", "862", "863", "864", "865",
        "866", "867", "869", "871", "872", "873", "877", "878", "879", "881", "882", "884", "885",
        "886", "891", "892", "893", "896", "897",
    ];

    LANDLINE_CODES.contains(&area_code)
}

/// Phone masking: +7 999 123-45-67 → +7 999 ***-**-67
pub fn mask_phone(s: &str) -> String {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 10 {
        let last4 = &digits[digits.len() - 4..];
        let prefix = if digits.starts_with('7') || digits.starts_with('8') {
            &s[..s
                .find(|c: char| c.is_whitespace() || c == '(' || c == '-')
                .map(|i| i + 1)
                .unwrap_or(2)]
        } else {
            ""
        };
        format!("{}***-**-{}", prefix, last4)
    } else {
        "***".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_api_key() {
        let text = r#"{"api_key": "sk-1234567890abcdef", "text": "hello"}"#;
        let (masked, detections) = DpiEngine::mask_text(text);
        assert!(
            !masked.contains("1234567890abcdef"),
            "Secret should be masked: {}",
            masked
        );
        assert!(
            detections
                .iter()
                .any(|d| d.violation_type == ViolationType::Secret)
        );
    }

    #[test]
    fn test_detect_sk_key() {
        let text = "Authorization: Bearer sk-abc123xyz-secret";
        let (masked, detections) = DpiEngine::mask_text(text);
        assert!(!masked.contains("abc123xyz"));
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_detect_fio() {
        let text = "Привет, я Иван Иванов из отдела разработки";
        let (masked, detections) = DpiEngine::mask_text(text);
        assert!(
            !masked.contains("Иван Иванов"),
            "FIO should be masked: {}",
            masked
        );
        assert!(
            detections
                .iter()
                .any(|d| d.violation_type == ViolationType::PiiFio)
        );
    }

    #[test]
    fn test_detect_fio_full() {
        let text = "Петров Пётр Сергеевич отвечает за проект";
        let (masked, detections) = DpiEngine::mask_text(text);
        assert!(!masked.contains("Петров Пётр Сергеевич"));
        assert!(
            detections
                .iter()
                .any(|d| d.violation_type == ViolationType::PiiFio)
        );
    }

    #[test]
    fn test_detect_email() {
        let text = "мой email: user@company.com, пишите";
        let (masked, detections) = DpiEngine::mask_text(text);
        assert!(
            !masked.contains("user@company.com"),
            "Email should be masked: {}",
            masked
        );
        assert!(
            detections
                .iter()
                .any(|d| d.violation_type == ViolationType::PiiEmail)
        );
    }

    #[test]
    fn test_service_address_filtered() {
        let at = "@";
        // Service accounts → NOT detected as PII
        let service = [
            format!("root{at}server.example.com"),
            format!("postgres{at}db.internal.org"),
            format!("git{at}github.com:user/repo.git"),
            format!("deploy{at}192.168.1.5.nip.io"),
        ];
        for text in &service {
            let (_, dets) = DpiEngine::mask_text(text);
            assert!(
                !dets.iter().any(|d| d.violation_type == ViolationType::PiiEmail),
                "Service address should NOT be PII: {:?}",
                text
            );
        }
        // Real personal email → IS detected
        let personal = format!("john.doe{at}gmail.com");
        let (_, dets) = DpiEngine::mask_text(&personal);
        assert!(
            dets.iter().any(|d| d.violation_type == ViolationType::PiiEmail),
            "Real email should be detected: {:?}",
            personal
        );
    }


    #[test]
    fn test_detect_phone() {
        let text = "позвони мне +7 999 123-45-67 завтра";
        let (masked, detections) = DpiEngine::mask_text(text);
        assert!(
            !masked.contains("123-45-67"),
            "Phone should be masked: {}",
            masked
        );
        assert!(
            detections
                .iter()
                .any(|d| d.violation_type == ViolationType::PiiPhone)
        );
    }

    #[test]
    fn test_detect_phone_mobile_8() {
        // 8 9XX format — Russian mobile with trunk prefix
        let text = "Мой телефон 8 921 555-44-33";
        let (masked, detections) = DpiEngine::mask_text(text);
        assert!(!masked.contains("555-44-33"));
        assert!(
            detections
                .iter()
                .any(|d| d.violation_type == ViolationType::PiiPhone)
        );
    }

    #[test]
    fn test_detect_phone_landline_spb() {
        // 812 — St. Petersburg landline
        let text = "Звоните 8 812 345-67-89";
        let detections = DpiEngine::scan(text);
        assert!(
            detections
                .iter()
                .any(|d| d.violation_type == ViolationType::PiiPhone)
        );
    }

    #[test]
    fn test_no_false_positive_phone_inn() {
        // INN-like numbers starting with 81... — NOT a phone number
        let texts = [
            "Номер счёта 8 123 456-78-90",
            "Код заказа 81234567890",
            "ИНН 8 156 789-01-23",
        ];
        for text in &texts {
            let detections = DpiEngine::scan(text);
            let phone_detections: Vec<_> = detections
                .iter()
                .filter(|d| d.violation_type == ViolationType::PiiPhone)
                .collect();
            assert!(
                phone_detections.is_empty(),
                "False positive PHONE in '{}': {:?}",
                text,
                phone_detections
                    .iter()
                    .map(|d| &d.matched_text)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_no_panic_on_utf8_boundary() {
        // Truncation at byte boundary inside multi-byte char must not panic.
        let russian = "а".repeat(400); // 800 bytes of Cyrillic
        let body = russian.to_string();
        let masked = super::super::forward::fmt_body(&body);
        assert!(masked.contains("truncated"));

        // Short body returns as-is
        assert_eq!(super::super::forward::fmt_body("short"), "short");
    }

    #[test]
    fn test_mask_company_cyrillic_quote() {
        // « is 2 bytes — must not panic on &str[..1]
        let masked = mask_company("ООО «Ромашка»");
        assert!(masked.contains("ООО"));
        assert!(!masked.contains("омашка"));
    }

    #[test]
    fn test_mask_company_cyrillic_no_split() {
        // No legal prefix — takes first 4 chars, not bytes
        let masked = mask_company("Ромашка");
        assert!(!masked.contains("ашка"));
    }

    #[test]
    fn test_no_false_positive() {
        let text = "Просто обычный текст без секретов и персональных данных";
        let (masked, detections) = DpiEngine::mask_text(text);
        assert_eq!(masked, text);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_no_false_positive_crm_fields() {
        // Common CRM/HR field names that look like FIO but are NOT names
        let texts = [
            "Обзор Личного кабинета",
            "Описание Статуса заказа",
            "Окружение Тестовое",
            "Руководитель Начальника отдела",
            "Действие Кнопка",
            "Отображение Активное",
            "Авторизован Администратор",
            "Обед Отдела продаж",
            "Перерыв Перерыв",
            "Коучинг Команды",
            "Бездействие Бизнес",
            "Назначен Автоматически",
            "Требует Авторизации",
            "Канал Связи Внутренний",
        ];
        for text in &texts {
            let detections = DpiEngine::scan(text);
            let fio_detections: Vec<_> = detections
                .iter()
                .filter(|d| d.violation_type == ViolationType::PiiFio)
                .collect();
            assert!(
                fio_detections.is_empty(),
                "False positive FIO in '{}': {:?}",
                text,
                fio_detections
                    .iter()
                    .map(|d| &d.matched_text)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_no_false_positive_api_reference() {
        // 'api-reference' should NOT match as an API key
        let text = "See api-reference documentation for details";
        let detections = DpiEngine::scan(text);
        let secret_detections: Vec<_> = detections
            .iter()
            .filter(|d| d.violation_type == ViolationType::Secret)
            .collect();
        assert!(
            secret_detections.is_empty(),
            "False positive SECRET in '{}'",
            text
        );
    }

    #[test]
    fn test_real_fio_still_detected() {
        // Real names must still be detected
        let texts = [
            "Иван Иванов отвечает за проект",
            "Мария Петрова подготовила отчёт",
            "Документ подписал Александр Смирнов",
        ];
        for text in &texts {
            let detections = DpiEngine::scan(text);
            assert!(
                detections
                    .iter()
                    .any(|d| d.violation_type == ViolationType::PiiFio),
                "Real FIO not detected in '{}'",
                text
            );
        }
    }

    #[test]
    fn test_empty_string() {
        let (masked, detections) = DpiEngine::mask_text("");
        assert_eq!(masked, "");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_multiple_violations() {
        let text = r#"{"api_key": "sk-1234567890abcdef", "text": "Привет, я Иван Иванов из ООО Ромашка, мой email: user@company.com"}"#;
        let (masked, detections) = DpiEngine::mask_text(text);
        let types: Vec<_> = detections
            .iter()
            .map(|d| d.violation_type.clone())
            .collect();
        assert!(types.contains(&ViolationType::Secret), "Secret not found");
        assert!(types.contains(&ViolationType::PiiFio), "FIO not found");
        // Company detection disabled — public info
        assert!(types.contains(&ViolationType::PiiEmail), "Email not found");
        assert!(!masked.contains("1234567890abcdef"));
        assert!(!masked.contains("Иванов"));
        assert!(!masked.contains("user@company.com"));
    }

    #[test]
    fn test_masking_boundary() {
        assert!(mask_secret("ab").contains("***"));
        assert!(mask_secret("sk-12345678").contains("***"));
    }

    // ─── Tokenization tests (new) ───────────────────

    #[test]
    fn test_generate_token_deterministic() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("user1"), "api.deepseek.com");

        let t1 = super::generate_token("sk-abc123", &ViolationType::Secret, &session);
        let t2 = super::generate_token("sk-abc123", &ViolationType::Secret, &session);
        assert_eq!(t1, t2, "same value + same session = same token");
        assert!(t1.starts_with("‹KEY_"));
        assert!(t1.ends_with("›"));
    }

    #[test]
    fn test_generate_token_different_sessions() {
        use crate::session::SessionId;
        let s1 = SessionId::new(Some("alice"), "api.deepseek.com");
        let s2 = SessionId::new(Some("bob"), "api.deepseek.com");

        let t1 = super::generate_token("sk-abc123", &ViolationType::Secret, &s1);
        let t2 = super::generate_token("sk-abc123", &ViolationType::Secret, &s2);
        assert_ne!(t1, t2, "different sessions = different tokens");
    }

    #[test]
    fn test_generate_token_prefixes() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("u"), "d");

        assert!(
            super::generate_token("val", &ViolationType::Secret, &session).starts_with("‹KEY_")
        );
        assert!(
            super::generate_token("val", &ViolationType::PiiFio, &session).starts_with("‹FIO_")
        );
        assert!(
            super::generate_token("val", &ViolationType::PiiCompany, &session).starts_with("‹ORG_")
        );
        assert!(
            super::generate_token("val", &ViolationType::PiiEmail, &session).starts_with("‹EML_")
        );
        assert!(
            super::generate_token("val", &ViolationType::PiiPhone, &session).starts_with("‹PHN_")
        );
    }

    #[test]
    fn test_tokenize_text_basic() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("u"), "api.deepseek.com");
        let text = r#"{"api_key": "sk-1234567890abcdef"}"#;

        let (tokenized, tokens) = DpiEngine::tokenize_text(text, &session);
        assert!(
            !tokenized.contains("1234567890abcdef"),
            "Secret should be tokenized"
        );
        assert!(
            tokenized.contains("‹KEY_"),
            "Token placeholder should be present"
        );
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].0.violation_type, ViolationType::Secret);
    }

    #[test]
    fn test_tokenize_text_multiple_types() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("u"), "api.deepseek.com");
        let text = "Привет, я Иван Иванов из ООО Ромашка, почта user@company.com";

        let (tokenized, tokens) = DpiEngine::tokenize_text(text, &session);
        assert!(tokenized.contains("‹FIO_"), "FIO should be tokenized");
        // Company detection disabled
        assert!(tokenized.contains("‹EML_"), "Email should be tokenized");
        assert!(!tokenized.contains("Иванов"));
        assert!(!tokenized.contains("‹EML_c54971›"));
        assert!(tokens.len() >= 2);
    }

    #[test]
    fn test_tokenize_text_no_violations() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("u"), "d");
        let text = "Просто обычный безопасный текст";

        let (tokenized, tokens) = DpiEngine::tokenize_text(text, &session);
        assert_eq!(tokenized, text);
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_tokenize_roundtrip() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("user1"), "api.deepseek.com");
        let text = r#"{"api_key": "sk-1234567890abcdef", "user": "Иван Иванов"}"#;

        let (tokenized, tokens) = DpiEngine::tokenize_text(text, &session);

        assert!(
            !tokenized.contains("1234567890abcdef"),
            "Secret leaked: {}",
            tokenized
        );
        assert!(!tokenized.contains("Иванов"), "FIO leaked: {}", tokenized);

        assert!(
            tokenized.contains("‹KEY_"),
            "No KEY token in: {}",
            tokenized
        );
        assert!(
            tokenized.contains("‹FIO_"),
            "No FIO token in: {}",
            tokenized
        );

        assert_eq!(tokens.len(), 2, "Expected 2 tokens, got {}", tokens.len());

        let (tokenized2, _tokens2) = DpiEngine::tokenize_text(text, &session);
        assert_eq!(tokenized, tokenized2, "Tokens must be deterministic");
    }

    #[test]
    fn test_tokenize_json_body_preserves_structure() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("user1"), "api.deepseek.com");
        // Realistic AI API request with secrets in string values
        let body = r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"My key sk-abc123def456ghi789 and email user@test.com"}],"api_key":"sk-secretkey123456789"}"#;

        let (tokenized, tokens) = DpiEngine::tokenize_json_body(body, &session);

        // Must be valid JSON after tokenization
        let reparsed: serde_json::Value =
            serde_json::from_str(&tokenized).expect("Tokenized body must be valid JSON");

        // Structure preserved
        assert_eq!(reparsed["model"], "deepseek-chat");
        assert_eq!(reparsed["messages"][0]["role"], "user");

        // Secrets tokenized
        assert!(!tokenized.contains("sk-abc123def456ghi789"), "Secret leaked");
        assert!(!tokenized.contains("user@test.com"), "Email leaked");
        assert!(tokens.len() >= 2, "Expected at least 2 tokens");
    }

    #[test]
    fn test_tokenize_json_body_does_not_touch_keys() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("user1"), "d");
        // JSON key "api_key" must NOT be tokenized — only values
        let body = r#"{"api_key":"safe-value","model":"gpt-4"}"#;

        let (tokenized, _tokens) = DpiEngine::tokenize_json_body(body, &session);

        // Must be valid JSON
        let reparsed: serde_json::Value =
            serde_json::from_str(&tokenized).expect("Must be valid JSON");
        // Key preserved
        assert!(reparsed.get("api_key").is_some(), "api_key key must exist");
        assert_eq!(reparsed["model"], "gpt-4");
    }

    #[test]
    fn test_tokenize_json_body_invalid_json_fallback() {
        use crate::session::SessionId;
        let session = SessionId::new(Some("user1"), "d");
        // Non-JSON body — should fall back to raw tokenization
        let body = "My key is sk-abc123def456ghi789";

        let (tokenized, tokens) = DpiEngine::tokenize_json_body(body, &session);
        assert!(tokenized.contains("‹KEY_"), "Should tokenize in raw mode");
        assert!(!tokens.is_empty());
    }

    // ─── Brand name detection ───────────────────────







}
