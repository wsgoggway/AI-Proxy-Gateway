/// File content scanner: base64 detection, binary blocking, text extraction.
use crate::dpi::{Detection, DpiEngine};
use crate::session::SessionId;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ContentFormat {
    Text,
    Image,
    Application,
    Binary,
}

impl ContentFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentFormat::Text => "text",
            ContentFormat::Image => "image",
            ContentFormat::Application => "application",
            ContentFormat::Binary => "binary",
        }
    }
}

/// Scan body for base64-encoded content and run DPI on extractable text.
/// Result of one attachment scan.
#[derive(Debug)]
pub struct FileScanResult {
    pub format: ContentFormat,
    /// Outcome: pass (no violations), masked (text rewritten), blocked (binary replaced).
    pub outcome: &'static str,
}

/// Save decoded attachment to disk for forensic analysis.
/// Only called when violations are found. Files land in /tmp/ai-proxy-files/.
fn save_attachment_to_disk(data: &[u8], format: ContentFormat, index: usize) -> Option<String> {
    let dir = std::path::Path::new("/tmp/ai-proxy-files");
    if std::fs::create_dir_all(dir).is_err() {
        return None;
    }
    let ext = match format {
        ContentFormat::Text => "txt",
        ContentFormat::Image => "img",
        ContentFormat::Application => "app",
        ContentFormat::Binary => "bin",
    };
    let path = dir.join(format!(
        "attachment-{}-{}.{}",
        std::process::id(),
        index,
        ext
    ));
    std::fs::write(&path, data).ok()?;
    Some(path.display().to_string())
}

/// Scan body for base64-encoded content and run DPI on extractable text.
pub fn scan_body_for_base64(
    body: &str,
    session: &SessionId,
) -> (String, Vec<(Detection, String)>, Vec<FileScanResult>) {
    use base64::Engine;
    use once_cell::sync::Lazy;
    use regex::Regex;

    static B64_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#""data:([^";]+);base64,([^"]+)""#).expect("base64 regex"));

    let engine = base64::engine::general_purpose::STANDARD;
    let mut result = body.to_string();
    let mut all_detections: Vec<(Detection, String)> = Vec::new();
    let mut scans: Vec<FileScanResult> = Vec::new();
    let mut index = 0usize;

    for cap in B64_RE.captures_iter(body) {
        let full_match = cap.get(0).unwrap();
        let b64_str = cap.get(2).unwrap().as_str();

        let decoded = match engine.decode(b64_str) {
            Ok(d) => d,
            Err(_) => continue,
        };
        index += 1;

        let format = detect_format(&decoded);

        match format {
            ContentFormat::Text => {
                // Text attachments: mask with the SAME session as the body.
                // Deterministic tokens -> same secret in body and file gets
                // the same ‹KEY_xxx› token. No divergence possible.
                let text = String::from_utf8_lossy(&decoded);
                let (masked_text, detections) = DpiEngine::tokenize_text(&text, session);
                if !detections.is_empty() {
                    let saved = save_attachment_to_disk(&decoded, format, index);
                    all_detections.extend(detections);
                    let new_b64 = engine.encode(masked_text.as_bytes());
                    let replacement = format!(
                        "\"data:{};base64,{}\"",
                        cap.get(1).unwrap().as_str(),
                        new_b64
                    );
                    result = result.replace(full_match.as_str(), &replacement);
                    scans.push(FileScanResult {
                        format,
                        outcome: "masked",
                    });
                    if let Some(p) = saved {
                        tracing::debug!("attachment_saved path={}", p);
                    }
                } else {
                    scans.push(FileScanResult {
                        format,
                        outcome: "pass",
                    });
                }
            }
            _ => {
                // Binary/image/PDF: cannot reliably rewrite pixels.
                // Lossy text scan catches secrets in readable parts.
                let text = String::from_utf8_lossy(&decoded);
                let scanned = DpiEngine::scan(&text);
                if !scanned.is_empty() {
                    let saved = save_attachment_to_disk(&decoded, format, index);
                    for det in scanned {
                        all_detections.push((det, "BLOCKED".to_string()));
                    }
                    let replacement = format!(
                        "\"data:{};base64,{}\"",
                        cap.get(1).unwrap().as_str(),
                        engine.encode(b"[BLOCKED: uninspectable content]")
                    );
                    result = result.replace(full_match.as_str(), &replacement);
                    scans.push(FileScanResult {
                        format,
                        outcome: "blocked",
                    });
                    if let Some(p) = saved {
                        tracing::debug!("attachment_saved path={}", p);
                    }
                } else {
                    scans.push(FileScanResult {
                        format,
                        outcome: "pass",
                    });
                }
            }
        }
    }

    // Metrics: one sample per attachment
    for s in &scans {
        crate::metrics::FILE_SCAN_TOTAL
            .with_label_values(&[s.format.as_str(), s.outcome])
            .inc();
    }

    (result, all_detections, scans)
}

/// Detect content format from magic bytes.
/// Order matters: check application/pdf before text (both start with ASCII).
pub fn detect_format(data: &[u8]) -> ContentFormat {
    if data.is_empty() {
        return ContentFormat::Binary;
    }

    // Application: check before text (PDF starts with ASCII)
    if data.starts_with(b"%PDF") {
        return ContentFormat::Application;
    }
    if data.len() >= 4 && data[0..4] == [b'P', b'K', 0x03, 0x04] {
        return ContentFormat::Application;
    }

    // Image: check before text (GIF89a is valid UTF-8!)
    if data.len() >= 2 && data[0..2] == [0xFF, 0xD8] {
        return ContentFormat::Image;
    }
    if data.len() >= 4 && data[0..4] == [0x89, b'P', b'N', b'G'] {
        return ContentFormat::Image;
    }
    if data.starts_with(b"GIF8") {
        return ContentFormat::Image;
    }
    if data.len() >= 12 && data[0..4] == *b"RIFF" && &data[8..12] == b"WEBP" {
        return ContentFormat::Image;
    }
    if data.len() >= 2 && data.starts_with(b"BM") {
        return ContentFormat::Image;
    }

    // Text: valid UTF-8 with high printable ratio
    if std::str::from_utf8(data).is_ok() {
        let printable = data
            .iter()
            .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace() || **b >= 0x80)
            .count() as f64
            / data.len() as f64;
        if printable > 0.95 {
            return ContentFormat::Text;
        }
    }

    ContentFormat::Binary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> SessionId {
        SessionId::new(Some("test"), "api.test.com")
    }

    #[test]
    fn test_detect_format_text_ascii() {
        assert_eq!(detect_format(b"hello world"), ContentFormat::Text);
    }

    #[test]
    fn test_detect_format_text_json() {
        assert_eq!(detect_format(b"{\"key\": 42}"), ContentFormat::Text);
    }

    #[test]
    fn test_detect_format_jpeg() {
        assert_eq!(detect_format(b"\xff\xd8\xff"), ContentFormat::Image);
    }

    #[test]
    fn test_detect_format_png() {
        assert_eq!(detect_format(b"\x89PNG\r\n\x1a\n"), ContentFormat::Image);
    }

    #[test]
    fn test_detect_format_gif() {
        assert_eq!(detect_format(b"GIF89a"), ContentFormat::Image);
    }

    #[test]
    fn test_detect_format_pdf() {
        assert_eq!(detect_format(b"%PDF-1.4"), ContentFormat::Application);
    }

    #[test]
    fn test_detect_format_zip() {
        assert_eq!(detect_format(b"PK\x03\x04"), ContentFormat::Application);
    }

    #[test]
    fn test_detect_format_binary() {
        assert_eq!(detect_format(b"\x00\x01\x02\x03"), ContentFormat::Binary);
    }

    // ─── Base64 scanning ──────────────────────────────────

    #[test]
    fn test_scan_base64_text_no_pii() {
        let session = test_session();
        let body = r#"{"image": "data:text/plain;base64,SGVsbG8gV29ybGQ="}"#;
        let (result, detections, scans) = scan_body_for_base64(body, &session);
        assert_eq!(result, body);
        assert!(detections.is_empty());
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].outcome, "pass");
    }

    #[test]
    fn test_scan_base64_text_with_secret() {
        let session = test_session();
        use base64::Engine;
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(b"api_key = sk-1234567890abcdef");
        let body = format!(r#"{{"file": "data:text/plain;base64,{}"}}"#, b64);
        let (result, detections, scans) = scan_body_for_base64(&body, &session);
        assert!(
            !result.contains("sk-1234567890abcdef"),
            "Secret leaked: {}",
            result
        );
        assert_ne!(result, body, "Body should be modified");
        assert!(!detections.is_empty(), "Secret not detected");
        assert_eq!(scans[0].outcome, "masked");
    }

    #[test]
    fn test_scan_base64_image_redacted() {
        let session = test_session();
        use base64::Engine;
        let mut data = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        data.extend_from_slice(b"password=secretkey123456");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        let body = format!(r#"{{"image": "data:image/png;base64,{}"}}"#, b64);
        let (result, _detections, scans) = scan_body_for_base64(&body, &session);
        assert_ne!(result, body, "Image should be modified");
        assert!(!result.contains(&b64), "Old base64 not removed");
        assert_eq!(scans[0].outcome, "blocked");
    }

    #[test]
    fn test_scan_body_no_base64() {
        let session = test_session();
        let body = r#"{"model":"test","messages":[{"content":"hello"}]}"#;
        let (result, detections, scans) = scan_body_for_base64(body, &session);
        assert_eq!(result, body);
        assert!(detections.is_empty());
        assert!(scans.is_empty());
    }

    // ─── Token consistency: body + file same secret → same token ──

    #[test]
    fn test_body_and_file_same_token() {
        let session = test_session();
        use base64::Engine;

        // Same secret value in body text AND in a text attachment
        let secret_text = "access_token = abcdef1234567890abcdef";
        let body_text = format!("Use the secret {} for access", secret_text);
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret_text.as_bytes());
        let body = format!(
            r#"{{"message": "{}", "file": "data:text/plain;base64,{}"}}"#,
            body_text, b64
        );

        // Mask the body
        let (body_masked, body_tokens) = DpiEngine::tokenize_text(&body, &session);
        // Scan the file with the same session
        let (_, file_detections, _) = scan_body_for_base64(&body, &session);

        // Find token used for the secret in body
        let body_token = body_tokens
            .iter()
            .find(|(d, _)| d.matched_text == secret_text)
            .map(|(_, t)| t.clone());
        assert!(
            body_token.is_some(),
            "Secret should be ‹KEY_aa782d› in body"
        );

        // Find token used for the secret in file
        let file_token = file_detections
            .iter()
            .find(|(d, _)| d.matched_text == secret_text)
            .map(|(_, t)| t.clone());
        assert!(
            file_token.is_some(),
            "Secret should be ‹KEY_aa782d› in file"
        );

        // CRITICAL: both must be the same token — no semantic divergence
        assert_eq!(
            body_token, file_token,
            "Body and file use DIFFERENT tokens for the same secret!"
        );
        // And the masked body should contain that token
        assert!(
            body_masked.contains(body_token.as_deref().unwrap_or("")),
            "Masked body should contain the token"
        );
    }
}
