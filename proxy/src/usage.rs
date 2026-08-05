#![allow(clippy::manual_map)]
#![allow(dead_code)]
use serde_json::Value;

#[derive(Debug, Default, Clone)]
pub struct Rec {
    pub prompt: Option<u64>,
    pub complet: Option<u64>,
    pub model: Option<String>,
}

pub fn parse(body: &str) -> Option<Rec> {
    let v: Value = serde_json::from_str(body).ok()?;
    let obj = v.as_object()?;
    if let Some(u) = obj.get("usage").and_then(|x| x.as_object()) {
        let p = u.get("prompt_tokens").and_then(|x| x.as_u64());
        let c = u.get("completion_tokens").and_then(|x| x.as_u64());
        if p.is_some() || c.is_some() {
            let m = obj
                .get("model")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            return Some(Rec {
                prompt: p,
                complet: c,
                model: m,
            });
        }
        let p = u.get("input_tokens").and_then(|x| x.as_u64());
        let c = u.get("output_tokens").and_then(|x| x.as_u64());
        if p.is_some() || c.is_some() {
            let m = obj
                .get("model")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            return Some(Rec {
                prompt: p,
                complet: c,
                model: m,
            });
        }
    }
    None
}

pub fn estimate(body: &str) -> Option<u64> {
    let v: Value = serde_json::from_str(body).ok()?;
    let msgs = v.get("messages")?.as_array()?;
    let n: usize = msgs
        .iter()
        .filter_map(|m| m.get("content"))
        .filter_map(|c| {
            if let Some(s) = c.as_str() {
                Some(s.len())
            } else if let Some(arr) = c.as_array() {
                Some(
                    arr.iter()
                        .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                        .map(|t| t.len())
                        .sum(),
                )
            } else {
                None
            }
        })
        .sum();
    if n > 0 {
        Some((n as f64 / 4.0).ceil() as u64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── parse ────────────────────────────────────────────────

    #[test]
    fn test_parse_openai_format() {
        let body = r#"{
            "model": "gpt-4",
            "usage": {
                "prompt_tokens": 150,
                "completion_tokens": 300,
                "total_tokens": 450
            }
        }"#;
        let rec = parse(body).unwrap();
        assert_eq!(rec.prompt, Some(150));
        assert_eq!(rec.complet, Some(300));
        assert_eq!(rec.model.as_deref(), Some("gpt-4"));
    }

    #[test]
    fn test_parse_anthropic_format() {
        let body = r#"{
            "model": "claude-3-opus",
            "usage": {
                "input_tokens": 500,
                "output_tokens": 1200
            }
        }"#;
        let rec = parse(body).unwrap();
        assert_eq!(rec.prompt, Some(500));
        assert_eq!(rec.complet, Some(1200));
        assert_eq!(rec.model.as_deref(), Some("claude-3-opus"));
    }

    #[test]
    fn test_parse_no_usage() {
        let body = r#"{"model": "gpt-4", "choices": []}"#;
        assert!(parse(body).is_none());
    }

    #[test]
    fn test_parse_no_model() {
        let body = r#"{"usage": {"prompt_tokens": 10, "completion_tokens": 20}}"#;
        let rec = parse(body).unwrap();
        assert_eq!(rec.prompt, Some(10));
        assert_eq!(rec.complet, Some(20));
        assert!(rec.model.is_none());
    }

    #[test]
    fn test_parse_empty_usage() {
        let body = r#"{"model": "gpt-4", "usage": {}}"#;
        assert!(parse(body).is_none());
    }

    #[test]
    fn test_parse_invalid_json() {
        assert!(parse("not json").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn test_parse_zero_tokens() {
        let body = r#"{"usage": {"prompt_tokens": 0, "completion_tokens": 0}}"#;
        // 0 is Some(0), which satisfies is_some() — should return a record
        let rec = parse(body).unwrap();
        assert_eq!(rec.prompt, Some(0));
        assert_eq!(rec.complet, Some(0));
    }

    #[test]
    fn test_parse_only_prompt_tokens() {
        let body = r#"{"usage": {"prompt_tokens": 42}}"#;
        let rec = parse(body).unwrap();
        assert_eq!(rec.prompt, Some(42));
        assert_eq!(rec.complet, None);
    }

    #[test]
    fn test_estimate_simple_messages() {
        let body = r#"{
            "messages": [
                {"role": "user", "content": "Hello, how are you?"},
                {"role": "assistant", "content": "I am fine, thank you!"}
            ]
        }"#;
        let tokens = estimate(body).unwrap();
        // "Hello, how are you?" = 19 + "I am fine, thank you!" = 21 = 40 chars
        // 40 / 4 = 10 → ceil = 10
        assert_eq!(tokens, 10);
    }

    #[test]
    fn test_estimate_multipart_content() {
        let body = r#"{
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "Describe this image"},
                    {"type": "image_url", "image_url": {"url": "data:..."}}
                ]}
            ]
        }"#;
        let tokens = estimate(body).unwrap();
        // "Describe this image" = 19 chars / 4 = 4.75 → ceil = 5
        assert_eq!(tokens, 5);
    }

    #[test]
    fn test_estimate_no_messages() {
        let body = r#"{"model": "gpt-4"}"#;
        assert!(estimate(body).is_none());
    }

    #[test]
    fn test_estimate_empty_messages() {
        let body = r#"{"messages": []}"#;
        assert!(estimate(body).is_none());
    }

    #[test]
    fn test_estimate_invalid_json() {
        assert!(estimate("not json").is_none());
    }

    #[test]
    fn test_estimate_message_without_content() {
        let body = r#"{"messages": [{"role": "system"}]}"#;
        assert!(estimate(body).is_none());
    }
}
