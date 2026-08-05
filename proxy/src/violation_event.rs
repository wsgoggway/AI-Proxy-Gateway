use serde::{Deserialize, Serialize};

use crate::dpi::{Detection, ViolationType};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ViolationEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub resource: String,
    pub violation_type: String,
    pub masked_context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_path: Option<String>,
    pub timestamp: String,
}

impl ViolationEvent {
    pub fn from_detection(
        detection: &Detection,
        user_id: Option<&str>,
        resource: &str,
        request_path: Option<&str>,
        token: &str,
        context: &str,
    ) -> Self {
        let violation_type = match detection.violation_type {
            ViolationType::Secret => "SECRET",
            ViolationType::PiiFio => "PII_FIO",
            ViolationType::PiiCompany => "PII_COMPANY",
            ViolationType::PiiEmail => "PII_EMAIL",
            ViolationType::PiiPhone => "PII_PHONE",
        };

        Self {
            user_id: user_id.map(|s| s.to_string()),
            resource: resource.to_string(),
            violation_type: violation_type.to_string(),
            masked_context: context.to_string(),
            token: Some(token.to_string()),
            request_path: request_path.map(|s| s.to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_violation_event_serialize() {
        let event = ViolationEvent {
            user_id: Some("user123".into()),
            resource: "api.deepseek.com".into(),
            violation_type: "SECRET".into(),
            masked_context: "Ключ ‹KEY_a3f2b1› сохранён".into(),
            token: Some("‹KEY_a3f2b1›".into()),
            request_path: Some("/v1/chat".into()),
            timestamp: "2026-07-30T21:00:00Z".into(),
        };

        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"violation_type\":\"SECRET\""));
        assert!(json.contains("\"masked_context\":\"Ключ ‹KEY_a3f2b1› сохранён\""));
        assert!(json.contains("\"token\":\"‹KEY_a3f2b1›\""));
    }

    #[test]
    fn test_no_original_data() {
        let event = ViolationEvent {
            user_id: Some("user123".into()),
            resource: "api.deepseek.com".into(),
            violation_type: "SECRET".into(),
            masked_context: "‹KEY_a3f2b1›".into(),
            token: Some("‹KEY_a3f2b1›".into()),
            request_path: None,
            timestamp: "2026-07-30T21:00:00Z".into(),
        };

        let json = serde_json::to_string(&event).expect("serialize");
        assert!(!json.contains("matched_text"));
        assert!(!json.contains("original"));
    }

    #[test]
    fn test_detection_to_event() {
        let detection = Detection {
            violation_type: ViolationType::PiiFio,
            matched_text: "Иван Иванов".into(),
            masked_text: "Иван И***".into(),
            start: 0,
            end: 10,
        };

        let event = ViolationEvent::from_detection(
            &detection,
            Some("user456"),
            "api.qwen.ai",
            Some("/v1/chat/completions"),
            "‹FIO_9b2c7d›",
            "Контекст с ‹FIO_9b2c7d›",
        );

        assert_eq!(event.violation_type, "PII_FIO");
        assert_eq!(event.masked_context, "Контекст с ‹FIO_9b2c7d›");
        assert_eq!(event.token, Some("‹FIO_9b2c7d›".to_string()));
        assert!(!event.masked_context.contains("Иванов"));
    }
}
