//! Module: audit events aggregation
use tokio::sync::mpsc;

use crate::violation_event::ViolationEvent;

#[derive(Clone)]
pub struct AuditChannel {
    sender: mpsc::UnboundedSender<ViolationEvent>,
}

pub struct AuditReceiver {
    receiver: mpsc::UnboundedReceiver<ViolationEvent>,
}

pub fn audit_channel() -> (AuditChannel, AuditReceiver) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (AuditChannel { sender }, AuditReceiver { receiver })
}

impl AuditChannel {
    pub fn send(&self, event: ViolationEvent) {
        // ignore error — fire-and-forget
        let _ = self.sender.send(event);
    }
}

impl AuditReceiver {
    pub async fn recv(&mut self) -> Option<ViolationEvent> {
        self.receiver.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event() -> ViolationEvent {
        ViolationEvent {
            user_id: Some("test_user".into()),
            resource: "api.deepseek.com".into(),
            violation_type: "SECRET".into(),
            masked_context: "sk-***-cdef".into(),
            token: Some("‹KEY_abc›".into()),
            request_path: Some("/v1/chat".into()),
            timestamp: "2026-07-30T21:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn test_audit_channel_send_recv() {
        let (sender, mut receiver) = audit_channel();
        let event = make_event();
        sender.send(event.clone());
        let received = receiver.recv().await.expect("should receive event");
        assert_eq!(received, event);
    }

    #[tokio::test]
    async fn test_audit_channel_multiple() {
        let (sender, mut receiver) = audit_channel();
        sender.send(make_event());
        sender.send(make_event());
        sender.send(make_event());

        let mut count = 0;
        while receiver.recv().await.is_some() {
            count += 1;
            if count >= 3 {
                break;
            }
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_audit_channel_fire_and_forget() {
        let (sender, receiver) = audit_channel();
        drop(receiver);
        sender.send(make_event()); // must not panic
    }
}
