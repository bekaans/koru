//! IP masking in notifications (privacy; ADR-0007 §8, KT-71). Default: masked. The full IP stays
//! only in the local store; it never enters a channel or the queue file. The function lives in
//! koru-event ([`koru_event::mask_ip_in_text`]; koru-notify does not know koru-store).

use koru_event::{Notification, mask_ip_in_text};

/// Masks IPv4 (/24) and IPv6 (/48) addresses in the title and body; severity and the event id stay.
pub fn mask_notification(notification: &Notification) -> Notification {
    Notification {
        severity: notification.severity,
        title: mask_ip_in_text(&notification.title),
        body: mask_ip_in_text(&notification.body),
        event_id: notification.event_id,
    }
}
