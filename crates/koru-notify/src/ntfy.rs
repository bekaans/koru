//! The ntfy channel (`KORU_NTFY_URL`, optional `KORU_NTFY_TOKEN`).
//!
//! `POST <url>`; the body is plain text, the headers `Title`, `Priority`, `Tags` (and, with a
//! token, `Authorization: Bearer [REDACTED]`). Header values cannot contain line breaks; non-ASCII
//! characters are RFC 2047 encoded.

use std::time::Duration;

use koru_event::{InterfaceError, Notification, NotificationChannel, Severity};

use crate::http::{self, Request};
use crate::text::{header_value, sanitize_body};
use crate::{HttpsAddress, Secret};

/// The ntfy message limit is 4096 bytes.
const MAX_BODY_BYTES_WIRE: usize = 4000;
/// The title goes into an HTTP header; encoded it grows ~4/3. It fits three RFC 2047 words.
const MAX_HEADER_BYTES: usize = 120;

/// ntfy settings.
#[derive(Debug, Clone)]
pub struct NtfySettings {
    /// Server and topic address (e.g. `https://ntfy.sh/my-topic`).
    pub url: HttpsAddress,
    /// Access token (optional).
    pub token: Option<Secret>,
    /// Connect, write and read deadline.
    pub timeout: Duration,
}

impl NtfySettings {
    /// Settings with the default deadline (10 s) and no token.
    pub fn new(url: HttpsAddress) -> NtfySettings {
        NtfySettings { url, token: None, timeout: Duration::from_secs(10) }
    }
}

/// The ntfy channel.
#[derive(Debug)]
pub struct NtfyChannel {
    settings: NtfySettings,
    last_status: Option<u16>,
}

impl NtfyChannel {
    /// The HTTP status code from the last send (a failed response's code too); `None` when no
    /// response was received or nothing was sent yet. Just a number; it cannot carry a secret.
    pub fn last_status(&self) -> Option<u16> {
        self.last_status
    }

    /// Builds the channel (no network).
    pub fn new(settings: NtfySettings) -> NtfyChannel {
        NtfyChannel { settings, last_status: None }
    }
}

fn priority_and_tags(severity: Severity) -> (&'static str, &'static str) {
    match severity {
        Severity::Info => ("2", "information_source,koru"),
        Severity::Warning => ("4", "warning,koru"),
        Severity::Critical => ("5", "rotating_light,koru"),
    }
}

impl NotificationChannel for NtfyChannel {
    fn name(&self) -> &str {
        "ntfy"
    }

    fn send(&mut self, notification: &Notification) -> Result<(), InterfaceError> {
        self.last_status = None;
        let title = header_value(&notification.title, MAX_HEADER_BYTES, " ");
        let body = sanitize_body(&notification.body, MAX_BODY_BYTES_WIRE);
        let (priority, tags) = priority_and_tags(notification.severity);
        let mut headers: Vec<http::Header> = vec![
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
            ("Title", title),
            ("Priority", priority.to_string()),
            ("Tags", tags.to_string()),
        ];
        if let Some(j) = &self.settings.token {
            headers.push(("Authorization", format!("Bearer {}", j.reveal())));
        }
        let request = Request {
            method: "POST",
            url: &self.settings.url,
            headers: &headers,
            body: body.as_bytes(),
            timeout: self.settings.timeout,
        };
        let state = http::send(&request)?;
        self.last_status = Some(state);
        http::classify_status(state)
    }
}
