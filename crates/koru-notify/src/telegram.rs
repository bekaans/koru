//! The Telegram Bot API channel (`KORU_TELEGRAM_BOT_TOKEN`, `KORU_TELEGRAM_CHAT_ID`).
//!
//! `POST <api>/bot<token>/sendMessage`, JSON body `{chat_id, text, disable_web_page_preview}`.
//! `parse_mode` is never sent: the text is plain; markup like `<b>`, `*`, `_`, `[` is
//! interpreted.

use std::time::Duration;

use koru_event::{InterfaceError, Notification, NotificationChannel, Severity};

use crate::http::{self, Request};
use crate::text::{MAX_HEADER_BYTES, sanitize_body, sanitize_header};
use crate::{HttpsAddress, NotifyError, Secret};

/// Telegram's message limit is 4096 characters; the byte limit stays below the character limit.
const MAX_BODY_BYTES_WIRE: usize = 3500;

/// Bot token shape: `<digits>:<letters, digits, _ and ->`. The token enters the URL path, so
/// the shape is checked strictly.
pub(crate) fn is_token_valid(token: &str) -> bool {
    match token.split_once(':') {
        Some((number, secret)) => {
            (1..=20).contains(&number.len())
                && number.bytes().all(|b| b.is_ascii_digit())
                && (1..=100).contains(&secret.len())
                && secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        }
        None => false,
    }
}

/// Chat id: `-?<digits>` or `@channel` (5-32 characters, starts with a letter).
pub(crate) fn is_chat_id_valid(chat: &str) -> bool {
    if let Some(name) = chat.strip_prefix('@') {
        let mut c = name.chars();
        return (5..=32).contains(&name.len())
            && c.next().is_some_and(|k| k.is_ascii_alphabetic())
            && c.all(|k| k.is_ascii_alphanumeric() || k == '_');
    }
    let number = chat.strip_prefix('-').unwrap_or(chat);
    (1..=20).contains(&number.len()) && number.bytes().all(|b| b.is_ascii_digit())
}

/// Telegram settings.
#[derive(Debug, Clone)]
pub struct TelegramSettings {
    /// API address (default `https://api.telegram.org`; a fake server in tests).
    pub api_base: HttpsAddress,
    /// Bot token (`<number>:<letters-digits-_->`).
    pub bot_token: Secret,
    /// Chat id (`-?<number>` or `@channel`).
    pub chat_id: String,
    /// Connect, write and read deadline.
    pub timeout: Duration,
}

impl TelegramSettings {
    /// Validates the token and chat id; error messages carry no values.
    pub fn new(bot_token: Secret, chat_id: impl Into<String>) -> Result<TelegramSettings, NotifyError> {
        let chat_id = chat_id.into();
        if !is_token_valid(bot_token.reveal()) {
            return Err(NotifyError::Settings("invalid Telegram bot token format".to_string()));
        }
        if !is_chat_id_valid(&chat_id) {
            return Err(NotifyError::Settings("invalid Telegram chat id format".to_string()));
        }
        let api_base = HttpsAddress::parse_parts("https://api.telegram.org")
            .map_err(|_| NotifyError::Settings("invalid Telegram API address".to_string()))?;
        Ok(TelegramSettings { api_base, bot_token, chat_id, timeout: Duration::from_secs(10) })
    }

    /// Replaces the API address (for tests).
    pub fn set_api_base(mut self, url: HttpsAddress) -> TelegramSettings {
        self.api_base = url;
        self
    }
}

/// The Telegram channel.
#[derive(Debug)]
pub struct TelegramChannel {
    settings: TelegramSettings,
    last_status: Option<u16>,
}

impl TelegramChannel {
    /// The HTTP status code from the last send (a failed response's code too); `None` when no
    /// response was received or nothing was sent yet. Just a number; it cannot carry a secret.
    pub fn last_status(&self) -> Option<u16> {
        self.last_status
    }

    /// Builds the channel (no network).
    pub fn new(settings: TelegramSettings) -> TelegramChannel {
        TelegramChannel { settings, last_status: None }
    }
}

impl NotificationChannel for TelegramChannel {
    fn name(&self) -> &str {
        "telegram"
    }

    fn send(&mut self, notification: &Notification) -> Result<(), InterfaceError> {
        self.last_status = None;
        let label = match notification.severity {
            Severity::Info => "Info",
            Severity::Warning => "Warning",
            Severity::Critical => "Critical",
        };
        let text = format!(
            "[Koru {label}] {}\n\n{}\n\nEvent: {}",
            sanitize_header(&notification.title, MAX_HEADER_BYTES),
            sanitize_body(&notification.body, MAX_BODY_BYTES_WIRE),
            notification.event_id
        );
        // `parse_mode` is absent on purpose: the text is plain; no markup is interpreted.
        let body = serde_json::json!({
            "chat_id": self.settings.chat_id,
            "text": text,
            "disable_web_page_preview": true,
        })
        .to_string();
        let url = self
            .settings
            .api_base
            .join_path(&format!("bot{}", self.settings.bot_token.reveal()))
            .and_then(|a| a.join_path("sendMessage"))
            .map_err(|_| InterfaceError::Permanent("could not build the Telegram address".to_string()))?;
        let headers: Vec<http::Header> = vec![("Content-Type", "application/json".to_string())];
        let request = Request {
            method: "POST",
            url: &url,
            headers: &headers,
            body: body.as_bytes(),
            timeout: self.settings.timeout,
        };
        let state = http::send(&request)?;
        self.last_status = Some(state);
        http::classify_status(state)
    }
}
