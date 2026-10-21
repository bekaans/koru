#![forbid(unsafe_code)]
//! # koru-notify
//!
//! Koru notification channels (ntfy, Telegram, SMTP), rate limiting and summarization, a
//! disk-persistent queue with exponential-backoff retries, and Healthchecks.io heartbeats
//! (ADR-0007).
//!
//! This layer depends only on koru-event; it does not know Pulsar, the other layers or the sensor.
//! It talks to the other layers through
//! [`koru_event::NotificationChannel`] and [`koru_event::Heartbeat`].
//!
//! Security principles:
//! - TLS is rustls only; addresses are `https` (the single exception is test-only
//!   `http://127.0.0.1`). The server certificate and host name are verified every time.
//! - All notification text is sanitized before it reaches a channel ([`text`]): line breaks,
//!   control and direction characters are neutralized and lengths are bounded.
//! - Tokens, passwords and the ping address are wrapped in [`Secret`] and URL types; they never
//!   enter `Debug` output, error messages or logs.

pub mod address;
pub mod backoff;
pub mod dispatcher;
pub mod error;
pub mod heartbeat;
mod http;
mod mask;
pub mod ntfy;
pub mod queue;
pub mod rate;
mod safe_file;
pub mod secret;
pub mod settings;
pub mod smtp;
pub mod telegram;
pub mod text;

pub use address::HttpsAddress;
pub use backoff::BackoffSettings;
pub use dispatcher::{ChannelSettings, ChannelStats, Dispatcher};
pub use error::NotifyError;
pub use heartbeat::{HealthchecksHeartbeat, HeartbeatLoop};
pub use mask::mask_notification;
pub use ntfy::{NtfyChannel, NtfySettings};
pub use queue::{PersistentQueue, QueueRecord, queue_content_valid};
pub use rate::{RateSettings, Summarizer, TokenBucket};
pub use secret::Secret;
pub use settings::{ChannelSet, parse_dotenv, read_dotenv};
pub use smtp::{SmtpChannel, SmtpSettings, SmtpTls};
pub use telegram::{TelegramChannel, TelegramSettings};
