//! Error type. Messages carry no secret, URL or notification content.

use koru_event::InterfaceError;

/// Configuration, queue and setup error (send errors are [`InterfaceError`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotifyError {
    /// Invalid or missing settings. The message contains only variable or field names, never
    /// their values.
    #[error("invalid notification setting: {0}")]
    Settings(String),
    /// Queue file or directory error.
    #[error("queue: {0}")]
    Queue(String),
}

impl From<NotifyError> for InterfaceError {
    fn from(h: NotifyError) -> InterfaceError {
        InterfaceError::Permanent(h.to_string())
    }
}
