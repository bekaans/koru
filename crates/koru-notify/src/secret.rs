//! Secret wrapper: tokens and passwords never enter `Debug` output.

use std::fmt;

/// A value that must stay out of logs, error messages and `Debug` output (token, password).
/// Deliberately has no `Display`; the raw value opens only through [`Secret::reveal`], on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wraps the value.
    pub fn new(value: impl Into<String>) -> Secret {
        Secret(value.into())
    }

    /// The raw value. Never for output; only for sending to the channel.
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}
