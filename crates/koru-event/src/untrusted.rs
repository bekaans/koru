//! A wrapper type for values an attacker can control.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A value an attacker can control: a file name, command line, environment variable, container
/// name, and similar. In the JSON schema these fields are marked with
/// `x-koru-untrusted: true` (`schemas/event.v1.json`, [`crate::UNTRUSTED_FIELDS`]).
///
/// It is transparent in serialization: the inner value is written to JSON as-is. It deliberately
/// does not implement `Display`; code that wants to print the value to a screen, notification, or
/// log either neutralizes control and bidi characters with [`Untrusted::safe_display`] or
/// explicitly requests the raw value with [`Untrusted::untrusted_value`] (KT-15).
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    /// Marks the value as untrusted.
    pub const fn new(value: T) -> Self {
        Untrusted(value)
    }

    /// The raw value. The name shows the caller uses the value knowing it is untrusted.
    pub fn untrusted_value(&self) -> &T {
        &self.0
    }

    /// Unwraps and returns the raw value.
    pub fn untrusted_inner(self) -> T {
        self.0
    }
}

impl Untrusted<String> {
    /// A form safe to show in a terminal, notification, or log: control characters (C0, DEL, C1;
    /// e.g. ANSI escape sequences) and Unicode bidi formatting characters are written as `\u{..}`;
    /// backslashes are doubled (so the rendering stays unambiguous). Other characters (including
    /// non-ASCII letters) are kept as-is.
    pub fn safe_display(&self) -> String {
        safe_text(&self.0)
    }
}

impl Untrusted<Vec<String>> {
    /// The same rule for lists such as command lines; items are joined with spaces.
    pub fn safe_display(&self) -> String {
        self.0.iter().map(|s| safe_text(s.as_str())).collect::<Vec<_>>().join(" ")
    }
}

impl<T: fmt::Debug> fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The Debug output of the inner value (for String, control characters are escaped).
        f.debug_tuple("Untrusted").field(&self.0).finish()
    }
}

/// Invisible Unicode formatting characters, or characters that change text direction (Trojan
/// Source, CVE-2021-42574): ALM, LRM, RLM, LRE..RLO, LRI..PDI.
fn is_bidi_format_char(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn safe_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control() || is_bidi_format_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backslash_is_escaped() {
        // The literal text "\u{1b}" written by an attacker is not confused with the rendering of a real escape character.
        let g = Untrusted::new("a\\u{1b}b\u{1b}".to_string());
        assert_eq!(g.safe_display(), "a\\\\u{1b}b\\u{1b}");
    }
}
