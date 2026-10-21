//! Notification text sanitization (injection and length). Every channel routes content through here.
//!
//! The rule matches [`koru_event::Untrusted::safe_display`] (control characters C0, DEL and
//! C1; Unicode direction-formatting characters; backslash), plus U+2028 and U+2029 line
//! separators are neutralized too. Sanitization runs in linear time and stops at the output
//! bound without scanning the whole input.

use std::fmt::Write as _;

/// Max bytes for a title.
pub const MAX_HEADER_BYTES: usize = 200;

const THRESHOLD: char = '…';

/// Invisible or direction-changing Unicode characters (Trojan Source, CVE-2021-42574) plus
/// line/paragraph separators.
fn is_bidi_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}'
    )
}

fn clean(text: &str, max_bytes: usize, allow_newline: bool) -> String {
    let marker_len = THRESHOLD.len_utf8();
    let cut_budget = max_bytes.saturating_sub(marker_len);
    let mut result = String::with_capacity(text.len().min(max_bytes));
    let mut safe_len = 0;
    for c in text.chars() {
        let mut piece = String::new();
        if c == '\\' {
            piece.push_str("\\\\");
        } else if (c.is_control() && !(allow_newline && c == '\n')) || is_bidi_format_char(c) {
            // Writing to a String never fails.
            let _ = write!(piece, "\\u{{{:x}}}", u32::from(c));
        } else {
            piece.push(c);
        }
        if result.len() + piece.len() > max_bytes {
            result.truncate(safe_len);
            if max_bytes >= marker_len {
                result.push(THRESHOLD);
            }
            return result;
        }
        result.push_str(&piece);
        if result.len() <= cut_budget {
            safe_len = result.len();
        }
    }
    result
}

/// Single-line text: all control characters (line breaks too), direction-formatting
/// characters and backslash are written as `\u{..}` / `\\` (same rule as
/// [`koru_event::Untrusted::safe_display`]); the result is at most `max_bytes` bytes, with `…`
/// appended on overflow. Escape sequences are never split.
pub fn sanitize_header(text: &str, max_bytes: usize) -> String {
    clean(text, max_bytes, false)
}

/// Multi-line text: `\n` is kept; other control characters (CR too) and direction characters are
/// neutralized; the result is at most `max_bytes` bytes, with `…` appended on overflow.
pub fn sanitize_body(text: &str, max_bytes: usize) -> String {
    clean(text, max_bytes, true)
}

/// The most UTF-8 bytes one RFC 2047 word can carry (45 bytes = 60 base64 chars;
/// with `=?UTF-8?B?` and `?=` it is 72 chars, under the 75 limit).
const WORD_BYTES: usize = 45;

/// RFC 2047 "B" encoding: printable-ASCII text (without `=?`) returns as-is; otherwise it
/// splits into `=?UTF-8?B?...?=` words (each at most 75 chars, a UTF-8 char is never split)
/// joined with `separator`. CR or LF in the input goes inside the words; in the output they
/// appear only inside `separator`.
pub fn rfc2047_encode(text: &str, separator: &str) -> String {
    if text.chars().all(|c| (' '..='~').contains(&c)) && !text.contains("=?") {
        return text.to_string();
    }
    rfc2047_forced(text, separator)
}

/// Like [`rfc2047_encode`], but encodes even plain-ASCII text. When sanitizing attacker data
/// changed it (escaping, truncation), only the encoded form reaches the header, so even the
/// sanitized content never shows on the raw header line.
pub fn rfc2047_forced(text: &str, separator: &str) -> String {
    let mut words: Vec<String> = Vec::new();
    let mut piece = String::new();
    for c in text.chars() {
        if piece.len() + c.len_utf8() > WORD_BYTES {
            words.push(encode_word(&piece));
            piece.clear();
        }
        piece.push(c);
    }
    if !piece.is_empty() {
        words.push(encode_word(&piece));
    }
    words.join(separator)
}

/// Sanitizing and encoding for a header value: the text is sanitized ([`sanitize_header`]);
/// when sanitizing changed it (control char, backslash, truncation) or it is not ASCII, it is
/// RFC 2047 encoded; otherwise it goes as-is.
pub fn header_value(text: &str, max_bytes: usize, separator: &str) -> String {
    let clean = sanitize_header(text, max_bytes);
    if clean != text { rfc2047_forced(&clean, separator) } else { rfc2047_encode(&clean, separator) }
}

fn encode_word(piece: &str) -> String {
    format!("=?UTF-8?B?{}?=", base64_encode(piece.as_bytes()))
}

const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648, padded).
pub fn base64_encode(byte: &[u8]) -> String {
    let mut s = String::with_capacity(byte.len().div_ceil(3) * 4);
    for piece in byte.chunks(3) {
        let b0 = u32::from(piece[0]);
        let b1 = u32::from(piece.get(1).copied().unwrap_or(0));
        let b2 = u32::from(piece.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        s.push(char::from(BASE64_TABLE[(n >> 18) as usize & 63]));
        s.push(char::from(BASE64_TABLE[(n >> 12) as usize & 63]));
        s.push(if piece.len() > 1 { char::from(BASE64_TABLE[(n >> 6) as usize & 63]) } else { '=' });
        s.push(if piece.len() > 2 { char::from(BASE64_TABLE[n as usize & 63]) } else { '=' });
    }
    s
}
