//! Text sanitizing, encoding and URL validation (protected set):
//! terminal and bidi characters, CR/LF, excessive length, RFC 2047 and base64.

use koru_event::Untrusted;
use koru_notify::text::{MAX_HEADER_BYTES, base64_encode, rfc2047_encode, sanitize_body, sanitize_header};
use koru_notify::{HttpsAddress, NotifyError};

const HOSTILE_INPUTS: &[&str] = &[
    "a\r\nX-Evil: 1",
    "a\nb",
    "a\rb",
    "\u{1b}[31mred\u{1b}[0m",
    "\u{1b}]0;window title\u{7}",
    "a\u{0}b",
    "\u{202e}gnp.exe",
    "\u{2066}x\u{2069}",
    "\u{200f}\u{200e}\u{061c}",
    "\u{85}\u{9b}31m",
    "a\u{2028}b\u{2029}c",
    "\\u{1b} fake escape",
];

fn has_dangerous_bytes(s: &str, allow_newline: bool) -> bool {
    s.chars().any(|c| {
        (c.is_control() && !(allow_newline && c == '\n'))
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            || c == '\u{2028}'
            || c == '\u{2029}'
    })
}

#[test]
fn the_title_is_one_safe_line() {
    for input in HOSTILE_INPUTS {
        let s = sanitize_header(input, MAX_HEADER_BYTES);
        assert!(!has_dangerous_bytes(&s, false), "{input:?} -> {s:?}");
        assert!(!s.contains('\n') && !s.contains('\r'));
    }
}

#[test]
fn the_title_follows_the_safe_display_rule() {
    for input in HOSTILE_INPUTS {
        let expected = Untrusted::new((*input).to_string()).safe_display();
        // U+2028/2029 stay in safe_display; in headers they are neutralized separately.
        if !input.contains('\u{2028}') && !input.contains('\u{2029}') {
            assert_eq!(sanitize_header(input, MAX_HEADER_BYTES), expected, "{input:?}");
        }
    }
}

#[test]
fn the_title_keeps_turkish_letters() {
    assert_eq!(
        sanitize_header("\u{015e}\u{00fc}spicious out: \u{0131}\u{011f}d\u{00f6}\u{00fc}", MAX_HEADER_BYTES),
        "\u{015e}\u{00fc}spicious out: \u{0131}\u{011f}d\u{00f6}\u{00fc}"
    );
}

#[test]
fn the_body_keeps_newlines_and_neutralizes_the_rest() {
    let s = sanitize_body("line1\nline2\r\n\u{1b}[31mx\u{202e}y", 4000);
    assert!(s.starts_with("line1\nline2"));
    assert!(!has_dangerous_bytes(&s, true), "{s:?}");
    assert!(s.contains("\\u{d}"), "CR must be neutralized: {s:?}");
    assert!(s.contains("\\u{1b}"));
    assert!(s.contains("\\u{202e}"));
}

#[test]
fn the_body_is_safe_for_hostile_input() {
    for input in HOSTILE_INPUTS {
        let s = sanitize_body(input, 4000);
        assert!(!has_dangerous_bytes(&s, true), "{input:?} -> {s:?}");
    }
}

#[test]
fn length_is_bounded_without_splitting_a_character() {
    for n in [10usize, 11, 12, 50, 200] {
        let long = "\u{015f}".repeat(5_000);
        let b = sanitize_header(&long, n);
        assert!(b.len() <= n, "header {} bytes, limit {n}", b.len());
        assert!(b.ends_with('…'), "{b:?}");
        let g = sanitize_body(&long, n);
        assert!(g.len() <= n, "body {} bytes, limit {n}", g.len());
        assert!(g.ends_with('…'));
    }
}

#[test]
fn text_within_the_limit_is_unchanged_and_gets_no_dots() {
    assert_eq!(sanitize_header("sh\u{0131}rt", 200), "sh\u{0131}rt");
    assert_eq!(sanitize_body("sh\u{0131}rt\ntext", 200), "sh\u{0131}rt\ntext");
}

#[test]
fn an_escape_sequence_is_never_split() {
    // Every ESC costs 6 bytes as "\u{1b}"; even if the limit lands mid-escape, no half escape stays.
    let input = "\u{1b}".repeat(1_000);
    for n in 7..40 {
        let s = sanitize_header(&input, n);
        assert!(s.len() <= n);
        let body = s.trim_end_matches('…');
        assert_eq!(body.len() % 6, 0, "n={n}: {s:?}");
    }
}

#[test]
fn overlong_input_stays_fast() {
    let input = "x\u{1b}".repeat(2_000_000);
    let t = std::time::Instant::now();
    let s = sanitize_body(&input, 4000);
    assert!(s.len() <= 4000);
    assert!(t.elapsed() < std::time::Duration::from_secs(2), "must finish in linear time");
}

#[test]
fn base64_standard_vectors() {
    // RFC 4648 §10
    for (input, expected) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64_encode(input.as_bytes()), expected);
    }
    assert_eq!(base64_encode(&[0xff, 0xfe, 0xfd]), "//79");
}

#[test]
fn rfc2047_leaves_ascii_as_is() {
    assert_eq!(rfc2047_encode("[Koru] Critical: decoy read", "\r\n "), "[Koru] Critical: decoy read");
}

#[test]
fn rfc2047_encodes_and_decodes_turkish() {
    let k = rfc2047_encode("\u{015e}\u{00fc}spicious out", " ");
    assert!(k.starts_with("=?UTF-8?B?") && k.ends_with("?="), "{k}");
    assert!(k.is_ascii());
    // Decode: join the B-encoded words.
    let body = k.trim_start_matches("=?UTF-8?B?").trim_end_matches("?=");
    assert_eq!(body, base64_encode("\u{015e}\u{00fc}spicious out".as_bytes()));
}

#[test]
fn long_text_splits_into_words_with_newlines_only_at_separators() {
    let input = "A very long h\u{011f}ader ".repeat(30);
    let k = rfc2047_encode(&input, "\r\n ");
    for (i, line) in k.split("\r\n ").enumerate() {
        assert!(line.len() <= 75, "word {i} is {} characters", line.len());
        assert!(line.starts_with("=?UTF-8?B?") && line.ends_with("?="));
        assert!(!line.contains('\r') && !line.contains('\n'));
    }
    assert!(k.is_ascii());
}

#[test]
fn rfc2047_encodes_newlines_and_cannot_inject_headers() {
    let k = rfc2047_encode("first\r\nX-Evil: 1", "\r\n ");
    assert!(!k.contains("X-Evil"), "{k}");
    for line in k.split("\r\n ") {
        assert!(!line.contains('\r') && !line.contains('\n'));
    }
}

#[test]
fn a_fake_encoded_word_does_not_pass_as_ascii() {
    // ASCII text containing "=?" would be read as an encoded word if left as-is.
    let k = rfc2047_encode("=?UTF-8?B?AAAA?=", " ");
    assert_ne!(k, "=?UTF-8?B?AAAA?=");
}

// --- url ---

fn completed(a: &str) -> HttpsAddress {
    HttpsAddress::parse_parts(a).unwrap_or_else(|e| panic!("{a}: {e}"))
}

fn a_rejection(a: &str) {
    let error = HttpsAddress::parse_parts(a).expect_err(a);
    assert!(matches!(error, NotifyError::Settings(_)), "{a}: {error:?}");
    assert!(a.is_empty() || !error.to_string().contains(a), "the error must not contain the address: {error}");
}

#[test]
fn an_https_address_is_accepted() {
    let a = completed("https://ntfy.sh/secret-topic");
    assert!(a.is_tls());
    assert_eq!(a.host(), "ntfy.sh");
    assert_eq!(a.port(), 443);
    assert_eq!(a.path(), "/secret-topic");
    assert_eq!(a.query(), None);
    let b = completed("https://hc-ping.com:8443/abc-123?x=1");
    assert_eq!((b.host(), b.port(), b.path(), b.query()), ("hc-ping.com", 8443, "/abc-123", Some("x=1")));
    assert_eq!(completed("https://example.test").path(), "/");
}

#[test]
fn addresses_are_https_only_with_one_127_0_0_1_exception() {
    a_rejection("http://ntfy.sh/topic");
    a_rejection("http://localhost:8080/");
    a_rejection("http://127.0.0.2:8080/");
    a_rejection("http://127.0.0.1.evil.test/");
    a_rejection("ftp://example.test/");
    a_rejection("//example.test/");
    a_rejection("example.test/topic");
    let a = completed("http://127.0.0.1:8080/topic");
    assert!(!a.is_tls());
    assert_eq!((a.host(), a.port()), ("127.0.0.1", 8080));
    assert_eq!(completed("http://127.0.0.1/x").port(), 80);
}

#[test]
fn an_address_rejects_dangerous_input() {
    a_rejection("https://user:password@example.test/");
    a_rejection("https://user@example.test/");
    a_rejection("https://example.test/path#piece");
    a_rejection("https://example.test/a b");
    a_rejection("https://example.test/a\r\nHost: evil");
    a_rejection("https://example.test/a\nb");
    a_rejection("https://sample\u{0}.test/");
    a_rejection("https://\u{00fc}ber.test/");
    a_rejection("https://example.test/\u{00e9}t\u{00e9}");
    a_rejection("https://[::1]/");
    a_rejection("https:///path");
    a_rejection("https://:443/path");
    a_rejection("https://example.test:0/");
    a_rejection("https://example.test:99999/");
    a_rejection("https://example.test:abc/");
    a_rejection("https://ex ample.test/");
    a_rejection("https://example.test\\@evil.test/");
    a_rejection("");
}

#[test]
fn adding_a_path_keeps_and_validates_the_query() {
    let a = completed("https://hc-ping.com/uuid-1");
    assert_eq!(a.join_path("fail").unwrap().path(), "/uuid-1/fail");
    let b = completed("https://hc-ping.com/uuid-1/?rid=7");
    let c = b.join_path("start").unwrap();
    assert_eq!((c.path(), c.query()), ("/uuid-1/start", Some("rid=7")));
    assert!(a.join_path("a b").is_err());
    assert!(a.join_path("x\r\ny").is_err());
    assert!(a.join_path("../x").is_err());
}

#[test]
fn the_address_debug_output_hides_the_address() {
    let a = completed("https://hc-ping.com/very-secret-uuid");
    let d = format!("{a:?}");
    assert!(!d.contains("very-secret-uuid") && !d.contains("hc-ping"), "{d}");
}
