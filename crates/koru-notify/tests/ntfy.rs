//! The ntfy channel (protected set): sending against a fake HTTP
//! server, header injection, error classes, mandatory TLS and secret secrecy.

mod common;

use std::time::Duration;

use common::*;
use koru_event::{InterfaceError, NotificationChannel, Severity};
use koru_notify::{HttpsAddress, NtfyChannel, NtfySettings, Secret};

fn channel(fake: &FakeHttp, token: Option<&str>) -> NtfyChannel {
    let mut settings = NtfySettings::new(HttpsAddress::parse_parts(&fake.url("/koru-secret-topic")).unwrap());
    settings.token = token.map(Secret::new);
    settings.timeout = Duration::from_millis(800);
    NtfyChannel::new(settings)
}

#[test]
fn ntfy_channel_name() {
    let s = FakeHttp::start();
    assert_eq!(channel(&s, None).name(), "ntfy");
}

#[test]
fn a_notification_goes_by_post() {
    let s = FakeHttp::start();
    let mut k = channel(&s, None);
    k.send(&notification(Severity::Critical, "Decoy read", "The process opened /root/.ssh/id_ed25519")).unwrap();
    let i = s.one_request();
    assert_eq!(i.method, "POST");
    assert_eq!(i.path, "/koru-secret-topic");
    assert_eq!(i.body_text(), "The process opened /root/.ssh/id_ed25519");
    assert_eq!(i.title("Title"), Some("Decoy read"));
    assert_eq!(i.title("Priority"), Some("5"));
    assert_eq!(i.header_count("Title"), 1);
    assert!(i.title("Authorization").is_none(), "without a token no Authorization is sent");
    assert!(i.title("Host").unwrap().starts_with("127.0.0.1"));
}

#[test]
fn severity_sets_priority_and_tags() {
    let s = FakeHttp::start();
    let mut k = channel(&s, None);
    for severity in [Severity::Info, Severity::Warning, Severity::Critical] {
        k.send(&notification(severity, "b", "g")).unwrap();
    }
    let requests = s.requests();
    assert_eq!(requests.len(), 3);
    for (i, priority) in requests.iter().zip(["2", "4", "5"]) {
        assert_eq!(i.title("Priority"), Some(priority));
        let tags = i.title("Tags").expect("Tags");
        assert!(tags.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ',' || c == '-'), "{tags}");
    }
}

#[test]
fn a_token_goes_as_a_bearer() {
    let s = FakeHttp::start();
    let mut k = channel(&s, Some("tk_example_token_123"));
    k.send(&plain_notification()).unwrap();
    assert_eq!(s.one_request().title("Authorization"), Some("Bearer tk_example_token_123"));
}

#[test]
fn a_non_ascii_header_goes_rfc2047_the_body_stays_utf8() {
    let s = FakeHttp::start();
    let mut k = channel(&s, None);
    k.send(&notification(
        Severity::Warning,
        "\u{015e}uspicious out",
        "\u{011f}\u{00fc}\u{015f}i\u{00f6}\u{00e7} \u{0130}I",
    ))
    .unwrap();
    let i = s.one_request();
    let t = i.title("Title").unwrap();
    assert!(t.is_ascii() && t.starts_with("=?UTF-8?B?"), "{t}");
    assert!(i.raw.windows(b"Title: ".len()).any(|w| w == b"Title: "));
    assert_eq!(i.body_text(), "\u{011f}\u{00fc}\u{015f}i\u{00f6}\u{00e7} \u{0130}I");
    // The body length is in bytes.
    assert_eq!(
        i.title("Content-Length").unwrap(),
        "\u{011f}\u{00fc}\u{015f}i\u{00f6}\u{00e7} \u{0130}I".len().to_string()
    );
}

#[test]
fn header_injection_adds_no_extra_header() {
    let s = FakeHttp::start();
    let mut k = channel(&s, None);
    for title in [
        "x\r\nX-Evil: 1",
        "x\nX-Evil: 1",
        "x\rX-Evil: 1",
        "x\r\n\r\nPOST /second HTTP/1.1\r\nHost: a\r\n\r\n",
        "x\u{0}\u{1b}[2J",
    ] {
        k.send(&notification(Severity::Critical, title, "body")).unwrap();
    }
    let requests = s.requests();
    assert_eq!(requests.len(), 5, "the request must not split: {}", requests.len());
    for i in requests {
        assert_eq!(i.header_count("X-Evil"), 0, "{:?}", i.headers);
        assert_eq!(i.header_count("Title"), 1);
        assert_eq!(i.body_text(), "body");
        let raw = String::from_utf8_lossy(&i.raw);
        // In the header block, CRLFs belong only to the request framing.
        let block = raw.split("\r\n\r\n").next().unwrap();
        assert!(!block.contains('\u{0}') && !block.contains('\u{1b}'));
        assert!(!block.contains("X-Evil"));
    }
}

#[test]
fn body_injection_and_terminal_codes_are_neutralized() {
    let s = FakeHttp::start();
    let mut k = channel(&s, None);
    k.send(&notification(Severity::Warning, "b", "a\u{1b}[31mred\u{202e}gnp.exe\u{0}")).unwrap();
    let g = s.one_request().body_text();
    assert!(!g.contains('\u{1b}') && !g.contains('\u{202e}') && !g.contains('\u{0}'), "{g:?}");
    assert!(g.contains("\\u{1b}") && g.contains("\\u{202e}"));
}

#[test]
fn an_overlong_subject_and_body_are_bounded() {
    let s = FakeHttp::start();
    let mut k = channel(&s, None);
    k.send(&notification(Severity::Warning, &"B".repeat(1_000_000), &"g".repeat(5_000_000))).unwrap();
    let i = s.one_request();
    assert!(i.title("Title").unwrap().len() <= 300);
    assert!(i.body.len() <= 4096, "the ntfy body limit is 4096 bytes: {}", i.body.len());
    assert!(i.raw.len() < 8192);
}

#[test]
fn http_statuses_are_classified_right() {
    for (state, is_transient) in [
        (500u16, true),
        (502, true),
        (503, true),
        (429, true),
        (408, true),
        (400, false),
        (401, false),
        (403, false),
        (404, false),
        (413, false),
    ] {
        let s = FakeHttp::start_answering(FakeReply::WithStatus(state));
        let error = channel(&s, None).send(&plain_notification()).expect_err("an error is expected");
        match (is_transient, &error) {
            (true, InterfaceError::Transient(_)) | (false, InterfaceError::Permanent(_)) => {}
            _ => panic!("state {state}: {error:?}"),
        }
    }
    let s = FakeHttp::start_answering(FakeReply::WithStatus(204));
    channel(&s, None).send(&plain_notification()).expect("2xx succeeds");
}

#[test]
fn redirects_are_never_followed() {
    let target = FakeHttp::start();
    let s = FakeHttp::start_answering(FakeReply::Redirect(302, target.url("/other")));
    let error = channel(&s, Some("token")).send(&plain_notification()).expect_err("3xx is an error");
    assert!(matches!(error, InterfaceError::Permanent(_)), "{error:?}");
    assert_eq!(target.request_count(), 0, "redirects are never followed (the token would leak)");
}

#[test]
fn a_connect_error_and_a_timeout_are_transient() {
    let settings =
        NtfySettings::new(HttpsAddress::parse_parts(&format!("http://127.0.0.1:{}/k", a_free_port())).unwrap());
    let error = NtfyChannel::new(settings).send(&plain_notification()).expect_err("a refused connection");
    assert!(matches!(error, InterfaceError::Transient(_)), "{error:?}");

    let s = FakeHttp::start_answering(FakeReply::Silent);
    let t = std::time::Instant::now();
    let error = channel(&s, None).send(&plain_notification()).expect_err("a timeout");
    assert!(matches!(error, InterfaceError::Transient(_)), "{error:?}");
    assert!(t.elapsed() < Duration::from_secs(4), "the timeout must apply: {:?}", t.elapsed());

    let s = FakeHttp::start_answering(FakeReply::DropConnection);
    let error = channel(&s, None).send(&plain_notification()).expect_err("a severed connection");
    assert!(matches!(error, InterfaceError::Transient(_)), "{error:?}");
}

#[test]
fn an_https_address_speaks_tls_not_plaintext() {
    let (port, rx) = raw_capture();
    let mut settings =
        NtfySettings::new(HttpsAddress::parse_parts(&format!("https://127.0.0.1:{port}/topic")).unwrap());
    settings.timeout = TLS_START_DEADLINE;
    let error = NtfyChannel::new(settings).send(&plain_notification()).expect_err("the TLS handshake fails");
    assert!(matches!(error, InterfaceError::Transient(_) | InterfaceError::Permanent(_)));
    let first = rx.recv_timeout(TLS_START_DEADLINE + Duration::from_secs(2)).expect("it must connect");
    assert!(
        first.len() >= 3 && first[0] == 0x16 && first[1] == 0x03,
        "a TLS ClientHello is expected: {:02x?}",
        &first[..first.len().min(8)]
    );
    let text = String::from_utf8_lossy(&first);
    assert!(!text.contains("POST") && !text.contains("Title"), "plaintext must never go out");
}

#[test]
fn errors_and_debug_hide_the_secret() {
    let s = FakeHttp::start_answering(FakeReply::WithStatus(500));
    let mut k = channel(&s, Some("tk_VERY_SECRET_TOKEN"));
    let error = k.send(&plain_notification()).unwrap_err().to_string();
    for forbidden in ["tk_VERY_SECRET_TOKEN", "koru-secret-topic", "127.0.0.1", &s.port.to_string()] {
        assert!(!error.contains(forbidden), "the error message must not contain {forbidden:?}: {error}");
    }
    let d = format!("{k:?}");
    for forbidden in ["tk_VERY_SECRET_TOKEN", "koru-secret-topic"] {
        assert!(!d.contains(forbidden), "Debug must not contain {forbidden:?}: {d}");
    }
}
