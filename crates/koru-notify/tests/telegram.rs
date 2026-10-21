//! The Telegram channel (protected set): sending against a fake
//! HTTP server, `parse_mode` injection (plain text), token and chat-id validation, error classes.

mod common;

use std::time::Duration;

use common::*;
use koru_event::{InterfaceError, NotificationChannel, Severity};
use koru_notify::{HttpsAddress, NotifyError, Secret, TelegramChannel, TelegramSettings};

const TOKEN: &str = "123456789:AAE_secret-TOKEN_xyz";

fn channel(fake: &FakeHttp) -> TelegramChannel {
    let mut settings = TelegramSettings::new(Secret::new(TOKEN), "-1001234567890")
        .unwrap()
        .set_api_base(HttpsAddress::parse_parts(&fake.url("")).unwrap());
    settings.timeout = Duration::from_millis(800);
    TelegramChannel::new(settings)
}

#[test]
fn telegram_channel_name() {
    let s = FakeHttp::start();
    assert_eq!(channel(&s).name(), "telegram");
}

#[test]
fn send_message_posts_json() {
    let s = FakeHttp::start();
    channel(&s).send(&notification(Severity::Critical, "Decoy read", "Pr\u{00f6}cess the file opened")).unwrap();
    let i = s.one_request();
    assert_eq!(i.method, "POST");
    assert_eq!(i.path, format!("/bot{TOKEN}/sendMessage"));
    assert_eq!(i.title("Content-Type"), Some("application/json"));
    let j = i.body_json();
    assert_eq!(j["chat_id"], "-1001234567890");
    let text = j["text"].as_str().unwrap();
    assert!(text.contains("Decoy read") && text.starts_with("[Koru Critical]"), "{text}");
    assert_eq!(j["disable_web_page_preview"], true);
}

#[test]
fn parse_mode_is_never_sent_and_markup_is_not_interpreted() {
    let s = FakeHttp::start();
    let body = "<b>bold</b> *star* _under_ [link](http://evil.test) `code` <a href=\"http://evil.test\">x</a> &amp; <tg-spoiler>s</tg-spoiler>";
    channel(&s).send(&notification(Severity::Warning, "<i>title</i>", body)).unwrap();
    let raw = s.one_request();
    let j = raw.body_json();
    let object = j.as_object().unwrap();
    assert!(!object.contains_key("parse_mode"), "parse_mode must not be sent: {object:?}");
    assert!(!object.contains_key("entities"));
    // It goes as plain text, as-is (unescaped); Telegram does not interpret plain text.
    let text = j["text"].as_str().unwrap();
    assert!(text.contains(body), "{text}");
    assert!(text.contains("<i>title</i>"));
    assert!(!raw.body_text().contains("parse_mode"));
}

#[test]
fn json_escaping_keeps_the_body_intact() {
    let s = FakeHttp::start();
    let body = "quote \" back \\ line\nbreak \",\"parse_mode\":\"HTML\",\"x\":\"";
    channel(&s).send(&notification(Severity::Warning, "b", body)).unwrap();
    let j = s.one_request().body_json();
    assert!(j.as_object().unwrap().get("parse_mode").is_none(), "{j}");
    assert_eq!(j.as_object().unwrap().len(), 3, "only chat_id, text, disable_web_page_preview: {j}");
}

#[test]
fn terminal_and_direction_chars_are_neutralized() {
    let s = FakeHttp::start();
    channel(&s).send(&notification(Severity::Warning, "\u{1b}[31mb\u{202e}", "g\u{0}\r\nx\u{9b}")).unwrap();
    let text = s.one_request().body_json()["text"].as_str().unwrap().to_string();
    for c in text.chars() {
        assert!(c == '\n' || !c.is_control(), "a control character remains: {text:?}");
        assert!(c != '\u{202e}');
    }
    assert!(text.contains("\\u{1b}") && text.contains("\\u{202e}"));
}

#[test]
fn the_length_stays_within_the_telegram_limit() {
    let s = FakeHttp::start();
    channel(&s).send(&notification(Severity::Warning, &"B".repeat(100_000), &"\u{015f}".repeat(1_000_000))).unwrap();
    let text = s.one_request().body_json()["text"].as_str().unwrap().to_string();
    assert!(text.chars().count() <= 4096, "{} characters", text.chars().count());
}

#[test]
fn the_token_and_chat_id_are_validated() {
    for token in [
        "",
        "t0ken",
        "123:abc/../x",
        "123:abc def",
        "123:abc\r\nX: 1",
        "abc:123",
        "123456789:",
        ":AAE",
        "123:ab?c=1",
        "123:ab#c",
        "12345:\u{011f}\u{00fc}",
    ] {
        let error = TelegramSettings::new(Secret::new(token), "123").expect_err(token);
        assert!(matches!(error, NotifyError::Settings(_)));
        if !token.is_empty() {
            assert!(!error.to_string().contains(token), "the error must not contain the token: {error}");
        }
    }
    for chat in [
        "",
        "abc",
        "12 3",
        "-",
        "@",
        "@a",
        "123\r\n",
        "12.5",
        "@channel name",
        "@channel/../x",
        "1234567890123456789012345",
    ] {
        assert!(TelegramSettings::new(Secret::new(TOKEN), chat).is_err(), "{chat:?}");
    }
    for chat in ["123456", "-1001234567890", "@koru_alert"] {
        assert!(TelegramSettings::new(Secret::new(TOKEN), chat).is_ok(), "{chat:?}");
    }
}

#[test]
fn the_default_api_address_is_telegram_https() {
    // No network; only the default being https://api.telegram.org is checked.
    let settings = TelegramSettings::new(Secret::new(TOKEN), "123").unwrap();
    assert!(settings.api_base.is_tls());
    assert_eq!(settings.api_base.host(), "api.telegram.org");
    assert_eq!(settings.api_base.port(), 443);
}

#[test]
fn http_statuses_are_classified_right() {
    for (state, is_transient) in
        [(500u16, true), (502, true), (429, true), (400, false), (401, false), (403, false), (404, false)]
    {
        let s = FakeHttp::start_answering(FakeReply::WithStatus(state));
        let error = channel(&s).send(&plain_notification()).expect_err("an error is expected");
        match (is_transient, &error) {
            (true, InterfaceError::Transient(_)) | (false, InterfaceError::Permanent(_)) => {}
            _ => panic!("state {state}: {error:?}"),
        }
    }
    let s = FakeHttp::start_answering(FakeReply::WithStatus(200));
    channel(&s).send(&plain_notification()).unwrap();
}

#[test]
fn a_connect_error_is_transient() {
    let settings = TelegramSettings::new(Secret::new(TOKEN), "123")
        .unwrap()
        .set_api_base(HttpsAddress::parse_parts(&format!("http://127.0.0.1:{}", a_free_port())).unwrap());
    let error = TelegramChannel::new(settings).send(&plain_notification()).expect_err("must be rejected");
    assert!(matches!(error, InterfaceError::Transient(_)), "{error:?}");
}

#[test]
fn the_token_stays_out_of_errors_and_debug() {
    let s = FakeHttp::start_answering(FakeReply::WithStatus(401));
    let mut k = channel(&s);
    let error = k.send(&plain_notification()).unwrap_err().to_string();
    for forbidden in [TOKEN, "AAE_secret", "-1001234567890", "127.0.0.1"] {
        assert!(!error.contains(forbidden), "the error message must not contain {forbidden:?}: {error}");
    }
    let d = format!("{k:?}");
    for forbidden in [TOKEN, "AAE_secret"] {
        assert!(!d.contains(forbidden), "Debug must not contain {forbidden:?}: {d}");
    }
    let settings_debug = format!("{:?}", TelegramSettings::new(Secret::new(TOKEN), "123").unwrap());
    assert!(!settings_debug.contains("AAE_secret"), "{settings_debug}");
}

#[test]
fn redirects_are_never_followed() {
    let target = FakeHttp::start();
    let s = FakeHttp::start_answering(FakeReply::Redirect(307, target.url("/x")));
    let error = channel(&s).send(&plain_notification()).expect_err("3xx");
    assert!(matches!(error, InterfaceError::Permanent(_)));
    assert_eq!(target.request_count(), 0);
}
