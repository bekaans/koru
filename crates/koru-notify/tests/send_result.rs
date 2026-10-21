//! The last send result (protected set):
//! for live-lab evidence the channels expose their last HTTP status (`last_status`) and SMTP
//! its last server response (`last_response`). Secrets never leak into these outputs.

mod common;

use std::time::Duration;

use common::*;
use koru_event::{Heartbeat, NotificationChannel};
use koru_notify::{
    HealthchecksHeartbeat, HttpsAddress, NtfyChannel, NtfySettings, Secret, SmtpChannel, SmtpSettings, SmtpTls,
    TelegramChannel, TelegramSettings,
};

const PASSWORD: &str = "very-secret-password-9!";
const TOKEN: &str = "123456789:AAE_secret-TOKEN_xyz";

fn ntfy(s: &FakeHttp) -> NtfyChannel {
    let mut a = NtfySettings::new(HttpsAddress::parse_parts(&s.url("/secret-topic")).unwrap());
    a.token = Some(Secret::new("tk_secret"));
    a.timeout = Duration::from_millis(800);
    NtfyChannel::new(a)
}

fn telegram(s: &FakeHttp) -> TelegramChannel {
    let mut a = TelegramSettings::new(Secret::new(TOKEN), "123456")
        .unwrap()
        .set_api_base(HttpsAddress::parse_parts(&s.url("")).unwrap());
    a.timeout = Duration::from_millis(800);
    TelegramChannel::new(a)
}

fn smtp(s: &FakeSmtp) -> SmtpChannel {
    let mut a = SmtpSettings::new(
        "127.0.0.1",
        s.port,
        "koru-user",
        Secret::new(PASSWORD),
        "koru@example.test",
        "alice@example.test",
    )
    .unwrap()
    .set_tls(SmtpTls::None)
    .unwrap();
    a.timeout = Duration::from_millis(1500);
    SmtpChannel::new(a)
}

#[test]
fn the_ntfy_last_status() {
    let s = FakeHttp::start();
    let mut k = ntfy(&s);
    assert_eq!(k.last_status(), None, "nothing before any send");
    k.send(&plain_notification()).unwrap();
    assert_eq!(k.last_status(), Some(200));
    s.set_defaults(FakeReply::WithStatus(503));
    assert!(k.send(&plain_notification()).is_err());
    assert_eq!(k.last_status(), Some(503), "a failed response code is visible too");
    s.set_defaults(FakeReply::WithStatus(204));
    k.send(&plain_notification()).unwrap();
    assert_eq!(k.last_status(), Some(204));
}

#[test]
fn a_failed_ntfy_reply_clears_the_last_status() {
    let s = FakeHttp::start();
    let mut k = ntfy(&s);
    k.send(&plain_notification()).unwrap();
    assert_eq!(k.last_status(), Some(200));
    s.set_defaults(FakeReply::DropConnection);
    assert!(k.send(&plain_notification()).is_err());
    assert_eq!(k.last_status(), None, "an old success must not mask a new failure");
}

#[test]
fn the_telegram_last_status() {
    let s = FakeHttp::start();
    let mut k = telegram(&s);
    assert_eq!(k.last_status(), None);
    k.send(&plain_notification()).unwrap();
    assert_eq!(k.last_status(), Some(200));
    s.set_defaults(FakeReply::WithStatus(401));
    assert!(k.send(&plain_notification()).is_err());
    assert_eq!(k.last_status(), Some(401));
}

#[test]
fn the_heartbeat_last_status() {
    let s = FakeHttp::start();
    let mut k = HealthchecksHeartbeat::new(HttpsAddress::parse_parts(&s.url("/ping/uuid")).unwrap())
        .set_timeout(Duration::from_millis(800));
    assert_eq!(k.last_status(), None);
    k.beat().unwrap();
    assert_eq!(k.last_status(), Some(200));
    s.set_defaults(FakeReply::WithStatus(404));
    assert!(k.failed().is_err());
    assert_eq!(k.last_status(), Some(404));
}

#[test]
fn an_error_carries_only_the_status_code() {
    // `last_status` is a number; it cannot carry a token, URL or body (by type).
    let s = FakeHttp::start();
    let mut k = telegram(&s);
    k.send(&plain_notification()).unwrap();
    let state: Option<u16> = k.last_status();
    assert_eq!(state, Some(200));
}

#[test]
fn on_success_the_last_response_is_the_final_server_reply() {
    let s = FakeSmtp::start(SmtpScript::default());
    let mut k = smtp(&s);
    assert_eq!(k.last_response(), None);
    k.send(&plain_notification()).unwrap();
    assert_eq!(k.last_response(), Some("250 2.0.0 Ok: queued as ABC123"));
}

#[test]
fn on_failure_the_last_response_is_the_error_reply() {
    let s = FakeSmtp::start(SmtpScript { rcpt_reply: "550 5.1.1 to_addr unknown", ..SmtpScript::default() });
    let mut k = smtp(&s);
    assert!(k.send(&plain_notification()).is_err());
    assert_eq!(k.last_response(), Some("550 5.1.1 to_addr unknown"));
}

#[test]
fn a_smtp_connect_error_leaves_no_last_response() {
    let s = FakeSmtp::start(SmtpScript::default());
    let mut k = smtp(&s);
    k.send(&plain_notification()).unwrap();
    assert!(k.last_response().is_some());
    let closed_port = a_free_port();
    let mut a =
        SmtpSettings::new("127.0.0.1", closed_port, "k", Secret::new(PASSWORD), "a@example.test", "b@example.test")
            .unwrap()
            .set_tls(SmtpTls::None)
            .unwrap();
    a.timeout = Duration::from_millis(500);
    let mut k2 = SmtpChannel::new(a);
    assert!(k2.send(&plain_notification()).is_err());
    assert_eq!(k2.last_response(), None, "nothing when no response came");
}

#[test]
fn the_last_response_neutralizes_control_chars_and_is_bounded() {
    let s = FakeSmtp::start(SmtpScript { data_end_reply: "250 ok \u{1b}[31mred\u{202e}", ..SmtpScript::default() });
    let mut k = smtp(&s);
    k.send(&plain_notification()).unwrap();
    let y = k.last_response().unwrap();
    assert!(!y.contains('\u{1b}') && !y.contains('\u{202e}'), "{y:?}");
    assert!(y.starts_with("250 ok "));

    let long_reply: &'static str = Box::leak(format!("250 {}", "x".repeat(1500)).into_boxed_str());
    let s = FakeSmtp::start(SmtpScript { data_end_reply: long_reply, ..SmtpScript::default() });
    let mut k = smtp(&s);
    k.send(&plain_notification()).unwrap();
    assert!(k.last_response().unwrap().len() <= 200);
}

#[test]
fn the_last_response_hides_the_secret_even_when_echoed() {
    // Even when the server echoes the password and user name, they never reach the output.
    let response: &'static str = Box::leak(format!("250 ok user=koru-user password={PASSWORD}").into_boxed_str());
    let s = FakeSmtp::start(SmtpScript { data_end_reply: response, ..SmtpScript::default() });
    let mut k = smtp(&s);
    k.send(&plain_notification()).unwrap();
    let y = k.last_response().unwrap().to_string();
    assert!(!y.contains(PASSWORD) && !y.contains("koru-user"), "{y}");
    assert!(y.starts_with("250 ok"));
    // In a normal session too (the final reply, not the AUTH reply) there is no secret.
    let s = FakeSmtp::start(SmtpScript::default());
    let mut k = smtp(&s);
    k.send(&plain_notification()).unwrap();
    assert!(!k.last_response().unwrap().contains(PASSWORD));
    assert!(!format!("{k:?}").contains(PASSWORD));
}
