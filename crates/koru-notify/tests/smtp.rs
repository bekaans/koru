//! The SMTP channel (protected set): sessions against a fake
//! SMTP server, Subject and header injection, mandatory STARTTLS, id validation, reply classes.

mod common;

use std::time::Duration;

use common::*;
use koru_event::{InterfaceError, NotificationChannel, Severity};
use koru_notify::text::base64_encode;
use koru_notify::{NotifyError, Secret, SmtpChannel, SmtpSettings, SmtpTls};

const PASSWORD: &str = "very-secret-password-9!";

fn settings(s: &FakeSmtp) -> SmtpSettings {
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
    a
}

fn channel(s: &FakeSmtp) -> SmtpChannel {
    SmtpChannel::new(settings(s))
}

fn command_seen(o: &FakeSmtpSession, prefix: &str) -> bool {
    o.commands.iter().any(|k| k.to_ascii_uppercase().starts_with(&prefix.to_ascii_uppercase()))
}

#[test]
fn smtp_channel_name() {
    let s = FakeSmtp::start(SmtpScript::default());
    assert_eq!(channel(&s).name(), "smtp");
}

#[test]
fn a_full_session_delivers_the_mail() {
    let s = FakeSmtp::start(SmtpScript::default());
    let b = notification(Severity::Critical, "Decoy read", "The process opened /root/.ssh/id_ed25519.\nSecond line.");
    channel(&s).send(&b).unwrap();
    let o = s.one_session();
    assert!(o.commands[0].to_ascii_uppercase().starts_with("EHLO"));
    assert!(command_seen(&o, "MAIL FROM:<koru@example.test>"), "{:?}", o.commands);
    assert!(command_seen(&o, "RCPT TO:<alice@example.test>"));
    assert!(command_seen(&o, "DATA"));
    assert!(command_seen(&o, "QUIT"));
    let (headers, body) = parse_mailbox(o.data.as_ref().expect("DATA"));
    let al = |name: &str| headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(name)).map(|(_, d)| d.clone());
    assert_eq!(al("From").as_deref(), Some("koru@example.test"));
    assert_eq!(al("To").as_deref(), Some("alice@example.test"));
    assert!(al("Subject").unwrap().contains("Decoy read"), "{:?}", al("Subject"));
    assert!(al("Date").is_some() && al("Message-ID").is_some());
    assert_eq!(al("MIME-Version").as_deref(), Some("1.0"));
    assert!(al("Content-Type").unwrap().to_ascii_lowercase().contains("text/plain; charset=utf-8"));
    assert_eq!(al("Content-Transfer-Encoding").as_deref(), Some("base64"));
    assert!(al("X-Koru-Event").unwrap().contains(&b.event_id.to_string()));
    // The body is base64: decoding brings the text back.
    let text: String = String::from_utf8(body).unwrap().split("\r\n").collect();
    assert!(text.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)), "{text}");
    assert!(text.contains(&base64_encode("The process opened /root/.ssh/id_ed25519.\nSecond line.".as_bytes())));
}

#[test]
fn authentication_uses_auth_plain() {
    let s = FakeSmtp::start(SmtpScript::default());
    channel(&s).send(&plain_notification()).unwrap();
    let o = s.one_session();
    let expected = format!("AUTH PLAIN {}", base64_encode(format!("\0koru-user\0{PASSWORD}").as_bytes()));
    assert!(o.commands.contains(&expected), "{:?}", o.commands);
}

#[test]
fn subject_injection_adds_no_header_or_command() {
    for title in [
        "x\r\nBcc: victim@evil.test",
        "x\nBcc: victim@evil.test",
        "x\rBcc: victim@evil.test",
        "x\r\n\r\nBody injection\r\n.\r\nMAIL FROM:<evil@evil.test>\r\n",
        "x\u{0}\u{1b}[2J",
    ] {
        let s = FakeSmtp::start(SmtpScript::default());
        channel(&s).send(&notification(Severity::Critical, title, "g")).unwrap();
        let o = s.one_session();
        let (headers, _) = parse_mailbox(o.data.as_ref().unwrap());
        assert!(!headers.iter().any(|(a, _)| a.eq_ignore_ascii_case("bcc")), "{title:?}: {headers:?}");
        assert_eq!(headers.iter().filter(|(a, _)| a.eq_ignore_ascii_case("subject")).count(), 1);
        assert_eq!(
            o.commands.iter().filter(|k| k.to_ascii_uppercase().starts_with("MAIL FROM")).count(),
            1,
            "{title:?}: {:?}",
            o.commands
        );
        assert_eq!(o.commands.iter().filter(|k| k.to_ascii_uppercase().starts_with("RCPT TO")).count(), 1);
        let raw = o.data.unwrap();
        let text = String::from_utf8_lossy(&raw);
        let header_block = text.split("\r\n\r\n").next().unwrap();
        assert!(!header_block.contains("Bcc") && !header_block.contains("evil.test"), "{header_block}");
        assert!(!header_block.contains('\u{0}') && !header_block.contains('\u{1b}'));
    }
}

#[test]
fn a_dot_line_or_command_like_text_in_the_body_does_not_end_the_mail() {
    let s = FakeSmtp::start(SmtpScript::default());
    channel(&s)
        .send(&notification(Severity::Warning, "b", "line\r\n.\r\nQUIT\r\nMAIL FROM:<evil@evil.test>\r\n."))
        .unwrap();
    let o = s.one_session();
    assert_eq!(
        o.commands.iter().filter(|k| k.to_ascii_uppercase().starts_with("MAIL FROM")).count(),
        1,
        "{:?}",
        o.commands
    );
    assert_eq!(o.commands.iter().filter(|k| k.eq_ignore_ascii_case("QUIT")).count(), 1);
    assert!(
        !String::from_utf8_lossy(&o.raw).contains("evil@evil.test"),
        "the body must be base64; no raw text may go out"
    );
}

#[test]
fn a_non_ascii_subject_goes_rfc2047() {
    let s = FakeSmtp::start(SmtpScript::default());
    channel(&s)
        .send(&notification(Severity::Warning, "\u{015e}uspicious out: \u{0131}\u{011f}d\u{00f6}\u{00fc}", "g"))
        .unwrap();
    let o = s.one_session();
    let (headers, _) = parse_mailbox(o.data.as_ref().unwrap());
    let subject = &headers.iter().find(|(a, _)| a.eq_ignore_ascii_case("subject")).unwrap().1;
    assert!(subject.is_ascii() && subject.contains("=?UTF-8?B?"), "{subject}");
    // Raw data must never exceed 998 bytes per line (RFC 5322) and headers should target 78.
    for line in String::from_utf8_lossy(o.data.as_ref().unwrap()).split("\r\n") {
        assert!(line.len() <= 998, "a line too long");
    }
}

#[test]
fn an_overlong_subject_and_body_are_bounded() {
    let s = FakeSmtp::start(SmtpScript::default());
    channel(&s).send(&notification(Severity::Warning, &"\u{015e}".repeat(500_000), &"g".repeat(5_000_000))).unwrap();
    let o = s.one_session();
    let data = o.data.unwrap();
    assert!(data.len() < 64 * 1024, "mail is {} bytes", data.len());
    for line in String::from_utf8_lossy(&data).split("\r\n") {
        assert!(line.len() <= 998);
    }
}

#[test]
fn terminal_and_direction_chars_in_the_body_are_neutralized() {
    let s = FakeSmtp::start(SmtpScript::default());
    channel(&s).send(&notification(Severity::Warning, "b", "a\u{1b}[31mx\u{202e}y")).unwrap();
    let (_, body) = parse_mailbox(s.one_session().data.as_ref().unwrap());
    let decoded = base64_decode(&String::from_utf8(body).unwrap());
    let text = String::from_utf8(decoded).unwrap();
    assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'), "{text:?}");
    assert!(text.contains("\\u{1b}"));
}

fn base64_decode(input: &str) -> Vec<u8> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let mut accumulator = 0u32;
    let mut bit = 0;
    for c in input.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let d = table.iter().position(|t| *t == c).expect("base64 character") as u32;
        accumulator = (accumulator << 6) | d;
        bit += 6;
        if bit >= 8 {
            bit -= 8;
            result.push((accumulator >> bit) as u8);
            accumulator &= (1 << bit) - 1;
        }
    }
    result
}

#[test]
fn without_starttls_no_credentials_or_mail_are_sent() {
    let s = FakeSmtp::start(SmtpScript { offers_starttls: false, ..SmtpScript::default() });
    let mut a = settings(&s);
    a.tls = SmtpTls::StartTls; // field poked directly; an upgrade from a plain connection to 127.0.0.1 is requested
    let error = SmtpChannel::new(a).send(&plain_notification()).expect_err("must not send without TLS");
    assert!(matches!(error, InterfaceError::Transient(_) | InterfaceError::Permanent(_)));
    let o = s.one_session();
    let raw = String::from_utf8_lossy(&o.raw).to_ascii_uppercase();
    assert!(!raw.contains("AUTH"), "ids went out in plaintext: {:?}", o.commands);
    assert!(!command_seen(&o, "MAIL FROM") && !command_seen(&o, "DATA"), "{:?}", o.commands);
    assert!(!String::from_utf8_lossy(&o.raw).contains(&base64_encode(format!("\0koru-user\0{PASSWORD}").as_bytes())));
}

#[test]
fn with_starttls_the_handshake_starts_and_a_failure_sends_no_credentials() {
    let s = FakeSmtp::start(SmtpScript { offers_starttls: true, ..SmtpScript::default() });
    let mut a = settings(&s);
    a.tls = SmtpTls::StartTls;
    a.timeout = TLS_START_DEADLINE;
    let error = SmtpChannel::new(a).send(&plain_notification()).expect_err("the fake server does not know TLS");
    assert!(matches!(error, InterfaceError::Transient(_) | InterfaceError::Permanent(_)));
    let o = s.one_session();
    assert!(command_seen(&o, "STARTTLS"));
    assert!(o.tls_started, "a TLS ClientHello is expected after STARTTLS");
    assert!(!command_seen(&o, "AUTH") && !command_seen(&o, "MAIL FROM"), "{:?}", o.commands);
}

#[test]
fn an_implicit_tls_connection_never_speaks_plain_smtp() {
    let (port, rx) = raw_capture();
    let mut a =
        SmtpSettings::new("127.0.0.1", port, "k", Secret::new(PASSWORD), "koru@example.test", "alice@example.test")
            .unwrap();
    assert_eq!(a.tls, SmtpTls::StartTls, "a non-465 port picks STARTTLS");
    a.tls = SmtpTls::Implicit;
    a.timeout = TLS_START_DEADLINE;
    let error = SmtpChannel::new(a).send(&plain_notification()).expect_err("the TLS handshake fails");
    assert!(matches!(error, InterfaceError::Transient(_) | InterfaceError::Permanent(_)));
    let first_bytes = rx.recv_timeout(TLS_START_DEADLINE + Duration::from_secs(2)).unwrap();
    assert!(
        first_bytes.len() >= 3 && first_bytes[0] == 0x16 && first_bytes[1] == 0x03,
        "a ClientHello is expected: {:02x?}",
        &first_bytes[..first_bytes.len().min(8)]
    );
}

#[test]
fn port_465_is_implicit_other_ports_starttls() {
    let a =
        SmtpSettings::new("mail.example.test", 465, "k", Secret::new("p"), "a@example.test", "b@example.test").unwrap();
    assert_eq!(a.tls, SmtpTls::Implicit);
    for port in [587u16, 25, 2525] {
        let a = SmtpSettings::new("mail.example.test", port, "k", Secret::new("p"), "a@example.test", "b@example.test")
            .unwrap();
        assert_eq!(a.tls, SmtpTls::StartTls, "port {port}");
    }
}

#[test]
fn no_tls_is_accepted_only_for_127_0_0_1() {
    let a =
        SmtpSettings::new("mail.example.test", 25, "k", Secret::new("p"), "a@example.test", "b@example.test").unwrap();
    assert!(matches!(a.clone().set_tls(SmtpTls::None), Err(NotifyError::Settings(_))));
    assert!(a.clone().set_tls(SmtpTls::Implicit).is_ok());
    let l = SmtpSettings::new("127.0.0.1", 25, "k", Secret::new("p"), "a@example.test", "b@example.test").unwrap();
    assert!(l.set_tls(SmtpTls::None).is_ok());
    let l2 = SmtpSettings::new("localhost", 25, "k", Secret::new("p"), "a@example.test", "b@example.test").unwrap();
    assert!(l2.set_tls(SmtpTls::None).is_err(), "only exactly 127.0.0.1");
}

#[test]
fn settings_fields_are_validated() {
    let p = || Secret::new("p");
    let k =
        |run_live: &str, user: &str, par: Secret, g: &str, a: &str| SmtpSettings::new(run_live, 587, user, par, g, a);
    assert!(k("mail.example.test", "user", p(), "a@example.test", "b@example.test").is_ok());
    for bad_address in [
        "",
        "a",
        "a@",
        "@b.test",
        "a b@example.test",
        "a@example.test\r\nBcc: x@evil.test",
        "a@example.test>\r\nRCPT TO:<x@evil.test",
        "<a@example.test>",
        "a@@example.test",
        "\u{011f}@example.test",
        "a@example.test,b@example.test",
        "\"a\"@example.test",
        "a@example.test\n",
    ] {
        assert!(k("mail.example.test", "user", p(), bad_address, "b@example.test").is_err(), "sender {bad_address:?}");
        assert!(
            k("mail.example.test", "user", p(), "a@example.test", bad_address).is_err(),
            "recipient {bad_address:?}"
        );
    }
    for bad in ["", "a b", "a\r\nb", "a\u{0}b", "\u{011f}", "a/b"] {
        assert!(k(bad, "user", p(), "a@example.test", "b@example.test").is_err(), "run_live machine {bad:?}");
    }
    assert!(k("mail.example.test", "ku\r\nl", p(), "a@example.test", "b@example.test").is_err());
    assert!(k("mail.example.test", "ku\0l", p(), "a@example.test", "b@example.test").is_err());
    assert!(k("mail.example.test", "user", Secret::new("pa\r\nro"), "a@example.test", "b@example.test").is_err());
    assert!(k("mail.example.test", "user", Secret::new("pa\0ro"), "a@example.test", "b@example.test").is_err());
    assert!(SmtpSettings::new("mail.example.test", 0, "user", p(), "a@example.test", "b@example.test").is_err());
}

#[test]
fn response_codes_are_classified_right() {
    let attempts_count = [
        (SmtpScript { rcpt_reply: "550 5.1.1 to_addr unknown", ..SmtpScript::default() }, false),
        (SmtpScript { rcpt_reply: "451 4.3.0 is_transient error", ..SmtpScript::default() }, true),
        (SmtpScript { mail_reply: "421 4.3.2 service_v closing", ..SmtpScript::default() }, true),
        (SmtpScript { mail_reply: "553 5.1.8 from_addr was_rejected", ..SmtpScript::default() }, false),
        (SmtpScript { data_end_reply: "554 5.7.1 was_rejected", ..SmtpScript::default() }, false),
        (SmtpScript { data_end_reply: "452 4.2.2 quota exceeded", ..SmtpScript::default() }, true),
    ];
    for (i, (script, is_transient)) in attempts_count.into_iter().enumerate() {
        let s = FakeSmtp::start(script);
        let error = channel(&s).send(&plain_notification()).expect_err("an error is expected");
        match (is_transient, &error) {
            (true, InterfaceError::Transient(_)) | (false, InterfaceError::Permanent(_)) => {}
            _ => panic!("script {i}: {error:?}"),
        }
    }
}

#[test]
fn a_connect_error_is_transient() {
    let mut a =
        SmtpSettings::new("127.0.0.1", a_free_port(), "k", Secret::new(PASSWORD), "a@example.test", "b@example.test")
            .unwrap()
            .set_tls(SmtpTls::None)
            .unwrap();
    a.timeout = Duration::from_millis(500);
    let error = SmtpChannel::new(a).send(&plain_notification()).expect_err("must be rejected");
    assert!(matches!(error, InterfaceError::Transient(_)), "{error:?}");
}

#[test]
fn the_password_stays_out_of_errors_and_debug() {
    let s = FakeSmtp::start(SmtpScript { rcpt_reply: "550 unknown", ..SmtpScript::default() });
    let mut k = channel(&s);
    let error = k.send(&plain_notification()).unwrap_err().to_string();
    for forbidden in [PASSWORD, "koru-user", "alice@example.test", "koru@example.test"] {
        assert!(!error.contains(forbidden), "the error message must not contain {forbidden:?}: {error}");
    }
    let d = format!("{k:?}");
    assert!(!d.contains(PASSWORD), "{d}");
}

#[test]
fn a_no_tls_assignment_is_rejected_at_send_time_for_a_remote_host() {
    // The `tls` field is public; validation only in the constructor could be bypassed.
    let mut a =
        SmtpSettings::new("mail.example.test", 25, "k", Secret::new("p"), "a@example.test", "b@example.test").unwrap();
    a.tls = SmtpTls::None;
    a.timeout = Duration::from_millis(500);
    let error = SmtpChannel::new(a).send(&plain_notification()).expect_err("a plaintext connection must be rejected");
    assert!(matches!(error, InterfaceError::Permanent(_)), "a permanent settings error before any network: {error:?}");
}
