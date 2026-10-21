//! The injection matrix (protected set): the same hostile notification is sent on all three channels; the fake servers
//! verify the framing survives (no extra header, no extra command, no second request) and the content is neutralized.

mod common;

use std::time::Duration;

use common::*;
use koru_event::{NotificationChannel, Severity};
use koru_notify::{
    HttpsAddress, NtfyChannel, NtfySettings, Secret, SmtpChannel, SmtpSettings, SmtpTls, TelegramChannel,
    TelegramSettings,
};

const INPUTS: &[&str] = &[
    "x\r\nX-Evil: 1\r\nBcc: victim@evil.test",
    "x\nX-Evil: 1",
    "x\rX-Evil: 1",
    "x\r\n\r\nPOST /second HTTP/1.1\r\nHost: a\r\n\r\n",
    "x\r\n.\r\nMAIL FROM:<evil@evil.test>\r\nRCPT TO:<evil@evil.test>\r\nDATA\r\n",
    "\u{1b}[2J\u{1b}]0;fake\u{7}",
    "\u{202e}fdp.exe\u{2066}\u{2069}\u{200f}",
    "a\u{0}b\u{85}c\u{2028}d",
    "<b>b\u{00f6}ld</b> *x* _y_ `z` [l](http://evil.test)",
];

fn ntfy(s: &FakeHttp) -> NtfyChannel {
    let mut a = NtfySettings::new(HttpsAddress::parse_parts(&s.url("/topic")).unwrap());
    a.token = Some(Secret::new("token"));
    a.timeout = Duration::from_millis(800);
    NtfyChannel::new(a)
}

fn telegram(s: &FakeHttp) -> TelegramChannel {
    let mut a = TelegramSettings::new(Secret::new("123456789:AAEsecretTOKEN"), "123456")
        .unwrap()
        .set_api_base(HttpsAddress::parse_parts(&s.url("")).unwrap());
    a.timeout = Duration::from_millis(800);
    TelegramChannel::new(a)
}

fn smtp(s: &FakeSmtp) -> SmtpChannel {
    let mut a =
        SmtpSettings::new("127.0.0.1", s.port, "user", Secret::new("par"), "koru@example.test", "alice@example.test")
            .unwrap()
            .set_tls(SmtpTls::None)
            .unwrap();
    a.timeout = Duration::from_millis(1500);
    SmtpChannel::new(a)
}

fn no_dangerous_raw_bytes(raw: &[u8]) {
    for b in [0x00u8, 0x1b, 0x07] {
        assert!(!raw.contains(&b), "raw wire data holds byte {b:#x}");
    }
    let text = String::from_utf8_lossy(raw);
    for c in ['\u{202e}', '\u{2066}', '\u{2069}', '\u{200f}', '\u{85}', '\u{2028}'] {
        assert!(!text.contains(c), "raw output contains {c:?}");
    }
}

#[test]
fn the_ntfy_matrix() {
    for input in INPUTS {
        let s = FakeHttp::start();
        ntfy(&s).send(&notification(Severity::Critical, input, input)).unwrap();
        let i = s.one_request();
        assert_eq!(s.request_count(), 1, "{input:?}: the request must not split");
        for forbidden in ["X-Evil", "Bcc"] {
            assert_eq!(i.header_count(forbidden), 0, "{input:?}");
        }
        for (name, _) in &i.headers {
            let k = name.to_ascii_lowercase();
            assert!(
                [
                    "host",
                    "content-length",
                    "title",
                    "priority",
                    "tags",
                    "authorization",
                    "user-agent",
                    "connection",
                    "accept",
                    "content-type"
                ]
                .contains(&k.as_str()),
                "{input:?}: unexpected header {name}"
            );
        }
        let header_block = String::from_utf8_lossy(&i.raw).split("\r\n\r\n").next().unwrap().to_string();
        no_dangerous_raw_bytes(header_block.as_bytes());
        no_dangerous_raw_bytes(&i.body);
        assert_eq!(i.title("Tags").map(|t| t.contains(['\r', '\n'])), Some(false));
    }
}

#[test]
fn the_telegram_matrix() {
    for input in INPUTS {
        let s = FakeHttp::start();
        telegram(&s).send(&notification(Severity::Critical, input, input)).unwrap();
        let i = s.one_request();
        assert_eq!(s.request_count(), 1);
        assert_eq!(i.header_count("X-Evil"), 0);
        let j = i.body_json();
        assert!(j.get("parse_mode").is_none(), "{input:?}");
        assert_eq!(j.as_object().unwrap().len(), 3);
        no_dangerous_raw_bytes(j["text"].as_str().unwrap().as_bytes());
    }
}

#[test]
fn the_smtp_matrix() {
    for input in INPUTS {
        let s = FakeSmtp::start(SmtpScript::default());
        smtp(&s).send(&notification(Severity::Critical, input, input)).unwrap();
        let o = s.one_session();
        for prefix in ["MAIL FROM", "RCPT TO", "DATA", "QUIT"] {
            assert_eq!(
                o.commands.iter().filter(|k| k.to_ascii_uppercase().starts_with(prefix)).count(),
                1,
                "{input:?}: {prefix} must appear once: {:?}",
                o.commands
            );
        }
        assert!(!o.commands.iter().any(|k| k.contains("evil")), "{:?}", o.commands);
        let (headers, _) = parse_mailbox(o.data.as_ref().unwrap());
        assert!(
            !headers.iter().any(|(a, _)| a.eq_ignore_ascii_case("bcc") || a.eq_ignore_ascii_case("x-evil")),
            "{headers:?}"
        );
        for name in ["from", "to", "subject", "date", "message-id"] {
            assert_eq!(headers.iter().filter(|(a, _)| a.eq_ignore_ascii_case(name)).count(), 1, "{input:?}: {name}");
        }
        let raw = o.data.unwrap();
        let block = String::from_utf8_lossy(&raw).split("\r\n\r\n").next().unwrap().to_string();
        no_dangerous_raw_bytes(block.as_bytes());
    }
}

#[test]
fn attacker_data_never_goes_raw_beyond_identity_and_severity() {
    // Overlong input with control chars stays bounded on every channel.
    let huge = format!("{}\u{1b}[31m", "\u{011e}".repeat(2_000_000));
    let s = FakeHttp::start();
    ntfy(&s).send(&notification(Severity::Warning, &huge, &huge)).unwrap();
    assert!(s.one_request().raw.len() < 16 * 1024);
    let s = FakeHttp::start();
    telegram(&s).send(&notification(Severity::Warning, &huge, &huge)).unwrap();
    assert!(s.one_request().raw.len() < 32 * 1024);
    let s = FakeSmtp::start(SmtpScript::default());
    smtp(&s).send(&notification(Severity::Warning, &huge, &huge)).unwrap();
    assert!(s.one_session().raw.len() < 128 * 1024);
}
