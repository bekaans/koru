//! HTTP and SMTP client safety checks (code-review note; protected set): response-parsing
//! bounds (length, line counts, a total deadline), a slow server (slow-loris), corrupt
//! responses, redirects never followed, and never falling back to plaintext in a STARTTLS
//! stripping attack. The servers are raw sockets on 127.0.0.1.

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use koru_event::{Heartbeat, InterfaceError, NotificationChannel};
use koru_notify::{
    HealthchecksHeartbeat, HttpsAddress, NtfyChannel, NtfySettings, Secret, SmtpChannel, SmtpSettings, SmtpTls,
    TelegramChannel, TelegramSettings,
};

/// A raw server accepting one connection and running the given function against it; `f`
/// decides everything written to the accepted connection.
fn raw_server(f: impl FnOnce(TcpStream) + Send + 'static) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((s, _)) = l.accept() {
            f(s);
        }
    });
    port
}

fn ntfy(port: u16, timeout_ms: u64) -> NtfyChannel {
    let mut a = NtfySettings::new(HttpsAddress::parse_parts(&format!("http://127.0.0.1:{port}/k")).unwrap());
    a.timeout = Duration::from_millis(timeout_ms);
    NtfyChannel::new(a)
}

fn is_transient_error(h: &InterfaceError) -> bool {
    matches!(h, InterfaceError::Transient(_))
}

// --- HTTP response bounds ---

#[test]
fn an_overlong_status_line_is_bounded() {
    let port = raw_server(|mut s| {
        let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b);
        // 10 MiB without a line break, which it must not buffer in memory.
        let piece = vec![b'A'; 64 * 1024];
        for _ in 0..160 {
            if s.write_all(&piece).is_err() {
                break;
            }
        }
    });
    let t = Instant::now();
    let error = ntfy(port, 3000).send(&plain_notification()).expect_err("it must be bounded");
    assert!(is_transient_error(&error), "{error:?}");
    assert!(t.elapsed() < Duration::from_secs(3), "a long line must not be read forever: {:?}", t.elapsed());
}

#[test]
fn a_slow_server_cannot_exceed_the_total_deadline() {
    // Slow-loris: one byte every 50 ms; the per-read timeout never trips, the total budget must.
    let port = raw_server(|mut s| {
        let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b);
        for c in b"HTTP/1.1 200 OK-but-endless-line-............................................................" {
            if s.write_all(&[*c]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let t = Instant::now();
    let error = ntfy(port, 600).send(&plain_notification()).expect_err("the total duration exceeded");
    assert!(is_transient_error(&error), "{error:?}");
    assert!(t.elapsed() < Duration::from_millis(2500), "the total duration budget must apply: {:?}", t.elapsed());
}

#[test]
fn broken_replies_are_transient_and_never_success() {
    for response in [
        &b"hello world\r\n"[..],
        &b"HTTP/2 200\r\n"[..],
        &b"HTTP/1.1 2x0 Weird\r\n"[..],
        &b"HTTP/1.1 20\r\n"[..],
        &b"HTTP/1.1  200\r\n"[..],
        &b"\x00\x01\x02\xff\r\n"[..],
        &b""[..],
    ] {
        let y = response.to_vec();
        let port = raw_server(move |mut s| {
            let mut b = [0u8; 4096];
            let _ = s.read(&mut b);
            let _ = s.write_all(&y);
            let _ = s.shutdown(Shutdown::Both);
        });
        let result = ntfy(port, 800).send(&plain_notification());
        let error = result.expect_err(&String::from_utf8_lossy(response));
        assert!(is_transient_error(&error), "{:?}: {error:?}", String::from_utf8_lossy(response));
    }
}

#[test]
fn a_body_without_a_status_line_is_not_success() {
    let port = raw_server(|mut s| {
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b);
        let _ = s.write_all(b"200 OK completed\r\n\r\n");
    });
    assert!(ntfy(port, 800).send(&plain_notification()).is_err());
}

// --- redirects ---

#[test]
fn no_redirect_code_is_followed_on_any_channel() {
    for code in [301u16, 302, 303, 307, 308] {
        let target = FakeHttp::start();
        let s = FakeHttp::start_answering(FakeReply::Redirect(code, target.url("/redirected")));
        let url = |path: &str| HttpsAddress::parse_parts(&s.url(path)).unwrap();

        let mut a = NtfySettings::new(url("/k"));
        a.token = Some(Secret::new("token"));
        let error = NtfyChannel::new(a).send(&plain_notification()).expect_err("ntfy");
        assert!(matches!(error, InterfaceError::Permanent(_)), "ntfy {code}: {error:?}");

        let t = TelegramSettings::new(Secret::new("123456789:AAEsecretTOKEN"), "123").unwrap().set_api_base(url(""));
        let error = TelegramChannel::new(t).send(&plain_notification()).expect_err("telegram");
        assert!(matches!(error, InterfaceError::Permanent(_)), "telegram {code}: {error:?}");

        let error = HealthchecksHeartbeat::new(url("/ping/uuid")).beat().expect_err("a heartbeat beat");
        assert!(matches!(error, InterfaceError::Permanent(_)), "a heartbeat beat {code}: {error:?}");

        assert_eq!(target.request_count(), 0, "{code}: the redirect target must not be visited");
    }
}

// --- SMTP: a fake plain server (scripted replies) ---

#[derive(Default, Clone)]
struct SmtpRecord {
    commands: Vec<String>,
    raw: Vec<u8>,
}

/// `reply(command)`: raw reply bytes for a command; `None` severs the connection. The first
/// line is the greeting.
fn smtp_server(
    greeting: Vec<u8>,
    reply: impl Fn(&str) -> Option<Vec<u8>> + Send + 'static,
) -> (u16, Arc<Mutex<SmtpRecord>>) {
    let record = Arc::new(Mutex::new(SmtpRecord::default()));
    let k = record.clone();
    let port = raw_server(move |mut s| {
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = s.write_all(&greeting);
        let mut buffer: Vec<u8> = Vec::new();
        let mut piece = [0u8; 4096];
        loop {
            while let Some(i) = buffer.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = buffer.drain(..i + 2).collect();
                let text = String::from_utf8_lossy(&line[..i]).into_owned();
                k.lock().unwrap().commands.push(text.clone());
                match reply(&text) {
                    Some(y) => {
                        let _ = s.write_all(&y);
                    }
                    None => return,
                }
            }
            match s.read(&mut piece) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    k.lock().unwrap().raw.extend_from_slice(&piece[..n]);
                    buffer.extend_from_slice(&piece[..n]);
                }
            }
        }
    });
    (port, record)
}

fn smtp_channel_fn(port: u16, tls: SmtpTls) -> SmtpChannel {
    let mut a = SmtpSettings::new(
        "127.0.0.1",
        port,
        "user",
        Secret::new("password-SECRET"),
        "koru@example.test",
        "alice@example.test",
    )
    .unwrap();
    a.tls = tls;
    a.timeout = Duration::from_millis(1500);
    SmtpChannel::new(a)
}

fn ehlo_advertising_starttls(smtp_command: &str) -> Option<Vec<u8>> {
    let k = smtp_command.to_ascii_uppercase();
    if k.starts_with("EHLO") {
        Some(b"250-fake\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n".to_vec())
    } else {
        Some(b"500 unexpected\r\n".to_vec())
    }
}

fn downgraded_to_plain(k: &SmtpRecord) -> bool {
    let raw = String::from_utf8_lossy(&k.raw).to_ascii_uppercase();
    ["AUTH", "MAIL FROM", "RCPT TO", "DATA"].iter().any(|c| raw.contains(c))
}

#[test]
fn a_refused_starttls_never_falls_back_to_plaintext() {
    for ret in [
        "454 4.7.0 TLS not available",
        "500 5.5.1 STARTTLS unavailable",
        "554 5.7.0 was_rejected",
        "250 completed apparently",
    ] {
        let (port, record) = smtp_server(b"220 fake ready\r\n".to_vec(), move |k| {
            if k.to_ascii_uppercase().starts_with("STARTTLS") {
                Some(format!("{ret}\r\n").into_bytes())
            } else {
                ehlo_advertising_starttls(k)
            }
        });
        let error = smtp_channel_fn(port, SmtpTls::StartTls).send(&plain_notification()).expect_err(ret);
        assert!(matches!(error, InterfaceError::Transient(_) | InterfaceError::Permanent(_)), "{ret}: {error:?}");
        thread::sleep(Duration::from_millis(100));
        let k = record.lock().unwrap().clone();
        assert!(!downgraded_to_plain(&k), "{ret}: ids or mail went out in plaintext: {:?}", k.commands);
    }
}

#[test]
fn a_missing_starttls_offer_cuts_the_connection() {
    // The man in the middle deletes the STARTTLS capability from the EHLO reply.
    let (port, record) = smtp_server(b"220 fake ready\r\n".to_vec(), |k| {
        if k.to_ascii_uppercase().starts_with("EHLO") {
            Some(b"250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n".to_vec())
        } else {
            Some(b"250 ok\r\n".to_vec())
        }
    });
    let error =
        smtp_channel_fn(port, SmtpTls::StartTls).send(&plain_notification()).expect_err("must not send without TLS");
    assert!(matches!(error, InterfaceError::Transient(_)), "counts as transient (may wait in the queue): {error:?}");
    thread::sleep(Duration::from_millis(100));
    let k = record.lock().unwrap().clone();
    assert!(!downgraded_to_plain(&k), "{:?}", k.commands);
    assert!(
        !k.commands.iter().any(|c| c.to_ascii_uppercase().starts_with("STARTTLS")),
        "an unadvertised capability is not requested"
    );
}

#[test]
fn extra_buffered_data_after_starttls_is_rejected() {
    // CVE-2011-0411 shape: a plaintext command reply is injected in the same packet as the 220.
    let (port, record) = smtp_server(b"220 fake ready\r\n".to_vec(), |k| {
        if k.to_ascii_uppercase().starts_with("STARTTLS") {
            Some(b"220 2.0.0 Ready\r\n250 injected response\r\n".to_vec())
        } else {
            ehlo_advertising_starttls(k)
        }
    });
    let error =
        smtp_channel_fn(port, SmtpTls::StartTls).send(&plain_notification()).expect_err("injection must be rejected");
    assert!(matches!(error, InterfaceError::Transient(_) | InterfaceError::Permanent(_)), "{error:?}");
    thread::sleep(Duration::from_millis(100));
    let k = record.lock().unwrap().clone();
    assert!(!downgraded_to_plain(&k));
    assert!(
        !k.raw.contains(&0x16) || !k.raw.windows(2).any(|w| w == [0x16, 0x03]),
        "it must not upgrade to TLS (no ClientHello may go out)"
    );
}

#[test]
fn a_non_220_greeting_is_rejected_and_nothing_is_sent() {
    for greeting in ["554 5.3.2 no service\r\n", "421 4.3.2 closing\r\n", "a strange greeting\r\n", "250 ok\r\n"] {
        let (port, record) = smtp_server(greeting.as_bytes().to_vec(), |_| Some(b"250 ok\r\n".to_vec()));
        let error = smtp_channel_fn(port, SmtpTls::None).send(&plain_notification()).expect_err(greeting);
        assert!(matches!(error, InterfaceError::Transient(_) | InterfaceError::Permanent(_)), "{greeting}: {error:?}");
        thread::sleep(Duration::from_millis(100));
        let k = record.lock().unwrap().clone();
        assert!(!downgraded_to_plain(&k), "{greeting}: {:?}", k.commands);
    }
}

#[test]
fn an_overlong_response_line_is_bounded() {
    let (port, _) = smtp_server(vec![b'x'; 200_000], |_| None);
    let error = smtp_channel_fn(port, SmtpTls::None).send(&plain_notification()).expect_err("the line limit");
    assert!(is_transient_error(&error), "{error:?}");
}

#[test]
fn a_many_line_response_is_bounded() {
    let mut greeting = Vec::new();
    for _ in 0..5_000 {
        greeting.extend_from_slice(b"220-continuing\r\n");
    }
    greeting.extend_from_slice(b"220 done\r\n");
    let (port, _) = smtp_server(greeting, |_| Some(b"250 ok\r\n".to_vec()));
    let error = smtp_channel_fn(port, SmtpTls::None).send(&plain_notification()).expect_err("the line-count limit");
    assert!(is_transient_error(&error), "{error:?}");
}

#[test]
fn malformed_smtp_replies_are_transient() {
    for greeting in ["22\r\n", "abc ready\r\n", "220_ready\r\n", "2200 ready\r\n", "\r\n"] {
        let (port, _) = smtp_server(greeting.as_bytes().to_vec(), |_| None);
        let error = smtp_channel_fn(port, SmtpTls::None).send(&plain_notification()).expect_err(greeting);
        assert!(is_transient_error(&error), "{greeting:?}: {error:?}");
    }
}

#[test]
fn a_slow_smtp_server_cannot_exceed_the_total_deadline() {
    let port = raw_server(|mut s| {
        for c in b"220 ................................................................................" {
            if s.write_all(&[*c]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let mut a = SmtpSettings::new("127.0.0.1", port, "k", Secret::new("p"), "a@example.test", "b@example.test")
        .unwrap()
        .set_tls(SmtpTls::None)
        .unwrap();
    a.timeout = Duration::from_millis(600);
    let t = Instant::now();
    let error = SmtpChannel::new(a).send(&plain_notification()).expect_err("the total duration");
    assert!(is_transient_error(&error), "{error:?}");
    assert!(t.elapsed() < Duration::from_millis(2500), "{:?}", t.elapsed());
}

#[test]
fn smtp_errors_carry_no_server_text_or_addresses() {
    let (port, _) = smtp_server(b"220 ready\r\n".to_vec(), |k| {
        let b = k.to_ascii_uppercase();
        if b.starts_with("EHLO") {
            Some(b"250 fake\r\n".to_vec())
        } else if b.starts_with("MAIL") {
            Some(b"250 ok\r\n".to_vec())
        } else if b.starts_with("RCPT") {
            Some(b"550 5.1.1 <alice@example.test>: to_addr SERVER-TEXT-SECRET unknown\r\n".to_vec())
        } else {
            Some(b"250 ok\r\n".to_vec())
        }
    });
    let error = smtp_channel_fn(port, SmtpTls::None).send(&plain_notification()).unwrap_err().to_string();
    assert!(
        !error.contains("SERVER-TEXT-SECRET")
            && !error.contains("alice@example.test")
            && !error.contains("password-SECRET"),
        "{error}"
    );
}
