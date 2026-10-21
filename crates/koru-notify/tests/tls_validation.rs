//! Certificate validation (code-review note; protected set): the client rejects every
//! certificate outside the system's trusted roots; there is no path that turns validation off.
//! The fake servers are real TLS servers on 127.0.0.1 using a self-signed certificate generated
//! in the test (the private key is never written to disk; the repo holds no key). This cert is
//! in no system store, so the connection must be rejected; once rejected, the server must see
//! no application data at all (no HTTP request, no SMTP ids, no mail).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::*;
use koru_event::{Heartbeat, InterfaceError, NotificationChannel};
use koru_notify::{
    HealthchecksHeartbeat, HttpsAddress, NtfyChannel, NtfySettings, Secret, SmtpChannel, SmtpSettings, SmtpTls,
    TelegramChannel, TelegramSettings,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};

/// What the server saw.
#[derive(Default, Clone, Debug)]
struct Seen {
    /// Whether the handshake completed (the client accepted the certificate).
    handshake_done: bool,
    /// Application data read after the handshake.
    app_data: Vec<u8>,
    /// Plaintext lines before STARTTLS (the SMTP STARTTLS scenario only).
    plain_commands: Vec<String>,
}

fn server_settings() -> Arc<ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
        .expect("certificate");
    let chain = vec![ck.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let settings = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("the certificate config");
    Arc::new(settings)
}

/// Attempts the TLS handshake and records the outcome.
fn try_tls(mut tcp: TcpStream, settings: Arc<ServerConfig>, g: &Arc<Mutex<Seen>>) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(3)));
    let Ok(mut session) = ServerConnection::new(settings) else { return };
    while session.is_handshaking() {
        if session.complete_io(&mut tcp).is_err() {
            return;
        }
    }
    g.lock().unwrap().handshake_done = true;
    let mut buffer = [0u8; 4096];
    if let Ok(n) = session.reader().read(&mut buffer) {
        g.lock().unwrap().app_data.extend_from_slice(&buffer[..n]);
    }
    let _ = session.writer().write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let _ = session.complete_io(&mut tcp);
}

/// A server speaking TLS directly (HTTPS and SMTPS).
fn tls_server() -> (u16, Arc<Mutex<Seen>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let g = Arc::new(Mutex::new(Seen::default()));
    let (g2, settings) = (g.clone(), server_settings());
    thread::spawn(move || {
        for s in l.incoming().take(1).flatten() {
            try_tls(s, settings.clone(), &g2);
        }
    });
    (port, g)
}

/// A server that first speaks plain SMTP and switches to TLS after STARTTLS.
fn a_starttls_server() -> (u16, Arc<Mutex<Seen>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let g = Arc::new(Mutex::new(Seen::default()));
    let (g2, settings) = (g.clone(), server_settings());
    thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = s.write_all(b"220 fake ready\r\n");
        let mut buffer = Vec::new();
        let mut piece = [0u8; 1024];
        loop {
            while let Some(i) = buffer.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = buffer.drain(..i + 2).collect();
                let text = String::from_utf8_lossy(&line[..i]).into_owned();
                g2.lock().unwrap().plain_commands.push(text.clone());
                if text.to_ascii_uppercase().starts_with("EHLO") {
                    let _ = s.write_all(b"250-fake\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n");
                } else if text.to_ascii_uppercase().starts_with("STARTTLS") {
                    let _ = s.write_all(b"220 2.0.0 Ready to start TLS\r\n");
                    try_tls(s, settings, &g2);
                    return;
                } else {
                    let _ = s.write_all(b"500 unexpected\r\n");
                }
            }
            match s.read(&mut piece) {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&piece[..n]),
            }
        }
    });
    (port, g)
}

fn was_rejected(h: &InterfaceError) {
    assert!(matches!(h, InterfaceError::Transient(_) | InterfaceError::Permanent(_)), "{h:?}");
    let message = h.to_string();
    for forbidden in ["127.0.0.1", "localhost", "UnknownIssuer"] {
        assert!(!message.contains(forbidden), "a TLS error message must not contain {forbidden:?}: {message}");
    }
}

fn wait_until_seen(g: &Arc<Mutex<Seen>>) -> Seen {
    thread::sleep(Duration::from_millis(300));
    g.lock().unwrap().clone()
}

#[test]
fn https_rejects_an_unknown_certificate_and_sends_nothing() {
    let (port, g) = tls_server();
    let mut a = NtfySettings::new(HttpsAddress::parse_parts(&format!("https://127.0.0.1:{port}/topic")).unwrap());
    a.token = Some(Secret::new("tk_SECRET_TOKEN"));
    a.timeout = Duration::from_secs(3);
    let error =
        NtfyChannel::new(a).send(&plain_notification()).expect_err("a self-signed certificate must be rejected");
    was_rejected(&error);
    let g = wait_until_seen(&g);
    assert!(!g.handshake_done, "the client must not accept the certificate");
    assert!(g.app_data.is_empty(), "the token and body must never reach the server: {:?}", g.app_data);
}

#[test]
fn telegram_and_the_heartbeat_reject_unknown_certificates() {
    let (port, g) = tls_server();
    let t = TelegramSettings::new(Secret::new("123456789:AAEsecretTOKEN"), "123")
        .unwrap()
        .set_api_base(HttpsAddress::parse_parts(&format!("https://127.0.0.1:{port}")).unwrap());
    let mut t = t;
    t.timeout = Duration::from_secs(3);
    was_rejected(&TelegramChannel::new(t).send(&plain_notification()).expect_err("telegram"));
    let g1 = wait_until_seen(&g);
    assert!(!g1.handshake_done && g1.app_data.is_empty(), "{g1:?}");

    let (port, g) = tls_server();
    let mut k =
        HealthchecksHeartbeat::new(HttpsAddress::parse_parts(&format!("https://127.0.0.1:{port}/ping/uuid")).unwrap())
            .set_timeout(Duration::from_secs(3));
    was_rejected(&k.beat().expect_err("a heartbeat beat"));
    let g2 = wait_until_seen(&g);
    assert!(!g2.handshake_done && g2.app_data.is_empty(), "{g2:?}");
}

#[test]
fn implicit_tls_rejects_an_unknown_certificate_and_sends_no_credentials() {
    let (port, g) = tls_server();
    let mut a = SmtpSettings::new(
        "127.0.0.1",
        port,
        "user",
        Secret::new("password-SECRET"),
        "a@example.test",
        "b@example.test",
    )
    .unwrap();
    a.tls = SmtpTls::Implicit;
    a.timeout = Duration::from_secs(3);
    was_rejected(&SmtpChannel::new(a).send(&plain_notification()).expect_err("must be rejected"));
    let g = wait_until_seen(&g);
    assert!(!g.handshake_done && g.app_data.is_empty(), "{g:?}");
}

#[test]
fn starttls_rejects_an_unknown_certificate_and_sends_no_credentials_or_mail() {
    let (port, g) = a_starttls_server();
    let mut a = SmtpSettings::new(
        "127.0.0.1",
        port,
        "user",
        Secret::new("password-SECRET"),
        "a@example.test",
        "b@example.test",
    )
    .unwrap();
    a.tls = SmtpTls::StartTls;
    a.timeout = Duration::from_secs(3);
    was_rejected(&SmtpChannel::new(a).send(&plain_notification()).expect_err("must be rejected"));
    let g = wait_until_seen(&g);
    assert!(g.plain_commands.iter().any(|k| k.to_ascii_uppercase().starts_with("STARTTLS")), "{:?}", g.plain_commands);
    assert!(!g.handshake_done, "the client must not accept the certificate");
    assert!(g.app_data.is_empty(), "no data may go out after TLS");
    assert!(
        !g.plain_commands
            .iter()
            .any(|k| ["AUTH", "MAIL", "RCPT", "DATA"].iter().any(|c| k.to_ascii_uppercase().starts_with(c))),
        "no ids or mail in the plaintext before STARTTLS: {:?}",
        g.plain_commands
    );
}
