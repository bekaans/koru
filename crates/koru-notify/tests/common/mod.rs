//! Shared test helpers (protected set).
//!
//! The fake HTTP and SMTP servers listen only on 127.0.0.1; the tests never touch a real network.
//! The fake servers record the raw bytes they receive as-is; the parsing mimics a real server
//! (headers line by line, the body `Content-Length` long). A successful injection shows up as
//! an extra header or an extra command at the fake server.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use koru_event::{EventId, InterfaceError, Notification, NotificationChannel, Severity};

pub fn is_transient() -> tempfile::TempDir {
    let t = tempfile::tempdir().expect("a temp dir");
    std::fs::set_permissions(t.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).expect("0700");
    t
}

/// The temp dir's canonicalized (symlink-free) path; on macOS `/var` is a link.
pub fn canonicalized(t: &tempfile::TempDir) -> PathBuf {
    std::fs::canonicalize(t.path()).expect("canonicalized path")
}

pub fn file_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path).expect("meta").permissions().mode() & 0o7777
}

pub fn notification(severity: Severity, title: &str, body: &str) -> Notification {
    Notification { severity, title: title.to_string(), body: body.to_string(), event_id: EventId::new() }
}

pub fn plain_notification() -> Notification {
    notification(Severity::Critical, "The decoy file was read", "The process opened the file /root/.ssh/id_ed25519.")
}

/// A port nothing listens on (the connection is refused).
pub fn a_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------------------------
// Fake HTTP server
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FakeRequest {
    pub raw: Vec<u8>,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FakeRequest {
    pub fn title(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(name)).map(|(_, d)| d.as_str())
    }

    pub fn header_count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(a, _)| a.eq_ignore_ascii_case(name)).count()
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("the body must be JSON")
    }
}

#[derive(Debug, Clone)]
pub enum FakeReply {
    /// An empty-body reply with the given status.
    WithStatus(u16),
    /// Drops the connection without replying.
    DropConnection,
    /// Waits without replying (the client's timeout is exercised).
    Silent,
    /// A 3xx reply with the given headers.
    Redirect(u16, String),
}

pub struct FakeHttp {
    pub port: u16,
    requests: Arc<Mutex<Vec<FakeRequest>>>,
    replies: Arc<Mutex<VecDeque<FakeReply>>>,
    defaults: Arc<Mutex<FakeReply>>,
    close: Arc<AtomicBool>,
}

impl FakeHttp {
    pub fn start() -> FakeHttp {
        Self::start_answering(FakeReply::WithStatus(200))
    }

    pub fn start_answering(defaults: FakeReply) -> FakeHttp {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(VecDeque::new()));
        let defaults = Arc::new(Mutex::new(defaults));
        let close = Arc::new(AtomicBool::new(false));
        {
            let (requests, replies, defaults, close) =
                (requests.clone(), replies.clone(), defaults.clone(), close.clone());
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if close.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let (requests, replies, defaults) = (requests.clone(), replies.clone(), defaults.clone());
                    thread::spawn(move || handle_connection(stream, requests, replies, defaults));
                }
            });
        }
        FakeHttp { port, requests, replies, defaults, close }
    }

    /// `http://127.0.0.1:<port><path>`
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    /// Replies served one by one to the next requests; when they run out the default applies.
    pub fn in_order(&self, replies: Vec<FakeReply>) {
        self.replies.lock().unwrap().extend(replies);
    }

    pub fn set_defaults(&self, reply: FakeReply) {
        *self.defaults.lock().unwrap() = reply;
    }

    pub fn requests(&self) -> Vec<FakeRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// Waits for one request (at most ~5 s) and returns it.
    pub fn one_request(&self) -> FakeRequest {
        for _ in 0..100 {
            let i = self.requests();
            if i.len() == 1 {
                return i[0].clone();
            }
            assert!(i.len() < 2, "expected a single request, got {}", i.len());
            thread::sleep(Duration::from_millis(50));
        }
        panic!("no request arrived");
    }
}

impl Drop for FakeHttp {
    fn drop(&mut self) {
        self.close.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_connection(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<FakeRequest>>>,
    replies: Arc<Mutex<VecDeque<FakeReply>>>,
    defaults: Arc<Mutex<FakeReply>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut raw = Vec::new();
    let mut piece = [0u8; 4096];
    let headers_end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match stream.read(&mut piece) {
            Ok(0) | Err(_) => return,
            Ok(n) => raw.extend_from_slice(&piece[..n]),
        }
    };
    let headers_text = String::from_utf8_lossy(&raw[..headers_end - 4]).into_owned();
    let mut lines = headers_text.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((a, d)) = line.split_once(':') {
            headers.push((a.trim().to_string(), d.trim().to_string()));
        }
    }
    let length = headers
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, d)| d.parse::<usize>().ok())
        .unwrap_or(0);
    while raw.len() < headers_end + length {
        match stream.read(&mut piece) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&piece[..n]),
        }
    }
    let body = raw[headers_end..raw.len().min(headers_end + length)].to_vec();
    requests.lock().unwrap().push(FakeRequest { raw: raw.clone(), method, path, headers, body });
    let reply = replies.lock().unwrap().pop_front().unwrap_or_else(|| defaults.lock().unwrap().clone());
    match reply {
        FakeReply::WithStatus(d) => {
            let _ = write!(stream, "HTTP/1.1 {d} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        FakeReply::Redirect(d, target) => {
            let _ = write!(
                stream,
                "HTTP/1.1 {d} Test\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
        FakeReply::DropConnection => {}
        FakeReply::Silent => thread::sleep(Duration::from_secs(5)),
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// Deadline for tests that must observe a TLS ClientHello. The client loads the system root
/// store on its first TLS use and that time counts against its deadline; on a busy host it can
/// pass a second. The fake servers close right after the first bytes, so normal runs stay fast.
#[allow(dead_code)]
pub const TLS_START_DEADLINE: Duration = Duration::from_secs(10);

/// Accepts one connection, records its first bytes and closes without replying; shows an
/// `https` client speaks TLS (ClientHello: 0x16 0x03), never plaintext.
pub fn raw_capture() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(TLS_START_DEADLINE));
            let mut buffer = [0u8; 512];
            let n = stream.read(&mut buffer).unwrap_or(0);
            let _ = tx.send(buffer[..n].to_vec());
        }
    });
    (port, rx)
}

// ---------------------------------------------------------------------------------------------
// Fake SMTP server
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SmtpScript {
    pub offers_starttls: bool,
    pub offers_auth: bool,
    pub mail_reply: &'static str,
    pub rcpt_reply: &'static str,
    pub data_end_reply: &'static str,
}

impl Default for SmtpScript {
    fn default() -> SmtpScript {
        SmtpScript {
            offers_starttls: false,
            offers_auth: true,
            mail_reply: "250 2.1.0 Ok",
            rcpt_reply: "250 2.1.5 Ok",
            data_end_reply: "250 2.0.0 Ok: queued as ABC123",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeSmtpSession {
    /// The lines the client sent besides DATA (without CRLF).
    pub commands: Vec<String>,
    /// The DATA content (the final `.` line excluded, the dot un-stuffed).
    pub data: Option<Vec<u8>>,
    /// Whether the client sent a TLS ClientHello (0x16) after STARTTLS.
    pub tls_started: bool,
    /// Every byte that arrived from the client.
    pub raw: Vec<u8>,
}

pub struct FakeSmtp {
    pub port: u16,
    sessions: Arc<Mutex<Vec<FakeSmtpSession>>>,
    close: Arc<AtomicBool>,
}

impl FakeSmtp {
    pub fn start(script: SmtpScript) -> FakeSmtp {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let close = Arc::new(AtomicBool::new(false));
        {
            let (sessions, close) = (sessions.clone(), close.clone());
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if close.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let (sessions, script) = (sessions.clone(), script.clone());
                    thread::spawn(move || smtp_handle(stream, script, sessions));
                }
            });
        }
        FakeSmtp { port, sessions, close }
    }

    pub fn sessions(&self) -> Vec<FakeSmtpSession> {
        self.sessions.lock().unwrap().clone()
    }

    /// Waits for a session to finish (at most ~5 s) and returns it.
    pub fn one_session(&self) -> FakeSmtpSession {
        for _ in 0..100 {
            let o = self.sessions();
            if o.len() == 1 {
                return o[0].clone();
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("the session never completed");
    }
}

impl Drop for FakeSmtp {
    fn drop(&mut self) {
        self.close.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn read_line(stream: &mut TcpStream, raw: &mut Vec<u8>, buffer: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(i) = buffer.windows(2).position(|w| w == b"\r\n") {
            let line: Vec<u8> = buffer.drain(..i + 2).collect();
            return Some(String::from_utf8_lossy(&line[..i]).into_owned());
        }
        let mut piece = [0u8; 4096];
        match stream.read(&mut piece) {
            Ok(0) | Err(_) => return None,
            Ok(n) => {
                raw.extend_from_slice(&piece[..n]);
                buffer.extend_from_slice(&piece[..n]);
            }
        }
    }
}

fn smtp_handle(mut stream: TcpStream, s: SmtpScript, sessions: Arc<Mutex<Vec<FakeSmtpSession>>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut o = FakeSmtpSession::default();
    let mut buffer = Vec::new();
    let _ = stream.write_all(b"220 fake.test ESMTP ready\r\n");
    'main_loop: while let Some(line) = read_line(&mut stream, &mut o.raw, &mut buffer) {
        let upper = line.to_ascii_uppercase();
        o.commands.push(line.clone());
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let mut y = String::from("250-fake.test greeting\r\n");
            if s.offers_starttls {
                y.push_str("250-STARTTLS\r\n");
            }
            if s.offers_auth {
                y.push_str("250-AUTH PLAIN LOGIN\r\n");
            }
            y.push_str("250 8BITMIME\r\n");
            let _ = stream.write_all(y.as_bytes());
        } else if upper.starts_with("STARTTLS") {
            let _ = stream.write_all(b"220 2.0.0 Ready to start TLS\r\n");
            // The fake server knows no TLS: it records the client's first byte and disconnects.
            let mut b = [0u8; 8];
            if let Ok(n) = stream.read(&mut b)
                && n > 0
            {
                o.raw.extend_from_slice(&b[..n]);
                o.tls_started = b[0] == 0x16;
            }
            break 'main_loop;
        } else if upper.starts_with("AUTH PLAIN") && line.len() > 11 {
            let _ = stream.write_all(b"235 2.7.0 Authentication successful\r\n");
        } else if upper.starts_with("AUTH LOGIN") || upper == "AUTH PLAIN" {
            let _ = stream.write_all(b"334 \r\n");
            // The auth line(s) are recorded as commands.
            let _ = read_line(&mut stream, &mut o.raw, &mut buffer).map(|k| o.commands.push(k));
            let _ = stream.write_all(b"235 2.7.0 Authentication successful\r\n");
        } else if upper.starts_with("MAIL FROM") {
            let _ = stream.write_all(format!("{}\r\n", s.mail_reply).as_bytes());
        } else if upper.starts_with("RCPT TO") {
            let _ = stream.write_all(format!("{}\r\n", s.rcpt_reply).as_bytes());
        } else if upper == "DATA" {
            let _ = stream.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n");
            let mut data = Vec::new();
            while let Some(v) = read_line(&mut stream, &mut o.raw, &mut buffer) {
                if v == "." {
                    break;
                }
                let v = if v.starts_with("..") { v[1..].to_string() } else { v };
                data.extend_from_slice(v.as_bytes());
                data.extend_from_slice(b"\r\n");
            }
            o.data = Some(data);
            let _ = stream.write_all(format!("{}\r\n", s.data_end_reply).as_bytes());
        } else if upper == "QUIT" {
            let _ = stream.write_all(b"221 2.0.0 Bye\r\n");
            break 'main_loop;
        } else if upper.starts_with("RSET") || upper.starts_with("NOOP") {
            let _ = stream.write_all(b"250 Ok\r\n");
        } else {
            let _ = stream.write_all(b"500 5.5.2 smtp_command not_understood\r\n");
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    sessions.lock().unwrap().push(o);
}

/// Splits the DATA content into headers (folded lines joined) and the body.
pub fn parse_mailbox(data: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
    let text = data;
    let boundary = text.windows(4).position(|w| w == b"\r\n\r\n").expect("the headers/body split");
    let headers_text = String::from_utf8_lossy(&text[..boundary]).into_owned();
    let body = text[boundary + 4..].to_vec();
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in headers_text.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
        } else if let Some((a, d)) = line.split_once(':') {
            headers.push((a.trim().to_string(), d.trim().to_string()));
        } else {
            panic!("a non-header line: {line:?}");
        }
    }
    (headers, body)
}

// ---------------------------------------------------------------------------------------------
// The fake channel (for dispatcher tests)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ChannelProbe {
    pub sent_items: Vec<Notification>,
    pub attempts_count: usize,
    /// `true`: a transient error, `false`: success.
    pub transient_failure: bool,
    pub permanent_errors: bool,
}

#[derive(Clone)]
pub struct FakeChannel {
    name: &'static str,
    pub state: Arc<Mutex<ChannelProbe>>,
}

impl FakeChannel {
    pub fn new(name: &'static str) -> FakeChannel {
        FakeChannel { name, state: Arc::new(Mutex::new(ChannelProbe::default())) }
    }

    pub fn set_a_transient_failure(&self, on: bool) {
        self.state.lock().unwrap().transient_failure = on;
    }

    pub fn set_a_permanent_failure(&self, on: bool) {
        self.state.lock().unwrap().permanent_errors = on;
    }

    pub fn sent_items(&self) -> Vec<Notification> {
        self.state.lock().unwrap().sent_items.clone()
    }

    pub fn attempts_count(&self) -> usize {
        self.state.lock().unwrap().attempts_count
    }
}

impl NotificationChannel for FakeChannel {
    fn name(&self) -> &str {
        self.name
    }

    fn send(&mut self, b: &Notification) -> Result<(), InterfaceError> {
        let mut d = self.state.lock().unwrap();
        d.attempts_count += 1;
        if d.permanent_errors {
            return Err(InterfaceError::Permanent("a fake permanent error".into()));
        }
        if d.transient_failure {
            return Err(InterfaceError::Transient("a fake transient error".into()));
        }
        d.sent_items.push(b.clone());
        Ok(())
    }
}
