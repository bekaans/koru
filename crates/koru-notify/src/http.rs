//! A small synchronous HTTP/1.1 client and TLS transport (ADR-0007 "Channel design").
//!
//! - TLS is rustls only (the ring provider); root certificates come from the system store.
//!   The certificate chain and the host name are verified every time; there is no way to
//!   there is no setting that turns this off.
//! - Redirects are never followed (a token must not leak to another address).
//! - The whole exchange shares one deadline (connect, handshake, write, read), so a slow
//!   server cannot hold the thread. Name resolution runs on its own thread with a deadline
//!   of its own.
//! - Error messages hold no URL, host, port, token or response body; only short fixed
//!   reasons and the HTTP status code.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use koru_event::InterfaceError;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::HttpsAddress;

/// One header line: name and value.
pub(crate) type Header = (&'static str, String);

const MAX_STATUS_LINE_BYTES: usize = 4096;

static TLS_CONFIG: Mutex<Option<Arc<ClientConfig>>> = Mutex::new(None);

/// The shared TLS config. Failures are not cached (the system store may later heal).
fn tls_settings() -> Result<Arc<ClientConfig>, InterfaceError> {
    let mut guard = TLS_CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(a) = guard.as_ref() {
        return Ok(a.clone());
    }
    let result = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (appended, _) = roots.add_parsable_certificates(result.certs);
    if appended == 0 {
        return Err(InterfaceError::Transient("the system certificate store is empty or unreadable".to_string()));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let settings = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|_| InterfaceError::Permanent("could not set the TLS protocol versions".to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let settings = Arc::new(settings);
    *guard = Some(settings.clone());
    Ok(settings)
}

/// A connection: plain or TLS. Every read and write is bounded by the remaining deadline.
pub(crate) struct Connection {
    stream: Stream,
    deadline: Instant,
    timeout: Duration,
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Connection {
    fn tcp(&self) -> &TcpStream {
        match &self.stream {
            Stream::Plain(t) => t,
            Stream::Tls(t) => &t.sock,
        }
    }

    fn with_duration(&self) -> io::Result<()> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let dur = remaining.min(self.timeout);
        self.tcp().set_read_timeout(Some(dur))?;
        self.tcp().set_write_timeout(Some(dur))
    }

    /// Upgrades the connection to TLS (STARTTLS and implicit TLS). The read buffer must hold
    /// no pending data; the caller checks that.
    pub(crate) fn upgrade_to_tls(self, host: &str) -> Result<Connection, InterfaceError> {
        let Stream::Plain(tcp) = self.stream else {
            return Err(InterfaceError::Permanent("the connection is already TLS".to_string()));
        };
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| InterfaceError::Permanent("the host name is invalid for TLS".to_string()))?;
        let session = ClientConnection::new(tls_settings()?, name)
            .map_err(|_| InterfaceError::Permanent("could not build the TLS client".to_string()))?;
        Ok(Connection {
            stream: Stream::Tls(Box::new(StreamOwned::new(session, tcp))),
            deadline: self.deadline,
            timeout: self.timeout,
        })
    }

    /// Completes the TLS handshake (sending no data); certificate errors surface here.
    pub(crate) fn handshake(&mut self) -> Result<(), InterfaceError> {
        loop {
            self.with_duration().map_err(|e| network_failure(&e, "TLS handshake"))?;
            let Stream::Tls(t) = &mut self.stream else {
                return Ok(());
            };
            if !t.conn.is_handshaking() {
                return Ok(());
            }
            t.conn.complete_io(&mut t.sock).map_err(|e| network_failure(&e, "TLS handshake"))?;
        }
    }

    /// Sends `close_notify` when TLS (best effort).
    pub(crate) fn close(mut self) {
        if let Stream::Tls(t) = &mut self.stream {
            t.conn.send_close_notify();
            let _ = t.flush();
        }
    }
}

impl Read for Connection {
    fn read(&mut self, pending: &mut [u8]) -> io::Result<usize> {
        self.with_duration()?;
        match &mut self.stream {
            Stream::Plain(t) => t.read(pending),
            Stream::Tls(t) => t.read(pending),
        }
    }
}

impl Write for Connection {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.with_duration()?;
        match &mut self.stream {
            Stream::Plain(t) => t.write(data),
            Stream::Tls(t) => t.write(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.with_duration()?;
        match &mut self.stream {
            Stream::Plain(t) => t.flush(),
            Stream::Tls(t) => t.flush(),
        }
    }
}

/// Maps an I/O error to a detail-free transient interface error. rustls error text (certificate,
/// protocol) may embed the host name, so it is never printed.
pub(crate) fn network_failure(e: &io::Error, stage: &str) -> InterfaceError {
    let reason = if e.get_ref().is_some_and(|i| i.is::<rustls::Error>()) {
        "TLS error (certificate or protocol)".to_string()
    } else {
        e.kind().to_string()
    };
    InterfaceError::Transient(format!("{stage}: {reason}"))
}

fn resolve_addresses(host: &str, port: u16, dur: Duration) -> Result<Vec<SocketAddr>, InterfaceError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let (send, rx) = mpsc::channel();
    let name = host.to_string();
    std::thread::spawn(move || {
        let _ = send.send((name.as_str(), port).to_socket_addrs().map(Iterator::collect::<Vec<_>>));
    });
    match rx.recv_timeout(dur) {
        Ok(Ok(a)) if !a.is_empty() => Ok(a),
        Ok(_) => Err(InterfaceError::Transient("the name could not be resolved".to_string())),
        Err(_) => Err(InterfaceError::Transient("name resolution timed out".to_string())),
    }
}

/// Opens a plain TCP connection; for TLS the caller then calls [`Connection::upgrade_to_tls`].
pub(crate) fn connect(host: &str, port: u16, timeout: Duration) -> Result<Connection, InterfaceError> {
    let deadline = Instant::now() + timeout;
    let addresses = resolve_addresses(host, port, timeout)?;
    let mut last_error = InterfaceError::Transient("could not connect".to_string());
    for a in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&a, remaining) {
            Ok(t) => {
                let _ = t.set_nodelay(true);
                return Ok(Connection { stream: Stream::Plain(t), deadline, timeout });
            }
            Err(e) => last_error = network_failure(&e, "connect"),
        }
    }
    Err(last_error)
}

/// An HTTP request.
pub(crate) struct Request<'a> {
    pub method: &'static str,
    pub url: &'a HttpsAddress,
    pub headers: &'a [Header],
    pub body: &'a [u8],
    pub timeout: Duration,
}

fn is_header_name_valid(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn is_header_value_valid(value: &str) -> bool {
    value.chars().all(|c| (' '..='~').contains(&c))
}

/// Builds the request bytes. When a header name or value holds a line break, a control
/// character or a non-ASCII character, the request is never built (defense in depth: callers sanitize already).
fn build_request(i: &Request<'_>) -> Result<Vec<u8>, InterfaceError> {
    let mut s = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: koru-notify\r\nAccept: */*\r\nConnection: close\r\n",
        i.method,
        i.url.request_target(),
        i.url.host_header()
    );
    for (name, value) in i.headers {
        if !is_header_name_valid(name) || !is_header_value_valid(value) {
            return Err(InterfaceError::Permanent(
                "invalid request header (line break or control character)".to_string(),
            ));
        }
        s.push_str(name);
        s.push_str(": ");
        s.push_str(value);
        s.push_str("\r\n");
    }
    if !i.body.is_empty() || i.method == "POST" {
        s.push_str(&format!("Content-Length: {}\r\n", i.body.len()));
    }
    s.push_str("\r\n");
    let mut byte = s.into_bytes();
    byte.extend_from_slice(i.body);
    Ok(byte)
}

/// Sends the request and returns the HTTP status code.
pub(crate) fn send(i: &Request<'_>) -> Result<u16, InterfaceError> {
    let wire = build_request(i)?;
    let mut b = connect(i.url.host(), i.url.port(), i.timeout)?;
    if i.url.is_tls() {
        b = b.upgrade_to_tls(i.url.host())?;
        b.handshake()?;
    }
    b.write_all(&wire).map_err(|e| network_failure(&e, "request send"))?;
    b.flush().map_err(|e| network_failure(&e, "request send"))?;
    let state = read_status(&mut b);
    b.close();
    state
}

/// Reads the status code from the response's first line (`HTTP/1.x NNN ...`).
fn read_status(b: &mut Connection) -> Result<u16, InterfaceError> {
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        match b.read(&mut byte) {
            Ok(0) => {
                return Err(InterfaceError::Transient(
                    "the server closed the connection without responding".to_string(),
                ));
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > MAX_STATUS_LINE_BYTES {
                    return Err(InterfaceError::Transient("the response status line is too long".to_string()));
                }
            }
            Err(e) => return Err(network_failure(&e, "response read")),
        }
    }
    let line = String::from_utf8_lossy(&line);
    let mut parts = line.trim_end_matches('\r').split(' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") || code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InterfaceError::Transient("the response is not HTTP".to_string()));
    }
    code.parse().map_err(|_| InterfaceError::Transient("the response status code could not be read".to_string()))
}

/// Classifies a status code: 2xx success; 408, 425, 429 and 5xx transient; everything else
/// (3xx and other 4xx included; redirects are never followed) permanent.
pub(crate) fn classify_status(state: u16) -> Result<(), InterfaceError> {
    match state {
        200..=299 => Ok(()),
        408 | 425 | 429 | 500..=599 => Err(InterfaceError::Transient(format!("HTTP status {state}"))),
        _ => Err(InterfaceError::Permanent(format!("HTTP status {state}"))),
    }
}
