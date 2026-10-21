//! The SMTP channel (`KORU_SMTP_*`).
//!
//! TLS is mandatory: implicit TLS on port 465, STARTTLS elsewhere. When the server does not
//! offer STARTTLS or the handshake fails, no credentials are sent and no mail is sent. A
//! plaintext connection exists only for `127.0.0.1` fake servers.

use std::io::{Read, Write};
use std::time::Duration;

use koru_event::{InterfaceError, Notification, NotificationChannel, Severity};

use crate::address::is_valid_host;
use crate::backoff::random_u64;
use crate::http::{self, Connection, network_failure};
use crate::text::{base64_encode, header_value, sanitize_body, sanitize_header};
use crate::{NotifyError, Secret};

/// The name announced in EHLO (the real host name never leaks).
const EHLO_NAME: &str = "koru.local";
/// Max bytes for the subject (before encoding).
const MAX_SUBJECT_BYTES: usize = 200;
/// Max bytes for the body.
const MAX_BODY_BYTES_WIRE: usize = 20_000;

/// Connection security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// Implicit TLS (usually 465).
    Implicit,
    /// Connect plain and upgrade with STARTTLS (usually 587); the upgrade is mandatory.
    StartTls,
    /// No TLS; accepted only when the host is exactly `127.0.0.1` (tests).
    None,
}

/// SMTP settings.
#[derive(Debug, Clone)]
pub struct SmtpSettings {
    /// Host name.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name.
    pub user: String,
    /// Password.
    pub password: Secret,
    /// Sender address.
    pub from_addr: String,
    /// Recipient address.
    pub to_addr: String,
    /// Connection security.
    pub tls: SmtpTls,
    /// Connect, write and read deadline.
    pub timeout: Duration,
}

/// Mail address (`local@domain`): ASCII only; the local part is unquoted "dot-atom" characters;
/// the domain is a valid host name. No line break, space, `<`, `>`, `,` or `"`.
pub(crate) fn is_address_text_valid(url: &str) -> bool {
    let Some((local, field)) = url.split_once('@') else { return false };
    url.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|b| b.is_ascii_alphanumeric() || b".!#%&'*+/=?^_`{|}~-".contains(&b))
        && is_valid_host(field)
}

/// User name and password: non-empty, no control characters (NUL, CR, LF included).
pub(crate) fn is_credential_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
}

/// Whether the host name is valid.
pub(crate) fn is_host_text_valid(host: &str) -> bool {
    is_valid_host(host)
}

fn settings_error(field: &str) -> NotifyError {
    NotifyError::Settings(format!("invalid SMTP {field}"))
}

impl SmtpSettings {
    /// Validates the fields (addresses in `local@domain` form, no line breaks; user and password
    /// with no control characters). Connection security follows the port: 465 → [`SmtpTls::Implicit`],
    /// the rest → [`SmtpTls::StartTls`].
    pub fn new(
        host: &str,
        port: u16,
        user: &str,
        password: Secret,
        from_addr: &str,
        to_addr: &str,
    ) -> Result<SmtpSettings, NotifyError> {
        if !is_host_text_valid(host) {
            return Err(settings_error("host name"));
        }
        if port == 0 {
            return Err(settings_error("port"));
        }
        if !is_credential_valid(user) {
            return Err(settings_error("user name"));
        }
        if !is_credential_valid(password.reveal()) {
            return Err(settings_error("password"));
        }
        if !is_address_text_valid(from_addr) {
            return Err(settings_error("sender address"));
        }
        if !is_address_text_valid(to_addr) {
            return Err(settings_error("recipient address"));
        }
        Ok(SmtpSettings {
            host: host.to_string(),
            port,
            user: user.to_string(),
            password,
            from_addr: from_addr.to_string(),
            to_addr: to_addr.to_string(),
            tls: if port == 465 { SmtpTls::Implicit } else { SmtpTls::StartTls },
            timeout: Duration::from_secs(15),
        })
    }

    /// Changes the connection security; [`SmtpTls::None`] is accepted only for `127.0.0.1`.
    pub fn set_tls(mut self, tls: SmtpTls) -> Result<SmtpSettings, NotifyError> {
        if tls == SmtpTls::None && self.host != "127.0.0.1" {
            return Err(NotifyError::Settings("SMTP without TLS is accepted only for 127.0.0.1".to_string()));
        }
        self.tls = tls;
        Ok(self)
    }
}

/// An SMTP response: the code and the text lines.
struct Response {
    code: u16,
    /// The last line's text (without the code and the separator).
    text: String,
    /// All text lines of a multi-line response (for the capability list).
    lines: Vec<String>,
}

/// An SMTP session: the connection and the line buffer.
struct Session<'a> {
    b: Connection,
    pending: Vec<u8>,
    /// The last server response received (for `SmtpChannel::last_response`); written with `store`
    /// with secret values stripped before it is stored.
    last: &'a mut Option<String>,
    secrets: Vec<String>,
}

const MAX_LINE_LEN: usize = 2048;
const MAX_RESPONSE_LINES: usize = 64;
const MAX_LAST_RESPONSE_BYTES: usize = 200;

fn network_error(e: &std::io::Error, stage: &str) -> InterfaceError {
    network_failure(e, stage)
}

impl Session<'_> {
    fn read_line(&mut self) -> Result<String, InterfaceError> {
        loop {
            if let Some(i) = self.pending.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.pending.drain(..i + 2).collect();
                return Ok(String::from_utf8_lossy(&line[..i]).into_owned());
            }
            if self.pending.len() > MAX_LINE_LEN {
                return Err(InterfaceError::Transient("the SMTP response line is too long".to_string()));
            }
            let mut piece = [0u8; 1024];
            match self.b.read(&mut piece) {
                Ok(0) => return Err(InterfaceError::Transient("the SMTP server closed the connection".to_string())),
                Ok(n) => self.pending.extend_from_slice(&piece[..n]),
                Err(e) => return Err(network_error(&e, "SMTP response read")),
            }
        }
    }

    /// Records the last response: secret values become `***`, control characters are neutralized, it is truncated to 200 bytes.
    fn store(&mut self, y: &Response) {
        let mut text = format!("{} {}", y.code, y.text);
        for g in &self.secrets {
            if !g.is_empty() {
                text = text.replace(g.as_str(), "***");
            }
        }
        *self.last = Some(sanitize_header(&text, MAX_LAST_RESPONSE_BYTES));
    }

    fn read_response(&mut self) -> Result<Response, InterfaceError> {
        let mut lines = Vec::new();
        loop {
            let line = self.read_line()?;
            let b = line.as_bytes();
            if b.len() < 3 || !b[..3].iter().all(u8::is_ascii_digit) || (b.len() > 3 && b[3] != b' ' && b[3] != b'-') {
                return Err(InterfaceError::Transient("the SMTP response is malformed".to_string()));
            }
            let code: u16 = line[..3]
                .parse()
                .map_err(|_| InterfaceError::Transient("the SMTP response is malformed".to_string()))?;
            let text = line.get(4..).unwrap_or("").to_string();
            lines.push(text.clone());
            if lines.len() > MAX_RESPONSE_LINES {
                return Err(InterfaceError::Transient("the SMTP response is too long".to_string()));
            }
            if b.len() == 3 || b[3] == b' ' {
                let y = Response { code, text, lines };
                self.store(&y);
                return Ok(y);
            }
        }
    }

    fn write_message(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        self.b.write_all(data).map_err(|e| network_error(&e, "SMTP command send"))?;
        self.b.flush().map_err(|e| network_error(&e, "SMTP command send"))
    }

    fn smtp_command(&mut self, line: &str) -> Result<Response, InterfaceError> {
        self.write_message(format!("{line}\r\n").as_bytes())?;
        self.read_response()
    }
}

/// The response code must be one of the expected codes; otherwise 5xx is permanent and
/// everything else (4xx and unexpected 2xx/3xx) is transient. For the greeting (220),
/// STARTTLS (220), AUTH (235, 334), DATA (354) and the mail steps the exact code is required:
/// accepting "any 2xx" would let a man-in-the-middle or a broken server skip a step. The message
/// holds only the step name, the code and (when present) the RFC 3463 enhanced status code; the
fn expect_code(y: &Response, expected: &[u16], step: &str) -> Result<(), InterfaceError> {
    if expected.contains(&y.code) {
        return Ok(());
    }
    let enhanced = y.text.split(' ').next().filter(|t| {
        let p: Vec<&str> = t.split('.').collect();
        p.len() == 3 && p.iter().all(|x| !x.is_empty() && x.len() <= 3 && x.bytes().all(|b| b.is_ascii_digit()))
    });
    let message = match enhanced {
        Some(g) => format!("SMTP replied {} at the {step} step ({g})", y.code),
        None => format!("SMTP replied {} at the {step} step", y.code),
    };
    if y.code / 100 == 5 { Err(InterfaceError::Permanent(message)) } else { Err(InterfaceError::Transient(message)) }
}

fn capabilities(y: &Response) -> Vec<String> {
    y.lines.iter().skip(1).map(|s| s.to_ascii_uppercase()).collect()
}

/// Converts days to a date for the RFC 5322 date format (UTC) (Howard Hinnant's civil_from_days
/// algorithm).
fn date_header(unix_s: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = i64::try_from(unix_s / 86_400).unwrap_or(0);
    let sn = unix_s % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let g = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[usize::try_from(days.rem_euclid(7)).unwrap_or(0)],
        g,
        MONTHS[usize::try_from(month - 1).unwrap_or(0)],
        year,
        sn / 3600,
        (sn % 3600) / 60,
        sn % 60
    )
}

/// Splits base64 text into 76-character CRLF lines.
fn base64_wrap(b64: &str) -> String {
    let mut s = String::with_capacity(b64.len() + b64.len() / 76 * 2 + 2);
    for piece in b64.as_bytes().chunks(76) {
        s.push_str(&String::from_utf8_lossy(piece));
        s.push_str("\r\n");
    }
    s
}

fn build_message(settings: &SmtpSettings, b: &Notification) -> String {
    let label = match b.severity {
        Severity::Info => "Info",
        Severity::Warning => "Warning",
        Severity::Critical => "Critical",
    };
    let subject = header_value(&format!("[Koru {label}] {}", b.title), MAX_SUBJECT_BYTES, "\r\n ");
    let body = sanitize_body(&b.body, MAX_BODY_BYTES_WIRE);
    let unix_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let random = random_u64();
    let event = b.event_id.to_string();
    let mut m = String::new();
    m.push_str(&format!("From: {}\r\n", settings.from_addr));
    m.push_str(&format!("To: {}\r\n", settings.to_addr));
    m.push_str(&format!("Subject: {subject}\r\n"));
    m.push_str(&format!("Date: {}\r\n", date_header(unix_s)));
    m.push_str(&format!("Message-ID: <{event}.{random:016x}@koru.local>\r\n"));
    m.push_str("MIME-Version: 1.0\r\n");
    m.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    m.push_str("Content-Transfer-Encoding: base64\r\n");
    m.push_str(&format!("X-Koru-Event: {event}\r\n"));
    m.push_str(&format!("X-Koru-Severity: {}\r\n", label.to_ascii_lowercase()));
    m.push_str("\r\n");
    m.push_str(&base64_wrap(&base64_encode(body.as_bytes())));
    m
}

/// Dot-stuffing for DATA: a line starting with `.` becomes `..`.
fn dot_double_body(message: &str) -> String {
    let mut s = String::with_capacity(message.len() + 8);
    for line in message.split_inclusive("\r\n") {
        if line.starts_with('.') {
            s.push('.');
        }
        s.push_str(line);
    }
    s
}

/// The SMTP channel.
#[derive(Debug)]
pub struct SmtpChannel {
    settings: SmtpSettings,
    last_response: Option<String>,
}

impl SmtpChannel {
    /// The last server response from the last send (`250 2.0.0 Ok: queued as ...`; on failure, the
    /// error response). Control characters are neutralized, at most 200 bytes, and the user name
    /// and password are replaced with `***` even when the server echoes them. `None` when no response came.
    pub fn last_response(&self) -> Option<&str> {
        self.last_response.as_deref()
    }

    /// Builds the channel (no network).
    pub fn new(settings: SmtpSettings) -> SmtpChannel {
        SmtpChannel { settings, last_response: None }
    }

    fn run_session(&self, notification: &Notification, last: &mut Option<String>) -> Result<(), InterfaceError> {
        let a = &self.settings;
        if a.tls == SmtpTls::None && a.host != "127.0.0.1" {
            return Err(InterfaceError::Permanent("SMTP without TLS is accepted only for 127.0.0.1".to_string()));
        }
        if !is_address_text_valid(&a.from_addr) || !is_address_text_valid(&a.to_addr) {
            return Err(InterfaceError::Permanent("invalid SMTP addresses".to_string()));
        }
        if !is_credential_valid(&a.user) || !is_credential_valid(a.password.reveal()) {
            return Err(InterfaceError::Permanent("invalid SMTP credentials".to_string()));
        }
        let mut b = http::connect(&a.host, a.port, a.timeout)?;
        if a.tls == SmtpTls::Implicit {
            b = b.upgrade_to_tls(&a.host)?;
            b.handshake()?;
        }
        let credentials_b64 = base64_encode(format!("\0{}\0{}", a.user, a.password.reveal()).as_bytes());
        let secrets = vec![
            a.password.reveal().to_string(),
            a.user.clone(),
            credentials_b64,
            base64_encode(a.password.reveal().as_bytes()),
            base64_encode(a.user.as_bytes()),
        ];
        let mut o = Session { b, pending: Vec::new(), last, secrets };
        expect_code(&o.read_response()?, &[220], "greeting")?;
        let mut y = o.smtp_command(&format!("EHLO {EHLO_NAME}"))?;
        expect_code(&y, &[250], "EHLO")?;
        if a.tls == SmtpTls::StartTls {
            if !capabilities(&y).iter().any(|c| c == "STARTTLS") {
                return Err(InterfaceError::Transient(
                    "the server does not offer STARTTLS; credentials and mail were not sent in plaintext".to_string(),
                ));
            }
            expect_code(&o.smtp_command("STARTTLS")?, &[220], "STARTTLS")?;
            if !o.pending.is_empty() {
                // STARTTLS injection (CVE-2011-0411): extra data before TLS is rejected.
                return Err(InterfaceError::Transient("unexpected data after STARTTLS".to_string()));
            }
            o.b = o.b.upgrade_to_tls(&a.host)?;
            o.b.handshake()?;
            y = o.smtp_command(&format!("EHLO {EHLO_NAME}"))?;
            expect_code(&y, &[250], "EHLO (after TLS)")?;
        }
        let yet = capabilities(&y);
        if let Some(auth) = yet.iter().find(|c| c.starts_with("AUTH ") || *c == "AUTH") {
            let methods: Vec<&str> = auth.split([' ', '=']).collect();
            if methods.contains(&"PLAIN") {
                let id = base64_encode(format!("\0{}\0{}", a.user, a.password.reveal()).as_bytes());
                expect_code(&o.smtp_command(&format!("AUTH PLAIN {id}"))?, &[235], "AUTH")?;
            } else if methods.contains(&"LOGIN") {
                expect_code(&o.smtp_command("AUTH LOGIN")?, &[334], "AUTH")?;
                expect_code(&o.smtp_command(&base64_encode(a.user.as_bytes()))?, &[334], "AUTH")?;
                expect_code(&o.smtp_command(&base64_encode(a.password.reveal().as_bytes()))?, &[235], "AUTH")?;
            } else {
                return Err(InterfaceError::Permanent(
                    "the server's authentication methods are not supported".to_string(),
                ));
            }
        }
        expect_code(&o.smtp_command(&format!("MAIL FROM:<{}>", a.from_addr))?, &[250], "MAIL FROM")?;
        expect_code(&o.smtp_command(&format!("RCPT TO:<{}>", a.to_addr))?, &[250, 251], "RCPT TO")?;
        expect_code(&o.smtp_command("DATA")?, &[354], "DATA")?;
        let message = dot_double_body(&build_message(a, notification));
        o.write_message(message.as_bytes())?;
        let last = o.smtp_command(".")?;
        expect_code(&last, &[250], "DATA end")?;
        // The QUIT reply is not recorded: last_response stays the delivery reply.
        let _ = o.write_message(b"QUIT\r\n");
        o.b.close();
        Ok(())
    }
}

impl NotificationChannel for SmtpChannel {
    fn name(&self) -> &str {
        "smtp"
    }

    fn send(&mut self, notification: &Notification) -> Result<(), InterfaceError> {
        let mut last = None;
        let result = self.run_session(notification, &mut last);
        self.last_response = last;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_header_for_known_values() {
        for (sn, expected) in [
            (0, "Thu, 01 Jan 1970 00:00:00 +0000"),
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 +0000"),
            (1_791_990_000, "Wed, 14 Oct 2026 15:00:00 +0000"),
            (4_102_444_799, "Thu, 31 Dec 2099 23:59:59 +0000"),
            (1_709_251_199, "Thu, 29 Feb 2024 23:59:59 +0000"),
        ] {
            assert_eq!(date_header(sn), expected);
        }
    }

    #[test]
    fn dot_doubling() {
        assert_eq!(dot_double_body("a\r\n.b\r\n..c\r\n"), "a\r\n..b\r\n...c\r\n");
    }
}
