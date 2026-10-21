//! `https`-only addresses (one exception: the `http://127.0.0.1` fake servers in tests).

use std::fmt;

use crate::NotifyError;

/// A validated address. It may embed a secret (a ping address, a Telegram token), so its
/// `Debug` output never shows the address.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpsAddress {
    tls: bool,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
}

const MAX_ADDRESS_LEN: usize = 2048;

fn error() -> NotifyError {
    // The message deliberately omits the address.
    NotifyError::Settings("invalid address (https only; details withheld by design)".to_string())
}

/// Characters allowed in the path and query: RFC 3986 unreserved + sub-delims + `:` `@` `/` `%`.
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@/%".contains(c)
}

/// A `%` must be followed by two hex digits.
fn percent_codes_are_valid(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            match (b.get(i + 1), b.get(i + 2)) {
                (Some(x), Some(y)) if x.is_ascii_hexdigit() && y.is_ascii_hexdigit() => i += 3,
                _ => return false,
            }
        } else {
            i += 1;
        }
    }
    true
}

/// Host name: letters, digits, `-` and `.`; no empty label; a label is at most 63 chars.
pub(crate) fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|e| {
        !e.is_empty()
            && e.len() <= 63
            && !e.starts_with('-')
            && !e.ends_with('-')
            && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

impl HttpsAddress {
    /// Validates the form `https://host[:port][/path][?query]`. Rejected: `http` (unless the
    /// host is exactly `127.0.0.1`), user info (`@`), fragment (`#`), spaces and control
    /// characters, non-ASCII characters, IPv6 literals, an empty host, port 0.
    pub fn parse_parts(text: &str) -> Result<HttpsAddress, NotifyError> {
        if text.is_empty() || text.len() > MAX_ADDRESS_LEN || !text.chars().all(|c| c.is_ascii_graphic()) {
            return Err(error());
        }
        if text.contains(['#', '\\', '[', ']']) {
            return Err(error());
        }
        let (tls, remaining) = if let Some(k) = text.strip_prefix("https://") {
            (true, k)
        } else if let Some(k) = text.strip_prefix("http://") {
            (false, k)
        } else {
            return Err(error());
        };
        let authority_end = remaining.find(['/', '?']).unwrap_or(remaining.len());
        let (authority, rest) = remaining.split_at(authority_end);
        if authority.contains('@') {
            return Err(error());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(error());
                }
                let p: u16 = p.parse().map_err(|_| error())?;
                if p == 0 {
                    return Err(error());
                }
                (h, p)
            }
            None => (authority, if tls { 443 } else { 80 }),
        };
        if !is_valid_host(host) {
            return Err(error());
        }
        if !tls && host != "127.0.0.1" {
            return Err(error());
        }
        let (path, query) = match rest.split_once('?') {
            Some((y, s)) => (y, Some(s)),
            None => (rest, None),
        };
        let path = if path.is_empty() { "/" } else { path };
        if !path.chars().all(is_path_char) || !percent_codes_are_valid(path) {
            return Err(error());
        }
        if let Some(s) = query
            && (!s.chars().all(|c| is_path_char(c) || c == '?') || !percent_codes_are_valid(s))
        {
            return Err(error());
        }
        Ok(HttpsAddress { tls, host: host.to_string(), port, path: path.to_string(), query: query.map(str::to_string) })
    }

    /// The host name.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port (443 when omitted, 80 for `http://127.0.0.1`).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path (always starts with `/`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query string (without the `?`); `None` if absent.
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// Whether TLS is used (`https`).
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    /// Appends a segment to the path (`fail`, `sendMessage`); the query is kept. The segment
    /// may hold letters, digits, `-`, `_`, `~`, `:` and `.`; it cannot be `.` or `..`, nor hold `/`.
    pub fn join_path(&self, suffix: &str) -> Result<HttpsAddress, NotifyError> {
        let current = !suffix.is_empty()
            && suffix != "."
            && suffix != ".."
            && suffix.len() <= 512
            && suffix.chars().all(|c| c.is_ascii_alphanumeric() || "-_~:.".contains(c));
        if !current {
            return Err(error());
        }
        let mut new = self.clone();
        new.path = format!("{}/{}", self.path.trim_end_matches('/'), suffix);
        Ok(new)
    }

    /// The `Host` header value (no port at the default port).
    pub(crate) fn host_header(&self) -> String {
        let defaults = if self.tls { 443 } else { 80 };
        if self.port == defaults { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }

    /// The request target: path plus query when present.
    pub(crate) fn request_target(&self) -> String {
        match &self.query {
            Some(s) => format!("{}?{}", self.path, s),
            None => self.path.clone(),
        }
    }
}

impl fmt::Debug for HttpsAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HttpsAddress(***)")
    }
}
