//! The format and safety checks of generated content (ADR-0004 "Template safety"; KT-11, KT-16,
//! KT-17, KT-23).
//!
//! For every content:
//! - No control characters (except newline and tab).
//! - IPv4 literals only from the RFC 5737 documentation networks (TEST-NET-1/2/3); these
//!   addresses are not routed and never reach a real target.
//! - URL hosts only a documentation network or `.invalid` (RFC 6761: never resolves).
//! - The domain of an email-shaped address is single-label or ends in a reserved top-level
//!   (`.invalid`, `.test`, `.example`, `.localhost`, `.internal`).
//!
//! By format: .env, INI, JSON, an MCP configuration (remote servers only, no `command`/`args`/`env`
//! ), an SQL dump, an OpenSSH key file, `~/.ssh/config` (an allowlist; no wildcard, `Match`,
//! `Include`, or `ProxyCommand`), `known_hosts`, shell history and notes (no line carrying a
//! destructive, exfiltrating, or prompt-injection pattern).

use std::net::Ipv4Addr;

use serde_json::Value;

use crate::template::Format;

/// The RFC 5737 documentation networks.
pub(crate) fn is_test_network(ip: Ipv4Addr) -> bool {
    matches!(ip.octets(), [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
}

const RESERVED_TOP_FIELDS: [&str; 5] = [".invalid", ".test", ".example", ".localhost", ".internal"];

/// Forbidden patterns in shell history, notes, and free text (compared lowercase). Anything
/// that could steer a well-meaning agent toward a destructive, exfiltrating, or
/// instruction-changing action is rejected here.
const FORBIDDEN_PATTERNS: [&str; 43] = [
    "rm -",
    "rmdir",
    "mkfs",
    "dd if=",
    ":(){",
    "curl",
    "wget",
    "| sh",
    "|sh",
    "| bash",
    "|bash",
    "nc ",
    "ncat",
    "netcat",
    "socat",
    "base64 -d",
    "chmod 777",
    "chmod -r",
    "chown -r",
    "> /dev/",
    "shutdown",
    "reboot",
    "poweroff",
    "kill -9",
    "pkill",
    "killall",
    "iptables",
    "systemctl stop",
    "systemctl disable",
    "crontab",
    "scp ",
    "rsync",
    "sftp",
    "ftp ",
    "telnet",
    "http://",
    "https://",
    "ignore previous",
    "ignore all previous",
    "disregard",
    "system prompt",
    "you are now",
    "history -c",
];

/// Does the constant text written in a template hold a value that could be a real secret? (KT-11)
///
/// Known prefixes (AWS, GitHub, API keys) are sought in narrow parts (`[A-Za-z0-9_-]`), and
/// high entropy in wide parts (base64 characters included).
pub(crate) fn fixed_secret(text: &str) -> Option<&'static str> {
    if text.contains("PRIVATE KEY-----") {
        return Some("a PEM private key header");
    }
    let narrow_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-');
    for j in text.split(|c: char| !narrow_char(c)) {
        let rest_len = |prefix: &str| j.strip_prefix(prefix).map_or(0, str::len);
        if (j.starts_with("AKIA") || j.starts_with("ASIA"))
            && j.len() == 20
            && j[4..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return Some("an AWS access key id");
        }
        if ["ghp_", "gho_", "ghs_", "ghu_", "github_pat_"].iter().any(|o| rest_len(o) >= 30) {
            return Some("GitHub token");
        }
        if rest_len("sk-") >= 24 || rest_len("sk_live_") >= 16 || rest_len("xox") >= 20 || rest_len("AIza") >= 30 {
            return Some("an API key prefix");
        }
    }
    let token_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=');
    for j in text.split(|c: char| !token_char(c)) {
        let mixed = j.chars().any(|c| c.is_ascii_uppercase())
            && j.chars().any(|c| c.is_ascii_lowercase())
            && j.chars().any(|c| c.is_ascii_digit());
        if j.len() >= 32 && mixed {
            return Some("a long high-entropy string");
        }
        if j.len() >= 40 && j.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some("a long hex string");
        }
    }
    None
}

/// The IPv4 literals in the text: parts in exactly dotted-decimal form, separated by characters
/// other than letters, digits, and dots.
pub(crate) fn ipv4_constants(text: &str) -> Vec<Ipv4Addr> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
        .filter(|p| p.chars().all(|c| c.is_ascii_digit() || c == '.'))
        .filter(|p| p.split('.').count() == 4 && p.split('.').all(|s| !s.is_empty() && s.len() <= 3))
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// Is the host reserved: a documentation-network IPv4 or `.invalid`.
pub(crate) fn reserved_host(host: &str) -> bool {
    host.parse().is_ok_and(is_test_network) || (host.len() > 8 && host.to_ascii_lowercase().ends_with(".invalid"))
}

fn url_hosts(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut remaining = text;
    while let Some(i) = remaining.find("://") {
        let remainder = &remaining[i + 3..];
        let authority: String =
            remainder.chars().take_while(|c| !c.is_whitespace() && !"/?#\"'`<>)],;".contains(*c)).collect();
        let authority = authority.rsplit_once('@').map_or(authority.as_str(), |(_, k)| k).to_string();
        let host = if authority.starts_with('[') {
            authority.clone()
        } else {
            authority.split(':').next().unwrap_or("").to_string()
        };
        hosts.push(host);
        remaining = remainder;
    }
    hosts
}

fn email_fields(text: &str) -> Vec<String> {
    let local = |c: char| c.is_ascii_alphanumeric() || "._%+-".contains(c);
    let field = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
    let mut result = Vec::new();
    for (i, _) in text.match_indices('@') {
        let before = &text[..i];
        let local_part: String = before.chars().rev().take_while(|c| local(*c)).collect();
        if local_part.is_empty() {
            continue;
        }
        let name: String = text[i + 1..].chars().take_while(|c| field(*c)).collect();
        let name = name.trim_end_matches(['.', '-']).to_string();
        if !name.is_empty() {
            result.push(name);
        }
    }
    result
}

/// The checks common to all formats.
fn check_common(text: &str) -> Result<(), String> {
    if text.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err("checksum character".into());
    }
    for ip in ipv4_constants(text) {
        if !is_test_network(ip) {
            return Err(format!("an IPv4 address outside the documentation networks (RFC 5737): {ip}"));
        }
    }
    for host in url_hosts(text) {
        if !reserved_host(&host) {
            return Err(format!("the URL points to an unreserved host: {host:?}"));
        }
    }
    for name in email_fields(text) {
        let current = !name.contains('.')
            || name.parse().is_ok_and(is_test_network)
            || RESERVED_TOP_FIELDS.iter().any(|u| name.to_ascii_lowercase().ends_with(u));
        if !current {
            return Err(format!("the address points to an unreserved domain: @{name}"));
        }
    }
    Ok(())
}

fn forbidden_pattern(text: &str) -> Result<(), String> {
    let lowercased = text.to_lowercase();
    match FORBIDDEN_PATTERNS.iter().find(|k| lowercased.contains(*k)) {
        Some(k) => {
            Err(format!("forbidden pattern: {k:?} (destructive, exfiltrating, or instruction-changing content)"))
        }
        None => Ok(()),
    }
}

fn check_env(text: &str) -> Result<(), String> {
    let mut number = 0;
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (a, _) = line.split_once('=').ok_or_else(|| format!("line {}: not KEY=VALUE", i + 1))?;
        let mut c = a.chars();
        let current = c.next().is_some_and(|k| k.is_ascii_uppercase() || k == '_')
            && c.all(|k| k.is_ascii_uppercase() || k.is_ascii_digit() || k == '_');
        if !current {
            return Err(format!("line {}: invalid key {a:?}", i + 1));
        }
        number += 1;
    }
    if number == 0 {
        return Err("no KEY=VALUE line".into());
    }
    Ok(())
}

fn check_ini(text: &str) -> Result<(), String> {
    let mut section = false;
    for (i, line) in text.lines().enumerate() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') || s.starts_with(';') {
            continue;
        }
        if let Some(name) = s.strip_prefix('[').and_then(|g| g.strip_suffix(']')) {
            if name.is_empty() || name.contains(['[', ']']) {
                return Err(format!("line {}: invalid section", i + 1));
            }
            section = true;
            continue;
        }
        let (a, _) = s.split_once('=').ok_or_else(|| format!("line {}: no '='", i + 1))?;
        let a = a.trim();
        if !section || a.is_empty() || !a.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)) {
            return Err(format!("line {}: outside a section, or an invalid key", i + 1));
        }
    }
    if !section {
        return Err("no section".into());
    }
    Ok(())
}

fn json_keys<'a>(d: &'a Value, output: &mut Vec<&'a str>) {
    match d {
        Value::Object(n) => {
            for (a, child) in n {
                output.push(a);
                json_keys(child, output);
            }
        }
        Value::Array(array) => array.iter().for_each(|child| json_keys(child, output)),
        _ => {}
    }
}

/// An MCP configuration: remote (HTTP) servers only, a reserved address, no `command` (KT-17).
fn check_mcp(d: &Value) -> Result<(), String> {
    let mut keys = Vec::new();
    json_keys(d, &mut keys);
    if let Some(a) = keys.iter().find(|a| matches!(**a, "command" | "args" | "env")) {
        return Err(format!("the {a:?} field cannot be used in an MCP decoy (KT-17)"));
    }
    let servers = d
        .get("mcpServers")
        .and_then(Value::as_object)
        .filter(|s| !s.is_empty())
        .ok_or("mcpServers must be a non-empty object")?;
    for (name, server) in servers {
        let object = server.as_object().ok_or_else(|| format!("{name}: the server definition must be an object"))?;
        if let Some(a) = object.keys().find(|a| !matches!(a.as_str(), "type" | "url" | "headers")) {
            return Err(format!("{name}: field {a:?} is not allowed (type, url, headers)"));
        }
        let kind = object.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(kind, "http" | "sse" | "streamable-http") {
            return Err(format!("{name}: only remote server kinds (http, sse, streamable-http)"));
        }
        let url = object.get("url").and_then(Value::as_str).ok_or_else(|| format!("{name}: url missing"))?;
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(format!("{name}: the url must be http(s)"));
        }
        let headers =
            object.get("headers").and_then(Value::as_object).ok_or_else(|| format!("{name}: headers missing"))?;
        if !headers.values().all(Value::is_string) {
            return Err(format!("{name}: header values must be strings"));
        }
    }
    Ok(())
}

fn check_sql(text: &str) -> Result<(), String> {
    if !text.starts_with("-- ") {
        return Err("the SQL dump must start with a comment header".into());
    }
    if !text.contains("CREATE TABLE") || !text.contains("INSERT INTO") {
        return Err("CREATE TABLE and INSERT INTO expected".into());
    }
    let body: String = text.lines().filter(|s| !s.starts_with("--")).flat_map(|s| [s, "\n"]).collect();
    let c: Vec<char> = body.chars().collect();
    let (mut single, mut in_backtick, mut comment, mut depth) = (false, false, false, 0i64);
    let mut i = 0;
    while i < c.len() {
        if comment {
            if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                comment = false;
                i += 1;
            }
        } else if single {
            if c[i] == '\\' {
                i += 1;
            } else if c[i] == '\'' {
                if c.get(i + 1) == Some(&'\'') {
                    i += 1;
                } else {
                    single = false;
                }
            }
        } else if in_backtick {
            in_backtick = c[i] != '`';
        } else {
            match c[i] {
                '\'' => single = true,
                '`' => in_backtick = true,
                '/' if c.get(i + 1) == Some(&'*') => {
                    comment = true;
                    i += 1;
                }
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth < 0 {
                        return Err("unmatched closing parenthesis".into());
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    if single || in_backtick || comment || depth != 0 {
        return Err("unbalanced quote, backtick, comment, or parenthesis".into());
    }
    if !body.trim_end().ends_with(';') {
        return Err("the last statement must end with ';'".into());
    }
    Ok(())
}

fn check_ssh_config(text: &str) -> Result<(), String> {
    let valid_name = |s: &str| {
        !s.is_empty()
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            && (!s.contains('.') || s.to_ascii_lowercase().ends_with(".invalid"))
    };
    let mut aliases: Vec<&str> = Vec::new();
    let mut in_block = false;
    for (i, line) in text.lines().enumerate() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let (key, value) = s.split_once(char::is_whitespace).map_or((s, ""), |(a, d)| (a, d.trim()));
        let error = |n: &str| format!("line {}: {n}", i + 1);
        match key.to_ascii_lowercase().as_str() {
            "host" => {
                if line.starts_with(char::is_whitespace) {
                    return Err(error("the Host line must not be indented"));
                }
                let names: Vec<&str> = value.split_whitespace().collect();
                if names.is_empty() || !names.iter().all(|a| valid_name(a)) {
                    return Err(error("Host may hold only wildcard-free, single-label or .invalid names"));
                }
                aliases.extend(names);
                in_block = true;
            }
            _ if !in_block => return Err(error("a directive outside a Host block")),
            "hostname" => {
                if !reserved_host(value) {
                    return Err(error("HostName may only be a documentation network or .invalid"));
                }
            }
            "user" => {
                if value.is_empty() || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    return Err(error("an invalid User"));
                }
            }
            "port" | "serveraliveinterval" | "serveralivecountmax" => {
                if value.parse::<u16>().is_err() {
                    return Err(error("a number is expected"));
                }
            }
            "identityfile" => {
                if !value.starts_with("~/.ssh/") || value.contains(char::is_whitespace) || value.contains("..") {
                    return Err(error("IdentityFile must be a space-free path under ~/.ssh/"));
                }
            }
            "identitiesonly" => {
                if !matches!(value, "yes" | "no") {
                    return Err(error("IdentitiesOnly must be yes or no"));
                }
            }
            "proxyjump" => {
                if !aliases.contains(&value) {
                    return Err(error("ProxyJump may only point to a previously defined fake target"));
                }
            }
            _ => return Err(error(&format!("a directive that is not allowed: {key}"))),
        }
    }
    if aliases.is_empty() {
        return Err("no Host block".into());
    }
    Ok(())
}

fn check_known_hosts(text: &str) -> Result<(), String> {
    let mut number = 0;
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let error = |n: &str| format!("line {}: {n}", i + 1);
        if fields.len() < 3 {
            return Err(error("expected <hosts> <kind> <key>"));
        }
        for host in fields[0].split(',') {
            let host = host.strip_prefix('[').and_then(|k| k.split_once("]:")).map_or(host, |(k, _)| k);
            if !reserved_host(host) {
                return Err(error("the host may only be a documentation network or .invalid"));
            }
        }
        if !matches!(fields[1], "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ssh-rsa") {
            return Err(error("an unknown key kind"));
        }
        if !fields[2].chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)) {
            return Err(error("the key is not base64"));
        }
        number += 1;
    }
    if number == 0 {
        return Err("no entries".into());
    }
    Ok(())
}

fn check_lines(text: &str) -> Result<(), String> {
    if !text.ends_with('\n') {
        return Err("the last line must end with a newline".into());
    }
    if text.lines().any(|s| s.trim().is_empty()) {
        return Err("no empty line is allowed".into());
    }
    Ok(())
}

/// Checks generated content by its format. The format check runs on the real content; the
/// address, URL, and forbidden-pattern checks run on the content with random values masked
/// (`masked`): patterns like "nc " or "://" arising by chance inside random strings are not
/// false alarms; every text the template author wrote or picked from a list is checked.
pub(crate) fn check_content(format: Format, text: &str, masked: &str) -> Result<(), String> {
    if text.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err("checksum character".into());
    }
    check_common(masked)?;
    match format {
        Format::Text | Format::Markdown => forbidden_pattern(masked),
        Format::BashHistory => {
            check_lines(text)?;
            forbidden_pattern(masked)
        }
        Format::Env => check_env(text),
        Format::Ini => check_ini(text),
        Format::Json => serde_json::from_str::<Value>(text).map(|_| ()).map_err(|e| format!("not JSON: {e}")),
        Format::McpJson => {
            let d = serde_json::from_str::<Value>(text).map_err(|e| format!("not JSON: {e}"))?;
            check_mcp(&d)
        }
        Format::Sql => check_sql(text),
        Format::OpensshPrivateKey => {
            let (begin, last) = crate::generator::openssh_limits();
            if text.starts_with(&begin) && text.ends_with(&last) {
                Ok(())
            } else {
                Err("not an OpenSSH private key file".into())
            }
        }
        Format::SshConfig => check_ssh_config(text),
        Format::KnownHosts => check_known_hosts(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_rules() {
        assert!(check_common("postgres://u:p@203.0.113.5:5432/db").is_ok());
        assert!(check_common("postgres://u:p@10.0.0.5:5432/db").is_err());
        assert!(check_common("https://api.example.com/x").is_err());
        assert!(check_common("https://mcp.payments.invalid/x").is_ok());
        assert!(check_common("ssh deploy@bastion-prod").is_ok());
        assert!(check_common("mail ops@corp.internal").is_ok());
        assert!(check_common("mail ops@gmail.com").is_err());
        assert!(check_common("SET @OLD=@@CHARACTER_SET_CLIENT").is_ok());
        assert!(check_common("Distrib 8.0.39").is_ok());
        assert!(check_common("a\u{7}b").is_err());
    }

    #[test]
    fn fixed_secret_detection() {
        assert!(fixed_secret("x").is_none());
        assert!(fixed_secret("sk-proj-").is_none());
        assert!(fixed_secret("T3BlbkFJ").is_none());
        assert!(fixed_secret(&format!("AKIA{}", "Z".repeat(16))).is_some());
        assert!(fixed_secret(&format!("{}{}", "Ab1", "x".repeat(30))).is_some());
        assert!(fixed_secret(&"a1".repeat(20)).is_some());
        assert!(fixed_secret(&format!("KEY_ID=AKIA{}", "Q".repeat(16))).is_some());
    }
}
