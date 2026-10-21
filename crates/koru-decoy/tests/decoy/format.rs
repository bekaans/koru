//! Format tests: installed decoys are read back with real tools and parsers.
//!
//! - An OpenSSH private key: `ssh-keygen -l` (fingerprint) and `ssh-keygen -y` (public-key derivation).
//! - MCP configurations and other JSON files: `serde_json`; in MCP, remote (HTTP) servers only,
//!   a reserved address, and no `command`/`args`/`env` (KT-17).
//! - A cloud credentials file: INI (section + `key = value`).
//! - .env: `KEY=VALUE` lines; LLM provider keys resemble the real formats.
//! - An SQL dump: a comment header, CREATE TABLE and INSERT INTO; quote and parenthesis balance.
//! - `~/.ssh/config`: `ssh -G -F`; `known_hosts`: `ssh-keygen -l -f`.
//! - In all content, IPv4 literals come only from the RFC 5737 documentation networks.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use koru_decoy::{Format, InstallReport, Package, RecordEntry};
use serde_json::Value;

use crate::common::{Env, command, ipv4_constants, is_test_network, package};

fn by_format<'a>(package: &Package, report: &'a InstallReport, format: Format) -> Vec<&'a RecordEntry> {
    let entries: Vec<&RecordEntry> = report
        .entries
        .iter()
        .filter(|g| {
            package.template(&g.template).unwrap_or_else(|| panic!("no template {}", g.template)).format == format
        })
        .collect();
    assert!(!entries.is_empty(), "no installed decoy in {format:?} format");
    entries
}

fn by_class<'a>(report: &'a InstallReport, class: &str) -> Vec<&'a RecordEntry> {
    let entries: Vec<&RecordEntry> = report.entries.iter().filter(|g| g.class == class).collect();
    assert!(!entries.is_empty(), "no installed decoy in class {class}");
    entries
}

fn read(g: &RecordEntry) -> String {
    fs::read_to_string(&g.path).unwrap_or_else(|e| panic!("{}: {e}", g.path))
}

fn only_chars(s: &str, allowed: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.chars().all(allowed)
}

fn base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn url_host(url: &str) -> String {
    let rest_len = url.split_once("://").map_or(url, |(_, g)| g);
    let authority = rest_len.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, k)| k);
    authority.split(':').next().unwrap_or("").to_string()
}

fn reserved_host(host: &str) -> bool {
    host.parse().is_ok_and(is_test_network) || host.to_ascii_lowercase().ends_with(".invalid")
}

#[test]
fn ssh_key_parses_with_ssh_keygen() {
    let environment = Env::new();
    let report = environment.install();
    for g in by_format(&package(), &report, Format::OpensshPrivateKey) {
        let mode = fs::metadata(&g.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}: a private key must be 0600", g.path);
        let fingerprint = command("ssh-keygen", &["-l", "-f", &g.path], environment.root());
        let output_text = String::from_utf8_lossy(&fingerprint.stdout);
        assert!(fingerprint.status.success(), "ssh-keygen -l failed: {}", String::from_utf8_lossy(&fingerprint.stderr));
        assert!(output_text.starts_with("256 SHA256:"), "unexpected fingerprint: {output_text}");
        assert!(output_text.trim_end().ends_with("(ED25519)"), "an unexpected key kind: {output_text}");
        let public_part = command("ssh-keygen", &["-y", "-f", &g.path], environment.root());
        let public_text = String::from_utf8_lossy(&public_part.stdout);
        assert!(public_part.status.success(), "ssh-keygen -y failed: {}", String::from_utf8_lossy(&public_part.stderr));
        assert!(
            public_text.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"),
            "the public key could not be derived: {public_text}"
        );
        // The header and footer lines are not written whole in source: secret scanners
        // (gitleaks) would take what sits between them for a private key.
        let content = read(g);
        let kind = "OPENSSH PRIVATE KEY";
        assert!(content.starts_with(&format!("-----BEGIN {kind}-----\n")));
        assert!(content.ends_with(&format!("-----END {kind}-----\n")));
    }
}

fn json_keys(d: &Value, output_text: &mut Vec<String>) {
    match d {
        Value::Object(object) => {
            for (a, child) in object {
                output_text.push(a.clone());
                json_keys(child, output_text);
            }
        }
        Value::Array(array) => array.iter().for_each(|child| json_keys(child, output_text)),
        _ => {}
    }
}

#[test]
fn mcp_configs_parse_as_json_with_only_reserved_remote_servers() {
    let environment = Env::new();
    let report = environment.install();
    let mcp = by_format(&package(), &report, Format::McpJson);
    assert!(mcp.len() >= 3, ".mcp.json, claude_desktop_config.json and ~/.cursor/mcp.json expected");
    for g in mcp {
        let d: Value = serde_json::from_str(&read(g)).unwrap_or_else(|e| panic!("{}: not JSON: {e}", g.path));
        let servers = d["mcpServers"].as_object().unwrap_or_else(|| panic!("{}: mcpServers object missing", g.path));
        assert!(!servers.is_empty());
        let mut keys = Vec::new();
        json_keys(&d, &mut keys);
        for forbidden in ["command", "args", "env"] {
            assert!(!keys.iter().any(|a| a == forbidden), "{}: the {forbidden} field is present (KT-17)", g.path);
        }
        for (name, server) in servers {
            let kind = server["type"].as_str().unwrap_or("");
            assert!(["http", "sse", "streamable-http"].contains(&kind), "{name}: not a remote server kind: {kind}");
            let url = server["url"].as_str().unwrap_or_else(|| panic!("{name}: url missing"));
            assert!(url.starts_with("http://") || url.starts_with("https://"), "{name}: {url}");
            assert!(reserved_host(&url_host(url)), "{name}: an unreserved address: {url}");
            let headers = server["headers"].as_object().unwrap_or_else(|| panic!("{name}: headers missing"));
            assert!(headers.values().all(Value::is_string));
        }
    }
    let package = package();
    let json_formatnde = |g: &&RecordEntry| {
        matches!(package.template(&g.template).map(|s| s.format), Some(Format::Json | Format::McpJson))
    };
    for g in report.entries.iter().filter(json_formatnde) {
        serde_json::from_str::<Value>(&read(g)).unwrap_or_else(|e| panic!("{}: not JSON: {e}", g.path));
    }
}

/// A strict INI parser: section headers and `key = value` lines.
fn parse_ini(text: &str) -> Result<BTreeMap<String, BTreeMap<String, String>>, String> {
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut section: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') || s.starts_with(';') {
            continue;
        }
        if let Some(name) = s.strip_prefix('[').and_then(|g| g.strip_suffix(']')) {
            if name.is_empty() || sections.contains_key(name) {
                return Err(format!("line {}: an invalid or duplicate section", i + 1));
            }
            sections.insert(name.to_string(), BTreeMap::new());
            section = Some(name.to_string());
            continue;
        }
        let (a, d) = s.split_once('=').ok_or_else(|| format!("line {}: no '='", i + 1))?;
        let (a, d) = (a.trim(), d.trim());
        if a.is_empty() || !a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
            return Err(format!("line {}: an invalid key", i + 1));
        }
        let b = section.as_ref().ok_or_else(|| format!("line {}: a key outside a section", i + 1))?;
        sections.get_mut(b).expect("section").insert(a.to_string(), d.to_string());
    }
    if sections.is_empty() {
        return Err("no section".into());
    }
    Ok(sections)
}

#[test]
fn cloud_credentials_parse_as_ini() {
    let environment = Env::new();
    let report = environment.install();
    for g in by_format(&package(), &report, Format::Ini) {
        parse_ini(&read(g)).unwrap_or_else(|e| panic!("{}: not INI: {e}", g.path));
    }
    for g in by_class(&report, "cloud_credentials") {
        assert!(g.path.ends_with("/.aws/credentials"), "{}", g.path);
        let sections = parse_ini(&read(g)).unwrap();
        assert!(sections.contains_key("default"), "[default] profile missing");
        assert!(sections.len() >= 2, "at least two profiles expected");
        for (name, fields) in &sections {
            let id = &fields["aws_access_key_id"];
            assert!(
                id.len() == 20
                    && id.starts_with("AKIA")
                    && only_chars(&id[4..], |c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
                "[{name}] aws_access_key_id format"
            );
            let secret = &fields["aws_secret_access_key"];
            assert!(secret.len() == 40 && only_chars(secret, |c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
        }
    }
}

fn parse_env(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (a, d) = line.split_once('=').ok_or_else(|| format!("line {}: no '='", i + 1))?;
        let mut letters = a.chars();
        let first_valid = letters.next().is_some_and(|c| c.is_ascii_uppercase() || c == '_');
        if !first_valid || !letters.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return Err(format!("line {}: an invalid key {a:?}", i + 1));
        }
        if d.chars().any(char::is_control) {
            return Err(format!("line {}: a control character", i + 1));
        }
        if result.insert(a.to_string(), d.to_string()).is_some() {
            return Err(format!("line {}: a duplicate key {a}", i + 1));
        }
    }
    Ok(result)
}

#[test]
fn env_files_are_key_value_lines_and_llm_keys_resemble_real_formats() {
    let environment = Env::new();
    let report = environment.install();
    for g in by_format(&package(), &report, Format::Env) {
        assert!(g.path.ends_with("/.env"), "{}", g.path);
        let fields = parse_env(&read(g)).unwrap_or_else(|e| panic!("{}: not .env: {e}", g.path));
        assert!(fields.len() >= 4, "{}: at least 4 variables expected", g.path);
    }
    for g in by_class(&report, "llm_keys") {
        let a = parse_env(&read(g)).unwrap();
        let openai = &a["OPENAI_API_KEY"];
        assert!(openai.starts_with("sk-proj-") && openai.len() >= 100 && only_chars(&openai[8..], base64url));
        assert!(openai.contains("T3BlbkFJ"), "no OpenAI key marker");
        let anthropic = &a["ANTHROPIC_API_KEY"];
        assert!(anthropic.starts_with("sk-ant-api03-") && anthropic.ends_with("AA") && anthropic.len() == 13 + 93 + 2);
        assert!(only_chars(&anthropic[13..], base64url));
        let gemini = &a["GEMINI_API_KEY"];
        assert!(gemini.starts_with("AIza") && gemini.len() == 39 && only_chars(&gemini[4..], base64url));
        let openrouter = &a["OPENROUTER_API_KEY"];
        assert!(openrouter.starts_with("sk-or-v1-") && openrouter.len() == 9 + 64);
        assert!(only_chars(&openrouter[9..], |c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }
}

/// Strips comments from an SQL dump; checks quote, backtick, and parenthesis balance.
fn check_sql(text: &str) -> Result<(), String> {
    if !text.starts_with("-- ") {
        return Err("does not start with a comment header".into());
    }
    if !text.contains("CREATE TABLE") || !text.contains("INSERT INTO") {
        return Err("CREATE TABLE or INSERT INTO missing".into());
    }
    let mut body = String::new();
    for line in text.lines() {
        if !line.starts_with("--") {
            body.push_str(line);
            body.push('\n');
        }
    }
    let (mut single, mut in_backtick, mut comment, mut depth) = (false, false, false, 0i64);
    let c: Vec<char> = body.chars().collect();
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
            if c[i] == '`' {
                in_backtick = false;
            }
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
        return Err(format!("unbalanced: single={single} in_backtick={in_backtick} comment={comment} depth={depth}"));
    }
    if !body.trim_end().ends_with(';') {
        return Err("the last statement does not end with ';'".into());
    }
    Ok(())
}

#[test]
fn database_dump_looks_like_valid_sql() {
    let environment = Env::new();
    let report = environment.install();
    for g in by_format(&package(), &report, Format::Sql) {
        assert!(g.path.ends_with(".sql"), "{}", g.path);
        let text = read(g);
        check_sql(&text).unwrap_or_else(|e| panic!("{}: not SQL: {e}", g.path));
        let inserts = text.matches("INSERT INTO").count();
        assert!(inserts >= 2, "data expected in at least two tables");
        assert!(text.contains("$2b$"), "password hashes are expected in bcrypt format");
    }
}

#[test]
fn ssh_config_parses_and_points_to_reserved_address() {
    let environment = Env::new();
    let report = environment.install();
    for g in by_format(&package(), &report, Format::SshConfig) {
        let text = read(g);
        let aliases: Vec<String> = text
            .lines()
            .filter_map(|s| s.trim().strip_prefix("Host "))
            .flat_map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>())
            .collect();
        assert!(aliases.len() >= 2, "at least two fake targets are expected");
        for name in &aliases {
            assert!(!name.contains(['*', '?', '!']), "wildcard Host: {name}");
            let output_text = command("ssh", &["-G", "-F", &g.path, name], environment.root());
            let text = String::from_utf8_lossy(&output_text.stdout);
            assert!(output_text.status.success(), "ssh -G {name}: {}", String::from_utf8_lossy(&output_text.stderr));
            let host = text.lines().find_map(|s| s.strip_prefix("hostname ")).expect("hostname line");
            assert!(reserved_host(host), "{name} -> {host}: not a reserved address");
        }
    }
}

#[test]
fn known_hosts_parses_with_ssh_keygen() {
    let environment = Env::new();
    let report = environment.install();
    for g in by_format(&package(), &report, Format::KnownHosts) {
        let text = read(g);
        let entries: Vec<&str> = text.lines().filter(|s| !s.trim().is_empty() && !s.starts_with('#')).collect();
        assert!(entries.len() >= 2);
        for line in &entries {
            let hosts = line.split_whitespace().next().unwrap();
            for host in hosts.split(',') {
                let host = host.trim_start_matches('[').split(']').next().unwrap();
                assert!(reserved_host(host), "known_hosts unreserved host: {host}");
            }
        }
        let output_text = command("ssh-keygen", &["-l", "-f", &g.path], environment.root());
        let text = String::from_utf8_lossy(&output_text.stdout);
        assert!(
            output_text.status.success(),
            "ssh-keygen -l known_hosts: {}",
            String::from_utf8_lossy(&output_text.stderr)
        );
        assert_eq!(text.lines().count(), entries.len());
        assert!(text.lines().all(|s| s.starts_with("256 SHA256:") && s.ends_with("(ED25519)")), "{text}");
    }
}

/// Destructive, exfiltrating, or instruction-changing patterns. Phrases holding non-letter,
/// non-digit characters are searched as substrings, command names as words: a letter run like
/// "nc" appearing by chance inside a random password is not a pattern.
fn forbidden_pattern(line: &str) -> Option<String> {
    let lowercased = line.to_lowercase();
    let phrases = [
        "http://",
        "https://",
        "| sh",
        "|sh",
        "| bash",
        "|bash",
        "dd if=",
        "chmod 777",
        "base64 -d",
        "> /dev/",
        "ignore previous",
        "ignore all previous",
    ];
    if let Some(i) = phrases.iter().find(|i| lowercased.contains(*i)) {
        return Some((*i).to_string());
    }
    let commands = ["rm", "curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "rsync", "sftp", "mkfs", "shutdown"];
    lowercased
        .split_whitespace()
        .map(|s| s.trim_start_matches(['`', '(', '$']))
        .find(|s| commands.contains(s))
        .map(str::to_string)
}

#[test]
fn bash_history_and_notes_are_harmless_and_point_only_to_other_decoys() {
    let environment = Env::new();
    let report = environment.install();
    let package = package();
    for g in by_format(&package, &report, Format::BashHistory) {
        let text = read(g);
        assert!(text.lines().count() >= 5);
        for line in text.lines() {
            assert!(!line.trim().is_empty() && line.chars().all(|c| !c.is_control()), "an invalid line: {line:?}");
            assert_eq!(forbidden_pattern(line), None, "a forbidden pattern in history: {line}");
        }
    }
    for g in by_format(&package, &report, Format::Markdown) {
        let text = read(g);
        for line in text.lines() {
            assert_eq!(forbidden_pattern(line), None, "a forbidden pattern in a note: {line}");
        }
        let references: Vec<String> = text
            .split(|c: char| c.is_whitespace() || matches!(c, '`' | '(' | ')' | ',' | '"' | '\''))
            .filter_map(|s| s.strip_prefix("~/"))
            .map(|s| s.trim_end_matches(['.', ':', ';']).to_string())
            .collect();
        assert!(references.len() >= 3, "a note must point to at least three decoys: {references:?}");
        for reference in &references {
            assert!(environment.root().join(reference).exists(), "a note points to a non-existent path: ~/{reference}");
        }
    }
}

#[test]
fn ipv4_in_all_content_from_documentation_networks() {
    let environment = Env::new();
    let report = environment.install();
    let mut number = 0;
    for g in &report.entries {
        let content = fs::read(&g.path).unwrap();
        for ip in ipv4_constants(&String::from_utf8_lossy(&content)) {
            assert!(is_test_network(ip), "{}: an IPv4 outside the documentation networks: {ip}", g.path);
            number += 1;
        }
    }
    assert!(number >= 3, "breadcrumb fake targets must appear as IPv4");
    assert!(Path::new(&report.entries[0].path).is_absolute());
}
