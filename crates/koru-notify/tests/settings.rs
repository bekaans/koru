//! Reading settings (protected set): environment variables and
//! `.env`. Secrets are read only from the environment and `.env`; errors and `Debug` carry no values.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use common::*;
use koru_notify::{ChannelSet, NotifyError, SmtpTls, parse_dotenv, read_dotenv};

const TELEGRAM_TOKEN: &str = "123456789:AAE_very-secret_TOKEN";
const NTFY_TOKEN: &str = "tk_very_secret_ntfy";
const SMTP_PASSWORD: &str = "very-secret-smtp-password";
const PING_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

fn a_full_environment() -> BTreeMap<String, String> {
    [
        ("KORU_NTFY_URL", "https://ntfy.example.test/secret-topic"),
        ("KORU_NTFY_TOKEN", NTFY_TOKEN),
        ("KORU_TELEGRAM_BOT_TOKEN", TELEGRAM_TOKEN),
        ("KORU_TELEGRAM_CHAT_ID", "-1001234567890"),
        ("KORU_SMTP_HOST", "mail.example.test"),
        ("KORU_SMTP_PORT", "587"),
        ("KORU_SMTP_USER", "koru-user"),
        ("KORU_SMTP_PASSWORD", SMTP_PASSWORD),
        ("KORU_SMTP_FROM", "koru@example.test"),
        ("KORU_SMTP_TO", "alice@example.test"),
        ("KORU_HEARTBEAT_URL", "https://hc-ping.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
    ]
    .into_iter()
    .map(|(a, d)| (a.to_string(), d.to_string()))
    .collect()
}

fn read(o: &BTreeMap<String, String>) -> Result<ChannelSet, NotifyError> {
    ChannelSet::from_env(&|name| o.get(name).cloned())
}

fn settings_error(o: &BTreeMap<String, String>) -> String {
    match read(o) {
        Err(NotifyError::Settings(m)) => m,
        other => panic!("expected a settings error: {other:?}"),
    }
}

#[test]
fn all_channels_build_from_a_full_environment() {
    let t = read(&a_full_environment()).unwrap();
    let ntfy = t.ntfy.unwrap();
    assert_eq!(ntfy.url.host(), "ntfy.example.test");
    assert_eq!(ntfy.token.unwrap().reveal(), NTFY_TOKEN);
    let tg = t.telegram.unwrap();
    assert_eq!(tg.chat_id, "-1001234567890");
    assert_eq!(tg.bot_token.reveal(), TELEGRAM_TOKEN);
    let smtp = t.smtp.unwrap();
    assert_eq!((smtp.host.as_str(), smtp.port), ("mail.example.test", 587));
    assert_eq!(smtp.tls, SmtpTls::StartTls);
    assert_eq!((smtp.from_addr.as_str(), smtp.to_addr.as_str()), ("koru@example.test", "alice@example.test"));
    assert!(t.heartbeat.unwrap().is_tls());
}

#[test]
fn an_empty_environment_opens_no_channel() {
    let t = read(&BTreeMap::new()).unwrap();
    assert!(t.ntfy.is_none() && t.telegram.is_none() && t.smtp.is_none() && t.heartbeat.is_none());
}

#[test]
fn empty_values_are_ignored() {
    let mut o = a_full_environment();
    for d in o.values_mut() {
        d.clear();
    }
    let t = read(&o).unwrap();
    assert!(t.ntfy.is_none() && t.telegram.is_none() && t.smtp.is_none() && t.heartbeat.is_none());
}

#[test]
fn the_ntfy_token_is_optional() {
    let mut o = a_full_environment();
    o.remove("KORU_NTFY_TOKEN");
    assert!(read(&o).unwrap().ntfy.unwrap().token.is_none());
}

#[test]
fn a_partial_channel_config_errors_with_variable_names() {
    let mut o = a_full_environment();
    o.remove("KORU_TELEGRAM_CHAT_ID");
    let m = settings_error(&o);
    assert!(m.contains("KORU_TELEGRAM_CHAT_ID"), "{m}");
    assert!(!m.contains(TELEGRAM_TOKEN), "the value must not be printed: {m}");

    let mut o = a_full_environment();
    for a in ["KORU_SMTP_USER", "KORU_SMTP_PASSWORD"] {
        o.remove(a);
    }
    let m = settings_error(&o);
    assert!(m.contains("KORU_SMTP_USER") && m.contains("KORU_SMTP_PASSWORD"), "{m}");
    assert!(!m.contains(SMTP_PASSWORD));
}

#[test]
fn invalid_values_are_rejected_without_printing_them() {
    let attempts_count = [
        ("KORU_NTFY_URL", "http://ntfy.example.test/secret-topic-VERY-SECRET"),
        ("KORU_HEARTBEAT_URL", "http://hc-ping.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        ("KORU_SMTP_PORT", "abc"),
        ("KORU_SMTP_PORT", "0"),
        ("KORU_SMTP_PORT", "70000"),
        ("KORU_SMTP_FROM", "bad url VERY-SECRET"),
        ("KORU_TELEGRAM_BOT_TOKEN", "corrupt-token-VERY-SECRET"),
        ("KORU_TELEGRAM_CHAT_ID", "corrupt chat VERY-SECRET"),
    ];
    for (name, value) in attempts_count {
        let mut o = a_full_environment();
        o.insert(name.to_string(), value.to_string());
        let m = settings_error(&o);
        assert!(m.contains(name), "{name}: the variable name must be printed: {m}");
        assert!(!m.contains("VERY-SECRET") && !m.contains(value), "{name}: the value must not be printed: {m}");
    }
}

#[test]
fn debug_output_hides_the_secret() {
    let d = format!("{:?}", read(&a_full_environment()).unwrap());
    for forbidden in
        [TELEGRAM_TOKEN, "AAE_very-secret", NTFY_TOKEN, SMTP_PASSWORD, PING_UUID, "secret-topic", "hc-ping.com"]
    {
        assert!(!d.contains(forbidden), "Debug must not contain {forbidden:?}: {d}");
    }
}

#[test]
fn port_465_is_implicit_tls() {
    let mut o = a_full_environment();
    o.insert("KORU_SMTP_PORT".into(), "465".into());
    assert_eq!(read(&o).unwrap().smtp.unwrap().tls, SmtpTls::Implicit);
}

// --- .env ---

#[test]
fn dotenv_text_is_parsed() {
    let m = parse_dotenv(
        "# comment\n\nKORU_A=1\nexport KORU_B=two\nKORU_C=\"quoted value # not a comment\"\nKORU_D='single quotes'\n  KORU_E = spaced  \nKORU_F=a=b=c\nINVALID LINE\n=empty_key\nKORU_G=\r\nKORU_H=tail # not an end-of-line comment, the value\n",
    );
    assert_eq!(m["KORU_A"], "1");
    assert_eq!(m["KORU_B"], "two");
    assert_eq!(m["KORU_C"], "quoted value # not a comment");
    assert_eq!(m["KORU_D"], "single quotes");
    assert_eq!(m["KORU_E"], "spaced");
    assert_eq!(m["KORU_F"], "a=b=c");
    assert_eq!(m["KORU_G"], "");
    assert!(!m.contains_key("INVALID LINE") && !m.contains_key(""));
    assert_eq!(
        m["KORU_H"], "tail # not an end-of-line comment, the value",
        "no end-of-line comments: a secret value must not be truncated"
    );
    assert_eq!(m.len(), 8, "{m:?}");
}

#[test]
fn dotenv_parsing_does_not_touch_the_environment() {
    let _ = parse_dotenv("KORU_TEST_DOTENV_LEAK=1\n");
    assert!(std::env::var("KORU_TEST_DOTENV_LEAK").is_err());
}

fn write_dotenv(t: &tempfile::TempDir, content: &str, mode: u32) -> std::path::PathBuf {
    let path = canonicalized(t).join(".env");
    fs::write(&path, content).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn read_dotenv_reads_a_0600_file() {
    let t = is_transient();
    let path = write_dotenv(&t, "KORU_NTFY_URL=https://ntfy.example.test/k\n", 0o600);
    assert_eq!(read_dotenv(&path).unwrap()["KORU_NTFY_URL"], "https://ntfy.example.test/k");
}

#[test]
fn read_dotenv_rejects_a_wide_mode_and_errors_carry_no_content() {
    let t = is_transient();
    for mode in [0o644, 0o640, 0o604, 0o666] {
        let path = write_dotenv(&t, "KORU_X=VERY-SECRET-VALUE\n", mode);
        let error = read_dotenv(&path).expect_err("wide mode");
        assert!(!error.to_string().contains("VERY-SECRET-VALUE"));
    }
}

#[test]
fn read_dotenv_rejects_symlinks_big_files_and_directories() {
    let t = is_transient();
    let root = canonicalized(&t);
    let real = write_dotenv(&t, "KORU_X=1\n", 0o600);
    let link = root.join("link.env");
    symlink(&real, &link).unwrap();
    assert!(read_dotenv(&link).is_err());

    let big = root.join("big.env");
    fs::write(&big, "A=".to_string() + &"x".repeat(200 * 1024)).unwrap();
    fs::set_permissions(&big, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_dotenv(&big).is_err(), "over 64 KiB must be rejected");

    assert!(read_dotenv(&root).is_err(), "a directory is not readable");
    assert!(read_dotenv(&root.join("missing.env")).is_err());
}
