//! Channel settings from environment variables and a `.env` file. Error messages contain only
//! variable names; values are never printed anywhere.

use std::collections::BTreeMap;
use std::path::Path;

use crate::safe_file;
use crate::smtp::{is_address_text_valid, is_credential_valid, is_host_text_valid};
use crate::telegram::{is_chat_id_valid, is_token_valid};
use crate::{HttpsAddress, NotifyError, NtfySettings, Secret, SmtpSettings, TelegramSettings};

/// The largest `.env` file size (bytes).
const MAX_DOTENV_BYTES: u64 = 64 * 1024;

/// The channels configured in the environment. When none of a channel's variables exist the
/// channel is off (`None`); when only some exist it is a settings error.
#[derive(Debug, Clone)]
pub struct ChannelSet {
    /// `KORU_NTFY_URL` (+ optional `KORU_NTFY_TOKEN`).
    pub ntfy: Option<NtfySettings>,
    /// `KORU_TELEGRAM_BOT_TOKEN` and `KORU_TELEGRAM_CHAT_ID`.
    pub telegram: Option<TelegramSettings>,
    /// `KORU_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_TO`.
    pub smtp: Option<SmtpSettings>,
    /// `KORU_HEARTBEAT_URL`.
    pub heartbeat: Option<HttpsAddress>,
    /// `KORU_NOTIFY_MASK_IP` (`true`/`false`, `1`/`0`, `yes`/`no`): IP masking in notifications
    /// masking. Default: on.
    pub mask_ip: bool,
}

impl Default for ChannelSet {
    fn default() -> ChannelSet {
        ChannelSet { ntfy: None, telegram: None, smtp: None, heartbeat: None, mask_ip: true }
    }
}

/// Collects the variables read and the problems found. Problems name only variables.
struct Reader<'a> {
    read: &'a dyn Fn(&str) -> Option<String>,
    missing: Vec<&'static str>,
    invalid: Vec<&'static str>,
}

impl Reader<'_> {
    /// An empty value is ignored; leading and trailing whitespace is trimmed.
    fn get(&self, name: &str) -> Option<String> {
        (self.read)(name).map(|d| d.trim().to_string()).filter(|d| !d.is_empty())
    }

    /// `None` when none of a channel's variables exist; records the missing ones otherwise.
    fn one_group(
        &mut self,
        names: &[&'static str],
        required_arg: &[&'static str],
    ) -> Option<BTreeMap<&'static str, String>> {
        let values: BTreeMap<&'static str, String> =
            names.iter().filter_map(|a| self.get(a).map(|d| (*a, d))).collect();
        if values.is_empty() {
            return None;
        }
        let mut completed = true;
        for z in required_arg {
            if !values.contains_key(z) {
                self.missing.push(z);
                completed = false;
            }
        }
        completed.then_some(values)
    }
}

impl ChannelSet {
    /// `read`: variable name to value. An empty value is ignored.
    pub fn from_env(read: &dyn Fn(&str) -> Option<String>) -> Result<ChannelSet, NotifyError> {
        let mut o = Reader { read, missing: Vec::new(), invalid: Vec::new() };
        let mut set = ChannelSet::default();

        if let Some(d) = o.one_group(&["KORU_NTFY_URL", "KORU_NTFY_TOKEN"], &["KORU_NTFY_URL"]) {
            match HttpsAddress::parse_parts(&d["KORU_NTFY_URL"]) {
                Ok(url) => {
                    let mut a = NtfySettings::new(url);
                    a.token = d.get("KORU_NTFY_TOKEN").map(|t| Secret::new(t.as_str()));
                    set.ntfy = Some(a);
                }
                Err(_) => o.invalid.push("KORU_NTFY_URL"),
            }
        }

        let tg = ["KORU_TELEGRAM_BOT_TOKEN", "KORU_TELEGRAM_CHAT_ID"];
        if let Some(d) = o.one_group(&tg, &tg) {
            let (token, chat) = (&d["KORU_TELEGRAM_BOT_TOKEN"], &d["KORU_TELEGRAM_CHAT_ID"]);
            if !is_token_valid(token) {
                o.invalid.push("KORU_TELEGRAM_BOT_TOKEN");
            }
            if !is_chat_id_valid(chat) {
                o.invalid.push("KORU_TELEGRAM_CHAT_ID");
            }
            if is_token_valid(token) && is_chat_id_valid(chat) {
                set.telegram = TelegramSettings::new(Secret::new(token.as_str()), chat.as_str()).ok();
            }
        }

        let smtp = [
            "KORU_SMTP_HOST",
            "KORU_SMTP_PORT",
            "KORU_SMTP_USER",
            "KORU_SMTP_PASSWORD",
            "KORU_SMTP_FROM",
            "KORU_SMTP_TO",
        ];
        if let Some(d) = o.one_group(&smtp, &smtp) {
            let port = d["KORU_SMTP_PORT"].parse::<u16>().ok().filter(|p| *p != 0);
            let checks = [
                ("KORU_SMTP_HOST", is_host_text_valid(&d["KORU_SMTP_HOST"])),
                ("KORU_SMTP_PORT", port.is_some()),
                ("KORU_SMTP_USER", is_credential_valid(&d["KORU_SMTP_USER"])),
                ("KORU_SMTP_PASSWORD", is_credential_valid(&d["KORU_SMTP_PASSWORD"])),
                ("KORU_SMTP_FROM", is_address_text_valid(&d["KORU_SMTP_FROM"])),
                ("KORU_SMTP_TO", is_address_text_valid(&d["KORU_SMTP_TO"])),
            ];
            let invalid_names: Vec<&'static str> = checks.iter().filter(|(_, ok)| !ok).map(|(a, _)| *a).collect();
            if invalid_names.is_empty() {
                set.smtp = port.and_then(|port| {
                    SmtpSettings::new(
                        &d["KORU_SMTP_HOST"],
                        port,
                        &d["KORU_SMTP_USER"],
                        Secret::new(d["KORU_SMTP_PASSWORD"].as_str()),
                        &d["KORU_SMTP_FROM"],
                        &d["KORU_SMTP_TO"],
                    )
                    .ok()
                });
            } else {
                o.invalid.extend(invalid_names);
            }
        }

        if let Some(d) = o.one_group(&["KORU_HEARTBEAT_URL"], &["KORU_HEARTBEAT_URL"]) {
            match HttpsAddress::parse_parts(&d["KORU_HEARTBEAT_URL"]) {
                Ok(url) => set.heartbeat = Some(url),
                Err(_) => o.invalid.push("KORU_HEARTBEAT_URL"),
            }
        }

        if let Some(value) = o.get("KORU_NOTIFY_MASK_IP") {
            match value.to_lowercase().as_str() {
                "true" | "1" | "yes" => set.mask_ip = true,
                "false" | "0" | "no" => set.mask_ip = false,
                _ => o.invalid.push("KORU_NOTIFY_MASK_IP"),
            }
        }

        if o.missing.is_empty() && o.invalid.is_empty() {
            return Ok(set);
        }
        let mut parts = Vec::new();
        if !o.missing.is_empty() {
            parts.push(format!("missing variables: {}", o.missing.join(", ")));
        }
        if !o.invalid.is_empty() {
            parts.push(format!("invalid variables: {}", o.invalid.join(", ")));
        }
        Err(NotifyError::Settings(parts.join("; ")))
    }
}

/// Parses `.env` content: `KEY=value` lines, `#` comment lines, an `export ` prefix, single
/// and double quotes. There is no end-of-line comment (`value # x` keeps the tail, so a secret
/// value is never truncated by accident). Malformed lines are skipped. Nothing is exported.
pub fn parse_dotenv(content: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in content.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        let key_valid = !key.is_empty()
            && !key.starts_with(|c: char| c.is_ascii_digit())
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !key_valid {
            continue;
        }
        let value = value.trim();
        let quoted = value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"')) || (value.starts_with('\'') && value.ends_with('\'')));
        let value = if quoted { &value[1..value.len() - 1] } else { value };
        map.insert(key.to_string(), value.to_string());
    }
    map
}

/// Reads and parses a `.env` file. Symlinks are not followed; it must be a regular file owned
/// by the user running Koru and closed to the group and others (0600); at most 64 KiB. Error
/// messages never contain the file's content.
pub fn read_dotenv(path: &Path) -> Result<BTreeMap<String, String>, NotifyError> {
    let bytes = safe_file::read_from_path(path, MAX_DOTENV_BYTES)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| NotifyError::Settings(format!("{}: file is not UTF-8", path.display())))?;
    Ok(parse_dotenv(&text))
}
