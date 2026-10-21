//! Self-protection: Koru's protected paths and names.
//!
//! Changes to Koru's config, store, state directory, decoy files, binary, and service unit,
//! and stop attempts (`systemctl stop|disable|mask`, `kill`, `pkill`, `killall`), are threat
//! events. Path comparisons run on lexically normalized paths at directory boundaries
//! (`/etc/koru-backup` does not count as under `/etc/koru`).
//!
//! Boundary: `kill -9` kills Koru with no event; the external heartbeat catches that.
//! A shell's builtin `kill` starts no separate process, so it produces no exec event; only
//! `/usr/bin/kill` is seen.

use crate::KoruIdentity;
use crate::file::sanitize;
use crate::normalize_path;
use crate::pattern::Pattern;
use crate::shell::Shell;

/// Koru's protected paths and service/process names. Paths must be absolute; a directory
/// protects everything under it. These come from one config file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelfProtection {
    /// Config files or directories (`koru.protected_kind: config`).
    pub config: Vec<String>,
    /// Secret value files, e.g. `.env` (`secret`); reading one is also a finding.
    pub secret: Vec<String>,
    /// Event store (`store`).
    pub store: Vec<String>,
    /// The StateDir directory: the integrity record and backups (`state`).
    pub state: Vec<String>,
    /// Koru binaries (`binary`).
    pub binaries: Vec<String>,
    /// systemd unit files and drop-in directories (`service`).
    pub service_files: Vec<String>,
    /// Service names (systemctl/service targets).
    pub service_names: Vec<String>,
    /// Process names (pkill/killall targets).
    pub process_names: Vec<String>,
}

/// Validated and normalized protected paths.
#[derive(Debug, Clone)]
pub(crate) struct ProtectedPaths {
    /// `(kind, normalized path)`; kinds: config, secret, store, state, binary, service.
    paths: Vec<(&'static str, String)>,
    binaries: Vec<String>,
    service_names: Vec<String>,
    process_names: Vec<String>,
}

/// Priority at an equal-length match: the most specific kind first.
const KIND_ORDER: [&str; 6] = ["secret", "binary", "service", "store", "state", "config"];

/// Whether `root` is `path` itself or (at a directory boundary) its parent.
fn is_under(path: &str, root: &str) -> bool {
    root == "/" || path == root || (path.starts_with(root) && path.as_bytes().get(root.len()) == Some(&b'/'))
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

impl SelfProtection {
    /// Normalizes paths and validates the settings.
    pub(crate) fn prepare(&self) -> Result<ProtectedPaths, String> {
        let mut paths = Vec::new();
        let groups: [(&'static str, &Vec<String>); 6] = [
            ("config", &self.config),
            ("secret", &self.secret),
            ("store", &self.store),
            ("state", &self.state),
            ("binary", &self.binaries),
            ("service", &self.service_files),
        ];
        for (kind, string_list) in groups {
            for y in string_list {
                match normalize_path(y) {
                    Some(n) if n != "/" => paths.push((kind, n)),
                    _ => {
                        return Err(format!(
                            "{kind}: a protected path must be absolute and below the root: {}",
                            sanitize(y)
                        ));
                    }
                }
            }
        }
        let binary = self.binaries.iter().filter_map(|y| normalize_path(y)).collect();
        for (name, string_list) in [("service_names", &self.service_names), ("process_names", &self.process_names)] {
            if let Some(k) =
                string_list.iter().find(|a| a.is_empty() || a.chars().any(|c| c.is_whitespace() || c == '/'))
            {
                return Err(format!("{name} cannot be empty and cannot hold a space or /: {}", sanitize(k)));
            }
        }
        Ok(ProtectedPaths {
            paths,
            binaries: binary,
            service_names: self.service_names.clone(),
            process_names: self.process_names.clone(),
        })
    }
}

impl ProtectedPaths {
    /// If the (normalized) path is under a protected path, the most specific match's kind.
    pub(crate) fn kind(&self, path: &str) -> Option<&'static str> {
        self.paths
            .iter()
            .filter(|(_, root)| is_under(path, root))
            .max_by_key(|(kind, root)| {
                (root.len(), KIND_ORDER.len() - KIND_ORDER.iter().position(|t| t == kind).unwrap_or(KIND_ORDER.len()))
            })
            .map(|(kind, _)| *kind)
    }

    /// Whether a process tries to stop Koru: `service` (systemctl, service, init script) or
    /// `process` (kill, pkill, killall).
    pub(crate) fn stopping(&self, exe: &str, command: &[String], koru: Option<&KoruIdentity>) -> Option<&'static str> {
        let (program, args) = program_and_arg(exe, command);
        if program.is_empty() {
            // /etc/init.d/<service> stop
            let script_name = base_name(exe);
            if exe.starts_with("/etc/init.d/") && self.service_names.iter().any(|s| s == script_name) {
                return stop_action(command.get(1).map(String::as_str)).then_some("service");
            }
            // sh /etc/init.d/<service> stop: a shell runs the init script as interpreter.
            if SHELLS.contains(&base_name(exe)) {
                let positional: Vec<&String> = command.iter().skip(1).filter(|a| !a.starts_with('-')).collect();
                if let Some((script, remaining)) = positional.split_first()
                    && (script.starts_with("/etc/init.d/") || script.starts_with("/etc/rc.d/init.d/"))
                    && self.service_names.iter().any(|s| s == base_name(script))
                {
                    return stop_action(remaining.first().map(|e| e.as_str())).then_some("service");
                }
            }
            return None;
        }
        match program {
            "systemctl" => self.systemctl(&args).then_some("service"),
            "service" | "invoke-rc.d" | "rc-service" => self.service(&args).then_some("service"),
            "kill" => kill_targets_koru(&args, koru).then_some("process"),
            "pkill" => self.pkill(&args, koru).then_some("process"),
            "killall" => self.killall(&args, koru).then_some("process"),
            _ => None,
        }
    }

    /// Whether a unit name is one of Koru's services (`koru`, `koru.service`, `kor*`,
    /// `kor[u]`). systemd globs match the full unit name (`koru.service`) by fnmatch rules
    /// (bracket classes included).
    fn is_koru_unit(&self, unit: &str) -> bool {
        if Shell::is_special(unit) {
            let pattern = Shell::compile_pattern(unit);
            self.service_names
                .iter()
                .any(|s| pattern.matches_pattern(s) || pattern.matches_pattern(&format!("{s}.service")))
        } else {
            let name = unit.strip_suffix(".service").unwrap_or(unit);
            self.service_names.iter().any(|s| s == name)
        }
    }

    fn systemctl(&self, args: &[String]) -> bool {
        let positional = positional_args(args, &["-H", "-M", "-t", "-p", "-s", "-n", "-o"], SYSTEMCTL_LONG);
        let Some((action, units)) = positional.split_first() else {
            return false;
        };
        matches!(action.as_str(), "stop" | "kill" | "disable" | "mask" | "restart" | "try-restart")
            && units.iter().any(|b| self.is_koru_unit(b))
    }

    fn service(&self, args: &[String]) -> bool {
        let positional = positional_args(args, &[], &[]);
        match positional.as_slice() {
            [name, action, ..] => self.is_koru_unit(name) && stop_action(Some(action)),
            _ => false,
        }
    }

    /// Whether one of Koru's names matches the (crude regex) pattern.
    fn name_matches_pattern(&self, pattern: &str, full_command: bool, koru: Option<&KoruIdentity>) -> bool {
        let mut candidates: Vec<String> = self.process_names.clone();
        if let Some(k) = koru {
            candidates.push(base_name(&k.exe).to_string());
            if full_command {
                candidates.push(k.command_line.join(" "));
                candidates.push(k.exe.clone());
            }
        }
        candidates.iter().any(|a| matches_coarse_regex(pattern, a))
    }

    fn pkill(&self, args: &[String], koru: Option<&KoruIdentity>) -> bool {
        let full_command = has_option(args, 'f', "full", PKILL_LONG);
        let exact_name = has_option(args, 'x', "exact", PKILL_LONG);
        let positional = positional_args(args, &["-u", "-U", "-g", "-G", "-P", "-s", "-t"], PKILL_LONG);
        let Some(pattern) = positional.first() else {
            return false;
        };
        if exact_name {
            self.process_names.iter().any(|a| a == pattern) || koru.is_some_and(|k| base_name(&k.exe) == pattern)
        } else {
            self.name_matches_pattern(pattern, full_command, koru)
        }
    }

    fn killall(&self, args: &[String], koru: Option<&KoruIdentity>) -> bool {
        let regex = has_option(args, 'r', "regexp", KILLALL_LONG);
        let positional = positional_args(args, &["-s", "-u", "-o", "-y", "-Z"], KILLALL_LONG);
        positional.iter().any(|name| {
            if regex {
                return self.name_matches_pattern(name, false, koru);
            }
            if name.contains('/') {
                // A path was given: the running binary's path.
                let normal = normalize_path(name);
                let is_binary = normal.as_deref().is_some_and(|n| {
                    self.binaries.iter().any(|i| i == n)
                        || koru.is_some_and(|k| normalize_path(&k.exe).as_deref() == Some(n))
                });
                return is_binary || self.process_names.iter().any(|s| s == base_name(name));
            }
            self.process_names.iter().any(|s| s == name) || koru.is_some_and(|k| base_name(&k.exe) == name)
        })
    }
}

/// The program's name and arguments: `busybox kill ...` shows the applet,
/// `sh /usr/sbin/service ...` the script. `exe` is the normalized path; that is the real
/// identity, `argv[0]` serves only as the applet name for busybox and toybox.
fn program_and_arg(exe: &str, command: &[String]) -> (&'static str, Vec<String>) {
    const KNOWN: [&str; 7] = ["systemctl", "service", "invoke-rc.d", "rc-service", "kill", "pkill", "killall"];
    let base = base_name(exe);
    let find = |name: &str| KNOWN.iter().copied().find(|b| *b == name);
    if let Some(p) = find(base) {
        return (p, command.iter().skip(1).cloned().collect());
    }
    if matches!(base, "busybox" | "toybox")
        && let Some(p) = command.first().and_then(|a| find(base_name(a)))
    {
        return (p, command.iter().skip(1).cloned().collect());
    }
    if SHELLS.contains(&base)
        && let Some(p) = command.get(1).and_then(|a| find(base_name(a)))
    {
        return (p, command.iter().skip(2).cloned().collect());
    }
    ("", Vec::new())
}

/// The long-option table: `(name, takes a value)`. Because getopt_long accepts every
/// unambiguous prefix abbreviation (`--sig` = `--signal`), options resolve by prefix too;
/// otherwise an abbreviated option's value would be read as a positional argument and the
/// command's real target would slip away.
type LongOptions = &'static [(&'static str, bool)];

const SHELLS: [&str; 6] = ["sh", "bash", "dash", "ash", "zsh", "ksh"];

const SYSTEMCTL_LONG: LongOptions = &[
    ("type", true),
    ("state", true),
    ("job-mode", true),
    ("property", true),
    ("signal", true),
    ("kill-whom", true),
    ("kill-who", true),
    ("kill-value", true),
    ("host", true),
    ("machine", true),
    ("root", true),
    ("image", true),
    ("image-policy", true),
    ("output", true),
    ("lines", true),
    ("timestamp", true),
    ("what", true),
    ("check-inhibitors", true),
    ("message", true),
    ("when", true),
    ("boot-loader-entry", true),
    ("boot-loader-menu", true),
    ("reboot-argument", true),
    ("preset-mode", true),
    ("marked", true),
    ("all", false),
    ("after", false),
    ("before", false),
    ("dry-run", false),
    ("failed", false),
    ("fail", false),
    ("firmware-setup", false),
    ("force", false),
    ("full", false),
    ("global", false),
    ("help", false),
    ("ignore-dependencies", false),
    ("ignore-inhibitors", false),
    ("jobs", false),
    ("no-ask-password", false),
    ("no-block", false),
    ("no-legend", false),
    ("no-pager", false),
    ("no-reload", false),
    ("no-warn", false),
    ("no-wall", false),
    ("now", false),
    ("plain", false),
    ("quiet", false),
    ("recursive", false),
    ("reverse", false),
    ("runtime", false),
    ("show-transaction", false),
    ("show-types", false),
    ("system", false),
    ("user", false),
    ("value", false),
    ("version", false),
    ("wait", false),
    ("with-dependencies", false),
];

const PKILL_LONG: LongOptions = &[
    ("signal", true),
    ("delimiter", true),
    ("older", true),
    ("parent", true),
    ("pgroup", true),
    ("pidfile", true),
    ("session", true),
    ("terminal", true),
    ("uid", true),
    ("euid", true),
    ("group", true),
    ("runstates", true),
    ("cgroup", true),
    ("ns", true),
    ("nslist", true),
    ("queue", true),
    ("count", false),
    ("echo", false),
    ("exact", false),
    ("full", false),
    ("help", false),
    ("ignore-case", false),
    ("inverse", false),
    ("lightweight", false),
    ("list-full", false),
    ("list-name", false),
    ("newest", false),
    ("oldest", false),
    ("require-handler", false),
    ("version", false),
];

const KILLALL_LONG: LongOptions = &[
    ("signal", true),
    ("user", true),
    ("context", true),
    ("older-than", true),
    ("younger-than", true),
    ("ns", true),
    ("cgroup", true),
    ("exact", false),
    ("ignore-case", false),
    ("process-group", false),
    ("interactive", false),
    ("list", false),
    ("quiet", false),
    ("regexp", false),
    ("verbose", false),
    ("wait", false),
    ("require-glob", false),
    ("inverse", false),
    ("help", false),
    ("version", false),
];

/// Resolves a long-option name (no `--`, no `=`) in the table: an exact match or an
/// unambiguous prefix. An ambiguous prefix errors in getopt_long and the command does not
/// run; `None`.
fn resolve_long(table: LongOptions, name: &str) -> Option<(&'static str, bool)> {
    if name.is_empty() {
        return None;
    }
    if let Some(t) = table.iter().find(|(a, _)| *a == name) {
        return Some(*t);
    }
    let mut candidates = table.iter().filter(|(a, _)| a.starts_with(name));
    let first = candidates.next()?;
    // If several candidates share the value behaviour (e.g. kill-who/kill-whom), it is known.
    candidates.all(|t| t.1 == first.1).then_some(*first)
}

/// Whether a flag appears on a command line in short (`-f`, inside a `-fx` bundle) or long
/// (`--full`, prefix abbreviations included) form.
fn has_option(args: &[String], short: char, long_name: &str, table: LongOptions) -> bool {
    let mut double_dash = false;
    args.iter().any(|a| {
        if double_dash {
            return false;
        }
        if a == "--" {
            double_dash = true;
            return false;
        }
        if let Some(body) = a.strip_prefix("--") {
            let name = body.split('=').next().unwrap_or("");
            return resolve_long(table, name).is_some_and(|(full, _)| full == long_name);
        }
        a.starts_with('-') && a.len() > 1 && a[1..].contains(short)
    })
}

/// Skips options; also skips the separate-argument values of short options in
/// `short_with_value` and of value-taking long options in the table (prefix abbreviations
/// included). Everything after `--` is positional.
fn positional_args(args: &[String], short_with_value: &[&str], long_name: LongOptions) -> Vec<String> {
    let mut positional = Vec::new();
    let mut i = 0;
    let mut double_dash = false;
    while i < args.len() {
        let a = args[i].as_str();
        if double_dash {
            positional.push(a.to_string());
        } else if a == "--" {
            double_dash = true;
        } else if let Some(body) = a.strip_prefix("--") {
            // `--name=value`: the value is in the same argument; `--name value`: the next one.
            if !body.contains('=') && resolve_long(long_name, body).is_some_and(|(_, takes_value)| takes_value) {
                i += 1;
            }
        } else if a.starts_with('-') && a.len() > 1 {
            if short_with_value.contains(&a) {
                i += 1;
            }
        } else {
            positional.push(a.to_string());
        }
        i += 1;
    }
    positional
}

fn stop_action(action: Option<&str>) -> bool {
    matches!(action, Some("stop" | "restart" | "try-restart" | "force-stop" | "kill"))
}

/// `kill [-signal] pid...`: whether a pid is Koru's. `-l`, `-L` only list signals.
fn kill_targets_koru(args: &[String], koru: Option<&KoruIdentity>) -> bool {
    let Some(koru) = koru else {
        return false;
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-l" | "-L" | "--list" | "--table" => return false,
            "-s" | "-n" | "-q" | "--signal" | "--queue" => i += 1,
            _ if a.starts_with('-') && a.len() > 1 => {}
            _ => {
                if a.parse::<u32>().is_ok_and(|p| p == koru.pid) {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// A crude regex matcher for pkill/killall patterns: `|`-separated alternatives, `^` and `$`
/// anchors, `.` and `.*` wildcards. Complex constructs (`[]`, `()`, `{}`, `+`, `\`) cannot
/// be resolved and count as targeting Koru (the safe direction for self-protection).
fn matches_coarse_regex(pattern: &str, name: &str) -> bool {
    pattern.split('|').any(|child| {
        if child.contains(['[', ']', '(', ')', '{', '}', '+', '\\']) {
            return true;
        }
        let leading = child.starts_with('^');
        let trailing = child.ends_with('$');
        let body = child.strip_prefix('^').unwrap_or(child);
        let body = body.strip_suffix('$').unwrap_or(body);
        let wildcard = body.replace(".*", "*").replace('.', "?");
        let full = format!("{}{wildcard}{}", if leading { "" } else { "*" }, if trailing { "" } else { "*" });
        Pattern::simple_token(&full, true).matches_pattern(name)
    })
}
