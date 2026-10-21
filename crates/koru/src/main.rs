#![forbid(unsafe_code)]
//! # koru
//!
//! The Koru command-line tool. The layers (sensor, detection, decoy, store, notify) are composed only
//! here. The `decoy` commands come from koru-decoy (ADR-0004), the `rule` commands from koru-detect
//! (ADR-0005); `event ingest`, `report data-quality`, `export` and `store freeze` come from koru-store
//! (ADR-0006); `install_distribution`, `uninstall`, `upgrade` and `rollback` are described in ADR-0008;
//! `report threat` produces the Threat Report. The agent is a separate binary (`koru-agent`,
//! ADR-0003 §7).
//!
//! Exit codes: 0 success; 1 runtime error or finding (corrupt template, changed decoy, entry left
//! behind); 2 usage error. Root and state directories have no default: decoys are never
//! installed into a real home directory implicitly.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

use koru::config::{Config, DEFAULT_NAME, source_tag_from_str};
use koru::distribution::{self, EMBEDDED_PUBLIC_KEY, InstallOptions, LineContext, NoSystemd, RealSystemd, Systemd};
use koru::input::{InputLine, read_line, split_flags};
use koru_decoy::{
    DecoyKind, InstallSettings, IntegrityStatus, Placement, RecordEntry, RemovalStatus, install, integrity,
    list_entries, read_package, uninstall, validate_directory,
};
use koru_detect::{coverage, coverage_markdown, export_sigma, navigator_layer, read_rule_pack, validate_rule_dir};
use koru_event::{SourceTag, Timestamp, Untrusted};
use koru_store::{ExportFormat, ExportOptions, IngestOutcome, RejectReason, Store, StoreSettings};

const USAGE: &str = "Usage: koru <command>

Commands:
  version      Prints the version
  help     Prints this help

  decoy validate <dir|file>
             Validates decoy templates against the schema, the safety rules and trial
             generations.
  decoy plant --package <dir> --root <dir> --state <dir> [--allowed-root <dir>]... [--owner <uid>:<gid>]
             Plants decoys and breadcrumbs under the root (the target home directory);
             writes the integrity record and backups into the state directory.
  decoy list --state <dir>
             Lists the planted decoys and breadcrumbs.
  decoy integrity --state <dir>
             Compares the integrity record with what is on disk; exit code 1 if anything
             changed.
  decoy uninstall --state <dir>
             Removes the decoys; restores pre-existing files from backup byte for byte.
             A decoy changed after planting is not deleted; it is reported (exit code 1).

  rule validate <dir|file>
             Validates Sigma-compatible rule files (packages/rules/*.yml) against the
             schema, the field and modifier rules and the ATT&CK mapping; prints the count
             of rules without ATT&CK (must be 0). Exit code 1 if any rule is invalid.
  rule export [--format sigma] [--source <dir>] [--output <dir>]
             Exports the verified rule pack as Sigma YAML (default source packages/rules;
             without --output, multi-document YAML goes to stdout).
  rule coverage <dir> [--format markdown|navigator]
             Prints the ATT&CK coverage table (Markdown, default) or the ATT&CK Navigator
             layer (JSON) to stdout (docs/reports/).

  event ingest --store <path> [--input <file>]
             Validates JSONL event lines (file or stdin) against schema v1 and writes them
             to the store. Corrupt, untagged and duplicate events never enter the store;
             they are counted by reason.
  report data-quality --store <path>
             Prints the 'schema compliance 100% / duplicates 0 / untagged 0 / rejected N'
             line and the details. Exit code 1 if any stored record breaks the schema, or
             any duplicate or untagged record exists.
  report threat --source <jsonl>
             Prints a threat summary from a JSONL event file: total / with_detection
             events, and day, source, rule, threat class, ATT&CK technique, actor and
             target path distributions. An invalid line aborts the report (exit code 1).
  export --store <path> --format <jsonl|ocsf> [--mask] [--source <synthetic|legitimate|real>]
             [--output <file>]
             Writes events as JSONL (schema v1) or OCSF 1.9.0 (stdout by default; a file
             is created new with mode 0600). --mask masks IPv4 and IPv6 addresses (data
             protection). If the store holds several source tags, --source is required;
             a mixed export is rejected.
  store freeze --store <path> [--retention-days <N>]
             Deletes expired records (default 90 days), enforces the record limit and
             checkpoints the WAL.

  install --version-dir <dir> (--config <toml> | --source-tag <synthetic|legitimate|real> --decoy-root <dir>)
      [--name <name>] [--decoy-owner <uid>:<gid>] [--environment <env-file>] [--public-key <pem>]
      [--no-systemd] [--show-plan]
             Verifies the version package signature and SHA-256 digests, installs the
             agent, plants the decoys, writes the systemd unit and starts it. Nothing is
             installed from an unverifiable package. --name sets the process and service
             name (default system-observer); --show-plan only verifies and lists the paths
             that would be written.
  uninstall (--config <toml> | --name <name>) [--keep-data] [--no-systemd]
             Stops the service, rolls back the decoys and deletes everything the install
             created. A changed decoy is not deleted (exit code 1); the record stays.
  upgrade --version-dir <dir> (--config <toml> | --name <name>) [--public-key <pem>] [--no-systemd]
             Switches to a verified newer version; the previous version is kept for
             rollback. A failed health check rolls back automatically.
  rollback (--config <toml> | --name <name>) [--no-systemd]
             Goes back to the previous version (running it again moves forward).

Root, state and store paths have no defaults; they are always given explicitly and must be
absolute paths containing no symlinks. The state directory lives outside the root, in a
place that does not reveal Koru to an attacker (ADR-0004).

Exit codes: 0 success, 1 runtime error or finding, 2 usage error.";

/// A usage error (exit 2) or a runtime error (exit 1).
enum InputError {
    Usage(String),
    Runtime(String),
}

type CliResult = Result<ExitCode, InputError>;

fn usage_err(reason: impl Into<String>) -> InputError {
    InputError::Usage(reason.into())
}

fn runtime(reason: impl ToString) -> InputError {
    InputError::Runtime(reason.to_string())
}

/// Reads `--name value` style options (parsing lives in `koru::input`; the fuzz target uses it too).
fn options(
    args: &[String],
    allowed: &[&str],
    repeatable: &[&str],
) -> Result<BTreeMap<String, Vec<String>>, InputError> {
    koru::input::options(args, allowed, repeatable).map_err(|e| usage_err(e.0))
}

fn required_arg(s: &BTreeMap<String, Vec<String>>, name: &str) -> Result<PathBuf, InputError> {
    s.get(name).and_then(|d| d.first()).map(PathBuf::from).ok_or_else(|| usage_err(format!("{name} is required")))
}

fn kind_name(t: DecoyKind) -> &'static str {
    match t {
        DecoyKind::Decoy => "decoy",
        DecoyKind::Breadcrumb => "breadcrumb",
    }
}

fn placement_name(y: Placement) -> &'static str {
    match y {
        Placement::NewFile => "new file",
        Placement::Append => "append",
    }
}

fn input_line(g: &RecordEntry) -> String {
    format!("{}  {:<13} {:<20} {:<10} {}", g.id, kind_name(g.kind), g.class, placement_name(g.placement), g.path)
}

fn validate(args: &[String]) -> CliResult {
    let [path] = args else {
        return Err(usage_err("decoy validate takes a single directory or file"));
    };
    let report = validate_directory(&PathBuf::from(path));
    let mut passed_v = 0;
    for d in &report.files {
        let name =
            d.file.file_name().map_or_else(|| d.file.display().to_string(), |a| a.to_string_lossy().into_owned());
        match (&d.error, &d.id) {
            (None, Some(k)) => {
                passed_v += 1;
                println!("PASS    {name} ({k})");
            }
            (Some(h), _) => println!("FAIL     {name}: {h}"),
            (None, None) => println!("FAIL     {name}"),
        }
    }
    if let Some(h) = &report.package_error {
        println!("ERROR  package: {h}");
    }
    let failed_v = report.files.len() - passed_v;
    println!(
        "Result: {} templates, {passed_v} passed, {failed_v} failed{}",
        report.files.len(),
        if report.package_error.is_some() { "; there is a package-level error" } else { "" }
    );
    Ok(if report.succeeded() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn install_command(args: &[String]) -> CliResult {
    let s = options(args, &["--package", "--root", "--state", "--owner"], &["--allowed-root"])?;
    let package_dir = required_arg(&s, "--package")?;
    let mut settings = InstallSettings::new(required_arg(&s, "--root")?, required_arg(&s, "--state")?);
    for allowed in s.get("--allowed-root").into_iter().flatten() {
        settings = settings.allowed_root(PathBuf::from(allowed));
    }
    if let Some(owner) = s.get("--owner").and_then(|d| d.first()) {
        let (uid, gid) = owner
            .split_once(':')
            .and_then(|(u, g)| Some((u.parse::<u32>().ok()?, g.parse::<u32>().ok()?)))
            .ok_or_else(|| usage_err("--owner must be numeric, in <uid>:<gid> form"))?;
        settings = settings.owner(uid, gid);
    }
    let package = read_package(&package_dir).map_err(runtime)?;
    let report = install(&package, &settings).map_err(runtime)?;
    let crumb_v = report.entries.iter().filter(|g| g.kind == DecoyKind::Breadcrumb).count();
    println!(
        "Planting completed: {} entries ({} decoys, {crumb_v} breadcrumbs); install id {}",
        report.entries.len(),
        report.entries.len() - crumb_v,
        report.install_id
    );
    for g in &report.entries {
        println!("{}", input_line(g));
    }
    println!("Integrity record and backups: {}", settings.state_dir.display());
    Ok(ExitCode::SUCCESS)
}

fn state_option(args: &[String]) -> Result<PathBuf, InputError> {
    required_arg(&options(args, &["--state"], &[])?, "--state")
}

fn list_command(args: &[String]) -> CliResult {
    let entries = list_entries(&state_option(args)?).map_err(runtime)?;
    for g in &entries {
        println!("{}", input_line(g));
    }
    println!("Total: {} entries", entries.len());
    Ok(ExitCode::SUCCESS)
}

fn integrity_command(args: &[String]) -> CliResult {
    let report = integrity(&state_option(args)?).map_err(runtime)?;
    let (mut intact, mut changed_v, mut missing_v) = (0, 0, 0);
    for s in &report.results {
        match &s.state {
            IntegrityStatus::Intact => {
                intact += 1;
                println!("INTACT     {}", s.path);
            }
            IntegrityStatus::Changed { reasons } => {
                changed_v += 1;
                println!("CHANGED    {}: {}", s.path, reasons.join(", "));
            }
            IntegrityStatus::Missing => {
                missing_v += 1;
                println!("MISSING    {}", s.path);
            }
        }
    }
    println!("Result: {} entries, {intact} intact, {changed_v} changed, {missing_v} missing", report.results.len());
    Ok(if report.intact() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn remove_command(args: &[String]) -> CliResult {
    let report = uninstall(&state_option(args)?).map_err(runtime)?;
    for s in &report.results {
        match &s.state {
            RemovalStatus::Removed => println!("REMOVED        {}", s.path),
            RemovalStatus::Restored => println!("RESTORED       {}", s.path),
            RemovalStatus::AppendRemoved => println!("APPEND REMOVED {}", s.path),
            RemovalStatus::AlreadyAbsent => println!("ALREADY ABSENT {}", s.path),
            RemovalStatus::Left { reason } => println!("LEFT BEHIND    {}: {reason}", s.path),
        }
    }
    for u in &report.warnings {
        println!("Warning: {u}");
    }
    if report.completed() {
        println!("Result: uninstall completed");
        Ok(ExitCode::SUCCESS)
    } else {
        let remaining = report.results.iter().filter(|s| matches!(s.state, RemovalStatus::Left { .. })).count();
        println!(
            "Result: uninstall incomplete; {remaining} entries were left and stay in the record. Inspect them and re-run."
        );
        Ok(ExitCode::from(1))
    }
}

fn decoy(args: &[String]) -> CliResult {
    let Some((command, remaining)) = args.split_first() else {
        return Err(usage_err("decoy subcommand is missing"));
    };
    match command.as_str() {
        "validate" => validate(remaining),
        "plant" => install_command(remaining),
        "list" => list_command(remaining),
        "integrity" => integrity_command(remaining),
        "uninstall" => remove_command(remaining),
        other => Err(usage_err(format!("unknown decoy command: {other}"))),
    }
}

/// Strips control and direction characters from untrusted text (file names, rule messages) before
/// printing it to the terminal (KT-15).
fn sanitized(text: &str) -> String {
    Untrusted::new(text.to_string()).safe_display()
}

fn verify_rules(args: &[String]) -> CliResult {
    let [path] = args else {
        return Err(usage_err("rule validate takes a single directory or file"));
    };
    let report = validate_rule_dir(&PathBuf::from(path));
    let mut passed_v = 0;
    for d in &report.files {
        let name =
            d.file.file_name().map_or_else(|| d.file.display().to_string(), |a| a.to_string_lossy().into_owned());
        let name = sanitized(&name);
        match (&d.error, &d.name) {
            (None, Some(k)) => {
                passed_v += 1;
                println!("PASS    {name} ({k}; {})", d.techniques.join(", "));
            }
            (Some(h), _) => println!("FAIL     {name}: {}", sanitized(h)),
            (None, None) => println!("FAIL     {name}"),
        }
    }
    if let Some(h) = &report.package_error {
        println!("ERROR  package: {}", sanitized(h));
    }
    println!("Rules without ATT&CK: {}", report.without_attack_count());
    let failed_v = report.files.len() - passed_v;
    println!(
        "Result: {} rules, {passed_v} passed, {failed_v} failed{}",
        report.files.len(),
        if report.package_error.is_some() { "; there is a package-level error" } else { "" }
    );
    Ok(if report.succeeded() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn rule_coverage(args: &[String]) -> CliResult {
    let (dir, format) = match args {
        [dir] => (dir, "markdown"),
        [dir, option, format] if option == "--format" => (dir, format.as_str()),
        _ => return Err(usage_err("usage: rule coverage <dir> [--format markdown|navigator]")),
    };
    if !matches!(format, "markdown" | "navigator") {
        return Err(usage_err(format!("unknown format: {} (markdown or navigator)", sanitized(format))));
    }
    let package = read_rule_pack(&PathBuf::from(dir)).map_err(runtime)?;
    let k = coverage(&package);
    match format {
        "navigator" => print!("{}", navigator_layer(&k)),
        _ => print!("{}", coverage_markdown(&k)),
    }
    Ok(ExitCode::SUCCESS)
}

fn export_rules(args: &[String]) -> CliResult {
    let mut source = "packages/rules".to_string();
    let mut output: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                let format = args.get(i + 1).ok_or_else(|| usage_err("--format needs a value"))?;
                if format != "sigma" {
                    return Err(usage_err(format!("unknown format: {} (only sigma)", sanitized(format))));
                }
                i += 2;
            }
            "--source" => {
                source = args.get(i + 1).ok_or_else(|| usage_err("--source takes a directory"))?.clone();
                i += 2;
            }
            "--output" => {
                output = Some(args.get(i + 1).ok_or_else(|| usage_err("--output expects a directory"))?.clone());
                i += 2;
            }
            other => return Err(usage_err(format!("unknown option: {}", sanitized(other)))),
        }
    }
    // Default source: if not in the working directory, packages/rules is searched for in parent directories
    // (the command can run from the store root or a crate directory).
    let source_path = if args.iter().any(|a| a == "--source") {
        PathBuf::from(&source)
    } else {
        let mut candidate = Some(std::env::current_dir().map_err(runtime)?);
        let mut found = PathBuf::from(&source);
        while let Some(d) = candidate {
            let attempt = d.join(&source);
            if attempt.is_dir() {
                found = attempt;
                break;
            }
            candidate = d.parent().map(|u| u.to_path_buf());
        }
        found
    };
    let files = export_sigma(&source_path).map_err(runtime)?;
    match output {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            std::fs::create_dir_all(&dir).map_err(runtime)?;
            for (name, content) in &files {
                std::fs::write(dir.join(name), content).map_err(runtime)?;
            }
            println!("{} rules written to {}", files.len(), sanitized(&dir.display().to_string()));
        }
        None => {
            for (idx, (_, content)) in files.iter().enumerate() {
                if idx > 0 {
                    println!("---");
                }
                print!("{}", content);
                if !content.ends_with('\n') {
                    println!();
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn rule(args: &[String]) -> CliResult {
    let Some((command, remaining)) = args.split_first() else {
        return Err(usage_err("rule subcommand is missing"));
    };
    match command.as_str() {
        "validate" => verify_rules(remaining),
        "coverage" => rule_coverage(remaining),
        "export" => export_rules(remaining),
        other => Err(usage_err(format!("unknown rule command: {}", sanitized(other)))),
    }
}

// ---------------------------------------------------------------------------------------------
// koru-store commands (ADR-0006)
// ---------------------------------------------------------------------------------------------

fn open_store(store_path: PathBuf, must_exist: bool) -> Result<Store, InputError> {
    let mut settings_v = StoreSettings::new(store_path);
    if must_exist {
        settings_v = settings_v.must_exist();
    }
    Store::open(settings_v).map_err(runtime)
}

fn retention_day(s: &BTreeMap<String, Vec<String>>) -> Result<Option<u32>, InputError> {
    match s.get("--retention-days").and_then(|d| d.first()) {
        None => Ok(None),
        Some(g) => match g.parse::<u32>() {
            Ok(n) if n >= 1 => Ok(Some(n)),
            _ => Err(usage_err("--retention-days must be an integer of at least 1")),
        },
    }
}

fn ingest_events(args: &[String]) -> CliResult {
    let s = options(args, &["--store", "--input"], &[])?;
    let store_path = required_arg(&s, "--store")?;
    let mut store = open_store(store_path, false)?;
    let mut input: Box<dyn BufRead> = match s.get("--input").and_then(|d| d.first()) {
        Some(path) => Box::new(BufReader::new(
            std::fs::File::open(path).map_err(|e| runtime(format!("{} could not be opened: {e}", sanitized(path))))?,
        )),
        None => Box::new(BufReader::new(std::io::stdin())),
    };
    let (mut stored, mut duplicates, mut rejected) = (0u64, 0u64, 0u64);
    while let Some(line) = read_line(&mut input).map_err(|e| runtime(format!("the input could not be read: {e}")))? {
        let result = match line {
            InputLine::Text(m) if m.trim().is_empty() => continue,
            InputLine::Text(m) => store.store_json(&m).map_err(runtime)?,
            InputLine::Invalid => {
                store.count_rejected(RejectReason::JsonFormat, 1).map_err(runtime)?;
                IngestOutcome::Rejected(RejectReason::JsonFormat)
            }
            InputLine::TooLarge => {
                store.count_rejected(RejectReason::SizeLimit, 1).map_err(runtime)?;
                IngestOutcome::Rejected(RejectReason::SizeLimit)
            }
        };
        match result {
            IngestOutcome::Stored => stored += 1,
            IngestOutcome::Duplicate => duplicates += 1,
            IngestOutcome::Rejected(_) => rejected += 1,
        }
    }
    println!("Result: stored {stored} · duplicates {duplicates} · rejected {rejected}");
    Ok(ExitCode::SUCCESS)
}

fn event(args: &[String]) -> CliResult {
    match args.split_first() {
        Some((k, remaining)) if k == "ingest" => ingest_events(remaining),
        Some((k, _)) => Err(usage_err(format!("unknown event command: {}", sanitized(k)))),
        None => Err(usage_err("the event ingest command is missing")),
    }
}

fn report(args: &[String]) -> CliResult {
    let Some((command, remaining)) = args.split_first() else {
        return Err(usage_err("report subcommand is missing"));
    };
    match command.as_str() {
        "data-quality" => {
            let store_path = required_arg(&options(remaining, &["--store"], &[])?, "--store")?;
            let store = open_store(store_path, true)?;
            let r = store.quality_report().map_err(runtime)?;
            print!("{}", r.text());
            Ok(if r.is_clean() { ExitCode::SUCCESS } else { ExitCode::from(1) })
        }
        "threat" => {
            let source = required_arg(&options(remaining, &["--source"], &[])?, "--source")?;
            let file = std::fs::File::open(&source)
                .map_err(|e| runtime(format!("{} could not be opened: {e}", sanitized(&source.to_string_lossy()))))?;
            let report = koru_store::ThreatReport::read_jsonl(BufReader::new(file)).map_err(runtime)?;
            print!("{}", report.text());
            Ok(ExitCode::SUCCESS)
        }
        other => Err(usage_err(format!("unknown report command: {}", sanitized(other)))),
    }
}

fn export(args: &[String]) -> CliResult {
    let (mask, remaining) = split_flags(args, "--mask");
    let s = options(&remaining, &["--store", "--format", "--source", "--output"], &[])?;
    let store_path = required_arg(&s, "--store")?;
    let format = match s.get("--format").and_then(|d| d.first()).map(String::as_str) {
        Some("jsonl") => ExportFormat::Jsonl,
        Some("ocsf") => ExportFormat::Ocsf,
        Some(other) => return Err(usage_err(format!("unknown format: {} (jsonl or ocsf)", sanitized(other)))),
        None => return Err(usage_err("--format is required (jsonl or ocsf)")),
    };
    let source = match s.get("--source").and_then(|d| d.first()).map(String::as_str) {
        None => None,
        Some("synthetic") => Some(SourceTag::Synthetic),
        Some("legitimate") => Some(SourceTag::Legitimate),
        Some("real") => Some(SourceTag::Real),
        Some(other) => return Err(usage_err(format!("unknown source tag: {}", sanitized(other)))),
    };
    let mut option = ExportOptions::new(format);
    option.mask = mask;
    option.source = source;
    let store = open_store(store_path, true)?;
    let result = match s.get("--output").and_then(|d| d.first()) {
        Some(path) => {
            // A new file, 0600; an existing file or symlink is never overwritten (O_EXCL).
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| runtime(format!("{} could not be created: {e}", sanitized(path))))?;
            let mut writer = BufWriter::new(file);
            let r = store.export(&option, &mut writer).and_then(|s| {
                writer.flush().map_err(|e| koru_store::ExportError::Write(e.to_string()))?;
                Ok(s)
            });
            if r.is_err() {
                // We created the file; no half output is left behind.
                drop(writer);
                let _ = std::fs::remove_file(path);
            }
            r
        }
        None => {
            let output = std::io::stdout();
            let mut writer = BufWriter::new(output.lock());
            let r = store.export(&option, &mut writer);
            let _ = writer.flush();
            r
        }
    }
    .map_err(runtime)?;
    eprintln!("exported: {}", result.written);
    if result.skipped_corrupt > 0 {
        eprintln!(
            "warning: {} records not matching the schema were skipped (the store may have been tampered with)",
            result.skipped_corrupt
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn store_command(args: &[String]) -> CliResult {
    let Some((command, remaining)) = args.split_first() else {
        return Err(usage_err("store subcommand is missing"));
    };
    if command != "freeze" {
        return Err(usage_err(format!("unknown store command: {}", sanitized(command))));
    }
    let s = options(remaining, &["--store", "--retention-days"], &[])?;
    let store_path = required_arg(&s, "--store")?;
    let day = retention_day(&s)?;
    let mut settings_v = StoreSettings::new(store_path).must_exist();
    if let Some(g) = day {
        settings_v = settings_v.retention_days(g);
    }
    let mut store = Store::open(settings_v).map_err(runtime)?;
    let r = store.freeze(Timestamp::now()).map_err(runtime)?;
    println!("Rotation completed: expired {} · over limit {} · remaining {}", r.expired, r.over_limit, r.remaining);
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------------------------
// Lifecycle: install, uninstall, upgrade, rollback (ADR-0008)
// ---------------------------------------------------------------------------------------------

const HEALTH_ATTEMPTS: u32 = 5;

fn read_public_key(s: &BTreeMap<String, Vec<String>>) -> Result<String, InputError> {
    match s.get("--public-key").and_then(|d| d.first()) {
        None => Ok(EMBEDDED_PUBLIC_KEY.to_string()),
        Some(path) => {
            let m =
                std::fs::metadata(path).map_err(|e| runtime(format!("{} could not be read: {e}", sanitized(path))))?;
            if !m.is_file() || m.len() > 8192 {
                return Err(runtime(format!("{}: the public key must be a small file", sanitized(path))));
            }
            std::fs::read_to_string(path).map_err(|e| runtime(format!("{} could not be read: {e}", sanitized(path))))
        }
    }
}

/// Reads the installed config via `--config <toml>` or `--name <name>` (`/etc/<name>/config.toml`).
fn installed_config(s: &BTreeMap<String, Vec<String>>) -> Result<Config, InputError> {
    match (s.get("--config").and_then(|d| d.first()), s.get("--name").and_then(|d| d.first())) {
        (Some(_), Some(_)) => Err(usage_err("--config and --name cannot be given together")),
        (None, None) => Err(usage_err("--config or --name is required")),
        (Some(path), None) => Config::read(&PathBuf::from(path)).map_err(runtime),
        (None, Some(name)) => {
            if !koru::config::valid_service_name(name) {
                return Err(runtime(format!("invalid name: {}", sanitized(name))));
            }
            Config::read(&PathBuf::from(format!("/etc/{name}/config.toml"))).map_err(runtime)
        }
    }
}

fn lifecycle_context<'a>(
    systemd_ctl: &'a dyn Systemd,
    no_systemd: bool,
    s: &BTreeMap<String, Vec<String>>,
) -> Result<LineContext<'a>, InputError> {
    Ok(LineContext {
        systemd_ctl,
        public_key_pem: read_public_key(s)?,
        health_probe: if no_systemd { 1 } else { HEALTH_ATTEMPTS },
        health_wait: if no_systemd { std::time::Duration::ZERO } else { std::time::Duration::from_secs(1) },
    })
}

fn pick_systemd(no_systemd: bool) -> Box<dyn Systemd> {
    if no_systemd { Box::new(NoSystemd) } else { Box::new(RealSystemd) }
}

fn install_config(s: &BTreeMap<String, Vec<String>>) -> Result<Config, InputError> {
    let settings_v = s.get("--config").and_then(|d| d.first());
    let tag = s.get("--source-tag").and_then(|d| d.first());
    let root = s.get("--decoy-root").and_then(|d| d.first());
    match (settings_v, tag, root) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            Err(usage_err("--config cannot be combined with --source-tag/--decoy-root"))
        }
        (Some(_), None, None) if s.contains_key("--name") => {
            Err(usage_err("--config and --name cannot be given together"))
        }
        (Some(path), None, None) => Config::read(&PathBuf::from(path)).map_err(runtime),
        (None, Some(e), Some(k)) => {
            let tag = match e.as_str() {
                "synthetic" | "legitimate" | "real" => source_tag_from_str(e).map_err(runtime)?,
                other => return Err(usage_err(format!("unknown source tag: {}", sanitized(other)))),
            };
            let name = s.get("--name").and_then(|d| d.first()).map_or(DEFAULT_NAME, String::as_str);
            let mut y = Config::defaults(name, tag, &PathBuf::from(k)).map_err(runtime)?;
            if let Some(owner) = s.get("--decoy-owner").and_then(|d| d.first()) {
                let (u, g) = owner
                    .split_once(':')
                    .and_then(|(u, g)| Some((u.parse::<u32>().ok()?, g.parse::<u32>().ok()?)))
                    .ok_or_else(|| usage_err("--decoy-owner must be numeric, in <uid>:<gid> form"))?;
                y.decoy.owner = Some((u, g));
            }
            Ok(y)
        }
        _ => Err(usage_err("install needs --config or (--source-tag and --decoy-root)")),
    }
}

fn lifecycle_install_command(args: &[String]) -> CliResult {
    let (no_systemd, remaining) = split_flags(args, "--no-systemd");
    let (plan, remaining) = split_flags(&remaining, "--show-plan");
    let s = options(
        &remaining,
        &[
            "--version-dir",
            "--config",
            "--name",
            "--source-tag",
            "--decoy-root",
            "--decoy-owner",
            "--environment",
            "--public-key",
        ],
        &[],
    )?;
    let version_dir = required_arg(&s, "--version-dir")?;
    let y = install_config(&s)?;
    let systemd_ctl = pick_systemd(no_systemd);
    let self_context = lifecycle_context(systemd_ctl.as_ref(), no_systemd, &s)?;
    if plan {
        let package = distribution::read_package(&version_dir, &self_context.public_key_pem).map_err(runtime)?;
        println!(
            "Package verified (signature and SHA-256): version {}, {} files",
            package.version,
            package.paths().count()
        );
        println!("agent binary:  {}", y.version_dir(&package.version).join(&y.id.process_name).display());
        println!("data packages: {}", y.version_dir(&package.version).join("data").display());
        println!("active version:   {}", y.current_link().display());
        println!("config      :  {}", y.config_file().display());
        println!("environment file: {}", y.env_file().display());
        println!("unit:         {}", y.service_file().display());
        println!("state directory:  {}", y.directories.state.display());
        println!("decoy root    :    {}", y.decoy.root.display());
        println!("Nothing was written (--show-plan).");
        return Ok(ExitCode::SUCCESS);
    }
    let report = distribution::install_distribution(
        &self_context,
        &InstallOptions {
            version_dir,
            config: y.clone(),
            env_file: s.get("--environment").and_then(|d| d.first()).map(PathBuf::from),
        },
    )
    .map_err(runtime)?;
    println!("Install completed: version {}; service {}", report.version, y.id.service_name);
    println!("config: {}", y.config_file().display());
    Ok(ExitCode::SUCCESS)
}

fn lifecycle_remove_command(args: &[String]) -> CliResult {
    let (no_systemd, remaining) = split_flags(args, "--no-systemd");
    let (keep_data, remaining) = split_flags(&remaining, "--keep-data");
    let s = options(&remaining, &["--config", "--name"], &[])?;
    let y = installed_config(&s)?;
    let systemd_ctl = pick_systemd(no_systemd);
    let self_context = lifecycle_context(systemd_ctl.as_ref(), no_systemd, &BTreeMap::new())?;
    let r = distribution::uninstall(&self_context, &y, keep_data).map_err(runtime)?;
    for u in &r.warnings {
        println!("Warning: {}", sanitized(u));
    }
    if r.completed {
        println!("Uninstall completed");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("Uninstall incomplete: the entries left behind stay in the record. Inspect them and re-run.");
        Ok(ExitCode::from(1))
    }
}

fn upgrade_command(args: &[String]) -> CliResult {
    let (no_systemd, remaining) = split_flags(args, "--no-systemd");
    let s = options(&remaining, &["--version-dir", "--config", "--name", "--public-key"], &[])?;
    let version_dir = required_arg(&s, "--version-dir")?;
    let y = installed_config(&s)?;
    let systemd_ctl = pick_systemd(no_systemd);
    let self_context = lifecycle_context(systemd_ctl.as_ref(), no_systemd, &s)?;
    let r = distribution::upgrade(&self_context, &y, &version_dir).map_err(runtime)?;
    println!("Upgrade completed: {} -> {}", r.previous, r.new);
    Ok(ExitCode::SUCCESS)
}

fn downgrade_command(args: &[String]) -> CliResult {
    let (no_systemd, remaining) = split_flags(args, "--no-systemd");
    let s = options(&remaining, &["--config", "--name"], &[])?;
    let y = installed_config(&s)?;
    let systemd_ctl = pick_systemd(no_systemd);
    let self_context = lifecycle_context(systemd_ctl.as_ref(), no_systemd, &BTreeMap::new())?;
    let r = distribution::rollback(&self_context, &y).map_err(runtime)?;
    println!("Rollback completed: {} -> {}", r.previous, r.new);
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("version" | "--version") if args.len() == 1 => {
            println!("koru {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        None | Some("help" | "--help" | "-h") if args.len() <= 1 => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Some("decoy") => decoy(&args[1..]),
        Some("rule") => rule(&args[1..]),
        Some("event") => event(&args[1..]),
        Some("report") => report(&args[1..]),
        Some("export") => export(&args[1..]),
        Some("store") => store_command(&args[1..]),
        Some("install") => lifecycle_install_command(&args[1..]),
        Some("uninstall") => lifecycle_remove_command(&args[1..]),
        Some("upgrade") => upgrade_command(&args[1..]),
        Some("rollback") => downgrade_command(&args[1..]),
        _ => Err(usage_err("unknown command")),
    };
    match result {
        Ok(code) => code,
        Err(InputError::Usage(reason)) => {
            eprintln!("koru: {reason}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(InputError::Runtime(reason)) => {
            eprintln!("koru: error: {reason}");
            ExitCode::from(1)
        }
    }
}
