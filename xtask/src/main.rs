#![forbid(unsafe_code)]
//! `cargo xtask <task>` (alias: `.cargo/config.toml`).
//!
//! Tasks:
//! - `dependency-check [--rules <toml>] [--metadata <json>]`: checks the dependency matrix;
//!   the last line is "violations N". Exits 0 with no violation, 1 with violations, 2 on a tool
//!   error. `--metadata` reads a recorded output instead of `cargo metadata` (for tests and evidence).

use std::path::PathBuf;
use std::process::ExitCode;

use xtask::{CheckError, check, parse_metadata, parse_rules, read_metadata};

const USAGE: &str = "usage: cargo xtask dependency-check [--rules <toml>] [--metadata <json>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("dependency-check") => match dependency_check(&args[1..]) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::from(1),
            Err(e) => {
                eprintln!("ERROR: {e}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn dependency_check(args: &[String]) -> Result<usize, String> {
    // The workspace root is determined at run time: `cargo run` provides CARGO_MANIFEST_DIR in
    // the environment. The compile-time value is only a fallback (so a binary reused from a
    // cache does not check the repository in another copy).
    let manifest =
        std::env::var_os("CARGO_MANIFEST_DIR").map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from);
    let root = manifest.join("..");
    let mut rules_path = root.join("dependency-rules.toml");
    let mut metadata_path = None;
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).ok_or_else(|| USAGE.to_string())?;
        match args[i].as_str() {
            "--rules" => rules_path = PathBuf::from(value),
            "--metadata" => metadata_path = Some(PathBuf::from(value)),
            _ => return Err(USAGE.to_string()),
        }
        i += 2;
    }
    let rules_text =
        std::fs::read_to_string(&rules_path).map_err(|e| format!("could not read {}: {e}", rules_path.display()))?;
    let rules = parse_rules(&rules_text).map_err(|e| e.to_string())?;
    let metadata = match &metadata_path {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
            parse_metadata(&text)
        }
        None => read_metadata(&root),
    }
    .map_err(|e: CheckError| e.to_string())?;

    println!(
        "dependency check: {} workspace members, {} rules ({})",
        metadata.workspace_members.len(),
        rules.crates.len(),
        rules_path.file_name().map_or_else(|| rules_path.display().to_string(), |a| a.to_string_lossy().into_owned())
    );
    let violations = check(&metadata, &rules);
    for violation in &violations {
        println!("VIOLATION: {violation}");
    }
    println!("violations {}", violations.len());
    Ok(violations.len())
}
