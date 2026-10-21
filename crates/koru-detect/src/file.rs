//! Bounded, safe-read helpers for data files (rules, signatures, thresholds, allowlists).

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// A plain-language description of an I/O error.
pub(crate) fn io_reason(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "not found".to_string(),
        io::ErrorKind::PermissionDenied => "no read permission".to_string(),
        io::ErrorKind::InvalidData => "not valid UTF-8 text".to_string(),
        _ => format!("could not be read ({e})"),
    }
}

/// Reads a regular file as text. Symbolic links and special files (devices, pipes) are not
/// read; a file larger than `max` bytes is not read. The error is a reason without the path.
pub(crate) fn read_regular_file(path: &Path, max: u64) -> Result<String, String> {
    let m = fs::symlink_metadata(path).map_err(|e| io_reason(&e))?;
    if !m.file_type().is_file() {
        return Err("not a regular file (symbolic links and special files are not read)".to_string());
    }
    if m.len() > max {
        return Err(format!("file too large (at most {max} bytes)"));
    }
    let mut text = String::new();
    File::open(path).and_then(|f| f.take(max + 1).read_to_string(&mut text)).map_err(|e| io_reason(&e))?;
    if text.len() as u64 > max {
        return Err(format!("file too large (at most {max} bytes)"));
    }
    Ok(text)
}

/// Entries of a directory (sorted by name): `(file name, path)`. Returns a reason if unreadable.
pub(crate) fn directory_entries(directory: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut entries = Vec::new();
    for g in fs::read_dir(directory).map_err(|e| io_reason(&e))? {
        let g = g.map_err(|e| io_reason(&e))?;
        entries.push((g.file_name().to_string_lossy().into_owned(), g.path()));
    }
    entries.sort();
    Ok(entries)
}

/// Shortens untrusted text entering an error message and neutralizes control and direction
/// override characters (KT-15).
pub(crate) fn sanitize(text: &str) -> String {
    let short: String = text.chars().take(64).collect();
    let ellipsis = if text.chars().nth(64).is_some() { "…" } else { "" };
    format!("{}{ellipsis}", koru_event::Untrusted::new(short).safe_display())
}

/// Re-renders a serde (JSON or TOML) error message uniformly; field names are written with
/// safe display (KT-15). An unrecognized message is passed through as is (shortened, safe).
pub(crate) fn serde_message(raw: &str) -> String {
    let inside = |prefix: &str| -> Option<String> {
        let remaining = raw.strip_prefix(prefix)?;
        let end = remaining.find('`')?;
        Some(sanitize(&remaining[..end]))
    };
    if let Some(a) = inside("unknown field `") {
        format!("unknown field: {a}")
    } else if let Some(a) = inside("missing field `") {
        format!("missing required field: {a}")
    } else if let Some(a) = inside("unknown variant `") {
        let allowed = raw.split("expected ").nth(1).unwrap_or("").replace("one of ", "").replace("`, `", ", ");
        format!("invalid value: {a} (allowed values: {})", allowed.trim_matches('`'))
    } else if let Some(r) = raw.strip_prefix("invalid type: ") {
        format!("invalid kind: {}", sanitize(r))
    } else {
        format!("invalid value: {}", sanitize(raw))
    }
}
