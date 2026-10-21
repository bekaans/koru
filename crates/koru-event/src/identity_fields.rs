//! Strict identity field checks (KT-66).
//!
//! In imported events the `host` and `sensor.*` fields cannot carry free text: because these
//! fields are not masked (ADR-0006 §7), they could be used to leak an IP address, a password, or
//! personal data. Here every field is bound to a narrow format; an event that does not match the
//! format is rejected.
//!
//! - `host`: an RFC 1123 hostname (labels of 1-63 characters, `[A-Za-z0-9-]`, not starting or
//!   ending with `-`; at most 253 in total). The last label cannot consist of digits only: this
//!   excludes IPv4 and similar addresses (`10.9.8.7`, `1.2.3`, `123`).
//! - `sensor.name`: lowercase letters, digits, `-`, and `_`; the first character is a letter or
//!   digit; at most 64.
//! - `sensor.version`: `X.Y.Z` with an optional `-prerelease`/`+build` suffix (SemVer format); at
//!   most 64. A four-part `10.9.8.7` does not match this format.
//! - `sensor.platform`: `os-arch` (lowercase letters, digits, `_`; hyphen-separated parts); at
//!   most 64.

use crate::{Event, ValidationError};

fn invalid(field: &'static str, reason: &str) -> ValidationError {
    ValidationError::Invalid { field, reason: reason.to_string() }
}

/// Whether this is an RFC 1123 hostname (IP-like names excluded).
pub fn is_valid_host(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let mut last = "";
    for label in name.split('.') {
        let bytes = label.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= 63
            && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-';
        if !valid {
            return false;
        }
        last = label;
    }
    !last.bytes().all(|b| b.is_ascii_digit())
}

fn is_valid_sensor_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
}

fn is_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_valid_suffix(suffix: &str) -> bool {
    // `-prerelease` or `+build`: dot-separated, non-empty `[0-9A-Za-z-]` parts.
    suffix.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

fn is_valid_version(version: &str) -> bool {
    if version.is_empty() || version.len() > 64 {
        return false;
    }
    let (core, suffix) = match version.find(['-', '+']) {
        Some(i) => (&version[..i], Some(&version[i..])),
        None => (version, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 || !parts.iter().all(|p| is_number(p)) {
        return false;
    }
    let Some(suffix) = suffix else { return true };
    // `-prerelease` followed by an optional `+build`, or only `+build`.
    let (prerelease, build) = match suffix.find('+') {
        Some(i) => (&suffix[..i], Some(&suffix[i + 1..])),
        None => (suffix, None),
    };
    let prerelease_ok = match prerelease.strip_prefix('-') {
        Some(o) => is_valid_suffix(o),
        None => prerelease.is_empty(),
    };
    prerelease_ok && build.is_none_or(is_valid_suffix)
}

fn is_valid_platform(p: &str) -> bool {
    if p.is_empty() || p.len() > 64 {
        return false;
    }
    p.split('-')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
}

impl Event {
    /// Strict format check of the `host` and `sensor.*` fields (KT-66). Called in addition to
    /// [`Event::validate`] for events imported from an untrusted source.
    pub fn check_identity_fields(&self) -> Result<(), ValidationError> {
        if !is_valid_host(&self.host) {
            return Err(invalid("host", "must be an RFC 1123 hostname (IP-like names and free text are not allowed)"));
        }
        if !is_valid_sensor_name(&self.sensor.name) {
            return Err(invalid(
                "sensor.name",
                "must be at most 64 characters of lowercase letters, digits, '-', and '_'",
            ));
        }
        if !is_valid_version(&self.sensor.version) {
            return Err(invalid("sensor.version", "must be in X.Y.Z (SemVer) form"));
        }
        if !is_valid_platform(&self.sensor.platform) {
            return Err(invalid("sensor.platform", "must be lowercase letters in os-arch form"));
        }
        Ok(())
    }
}
