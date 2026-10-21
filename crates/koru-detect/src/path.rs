//! Lexical path normalization (a below-threshold note from the security review).
//!
//! Pulsar hands over the executed file's path (`bprm->filename`) unnormalized; an attacker
//! can mislead prefix comparisons with `/./`, `//`, and `..`. This normalization runs before
//! path comparisons. Symbolic links cannot be resolved lexically; the allowlist uses inodes
//! for that as well.

/// Normalizes an absolute path: `//` becomes one `/`, `.` components drop, `..` climbs one
/// component (staying at the root), a trailing `/` drops. `None` for a relative, empty, or
/// NUL-bearing path.
pub fn normalize_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.contains('\0') {
        return None;
    }
    let mut components: Vec<&str> = Vec::new();
    for b in path.split('/') {
        match b {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            name => components.push(name),
        }
    }
    if components.is_empty() { Some("/".to_string()) } else { Some(format!("/{}", components.join("/"))) }
}
