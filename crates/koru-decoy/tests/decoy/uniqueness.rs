//! Uniqueness, never revealing itself, and natural timestamps.
//!
//! A "generated value": a high-entropy value produced by the CSPRNG at install time (keys,
//! tokens, passwords, password hashes, UUIDs). List-picked values (like a profile name) and
//! narrow-range values (a port, a documentation-network address, a date) can coincide across
//! two installs by chance; they do not count as generated values.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use koru_decoy::{Generation, generate};

use crate::common::{Env, files, mtime_ns, now_ns, package, package_dir, snapshot};

const DAY_NS: i128 = 86_400 * 1_000_000_000;

#[test]
fn no_shared_generated_value_between_runs() {
    let package = package();
    let a = generate(&package).expect("generation");
    let b = generate(&package).expect("generation");
    let values = |u: &[Generation]| -> BTreeSet<String> { u.iter().flat_map(|x| x.unique_values.clone()).collect() };
    let (da, db) = (values(&a), values(&b));
    assert!(da.len() >= 20, "at least 20 generated values expected, {} found", da.len());
    for u in &a {
        for d in &u.unique_values {
            assert!(d.chars().count() >= 16, "{}: a generated value is too short", u.template);
            assert!(u.content.contains(d.as_str()), "{}: a generated value is not in the content", u.template);
        }
    }
    let shared: Vec<&String> = da.intersection(&db).collect();
    assert!(shared.is_empty(), "the two generations share values: {} of them", shared.len());
    let b_contents: String = b.iter().map(|x| x.content.as_str()).collect::<Vec<_>>().join("\n");
    for d in &da {
        assert!(!b_contents.contains(d.as_str()), "one generation's value appears in the other's content");
    }
}

/// The high-entropy strings in content: at least 16 characters, holding uppercase, lowercase,
/// and digits, and absent from template texts. `=` is a separator: in a `KEY=value` line the
/// constant name and a list-picked value do not count as one string. The constant first line of
/// the OpenSSH private-key format (the base64 of the "openssh-key-v1" magic) is the same in
/// every ed25519 key; it is excluded.
fn tokens(root: &Path, template_text: &str) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for content in files(root).values() {
        let text = String::from_utf8_lossy(content);
        for j in text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-'))) {
            let mixed = j.chars().any(|c| c.is_ascii_uppercase())
                && j.chars().any(|c| c.is_ascii_lowercase())
                && j.chars().any(|c| c.is_ascii_digit());
            if j.len() >= 16 && mixed && !j.starts_with("b3BlbnNzaC1rZXktdjE") && !template_text.contains(j) {
                result.insert(j.to_string());
            }
        }
    }
    result
}

#[test]
fn no_shared_high_entropy_string_between_installs() {
    let mut template_text = String::new();
    for g in fs::read_dir(package_dir()).unwrap() {
        template_text.push_str(&fs::read_to_string(g.unwrap().path()).unwrap());
    }
    let (a, b) = (Env::new(), Env::new());
    a.install();
    b.install();
    let (ja, jb) = (tokens(a.root(), &template_text), tokens(b.root(), &template_text));
    assert!(ja.len() >= 10, "at least 10 high-entropy strings expected, {} found", ja.len());
    let shared = ja.intersection(&jb).count();
    assert_eq!(shared, 0, "the two installs share a high-entropy string");
}

#[test]
fn no_koru_string_in_decoy_content_or_paths() {
    let package = package();
    for _ in 0..50 {
        for u in generate(&package).expect("generation") {
            assert!(!u.content.to_lowercase().contains("koru"), "{}: \"koru\" in the content", u.template);
            assert!(!u.path.to_lowercase().contains("koru"), "{}: in_path \"koru\"", u.template);
        }
    }
    let environment = Env::new();
    environment.install();
    let mut number = 0;
    for (relative, entry) in snapshot(environment.root()) {
        assert!(
            !relative.to_string_lossy().to_lowercase().contains("koru"),
            "in_path \"koru\": {}",
            relative.display()
        );
        if let Some(content) = entry.content {
            assert!(
                !String::from_utf8_lossy(&content).to_lowercase().contains("koru"),
                "{}: \"koru\"",
                relative.display()
            );
            number += 1;
        }
    }
    assert!(number >= 12);
}

fn is_uuidv7(k: &str) -> bool {
    let b = k.as_bytes();
    k.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && k.chars().enumerate().all(|(i, c)| [8, 13, 18, 23].contains(&i) || matches!(c, '0'..='9' | 'a'..='f'))
        && b[14] == b'7'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}

#[test]
fn decoy_ids_are_unique_uuidv7_invisible_in_content() {
    let (a, b) = (Env::new(), Env::new());
    let (ra, rb) = (a.install(), b.install());
    assert!(is_uuidv7(&ra.install_id), "the install id is not UUIDv7");
    assert_ne!(ra.install_id, rb.install_id);
    let ids_a: BTreeSet<&str> = ra.entries.iter().map(|g| g.id.as_str()).collect();
    let ids_b: BTreeSet<&str> = rb.entries.iter().map(|g| g.id.as_str()).collect();
    assert_eq!(ids_a.len(), ra.entries.len(), "decoy ids are not unique");
    assert!(ids_a.is_disjoint(&ids_b), "the same decoy id in two installs");
    assert!(!ids_a.contains(ra.install_id.as_str()));
    for k in &ids_a {
        assert!(is_uuidv7(k), "a decoy id is not UUIDv7: {k}");
    }
    for content in files(a.root()).values() {
        let text = String::from_utf8_lossy(content).to_lowercase();
        for k in ids_a.iter().copied().chain([ra.install_id.as_str()]) {
            assert!(!text.contains(k) && !text.contains(&k.replace('-', "")), "the id is visible in content");
        }
    }
}

#[test]
fn timestamps_are_natural() {
    let environment = Env::new();
    let report = environment.install();
    let now = now_ns();
    let mut seen = BTreeSet::new();
    let mut nonzero_ns = 0;
    for g in &report.entries {
        let t = mtime_ns(&fs::symlink_metadata(&g.path).unwrap());
        assert_eq!(t, g.mtime.unix_nanos(), "{}: the recorded time differs from the file's", g.path);
        assert!(t <= now - DAY_NS, "{}: the timestamp is close to the install time", g.path);
        assert!(t >= now - 3 * 365 * DAY_NS, "{}: the timestamp is too old", g.path);
        assert!(seen.insert(t), "{}: the same timestamp as another decoy", g.path);
        if t % 1_000_000_000 != 0 {
            nonzero_ns += 1;
        }
    }
    assert!(nonzero_ns * 2 > report.entries.len(), "the nanosecond part does not look natural");
    // Directories the install created are also in the past, and never older than their newest entry.
    let tree = snapshot(environment.root());
    for (path, entry) in tree.iter().filter(|(y, g)| g.kind == 'd' && y.as_os_str() != ".") {
        let t = entry.mtime_ns.expect("directory time");
        assert!(t <= now - DAY_NS, "{}: the directory time is close to the install time", path.display());
        let newest_child = tree
            .iter()
            .filter(|(c, _)| c.parent() == Some(path.as_path()))
            .filter_map(|(_, g)| g.mtime_ns)
            .max()
            .expect("a created directory must not be empty");
        assert!(t >= newest_child, "{}: the directory is older than its entry", path.display());
    }
    // Generated times follow the same rule.
    for u in generate(&package()).unwrap() {
        let t = u.mtime.unix_nanos();
        assert!(t <= now - DAY_NS && t >= now - 3 * 365 * DAY_NS, "{}: generation time", u.template);
    }
}
