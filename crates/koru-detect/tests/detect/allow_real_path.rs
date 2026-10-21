//! The allowlist uses the process's real exe path (a live-lab finding).
//!
//! Pulsar's process tracker can show the parent's old image (e.g. `timeout`) for files opened
//! right after exec; in the live lab, an allowed binary's first read arrived in such an event.
//! The allowlist also consults the real path the kernel knows, not only the event's exe.
//! (`/proc/<pid>/exe`, `IdentitySource::process_exe_path`) too: an entry only allows
//! a process when both agree. Both must match; if the real path is unreadable, nothing is silenced. Path and inode must
//! match together. (The rule was tightened after the security review; see the
//! allow_exec_bypass.rs header and ADR-0005 §7.)

use std::collections::HashMap;

use koru_detect::{Allowlist, FileIdentity, IdentitySource, parse_allowlist};

use crate::common::*;

const BACKUP: FileIdentity = FileIdentity { device: 64769, inode: 3003 };

/// A fake source giving the real exe path (`/proc/<pid>/exe`) per pid.
struct RealPathSource {
    base: FakeIdentity,
    paths: HashMap<u32, String>,
}

impl IdentitySource for RealPathSource {
    fn process_exe_id(&self, pid: u32) -> Option<FileIdentity> {
        self.base.process_exe_id(pid)
    }

    fn path_id(&self, path: &str) -> Option<FileIdentity> {
        self.base.path_id(path)
    }

    fn process_exe_path(&self, pid: u32) -> Option<String> {
        self.paths.get(&pid).cloned()
    }
}

fn allowed_detector(paths: &[(u32, &str)], inode_lar: &[(u32, FileIdentity)]) -> koru_detect::RuleDetector {
    let definition = parse_allowlist(
        "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\nrules = [\"decoy_credential_file\"]\nrationale = \"nightly backup\"\n",
    )
    .unwrap();
    let mut base = identity_source().path("/usr/local/bin/backup", BACKUP);
    for (pid, id) in inode_lar {
        base = base.process(*pid, *id);
    }
    let source = RealPathSource {
        base: base.clone(),
        paths: paths.iter().map(|(pid, path)| (*pid, (*path).to_string())).collect(),
    };
    let mut settings_v = settings();
    settings_v.allowlist = definition.resolve(&source, &settings_v.rules).unwrap();
    assert_ne!(settings_v.allowlist, Allowlist::empty());
    koru_detect::RuleDetector::new(settings_v, Box::new(decoy_catalog()), Box::new(source)).unwrap()
}

#[test]
fn a_stale_image_in_the_event_is_not_silenced() {
    // The event shows the parent's image (timeout); the kernel says the real exe is backup.
    // After the security review (HIGH) the rule was tightened:
    // silencing requires the event's exe to be allowed too, else "open then exec" bypasses it.
    // The legitimate stale-image case knowingly produces a false positive (see ADR-0005 §7, KT-57).
    let mut t = allowed_detector(&[(3000, "/usr/local/bin/backup")], &[(3000, BACKUP)]);
    let stale_image = s(3000, 1, "/usr/bin/timeout", &["timeout", "3", "backup", "-f", AWS]);
    assert_eq!(rule_names(&run(&mut t, vec![read_text(&stale_image, AWS, 0)])), ["decoy_credential_file"]);
    assert_eq!(t.suppressed_count(), 0);
}

#[test]
fn not_silenced_when_only_the_event_path_is_allowed() {
    // A hard link: the inode is the allowed binary's, the invoked path differs
    // (/tmp/backup-hard). Even if the event misleadingly shows the allowed path, the real path
    // decides.
    let mut t = allowed_detector(&[(3001, "/tmp/backup-hard")], &[(3001, BACKUP)]);
    let decoy_lookalike = s(3001, 1, "/usr/local/bin/backup", &["backup", "-f", AWS]);
    assert_eq!(rule_names(&run(&mut t, vec![read_text(&decoy_lookalike, AWS, 0)])), ["decoy_credential_file"]);
    assert_eq!(t.suppressed_count(), 0);
}

#[test]
fn not_silenced_when_the_real_path_is_a_deleted_binary() {
    // /proc/<pid>/exe shows a deleted binary with a " (deleted)" suffix; it never matches an allowed path.
    let mut t = allowed_detector(&[(3002, "/usr/local/bin/backup (deleted)")], &[(3002, BACKUP)]);
    let p = s(3002, 1, "/usr/local/bin/backup", &["backup"]);
    assert_eq!(rule_names(&run(&mut t, vec![read_text(&p, AWS, 0)])), ["decoy_credential_file"]);
}
