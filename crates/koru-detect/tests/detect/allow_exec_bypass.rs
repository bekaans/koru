//! The allowlist and Koru's self-exclusion: bypass via exec (a security-review finding).
//!
//! The silence/exclusion decision used the `/proc/<pid>/exe` value read while processing the
//! event. If an attacker opens a decoy with their own binary and immediately execs an
//! allowlisted one (keeping the process alive via `ptrace(PTRACE_TRACEME)` or a stdin wait),
//! `/proc` would show the allowed binary and the finding would be silenced. The rule now
//! requires both: the event's (normalized) exe matches the allowed entry AND the process's
//! real exe (path and inode) matches the entry. The same applies to Koru's own process.
//!
//! The fake source gives the real exe path per pid (`IdentitySource::process_exe_path`).

use std::collections::HashMap;

use koru_detect::{Allowlist, DetectorSettings, FileIdentity, IdentitySource, RuleDetector, parse_allowlist};

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

fn source(base: FakeIdentity, paths: &[(u32, &str)]) -> RealPathSource {
    RealPathSource { base, paths: paths.iter().map(|(pid, path)| (*pid, (*path).to_string())).collect() }
}

fn allowed_detector(paths: &[(u32, &str)], inode_lar: &[(u32, FileIdentity)]) -> RuleDetector {
    let definition = parse_allowlist(
        "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\nrules = [\"decoy_credential_file\"]\nrationale = \"nightly backup\"\n",
    )
    .unwrap();
    let mut base = identity_source().path("/usr/local/bin/backup", BACKUP);
    for (pid, id) in inode_lar {
        base = base.process(*pid, *id);
    }
    let source = source(base, paths);
    let mut settings_v: DetectorSettings = settings();
    settings_v.allowlist = definition.resolve(&source, &settings_v.rules).unwrap();
    assert_ne!(settings_v.allowlist, Allowlist::empty());
    RuleDetector::new(settings_v, Box::new(decoy_catalog()), Box::new(source)).unwrap()
}

#[test]
fn exec_bypass_is_not_suppressed_when_event_exe_is_not_allowed() {
    // The attacker opened the decoy with their own binary (/tmp/x), then exec'd the allowed
    // backup binary; while Koru processes the event, /proc shows the allowed binary (path and
    // inode). The event's exe is not allowed: a finding is produced.
    let mut t = allowed_detector(&[(3000, "/usr/local/bin/backup")], &[(3000, BACKUP)]);
    let attacker = s(3000, 1, "/tmp/x", &["x"]);
    assert_eq!(rule_names(&run(&mut t, vec![read_text(&attacker, AWS, 0)])), ["decoy_credential_file"]);
    assert_eq!(t.suppressed_count(), 0);
}

#[test]
fn silenced_when_event_and_real_exe_are_allowed() {
    // Control: the event's exe, real path, and real inode all match the allowed entry.
    let mut t = allowed_detector(&[(3000, "/usr/local/bin/backup")], &[(3000, BACKUP)]);
    let allowed = s(3000, 1, "/usr/local//bin/./backup", &["backup", "-f", AWS]);
    assert!(run(&mut t, vec![read_text(&allowed, AWS, 0)]).is_empty());
    assert_eq!(t.suppressed_count(), 1);
}

fn detector_with_koru(real_path: &str) -> RuleDetector {
    let k = source(identity_source(), &[(KORU_PID, real_path)]);
    RuleDetector::new(settings(), Box::new(decoy_catalog()), Box::new(k)).unwrap()
}

#[test]
fn koru_process_kept_when_the_real_path_differs() {
    // The event's exe, pid, and inode match Koru's, but the real exe path the kernel knows is
    // different: the process is not Koru (it may have exec'd).
    let mut t = detector_with_koru("/tmp/koru-agent");
    let k = s(KORU_PID, 1, KORU_EXE, &["koru-agent", "agent"]);
    assert_eq!(rule_names(&run(&mut t, vec![read_text(&k, AWS, 0)])), ["decoy_credential_file"]);
}

#[test]
fn koru_process_excluded_when_the_real_path_matches() {
    let mut t = detector_with_koru(KORU_EXE);
    let k = s(KORU_PID, 1, KORU_EXE, &["koru-agent", "agent"]);
    assert!(run(&mut t, vec![read_text(&k, AWS, 0)]).is_empty());
}
