//! Breadcrumbs: every read-capable open counts as a read (KT-58). `O_RDONLY` and `O_RDWR` (and
//! `O_APPEND`, `O_CREAT`, `O_TRUNC` combined with `O_RDWR`) produce a breadcrumb finding; a
//! write-only open (`O_WRONLY`, e.g. a shell appending to `.bash_history`) does not. Decoys
//! follow the same rule: a process opening a decoy with `O_RDWR` produces a decoy-access finding
//! alongside `koru_decoy_modified`.

use koru_detect::{FieldValue, Level};
use koru_event::{FileFlag, ThreatClass};

use crate::common::*;

use FileFlag::{Append, Creat, Rdonly, Rdwr, Trunc, Wronly};

const BREADCRUMB_PATHS: [(&str, &str); 4] = [
    (HISTORY, "breadcrumb_shell_history"),
    (SSH_CONFIG, "breadcrumb_ssh"),
    (KNOWN_HOSTS, "breadcrumb_ssh"),
    (NEW_BREADCRUMB, "breadcrumb_general"),
];

fn for_the_rules(flags: &[FileFlag], target: &str) -> Vec<String> {
    let c = cat(5000, 4999, target);
    rule_names(&findings_of(vec![open_file(&c, target, flags, 0)]))
}

#[test]
fn read_capable_opens_produce_breadcrumb_findings() {
    let modes: [&[FileFlag]; 6] =
        [&[Rdonly], &[Rdwr], &[Rdwr, Append], &[Rdwr, Creat], &[Rdwr, Trunc], &[Rdonly, Creat]];
    for (path, rule) in BREADCRUMB_PATHS {
        for mode in modes {
            assert_eq!(for_the_rules(mode, path), [rule], "{path} {mode:?}");
        }
    }
}

#[test]
fn an_o_rdwr_breadcrumb_finding_carries_same_class_level_and_tags() {
    let c = cat(5000, 4999, HISTORY);
    let b = findings_of(vec![open_file(&c, HISTORY, &[Rdwr], 0)]);
    assert_eq!(b.len(), 1);
    let t = b[0].event.detection.as_ref().unwrap();
    assert_eq!(t.rule, "breadcrumb_shell_history");
    assert_eq!(t.threat_class, ThreatClass::BreadcrumbAccess);
    assert_eq!(t.decoy_id.as_deref(), Some("breadcrumb-history"));
    assert_eq!(b[0].severity, Level::Low);
    assert!(!t.attack.is_empty());
    b[0].event.validate().unwrap();
}

#[test]
fn an_o_rdwr_breadcrumb_in_ai_agent_lineage_stays_in_its_class() {
    let b = findings_of(vec![open_file(&cat_under_claude(5100, HISTORY), HISTORY, &[Rdwr], 0)]);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].event.detection.as_ref().unwrap().threat_class, ThreatClass::BreadcrumbAccess);
    assert_eq!(b[0].event.actor.kind, koru_event::ActorKind::AiAgent);
}

#[test]
fn a_write_only_open_produces_no_breadcrumb_finding() {
    // A shell appending to its history is legitimate; no write-only open counts as a read.
    let modes: [&[FileFlag]; 5] =
        [&[Wronly], &[Wronly, Append], &[Wronly, Trunc], &[Wronly, Creat, Trunc], &[Wronly, Append, Creat]];
    for (path, _) in BREADCRUMB_PATHS {
        for mode in modes {
            assert!(for_the_rules(mode, path).is_empty(), "{path} {mode:?}");
        }
    }
}

#[test]
fn decoy_o_rdwr_behaviour_is_unchanged() {
    // KT-58 (hardening): a decoy opened with O_RDWR also produces
    // a decoy-access finding on top of the self-protection finding.
    let mut rdwr = for_the_rules(&[Rdwr], AWS);
    rdwr.sort();
    assert_eq!(rdwr, ["decoy_credential_file", "koru_decoy_modified"]);
    assert_eq!(for_the_rules(&[Rdonly], AWS), ["decoy_credential_file"]);
    assert!(for_the_rules(&[Wronly, Append], AWS).iter().all(|k| k == "koru_decoy_modified"));
}

#[test]
fn the_read_field_is_derived_from_the_open_mode() {
    let t = a_detector();
    let c = cat(5000, 4999, HISTORY);
    let read_field_of = |o: &koru_event::Event| match t.fields(o).get("koru.read") {
        Some(FieldValue::Bool(m)) => Some(*m),
        other => panic!("koru.read must be a boolean: {other:?}"),
    };
    for (mode, expected) in [
        (&[Rdonly][..], true),
        (&[Rdwr][..], true),
        (&[Rdwr, Append][..], true),
        (&[Wronly][..], false),
        (&[Wronly, Append][..], false),
        (&[Wronly, Creat, Trunc][..], false),
    ] {
        assert_eq!(read_field_of(&open_file(&c, HISTORY, mode, 0)), Some(expected), "{mode:?}");
    }
    // Non-open events have no read (the field is present anyway).
    assert_eq!(read_field_of(&file_deletion(&c, HISTORY, 0)), Some(false));
    assert_eq!(read_field_of(&process_creation(&c, HISTORY, 0)), Some(false));
}
