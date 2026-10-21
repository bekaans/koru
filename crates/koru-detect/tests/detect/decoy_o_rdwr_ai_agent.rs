//! The KT-58 decoy side (hardening): when the process opening a
//! decoy with `O_RDWR` has an AI agent in its lineage, the decoy-access finding appears in the
//! "suspected hijacked agent" class; the `koru_decoy_modified` (self-protection) finding
//! stays as is.

use koru_detect::Level;
use koru_event::{ActorKind, FileFlag, ThreatClass};

use crate::common::*;

use FileFlag::{Append, Rdwr, Wronly};

const DECOYS: [(&str, &str); 3] =
    [(AWS, "decoy_credential_file"), (SSH_PATH, "decoy_ssh_key"), (MCP, "decoy_credential_file")];

#[test]
fn a_decoy_opened_o_rdwr_under_an_ai_agent_is_a_compromised_suspect() {
    for (path, rule) in DECOYS {
        let b = findings_of(vec![open_file(&cat_under_claude(5100, path), path, &[Rdwr], 0)]);
        assert_eq!(b.len(), 2, "{path}: {:?}", rule_names(&b));
        let access = b.iter().find(|b| b.event.detection.as_ref().unwrap().rule == rule).unwrap_or_else(|| {
            panic!("{rule} finding is missing: {:?}", rule_names(&b));
        });
        let t = access.event.detection.as_ref().unwrap();
        assert_eq!(t.threat_class, ThreatClass::SuspectedHijackedAgent, "{path}");
        assert_eq!(access.event.actor.kind, ActorKind::AiAgent, "{path}");
        assert!(access.severity >= Level::High, "{path}: {:?}", access.severity);
        access.event.validate().unwrap();

        let protection = b.iter().find(|b| b.event.detection.as_ref().unwrap().rule == "koru_decoy_modified").unwrap();
        let k = protection.event.detection.as_ref().unwrap();
        assert_eq!(k.threat_class, ThreatClass::SelfProtection, "{path}");
        assert_eq!(k.decoy_id, t.decoy_id, "{path}");
        protection.event.validate().unwrap();
    }
}

#[test]
fn o_rdwr_decoy_access_without_an_ai_agent_is_decoy_access() {
    for (path, rule) in DECOYS {
        let b = findings_of(vec![open_file(&cat(5000, 4999, path), path, &[Rdwr], 0)]);
        let access = b.iter().find(|b| b.event.detection.as_ref().unwrap().rule == rule).unwrap();
        assert_eq!(access.event.detection.as_ref().unwrap().threat_class, ThreatClass::DecoyAccess, "{path}");
        assert_eq!(b.len(), 2, "{path}");
    }
}

#[test]
fn an_ai_agents_write_only_open_is_not_decoy_access() {
    // Write-only (O_WRONLY, O_APPEND) is not a read capability; the modification finding stays.
    for (path, _) in DECOYS {
        for mode in [&[Wronly][..], &[Wronly, Append][..]] {
            let b = findings_of(vec![open_file(&cat_under_claude(5100, path), path, mode, 0)]);
            assert_eq!(rule_names(&b), ["koru_decoy_modified"], "{path} {mode:?}");
        }
    }
}
