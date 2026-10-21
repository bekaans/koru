//! `DecoyCatalog` also gives a decoy's class: the detection layer picks rules and ATT&CK
//! mappings by class (`packages/rules/`). The class is the template class in the integrity record.

use std::collections::BTreeSet;

use koru_decoy::Catalog;
use koru_event::DecoyCatalog;

use crate::common::Env;

#[test]
fn catalog_gives_each_paths_recorded_class() {
    let environment = Env::new();
    let report = environment.install();
    let catalog = Catalog::read(&environment.state()).unwrap();
    for g in &report.entries {
        let found = catalog.find(&g.path).unwrap_or_else(|| panic!("missing from the catalog: {}", g.path));
        assert_eq!(found.class, g.class, "{}", g.path);
    }
    let classes: BTreeSet<String> = catalog.watched_paths().into_iter().map(|y| y.class).collect();
    for expected in [
        "cloud_credentials",
        "env",
        "llm_keys",
        "mcp_config",
        "ssh_key",
        "database_dump",
        "ai_note",
        "bash_history",
        "ssh_config",
        "known_hosts",
    ] {
        assert!(classes.contains(expected), "{expected} missing from the catalog: {classes:?}");
    }
    // A catalog built from record entries also carries the class.
    let second = Catalog::from_entries(&report.entries);
    for g in &report.entries {
        assert_eq!(second.find(&g.path).unwrap().class, g.class);
    }
}
