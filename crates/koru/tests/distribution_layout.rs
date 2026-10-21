//! The shape of the distribution deliverables: fuzz targets, devcontainer and documents.
//! These check existence and consistency, not behavior; real run behavior is covered by the other distribution tests.

mod common;

use std::fs;
use std::path::PathBuf;

use common::store_root;
use serde_json::Value;

fn read(relative: &str) -> String {
    fs::read_to_string(store_root().join(relative)).unwrap_or_else(|e| panic!("{relative} could not be read: {e}"))
}

const FUZZ_TARGETS: [&str; 7] = [
    "pulsar_event_translation",
    "config",
    "decoy_template",
    "rule_pack",
    "cli_input",
    "jsonl_import",
    "persistent_queue",
];

#[test]
fn fuzz_targets_separate_workspace_and_seeded() {
    let cargo = read("fuzz/Cargo.toml");
    // fuzz/ is its own workspace: libfuzzer-sys stays out of the main workspace's dependency audit.
    assert!(cargo.contains("[workspace]"), "fuzz/ must carry its own [workspace] table");
    assert!(cargo.contains("libfuzzer-sys"));
    let root = read("Cargo.toml");
    assert!(!root.contains("\"fuzz\""), "fuzz/ must not be a member of the main workspace");
    for h in FUZZ_TARGETS {
        assert!(cargo.contains(&format!("name = \"{h}\"")), "{h} is missing from Cargo.toml");
        let source = read(&format!("fuzz/fuzz_targets/{h}.rs"));
        assert!(source.contains("fuzz_target!"), "{h}");
        let seed: PathBuf = store_root().join("fuzz/corpus").join(h);
        let number = fs::read_dir(&seed).unwrap_or_else(|e| panic!("no seed directory for {h}: {e}")).count();
        assert!(number >= 3, "{h}: at least 3 seed inputs required, found {number}");
    }
    assert!(!store_root().join("fuzz/target").exists() || read(".gitignore").contains("fuzz/target"));
}

#[test]
fn fuzz_dir_builds_reproducibly() {
    // The lock file must be pinned; the release uses the same Rust toolchain as the workspace.
    assert!(store_root().join("fuzz/Cargo.lock").is_file(), "fuzz/Cargo.lock must be in the repo (--locked)");
    let g = read(".gitignore");
    assert!(g.contains("fuzz/target") && g.contains("fuzz/artifacts"), ".gitignore must exclude fuzz outputs");
}

#[test]
fn devcontainer_safe_same_toolchain_as_ci() {
    let j: Value = serde_json::from_str(&read(".devcontainer/devcontainer.json")).expect("valid JSON");
    assert!(j["name"].as_str().is_some_and(|a| !a.is_empty()));
    assert_eq!(j["build"]["dockerfile"], "Dockerfile");
    let user = j["remoteUser"].as_str().unwrap_or("root");
    assert_ne!(user, "root", "the dev container must not run as root");
    assert_ne!(j["privileged"], Value::Bool(true));
    let whole = j.to_string();
    assert!(!whole.contains("docker.sock"), "the Docker socket is never mounted");
    // `.env` (the signing key and the notify secrets) is hidden from the container: /dev/null is mounted
    // over it (lesson KT-38: secret files never reach the dev environment).
    assert!(whole.contains("source=/dev/null,target=/workspaces/koru/.env"), ".env must appear empty in the container");
    assert!(j.get("capAdd").is_none_or(|c| c.as_array().is_some_and(Vec::is_empty)), "no extra capabilities");
    let docker = read(".devcontainer/Dockerfile");
    // The base image is pinned by digest; the Rust version comes from rust-toolchain.toml (same as CI).
    let from = docker.lines().find(|s| s.starts_with("FROM ")).expect("no FROM line");
    assert!(from.contains("@sha256:"), "the base image must be pinned by digest: {from}");
    for package in ["clang", "llvm", "libsqlite3-dev", "pkg-config", "openssl", "openssh-client", "shellcheck"] {
        assert!(docker.contains(package), "{package} must be installed");
    }
    assert!(docker.contains("rust-toolchain.toml"), "the toolchain must be installed from rust-toolchain.toml");
    assert!(docker.contains("USER "), "must switch to a non-root user");
    let contract = read(".devcontainer/devcontainer.json");
    assert!(contract.contains("cargo"), "postCreateCommand must fetch dependencies with --locked");
}

#[test]
fn documents_exist_and_are_consistent() {
    let security = read("SECURITY.md");
    for title in ["Supported versions", "Reporting a vulnerability", "Secrets", "Response times", "Scope"] {
        assert!(security.contains(title), "SECURITY.md has no {title:?}");
    }
    assert!(!security.contains("KORU_SIGNING") && !security.to_lowercase().contains("password:"));
    let changelog = read("CHANGELOG.md");
    assert!(changelog.contains("Semantic Versioning") || changelog.contains("SemVer"));
    assert!(changelog.contains("## [Unreleased]"));
    assert!(changelog.contains("## [0.1.0]"), "the workspace version needs a heading");
    let adr = read("docs/adr/0008-distribution-hardening-signing.md");
    for key_v in ["\u{2264} 2.5", "Signing", "Lifecycle", "SBOM", "Fuzz", "devcontainer"] {
        assert!(adr.contains(key_v), "ADR-0008 has no {key_v:?}");
    }
    let tm = read("docs/threat-model.md");
    for kt in ["KT-58", "KT-66"] {
        let line =
            tm.lines().find(|s| s.starts_with(&format!("| {kt} |"))).unwrap_or_else(|| panic!("{kt} is missing"));
        assert!(line.trim_end().ends_with("| MITIGATED |"), "{kt} must be MITIGATED: {line}");
    }
}
