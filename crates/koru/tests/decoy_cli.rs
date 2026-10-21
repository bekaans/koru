//! Tests of the `koru decoy` commands (protected set).
//!
//! HARD RULE: these tests never write to a real home directory. `HOME` points at a temporary directory in
//! every command; the root (`--root`) and the state directory (`--state`) are always temporary directories. A plant
//! request without a root is separately tested to be rejected without writing anything.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Transient {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn temp() -> Transient {
    let dir = tempfile::tempdir().expect("temp directory");
    let path = fs::canonicalize(dir.path()).expect("canonical path");
    Transient { _dir: dir, path }
}

fn package_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/decoys")
}

fn koru(args: &[&str], home_v: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_koru")).args(args).env("HOME", home_v).output().expect("koru could not be run")
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// One entry's digest: (is-dir, mode and type bits, uid, gid, content, mtime).
type DigestEntry = (bool, u32, u32, u32, Option<Vec<u8>>, i128);

/// The digests of every entry under the root.
fn digest(root: &Path) -> BTreeMap<PathBuf, DigestEntry> {
    let mut result = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let m = fs::symlink_metadata(&path).unwrap();
        let content = m.is_file().then(|| fs::read(&path).unwrap());
        let mtime = i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec());
        result.insert(path.clone(), (m.is_dir(), m.mode(), m.uid(), m.gid(), content, mtime));
        if m.is_dir() {
            for g in fs::read_dir(&path).unwrap() {
                stack.push(g.unwrap().path());
            }
        }
    }
    result
}

#[test]
fn verify_passes_all_repo_templates() {
    let home_v = temp();
    let o = koru(&["decoy", "validate", &package_dir().to_string_lossy()], &home_v.path);
    assert!(o.status.success(), "validate failed:\n{}", text(&o));
    let output = text(&o);
    let mut number = 0;
    for g in fs::read_dir(package_dir()).unwrap() {
        let name = g.unwrap().file_name().to_string_lossy().into_owned();
        if name.ends_with(".toml") {
            assert!(output.contains(&name), "{name} is not in the output:\n{output}");
            number += 1;
        }
    }
    assert!(number >= 12);
}

#[test]
fn verify_rejects_corrupt_template() {
    let home_v = temp();
    let dir = temp();
    fs::write(dir.path.join("broken.toml"), "schema = 1\nid = \"broken\"\nextra_field = true\n").unwrap();
    let o = koru(&["decoy", "validate", &dir.path.to_string_lossy()], &home_v.path);
    assert_eq!(o.status.code(), Some(1), "a corrupt template must be rejected:\n{}", text(&o));
    assert!(text(&o).contains("broken.toml"));
    let o = koru(&["decoy", "validate", &dir.path.join("broken.toml").to_string_lossy()], &home_v.path);
    assert_eq!(o.status.code(), Some(1), "a single file must also be validatable:\n{}", text(&o));
}

#[test]
fn no_install_without_root_or_state() {
    let home_v = temp();
    let state = temp();
    let package = package_dir();
    let before = digest(&home_v.path);
    for args in [
        vec!["decoy", "plant", "--package", package.to_str().unwrap(), "--state", state.path.to_str().unwrap()],
        vec!["decoy", "plant", "--package", package.to_str().unwrap(), "--root", home_v.path.to_str().unwrap()],
        vec!["decoy", "plant", "--root", home_v.path.to_str().unwrap(), "--state", state.path.to_str().unwrap()],
        vec!["decoy", "plant", "--package"],
        vec!["decoy", "plant", "--unknown_key", "x"],
        vec!["decoy", "list"],
        vec!["decoy", "uninstall"],
        vec!["decoy", "integrity"],
        vec!["decoy", "nonexistent-command"],
        vec!["decoy"],
    ] {
        let o = koru(&args, &home_v.path);
        assert_eq!(o.status.code(), Some(2), "{args:?} must be a usage error:\n{}", text(&o));
    }
    assert_eq!(before, digest(&home_v.path), "the home directory changed on a usage error");
    assert!(fs::read_dir(&state.path).unwrap().next().is_none(), "the state directory was written to on a usage error");
}

#[test]
fn install_list_integrity_remove_cycle() {
    let home_v = temp();
    let parent = temp();
    let state = parent.path.join("state");
    let (root_s, state_s, package) = (home_v.path.to_str().unwrap(), state.to_str().unwrap(), package_dir());
    fs::write(home_v.path.join(".bash_history"), "ls\ncd /srv\n").unwrap();
    let before = digest(&home_v.path);

    let o = koru(
        &["decoy", "plant", "--package", package.to_str().unwrap(), "--root", root_s, "--state", state_s],
        &home_v.path,
    );
    assert!(o.status.success(), "plant failed:\n{}", text(&o));
    let aws =
        fs::read_to_string(home_v.path.join(".aws/credentials")).expect("the cloud credentials file must be planted");
    let secret =
        aws.lines().find_map(|s| s.split_once("aws_secret_access_key = ")).map(|(_, d)| d.to_string()).unwrap();
    assert!(!text(&o).contains(&secret), "the plant output must not contain the generated secret value");

    let o = koru(&["decoy", "list", "--state", state_s], &home_v.path);
    assert!(o.status.success(), "list failed:\n{}", text(&o));
    let listing = text(&o);
    for path in [".aws/credentials", ".bash_history", ".ssh/config", ".ssh/known_hosts", ".cursor/mcp.json"] {
        assert!(
            listing.contains(&home_v.path.join(path).to_string_lossy().into_owned()),
            "{path} missing from the listing:\n{listing}"
        );
    }
    assert!(!listing.contains(&secret), "the list output must not contain the generated secret value");

    let o = koru(&["decoy", "integrity", "--state", state_s], &home_v.path);
    assert_eq!(o.status.code(), Some(0), "integrity must be intact after planting:\n{}", text(&o));

    let key_v = fs::read_dir(home_v.path.join(".ssh"))
        .unwrap()
        .map(|g| g.unwrap().path())
        .find(|y| fs::read_to_string(y).is_ok_and(|m| m.contains("OPENSSH PRIVATE KEY")))
        .expect("the SSH key must be planted");
    fs::write(&key_v, b"modified\n").unwrap();
    let o = koru(&["decoy", "integrity", "--state", state_s], &home_v.path);
    assert_eq!(o.status.code(), Some(1), "the change must be caught:\n{}", text(&o));
    assert!(
        text(&o).contains(&key_v.to_string_lossy().into_owned()),
        "the changed path is not in the report:\n{}",
        text(&o)
    );

    // A changed decoy is left behind on removal; exit code 1. Once the admin inspects and removes the file,
    // the second removal completes.
    let o = koru(&["decoy", "uninstall", "--state", state_s], &home_v.path);
    assert_eq!(o.status.code(), Some(1), "a changed decoy must be left behind:\n{}", text(&o));
    assert!(key_v.exists());
    fs::remove_file(&key_v).unwrap();
    let o = koru(&["decoy", "uninstall", "--state", state_s], &home_v.path);
    assert_eq!(o.status.code(), Some(0), "the second removal must complete:\n{}", text(&o));
    assert_eq!(before, digest(&home_v.path), "after removal, the home directory differs from before planting");

    let o = koru(&["decoy", "list", "--state", state_s], &home_v.path);
    assert_eq!(o.status.code(), Some(1), "with no install, list must error:\n{}", text(&o));
}

#[test]
fn help_lists_decoy_commands() {
    let home_v = temp();
    let o = koru(&["help"], &home_v.path);
    assert!(o.status.success());
    let output = text(&o);
    for command in ["decoy validate", "decoy plant", "decoy list", "decoy integrity", "decoy uninstall"] {
        assert!(output.contains(command), "the help has no {command}:\n{output}");
    }
}
