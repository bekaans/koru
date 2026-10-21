//! Safe writing (Koru may later run as root; ADR-0004):
//! - If the target path or any intermediate directory is a symlink, nothing is written.
//! - A template path cannot hold `..`; the target cannot escape the root; an absolute path is
//!   allowed only under the allowed roots.
//! - An existing file is never overwritten; an append goes only to a single-linked regular file.
//! - File and directory modes; ownership follows the root's owner.
//! - A failed install leaves no trace at the root.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use koru_decoy::{InstallError, InstallSettings, install, parse_template, read_package};

use crate::common::{Env, SAMPLE_TEMPLATE, command, package, snapshot, snapshot_diff, temp_dir, write_package};

/// Tries to install the repo package; expects an error, and checks that neither the root nor the outside directory changed.
fn is_rejected(environment: &Env, settings: &InstallSettings, outside: &Path) -> InstallError {
    let (root_before, outside_before) = (snapshot(environment.root()), snapshot(outside));
    let error = install(&package(), settings).expect_err("install must be rejected");
    assert!(snapshot_diff(&root_before, &snapshot(environment.root())).is_empty(), "a failed install changed the root");
    assert!(snapshot_diff(&outside_before, &snapshot(outside)).is_empty(), "a failed install wrote outside the root");
    assert!(
        matches!(koru_decoy::list_entries(&environment.state()), Err(InstallError::NotInstalled)),
        "a record remained"
    );
    error
}

#[test]
fn symlink_intermediate_dir_is_not_written() {
    for name in [".ssh", ".aws", ".config", "apps"] {
        let environment = Env::new();
        let outside = temp_dir();
        fs::create_dir(outside.path.join("target")).unwrap();
        symlink(outside.path.join("target"), environment.root().join(name)).unwrap();
        let error = is_rejected(&environment, &environment.settings(), &outside.path);
        assert!(matches!(error, InstallError::Symlink { .. }), "{name}: {error}");
        assert!(
            fs::read_dir(outside.path.join("target")).unwrap().next().is_none(),
            "{name}: written to the link target"
        );
    }
}

#[test]
fn symlink_target_file_is_not_written() {
    for name in [".aws/credentials", ".bash_history", ".ssh/known_hosts"] {
        let environment = Env::new();
        let outside = temp_dir();
        fs::write(outside.path.join("victim"), "must not be touched\n").unwrap();
        let path = environment.root().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(outside.path.join("victim"), &path).unwrap();
        let error = is_rejected(&environment, &environment.settings(), &outside.path);
        assert!(matches!(error, InstallError::Symlink { .. }), "{name}: {error}");
        assert_eq!(fs::read_to_string(outside.path.join("victim")).unwrap(), "must not be touched\n");
    }
}

#[test]
fn symlink_in_root_or_state_path_rejected() {
    let environment = Env::new();
    let outside = temp_dir();
    symlink(environment.root(), outside.path.join("bag")).unwrap();
    let settings = InstallSettings::new(outside.path.join("bag"), environment.state());
    let error = is_rejected(&environment, &settings, &outside.path);
    assert!(matches!(error, InstallError::Symlink { .. }), "{error}");
    assert!(!environment.state().exists());

    let state_target = temp_dir();
    symlink(&state_target.path, environment.parent.path.join("bag")).unwrap();
    let settings = InstallSettings::new(environment.root().to_path_buf(), environment.parent.path.join("bag/state"));
    let error = is_rejected(&environment, &settings, &outside.path);
    assert!(matches!(error, InstallError::Symlink { .. }), "{error}");
    assert!(fs::read_dir(&state_target.path).unwrap().next().is_none(), "a state directory was opened through a link");
}

#[test]
fn existing_target_file_not_overwritten() {
    let environment = Env::new();
    let outside = temp_dir();
    fs::create_dir(environment.root().join(".aws")).unwrap();
    fs::write(environment.root().join(".aws/credentials"), "[default]\nregion = eu-central-1\n").unwrap();
    let error = is_rejected(&environment, &environment.settings(), &outside.path);
    assert!(matches!(error, InstallError::TargetExists { .. }), "{error}");
}

#[test]
fn append_target_must_be_single_link_regular_file() {
    // A hard link: another file's content could leak into the backup and the target user's file.
    let environment = Env::new();
    let outside = temp_dir();
    fs::write(outside.path.join("secret"), "root:x:0:0\n").unwrap();
    fs::hard_link(outside.path.join("secret"), environment.root().join(".bash_history")).unwrap();
    let error = is_rejected(&environment, &environment.settings(), &outside.path);
    assert!(matches!(error, InstallError::UnsafeFile { .. }), "hard link: {error}");

    // DirHandle.
    let environment = Env::new();
    fs::create_dir(environment.root().join(".bash_history")).unwrap();
    let error = is_rejected(&environment, &environment.settings(), &outside.path);
    assert!(matches!(error, InstallError::UnsafeFile { .. }), "dir: {error}");

    // A FIFO: opening it would hang the install; it must be rejected without being read.
    let environment = Env::new();
    let fifo = environment.root().join(".bash_history");
    let output = command("mkfifo", &[&fifo.to_string_lossy()], environment.root());
    assert!(output.status.success());
    let error = is_rejected(&environment, &environment.settings(), &outside.path);
    assert!(matches!(error, InstallError::UnsafeFile { .. }), "FIFO: {error}");
}

#[test]
fn path_traversal_rejected_in_template() {
    for path in ["../outside.env", "a/../../outside.env", "..", "a/./b.env", "/srv/../etc/passwd"] {
        let text = SAMPLE_TEMPLATE.replace("path = \"app/.env\"", &format!("path = \"{path}\""));
        assert!(parse_template(&text).is_err(), "{path} was accepted");
    }
}

fn absolute_template(path: &Path) -> String {
    SAMPLE_TEMPLATE.replace("path = \"app/.env\"", &format!("path = \"{}\"", path.join("app/.env").display()))
}

#[test]
fn absolute_target_only_under_allowed_root() {
    let environment = Env::new();
    let allowed = temp_dir();
    let package_dir = temp_dir();
    write_package(&package_dir.path, &[("absolute.toml", &absolute_template(&allowed.path))]);
    let package = read_package(&package_dir.path).unwrap();

    // Rejected without an allowed root; nothing is written anywhere.
    let (before, allowed_before) = (snapshot(environment.root()), snapshot(&allowed.path));
    let error = install(&package, &environment.settings()).unwrap_err();
    assert!(matches!(error, InstallError::OutsideRoot { .. }), "{error}");
    assert!(snapshot_diff(&before, &snapshot(environment.root())).is_empty());
    assert!(snapshot_diff(&allowed_before, &snapshot(&allowed.path)).is_empty());

    // Another allowed root does not suffice either.
    let other = temp_dir();
    let error = install(&package, &environment.settings().allowed_root(other.path.clone())).unwrap_err();
    assert!(matches!(error, InstallError::OutsideRoot { .. }), "{error}");

    // Written under the allowed root.
    let report = install(&package, &environment.settings().allowed_root(allowed.path.clone())).unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(Path::new(&report.entries[0].path), allowed.path.join("app/.env"));
    assert!(allowed.path.join("app/.env").is_file());
    let k = koru_decoy::uninstall(&environment.state()).unwrap();
    assert!(k.completed());
    assert!(
        snapshot_diff(&allowed_before, &snapshot(&allowed.path)).is_empty(),
        "a trace remained under the allowed root"
    );
}

#[test]
fn state_dir_cannot_nest_with_root() {
    let environment = Env::new();
    let outside = temp_dir();
    for settings in [
        InstallSettings::new(environment.root().to_path_buf(), environment.root().join(".cache/state")),
        InstallSettings::new(environment.root().to_path_buf(), environment.root().to_path_buf()),
        InstallSettings::new(environment.root().join("home"), environment.root().to_path_buf()),
    ] {
        fs::create_dir_all(environment.root().join("home")).unwrap();
        let error = is_rejected(&environment, &settings, &outside.path);
        assert!(matches!(error, InstallError::Settings(_)), "{error}");
    }
}

#[test]
fn relative_root_and_state_paths_rejected() {
    let environment = Env::new();
    let outside = temp_dir();
    for settings in [
        InstallSettings::new("relative/home".into(), environment.state()),
        InstallSettings::new(environment.root().to_path_buf(), "relative/state".into()),
        InstallSettings::new(environment.root().join("../home"), environment.state()),
    ] {
        let error = is_rejected(&environment, &settings, &outside.path);
        assert!(matches!(error, InstallError::Settings(_)), "{error}");
    }
}

#[test]
fn created_file_and_dir_modes_and_ownership() {
    let environment = Env::new();
    let report = environment.install();
    let package = package();
    let root = fs::metadata(environment.root()).unwrap();
    for g in &report.entries {
        let m = fs::metadata(&g.path).unwrap();
        let template = package.template(&g.template).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, template.target.mode, "{}: mode", g.path);
        if template.secret {
            assert_eq!(m.permissions().mode() & 0o7777, 0o600, "{}: a secret file must be 0600", g.path);
        }
        assert_eq!((m.uid(), m.gid()), (root.uid(), root.gid()), "{}: owner", g.path);
    }
    for (path, entry) in snapshot(environment.root()).iter().filter(|(y, g)| g.kind == 'd' && y.as_os_str() != ".") {
        assert_eq!(entry.mode, 0o700, "{}: a created directory must be 0700", path.display());
        assert_eq!((entry.uid, entry.gid), (root.uid(), root.gid()), "{}: dir owner", path.display());
    }
}

#[test]
fn explicit_owner_is_used() {
    let environment = Env::new();
    let root = fs::metadata(environment.root()).unwrap();
    let report = install(&package(), &environment.settings().owner(root.uid(), root.gid())).unwrap();
    for g in &report.entries {
        assert_eq!((g.uid, g.gid), (root.uid(), root.gid()));
    }
}
