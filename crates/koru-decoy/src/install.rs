//! Installation, removal, listing, and integrity checking (ADR-0004).
//!
//! The installation order:
//! 1. Settings: root, state, and allowed roots are absolute, normal paths; the state directory
//!    does not nest with the roots; off Linux, temp directories only (development safety).
//! 2. If an installation already exists in this state directory, it is rejected.
//! 3. Root and allowed roots are opened from `/` without following symlinks.
//! 4. Content is generated in memory (`generate`).
//! 5. Pre-check (nothing is written): every target path is opened; a link, an existing target,
//!    or an unsafe append target (link, non-regular, hard-linked, different owner) is rejected.
//! 6. The state directory is opened and locked; backups of existing files are written; the
//!    integrity record is written to disk before writing (with expected hashes).
//! 7. Files are written; created and touched directories get natural timestamps; the record is
//!    completed with real metadata. If a step fails, everything done is rolled back.
//!
//! Removal touches only the files in the record. A decoy changed after install is not deleted;
//! it is reported and stays in the record; for appends, only the appended lines are removed.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::Metadata;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use koru_event::Timestamp;
use rustix::fs::FileType;

use crate::error::InstallError;
use crate::generation::{Generation, generate};
use crate::package::Package;
use crate::random::Random;
use crate::record::{
    AppendInfo, DirectoryRecord, MAX_APPEND_TARGET, PreviousFile, RECORD_VERSION, Record, RecordEntry, StateDir,
    now_ns, open_state_dir,
};
use crate::safe_file::{
    DirHandle, NewFile, Owner, create_directory, entry_kind, mtime_ns, normal_components, open_absolute_dir,
    open_absolute_dir_if_exists, read_file, remove_empty_dir, remove_file, replace_file, sha256_hex, subdirectory,
    write_new_file,
};
use crate::template::{DecoyKind, Placement};

/// Installation settings. Root and state directory are always given explicitly; no defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InstallSettings {
    /// The root of relative template paths (the target user's home). Absolute, symlink-free.
    pub root: PathBuf,
    /// The state directory (integrity record and backups). Must sit outside the root and allowed roots.
    pub state_dir: PathBuf,
    /// The roots allowed for absolute template paths.
    pub allowed_roots: Vec<PathBuf>,
    /// The file and directory owner (uid, gid); the root's owner if not given.
    pub owner: Option<(u32, u32)>,
}

impl InstallSettings {
    /// Settings with a root and a state directory.
    pub fn new(root: PathBuf, state_dir: PathBuf) -> InstallSettings {
        InstallSettings { root, state_dir, allowed_roots: Vec::new(), owner: None }
    }

    /// Adds a root allowed for absolute template paths.
    pub fn allowed_root(mut self, path: PathBuf) -> InstallSettings {
        self.allowed_roots.push(path);
        self
    }

    /// Gives the file and directory owner explicitly.
    pub fn owner(mut self, uid: u32, gid: u32) -> InstallSettings {
        self.owner = Some((uid, gid));
        self
    }
}

/// Install report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    /// The installation's id (UUIDv7).
    pub install_id: String,
    /// The installed decoys and breadcrumbs (as held in the integrity record).
    pub entries: Vec<RecordEntry>,
}

/// One entry's removal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalStatus {
    /// The file the installation created was deleted.
    Removed,
    /// The existing file was restored exactly from backup (content, mode, owner, timestamps).
    Restored,
    /// The file changed after install; only the appended lines were removed.
    AppendRemoved,
    /// The file or the appended lines were already gone.
    AlreadyAbsent,
    /// The file was not touched (changed decoy, link, unreadable file); it stays in the record.
    Left {
        /// Reason.
        reason: String,
    },
}

/// One entry's removal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalResult {
    /// The decoy id.
    pub id: String,
    /// Path.
    pub path: String,
    /// The outcome.
    pub state: RemovalStatus,
}

/// The removal report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalReport {
    /// Per-entry outcomes.
    pub results: Vec<RemovalResult>,
    /// Directory warnings (a directory left because non-empty, a directory whose time was not restored).
    pub warnings: Vec<String>,
}

impl RemovalReport {
    /// Were all entries removed? If false, the leftovers stay in the record; removal is re-run
    /// after an administrator inspects them.
    pub fn completed(&self) -> bool {
        !self.results.iter().any(|s| matches!(s.state, RemovalStatus::Left { .. }))
    }
}

/// One entry's integrity state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// The same as recorded.
    Intact,
    /// Changed.
    Changed {
        /// What changed (content, mode, owner, timestamps, kind...).
        reasons: Vec<String>,
    },
    /// The file does not exist.
    Missing,
}

/// One entry's integrity outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityResult {
    /// The decoy id.
    pub id: String,
    /// Path.
    pub path: String,
    /// A decoy or a breadcrumb.
    pub kind: DecoyKind,
    /// StateDir.
    pub state: IntegrityStatus,
}

/// The integrity report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityReport {
    /// Per-entry outcomes.
    pub results: Vec<IntegrityResult>,
}

impl IntegrityReport {
    /// Are all entries intact?
    pub fn intact(&self) -> bool {
        self.results.iter().all(|s| s.state == IntegrityStatus::Intact)
    }
}

// ---------------------------------------------------------------------------------------------
// Settings and platform
// ---------------------------------------------------------------------------------------------

fn settings_error(reason: String) -> InstallError {
    InstallError::Settings(reason)
}

fn is_nested(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Off Linux (a development machine), install and removal happen only under the temp directory:
/// a decoy cannot be installed into a real home directory by accident (ADR-0004).
#[cfg(not(target_os = "linux"))]
fn check_platform(paths: &[&Path]) -> Result<(), InstallError> {
    let temp_root =
        std::fs::canonicalize(std::env::temp_dir()).map_err(|e| crate::safe_file::gc(Path::new("TMPDIR"), e))?;
    for y in paths {
        if !y.starts_with(&temp_root) || *y == temp_root {
            return Err(InstallError::Platform(format!(
                "{}: off Linux, decoy install and removal happen only under the temp directory ({})",
                y.display(),
                temp_root.display()
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_platform(_paths: &[&Path]) -> Result<(), InstallError> {
    Ok(())
}

fn validate_settings(a: &InstallSettings) -> Result<(), InstallError> {
    if normal_components(&a.root)?.is_empty() {
        return Err(settings_error("the root directory cannot be /".into()));
    }
    if normal_components(&a.state_dir)?.is_empty() {
        return Err(settings_error("the state directory cannot be /".into()));
    }
    for allowed in &a.allowed_roots {
        if normal_components(allowed)?.is_empty() {
            return Err(settings_error("an allowed root cannot be /".into()));
        }
    }
    for root in std::iter::once(&a.root).chain(&a.allowed_roots) {
        if is_nested(root, &a.state_dir) {
            return Err(settings_error(format!(
                "the state directory ({}) cannot nest with the root ({}): backups and the record never sit where the target user can reach them",
                a.state_dir.display(),
                root.display()
            )));
        }
    }
    let mut paths: Vec<&Path> = vec![&a.root, &a.state_dir];
    paths.extend(a.allowed_roots.iter().map(PathBuf::as_path));
    check_platform(&paths)
}

// ---------------------------------------------------------------------------------------------
// The plan (pre-check)
// ---------------------------------------------------------------------------------------------

/// A pre-existing file to append to.
struct ExistingFile {
    content: Vec<u8>,
    sha256: String,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_ns: i128,
}

struct Target {
    generated: Generation,
    /// 0: the root; i > 0: allowed_roots[i - 1].
    base: usize,
    parent_components: Vec<OsString>,
    name: OsString,
    full_path: PathBuf,
    existing: Option<ExistingFile>,
}

/// A touched directory (pre-install observation).
struct DirectoryPlan {
    to_create: bool,
    previous_mtime: Option<i128>,
    order: usize,
}

fn resolve_target(u: Generation, root: &Path, allowed: &[PathBuf]) -> Result<Target, InstallError> {
    let (absolute, components) = crate::template::path_components(&u.path)
        .map_err(|e| InstallError::UnsafeFile { path: u.path.clone(), reason: e })?;
    let (base, relative): (usize, Vec<&str>) = if absolute {
        let path = Path::new(&u.path);
        let (i, allowed) = allowed
            .iter()
            .enumerate()
            .find(|(_, k)| path.starts_with(k) && path != k.as_path())
            .ok_or_else(|| InstallError::OutsideRoot { path: u.path.clone() })?;
        let prefix = normal_components(allowed)?.len();
        (i + 1, components[prefix..].to_vec())
    } else {
        (0, components)
    };
    let (name, parent) = relative.split_last().ok_or_else(|| InstallError::OutsideRoot { path: u.path.clone() })?;
    let base_path = if base == 0 { root } else { allowed[base - 1].as_path() };
    let parent_components: Vec<OsString> = parent.iter().map(OsString::from).collect();
    let full_path = parent.iter().fold(base_path.to_path_buf(), |y, b| y.join(b)).join(name);
    let name = OsString::from(name);
    Ok(Target { generated: u, base, parent_components, name, full_path, existing: None })
}

/// Opens the chain from the base to the parent directory. Returns: (the deepest existing
/// directory, the number of existing components).
fn open_chain(base: &DirHandle, components: &[OsString]) -> Result<(Option<DirHandle>, usize), InstallError> {
    let mut last: Option<DirHandle> = None;
    for (i, b) in components.iter().enumerate() {
        let parent = last.as_ref().unwrap_or(base);
        match subdirectory(parent, b)? {
            Some(d) => last = Some(d),
            None => return Ok((last, i)),
        }
    }
    Ok((last, components.len()))
}

fn pre_check(
    targets: &mut [Target],
    bases: &[DirHandle],
    owner: Owner,
) -> Result<BTreeMap<PathBuf, DirectoryPlan>, InstallError> {
    let mut directories: BTreeMap<PathBuf, DirectoryPlan> = BTreeMap::new();
    let mut order = 0;
    for h in targets.iter_mut() {
        let base = &bases[h.base];
        let (last, existing_count) = open_chain(base, &h.parent_components)?;
        let deepest = last.as_ref().unwrap_or(base);
        // The deepest existing directory will change with this install; its previous time is observed once.
        if !directories.contains_key(deepest.path()) {
            directories.insert(
                deepest.path().to_path_buf(),
                DirectoryPlan { to_create: false, previous_mtime: Some(deepest.mtime_ns()?), order },
            );
            order += 1;
        }
        let mut path = deepest.path().to_path_buf();
        for b in &h.parent_components[existing_count..] {
            path.push(b);
            directories.entry(path.clone()).or_insert_with(|| DirectoryPlan {
                to_create: true,
                previous_mtime: None,
                order: usize::MAX,
            });
            if let Some(p) = directories.get_mut(&path)
                && p.order == usize::MAX
            {
                p.order = order;
                order += 1;
            }
        }
        if existing_count < h.parent_components.len() {
            continue;
        }
        let full = h.full_path.display().to_string();
        match (entry_kind(deepest, &h.name)?, h.generated.placement) {
            (None, _) => {}
            (Some(FileType::Symlink), _) => return Err(InstallError::Symlink { path: full }),
            (Some(_), Placement::NewFile) => return Err(InstallError::TargetExists { path: full }),
            (Some(FileType::RegularFile), Placement::Append) => {
                let file_read = read_file(deepest, &h.name, MAX_APPEND_TARGET)?;
                let m = &file_read.meta;
                if m.nlink() != 1 {
                    return Err(InstallError::UnsafeFile {
                        path: full,
                        reason: "a hard-linked file (another file's content could leak into the backup and the target)"
                            .into(),
                    });
                }
                if m.uid() != owner.uid {
                    return Err(InstallError::UnsafeFile {
                        path: full,
                        reason: format!("the file's owner ({}) is not the target user ({})", m.uid(), owner.uid),
                    });
                }
                h.existing = Some(ExistingFile {
                    sha256: sha256_hex(&file_read.content),
                    mode: m.permissions().mode() & 0o7777,
                    uid: m.uid(),
                    gid: m.gid(),
                    mtime_ns: mtime_ns(m),
                    content: file_read.content,
                });
            }
            (Some(_), Placement::Append) => {
                return Err(InstallError::UnsafeFile { path: full, reason: "not a regular file".into() });
            }
        }
    }
    Ok(directories)
}

fn timestamp(ns: i128) -> Result<Timestamp, InstallError> {
    Timestamp::from_unix_nanos(ns).map_err(|e| InstallError::Record(e.to_string()))
}

fn new_id() -> String {
    uuid::Uuid::now_v7().hyphenated().to_string()
}

/// The bytes to append: a leading newline if the existing file does not end with one.
fn to_append(previous: Option<&[u8]>, block: &str) -> String {
    match previous {
        Some(o) if !o.is_empty() && !o.ends_with(b"\n") => format!("\n{block}"),
        _ => block.to_string(),
    }
}

/// The pre-write record entry (with expected values).
fn pre_record_entry(h: &Target, owner: Owner) -> Result<RecordEntry, InstallError> {
    let u = &h.generated;
    let common = |sha256: String, size: usize, mode: u32, s: Owner, mtime: i128, append: Option<AppendInfo>| {
        Ok::<_, InstallError>(RecordEntry {
            id: new_id(),
            template: u.template.clone(),
            kind: u.kind,
            class: u.class.clone(),
            path: h.full_path.display().to_string(),
            placement: u.placement,
            sha256,
            size: size as u64,
            mode,
            uid: s.uid,
            gid: s.gid,
            mtime: timestamp(mtime)?,
            append,
        })
    };
    let mtime = u.mtime.unix_nanos();
    match (&h.existing, u.placement) {
        (_, Placement::NewFile) => {
            common(sha256_hex(u.content.as_bytes()), u.content.len(), u.mode, owner, mtime, None)
        }
        (None, Placement::Append) => common(
            sha256_hex(u.content.as_bytes()),
            u.content.len(),
            u.mode,
            owner,
            mtime,
            Some(AppendInfo { appended: u.content.clone(), previous: None }),
        ),
        (Some(v), Placement::Append) => {
            let appended = to_append(Some(&v.content), &u.content);
            let mut new = v.content.clone();
            new.extend_from_slice(appended.as_bytes());
            let previous = PreviousFile {
                backup: new_id(),
                sha256: v.sha256.clone(),
                size: v.content.len() as u64,
                mode: v.mode,
                uid: v.uid,
                gid: v.gid,
                mtime: timestamp(v.mtime_ns)?,
            };
            common(
                sha256_hex(&new),
                new.len(),
                v.mode,
                Owner { uid: v.uid, gid: v.gid },
                v.mtime_ns,
                Some(AppendInfo { appended, previous: Some(previous) }),
            )
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------------------------

/// Installs a package: writes the decoys and breadcrumbs safely under the root (and the
/// allowed roots), and writes the integrity record to the state directory.
pub fn install(package: &Package, settings: &InstallSettings) -> Result<InstallReport, InstallError> {
    validate_settings(settings)?;
    if let Some(d) = open_state_dir(&settings.state_dir, false, false)?
        && d.read_record()?.is_some()
    {
        return Err(InstallError::AlreadyInstalled);
    }
    let root = open_absolute_dir(&settings.root)?;
    let mut bases = vec![root];
    for allowed in &settings.allowed_roots {
        bases.push(open_absolute_dir(allowed)?);
    }
    let owner = match settings.owner {
        Some((uid, gid)) => Owner { uid, gid },
        None => {
            let m = bases[0].meta()?;
            Owner { uid: m.uid(), gid: m.gid() }
        }
    };
    let mut targets = generate(package)?
        .into_iter()
        .map(|u| resolve_target(u, &settings.root, &settings.allowed_roots))
        .collect::<Result<Vec<_>, _>>()?;
    let directory_plan = pre_check(&mut targets, &bases, owner)?;

    let state = open_state_dir(&settings.state_dir, true, true)?.ok_or(InstallError::NotInstalled)?;
    if state.read_record()?.is_some() {
        return Err(InstallError::AlreadyInstalled);
    }
    let mut entries = Vec::with_capacity(targets.len());
    for h in &targets {
        entries.push(pre_record_entry(h, owner)?);
    }
    let mut directories: Vec<(&PathBuf, &DirectoryPlan)> = directory_plan.iter().collect();
    directories.sort_by_key(|(_, p)| p.order);
    let mut record = Record {
        version: RECORD_VERSION,
        install_id: new_id(),
        installed_at: Timestamp::now(),
        root: settings.root.display().to_string(),
        completed: false,
        state_created: state.created,
        entries,
        directories: directories
            .iter()
            .map(|(y, p)| {
                Ok(DirectoryRecord {
                    path: y.display().to_string(),
                    created: p.to_create,
                    previous_mtime: p.previous_mtime.map(timestamp).transpose()?,
                    after_mtime: None,
                })
            })
            .collect::<Result<Vec<_>, InstallError>>()?,
    };
    match apply(&state, &mut record, &targets, &bases, owner) {
        Ok(()) => Ok(InstallReport { install_id: record.install_id, entries: record.entries }),
        Err(e) => {
            rollback(state, &record);
            Err(e)
        }
    }
}

/// Writes the backups and the record, places the files, sets directory times, completes the record.
fn apply(
    state: &StateDir,
    record: &mut Record,
    targets: &[Target],
    bases: &[DirHandle],
    owner: Owner,
) -> Result<(), InstallError> {
    for (h, g) in targets.iter().zip(&record.entries) {
        if let (Some(v), Some(AppendInfo { previous: Some(o), .. })) = (&h.existing, &g.append) {
            state.write_backup(&o.backup, &v.content)?;
        }
    }
    state.dir.sync_all()?;
    state.write_record(record)?;

    for (h, g) in targets.iter().zip(record.entries.iter_mut()) {
        let parent = create_directories(&bases[h.base], &h.parent_components, owner)?;
        let meta = match (&h.existing, &g.append) {
            (Some(v), Some(append)) => {
                let current = read_file(&parent, &h.name, MAX_APPEND_TARGET)?;
                if sha256_hex(&current.content) != v.sha256 || current.meta.nlink() != 1 {
                    return Err(InstallError::UnsafeFile {
                        path: g.path.clone(),
                        reason: "the file changed after the pre-check; the install was rolled back".into(),
                    });
                }
                let mut new = v.content.clone();
                new.extend_from_slice(append.appended.as_bytes());
                let d = NewFile {
                    content: &new,
                    mode: v.mode,
                    owner: Owner { uid: v.uid, gid: v.gid },
                    mtime_ns: v.mtime_ns,
                };
                replace_file(&parent, &h.name, &d)?
            }
            _ => {
                let d = NewFile {
                    content: h.generated.content.as_bytes(),
                    mode: h.generated.mode,
                    owner,
                    mtime_ns: h.generated.mtime.unix_nanos(),
                };
                write_new_file(&parent, &h.name, &d)?
            }
        };
        g.size = meta.len();
        g.mode = meta.permissions().mode() & 0o7777;
        g.uid = meta.uid();
        g.gid = meta.gid();
        g.mtime = timestamp(mtime_ns(&meta))?;
    }
    set_directory_times(record)?;
    record.completed = true;
    state.write_record(record)
}

/// Creates the missing directories from the base to the parent, 0700 with the target owner.
fn create_directories(base: &DirHandle, components: &[OsString], owner: Owner) -> Result<DirHandle, InstallError> {
    let mut last: Option<DirHandle> = None;
    for b in components {
        let parent = last.as_ref().unwrap_or(base);
        let next = match subdirectory(parent, b)? {
            Some(d) => d,
            None => create_directory(parent, b, owner)?.0,
        };
        last = Some(next);
    }
    match last {
        Some(d) => Ok(d),
        None => open_absolute_dir(base.path()),
    }
}

/// Gives created directories a natural timestamp (slightly after their newest entry) and
/// preserves the times of touched existing directories (advancing only if a new entry was added
/// and is newer). Starts from the deepest directory; the later times are written to the record.
fn set_directory_times(record: &mut Record) -> Result<(), InstallError> {
    let mut r = Random::new();
    let mut order: Vec<usize> = (0..record.directories.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(Path::new(&record.directories[i].path).components().count()));
    let mut new_times: BTreeMap<PathBuf, i128> = BTreeMap::new();
    for g in &record.entries {
        if g.append.as_ref().is_none_or(|e| e.previous.is_none()) {
            new_times.insert(PathBuf::from(&g.path), g.mtime.unix_nanos());
        }
    }
    for i in order {
        let path = PathBuf::from(&record.directories[i].path);
        let children = new_times.iter().filter(|(c, _)| c.parent() == Some(path.as_path())).map(|(_, t)| *t).max();
        let random = |r: &mut Random, a: u64, b: u64| r.range(a, b).map_err(|e| InstallError::Generation(e.into()));
        let jitter = i128::from(random(&mut r, 1, 90)?) * 1_000_000_000 + i128::from(random(&mut r, 0, 999_999_999)?);
        let d = &record.directories[i];
        let target = match (d.created, d.previous_mtime.map(|z| z.unix_nanos()), children) {
            (true, _, Some(c)) => c + jitter,
            (true, _, None) => now_ns(),
            (false, Some(o), Some(c)) => o.max(c + jitter),
            (false, Some(o), None) => o,
            (false, None, _) => continue,
        };
        let dir = open_absolute_dir(&path)?;
        dir.set_mtime(target)?;
        let real = dir.mtime_ns()?;
        if record.directories[i].created {
            new_times.insert(path.clone(), real);
        }
        record.directories[i].after_mtime = Some(timestamp(real)?);
    }
    Ok(())
}

/// Rolls back a failed install: written files are removed, directory times restored, the record
/// and backups deleted. Rollback errors are swallowed (the real error is returned); if anything
/// remains, the record stays in the state directory and is cleaned with `koru decoy uninstall`.
fn rollback(state: StateDir, record: &Record) {
    let (_, remaining) = uninstall_inner(&state, record, true);
    match remaining {
        None => {
            let _ = state.clean(record.state_created);
        }
        Some(k) => {
            let _ = state.write_record(&k);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Removal
// ---------------------------------------------------------------------------------------------

/// Removes the appended block at the end of the file. If the block cannot be found whole (the
/// file was rewritten meanwhile), its lines are removed one by one from the end. Nothing
/// is found, returns `None`.
fn strip_appended(content: &[u8], block: &[u8]) -> Option<Vec<u8>> {
    if block.is_empty() || content.len() < block.iter().filter(|b| **b != b'\n').count() {
        return None;
    }
    if let Some(i) = (0..=content.len().saturating_sub(block.len())).rev().find(|&i| content[i..].starts_with(block)) {
        let mut result = content[..i].to_vec();
        result.extend_from_slice(&content[i + block.len()..]);
        return Some(result);
    }
    let mut lines: Vec<&[u8]> = content.split_inclusive(|b| *b == b'\n').collect();
    let mut removed = 0;
    for block_line in block.split(|b| *b == b'\n').filter(|s| !s.is_empty()).rev() {
        if let Some(i) = lines.iter().rposition(|s| s.strip_suffix(b"\n").unwrap_or(s) == block_line) {
            lines.remove(i);
            removed += 1;
        }
    }
    (removed > 0).then(|| lines.concat())
}

fn left(reason: impl Into<String>) -> RemovalStatus {
    RemovalStatus::Left { reason: reason.into() }
}

fn path_parts(path: &str) -> Option<(&Path, &OsStr)> {
    let p = Path::new(path);
    Some((p.parent()?, p.file_name()?))
}

/// Opens the recorded entry's file. On `Err` the file is not touched.
fn entry_file(g: &RecordEntry) -> Result<Option<(DirHandle, crate::safe_file::ReadFile)>, String> {
    let (parent_path, name) = path_parts(&g.path).ok_or("an invalid path")?;
    let parent = match open_absolute_dir_if_exists(parent_path) {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(None),
        Err(InstallError::Symlink { path }) => return Err(format!("a symlink on the path ({path})")),
        Err(e) => return Err(e.to_string()),
    };
    match entry_kind(&parent, name).map_err(|e| e.to_string())? {
        None => return Ok(None),
        Some(FileType::RegularFile) => {}
        Some(FileType::Symlink) => return Err("turned into a symlink".into()),
        Some(_) => return Err("not a regular file".into()),
    }
    let file_read = read_file(&parent, name, MAX_APPEND_TARGET).map_err(|e| e.to_string())?;
    Ok(Some((parent, file_read)))
}

/// The pre-check before rewriting an existing file (removing appended lines, restoring from
/// backup); the same as the install-time append-target check (KT-47). The file must be regular,
/// single-linked (`nlink == 1`), and owned by the recorded (target) user. Rewriting a
/// hard-linked file would leave the old content (breadcrumb lines included) under the other
/// name; a re-owned file's content would move into a new file owned by the wrong user.
fn is_rewritable(m: &Metadata, uid: u32) -> Result<(), String> {
    if !m.file_type().is_file() {
        return Err("not a regular file".to_string());
    }
    if m.nlink() != 1 {
        return Err(format!("a hard-linked file (link count {})", m.nlink()));
    }
    if m.uid() != uid {
        return Err(format!("owner mismatch: the file's owner ({}) is not the recorded user ({})", m.uid(), uid));
    }
    Ok(())
}

fn remove_entry(state: &StateDir, g: &RecordEntry) -> RemovalStatus {
    let (parent, file_read) = match entry_file(g) {
        Ok(Some(d)) => d,
        Ok(None) => return RemovalStatus::AlreadyAbsent,
        Err(reason) => return left(format!("{reason}; not touched")),
    };
    let Some((_, name)) = path_parts(&g.path) else {
        return left("an invalid path");
    };
    let sha = sha256_hex(&file_read.content);
    let result: Result<RemovalStatus, InstallError> = (|| match &g.append {
        None if sha == g.sha256 => remove_file(&parent, name).map(|()| RemovalStatus::Removed),
        None => Ok(left("the content changed after install; a changed decoy is never deleted blindly, inspect it")),
        Some(append) if sha == g.sha256 => match &append.previous {
            None => remove_file(&parent, name).map(|()| RemovalStatus::Removed),
            Some(o) => {
                if let Err(reason) = is_rewritable(&file_read.meta, g.uid) {
                    return Ok(left(format!("{reason}; not touched")));
                }
                let backup = state.read_backup(&o.backup, &o.sha256)?;
                let d = NewFile {
                    content: &backup,
                    mode: o.mode,
                    owner: Owner { uid: o.uid, gid: o.gid },
                    mtime_ns: o.mtime.unix_nanos(),
                };
                replace_file(&parent, name, &d).map(|_| RemovalStatus::Restored)
            }
        },
        Some(append) if append.previous.as_ref().is_some_and(|o| o.sha256 == sha) => Ok(RemovalStatus::AlreadyAbsent),
        Some(append) => match strip_appended(&file_read.content, append.appended.as_bytes()) {
            None => Ok(RemovalStatus::AlreadyAbsent),
            Some(new) if new.is_empty() && append.previous.is_none() => {
                remove_file(&parent, name).map(|()| RemovalStatus::Removed)
            }
            Some(new) => {
                let m = &file_read.meta;
                if let Err(reason) = is_rewritable(m, g.uid) {
                    return Ok(left(format!("{reason}; not touched")));
                }
                let d = NewFile {
                    content: &new,
                    mode: m.permissions().mode() & 0o7777,
                    owner: Owner { uid: m.uid(), gid: m.gid() },
                    mtime_ns: mtime_ns(m),
                };
                replace_file(&parent, name, &d).map(|_| RemovalStatus::AppendRemoved)
            }
        },
    })();
    result.unwrap_or_else(|e| left(format!("the operation failed: {e}")))
}

/// The removal core (removal, and rolling back a failed install). Returns: the report and the
/// remaining record (`None` if everything was removed). If `rollback` is true, touched
/// directory times are restored unconditionally (the install made them new).
fn uninstall_inner(state: &StateDir, record: &Record, rollback: bool) -> (RemovalReport, Option<Record>) {
    // Were the touched existing directories changed by someone else after install?
    let matched: Vec<bool> = record
        .directories
        .iter()
        .map(|d| {
            !d.created
                && d.previous_mtime.is_some()
                && (rollback
                    || open_absolute_dir_if_exists(Path::new(&d.path)).ok().flatten().and_then(|h| h.mtime_ns().ok())
                        == d.after_mtime.map(|z| z.unix_nanos()))
        })
        .collect();

    let mut results = Vec::with_capacity(record.entries.len());
    let mut remaining_entries = Vec::new();
    for g in record.entries.iter().rev() {
        let result = remove_entry(state, g);
        if matches!(result, RemovalStatus::Left { .. }) {
            remaining_entries.push(g.clone());
        } else if let Some(o) = g.append.as_ref().and_then(|e| e.previous.as_ref()) {
            let _ = state.remove_backup(&o.backup);
        }
        results.push(RemovalResult { id: g.id.clone(), path: g.path.clone(), state: result });
    }
    results.reverse();
    remaining_entries.reverse();

    let mut warnings = Vec::new();
    let mut order: Vec<usize> = (0..record.directories.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(Path::new(&record.directories[i].path).components().count()));
    let mut remaining_dir = vec![false; record.directories.len()];
    for &i in &order {
        let d = &record.directories[i];
        if !d.created {
            continue;
        }
        let deleted = match path_parts(&d.path) {
            Some((parent_path, name)) => match open_absolute_dir_if_exists(parent_path) {
                Ok(Some(parent)) => remove_empty_dir(&parent, name).unwrap_or(false),
                Ok(None) => true,
                Err(_) => false,
            },
            None => false,
        };
        if !deleted {
            warnings.push(format!("{}: the directory is not empty or could not be removed; left in place", d.path));
            remaining_dir[i] = true;
        }
    }

    let complete = remaining_entries.is_empty() && !remaining_dir.iter().any(|k| *k);
    let mut remaining_dirs = Vec::new();
    for &i in &order {
        let d = &record.directories[i];
        if d.created {
            if remaining_dir[i] {
                remaining_dirs.push((i, d.clone()));
            }
            continue;
        }
        let ac = || open_absolute_dir_if_exists(Path::new(&d.path)).ok().flatten();
        if complete {
            match (matched[i], d.previous_mtime) {
                (true, Some(o)) => {
                    if ac().and_then(|h| h.set_mtime(o.unix_nanos()).ok()).is_none() {
                        warnings.push(format!("{}: the directory time could not be restored", d.path));
                    }
                }
                (false, Some(_)) => {
                    warnings
                        .push(format!("{}: the directory changed after install; its time was not restored", d.path));
                }
                _ => {}
            }
        } else {
            let mut new = d.clone();
            if matched[i] {
                new.after_mtime = ac().and_then(|h| h.mtime_ns().ok()).and_then(|t| Timestamp::from_unix_nanos(t).ok());
            } else {
                new.previous_mtime = None;
            }
            remaining_dirs.push((i, new));
        }
    }
    remaining_dirs.sort_by_key(|(i, _)| *i);

    let report = RemovalReport { results, warnings };
    if complete {
        (report, None)
    } else {
        let remaining = Record {
            entries: remaining_entries,
            directories: remaining_dirs.into_iter().map(|(_, d)| d).collect(),
            ..record.clone()
        };
        (report, Some(remaining))
    }
}

/// Uninstalls. Touches nothing beyond the recorded files; never deletes changed decoys, but
/// reports them and leaves them in the record.
pub fn uninstall(state: &Path) -> Result<RemovalReport, InstallError> {
    normal_components(state)?;
    check_platform(&[state])?;
    let d = open_state_dir(state, false, true)?.ok_or(InstallError::NotInstalled)?;
    let record = d.read_record()?.ok_or(InstallError::NotInstalled)?;
    let (report, remaining) = uninstall_inner(&d, &record, false);
    match remaining {
        None => d.clean(record.state_created)?,
        Some(k) => d.write_record(&k)?,
    }
    Ok(report)
}

// ---------------------------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------------------------

fn read_record_only(state: &Path) -> Result<Record, InstallError> {
    let d = open_state_dir(state, false, false)?.ok_or(InstallError::NotInstalled)?;
    d.read_record()?.ok_or(InstallError::NotInstalled)
}

/// The installed decoys and breadcrumbs (the integrity record).
pub fn list_entries(state: &Path) -> Result<Vec<RecordEntry>, InstallError> {
    Ok(read_record_only(state)?.entries)
}

fn check_entry(g: &RecordEntry) -> IntegrityStatus {
    let file_read = match entry_file(g) {
        Ok(Some((_, o))) => o,
        Ok(None) => return IntegrityStatus::Missing,
        Err(reason) => return IntegrityStatus::Changed { reasons: vec![reason] },
    };
    let mut reasons = Vec::new();
    match &g.append {
        Some(append) => {
            let block = append.appended.trim_start_matches('\n').as_bytes();
            if !file_read.content.windows(block.len().max(1)).any(|p| p == block) {
                reasons.push("the appended lines were not found".to_string());
            }
        }
        None => {
            if sha256_hex(&file_read.content) != g.sha256 {
                reasons.push("content (SHA-256)".to_string());
            }
            if mtime_ns(&file_read.meta) != g.mtime.unix_nanos() {
                reasons.push("mtime".to_string());
            }
        }
    }
    if file_read.meta.permissions().mode() & 0o7777 != g.mode {
        reasons.push("mode".to_string());
    }
    if (file_read.meta.uid(), file_read.meta.gid()) != (g.uid, g.gid) {
        reasons.push("owner".to_string());
    }
    if reasons.is_empty() { IntegrityStatus::Intact } else { IntegrityStatus::Changed { reasons } }
}

/// Compares every recorded entry against its on-disk state. For new-file decoys, the content
/// hash, mode, owner, and timestamps; for appends (the user keeps writing to the file), the
/// appended block's presence, mode, and owner are checked.
pub fn integrity(state: &Path) -> Result<IntegrityReport, InstallError> {
    let record = read_record_only(state)?;
    let results = record
        .entries
        .iter()
        .map(|g| IntegrityResult { id: g.id.clone(), path: g.path.clone(), kind: g.kind, state: check_entry(g) })
        .collect();
    Ok(IntegrityReport { results })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appended_block_is_removed() {
        assert_eq!(strip_appended(b"a\nb\nX\nY\nc\n", b"X\nY\n").unwrap(), b"a\nb\nc\n");
        assert_eq!(strip_appended(b"a\nY\nb\nX\n", b"X\nY\n").unwrap(), b"a\nb\n");
        assert!(strip_appended(b"a\nb\n", b"X\nY\n").is_none());
        assert_eq!(strip_appended(b"a\nX\n", b"\nX\n").unwrap(), b"a");
        assert_eq!(to_append(Some(b"a"), "X\n"), "\nX\n");
        assert_eq!(to_append(Some(b"a\n"), "X\n"), "X\n");
        assert_eq!(to_append(None, "X\n"), "X\n");
    }
}
