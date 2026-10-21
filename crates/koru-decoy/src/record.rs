//! The integrity record and the state directory (ADR-0004 "State directory and integrity record").
//!
//! The state directory lives in a configurable place (e.g. `/var/lib/<neutral name>`); its name
//! and contents never reveal Koru to an attacker, and it cannot nest inside the root (the target
//! home directory) or the allowed roots. The directory is open only to the user running Koru
//! (0700); the record and the backups are 0600.
//!
//! - `record.json`: the installation's integrity record (per decoy: id, path, SHA-256, size,
//!   mode, owner, mtime; for appends, the appended block and the previous state summary).
//! - `backups/<uuid>`: exact copies of existing files taken before an append. Names are random;
//!   they never carry the original file name.

use std::ffi::OsStr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use koru_event::Timestamp;
use serde::{Deserialize, Serialize};

use crate::error::InstallError;
use crate::safe_file::{
    self, DirHandle, NewFile, Owner, create_directory, entry_kind, lock_file, normal_components,
    open_absolute_dir_if_exists, read_file, remove_empty_dir, remove_file, replace_file, sha256_hex, subdirectory,
    write_new_file,
};
use crate::template::{DecoyKind, Placement};

/// The version of the record format.
pub(crate) const RECORD_VERSION: u32 = 1;
const RECORD_FILE: &str = "record.json";
const BACKUP_DIR: &str = "backups";
const MAX_RECORD: u64 = 64 * 1024 * 1024;
/// The maximum size of a file to append to (and back up).
pub(crate) const MAX_APPEND_TARGET: u64 = 16 * 1024 * 1024;

/// One decoy or breadcrumb in the integrity record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordEntry {
    /// The decoy's unique id (UUIDv7); never visible in content.
    pub id: String,
    /// The template id.
    pub template: String,
    /// A decoy or a breadcrumb.
    pub kind: DecoyKind,
    /// The class label.
    pub class: String,
    /// Absolute path.
    pub path: String,
    /// The placement form.
    pub placement: Placement,
    /// The SHA-256 of the post-install content.
    pub sha256: String,
    /// Size after installation.
    pub size: u64,
    /// Mode.
    pub mode: u32,
    /// The owner user.
    pub uid: u32,
    /// Owner group.
    pub gid: u32,
    /// The mtime (the natural timestamp, or the preserved mtime of an existing file).
    pub mtime: Timestamp,
    /// If the placement is `append`, the appended block and the previous state.
    pub append: Option<AppendInfo>,
}

/// An append to an existing (or created) file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendInfo {
    /// All appended bytes (with a leading newline if needed).
    pub appended: String,
    /// The previous state if the file existed before install; otherwise `None` (install created it).
    pub previous: Option<PreviousFile>,
}

/// The file before the append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousFile {
    /// The backup's name in the state directory (under `backups/`, random).
    pub backup: String,
    /// The SHA-256 of the previous content.
    pub sha256: String,
    /// The previous size.
    pub size: u64,
    /// The previous mode.
    pub mode: u32,
    /// The previous owner user.
    pub uid: u32,
    /// The previous owner group.
    pub gid: u32,
    /// The previous mtime.
    pub mtime: Timestamp,
}

/// A directory the installation touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryRecord {
    /// Absolute path.
    pub(crate) path: String,
    /// Did the installation create it? (Removed on uninstall if empty.)
    pub(crate) created: bool,
    /// The pre-install mtime of a pre-existing directory; absent if it will not be restored.
    pub(crate) previous_mtime: Option<Timestamp>,
    /// The mtime right after install (or the last partial removal).
    pub(crate) after_mtime: Option<Timestamp>,
}

/// The integrity record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub(crate) version: u32,
    pub(crate) install_id: String,
    pub(crate) installed_at: Timestamp,
    pub(crate) root: String,
    /// A pre-write record (`false`) or a completed installation.
    pub(crate) completed: bool,
    pub(crate) state_created: bool,
    pub(crate) entries: Vec<RecordEntry>,
    /// Directories created or touched by the installation. Older records used the key `dizinler`.
    #[serde(alias = "dizinler")]
    pub(crate) directories: Vec<DirectoryRecord>,
}

pub(crate) fn now_ns() -> i128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as i128)
}

/// An open and locked state directory.
pub(crate) struct StateDir {
    parent: DirHandle,
    pub(crate) dir: DirHandle,
    /// Did this open create the directory?
    pub(crate) created: bool,
}

/// Opens the state directory (creating it 0700 if needed) and locks it. If `create` is false
/// and the directory is absent, returns `None`; nothing is created.
pub(crate) fn open_state_dir(
    path: &Path,
    create: bool,
    exclusive_lock: bool,
) -> Result<Option<StateDir>, InstallError> {
    let components = normal_components(path)?;
    let (Some(name), Some(parent_path)) = (components.last(), path.parent()) else {
        return Err(InstallError::Settings("the state directory cannot be /".into()));
    };
    let Some(parent) = open_absolute_dir_if_exists(parent_path)? else {
        return if create { Err(safe_file::gc(parent_path, std::io::ErrorKind::NotFound)) } else { Ok(None) };
    };
    let euid = safe_file::effective_uid();
    let (dir, created) = match subdirectory(&parent, name)? {
        Some(d) => (d, false),
        None if create => {
            let gid = rustix::process::getegid().as_raw();
            create_directory(&parent, name, Owner { uid: euid, gid })?
        }
        None => return Ok(None),
    };
    let m = dir.meta()?;
    if m.uid() != euid || m.permissions().mode() & 0o077 != 0 {
        return Err(InstallError::UnsafeFile {
            path: path.display().to_string(),
            reason: "the state directory must belong to the user running Koru and be open only to them (0700)".into(),
        });
    }
    lock_file(&dir, exclusive_lock)?;
    Ok(Some(StateDir { parent, dir, created }))
}

impl StateDir {
    fn owner(&self) -> Result<Owner, InstallError> {
        let m = self.dir.meta()?;
        Ok(Owner { uid: m.uid(), gid: m.gid() })
    }

    pub(crate) fn read_record(&self) -> Result<Option<Record>, InstallError> {
        let name = OsStr::new(RECORD_FILE);
        if entry_kind(&self.dir, name)?.is_none() {
            return Ok(None);
        }
        let file_read = read_file(&self.dir, name, MAX_RECORD)?;
        let record: Record =
            serde_json::from_slice(&file_read.content).map_err(|e| InstallError::Record(e.to_string()))?;
        if record.version != RECORD_VERSION {
            return Err(InstallError::Record(format!("unsupported record version {}", record.version)));
        }
        Ok(Some(record))
    }

    pub(crate) fn write_record(&self, record: &Record) -> Result<(), InstallError> {
        let data = serde_json::to_vec_pretty(record).map_err(|e| InstallError::Record(e.to_string()))?;
        let d = NewFile { content: &data, mode: 0o600, owner: self.owner()?, mtime_ns: now_ns() };
        replace_file(&self.dir, OsStr::new(RECORD_FILE), &d)?;
        Ok(())
    }

    fn backup_dir(&self, create: bool) -> Result<Option<DirHandle>, InstallError> {
        let name = OsStr::new(BACKUP_DIR);
        match subdirectory(&self.dir, name)? {
            Some(d) => Ok(Some(d)),
            None if create => Ok(Some(create_directory(&self.dir, name, self.owner()?)?.0)),
            None => Ok(None),
        }
    }

    /// Writes the backup (0600, only if absent).
    pub(crate) fn write_backup(&self, name: &str, content: &[u8]) -> Result<(), InstallError> {
        let dir = self
            .backup_dir(true)?
            .ok_or_else(|| InstallError::Record("the backup directory could not be opened".into()))?;
        let d = NewFile { content, mode: 0o600, owner: self.owner()?, mtime_ns: now_ns() };
        write_new_file(&dir, OsStr::new(name), &d)?;
        Ok(())
    }

    /// Reads the backup and compares it with the recorded hash.
    pub(crate) fn read_backup(&self, name: &str, sha256: &str) -> Result<Vec<u8>, InstallError> {
        let dir = self.backup_dir(false)?.ok_or_else(|| InstallError::Record("backup directory is missing".into()))?;
        let file_read = read_file(&dir, OsStr::new(name), MAX_APPEND_TARGET)?;
        if sha256_hex(&file_read.content) != sha256 {
            return Err(InstallError::Record(format!("backup {name} does not match the recorded hash")));
        }
        Ok(file_read.content)
    }

    pub(crate) fn remove_backup(&self, name: &str) -> Result<(), InstallError> {
        if let Some(dir) = self.backup_dir(false)? {
            remove_file(&dir, OsStr::new(name))?;
        }
        Ok(())
    }

    /// When the installation is fully removed: the record and the empty backup directory are
    /// deleted; the state directory too, if the installation created it and it is empty.
    pub(crate) fn clean(self, state_created: bool) -> Result<(), InstallError> {
        remove_file(&self.dir, OsStr::new(RECORD_FILE))?;
        remove_empty_dir(&self.dir, OsStr::new(BACKUP_DIR))?;
        self.dir.sync_all()?;
        if state_created && let Some(name) = self.dir.path().file_name() {
            let name = name.to_os_string();
            drop(self.dir);
            remove_empty_dir(&self.parent, &name)?;
        }
        Ok(())
    }
}
