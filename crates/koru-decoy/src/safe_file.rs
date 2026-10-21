//! Safe filesystem operations (ADR-0004 "Safe writing"). Because Koru may later run as root,
//! when writing into directories controlled by the target user:
//!
//! - The path is opened component by component from the root (`/`) with
//!   `openat(O_DIRECTORY | O_NOFOLLOW)`; if any component is a symlink, the operation is
//!   rejected. Every later operation is relative to the open directory handle (`*at`), so the
//!   path cannot be swapped between check and use (TOCTOU).
//! - A new file is created with `O_CREAT | O_EXCL | O_NOFOLLOW`; an existing file or link is
//!   never overwritten. Replacing an existing file writes a temp file in the same directory and
//!   renames it with `renameat` (a half-written file is never visible).
//! - A file to read is opened with `O_NOFOLLOW | O_NONBLOCK` (never blocks on a FIFO); its kind
//!   and size are checked through the open handle (`fstat`).
//! - Mode, owner, and timestamps are set through the open handle, not the path.
//!
//! No `unsafe`; system calls go through rustix's safe interface.

use std::ffi::OsStr;
use std::fs::{File, FileTimes, Metadata};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, fchown};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use crate::error::InstallError;

/// Directory open flags: a symlink is never followed.
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
/// Read flags: no symlink following, no blocking on a FIFO, no controlling terminal.
const READ_FLAGS: OFlags =
    OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::NONBLOCK).union(OFlags::CLOEXEC).union(OFlags::NOCTTY);
/// New-file flags: created only if absent, no symlink following.
const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY);

/// The owner of a file and directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Owner {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

pub(crate) fn gc(path: &Path, error: impl Into<std::io::Error>) -> InstallError {
    InstallError::Gc { path: path.display().to_string(), error: error.into() }
}

fn path_text(path: &Path) -> String {
    path.display().to_string()
}

/// SHA-256, lowercase hex.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn mtime_ns(m: &Metadata) -> i128 {
    i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec())
}

fn system_time(ns: i128) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(u64::try_from(ns).unwrap_or(0))
}

/// The effective user id.
pub(crate) fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// An open directory and (for messages) its path.
pub(crate) struct DirHandle {
    fd: OwnedFd,
    path: PathBuf,
}

impl DirHandle {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn file(&self) -> Result<File, InstallError> {
        Ok(File::from(self.fd.try_clone().map_err(|e| gc(&self.path, e))?))
    }

    pub(crate) fn meta(&self) -> Result<Metadata, InstallError> {
        self.file()?.metadata().map_err(|e| gc(&self.path, e))
    }

    pub(crate) fn mtime_ns(&self) -> Result<i128, InstallError> {
        Ok(mtime_ns(&self.meta()?))
    }

    /// Sets the mtime; never touches the atime.
    pub(crate) fn set_mtime(&self, ns: i128) -> Result<(), InstallError> {
        self.file()?.set_times(FileTimes::new().set_modified(system_time(ns))).map_err(|e| gc(&self.path, e))
    }

    /// Flushes the DirHandle entries to disk (`fsync`).
    pub(crate) fn sync_all(&self) -> Result<(), InstallError> {
        rustix::fs::fsync(&self.fd).map_err(|e| gc(&self.path, e))
    }

    pub(crate) fn subpath(&self, name: &OsStr) -> PathBuf {
        self.path.join(name)
    }
}

/// The components of an absolute, normal path; a relative path and `..` are rejected.
pub(crate) fn normal_components(path: &Path) -> Result<Vec<&OsStr>, InstallError> {
    if !path.is_absolute() {
        return Err(InstallError::Settings(format!("{}: must be an absolute path", path.display())));
    }
    let mut components = Vec::new();
    for b in path.components() {
        match b {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(InstallError::Settings(format!("{}: cannot hold a '.' or '..' component", path.display())));
            }
        }
    }
    Ok(components)
}

/// The entry's kind (without following links); `None` if absent.
pub(crate) fn entry_kind(parent: &DirHandle, name: &OsStr) -> Result<Option<FileType>, InstallError> {
    match rustix::fs::statat(&parent.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(FileType::from_raw_mode(st.st_mode))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(gc(&parent.subpath(name), e)),
    }
}

/// Opens a subdirectory without following links; `None` if absent. A link yields
/// [`InstallError::Symlink`], a non-directory [`InstallError::UnsafeFile`].
pub(crate) fn subdirectory(parent: &DirHandle, name: &OsStr) -> Result<Option<DirHandle>, InstallError> {
    let path = parent.subpath(name);
    match rustix::fs::openat(&parent.fd, name, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(Some(DirHandle { fd, path })),
        Err(open_error) => match entry_kind(parent, name)? {
            None => Ok(None),
            Some(FileType::Symlink) => Err(InstallError::Symlink { path: path_text(&path) }),
            Some(FileType::Directory) => Err(gc(&path, open_error)),
            Some(_) => {
                Err(InstallError::UnsafeFile { path: path_text(&path), reason: "a directory was expected".into() })
            }
        },
    }
}

/// Opens an absolute path from the root without following links. `None` if a component is absent.
pub(crate) fn open_absolute_dir_if_exists(path: &Path) -> Result<Option<DirHandle>, InstallError> {
    let components = normal_components(path)?;
    let root = Path::new("/");
    let fd = rustix::fs::openat(CWD, root, DIRECTORY_FLAGS, Mode::empty()).map_err(|e| gc(root, e))?;
    let mut dir = DirHandle { fd, path: root.to_path_buf() };
    for name in components {
        match subdirectory(&dir, name)? {
            Some(d) => dir = d,
            None => return Ok(None),
        }
    }
    Ok(Some(dir))
}

/// Opens an absolute path from the root without following links; an error if a component is absent.
pub(crate) fn open_absolute_dir(path: &Path) -> Result<DirHandle, InstallError> {
    open_absolute_dir_if_exists(path)?.ok_or_else(|| gc(path, std::io::ErrorKind::NotFound))
}

fn set_owner_and_mode(f: &File, path: &Path, mode: u32, owner: Owner) -> Result<(), InstallError> {
    f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(|e| gc(path, e))?;
    let m = f.metadata().map_err(|e| gc(path, e))?;
    if (m.uid(), m.gid()) != (owner.uid, owner.gid) {
        fchown(f, Some(owner.uid), Some(owner.gid)).map_err(|e| gc(path, e))?;
    }
    Ok(())
}

/// Creates a subdirectory with mode 0700 and opens it. The returned bool: did this call create
/// it? A directory someone else created concurrently keeps its mode and owner untouched.
pub(crate) fn create_directory(
    parent: &DirHandle,
    name: &OsStr,
    owner: Owner,
) -> Result<(DirHandle, bool), InstallError> {
    let path = parent.subpath(name);
    let created = match rustix::fs::mkdirat(&parent.fd, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(gc(&path, e)),
    };
    let dir = subdirectory(parent, name)?.ok_or_else(|| gc(&path, std::io::ErrorKind::NotFound))?;
    if created {
        set_owner_and_mode(&dir.file()?, &path, 0o700, owner)?;
    }
    Ok((dir, created))
}

/// The file that was read.
pub(crate) struct ReadFile {
    pub(crate) content: Vec<u8>,
    pub(crate) meta: Metadata,
}

/// Reads a regular file without following links or blocking on a FIFO; at most `max` bytes.
pub(crate) fn read_file(parent: &DirHandle, name: &OsStr, max: u64) -> Result<ReadFile, InstallError> {
    let path = parent.subpath(name);
    let fd = rustix::fs::openat(&parent.fd, name, READ_FLAGS, Mode::empty()).map_err(|e| match e {
        Errno::LOOP | Errno::MLINK => InstallError::Symlink { path: path_text(&path) },
        e => gc(&path, e),
    })?;
    let f = File::from(fd);
    let meta = f.metadata().map_err(|e| gc(&path, e))?;
    if !meta.file_type().is_file() {
        return Err(InstallError::UnsafeFile { path: path_text(&path), reason: "not a regular file".into() });
    }
    if meta.len() > max {
        return Err(InstallError::UnsafeFile { path: path_text(&path), reason: format!("larger than {max} bytes") });
    }
    let mut content = Vec::with_capacity(meta.len() as usize);
    f.take(max + 1).read_to_end(&mut content).map_err(|e| gc(&path, e))?;
    if content.len() as u64 > max {
        return Err(InstallError::UnsafeFile { path: path_text(&path), reason: "grew while being read".into() });
    }
    Ok(ReadFile { content, meta })
}

/// The properties of a file to write.
pub(crate) struct NewFile<'a> {
    pub(crate) content: &'a [u8],
    pub(crate) mode: u32,
    pub(crate) owner: Owner,
    pub(crate) mtime_ns: i128,
}

/// Creates the new file (`O_EXCL`; never overwrites an existing one) and writes it. Mode, owner,
/// and timestamps are set through the open handle; the file is synced to disk. On error the
/// created file is deleted. Returns the file's final metadata.
pub(crate) fn write_new_file(parent: &DirHandle, name: &OsStr, d: &NewFile<'_>) -> Result<Metadata, InstallError> {
    let path = parent.subpath(name);
    let fd = match rustix::fs::openat(&parent.fd, name, CREATE_FLAGS, Mode::from_raw_mode(0o600)) {
        Ok(fd) => fd,
        Err(Errno::EXIST | Errno::LOOP) => {
            return Err(match entry_kind(parent, name)? {
                Some(FileType::Symlink) => InstallError::Symlink { path: path_text(&path) },
                _ => InstallError::TargetExists { path: path_text(&path) },
            });
        }
        Err(e) => return Err(gc(&path, e)),
    };
    let mut f = File::from(fd);
    let emit = |f: &mut File| -> Result<Metadata, InstallError> {
        f.write_all(d.content).map_err(|e| gc(&path, e))?;
        set_owner_and_mode(f, &path, d.mode, d.owner)?;
        let t = system_time(d.mtime_ns);
        f.set_times(FileTimes::new().set_accessed(t).set_modified(t)).map_err(|e| gc(&path, e))?;
        f.sync_all().map_err(|e| gc(&path, e))?;
        f.metadata().map_err(|e| gc(&path, e))
    };
    match emit(&mut f) {
        Ok(m) => Ok(m),
        Err(e) => {
            remove_own_file(parent, name, &f);
            Err(e)
        }
    }
}

/// Deletes the entry at the name only if it is still the file behind the open handle (never touches somebody else's file).
fn remove_own_file(parent: &DirHandle, name: &OsStr, f: &File) {
    let (Ok(public_part), Ok(existing_stat)) =
        (rustix::fs::fstat(f), rustix::fs::statat(&parent.fd, name, AtFlags::SYMLINK_NOFOLLOW))
    else {
        return;
    };
    if public_part.st_ino == existing_stat.st_ino && public_part.st_dev == existing_stat.st_dev {
        let _ = rustix::fs::unlinkat(&parent.fd, name, AtFlags::empty());
    }
}

/// Atomically replaces an existing file: writes a temp file in the same directory, then
/// Replaces in place with `renameat` and flushes the directory to disk.
pub(crate) fn replace_file(parent: &DirHandle, name: &OsStr, d: &NewFile<'_>) -> Result<Metadata, InstallError> {
    let path = parent.subpath(name);
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|e| gc(&path, std::io::Error::other(e.to_string())))?;
    let temp_name = format!(".{}.tmp", random.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let temp_name = OsStr::new(&temp_name);
    let meta = write_new_file(parent, temp_name, d)?;
    if let Err(e) = rustix::fs::renameat(&parent.fd, temp_name, &parent.fd, name) {
        let _ = rustix::fs::unlinkat(&parent.fd, temp_name, AtFlags::empty());
        return Err(gc(&path, e));
    }
    parent.sync_all()?;
    Ok(meta)
}

/// Deletes the file (no link following; `unlinkat` removes the name itself).
pub(crate) fn remove_file(parent: &DirHandle, name: &OsStr) -> Result<(), InstallError> {
    match rustix::fs::unlinkat(&parent.fd, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(gc(&parent.subpath(name), e)),
    }
}

/// Removes an empty directory. Returns: is the directory gone? (`false` if not empty.)
pub(crate) fn remove_empty_dir(parent: &DirHandle, name: &OsStr) -> Result<bool, InstallError> {
    match rustix::fs::unlinkat(&parent.fd, name, AtFlags::REMOVEDIR) {
        Ok(()) | Err(Errno::NOENT) => Ok(true),
        Err(Errno::NOTEMPTY | Errno::EXIST | Errno::NOTDIR) => Ok(false),
        Err(e) => Err(gc(&parent.subpath(name), e)),
    }
}

/// The longest wait for the lock.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Locks the directory (`flock`). If the lock is held, it retries at short intervals for at
/// most [`LOCK_TIMEOUT`]: a child process spawned by this process can hold a copy of the handle
/// until `exec`, and can outlive the lock's release very briefly. If the timeout expires,
/// another Koru operation is running: [`InstallError::Lock`].
pub(crate) fn lock_file(d: &DirHandle, private_key: bool) -> Result<(), InstallError> {
    let operation = if private_key {
        rustix::fs::FlockOperation::NonBlockingLockExclusive
    } else {
        rustix::fs::FlockOperation::NonBlockingLockShared
    };
    let last = std::time::Instant::now() + LOCK_TIMEOUT;
    loop {
        match rustix::fs::flock(&d.fd, operation) {
            Ok(()) => return Ok(()),
            Err(Errno::WOULDBLOCK) if std::time::Instant::now() < last => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(Errno::WOULDBLOCK) => return Err(InstallError::Lock),
            Err(e) => return Err(gc(&d.path, e)),
        }
    }
}
