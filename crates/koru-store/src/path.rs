//! Safe path and file checks (ADR-0006 "File security"; ADR-0004 principles).
//!
//! - The path must be absolute and must not contain `.` or `..`.
//! - The directory chain is opened component by component from the root (`/`) with
//!   `openat(O_DIRECTORY | O_NOFOLLOW)`; if any component is a symlink the operation is rejected.
//!   Only the directory directly above the store file is created (mode 0700) when missing; a
//!   missing directory higher up is an error.
//! - The store directory must belong to the user running Koru and be closed to group and others
//!   (0700); otherwise the store is not opened (and an uncreated file is not created).
//! - A missing store file is created with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600. If it
//!   exists, a symlink is not followed; it must be a regular file owned by the same user, closed
//!   to group and others, and singly linked (leakage through a hard link, KT-47). Because the
//!   kind is checked with `fstatat` before opening, special files such as FIFOs do not block.
//!
//! `unsafe` is not used; system calls go through rustix's safe interface.

use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::StoreError;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY);

/// `st_mode` is u16 on macOS and u32 on Linux; a conversion that works on both.
fn mode(mod_: impl Into<u32>) -> u32 {
    mod_.into()
}

/// `st_nlink` is u16 on macOS, u32 on Linux/aarch64, and u64 on Linux/x86_64.
fn link_count(n: impl Into<u64>) -> u64 {
    n.into()
}

fn io(path: &Path, e: impl ToString) -> StoreError {
    StoreError::Io { path: path.display().to_string(), reason: e.to_string() }
}

fn unsafe_path_error(path: &Path, reason: &str) -> StoreError {
    StoreError::UnsafePath { path: path.display().to_string(), reason: reason.to_string() }
}

fn symlink(path: &Path) -> StoreError {
    StoreError::Symlink { path: path.display().to_string() }
}

/// The entry kind without following links; `None` when absent.
fn entry_kind(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<Option<FileType>, StoreError> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(FileType::from_raw_mode(st.st_mode))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(io(path, e)),
    }
}

/// Opens a subdirectory without following links; `None` when absent.
fn subdirectory(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<Option<OwnedFd>, StoreError> {
    match rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(open_error) => match entry_kind(parent, name, path)? {
            None => Ok(None),
            Some(FileType::Symlink) => Err(symlink(path)),
            Some(FileType::Directory) => Err(io(path, open_error)),
            Some(_) => Err(unsafe_path_error(path, "a directory was expected")),
        },
    }
}

/// Validates the store path; creates the directory and file when needed. On success the path is a
/// regular file safe to hand to SQLite.
pub(crate) fn prepare(path: &Path, must_exist: bool) -> Result<(), StoreError> {
    if !path.is_absolute() {
        return Err(unsafe_path_error(path, "the store path must be absolute"));
    }
    let mut components = Vec::new();
    for b in path.components() {
        match b {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(unsafe_path_error(path, "must not contain a '.' or '..' component"));
            }
        }
    }
    let Some((file_name, directories)) = components.split_last() else {
        return Err(unsafe_path_error(path, "the store file has no name"));
    };
    let root = Path::new("/");
    let mut dir = rustix::fs::openat(CWD, root, DIRECTORY_FLAGS, Mode::empty()).map_err(|e| io(root, e))?;
    let mut current = root.to_path_buf();
    for (i, name) in directories.iter().enumerate() {
        current.push(name);
        let last_dir = i == directories.len() - 1;
        dir = match subdirectory(&dir, name, &current)? {
            Some(d) => d,
            None if last_dir && !must_exist => create_directory(&dir, name, &current)?,
            None if must_exist => return Err(StoreError::NotFound { path: path.display().to_string() }),
            None => return Err(io(&current, "the parent directory is missing")),
        };
    }
    check_directory(&dir, &current)?;
    prepare_file(&dir, file_name, path, must_exist)
}

fn create_directory(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<OwnedFd, StoreError> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => return Err(io(path, e)),
    }
    let fd = subdirectory(parent, name, path)?.ok_or_else(|| io(path, "the created directory was not found"))?;
    // umask can narrow the mode but not widen it; 0700 is still set explicitly (through the open
    // handle). If someone else created it concurrently, the check below rejects its mode.
    let st = rustix::fs::fstat(&fd).map_err(|e| io(path, e))?;
    if st.st_uid == rustix::process::geteuid().as_raw() && mode(st.st_mode) & 0o077 != 0 {
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o700)).map_err(|e| io(path, e))?;
    }
    Ok(fd)
}

fn check_directory(dir: &OwnedFd, path: &Path) -> Result<(), StoreError> {
    let st = rustix::fs::fstat(dir).map_err(|e| io(path, e))?;
    if st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(unsafe_path_error(path, "the directory does not belong to the user running Koru"));
    }
    if mode(st.st_mode) & 0o077 != 0 {
        return Err(unsafe_path_error(path, "the directory is open to group or others (must be 0700)"));
    }
    Ok(())
}

fn prepare_file(dir: &OwnedFd, name: &OsStr, path: &Path, must_exist: bool) -> Result<(), StoreError> {
    match entry_kind(dir, name, path)? {
        None if must_exist => Err(StoreError::NotFound { path: path.display().to_string() }),
        None => match rustix::fs::openat(dir, name, CREATE_FLAGS, Mode::from_raw_mode(0o600)) {
            Ok(fd) => {
                rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(|e| io(path, e))?;
                Ok(())
            }
            Err(Errno::EXIST | Errno::LOOP) => match entry_kind(dir, name, path)? {
                Some(FileType::Symlink) => Err(symlink(path)),
                _ => Err(unsafe_path_error(path, "the store file was created concurrently")),
            },
            Err(e) => Err(io(path, e)),
        },
        Some(FileType::Symlink) => Err(symlink(path)),
        Some(FileType::RegularFile) => {
            let st = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| io(path, e))?;
            if st.st_uid != rustix::process::geteuid().as_raw() {
                return Err(unsafe_path_error(path, "the file does not belong to the user running Koru"));
            }
            if mode(st.st_mode) & 0o077 != 0 {
                return Err(unsafe_path_error(path, "the file is open to group or others (must be 0600)"));
            }
            if link_count(st.st_nlink) != 1 {
                return Err(unsafe_path_error(path, "the file has more than one hard link"));
            }
            Ok(())
        }
        Some(_) => Err(unsafe_path_error(path, "not a regular file")),
    }
}
