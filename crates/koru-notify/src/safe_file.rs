//! Safe file operations (ADR-0007 "File safety"; ADR-0004 and ADR-0006 principles).
//!
//! - The path must be absolute and hold no `.` or `..` (a relative path first joins the current directory).
//! - The handle chain opens from the root, component by component, with `openat(O_DIRECTORY | O_NOFOLLOW)`;
//!   when a component is a symlink the operation is rejected. Only a missing last directory is
//!   created (0700); a missing higher directory is an error.
//! - Every PARENT directory must belong to the user
//!   running Koru or to root, and must not be group- or world-writable; a sticky-bit shared
//!   directory (`/tmp`) is accepted. Otherwise someone else could swap a path component.
//! - The directory handle itself must belong to the user running Koru, closed to others (0700).
//! - Files are checked not before opening but through the open handle (`fstat`) after
//!   `O_NOFOLLOW | O_NONBLOCK`: regular file, same owner, 0600, one link (hard-link leak).
//!   Special files like FIFOs are never blocked on.
//! - Writes are atomic: write a 0600 temp file, `fsync`, `rename` into place, and
//!   the directory is `fsync`ed.
//!
//! No `unsafe`; syscalls go through `rustix`'s safe interface.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::NotifyError;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const READ_FLAGS: OFlags =
    OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC).union(OFlags::NONBLOCK).union(OFlags::NOCTTY);
const WRITE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY);

/// `st_mode` is u16 on macOS and u32 on Linux; this conversion works on both.
fn mode(mod_: impl Into<u32>) -> u32 {
    mod_.into()
}

/// `st_nlink` is u16 on macOS, u32 on Linux/aarch64, u64 on Linux/x86_64.
fn link_count(n: impl Into<u64>) -> u64 {
    n.into()
}

fn error(path: &Path, reason: impl ToString) -> NotifyError {
    NotifyError::Queue(format!("{}: {}", path.display(), reason.to_string()))
}

/// The outcome of reading a file.
pub(crate) enum ReadOutcome {
    /// The file does not exist.
    NotFound,
    /// The file exceeds the limit (it was not read).
    TooLarge,
    /// The content.
    Content(Vec<u8>),
}

/// The entry's kind without following links; `None` when missing.
fn entry_kind(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<Option<FileType>, NotifyError> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(FileType::from_raw_mode(st.st_mode))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(error(path, e)),
    }
}

/// Opens a subdirectory without following links; `None` when missing.
fn subdirectory(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<Option<OwnedFd>, NotifyError> {
    match rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(open_error) => match entry_kind(parent, name, path)? {
            None => Ok(None),
            Some(FileType::Symlink) => Err(error(path, "symlinks are not followed")),
            Some(FileType::Directory) => Err(error(path, open_error)),
            Some(_) => Err(error(path, "a directory was expected")),
        },
    }
}

/// Validates the directory (creating the last component 0700 when needed) and returns its open handle.
pub(crate) fn prepare_directory(path: &Path) -> Result<OwnedFd, NotifyError> {
    if !path.is_absolute() {
        return Err(error(path, "the directory path must be absolute"));
    }
    let mut components = Vec::new();
    for b in path.components() {
        match b {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(error(path, "must not contain a '.' or '..' component"));
            }
        }
    }
    if components.is_empty() {
        return Err(error(path, "no directory name"));
    }
    let root = Path::new("/");
    let mut dir = rustix::fs::openat(CWD, root, DIRECTORY_FLAGS, Mode::empty()).map_err(|e| error(root, e))?;
    let mut current = root.to_path_buf();
    check_parent_directory(&dir, &current)?;
    for (i, name) in components.iter().enumerate() {
        current.push(name);
        let last = i == components.len() - 1;
        dir = match subdirectory(&dir, name, &current)? {
            Some(d) => d,
            None if last => create_directory(&dir, name, &current)?,
            None => return Err(error(&current, "the parent directory is missing")),
        };
        if !last {
            check_parent_directory(&dir, &current)?;
        }
    }
    check_directory(&dir, &current)?;
    Ok(dir)
}

/// A parent (non-final) directory: its owner must be the user running Koru or root;
/// when group/other-writable, the sticky bit (`/tmp`) is required.
fn check_parent_directory(dir: &OwnedFd, path: &Path) -> Result<(), NotifyError> {
    let st = rustix::fs::fstat(dir).map_err(|e| error(path, e))?;
    if st.st_uid != 0 && st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(error(path, "the parent directory does not belong to the user running Koru or to root"));
    }
    let k = mode(st.st_mode);
    if k & 0o022 != 0 && k & 0o1000 == 0 {
        return Err(error(path, "the parent directory is group- or world-writable (no sticky bit)"));
    }
    Ok(())
}

/// Splits a path into absolute components: a relative path joins the current directory;
/// `..` is rejected, `.` is skipped.
fn absolute_components(path: &Path) -> Result<Vec<std::ffi::OsString>, NotifyError> {
    let mut full = std::path::PathBuf::new();
    if !path.is_absolute() {
        full.push(std::env::current_dir().map_err(|e| error(path, e.kind()))?);
    }
    full.push(path);
    let mut result = Vec::new();
    for b in full.components() {
        match b {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => result.push(name.to_os_string()),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(error(path, "must not contain a '..' component"));
            }
        }
    }
    Ok(result)
}

fn create_directory(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<OwnedFd, NotifyError> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => return Err(error(path, e)),
    }
    let fd = subdirectory(parent, name, path)?.ok_or_else(|| error(path, "the created directory was not found"))?;
    // A umask can only narrow the mode, never widen it; 0700 is still set explicitly (via the open handle).
    // If someone else created it at the same moment, the check below rejects its mode.
    let st = rustix::fs::fstat(&fd).map_err(|e| error(path, e))?;
    if st.st_uid == rustix::process::geteuid().as_raw() && mode(st.st_mode) & 0o077 != 0 {
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o700)).map_err(|e| error(path, e))?;
    }
    Ok(fd)
}

fn check_directory(dir: &OwnedFd, path: &Path) -> Result<(), NotifyError> {
    let st = rustix::fs::fstat(dir).map_err(|e| error(path, e))?;
    if st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(error(path, "the directory does not belong to the user running Koru"));
    }
    if mode(st.st_mode) & 0o077 != 0 {
        return Err(error(path, "the directory is open to the group or others (must be 0700)"));
    }
    Ok(())
}

/// Checks an open file's safety with `fstat` and returns its size.
fn check_file(fd: &OwnedFd, path: &Path) -> Result<u64, NotifyError> {
    let st = rustix::fs::fstat(fd).map_err(|e| error(path, e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(error(path, "not a regular file"));
    }
    if st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(error(path, "the file does not belong to the user running Koru"));
    }
    if mode(st.st_mode) & 0o077 != 0 {
        return Err(error(path, "the file is open to the group or others (must be 0600)"));
    }
    if link_count(st.st_nlink) != 1 {
        return Err(error(path, "the file has more than one hard link"));
    }
    u64::try_from(st.st_size).map_err(|_| error(path, "invalid file size"))
}

/// Reads a file inside the directory handle safely. A symlink, a special file, a wrong owner,
/// a wide mode or a hard link is an error; a file over `max` bytes returns [`ReadOutcome::TooLarge`]
/// without being read.
pub(crate) fn read_file(dir: &OwnedFd, name: &str, path: &Path, max: u64) -> Result<ReadOutcome, NotifyError> {
    let fd = match rustix::fs::openat(dir, name, READ_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(ReadOutcome::NotFound),
        Err(Errno::LOOP) => return Err(error(path, "symlinks are not followed")),
        Err(e) => return Err(error(path, e)),
    };
    let size = check_file(&fd, path)?;
    if size > max {
        return Ok(ReadOutcome::TooLarge);
    }
    let mut content = Vec::new();
    File::from(fd).take(max + 1).read_to_end(&mut content).map_err(|e| error(path, e.kind()))?;
    if content.len() as u64 > max {
        return Ok(ReadOutcome::TooLarge);
    }
    Ok(ReadOutcome::Content(content))
}

/// Reads a file (e.g. `.env`) at a possibly-relative path safely: the path opens component by
/// component from the root (a parent cannot be a symlink, parent dirs cannot be writable);
/// the last component cannot be a symlink; the file must be regular, same-owner, 0600 and at
/// most `max` bytes.
pub(crate) fn read_from_path(path: &Path, max: u64) -> Result<Vec<u8>, NotifyError> {
    let components = absolute_components(path)?;
    let Some((file_name, directories)) = components.split_last() else {
        return Err(error(path, "no file name"));
    };
    let root = Path::new("/");
    let mut dir = rustix::fs::openat(CWD, root, DIRECTORY_FLAGS, Mode::empty()).map_err(|e| error(root, e))?;
    let mut current = root.to_path_buf();
    check_parent_directory(&dir, &current)?;
    for name in directories {
        current.push(name);
        dir = subdirectory(&dir, name, &current)?.ok_or_else(|| error(&current, "the parent directory is missing"))?;
        check_parent_directory(&dir, &current)?;
    }
    let fd = match rustix::fs::openat(&dir, file_name, READ_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => return Err(error(path, "symlinks are not followed")),
        Err(e) => return Err(error(path, e)),
    };
    let size = check_file(&fd, path)?;
    if size > max {
        return Err(error(path, "the file is too large"));
    }
    let mut content = Vec::new();
    File::from(fd).take(max + 1).read_to_end(&mut content).map_err(|e| error(path, e.kind()))?;
    if content.len() as u64 > max {
        return Err(error(path, "the file is too large"));
    }
    Ok(content)
}

/// Atomically replaces `dir/name` with `content` (0600).
pub(crate) fn write_atomically(dir: &OwnedFd, name: &str, path: &Path, content: &[u8]) -> Result<(), NotifyError> {
    let is_transient = format!(".{name}.tmp");
    // A leftover temp file from an earlier run (perhaps a symlink) is deleted first; never followed.
    match rustix::fs::unlinkat(dir, is_transient.as_str(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(e) => return Err(error(path, e)),
    }
    let fd = rustix::fs::openat(dir, is_transient.as_str(), WRITE_FLAGS, Mode::from_raw_mode(0o600))
        .map_err(|e| error(path, e))?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(|e| error(path, e))?;
    let mut file = File::from(fd);
    let written = file.write_all(content).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = rustix::fs::unlinkat(dir, is_transient.as_str(), AtFlags::empty());
        return Err(error(path, e.kind()));
    }
    if let Err(e) = rustix::fs::renameat(dir, is_transient.as_str(), dir, name) {
        let _ = rustix::fs::unlinkat(dir, is_transient.as_str(), AtFlags::empty());
        return Err(error(path, e));
    }
    rustix::fs::fsync(dir).map_err(|e| error(path, e))
}

/// Sets a corrupt file aside as `name.corrupt` (replacing any existing one); it stays inspectable.
pub(crate) fn set_aside(dir: &OwnedFd, name: &str, path: &Path) -> Result<(), NotifyError> {
    let new = format!("{name}.corrupt");
    rustix::fs::renameat(dir, name, dir, new.as_str()).map_err(|e| error(path, e))
}
