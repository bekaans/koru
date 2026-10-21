//! Safe file reading (ADR-0004 and ADR-0007 principles, ADR-0008): files root trusts, such as the config,
//! environment and install record, are opened component by component with `openat(O_NOFOLLOW | O_DIRECTORY)`
//! and checked through the open handle (`fstat`).
//!
//! - Intermediate directories must belong to the user running Koru or to root, and must not be writable
//!   by group/others (a sticky bit is accepted).
//! - The final component may not be a symlink; it must be a regular file owned by the same user (or root),
//!   not writable by group/others, and its size must not exceed the bound.
//!
//! No `unsafe`; system calls go through `rustix`'s safe API.

use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
use rustix::io::Errno;

const DIR_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const READ_FLAGS: OFlags =
    OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC).union(OFlags::NONBLOCK).union(OFlags::NOCTTY);

/// The file's mode rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadMode {
    /// Holds secret values: fully closed to group and others (0600).
    Secret,
    /// Holds no secrets: not writable by group/others (may be readable).
    Public,
}

fn kip_u32(m: impl Into<u32>) -> u32 {
    m.into()
}

fn error(path: &Path, reason: impl std::fmt::Display) -> String {
    format!("{}: {reason}", path.display())
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn check_intermediate(fd: &OwnedFd, path: &Path) -> Result<(), String> {
    let st = rustix::fs::fstat(fd).map_err(|e| error(path, e))?;
    if st.st_uid != 0 && st.st_uid != euid() {
        return Err(error(path, "a parent directory does not belong to the running user or root"));
    }
    let k = kip_u32(st.st_mode);
    if k & 0o022 != 0 && k & 0o1000 == 0 {
        return Err(error(path, "a parent directory is writable by group or others (no sticky bit)"));
    }
    Ok(())
}

/// Opens and checks the parents of an absolute path without following symlinks; gives the last directory's
/// handle and the file name.
pub(crate) fn open_parent_dir(path: &Path) -> Result<(OwnedFd, std::ffi::OsString), String> {
    if !path.is_absolute() {
        return Err(error(path, "the path must be absolute"));
    }
    let mut components = Vec::new();
    for b in path.components() {
        match b {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(error(path, "may not contain '.' or '..' components"));
            }
        }
    }
    let Some((file, directories)) = components.split_last() else {
        return Err(error(path, "there is no file name"));
    };
    let root = Path::new("/");
    let mut dir = rustix::fs::openat(CWD, root, DIR_FLAGS, Mode::empty()).map_err(|e| error(root, e))?;
    let mut valid = root.to_path_buf();
    check_intermediate(&dir, &valid)?;
    for name in directories {
        valid.push(name);
        dir = match rustix::fs::openat(&dir, name.as_os_str(), DIR_FLAGS, Mode::empty()) {
            Ok(fd) => fd,
            Err(e) => {
                return Err(match rustix::fs::statat(&dir, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Symlink => {
                        error(&valid, "symlinks are not followed")
                    }
                    _ => error(&valid, e),
                });
            }
        };
        check_intermediate(&dir, &valid)?;
    }
    Ok((dir, file.clone()))
}

/// Reads a file safely; at most `max` bytes.
pub(crate) fn read(path: &Path, max: u64, mode: ReadMode) -> Result<Vec<u8>, String> {
    let (dir, name) = open_parent_dir(path)?;
    let fd = match rustix::fs::openat(&dir, name.as_os_str(), READ_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => return Err(error(path, "symlinks are not followed")),
        Err(e) => return Err(error(path, e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| error(path, e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(error(path, "not a regular file"));
    }
    if st.st_uid != 0 && st.st_uid != euid() {
        return Err(error(path, "the file does not belong to the running user or root"));
    }
    let k = kip_u32(st.st_mode);
    match mode {
        ReadMode::Secret if k & 0o077 != 0 => {
            return Err(error(path, "the file is open to group or others (must be 0600)"));
        }
        ReadMode::Public if k & 0o022 != 0 => return Err(error(path, "the file is writable by group or others")),
        _ => {}
    }
    let size_v = u64::try_from(st.st_size).map_err(|_| error(path, "the file size is invalid"))?;
    if size_v > max {
        return Err(error(path, "the file is too large"));
    }
    let mut content = Vec::new();
    File::from(fd).take(max + 1).read_to_end(&mut content).map_err(|e| error(path, e.kind()))?;
    if content.len() as u64 > max {
        return Err(error(path, "the file is too large"));
    }
    Ok(content)
}
