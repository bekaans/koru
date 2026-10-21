//! File identity (device and inode) and Koru's own process identity.

use crate::normalize_path;

/// A file's identity: device and inode numbers. A path can be imitated; an identity cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// The device number (`st_dev`).
    pub device: u64,
    /// The inode number (`st_ino`).
    pub inode: u64,
}

/// The source of file identities: [`SystemIdentitySource`] live, a fake in tests.
pub trait IdentitySource {
    /// The identity of the binary a process runs (`/proc/<pid>/exe`); `None` if no process.
    fn process_exe_id(&self, pid: u32) -> Option<FileIdentity>;

    /// The identity of the file at a path (links followed); `None` if no file.
    fn path_id(&self, path: &str) -> Option<FileIdentity>;

    /// The real path of the binary a process runs (the `/proc/<pid>/exe` link); `None` if
    /// unreadable. The exe spelling in an event comes from Pulsar's process tracker and can
    /// show the parent's old image right after an exec; the allowlist therefore checks the
    /// real path. The default implementation does not know paths (`None`: the event's exe
    /// path is used).
    fn process_exe_path(&self, _pid: u32) -> Option<String> {
        None
    }

    /// Verifies that the real path and identity (device, inode) of the binary a process runs
    /// match the expectation together. Allowlist and Koru-exclusion decisions rest on this
    /// (against exec evasion: the event's exe must match too, see `RuleDetector`).
    ///
    /// The default implementation also requires the path from sources that give real paths,
    /// and checks identity only for (fake) sources without path knowledge. The real source
    /// ([`SystemIdentitySource`]) applies this fail-closed.
    fn verify_process_exe(&self, pid: u32, path: &str, file: FileIdentity) -> bool {
        if let Some(real) = self.process_exe_path(pid)
            && normalize_path(&real).as_deref() != Some(path)
        {
            return false;
        }
        self.process_exe_id(pid) == Some(file)
    }
}

/// The source reading from the operating system (Linux: `/proc/<pid>/exe`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemIdentitySource;

impl IdentitySource for SystemIdentitySource {
    fn process_exe_id(&self, pid: u32) -> Option<FileIdentity> {
        // The /proc/<pid>/exe magic link resolves to the running binary itself; the inode is
        // readable even if the binary was deleted. Outside Linux there is no /proc: `None`.
        read_id(&format!("/proc/{pid}/exe"))
    }

    fn path_id(&self, path: &str) -> Option<FileIdentity> {
        read_id(path)
    }

    fn process_exe_path(&self, pid: u32) -> Option<String> {
        // A deleted binary arrives with a " (deleted)" suffix; it matches no allowlist path.
        exe_path_text(&std::fs::read_link(format!("/proc/{pid}/exe")).ok()?)
    }

    /// Fail-closed: `false` if `/proc/<pid>/exe` is unreadable, the path is not UTF-8, or
    /// the path or identity mismatches (no fallback to the event's path).
    fn verify_process_exe(&self, pid: u32, path: &str, file: FileIdentity) -> bool {
        match self.process_exe_path(pid) {
            Some(real) => normalize_path(&real).as_deref() == Some(path) && self.process_exe_id(pid) == Some(file),
            None => false,
        }
    }
}

/// The `/proc/<pid>/exe` link target as text if UTF-8; else `None` (no event-path fallback).
fn exe_path_text(path: &std::path::Path) -> Option<String> {
    path.to_str().map(str::to_string)
}

/// A path's device and inode numbers (links followed).
fn read_id(path: &str) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(FileIdentity { device: m.dev(), inode: m.ino() })
}

/// Koru's own process. Exclusion happens only when pid, normalized exe path, and the exe's
/// identity (inode) all match together (KT-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KoruIdentity {
    /// The process id.
    pub pid: u32,
    /// The parent process id.
    pub ppid: u32,
    /// Exe path.
    pub exe: String,
    /// The command line.
    pub command_line: Vec<String>,
    /// The exe's identity.
    pub file: FileIdentity,
}

impl KoruIdentity {
    /// The running process's identity (`/proc/self`); an error outside Linux.
    pub fn this_process() -> std::io::Result<KoruIdentity> {
        if !cfg!(target_os = "linux") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a process identity can only be read on Linux",
            ));
        }
        let exe = std::fs::read_link("/proc/self/exe")?;
        let exe = exe
            .to_str()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "the exe path is not UTF-8"))?
            .to_string();
        let file = read_id("/proc/self/exe")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "the exe identity could not be read"))?;
        let raw = std::fs::read("/proc/self/cmdline")?;
        let mut command_line: Vec<String> =
            raw.split(|b| *b == 0).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
        if command_line.last().is_some_and(String::is_empty) {
            command_line.pop();
        }
        Ok(KoruIdentity { pid: std::process::id(), ppid: std::os::unix::process::parent_id(), exe, command_line, file })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::exe_path_text;

    #[test]
    fn non_utf8_exe_path_not_converted_to_text() {
        let broken = Path::new(OsStr::from_bytes(b"/usr/local/bin/backup\xff"));
        assert_eq!(exe_path_text(broken), None);
        assert_eq!(exe_path_text(Path::new("/usr/local/bin/backup")).as_deref(), Some("/usr/local/bin/backup"));
    }
}
