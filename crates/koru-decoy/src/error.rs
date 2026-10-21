//! Install, removal, and query errors.

use crate::generation::GenerationError;

/// When installation, removal, an integrity check, or record reading fails.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// Invalid settings: a relative path, a `..` component, a root nested inside the state directory.
    #[error("invalid setting: {0}")]
    Settings(String),
    /// A platform restriction (outside Linux, installation is only into temp directories; ADR-0004).
    #[error("platform restriction: {0}")]
    Platform(String),
    /// A symlink is on the path or at the target; not followed, not overwritten.
    #[error("{path}: symlink; not followed or overwritten for safety")]
    Symlink {
        /// The link's path.
        path: String,
    },
    /// The absolute target path is under none of the allowed roots.
    #[error("{path}: target outside the allowed roots")]
    OutsideRoot {
        /// Target path.
        path: String,
    },
    /// The target to be written as a new file already exists; it is not overwritten.
    #[error("{path}: target already exists; not overwritten")]
    TargetExists {
        /// Target path.
        path: String,
    },
    /// The target cannot be handled safely (not a regular file, hard-linked, different owner...).
    #[error("{path}: unsafe target: {reason}")]
    UnsafeFile {
        /// Target path.
        path: String,
        /// Reason.
        reason: String,
    },
    /// An installation already exists in the state directory.
    #[error("an installation already exists in this state directory; run `koru decoy uninstall` first")]
    AlreadyInstalled,
    /// No installation record in the state directory.
    #[error("no installation record in this state directory")]
    NotInstalled,
    /// The state directory is locked by another process.
    #[error("the state directory is in use by another Koru process")]
    Lock,
    /// The content could not be generated.
    #[error(transparent)]
    Generation(#[from] GenerationError),
    /// The integrity record or the backup could not be read, or is invalid.
    #[error("integrity record: {0}")]
    Record(String),
    /// A filesystem error.
    #[error("{path}: {error}")]
    Gc {
        /// The path being processed.
        path: String,
        /// The error.
        #[source]
        error: std::io::Error,
    },
}
