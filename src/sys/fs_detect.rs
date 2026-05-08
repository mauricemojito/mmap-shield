//! Network filesystem detection via `statfs(2)`.
//!
//! Identifies whether a file resides on a network filesystem
//! (NFS, CIFS/SMB, FUSE, etc.) to enable automatic fallback
//! from mmap to pread-based access.

use std::io;
use std::path::Path;

/// Filesystem type classification.
///
/// Determined by inspecting the `f_type` field from `statfs(2)`.
/// Used to decide whether mmap access is safe or whether a
/// pread fallback should be preferred.
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::sys::fs_detect::FsType;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let fs_type = FsType::detect("/mnt/efs/data.bin")?;
/// if fs_type.is_network() {
///     println!("network filesystem detected — using pread fallback");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    /// Local filesystem (ext4, xfs, btrfs, apfs, etc.).
    Local,

    /// NFS (Network File System).
    Nfs,

    /// CIFS / SMB (Samba).
    Cifs,

    /// FUSE-based filesystem (could be local or network).
    Fuse,

    /// Amazon EFS (presents as NFS but worth distinguishing).
    Efs,

    /// Unknown or unrecognized filesystem type.
    Unknown(u64),
}

impl FsType {
    /// Detects the filesystem type for a given path.
    ///
    /// # Parameters
    ///
    /// * `path` - Path to any file or directory on the target filesystem.
    ///
    /// # Returns
    ///
    /// The detected [`FsType`], or an [`io::Error`] if `statfs` fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the path does not exist or `statfs(2)` fails.
    pub fn detect(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let c_path = path_to_cstring(path)?;

        #[cfg(target_os = "linux")]
        {
            Self::detect_linux(&c_path)
        }

        #[cfg(target_os = "macos")]
        {
            Self::detect_macos(&c_path)
        }
    }

    /// Returns `true` if this filesystem type is known to be network-backed.
    ///
    /// # Returns
    ///
    /// `true` for [`FsType::Nfs`], [`FsType::Cifs`], and [`FsType::Efs`].
    /// `false` for [`FsType::Local`], [`FsType::Fuse`], and [`FsType::Unknown`].
    pub fn is_network(&self) -> bool {
        matches!(self, FsType::Nfs | FsType::Cifs | FsType::Efs)
    }

    #[cfg(target_os = "linux")]
    fn detect_linux(c_path: &std::ffi::CString) -> io::Result<Self> {
        const NFS_SUPER_MAGIC: i64 = 0x6969;
        const CIFS_MAGIC: i64 = 0xFF534D42;
        const FUSE_SUPER_MAGIC: i64 = 0x65735546;
        const EFS_SUPER_MAGIC: i64 = 0x00414A53;

        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let fs_type = match stat.f_type {
            NFS_SUPER_MAGIC => FsType::Nfs,
            CIFS_MAGIC => FsType::Cifs,
            FUSE_SUPER_MAGIC => FsType::Fuse,
            EFS_SUPER_MAGIC => FsType::Efs,
            _ => FsType::Local,
        };

        Ok(fs_type)
    }

    #[cfg(target_os = "macos")]
    fn detect_macos(c_path: &std::ffi::CString) -> io::Result<Self> {
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let fs_name =
            unsafe { std::ffi::CStr::from_ptr(stat.f_fstypename.as_ptr()).to_string_lossy() };

        let fs_type = match fs_name.as_ref() {
            "nfs" => FsType::Nfs,
            "smbfs" | "cifs" => FsType::Cifs,
            "fusefs" | "osxfuse" | "macfuse" => FsType::Fuse,
            "apfs" | "hfs" | "msdos" | "exfat" | "ufs" | "devfs" => FsType::Local,
            _ => FsType::Unknown(0),
        };

        Ok(fs_type)
    }
}

fn path_to_cstring(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null byte"))
}
