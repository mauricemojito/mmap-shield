//! `pread(2)`-based fallback reader.
//!
//! Provides the same read interface as the mmap path but uses
//! explicit `pread` syscalls instead of memory mapping. This path
//! returns proper [`std::io::Error`] on failure instead of SIGBUS,
//! making it the safe choice for network filesystems.

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::AccessError;
use crate::sys::pread::pread_exact;

/// A file reader using `pread(2)` for positional reads without seeking.
///
/// Unlike memory-mapped access, every read is an explicit syscall
/// that returns a proper error on failure. No SIGBUS risk.
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::fallback::PreadReader;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let reader = PreadReader::open("data.bin")?;
/// let header = reader.read(0..1024, |bytes| {
///     bytes[0..4].try_into().unwrap()
/// })?;
/// let magic: [u8; 4] = header;
/// # Ok(())
/// # }
/// ```
pub struct PreadReader {
    file: File,
    len: u64,
    path: PathBuf,
}

impl PreadReader {
    /// Opens a file for pread-based access.
    ///
    /// # Parameters
    ///
    /// * `path` - Path to the file to open.
    ///
    /// # Returns
    ///
    /// A new [`PreadReader`], or an [`io::Error`] if the file
    /// cannot be opened or its metadata cannot be read.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let len = file.metadata()?.len();

        Ok(Self {
            file,
            len,
            path: path.to_path_buf(),
        })
    }

    /// Reads a byte range and passes it to a closure.
    ///
    /// Allocates a temporary buffer, fills it via `pread(2)`, and
    /// invokes `f` with the buffer contents.
    ///
    /// # Parameters
    ///
    /// * `range` - Byte range to read from the file.
    /// * `f` - Closure that processes the read bytes.
    ///
    /// # Returns
    ///
    /// The return value of `f`, or an [`AccessError`] if the range
    /// is out of bounds or the read fails.
    ///
    /// # Type Parameters
    ///
    /// * `R` - Return type of the processing closure.
    pub fn read<R>(
        &self,
        range: std::ops::Range<usize>,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, AccessError> {
        let offset = range.start;
        let len = range.end - range.start;

        if range.end as u64 > self.len {
            return Err(AccessError::OutOfBounds {
                offset,
                len,
                mapping_len: self.len as usize,
            });
        }

        let mut buf = vec![0u8; len];
        pread_exact(self.file.as_raw_fd(), &mut buf, offset as i64)?;

        Ok(f(&buf))
    }

    /// Returns the file length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` if the file has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the path this reader was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
