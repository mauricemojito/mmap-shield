//! Error types for mmap-shield.
//!
//! Provides a unified error hierarchy covering mmap operations,
//! SIGBUS signal recovery, and I/O fallback failures.

use std::io;

/// Errors that can occur during memory-mapped file access.
///
/// This enum distinguishes between recoverable signal faults
/// (which indicate network filesystem issues) and standard
/// I/O errors (which indicate local system problems).
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::AccessError;
///
/// fn handle_error(err: AccessError) {
///     match err {
///         AccessError::Sigbus { fault_address } => {
///             eprintln!("page fault at address {:#x}", fault_address);
///         }
///         AccessError::OutOfBounds { offset, len, mapping_len } => {
///             eprintln!("access [{offset}..{}] exceeds mapping length {mapping_len}", offset + len);
///         }
///         AccessError::Poisoned { sigbus_count } => {
///             eprintln!("file poisoned after {sigbus_count} faults");
///         }
///         AccessError::Timeout { offset, len, deadline } => {
///             eprintln!("prefetch [{offset}..{}] timed out after {deadline:?}", offset + len);
///         }
///         AccessError::Io(err) => {
///             eprintln!("I/O error: {err}");
///         }
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    /// A SIGBUS signal was caught during memory access.
    ///
    /// This typically means the underlying network filesystem
    /// failed to page in the requested data.
    ///
    /// # Parameters
    ///
    /// * `fault_address` - The memory address that triggered the fault.
    #[error("SIGBUS caught at address {fault_address:#x}")]
    Sigbus { fault_address: usize },

    /// The requested byte range exceeds the mapping boundaries.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start of the requested range.
    /// * `len` - Length of the requested range.
    /// * `mapping_len` - Total length of the memory mapping.
    #[error("access [{offset}..{}] exceeds mapping length {mapping_len}", offset + len)]
    OutOfBounds {
        offset: usize,
        len: usize,
        mapping_len: usize,
    },

    /// The file has been marked poisoned after repeated SIGBUS faults.
    ///
    /// Once poisoned, all subsequent access attempts fail immediately
    /// without touching the mapped memory.
    ///
    /// # Parameters
    ///
    /// * `sigbus_count` - Number of SIGBUS faults recorded before poisoning.
    #[error("file poisoned after {sigbus_count} SIGBUS faults")]
    Poisoned { sigbus_count: u32 },

    /// A prefetch operation did not complete within the deadline.
    ///
    /// The worker thread may still be blocked on a page fault.
    /// The pages in the requested range should not be accessed
    /// until the underlying storage recovers.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start of the prefetch range.
    /// * `len` - Length of the prefetch range.
    /// * `deadline` - The timeout duration that was exceeded.
    #[error("prefetch [{offset}..{}] timed out after {deadline:?}", offset + len)]
    Timeout {
        offset: usize,
        len: usize,
        deadline: std::time::Duration,
    },

    /// A standard I/O error occurred.
    ///
    /// Wraps [`std::io::Error`] for errors from `mmap`, `munmap`,
    /// `madvise`, `pread`, or filesystem detection syscalls.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Errors that can occur when creating a memory mapping.
///
/// Separates mapping creation failures from access-time failures.
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::MmapError;
///
/// fn handle_mmap_error(err: MmapError) {
///     match err {
///         MmapError::EmptyFile => eprintln!("cannot map empty file"),
///         MmapError::OffsetBeyondFile { offset, file_len } => {
///             eprintln!("offset {offset} beyond file length {file_len}");
///         }
///         MmapError::Io(err) => eprintln!("mmap failed: {err}"),
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum MmapError {
    /// The file has zero length and cannot be memory-mapped.
    #[error("cannot memory-map an empty file")]
    EmptyFile,

    /// The computed mapping length is zero.
    ///
    /// This typically means the offset is at or beyond the end of the file,
    /// leaving no bytes to map.
    ///
    /// # Parameters
    ///
    /// * `offset` - The requested file offset.
    /// * `file_len` - The actual file length.
    #[error("offset {offset} is at or beyond file length {file_len}")]
    OffsetBeyondFile { offset: u64, file_len: u64 },

    /// A system call failed during mapping creation.
    #[error("mmap failed: {0}")]
    Io(#[from] io::Error),
}
