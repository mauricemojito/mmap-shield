//! Memory access pattern hints for the kernel.
//!
//! Wraps `madvise(2)` advice values to let the kernel optimize
//! page-in behavior for different access patterns. Particularly
//! useful on network filesystems where prefetching strategy
//! significantly impacts latency.

/// Kernel hint for expected memory access patterns.
///
/// Passed to [`crate::mmap::SafeMmap::advise`] or
/// [`crate::mmap::SafeMmap::advise_range`] to influence kernel
/// readahead and page cache behavior.
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::{SafeMmap, Advice};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mmap = SafeMmap::open("data.bin")?;
/// mmap.advise(Advice::Sequential)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advice {
    /// No special treatment. This is the default.
    Normal,

    /// Expect sequential page references.
    ///
    /// The kernel will aggressively read ahead.
    /// Best for streaming reads over large contiguous regions.
    Sequential,

    /// Expect random page references.
    ///
    /// Disables readahead. Best for index lookups or
    /// sparse or index-based access patterns.
    Random,

    /// Expect access in the near future.
    ///
    /// Initiates a non-blocking readahead for the specified range.
    /// On NFS/EFS this triggers background page-in, reducing
    /// latency on subsequent access.
    WillNeed,

    /// Do not expect access in the near future.
    ///
    /// Allows the kernel to free pages in the specified range.
    /// Useful for releasing memory pressure after processing
    /// a region.
    DontNeed,
}

impl Advice {
    /// Converts to the corresponding `libc` madvise constant.
    ///
    /// # Returns
    ///
    /// The platform-specific `MADV_*` constant for this advice value.
    pub(crate) fn as_libc(self) -> libc::c_int {
        match self {
            Advice::Normal => libc::MADV_NORMAL,
            Advice::Sequential => libc::MADV_SEQUENTIAL,
            Advice::Random => libc::MADV_RANDOM,
            Advice::WillNeed => libc::MADV_WILLNEED,
            Advice::DontNeed => libc::MADV_DONTNEED,
        }
    }
}
