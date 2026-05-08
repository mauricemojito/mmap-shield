//! Low-level memory mapping over `mmap(2)` / `munmap(2)` / `madvise(2)`.
//!
//! Provides a thin, owning wrapper around a raw memory-mapped region.
//! Handles alignment, system page size, and automatic cleanup via `Drop`.
//! No signal handling — that responsibility belongs to the `signal` module.
//!
//! # Builder
//!
//! Use [`MmapOptions`] for full control over mapping parameters:
//!
//! ```no_run
//! use std::fs::File;
//! use std::os::unix::io::AsRawFd;
//! use mmap_shield::sys::mmap::{MmapOptions, Protection, Visibility};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let file = File::open("data.bin")?;
//! let len = file.metadata()?.len() as usize;
//!
//! let mapping = unsafe {
//!     MmapOptions::new(len)
//!         .fd(file.as_raw_fd())
//!         .protection(Protection::ReadWrite)
//!         .visibility(Visibility::Shared)
//!         .offset(0)
//!         .map()?
//! };
//! # Ok(())
//! # }
//! ```

use std::io;
use std::os::fd::RawFd;
use std::ptr;

use crate::sys::advice::Advice;
use crate::sys::page::page_size;

/// Memory protection flags for a mapping.
///
/// Maps to `PROT_*` constants from `mmap(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Read-only access. Writes cause SIGSEGV.
    Read,

    /// Read and write access.
    ReadWrite,

    /// No access. Any dereference causes SIGSEGV.
    /// Useful for guard pages.
    None,
}

impl Protection {
    fn as_libc(self) -> libc::c_int {
        match self {
            Protection::Read => libc::PROT_READ,
            Protection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            Protection::None => libc::PROT_NONE,
        }
    }

    fn is_writable(self) -> bool {
        matches!(self, Protection::ReadWrite)
    }
}

/// Mapping visibility flags.
///
/// Maps to `MAP_PRIVATE` / `MAP_SHARED` from `mmap(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Changes are private (copy-on-write).
    /// Writes do not affect the underlying file.
    Private,

    /// Changes are shared with other processes and
    /// written back to the underlying file.
    Shared,
}

impl Visibility {
    fn as_libc(self) -> libc::c_int {
        match self {
            Visibility::Private => libc::MAP_PRIVATE,
            Visibility::Shared => libc::MAP_SHARED,
        }
    }
}

/// Builder for constructing memory mappings with full control
/// over protection, visibility, offset, and populate behavior.
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::sys::mmap::{MmapOptions, Protection, Visibility};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Anonymous mapping (no file):
/// let anon = unsafe {
///     MmapOptions::new(4096)
///         .protection(Protection::ReadWrite)
///         .map()?
/// };
///
/// // File-backed read-only:
/// use std::fs::File;
/// use std::os::unix::io::AsRawFd;
/// let f = File::open("data.bin")?;
/// let mapping = unsafe {
///     MmapOptions::new(f.metadata()?.len() as usize)
///         .fd(f.as_raw_fd())
///         .map()?
/// };
/// # Ok(())
/// # }
/// ```
#[must_use]
pub struct MmapOptions {
    len: usize,
    fd: Option<RawFd>,
    offset: u64,
    protection: Protection,
    visibility: Visibility,
    populate: bool,
}

impl MmapOptions {
    /// Creates a new builder for a mapping of `len` bytes.
    ///
    /// Defaults: read-only, private, no file, offset 0, no populate.
    ///
    /// # Parameters
    ///
    /// * `len` - Number of bytes to map. Must be greater than zero.
    pub fn new(len: usize) -> Self {
        Self {
            len,
            fd: None,
            offset: 0,
            protection: Protection::Read,
            visibility: Visibility::Private,
            populate: false,
        }
    }

    /// Sets the file descriptor to map.
    ///
    /// If not set, creates an anonymous mapping (`MAP_ANONYMOUS`).
    ///
    /// # Parameters
    ///
    /// * `fd` - Open file descriptor.
    pub fn fd(mut self, fd: RawFd) -> Self {
        self.fd = Some(fd);
        self
    }

    /// Sets the byte offset into the file.
    ///
    /// Must be page-aligned. Defaults to 0.
    ///
    /// # Parameters
    ///
    /// * `offset` - Byte offset (must be page-aligned).
    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }

    /// Sets the memory protection level.
    ///
    /// Defaults to [`Protection::Read`].
    ///
    /// # Parameters
    ///
    /// * `protection` - Protection flags for the mapping.
    pub fn protection(mut self, protection: Protection) -> Self {
        self.protection = protection;
        self
    }

    /// Sets the mapping visibility.
    ///
    /// Defaults to [`Visibility::Private`].
    ///
    /// # Parameters
    ///
    /// * `visibility` - Sharing behavior for the mapping.
    pub fn visibility(mut self, visibility: Visibility) -> Self {
        self.visibility = visibility;
        self
    }

    /// Enables `MAP_POPULATE` to pre-fault all pages on creation.
    ///
    /// This causes the kernel to read all pages into memory immediately
    /// rather than lazily on first access. Reduces page fault latency
    /// but increases mapping creation time.
    ///
    /// Only effective on Linux. Ignored on other platforms.
    pub fn populate(mut self) -> Self {
        self.populate = true;
        self
    }

    /// Creates the memory mapping.
    ///
    /// # Returns
    ///
    /// A new [`RawMmap`] owning the mapped region.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if:
    /// - `len` is zero.
    /// - `offset` is not page-aligned.
    /// - The `mmap(2)` syscall fails.
    ///
    /// # Safety
    ///
    /// For file-backed mappings, the caller must ensure the file
    /// descriptor remains valid. For writable shared mappings,
    /// the caller is responsible for synchronization.
    pub unsafe fn map(self) -> io::Result<RawMmap> {
        if self.len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "length must be non-zero",
            ));
        }

        if !(self.offset as usize).is_multiple_of(page_size()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "offset {} is not page-aligned (page size: {})",
                    self.offset,
                    page_size()
                ),
            ));
        }

        let mut flags = self.visibility.as_libc();

        let fd = match self.fd {
            Some(fd) => fd,
            None => {
                flags |= libc::MAP_ANON;
                -1
            }
        };

        #[cfg(target_os = "linux")]
        if self.populate {
            flags |= libc::MAP_POPULATE;
        }

        let prot = self.protection.as_libc();

        // SAFETY: All arguments are validated above. len > 0 and offset
        // is page-aligned. fd is -1 for anonymous or caller-provided.
        // The returned pointer is checked against MAP_FAILED.
        let raw_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                self.len,
                prot,
                flags,
                fd,
                self.offset as libc::off_t,
            )
        };

        if raw_ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(RawMmap {
            ptr: raw_ptr as *mut u8,
            len: self.len,
            writable: self.protection.is_writable(),
        })
    }
}

/// An owning handle to a raw memory-mapped region.
///
/// Created via [`MmapOptions::map`] or [`RawMmap::map`].
/// The region is unmapped when this value is dropped.
///
/// # Safety
///
/// The mapped memory may trigger SIGBUS on access if the backing
/// file is on a network filesystem and the server becomes unavailable.
/// Callers must install a signal handler before dereferencing the pointer.
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
/// use std::os::unix::io::AsRawFd;
/// use mmap_shield::sys::mmap::RawMmap;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let file = File::open("data.bin")?;
/// let len = file.metadata()?.len() as usize;
/// let mapping = unsafe { RawMmap::map(file.as_raw_fd(), 0, len)? };
/// # Ok(())
/// # }
/// ```
#[must_use]
pub struct RawMmap {
    ptr: *mut u8,
    len: usize,
    writable: bool,
}

// SAFETY: The mmap'd region is process-wide — the pointer is valid on any
// thread. Access synchronization is the caller's responsibility (same as
// &[u8] from a file). The kernel holds a reference to the inode, so the
// mapping remains valid regardless of which thread accesses it.
unsafe impl Send for RawMmap {}
unsafe impl Sync for RawMmap {}

// Compile-time assertions
const _: () = {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}
    assert_send::<RawMmap>();
    assert_sync::<RawMmap>();
};

impl RawMmap {
    /// Creates a new read-only, private memory mapping.
    ///
    /// Convenience method equivalent to:
    /// ```ignore
    /// MmapOptions::new(len).fd(fd).offset(offset).map()
    /// ```
    ///
    /// # Parameters
    ///
    /// * `fd` - Open file descriptor to map.
    /// * `offset` - Byte offset into the file (must be page-aligned).
    /// * `len` - Number of bytes to map.
    ///
    /// # Safety
    ///
    /// See [`MmapOptions::map`].
    pub unsafe fn map(fd: RawFd, offset: u64, len: usize) -> io::Result<Self> {
        unsafe { MmapOptions::new(len).fd(fd).offset(offset).map() }
    }

    /// Creates a new anonymous mapping (no backing file).
    ///
    /// The mapping is initialized to zero. Useful for scratch buffers
    /// or guard pages.
    ///
    /// # Parameters
    ///
    /// * `len` - Number of bytes to map.
    /// * `protection` - Protection flags.
    ///
    /// # Safety
    ///
    /// See [`MmapOptions::map`].
    pub unsafe fn anonymous(len: usize, protection: Protection) -> io::Result<Self> {
        unsafe { MmapOptions::new(len).protection(protection).map() }
    }

    /// Returns a raw pointer to the start of the mapped region.
    ///
    /// Dereferencing may trigger SIGBUS if the backing storage
    /// is unavailable.
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Returns a mutable raw pointer to the start of the mapped region.
    ///
    /// # Returns
    ///
    /// `Some(ptr)` if the mapping was created with write permission,
    /// `None` if read-only.
    pub fn as_mut_ptr(&self) -> Option<*mut u8> {
        if self.writable { Some(self.ptr) } else { None }
    }

    /// Returns the length of the mapped region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the mapped region has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if the mapping was created with write permission.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Returns `true` if the mapped region contains the given address.
    ///
    /// # Parameters
    ///
    /// * `addr` - A memory address to check.
    pub fn contains_addr(&self, addr: usize) -> bool {
        let start = self.ptr as usize;
        let end = start + self.len;
        addr >= start && addr < end
    }

    /// Applies an `madvise(2)` hint to the entire mapped region.
    ///
    /// # Parameters
    ///
    /// * `advice` - The access pattern hint to apply.
    pub fn advise(&self, advice: Advice) -> io::Result<()> {
        self.advise_range(advice, 0, self.len)
    }

    /// Applies an `madvise(2)` hint to a byte range within the mapping.
    ///
    /// The range is automatically aligned to page boundaries.
    ///
    /// # Parameters
    ///
    /// * `advice` - The access pattern hint to apply.
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to advise on.
    pub fn advise_range(&self, advice: Advice, offset: usize, len: usize) -> io::Result<()> {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "advise range exceeds mapping length",
            ));
        }

        let page = page_size();
        let aligned_offset = offset & !(page - 1);
        let aligned_len = (len + (offset - aligned_offset) + page - 1) & !(page - 1);
        let aligned_ptr = unsafe { self.ptr.add(aligned_offset) };

        let ret = unsafe {
            libc::madvise(
                aligned_ptr as *mut libc::c_void,
                aligned_len,
                advice.as_libc(),
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Flushes changes to the backing file via `msync(2)`.
    ///
    /// Only meaningful for writable, shared mappings. For private
    /// mappings this is a no-op.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to flush.
    /// * `async_flush` - If `true`, uses `MS_ASYNC` (non-blocking).
    ///   If `false`, uses `MS_SYNC` (blocks until written).
    pub fn flush(&self, offset: usize, len: usize, async_flush: bool) -> io::Result<()> {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flush range exceeds mapping length",
            ));
        }

        let page = page_size();
        let aligned_offset = offset & !(page - 1);
        let aligned_len = (len + (offset - aligned_offset) + page - 1) & !(page - 1);
        let aligned_ptr = unsafe { self.ptr.add(aligned_offset) };

        let flags = if async_flush {
            libc::MS_ASYNC
        } else {
            libc::MS_SYNC
        };
        let ret = unsafe { libc::msync(aligned_ptr as *mut libc::c_void, aligned_len, flags) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Queries which pages in a range are currently resident in memory.
    ///
    /// Uses `mincore(2)` to check page residency without touching
    /// the pages. Each element in the returned vector corresponds to
    /// one page: `true` means the page is in memory, `false` means
    /// it would trigger a page fault (and potentially a network read
    /// on NFS/EFS).
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping (page-aligned recommended).
    /// * `len` - Number of bytes to query.
    ///
    /// # Returns
    ///
    /// A `Vec<bool>` with one entry per page in the range.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the range is out of bounds or the
    /// syscall fails.
    pub fn mincore(&self, offset: usize, len: usize) -> io::Result<Vec<bool>> {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mincore range exceeds mapping length",
            ));
        }

        let page = page_size();
        let aligned_offset = offset & !(page - 1);
        let aligned_end = (offset + len + page - 1) & !(page - 1);
        let aligned_len = aligned_end - aligned_offset;
        let num_pages = aligned_len / page;

        let mut vec = vec![0u8; num_pages];
        let aligned_ptr = unsafe { self.ptr.add(aligned_offset) };

        let ret = unsafe {
            libc::mincore(
                aligned_ptr as *mut libc::c_void,
                aligned_len,
                vec.as_mut_ptr() as *mut _,
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(vec.into_iter().map(|b| b & 1 != 0).collect())
    }

    /// Locks the mapped region into physical memory via `mlock(2)`.
    ///
    /// Prevents the kernel from paging out the mapped data.
    pub fn lock(&self) -> io::Result<()> {
        let ret = unsafe { libc::mlock(self.ptr as *const libc::c_void, self.len) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Unlocks the mapped region, allowing the kernel to page it out.
    pub fn unlock(&self) -> io::Result<()> {
        let ret = unsafe { libc::munlock(self.ptr as *const libc::c_void, self.len) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

impl Drop for RawMmap {
    fn drop(&mut self) {
        // SAFETY: ptr and len were set by a successful mmap call in
        // MmapOptions::map(). This is the only place munmap is called
        // for this mapping.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}
