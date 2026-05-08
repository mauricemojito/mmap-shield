//! High-level SIGBUS-safe memory-mapped file access.
//!
//! [`SafeMmap`] wraps a raw memory mapping with automatic signal
//! handler installation, region registration, fault counting,
//! and poisoning. It is the primary entry point for this crate.
//!
//! # Submodules
//!
//! - [`guard`] — Scoped access guard for multiple reads.
//! - `prefetch` — Timed prefetch and page probing (internal).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use crate::error::{AccessError, MmapError};
use crate::signal;
use crate::sys::advice::Advice;
use crate::sys::mmap::{MmapOptions, Protection, RawMmap, Visibility};
use crate::sys::page::page_size;

pub mod guard;
mod prefetch;

pub use guard::ReadGuard;

/// Default number of SIGBUS faults before a mapping is poisoned.
const DEFAULT_MAX_SIGBUS: u32 = 3;

/// Events emitted by [`SafeMmap`] for observability.
///
/// Passed to the metrics callback registered via
/// [`SafeMmapOptions::on_event`].
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::mmap::MmapEvent;
///
/// fn log_event(event: &MmapEvent) {
///     match event {
///         MmapEvent::Sigbus { fault_address } => {
///             eprintln!("SIGBUS at {fault_address:#x}");
///         }
///         MmapEvent::Poisoned { sigbus_count } => {
///             eprintln!("poisoned after {sigbus_count} faults");
///         }
///         MmapEvent::PrefetchTimeout { offset, len } => {
///             eprintln!("prefetch timeout at [{offset}..{}]", offset + len);
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmapEvent {
    /// A SIGBUS fault was caught and recovered.
    Sigbus { fault_address: usize },

    /// The mapping was poisoned after repeated faults.
    Poisoned { sigbus_count: u32 },

    /// A prefetch operation timed out.
    PrefetchTimeout { offset: usize, len: usize },
}

/// Type alias for the metrics callback function.
pub type EventCallback = Arc<dyn Fn(&MmapEvent) + Send + Sync>;

/// A SIGBUS-safe, memory-mapped file.
///
/// Wraps a raw `mmap(2)` mapping with signal handling that converts
/// SIGBUS page faults into [`AccessError::Sigbus`] errors. Designed
/// for use with network filesystems (NFS, EFS) where the backing
/// storage may become temporarily unavailable.
///
/// Supports both read-only and read-write mappings via the builder
/// pattern ([`SafeMmap::options`]).
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::SafeMmap;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Simple read-only:
/// let mmap = SafeMmap::open("data.bin")?;
/// let header: Vec<u8> = mmap.read(0..1024, |bytes| bytes.to_vec())?;
///
/// // Builder with options:
/// let mmap = SafeMmap::options()
///     .writable(true)
///     .offset(4096)
///     .len(8192)
///     .max_sigbus(5)
///     .open("data.bin")?;
/// # Ok(())
/// # }
/// ```
///
/// # Poisoning
///
/// After 3 SIGBUS faults (configurable), the mapping is
/// "poisoned" and all subsequent access attempts return
/// [`AccessError::Poisoned`] without touching memory.
#[must_use]
pub struct SafeMmap {
    raw: RawMmap,
    path: PathBuf,
    _file: File,
    sigbus_count: AtomicU32,
    poisoned: AtomicBool,
    max_sigbus: u32,
    on_event: Option<EventCallback>,
}

// Compile-time assertions
const _: () = {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}
    assert_send::<SafeMmap>();
    assert_sync::<SafeMmap>();
};

/// Builder for constructing [`SafeMmap`] instances with full control
/// over mapping parameters.
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::SafeMmap;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mmap = SafeMmap::options()
///     .writable(true)
///     .shared(true)
///     .offset(0)
///     .len(1024 * 1024)
///     .max_sigbus(10)
///     .populate(true)
///     .open("data.bin")?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub struct SafeMmapOptions {
    writable: bool,
    shared: bool,
    offset: u64,
    len: Option<usize>,
    max_sigbus: u32,
    populate: bool,
    on_event: Option<EventCallback>,
    flock: bool,
}

impl SafeMmapOptions {
    fn new() -> Self {
        Self {
            writable: false,
            shared: false,
            offset: 0,
            len: None,
            max_sigbus: DEFAULT_MAX_SIGBUS,
            populate: false,
            on_event: None,
            flock: false,
        }
    }

    /// Enables read-write access.
    ///
    /// When `true`, the file is opened with write permission and the
    /// mapping is created with `PROT_READ | PROT_WRITE`.
    /// Defaults to `false` (read-only).
    ///
    /// # Parameters
    ///
    /// * `writable` - Whether to enable write access.
    pub fn writable(mut self, writable: bool) -> Self {
        self.writable = writable;
        self
    }

    /// Enables shared mapping visibility.
    ///
    /// When `true`, uses `MAP_SHARED` — writes are visible to other
    /// processes and are written back to the file. When `false`, uses
    /// `MAP_PRIVATE` (copy-on-write). Defaults to `false`.
    ///
    /// # Parameters
    ///
    /// * `shared` - Whether to use shared visibility.
    pub fn shared(mut self, shared: bool) -> Self {
        self.shared = shared;
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

    /// Sets the number of bytes to map.
    ///
    /// If not set, maps from `offset` to the end of the file.
    ///
    /// # Parameters
    ///
    /// * `len` - Number of bytes to map.
    pub fn len(mut self, len: usize) -> Self {
        self.len = Some(len);
        self
    }

    /// Sets the maximum number of SIGBUS faults before poisoning.
    ///
    /// Defaults to 3. Set to `u32::MAX` to disable poisoning.
    ///
    /// # Parameters
    ///
    /// * `max` - Maximum fault count.
    pub fn max_sigbus(mut self, max: u32) -> Self {
        self.max_sigbus = max;
        self
    }

    /// Enables `MAP_POPULATE` to pre-fault all pages on creation.
    ///
    /// Linux only. Ignored on other platforms.
    ///
    /// # Parameters
    ///
    /// * `populate` - Whether to populate pages on map creation.
    pub fn populate(mut self, populate: bool) -> Self {
        self.populate = populate;
        self
    }

    /// Registers a callback for observability events.
    ///
    /// The callback is invoked on SIGBUS faults, poisoning, and
    /// prefetch timeouts. Useful for metrics and monitoring.
    ///
    /// # Parameters
    ///
    /// * `callback` - Function called on each event.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    /// use std::sync::Arc;
    ///
    /// let mmap = SafeMmap::options()
    ///     .on_event(Arc::new(|event| {
    ///         eprintln!("mmap event: {event:?}");
    ///     }))
    ///     .open("data.bin")
    ///     .unwrap();
    /// ```
    pub fn on_event(mut self, callback: EventCallback) -> Self {
        self.on_event = Some(callback);
        self
    }

    /// Acquires an advisory file lock before mapping.
    ///
    /// When `true`, acquires a shared (`LOCK_SH`) or exclusive (`LOCK_EX`)
    /// advisory lock via `flock(2)` before creating the mapping. Shared
    /// locks are used for read-only mappings, exclusive for writable.
    ///
    /// Advisory locks are **cooperative** — they only prevent conflicts
    /// with other processes that also use `flock`. They do not prevent
    /// uncooperative writers from modifying the file.
    ///
    /// The lock is held for the lifetime of the [`SafeMmap`] and
    /// released automatically on drop.
    ///
    /// Defaults to `false`.
    ///
    /// # Parameters
    ///
    /// * `lock` - Whether to acquire an advisory lock.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::options()
    ///     .flock(true)
    ///     .open("data.bin")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn flock(mut self, lock: bool) -> Self {
        self.flock = lock;
        self
    }

    /// Opens and memory-maps a file with the configured options.
    ///
    /// # Parameters
    ///
    /// * `path` - Path to the file to map.
    ///
    /// # Returns
    ///
    /// A new [`SafeMmap`] instance.
    ///
    /// # Errors
    ///
    /// Returns [`MmapError::EmptyFile`] if the computed mapping length
    /// is zero, or [`MmapError::Io`] if the file cannot be opened or
    /// mapped.
    pub fn open(self, path: impl AsRef<Path>) -> Result<SafeMmap, MmapError> {
        let path = path.as_ref();

        let file = OpenOptions::new()
            .read(true)
            .write(self.writable)
            .open(path)?;

        if self.flock {
            let op = if self.writable {
                libc::LOCK_EX | libc::LOCK_NB
            } else {
                libc::LOCK_SH | libc::LOCK_NB
            };
            // SAFETY: fd is a valid open file descriptor.
            let ret = unsafe { libc::flock(file.as_raw_fd(), op) };
            if ret != 0 {
                return Err(MmapError::Io(io::Error::last_os_error()));
            }
        }

        let file_len = file.metadata()?.len();

        if file_len == 0 && self.len.is_none() {
            return Err(MmapError::EmptyFile);
        }

        let map_len = match self.len {
            Some(len) => len,
            None if self.offset >= file_len => {
                return Err(MmapError::OffsetBeyondFile {
                    offset: self.offset,
                    file_len,
                });
            }
            None => (file_len - self.offset) as usize,
        };

        if map_len == 0 {
            return Err(MmapError::EmptyFile);
        }

        let protection = if self.writable {
            Protection::ReadWrite
        } else {
            Protection::Read
        };

        let visibility = if self.shared {
            Visibility::Shared
        } else {
            Visibility::Private
        };

        let mut opts = MmapOptions::new(map_len)
            .fd(file.as_raw_fd())
            .offset(self.offset)
            .protection(protection)
            .visibility(visibility);

        if self.populate {
            opts = opts.populate();
        }

        let raw = unsafe { opts.map()? };

        signal::install_handler();
        signal::register_region(raw.as_ptr() as usize, raw.len());

        Ok(SafeMmap {
            raw,
            path: path.to_path_buf(),
            _file: file,
            sigbus_count: AtomicU32::new(0),
            poisoned: AtomicBool::new(false),
            max_sigbus: self.max_sigbus,
            on_event: self.on_event,
        })
    }
}

impl SafeMmap {
    /// Opens and memory-maps a file with default options (read-only, private).
    ///
    /// # Parameters
    ///
    /// * `path` - Path to the file to map.
    ///
    /// # Returns
    ///
    /// A new [`SafeMmap`] instance.
    ///
    /// # Errors
    ///
    /// Returns [`MmapError::EmptyFile`] if the file is zero-length,
    /// or [`MmapError::Io`] if the file cannot be opened or mapped.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// let mmap = SafeMmap::open("my_file.bin").expect("failed to open");
    /// ```
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MmapError> {
        SafeMmapOptions::new().open(path)
    }

    /// Returns a builder for constructing a [`SafeMmap`] with
    /// custom options.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::options()
    ///     .writable(true)
    ///     .open("data.bin")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn options() -> SafeMmapOptions {
        SafeMmapOptions::new()
    }

    /// Sets the maximum number of SIGBUS faults before poisoning.
    ///
    /// # Parameters
    ///
    /// * `max` - Maximum fault count. Set to `u32::MAX` to disable poisoning.
    ///
    /// # Returns
    ///
    /// `self` for method chaining.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// let mmap = SafeMmap::open("data.bin")
    ///     .unwrap()
    ///     .with_max_sigbus(5);
    /// ```
    pub fn with_max_sigbus(mut self, max: u32) -> Self {
        self.max_sigbus = max;
        self
    }

    /// Reads a byte range with SIGBUS protection.
    ///
    /// # Parameters
    ///
    /// * `range` - Byte range to read from the mapping.
    /// * `f` - Closure that processes the byte slice.
    ///
    /// # Returns
    ///
    /// `Ok(R)` with the closure's return value, or an [`AccessError`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("data.bin")?;
    /// let first_four: [u8; 4] = mmap.read(0..4, |bytes| {
    ///     bytes.try_into().unwrap()
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn read<R>(
        &self,
        range: std::ops::Range<usize>,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, AccessError> {
        self.check_poisoned()?;

        let guard = self.guard();
        let result = guard.read(range.start, range.end - range.start, f);

        if let Err(e @ AccessError::Sigbus { .. }) = &result {
            self.record_sigbus_from(e);
        }

        result
    }

    /// Writes data into the mapping with SIGBUS protection.
    ///
    /// The mapping must have been created with write permission
    /// (via [`SafeMmap::options`] with [`SafeMmapOptions::writable`]).
    ///
    /// # Parameters
    ///
    /// * `offset` - Byte offset to write at.
    /// * `data` - Bytes to write.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`AccessError`].
    ///
    /// # Errors
    ///
    /// - [`AccessError::Io`] if the mapping is read-only.
    /// - [`AccessError::OutOfBounds`] if the write exceeds the mapping.
    /// - [`AccessError::Sigbus`] if a page fault occurred during write.
    /// - [`AccessError::Poisoned`] if the mapping is poisoned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::options()
    ///     .writable(true)
    ///     .shared(true)
    ///     .open("data.bin")?;
    /// mmap.write(0, b"hello")?;
    /// mmap.flush(0, 5, false)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<(), AccessError> {
        self.check_poisoned()?;
        self.check_bounds(offset, data.len())?;

        let dst = self.raw.as_mut_ptr().ok_or_else(|| {
            AccessError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mapping is read-only",
            ))
        })?;

        // SAFETY: dst is a writable pointer (checked via as_mut_ptr).
        // offset + data.len() <= raw.len() is checked by check_bounds.
        // with_sigbus_protection catches any SIGBUS during the write.
        let result = unsafe {
            signal::with_sigbus_protection(|| {
                let target = dst.add(offset);
                std::ptr::copy_nonoverlapping(data.as_ptr(), target, data.len());
            })
        };

        match result {
            Ok(()) => Ok(()),
            Err(fault_address) => {
                let err = AccessError::Sigbus { fault_address };
                self.record_sigbus_from(&err);
                Err(err)
            }
        }
    }

    /// Flushes changes to the backing file via `msync(2)`.
    ///
    /// Only meaningful for writable, shared mappings.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to flush.
    /// * `async_flush` - If `true`, returns immediately (`MS_ASYNC`).
    ///   If `false`, blocks until written (`MS_SYNC`).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`io::Error`] on failure.
    pub fn flush(&self, offset: usize, len: usize, async_flush: bool) -> io::Result<()> {
        self.raw.flush(offset, len, async_flush)
    }

    /// Creates a [`ReadGuard`] for multiple reads within a single
    /// protected session.
    ///
    /// # Returns
    ///
    /// A [`ReadGuard`] borrowing this mapping.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("data.bin")?;
    /// let guard = mmap.guard();
    ///
    /// let header = guard.read(0, 64, |b| b.to_vec())?;
    /// let chunk  = guard.read(4096, 256, |b| b.to_vec())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn guard(&self) -> ReadGuard<'_> {
        ReadGuard::new(&self.raw)
    }

    /// Applies an `madvise(2)` hint to the entire mapping.
    ///
    /// # Parameters
    ///
    /// * `advice` - The access pattern hint.
    pub fn advise(&self, advice: Advice) -> io::Result<()> {
        self.raw.advise(advice)
    }

    /// Applies an `madvise(2)` hint to a byte range.
    ///
    /// # Parameters
    ///
    /// * `advice` - The access pattern hint.
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to advise on.
    pub fn advise_range(&self, advice: Advice, offset: usize, len: usize) -> io::Result<()> {
        self.raw.advise_range(advice, offset, len)
    }

    /// Pre-touches pages in the specified range to trigger early faults.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes in the range to probe.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("data.bin")?;
    /// mmap.probe(0, 4096)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn probe(&self, offset: usize, len: usize) -> Result<(), AccessError> {
        self.check_poisoned()?;
        self.check_bounds(offset, len)?;

        let guard = self.guard();
        let page = page_size();
        let mut pos = offset;

        while pos < offset + len {
            let result = guard.read(pos, 1, |b| b[0]);
            if let Err(e) = result {
                self.record_sigbus_from(&e);
                return Err(e);
            }
            pos += page;
        }

        Ok(())
    }

    /// Releases pages in the specified range back to the kernel.
    ///
    /// Issues `madvise(MADV_DONTNEED)` on the range.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to release.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("large_file.bin")?;
    /// let chunk = mmap.read(4096..8192, |b| b.to_vec())?;
    /// mmap.evict(4096, 4096)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn evict(&self, offset: usize, len: usize) -> io::Result<()> {
        self.raw.advise_range(Advice::DontNeed, offset, len)
    }

    /// Prefetches pages via `madvise(MADV_WILLNEED)`.
    ///
    /// Non-blocking. Initiates background readahead.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to prefetch.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("large_file.bin")?;
    /// mmap.prefetch(8192, 4096)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn prefetch(&self, offset: usize, len: usize) -> io::Result<()> {
        self.raw.advise_range(Advice::WillNeed, offset, len)
    }

    /// Prefetches and verifies pages with a timeout.
    ///
    /// Spawns a worker thread that touches every page in the range.
    /// If the deadline expires (NFS stall), returns [`AccessError::Timeout`].
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to prefetch and verify.
    /// * `timeout` - Maximum time to wait.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("large_file.bin")?;
    ///
    /// match mmap.prefetch_with_timeout(4096, 4096, Duration::from_secs(5)) {
    ///     Ok(()) => {
    ///         let data = mmap.read(4096..8192, |b| b.to_vec())?;
    ///     }
    ///     Err(e) => eprintln!("prefetch failed: {e}"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn prefetch_with_timeout(
        &self,
        offset: usize,
        len: usize,
        timeout: Duration,
    ) -> Result<(), AccessError> {
        self.check_poisoned()?;
        self.check_bounds(offset, len)?;

        let base_ptr = self.raw.as_ptr() as usize;
        let result = prefetch::prefetch_with_deadline(base_ptr, offset, len, timeout);

        match &result {
            Err(e @ AccessError::Sigbus { .. }) => self.record_sigbus_from(e),
            Err(AccessError::Timeout { .. }) => {
                self.emit_event(&MmapEvent::PrefetchTimeout { offset, len });
            }
            _ => {}
        }

        result
    }

    /// Reads a byte range into a caller-owned buffer with SIGBUS protection.
    ///
    /// Copies bytes directly into `buf` without requiring a closure.
    /// Useful for decoders that want `&mut [u8]`.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `buf` - Destination buffer to fill.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`AccessError`] on failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("data.bin")?;
    /// let mut header = [0u8; 64];
    /// mmap.read_into(0, &mut header)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_into(&self, offset: usize, buf: &mut [u8]) -> Result<(), AccessError> {
        self.check_poisoned()?;
        self.check_bounds(offset, buf.len())?;

        let src = self.raw.as_ptr();

        // SAFETY: offset + buf.len() <= raw.len() is checked by
        // check_bounds. src is a valid pointer from the mapping.
        // with_sigbus_protection catches any SIGBUS during the copy.
        let result = unsafe {
            signal::with_sigbus_protection(|| {
                let src_ptr = src.add(offset);
                std::ptr::copy_nonoverlapping(src_ptr, buf.as_mut_ptr(), buf.len());
            })
        };

        match result {
            Ok(()) => Ok(()),
            Err(fault_address) => {
                let err = AccessError::Sigbus { fault_address };
                self.record_sigbus_from(&err);
                Err(err)
            }
        }
    }

    /// Queries which pages in a range are currently resident in memory.
    ///
    /// Uses `mincore(2)` to check residency without touching pages.
    /// Useful to skip `prefetch_with_timeout` for pages already in memory.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to query.
    ///
    /// # Returns
    ///
    /// A `Vec<bool>` with one entry per page: `true` = resident,
    /// `false` = would page fault.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("data.bin")?;
    /// let resident = mmap.resident_pages(0, mmap.len())?;
    /// let cached = resident.iter().filter(|&&r| r).count();
    /// println!("{}/{} pages resident", cached, resident.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn resident_pages(&self, offset: usize, len: usize) -> io::Result<Vec<bool>> {
        self.raw.mincore(offset, len)
    }

    /// Locks a byte range into physical memory via `mlock(2)`.
    ///
    /// Prevents the kernel from paging out the specified range.
    /// Useful for pinning hot data like file headers or indices
    /// so they're never evicted.
    ///
    /// # Warning
    ///
    /// On network filesystems, `mlock` forces the kernel to fault in
    /// all pages in the range. If the storage is unavailable, this
    /// can stall the calling thread. Consider checking
    /// [`SafeMmap::is_poisoned`] before calling, and use
    /// [`SafeMmap::prefetch_with_timeout`] for stall-bounded page-in.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to lock.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`io::Error`] if the syscall fails
    /// (e.g., insufficient `RLIMIT_MEMLOCK`).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("data.bin")?;
    /// mmap.lock_range(0, 4096)?;  // pin the header
    /// # Ok(())
    /// # }
    /// ```
    pub fn lock_range(&self, offset: usize, len: usize) -> io::Result<()> {
        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.raw.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "lock range exceeds mapping length",
            ));
        }

        let ptr = unsafe { self.raw.as_ptr().add(offset) };
        let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Unlocks a previously locked byte range.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to unlock.
    pub fn unlock_range(&self, offset: usize, len: usize) -> io::Result<()> {
        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.raw.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unlock range exceeds mapping length",
            ));
        }

        let ptr = unsafe { self.raw.as_ptr().add(offset) };
        let ret = unsafe { libc::munlock(ptr as *const libc::c_void, len) };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Returns the length of the mapping in bytes.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Returns `true` if the mapping has zero length.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Returns `true` if the mapping is writable.
    pub fn is_writable(&self) -> bool {
        self.raw.is_writable()
    }

    /// Returns the path this mapping was created from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the number of SIGBUS faults recorded for this mapping.
    pub fn sigbus_count(&self) -> u32 {
        self.sigbus_count.load(Ordering::Relaxed)
    }

    /// Returns `true` if this mapping has been poisoned.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }

    /// Resets the poison state and fault counter.
    ///
    /// After a network filesystem recovers, call this to allow
    /// the mapping to accept reads again. The fault counter is
    /// reset to zero and the poisoned flag is cleared.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mmap_shield::SafeMmap;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mmap = SafeMmap::open("data.bin")?;
    ///
    /// // ... NFS dies, mapping gets poisoned ...
    ///
    /// // NFS recovers — reset and retry:
    /// mmap.reset_poison();
    /// let data = mmap.read(0..1024, |b| b.to_vec())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn reset_poison(&self) {
        self.poisoned.store(false, Ordering::Relaxed);
        self.sigbus_count.store(0, Ordering::Relaxed);
    }

    fn check_poisoned(&self) -> Result<(), AccessError> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(AccessError::Poisoned {
                sigbus_count: self.sigbus_count.load(Ordering::Relaxed),
            });
        }
        Ok(())
    }

    fn check_bounds(&self, offset: usize, len: usize) -> Result<(), AccessError> {
        let end = offset.checked_add(len).ok_or(AccessError::OutOfBounds {
            offset,
            len,
            mapping_len: self.raw.len(),
        })?;

        if end > self.raw.len() {
            return Err(AccessError::OutOfBounds {
                offset,
                len,
                mapping_len: self.raw.len(),
            });
        }
        Ok(())
    }

    fn record_sigbus_from(&self, err: &AccessError) {
        let fault_address = match err {
            AccessError::Sigbus { fault_address } => *fault_address,
            _ => 0,
        };

        let count = self.sigbus_count.fetch_add(1, Ordering::Relaxed) + 1;

        self.emit_event(&MmapEvent::Sigbus { fault_address });

        if count >= self.max_sigbus {
            self.poisoned.store(true, Ordering::Relaxed);
            self.emit_event(&MmapEvent::Poisoned {
                sigbus_count: count,
            });
        }
    }

    fn emit_event(&self, event: &MmapEvent) {
        if let Some(cb) = &self.on_event {
            cb(event);
        }
    }
}

impl Drop for SafeMmap {
    fn drop(&mut self) {
        signal::unregister_region(self.raw.as_ptr() as usize);
    }
}

impl SafeMmap {
    /// Returns an unprotected `&[u8]` view of the mapped region.
    ///
    /// # Safety
    ///
    /// Accessing the returned slice can trigger SIGBUS if the backing
    /// storage is unavailable. The caller must ensure all pages in the
    /// accessed range are resident (e.g., via [`SafeMmap::probe`] or
    /// [`SafeMmap::resident_pages`]) or that the file is on local storage.
    ///
    /// Use [`SafeMmap::read`] or [`SafeMmap::read_into`] for
    /// SIGBUS-protected access instead.
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.raw.as_ptr(), self.raw.len()) }
    }

    /// Returns an unprotected `&mut [u8]` view of the mapped region.
    ///
    /// # Safety
    ///
    /// Same SIGBUS caveat as [`SafeMmap::as_slice`]. Additionally,
    /// the caller must ensure no other references to the mapping
    /// exist for the lifetime of the returned slice.
    ///
    /// # Returns
    ///
    /// `Some(&mut [u8])` if the mapping is writable, `None` if read-only.
    pub unsafe fn as_mut_slice(&mut self) -> Option<&mut [u8]> {
        let ptr = self.raw.as_mut_ptr()?;
        Some(unsafe { std::slice::from_raw_parts_mut(ptr, self.raw.len()) })
    }
}
