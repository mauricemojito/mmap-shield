//! # mmap-shield
//!
//! SIGBUS-safe memory-mapped file access for network filesystems.
//!
//! On network filesystems like NFS and Amazon EFS, memory-mapped files
//! can raise `SIGBUS` when the backing storage becomes unavailable
//! during a page fault. By default this kills the process. `mmap-shield`
//! installs a signal handler that converts these faults into recoverable
//! [`AccessError::Sigbus`] errors.
//!
//! ## Quick Start
//!
//! ```no_run
//! use mmap_shield::{SafeMmap, AccessError, Advice};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mmap = SafeMmap::open("large_file.bin")?;
//! mmap.advise(Advice::Random)?;
//!
//! match mmap.read(0..1024, |bytes| bytes.to_vec()) {
//!     Ok(data) => println!("read {} bytes", data.len()),
//!     Err(AccessError::Sigbus { fault_address }) => {
//!         eprintln!("page fault at {:#x}", fault_address);
//!     }
//!     Err(e) => eprintln!("error: {e}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │  mmap::SafeMmap                     │  high-level API
//! │  ├─ mmap::guard::ReadGuard          │  scoped access
//! │  ├─ mmap::prefetch                  │  timed prefetch
//! │  └─ poison tracking                 │
//! ├─────────────────────────────────────┤
//! │  signal                             │  SIGBUS handler
//! │  ├─ signal::handler                 │  install + dispatch
//! │  ├─ signal::registry                │  lock-free regions
//! │  └─ signal::thread_state            │  per-thread jmp_buf
//! ├─────────────────────────────────────┤
//! │  sys                                │  syscall wrappers
//! │  ├─ sys::mmap::RawMmap             │  mmap/munmap/madvise
//! │  ├─ sys::advice::Advice            │  madvise hints
//! │  ├─ sys::pread                      │  pread(2)
//! │  ├─ sys::page                       │  page size
//! │  └─ sys::fs_detect::FsType         │  NFS/CIFS/FUSE/EFS
//! ├─────────────────────────────────────┤
//! │  fallback::PreadReader              │  safe I/O fallback
//! └─────────────────────────────────────┘
//! ```
//!
//! ## Dual-Path Strategy
//!
//! ```no_run
//! use mmap_shield::{SafeMmap, fallback::PreadReader, sys::fs_detect::FsType};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let path = "/mnt/efs/data.bin";
//! let fs = FsType::detect(path)?;
//!
//! if fs.is_network() {
//!     let reader = PreadReader::open(path)?;
//!     reader.read(0..1024, |bytes| { /* process */ })?;
//! } else {
//!     let mmap = SafeMmap::open(path)?;
//!     mmap.read(0..1024, |bytes| { /* process */ })?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Safety
//!
//! The SIGBUS handler uses `siglongjmp` to recover from faults.
//! This skips Rust destructors for any `Drop` types alive at the
//! fault point. The [`SafeMmap::read`] closure should:
//!
//! - **Copy data out** rather than holding references.
//! - **Avoid owning `Drop` types** that span the memory access.
//! - **Return `Copy` types** when possible.

#[cfg(not(unix))]
compile_error!("mmap-shield requires a Unix-like operating system (Linux, macOS)");

pub mod error;
pub mod fallback;
pub mod mmap;
mod signal;
pub mod sys;

pub use error::{AccessError, MmapError};
pub use mmap::{SafeMmap, SafeMmapOptions};
pub use sys::advice::Advice;
pub use sys::mmap::{MmapOptions, Protection, Visibility};

/// Test helpers for triggering SIGBUS in controlled scenarios.
///
/// These functions expose the signal handler internals needed
/// to build custom test fixtures. Not intended for production use.
#[doc(hidden)]
pub mod signal_test_helpers {
    /// Installs the SIGBUS handler and registers a memory region.
    ///
    /// # Parameters
    ///
    /// * `start` - Start address of the mapped region.
    /// * `len` - Length of the region in bytes.
    pub fn register_and_install(start: usize, len: usize) {
        crate::signal::install_handler();
        crate::signal::register_region(start, len);
    }

    /// Unregisters a previously registered memory region.
    ///
    /// # Parameters
    ///
    /// * `start` - Start address of the region to unregister.
    pub fn unregister(start: usize) {
        crate::signal::unregister_region(start);
    }

    /// Creates a read guard for a raw mapping.
    ///
    /// The region must already be registered via [`register_and_install`].
    pub fn guard(raw: &crate::sys::mmap::RawMmap) -> crate::mmap::guard::ReadGuard<'_> {
        crate::mmap::guard::ReadGuard::new(raw)
    }
}
