//! System page size query.
//!
//! Provides a cached lookup for the system page size via
//! `sysconf(_SC_PAGESIZE)`. Used throughout the crate for
//! alignment calculations and per-page iteration.

/// Returns the system page size in bytes.
///
/// # Returns
///
/// The page size as reported by `sysconf(_SC_PAGESIZE)`.
///
/// # Panics
///
/// Panics if `sysconf` returns an error (should never happen on
/// a functioning POSIX system).
pub fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(size > 0, "sysconf(_SC_PAGESIZE) failed");
    size as usize
}
