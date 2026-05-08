//! Scoped access guard for protected memory-mapped regions.
//!
//! A [`ReadGuard`] represents an active SIGBUS-protected session.
//! While the guard is alive, multiple slice operations can be
//! performed without re-establishing the `sigsetjmp` checkpoint
//! for each access.
//!
//! # Lifetime
//!
//! The guard borrows the [`crate::mmap::SafeMmap`] immutably,
//! preventing unmapping while slices are in use.

use crate::error::AccessError;
use crate::signal;
use crate::sys::mmap::RawMmap;

/// A SIGBUS-protected access session over a memory-mapped region.
///
/// Created via [`crate::mmap::SafeMmap::guard`]. Multiple
/// [`ReadGuard::read`] calls share a single `sigsetjmp` checkpoint.
///
/// # Safety Contract
///
/// A SIGBUS can occur on any byte access within returned slices.
/// The guard's protection covers the entire lifetime — if a fault
/// occurs, the `read` call that triggered it returns an error.
///
/// # Examples
///
/// ```no_run
/// use mmap_shield::SafeMmap;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mmap = SafeMmap::open("large_file.bin")?;
///
/// let header = mmap.read(0..64, |bytes| {
///     let mut buf = [0u8; 64];
///     buf.copy_from_slice(bytes);
///     buf
/// })?;
/// # Ok(())
/// # }
/// ```
pub struct ReadGuard<'a> {
    raw: &'a RawMmap,
}

impl<'a> ReadGuard<'a> {
    /// Creates a new read guard over the given raw mapping.
    ///
    /// # Parameters
    ///
    /// * `raw` - Reference to the underlying memory mapping.
    ///
    /// # Returns
    ///
    /// A new `ReadGuard` that protects access to the mapped region.
    pub(crate) fn new(raw: &'a RawMmap) -> Self {
        signal::install_handler();
        Self { raw }
    }

    /// Reads a byte slice from the mapped region with SIGBUS protection.
    ///
    /// Copies the requested range into a caller-owned buffer via `f`.
    /// If a SIGBUS occurs during the copy, returns an error instead
    /// of crashing the process.
    ///
    /// # Parameters
    ///
    /// * `offset` - Start offset within the mapping.
    /// * `len` - Number of bytes to access.
    /// * `f` - Closure that processes the byte slice. Should copy data
    ///   out rather than holding references, since the underlying memory
    ///   can fault at any time.
    ///
    /// # Returns
    ///
    /// `Ok(R)` with the closure's return value, or an [`AccessError`]
    /// if the range is out of bounds or a SIGBUS is caught.
    ///
    /// # Type Parameters
    ///
    /// * `R` - Return type of the processing closure.
    /// # Drop Safety
    ///
    /// If a SIGBUS occurs, `siglongjmp` skips Rust destructors.
    /// Any `Drop` types owned by `f` or returned as `R` will **leak**
    /// if a fault happens mid-execution. Prefer returning `Copy` types
    /// or small fixed-size arrays. If you must return a `Vec` or `String`,
    /// accept that it may leak on SIGBUS — this is a resource leak,
    /// not memory corruption.
    pub fn read<R>(
        &self,
        offset: usize,
        len: usize,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, AccessError> {
        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.raw.len())
        {
            return Err(AccessError::OutOfBounds {
                offset,
                len,
                mapping_len: self.raw.len(),
            });
        }

        // SAFETY: offset + len <= raw.len() is checked above.
        // The pointer arithmetic stays within the mapped region.
        let slice_ptr = unsafe { self.raw.as_ptr().add(offset) };

        // SAFETY: slice_ptr is valid for len bytes within the mapping.
        // with_sigbus_protection will catch any SIGBUS during access
        // and return Err instead of crashing.
        let result = unsafe {
            signal::with_sigbus_protection(|| {
                let slice = std::slice::from_raw_parts(slice_ptr, len);
                f(slice)
            })
        };

        match result {
            Ok(value) => Ok(value),
            Err(fault_address) => Err(AccessError::Sigbus { fault_address }),
        }
    }
}
