//! Positional read via `pread(2)`.
//!
//! Provides a reliable `pread_exact` that handles partial reads
//! by looping. Reusable across the fallback reader and any future
//! buffer pool implementation.

use std::io;

use crate::error::AccessError;

/// Reads exactly `buf.len()` bytes from `fd` at position `offset`.
///
/// Handles partial reads by looping until the buffer is filled.
///
/// # Parameters
///
/// * `fd` - File descriptor to read from.
/// * `buf` - Buffer to fill.
/// * `offset` - Byte offset in the file.
///
/// # Returns
///
/// `Ok(())` on success, or an [`AccessError::Io`] on failure.
pub fn pread_exact(fd: i32, buf: &mut [u8], offset: i64) -> Result<(), AccessError> {
    let mut total = 0usize;

    while total < buf.len() {
        let ret = unsafe {
            libc::pread(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
                offset + total as i64,
            )
        };

        if ret < 0 {
            return Err(AccessError::Io(io::Error::last_os_error()));
        }

        if ret == 0 {
            return Err(AccessError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "pread returned 0 before buffer was filled",
            )));
        }

        total += ret as usize;
    }

    Ok(())
}
