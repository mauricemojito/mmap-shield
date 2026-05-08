//! Timed prefetch and page probing.
//!
//! Provides utilities for touching pages on a worker thread with
//! a deadline, solving the invisible I/O stall problem on network
//! filesystems.
//!
//! The worker thread checks a cancellation flag between pages,
//! ensuring it exits promptly after a timeout rather than leaking.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::error::AccessError;
use crate::signal;
use crate::sys::page::page_size;

/// Touches one byte per page in the given range with SIGBUS protection.
///
/// Checks `cancelled` between pages. If set, returns early without
/// error — the caller has already timed out and doesn't need the result.
///
/// # Parameters
///
/// * `base_ptr` - Base address of the mapping.
/// * `offset` - Start offset within the mapping.
/// * `len` - Number of bytes in the range to probe.
/// * `cancelled` - Cancellation flag checked between page touches.
///
/// # Returns
///
/// `Ok(())` if all pages were touched successfully, or an
/// [`AccessError::Sigbus`] on the first failed page.
/// Returns `Ok(())` early if cancelled.
pub(crate) fn probe_pages(
    base_ptr: usize,
    offset: usize,
    len: usize,
    cancelled: &AtomicBool,
) -> Result<(), AccessError> {
    let page = page_size();
    let mut pos = offset;

    while pos < offset + len {
        if cancelled.load(Ordering::Relaxed) {
            return Ok(());
        }

        let r = unsafe {
            signal::with_sigbus_protection(|| {
                let ptr = (base_ptr + pos) as *const u8;
                std::ptr::read_volatile(ptr);
            })
        };

        if let Err(fault_addr) = r {
            return Err(AccessError::Sigbus {
                fault_address: fault_addr,
            });
        }

        pos += page;
    }

    Ok(())
}

/// Spawns a worker thread to probe pages and waits with a timeout.
///
/// If the worker completes before the deadline, returns its result.
/// If the deadline expires (NFS stall), sets a cancellation flag
/// so the worker exits on its next page boundary, then returns
/// [`AccessError::Timeout`].
///
/// The worker thread is joined before returning in all non-timeout
/// cases. On timeout, the cancellation flag ensures the worker
/// exits promptly rather than leaking.
///
/// # Parameters
///
/// * `base_ptr` - Base address of the mapping.
/// * `offset` - Start offset within the mapping.
/// * `len` - Number of bytes to prefetch.
/// * `timeout` - Maximum time to wait.
///
/// # Returns
///
/// `Ok(())` if all pages are resident, or an [`AccessError`] describing
/// the failure.
pub(crate) fn prefetch_with_deadline(
    base_ptr: usize,
    offset: usize,
    len: usize,
    timeout: Duration,
) -> Result<(), AccessError> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_clone = Arc::clone(&cancelled);

    let pair = Arc::new((
        std::sync::Mutex::new(None::<Result<(), AccessError>>),
        std::sync::Condvar::new(),
    ));
    let pair_clone = Arc::clone(&pair);

    let handle = std::thread::spawn(move || {
        signal::install_handler();

        let probe_result = probe_pages(base_ptr, offset, len, &cancelled_clone);

        let (lock, cvar) = &*pair_clone;
        let mut result = lock.lock().unwrap();
        *result = Some(probe_result);
        cvar.notify_one();
    });

    let (lock, cvar) = &*pair;
    let mut result = lock.lock().unwrap();

    if result.is_none() {
        let (guard, wait_result) = cvar.wait_timeout(result, timeout).unwrap();
        result = guard;

        if wait_result.timed_out() && result.is_none() {
            cancelled.store(true, Ordering::Relaxed);
            drop(result);
            let _ = handle.join();
            return Err(AccessError::Timeout {
                offset,
                len,
                deadline: timeout,
            });
        }
    }

    drop(result);
    let _ = handle.join();

    let (lock, _) = &*pair;
    let mut result = lock.lock().unwrap();

    match result.take() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(e),
        None => Err(AccessError::Timeout {
            offset,
            len,
            deadline: timeout,
        }),
    }
}
