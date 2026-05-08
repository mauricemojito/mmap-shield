//! SIGBUS signal handler installation and dispatch.
//!
//! The handler uses only async-signal-safe operations:
//! - `pthread_getspecific` to access per-thread state
//! - Atomic load to read the region snapshot
//! - `siglongjmp` to recover
//!
//! If the fault address is not in a registered region or the thread
//! is not in a protected block, restores the default handler and
//! re-raises SIGBUS.

use std::ptr;
use std::sync::Once;

use super::registry;
use super::thread_state::{self, ThreadState};

unsafe extern "C" {
    pub(crate) fn mmap_guard_siglongjmp(env: *mut u8, val: libc::c_int) -> !;
}

static HANDLER_INIT: Once = Once::new();

/// SIGBUS signal handler.
///
/// Checks if the fault address is in a registered region and the
/// thread is in a protected block. If so, records the fault address
/// and jumps back to the `sigsetjmp` checkpoint. Otherwise restores
/// the default handler and re-raises.
unsafe extern "C" fn sigbus_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    let fault_addr = unsafe { (*info).si_addr() as usize };

    let state_ptr = unsafe { libc::pthread_getspecific(thread_state::key()) } as *mut ThreadState;

    if state_ptr.is_null() {
        restore_default_and_reraise();
        return;
    }

    let state = unsafe { &mut *state_ptr };

    if !state.in_protected {
        restore_default_and_reraise();
        return;
    }

    if !registry::contains(fault_addr) {
        restore_default_and_reraise();
        return;
    }

    state.fault_addr = fault_addr;
    state.in_protected = false;

    unsafe {
        mmap_guard_siglongjmp(state.jmp_buf.as_mut_ptr(), 1);
    }
}

/// Restores the default SIGBUS handler and re-raises the signal.
fn restore_default_and_reraise() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGBUS, &sa, ptr::null_mut());
        libc::raise(libc::SIGBUS);
    }
}

/// Installs the process-wide SIGBUS handler.
///
/// Safe to call multiple times — the handler is installed exactly once
/// via [`Once`]. Subsequent calls are no-ops.
///
/// # Panics
///
/// Panics if `sigaction(2)` fails, which indicates a broken system.
pub(crate) fn install() {
    HANDLER_INIT.call_once(|| unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigbus_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
        libc::sigemptyset(&mut sa.sa_mask);

        let ret = libc::sigaction(libc::SIGBUS, &sa, ptr::null_mut());
        assert!(
            ret == 0,
            "failed to install SIGBUS handler: {}",
            std::io::Error::last_os_error()
        );
    });
}
