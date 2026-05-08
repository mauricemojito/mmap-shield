//! SIGBUS signal handler with per-thread recovery via `sigsetjmp`/`siglongjmp`.
//!
//! Installs a process-wide SIGBUS handler that converts page faults
//! into recoverable errors. Each thread maintains its own jump buffer
//! so that concurrent access from multiple threads is safe.
//!
//! # Async-Signal-Safety
//!
//! The signal handler uses only async-signal-safe operations:
//! - `pthread_getspecific` for per-thread state (POSIX async-signal-safe)
//! - Atomic loads for the region registry (lock-free)
//! - `siglongjmp` for recovery (POSIX async-signal-safe)
//!
//! # Submodules
//!
//! - [`handler`] — Signal handler installation and dispatch.
//! - [`registry`] — Lock-free region registry (RCU-style).
//! - [`thread_state`] — Per-thread jump buffer via pthread keys.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     SIGBUS      ┌──────────────────┐
//! │  mmap access  │ ──────────────► │  sigbus_handler   │
//! │  (page fault) │                 │                    │
//! └──────────────┘                 │  check si_addr     │
//!                                   │  in registered     │
//!                                   │  regions?          │
//!                                   │                    │
//!                                   │  YES → siglongjmp  │
//!                                   │  NO  → re-raise    │
//!                                   └──────────────────┘
//! ```

use std::ptr;

mod handler;
pub(crate) mod registry;
mod thread_state;

/// Callback type matching the C `rust_callback_fn` typedef.
type RustCallbackFn = unsafe extern "C" fn(*mut libc::c_void) -> *mut libc::c_void;

unsafe extern "C" {
    fn mmap_guard_protected_call(
        env: *mut u8,
        callback: RustCallbackFn,
        ctx: *mut libc::c_void,
        out: *mut *mut libc::c_void,
    ) -> libc::c_int;
}

/// Installs the process-wide SIGBUS handler.
///
/// Safe to call multiple times — installed exactly once.
pub(crate) fn install_handler() {
    handler::install();
}

/// Registers a memory region for SIGBUS interception.
///
/// # Parameters
///
/// * `start` - Start address of the mapped region.
/// * `len` - Length of the region in bytes.
pub(crate) fn register_region(start: usize, len: usize) {
    registry::register(start, len);
}

/// Unregisters a memory region from SIGBUS interception.
///
/// # Parameters
///
/// * `start` - Start address of the mapped region to remove.
pub(crate) fn unregister_region(start: usize) {
    registry::unregister(start);
}

/// Executes a closure inside a SIGBUS-protected region.
///
/// Sets up a `sigsetjmp` checkpoint before invoking `f`. If a SIGBUS
/// occurs during `f` and the fault address is in a registered region,
/// the handler performs `siglongjmp` back to the checkpoint and this
/// function returns the fault address.
///
/// # Parameters
///
/// * `f` - Closure to execute in the protected region.
///
/// # Returns
///
/// `Ok(value)` if `f` completes without a fault, or
/// `Err(fault_address)` if a SIGBUS was caught.
///
/// # Safety
///
/// The closure `f` must not hold any values that implement [`Drop`]
/// across the point where a SIGBUS could occur. `siglongjmp` does
/// not run Rust destructors — any `Drop` types alive at the fault
/// point will leak. Prefer returning [`Copy`] types from `f`.
pub(crate) unsafe fn with_sigbus_protection<F, R>(f: F) -> Result<R, usize>
where
    F: FnOnce() -> R,
{
    install_handler();

    let state = thread_state::get_or_init();

    struct CallCtx<F, R> {
        f: Option<F>,
        result: Option<R>,
    }

    let mut ctx = CallCtx {
        f: Some(f),
        result: None,
    };

    unsafe extern "C" fn trampoline<F: FnOnce() -> R, R>(
        raw_ctx: *mut libc::c_void,
    ) -> *mut libc::c_void {
        // SAFETY: raw_ctx is a valid pointer to CallCtx, passed from
        // with_sigbus_protection which holds it on the stack.
        let ctx = unsafe { &mut *(raw_ctx as *mut CallCtx<F, R>) };
        // This unwrap cannot fail: `f` is always `Some` when the
        // trampoline is called — it's set in the enclosing function
        // and consumed exactly once.
        let f = ctx
            .f
            .take()
            .expect("trampoline called with consumed closure");
        ctx.result = Some(f());
        ptr::null_mut()
    }

    // SAFETY: state is a valid pointer returned by get_or_init() for
    // the current thread. No other thread accesses this thread's state.
    unsafe { (*state).in_protected = true };

    let mut out: *mut libc::c_void = ptr::null_mut();
    // SAFETY: jmp_buf is initialized by mmap_guard_protected_call via
    // sigsetjmp. The trampoline pointer and ctx are valid for the
    // duration of this call. If SIGBUS occurs, siglongjmp returns
    // into the C function which is still on the stack.
    let jump_result = unsafe {
        mmap_guard_protected_call(
            (*state).jmp_buf.as_mut_ptr(),
            trampoline::<F, R>,
            &raw mut ctx as *mut libc::c_void,
            &mut out,
        )
    };

    // SAFETY: same state pointer, still valid, still this thread's.
    unsafe { (*state).in_protected = false };

    if jump_result != 0 {
        // SAFETY: fault_addr was set by the signal handler on this
        // thread before siglongjmp.
        let addr = unsafe { (*state).fault_addr };
        return Err(addr);
    }

    // This unwrap cannot fail: jump_result == 0 means the trampoline
    // completed normally and stored the result.
    Ok(ctx.result.expect("trampoline completed but result missing"))
}
