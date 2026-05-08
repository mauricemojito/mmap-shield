//! Per-thread state for SIGBUS recovery.
//!
//! Uses `pthread_getspecific` / `pthread_setspecific` for
//! async-signal-safe access from the signal handler.
//! Each thread gets a heap-allocated [`ThreadState`] on first use,
//! cleaned up automatically on thread exit.

use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering};

/// Opaque buffer holding a `sigjmp_buf` from C.
///
/// Sized conservatively for all supported platforms.
/// `sigjmp_buf` is 196 bytes on macOS aarch64, ~200 on Linux x86_64.
/// We use 512 to be safe across all architectures.
#[repr(C, align(16))]
pub(crate) struct SigJmpBuf {
    buf: [u8; 512],
}

impl SigJmpBuf {
    pub(crate) fn new() -> Self {
        Self { buf: [0u8; 512] }
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }
}

/// Per-thread state for SIGBUS recovery.
///
/// Allocated on the heap, pointer stored via `pthread_setspecific`.
/// All fields are accessed only by the owning thread (in normal code)
/// or by the signal handler running on that thread's stack.
pub(crate) struct ThreadState {
    pub(crate) jmp_buf: SigJmpBuf,
    pub(crate) in_protected: bool,
    pub(crate) fault_addr: usize,
}

impl ThreadState {
    fn new() -> Self {
        Self {
            jmp_buf: SigJmpBuf::new(),
            in_protected: false,
            fault_addr: 0,
        }
    }
}

/// Pthread key for per-thread state, stored as an atomic for
/// safe access from signal handlers without `static mut`.
static THREAD_STATE_KEY: AtomicU32 = AtomicU32::new(0);

static KEY_INIT: Once = Once::new();

/// Destructor called by pthreads when a thread exits.
unsafe extern "C" fn destroy_thread_state(ptr: *mut libc::c_void) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr as *mut ThreadState) });
    }
}

/// Returns the pthread key, which is guaranteed to be initialized
/// after any call to [`get_or_init`].
///
/// Safe to call from the signal handler — reads an atomic.
pub(crate) fn key() -> libc::pthread_key_t {
    THREAD_STATE_KEY.load(Ordering::Acquire) as libc::pthread_key_t
}

/// Returns a pointer to the current thread's state, initializing if needed.
///
/// Safe to call from normal code. The signal handler uses
/// [`key`] + `pthread_getspecific` directly.
pub(crate) fn get_or_init() -> *mut ThreadState {
    KEY_INIT.call_once(|| {
        let mut raw_key: libc::pthread_key_t = 0;
        let ret = unsafe { libc::pthread_key_create(&mut raw_key, Some(destroy_thread_state)) };
        assert!(ret == 0, "pthread_key_create failed");
        THREAD_STATE_KEY.store(raw_key as u32, Ordering::Release);
    });

    let k = key();
    let ptr = unsafe { libc::pthread_getspecific(k) } as *mut ThreadState;

    if !ptr.is_null() {
        return ptr;
    }

    let state = Box::into_raw(Box::new(ThreadState::new()));
    unsafe {
        libc::pthread_setspecific(k, state as *mut libc::c_void);
    }
    state
}
