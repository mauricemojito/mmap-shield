//! Lock-free region registry for the SIGBUS handler.
//!
//! Maintains a set of registered memory regions using an
//! `AtomicPtr` to immutable snapshots (RCU-style). The signal
//! handler reads the current snapshot via a single atomic load —
//! no locks, no allocations, fully async-signal-safe.
//!
//! Mutations (register/unregister) are serialized by a mutex
//! that is never held inside the signal handler. Old snapshots
//! are freed on the next mutation via deferred reclamation.

use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, Ordering};

/// A registered memory region that the SIGBUS handler should intercept.
#[derive(Clone, Copy)]
struct RegisteredRegion {
    start: usize,
    end: usize,
}

/// Snapshot of registered regions, immutable once published.
struct RegionSnapshot {
    regions: Vec<RegisteredRegion>,
}

/// Wrapper to allow `*mut RegionSnapshot` in a `Mutex`.
///
/// Safe because the retired list is only accessed under the mutex,
/// and the signal handler never touches it.
struct RetiredPtr(*mut RegionSnapshot);
unsafe impl Send for RetiredPtr {}

/// Global pointer to the current region snapshot.
/// Updated atomically; the signal handler reads it lock-free.
static REGION_SNAPSHOT: AtomicPtr<RegionSnapshot> = AtomicPtr::new(ptr::null_mut());

/// Two-generation retired snapshot tracker.
///
/// `previous` holds snapshots retired two mutations ago (safe to free).
/// `current` holds snapshots retired in the most recent mutation.
/// On each mutation, `previous` is drained (freed), then `current`
/// is moved to `previous`. This guarantees at least two full
/// mutex-guarded operations elapse before any snapshot is freed,
/// ensuring no signal handler can still be reading it.
struct RetiredTracker {
    previous: Vec<RetiredPtr>,
    current: Vec<RetiredPtr>,
}

impl RetiredTracker {
    const fn new() -> Self {
        Self {
            previous: Vec::new(),
            current: Vec::new(),
        }
    }
}

/// Mutex protecting mutation of the region registry and retired tracking.
/// Only held during register/unregister (never in the signal handler).
static REGION_MUTEX: Mutex<RetiredTracker> = Mutex::new(RetiredTracker::new());

/// Registers a memory region for SIGBUS interception.
///
/// Creates a new snapshot of all registered regions and publishes
/// it atomically. The signal handler will see the new snapshot
/// on its next invocation.
///
/// # Parameters
///
/// * `start` - Start address of the mapped region.
/// * `len` - Length of the region in bytes.
pub(crate) fn register(start: usize, len: usize) {
    let mut tracker = REGION_MUTEX.lock().expect("region mutex poisoned");

    rotate_retired(&mut tracker);

    let old_ptr = REGION_SNAPSHOT.load(Ordering::Acquire);
    let mut regions = if old_ptr.is_null() {
        Vec::new()
    } else {
        unsafe { &*old_ptr }.regions.clone()
    };

    regions.push(RegisteredRegion {
        start,
        end: start + len,
    });

    let new_snapshot = Box::into_raw(Box::new(RegionSnapshot { regions }));
    let prev = REGION_SNAPSHOT.swap(new_snapshot, Ordering::Release);

    if !prev.is_null() {
        tracker.current.push(RetiredPtr(prev));
    }
}

/// Unregisters a memory region from SIGBUS interception.
///
/// Creates a new snapshot without the specified region.
///
/// # Parameters
///
/// * `start` - Start address of the mapped region to remove.
pub(crate) fn unregister(start: usize) {
    let mut tracker = REGION_MUTEX.lock().expect("region mutex poisoned");

    rotate_retired(&mut tracker);

    let old_ptr = REGION_SNAPSHOT.load(Ordering::Acquire);
    let mut regions = if old_ptr.is_null() {
        return;
    } else {
        unsafe { &*old_ptr }.regions.clone()
    };

    regions.retain(|r| r.start != start);

    let new_snapshot = Box::into_raw(Box::new(RegionSnapshot { regions }));
    let prev = REGION_SNAPSHOT.swap(new_snapshot, Ordering::Release);

    if !prev.is_null() {
        tracker.current.push(RetiredPtr(prev));
    }
}

/// Checks whether a fault address belongs to a registered region.
///
/// Lock-free: reads the current snapshot via atomic load.
/// Safe to call from a signal handler.
///
/// # Parameters
///
/// * `addr` - The fault address from `siginfo_t.si_addr`.
///
/// # Returns
///
/// `true` if the address falls within any registered region.
pub(crate) fn contains(addr: usize) -> bool {
    let snapshot_ptr = REGION_SNAPSHOT.load(Ordering::Acquire);

    if snapshot_ptr.is_null() {
        return false;
    }

    let snapshot = unsafe { &*snapshot_ptr };
    snapshot
        .regions
        .iter()
        .any(|r| addr >= r.start && addr < r.end)
}

/// Rotates the two-generation retired tracker.
///
/// Frees snapshots from the `previous` generation (two mutations old),
/// then moves `current` to `previous`. This guarantees two full
/// mutex-guarded operations elapse before any snapshot is freed.
///
/// Safety argument:
/// - A signal handler reads a snapshot via atomic load, processes it
///   (nanoseconds), then either longjmps or returns.
/// - Between the atomic load and the dereference, the handler could
///   theoretically be preempted. But preemption during a signal handler
///   means another signal arrived, which masks the original.
/// - Two full mutex-guarded operations (each requiring user-space
///   scheduling, memory allocation, and an atomic swap) guarantee
///   far more wall-clock time than any signal handler execution.
fn rotate_retired(tracker: &mut RetiredTracker) {
    for ptr in tracker.previous.drain(..) {
        unsafe { drop(Box::from_raw(ptr.0)) };
    }
    std::mem::swap(&mut tracker.previous, &mut tracker.current);
}
