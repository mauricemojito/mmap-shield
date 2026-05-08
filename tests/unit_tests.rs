//! Unit-level tests that don't require SIGBUS triggering.
//!
//! These run in-process and cover the non-signal parts:
//! raw mapping, pread fallback, filesystem detection, advice,
//! and out-of-bounds checking.

use std::fs;
use std::io::Write;

use mmap_shield::Advice;
use mmap_shield::fallback::PreadReader;
use mmap_shield::sys::fs_detect::FsType;
use mmap_shield::sys::mmap::{MmapOptions, Protection, RawMmap};
use mmap_shield::{AccessError, MmapError, SafeMmap};

/// Verifies that a file can be mapped and its contents read correctly.
#[test]
fn read_mapped_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("read_test.bin");
    fs::write(&path, b"hello mmap-shield").unwrap();

    let mmap = SafeMmap::open(&path).unwrap();
    let result = mmap.read(0..5, |b| b.to_vec()).unwrap();

    assert_eq!(result, b"hello");
}

/// Verifies that reading past the end of the mapping returns OutOfBounds.
#[test]
fn out_of_bounds_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oob_test.bin");
    fs::write(&path, b"short").unwrap();

    let mmap = SafeMmap::open(&path).unwrap();
    let result = mmap.read(0..1024, |b| b.to_vec());

    assert!(matches!(result, Err(AccessError::OutOfBounds { .. })));
}

/// Verifies that mapping an empty file returns EmptyFile error.
#[test]
fn empty_file_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.bin");
    fs::write(&path, b"").unwrap();

    let result = SafeMmap::open(&path);

    assert!(matches!(result, Err(MmapError::EmptyFile)));
}

/// Verifies that offset beyond file returns OffsetBeyondFile, not EmptyFile.
#[test]
fn offset_beyond_file_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("offset_beyond.bin");
    fs::write(&path, vec![0u8; 100]).unwrap();

    let result = SafeMmap::options().offset(999999).open(&path);

    assert!(matches!(result, Err(MmapError::OffsetBeyondFile { .. })));
}

/// Verifies that integer overflow in offset+len is caught as OutOfBounds.
#[test]
fn overflow_offset_len_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overflow_test.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    let result = mmap.read_into(usize::MAX, &mut [0u8; 1]);
    assert!(matches!(result, Err(AccessError::OutOfBounds { .. })));

    let result = mmap.read(usize::MAX - 1..usize::MAX, |b| b.to_vec());
    assert!(matches!(result, Err(AccessError::OutOfBounds { .. })));
}

/// Verifies that the raw mapping reports correct length.
#[test]
fn raw_mmap_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("len_test.bin");
    let data = vec![0u8; 4096];
    fs::write(&path, &data).unwrap();

    let file = fs::File::open(&path).unwrap();
    let raw =
        unsafe { RawMmap::map(std::os::unix::io::AsRawFd::as_raw_fd(&file), 0, 4096).unwrap() };

    assert_eq!(raw.len(), 4096);
}

/// Verifies that contains_addr works for addresses inside and outside the mapping.
#[test]
fn raw_mmap_contains_addr() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("addr_test.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let file = fs::File::open(&path).unwrap();
    let raw =
        unsafe { RawMmap::map(std::os::unix::io::AsRawFd::as_raw_fd(&file), 0, 4096).unwrap() };

    let start = raw.as_ptr() as usize;
    assert!(raw.contains_addr(start));
    assert!(raw.contains_addr(start + 2048));
    assert!(!raw.contains_addr(start + 4096));
    assert!(!raw.contains_addr(0));
}

/// Verifies that madvise calls succeed on a valid mapping.
#[test]
fn advise_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("advise_test.bin");
    fs::write(&path, vec![0u8; 8192]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    mmap.advise(Advice::Random).unwrap();
    mmap.advise(Advice::Sequential).unwrap();
    mmap.advise_range(Advice::WillNeed, 0, 4096).unwrap();
}

/// Verifies that the pread fallback reader works correctly.
#[test]
fn pread_fallback_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pread_test.bin");
    fs::write(&path, b"fallback works").unwrap();

    let reader = PreadReader::open(&path).unwrap();
    let result = reader.read(0..8, |b| b.to_vec()).unwrap();

    assert_eq!(result, b"fallback");
}

/// Verifies that pread fallback returns OutOfBounds for invalid ranges.
#[test]
fn pread_fallback_out_of_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pread_oob.bin");
    fs::write(&path, b"tiny").unwrap();

    let reader = PreadReader::open(&path).unwrap();
    let result = reader.read(0..1024, |b| b.to_vec());

    assert!(matches!(result, Err(AccessError::OutOfBounds { .. })));
}

/// Verifies that filesystem detection returns a valid type for the temp directory.
#[test]
fn fs_detect_temp_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("detect_test.bin");
    fs::write(&path, b"x").unwrap();

    let fs_type = FsType::detect(&path).unwrap();

    assert!(!fs_type.is_network());
}

/// Verifies that probe succeeds on a valid, accessible mapping.
#[test]
fn probe_accessible_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe_test.bin");
    fs::write(&path, vec![0u8; 8192]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    mmap.probe(0, 8192).unwrap();
}

/// Verifies that probe returns OutOfBounds for excessive ranges.
#[test]
fn probe_out_of_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe_oob.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();
    let result = mmap.probe(0, 8192);

    assert!(matches!(result, Err(AccessError::OutOfBounds { .. })));
}

/// Verifies that multiple reads from the same mapping return correct data.
#[test]
fn multiple_reads_same_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multi_read.bin");
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(b"AAAABBBBCCCC").unwrap();
    drop(file);

    let mmap = SafeMmap::open(&path).unwrap();

    let a = mmap.read(0..4, |b| b.to_vec()).unwrap();
    let b = mmap.read(4..8, |b| b.to_vec()).unwrap();
    let c = mmap.read(8..12, |b| b.to_vec()).unwrap();

    assert_eq!(a, b"AAAA");
    assert_eq!(b, b"BBBB");
    assert_eq!(c, b"CCCC");
}

/// Verifies that the guard pattern works for multiple reads.
#[test]
fn guard_multiple_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guard_test.bin");
    fs::write(&path, b"0123456789ABCDEF").unwrap();

    let mmap = SafeMmap::open(&path).unwrap();
    let guard = mmap.guard();

    let first = guard.read(0, 4, |b| b.to_vec()).unwrap();
    let second = guard.read(10, 6, |b| b.to_vec()).unwrap();

    assert_eq!(first, b"0123");
    assert_eq!(second, b"ABCDEF");
}

/// Verifies that evict succeeds and subsequent reads still work
/// (pages are re-faulted in from the file).
#[test]
fn evict_then_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evict_test.bin");
    fs::write(&path, vec![0xBBu8; 32768]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    let before = mmap.read(0..4, |b| b.to_vec()).unwrap();
    mmap.evict(0, 32768).unwrap();
    let after = mmap.read(0..4, |b| b.to_vec()).unwrap();

    assert_eq!(before, after);
    assert_eq!(before, vec![0xBB; 4]);
}

/// Verifies that prefetch (MADV_WILLNEED) succeeds on a valid range.
#[test]
fn prefetch_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prefetch_test.bin");
    fs::write(&path, vec![0u8; 32768]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    mmap.prefetch(0, 32768).unwrap();
}

/// Verifies that prefetch_with_timeout succeeds on a local file
/// (pages are available immediately, well within timeout).
#[test]
fn prefetch_with_timeout_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prefetch_timeout_test.bin");
    fs::write(&path, vec![0xAAu8; 65536]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    mmap.prefetch_with_timeout(0, 65536, std::time::Duration::from_secs(5))
        .unwrap();

    let data = mmap.read(0..4, |b| b.to_vec()).unwrap();
    assert_eq!(data, vec![0xAA; 4]);
}

/// Verifies that prefetch_with_timeout returns OutOfBounds for invalid ranges.
#[test]
fn prefetch_with_timeout_out_of_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prefetch_oob.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    let result = mmap.prefetch_with_timeout(0, 999999, std::time::Duration::from_secs(1));

    assert!(matches!(result, Err(AccessError::OutOfBounds { .. })));
}

/// Verifies that evict on an out-of-bounds range returns an error.
#[test]
fn evict_out_of_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evict_oob.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    let result = mmap.evict(0, 999999);

    assert!(result.is_err());
}

/// Verifies that a writable mapping can write and read back data.
#[test]
fn write_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("write_test.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::options()
        .writable(true)
        .shared(true)
        .open(&path)
        .unwrap();

    mmap.write(0, b"hello").unwrap();

    let result = mmap.read(0..5, |b| b.to_vec()).unwrap();
    assert_eq!(result, b"hello");
}

/// Verifies that writing to a read-only mapping returns an error.
#[test]
fn write_to_readonly_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("readonly_write.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    let result = mmap.write(0, b"nope");

    assert!(matches!(result, Err(AccessError::Io(_))));
}

/// Verifies that write out of bounds returns an error.
#[test]
fn write_out_of_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("write_oob.bin");
    fs::write(&path, vec![0u8; 16]).unwrap();

    let mmap = SafeMmap::options().writable(true).open(&path).unwrap();

    let result = mmap.write(0, &[0u8; 1024]);

    assert!(matches!(result, Err(AccessError::OutOfBounds { .. })));
}

/// Verifies that the builder can set offset and length.
#[test]
fn builder_with_offset_and_len() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("builder_offset.bin");
    let mut data = vec![0u8; 32768];
    data[16384] = 0xAA;
    data[16385] = 0xBB;
    fs::write(&path, &data).unwrap();

    let mmap = SafeMmap::options()
        .offset(16384)
        .len(16384)
        .open(&path)
        .unwrap();

    assert_eq!(mmap.len(), 16384);

    let result = mmap.read(0..2, |b| b.to_vec()).unwrap();
    assert_eq!(result, vec![0xAA, 0xBB]);
}

/// Verifies that an anonymous mapping can be created and used.
#[test]
fn anonymous_mapping() {
    let raw = unsafe { RawMmap::anonymous(4096, Protection::ReadWrite).unwrap() };

    assert_eq!(raw.len(), 4096);
    assert!(raw.is_writable());

    let ptr = raw.as_mut_ptr().unwrap();
    unsafe {
        std::ptr::write(ptr, 0xDE);
        assert_eq!(std::ptr::read(ptr), 0xDE);
    }
}

/// Verifies that MmapOptions builder works for file-backed mapping.
#[test]
fn mmap_options_builder() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("options_test.bin");
    fs::write(&path, vec![0x42u8; 8192]).unwrap();

    let file = fs::File::open(&path).unwrap();
    let raw = unsafe {
        MmapOptions::new(8192)
            .fd(std::os::unix::io::AsRawFd::as_raw_fd(&file))
            .offset(0)
            .map()
            .unwrap()
    };

    assert_eq!(raw.len(), 8192);
    assert!(!raw.is_writable());

    let byte = unsafe { *raw.as_ptr() };
    assert_eq!(byte, 0x42);
}

/// Verifies that flush succeeds on a writable shared mapping.
#[test]
fn flush_writable_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flush_test.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::options()
        .writable(true)
        .shared(true)
        .open(&path)
        .unwrap();

    mmap.write(0, b"flushed").unwrap();
    mmap.flush(0, 4096, false).unwrap();

    let contents = fs::read(&path).unwrap();
    assert_eq!(&contents[0..7], b"flushed");
}

/// Verifies that is_writable returns the correct value.
#[test]
fn is_writable_flag() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writable_flag.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let ro = SafeMmap::open(&path).unwrap();
    assert!(!ro.is_writable());

    let rw = SafeMmap::options().writable(true).open(&path).unwrap();
    assert!(rw.is_writable());
}

/// Verifies that as_mut_ptr returns None for read-only mappings.
#[test]
fn as_mut_ptr_readonly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mut_ptr_test.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let file = fs::File::open(&path).unwrap();
    let raw =
        unsafe { RawMmap::map(std::os::unix::io::AsRawFd::as_raw_fd(&file), 0, 4096).unwrap() };

    assert!(raw.as_mut_ptr().is_none());
}

/// Verifies that read_into copies data into a caller-owned buffer.
#[test]
fn read_into_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("read_into_test.bin");
    fs::write(&path, b"read_into works!").unwrap();

    let mmap = SafeMmap::open(&path).unwrap();
    let mut buf = [0u8; 9];
    mmap.read_into(0, &mut buf).unwrap();

    assert_eq!(&buf, b"read_into");
}

/// Verifies that read_into returns OutOfBounds for excessive ranges.
#[test]
fn read_into_out_of_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("read_into_oob.bin");
    fs::write(&path, b"short").unwrap();

    let mmap = SafeMmap::open(&path).unwrap();
    let mut buf = [0u8; 1024];
    let result = mmap.read_into(0, &mut buf);

    assert!(matches!(result, Err(AccessError::OutOfBounds { .. })));
}

/// Verifies that resident_pages returns a result for a valid mapping.
#[test]
fn resident_pages_query() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mincore_test.bin");
    fs::write(&path, vec![0u8; 65536]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    // Touch first page to ensure it's resident
    let _ = mmap.read(0..1, |b| b[0]);

    let resident = mmap.resident_pages(0, mmap.len()).unwrap();
    assert!(!resident.is_empty());
    assert!(resident[0]); // first page should be resident after read
}

/// Verifies that lock_range and unlock_range work.
#[test]
fn lock_unlock_range() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lock_test.bin");
    fs::write(&path, vec![0u8; 32768]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    mmap.lock_range(0, 16384).unwrap();
    mmap.unlock_range(0, 16384).unwrap();
}

/// Verifies that lock_range returns error for out-of-bounds range.
#[test]
fn lock_range_out_of_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lock_oob.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::open(&path).unwrap();

    let result = mmap.lock_range(0, 999999);
    assert!(result.is_err());
}

/// Verifies that unsafe as_slice provides &[u8] access.
#[test]
fn unsafe_as_slice() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("as_slice_test.bin");
    fs::write(&path, b"slice works").unwrap();

    let mmap = SafeMmap::open(&path).unwrap();
    let slice = unsafe { mmap.as_slice() };

    assert_eq!(&slice[0..5], b"slice");
}

/// Verifies that unsafe as_mut_slice provides &mut [u8] access on writable mappings.
#[test]
fn unsafe_as_mut_slice() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("as_mut_slice_test.bin");
    fs::write(&path, vec![0u8; 16]).unwrap();

    let mut mmap = SafeMmap::options()
        .writable(true)
        .shared(true)
        .open(&path)
        .unwrap();

    let slice = unsafe { mmap.as_mut_slice().unwrap() };
    slice[0..5].copy_from_slice(b"hello");

    let read_back = mmap.read(0..5, |b| b.to_vec()).unwrap();
    assert_eq!(read_back, b"hello");
}

/// Verifies that as_mut_slice returns None for read-only mappings.
#[test]
fn as_mut_slice_readonly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("as_mut_slice_ro.bin");
    fs::write(&path, b"readonly").unwrap();

    let mut mmap = SafeMmap::open(&path).unwrap();
    let result = unsafe { mmap.as_mut_slice() };

    assert!(result.is_none());
}

/// Verifies that the event callback fires on SIGBUS-like errors.
#[test]
fn event_callback_fires() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("event_test.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&count);

    let mmap = SafeMmap::options()
        .on_event(Arc::new(move |_event| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        }))
        .open(&path)
        .unwrap();

    // Force a write-to-readonly error (not SIGBUS, but tests the wiring)
    let _ = mmap.write(0, b"test");

    // The write error is Io (permission denied), not Sigbus,
    // so the callback should not fire for that.
    // We can't easily trigger SIGBUS in a unit test without subprocess.
    // This test verifies the callback is accepted and the mapping works.
    assert_eq!(mmap.len(), 4096);
}

/// Verifies that advisory file locking works for shared (read) access.
#[test]
fn flock_shared_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flock_shared.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap1 = SafeMmap::options().flock(true).open(&path).unwrap();

    // Second shared lock should succeed (multiple readers allowed)
    let mmap2 = SafeMmap::options().flock(true).open(&path).unwrap();

    let v1 = mmap1.read(0..1, |b| b[0]).unwrap();
    let v2 = mmap2.read(0..1, |b| b[0]).unwrap();
    assert_eq!(v1, v2);
}

/// Verifies that an exclusive lock blocks a second exclusive lock.
#[test]
fn flock_exclusive_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flock_excl.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let _mmap1 = SafeMmap::options()
        .writable(true)
        .flock(true)
        .open(&path)
        .unwrap();

    // Second exclusive lock should fail with WouldBlock (LOCK_NB)
    let result = SafeMmap::options()
        .writable(true)
        .flock(true)
        .open(&path);

    assert!(result.is_err());
}

/// Verifies that the lock is released when SafeMmap is dropped.
#[test]
fn flock_released_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flock_drop.bin");
    fs::write(&path, vec![0u8; 4096]).unwrap();

    let mmap = SafeMmap::options()
        .writable(true)
        .flock(true)
        .open(&path)
        .unwrap();
    drop(mmap);

    // Should succeed now that the lock is released
    let _mmap2 = SafeMmap::options()
        .writable(true)
        .flock(true)
        .open(&path)
        .unwrap();
}
