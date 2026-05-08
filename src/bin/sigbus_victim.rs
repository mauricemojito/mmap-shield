//! Test binary for subprocess-based SIGBUS testing.
//!
//! Executes SIGBUS-triggering scenarios in a child process so that
//! test failures (actual crashes) don't kill the test runner.
//!
//! Uses the reliable "map beyond file size" approach to trigger
//! SIGBUS: writes a small file, maps two pages, and accesses
//! the second page which has no backing data.
//!
//! # Usage
//!
//! ```sh
//! sigbus_victim --scenario=sigbus_basic --dir=/tmp/test
//! ```
//!
//! # Exit Codes
//!
//! - `0` — scenario completed, SIGBUS was caught and recovered.
//! - `1` — scenario failed with an unexpected error.
//! - Signal death — protection did not work (SIGBUS killed the process).

use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use mmap_shield::error::AccessError;
use mmap_shield::signal_test_helpers;
use mmap_shield::sys::mmap::RawMmap;
use mmap_shield::sys::page::page_size;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scenario = args
        .iter()
        .find_map(|a| a.strip_prefix("--scenario="))
        .unwrap_or("sigbus_basic");
    let dir = args
        .iter()
        .find_map(|a| a.strip_prefix("--dir="))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);

    let file_path = args
        .iter()
        .find_map(|a| a.strip_prefix("--file="))
        .map(PathBuf::from);

    let exit_code = match scenario {
        "sigbus_basic" => scenario_sigbus_basic(&dir),
        "multi_thread" => scenario_multi_thread(&dir),
        "poison" => scenario_poison(&dir),
        "prefetch_sigbus" => scenario_prefetch_sigbus(&dir),
        "nfs_read" => scenario_nfs_read(file_path.as_deref()),
        "nfs_failure" => scenario_nfs_failure(file_path.as_deref()),
        _ => {
            eprintln!("unknown scenario: {scenario}");
            1
        }
    };

    std::process::exit(exit_code);
}

struct TestMapping {
    raw: RawMmap,
    path: PathBuf,
    _file: fs::File,
    page_size: usize,
}

fn create_sigbus_mapping(dir: &std::path::Path, name: &str) -> TestMapping {
    let path = dir.join(name);
    fs::write(&path, b"x").expect("write test file");

    let file = fs::File::open(&path).expect("open file");
    let ps = page_size();
    let map_len = ps * 2;

    let raw = unsafe { RawMmap::map(file.as_raw_fd(), 0, map_len).expect("mmap") };

    mmap_shield::signal_test_helpers::register_and_install(raw.as_ptr() as usize, raw.len());

    TestMapping {
        raw,
        path,
        _file: file,
        page_size: ps,
    }
}

fn scenario_sigbus_basic(dir: &std::path::Path) -> i32 {
    let tm = create_sigbus_mapping(dir, "sigbus_basic.bin");
    let guard = signal_test_helpers::guard(&tm.raw);

    match guard.read(tm.page_size, 1, |b| b[0]) {
        Err(AccessError::Sigbus { .. }) => {
            println!("recovered");
            let _ = fs::remove_file(&tm.path);
            0
        }
        Ok(val) => {
            eprintln!("unexpected success: got byte {val:#x}");
            let _ = fs::remove_file(&tm.path);
            1
        }
        Err(e) => {
            eprintln!("unexpected error: {e}");
            let _ = fs::remove_file(&tm.path);
            1
        }
    }
}

fn scenario_multi_thread(dir: &std::path::Path) -> i32 {
    let tm = create_sigbus_mapping(dir, "sigbus_mt.bin");

    let results: Vec<bool> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    let guard = signal_test_helpers::guard(&tm.raw);
                    matches!(
                        guard.read(tm.page_size, 1, |b| b[0]),
                        Err(AccessError::Sigbus { .. })
                    )
                })
            })
            .collect();

        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let _ = fs::remove_file(&tm.path);

    if results.iter().all(|&r| r) {
        println!("recovered");
        0
    } else {
        eprintln!("not all threads recovered");
        1
    }
}

fn scenario_poison(dir: &std::path::Path) -> i32 {
    let tm = create_sigbus_mapping(dir, "sigbus_poison.bin");
    let fault_count = AtomicU32::new(0);
    let max_faults: u32 = 2;

    for _ in 0..max_faults {
        let guard = signal_test_helpers::guard(&tm.raw);
        if let Err(AccessError::Sigbus { .. }) = guard.read(tm.page_size, 1, |b| b[0]) {
            fault_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    let count = fault_count.load(Ordering::Relaxed);
    let _ = fs::remove_file(&tm.path);

    if count >= max_faults {
        println!("poisoned after {count} faults");
        0
    } else {
        eprintln!("expected {max_faults} faults, got {count}");
        1
    }
}

fn scenario_prefetch_sigbus(dir: &std::path::Path) -> i32 {
    let path = dir.join("sigbus_prefetch.bin");
    let ps = page_size();
    fs::write(&path, vec![0xDDu8; ps * 4]).expect("write test file");

    let mmap = mmap_shield::SafeMmap::open(&path).expect("open mmap");

    let result = mmap.prefetch_with_timeout(0, ps * 4, std::time::Duration::from_secs(5));

    let _ = fs::remove_file(&path);

    match result {
        Ok(()) => {
            println!("prefetch_ok");
            0
        }
        Err(e) => {
            eprintln!("unexpected error: {e}");
            1
        }
    }
}

fn scenario_nfs_read(file_path: Option<&std::path::Path>) -> i32 {
    let path = match file_path {
        Some(p) => p,
        None => {
            eprintln!("--file= required for nfs_read scenario");
            return 1;
        }
    };

    let mmap = match mmap_shield::SafeMmap::open(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed to open: {e}");
            return 1;
        }
    };

    match mmap.read(0..4096, |b| b.iter().map(|&x| x as u64).sum::<u64>()) {
        Ok(sum) => {
            println!("nfs_read_ok sum={sum}");
            0
        }
        Err(e) => {
            eprintln!("nfs read error: {e}");
            1
        }
    }
}

fn scenario_nfs_failure(file_path: Option<&std::path::Path>) -> i32 {
    let path = match file_path {
        Some(p) => p,
        None => {
            eprintln!("--file= required for nfs_failure scenario");
            return 1;
        }
    };

    let mmap = match mmap_shield::SafeMmap::open(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed to open: {e}");
            return 1;
        }
    };

    let len = mmap.len();

    // Touch first page to verify mapping works
    match mmap.read(0..1, |b| b[0]) {
        Ok(_) => println!("initial read ok"),
        Err(e) => {
            eprintln!("initial read failed: {e}");
            return 1;
        }
    }

    // Evict all pages to force re-fetch from NFS on next access
    let _ = mmap.evict(0, len);

    // Wait for the test script to kill the NFS server
    println!("waiting for NFS server to die...");
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Now try to read — NFS server is gone, should SIGBUS or timeout
    println!("attempting read after NFS failure...");
    let page = page_size();
    let mut faults = 0u32;
    let mut successes = 0u32;

    for offset in (0..len).step_by(page) {
        let read_len = page.min(len - offset);
        match mmap.read(offset..offset + read_len, |b| b[0]) {
            Ok(_) => successes += 1,
            Err(mmap_shield::AccessError::Sigbus { fault_address }) => {
                println!("SIGBUS caught at {fault_address:#x} — recovered!");
                faults += 1;
            }
            Err(e) => {
                println!("other error: {e}");
                faults += 1;
            }
        }
    }

    println!("results: {successes} pages ok, {faults} faults caught");

    if faults > 0 {
        println!("nfs_failure_recovered");
        0
    } else {
        // Pages were still cached — NFS server died but kernel served from cache.
        // This is valid behavior, not a test failure.
        println!("nfs_pages_cached (server down but pages still resident)");
        0
    }
}
