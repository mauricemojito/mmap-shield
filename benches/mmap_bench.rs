//! Performance benchmarks for mmap-shield.
//!
//! Compares the overhead of SafeMmap (SIGBUS-protected) access against:
//! - Raw mmap pointer dereference (bare metal baseline)
//! - Raw mmap via RawMmap wrapper (syscall wrapper overhead)
//! - pread fallback (explicit syscall per read)
//!
//! Run with: cargo bench

use std::fs;
use std::hint::black_box;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use mmap_shield::SafeMmap;
use mmap_shield::fallback::PreadReader;
use mmap_shield::sys::mmap::RawMmap;

const FILE_SIZE: usize = 64 * 1024 * 1024; // 64 MB

fn create_test_file(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("bench_data.bin");
    if !path.exists() {
        let data: Vec<u8> = (0..FILE_SIZE).map(|i| (i % 256) as u8).collect();
        fs::write(&path, &data).unwrap();
    }
    path
}

// ─── Single read benchmarks ──────────────────────────────────────

fn bench_single_read(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = create_test_file(dir.path());

    let mut group = c.benchmark_group("single_read_4kb");
    group.throughput(Throughput::Bytes(4096));

    // Bare metal: raw mmap pointer dereference, no protection
    let file = fs::File::open(&path).unwrap();
    let raw = unsafe { RawMmap::map(file.as_raw_fd(), 0, FILE_SIZE).unwrap() };

    group.bench_function("bare_metal_ptr", |b| {
        b.iter(|| {
            let ptr = raw.as_ptr();
            let slice = unsafe { std::slice::from_raw_parts(ptr.add(8192), 4096) };
            let mut sum = 0u64;
            for &byte in slice {
                sum += byte as u64;
            }
            black_box(sum);
        });
    });

    // RawMmap: same but through the wrapper (should be identical)
    group.bench_function("raw_mmap_ptr", |b| {
        b.iter(|| {
            let ptr = raw.as_ptr();
            let slice = unsafe { std::slice::from_raw_parts(ptr.add(8192), 4096) };
            let mut sum = 0u64;
            for &byte in slice {
                sum += byte as u64;
            }
            black_box(sum);
        });
    });

    drop(raw);
    drop(file);

    // SafeMmap::read (closure-based, SIGBUS protected)
    let safe = SafeMmap::open(&path).unwrap();

    group.bench_function("safe_mmap_read", |b| {
        b.iter(|| {
            let sum = safe
                .read(8192..8192 + 4096, |slice| {
                    let mut s = 0u64;
                    for &byte in slice {
                        s += byte as u64;
                    }
                    s
                })
                .unwrap();
            black_box(sum);
        });
    });

    // SafeMmap::read_into (buffer copy, SIGBUS protected)
    let mut buf = vec![0u8; 4096];

    group.bench_function("safe_mmap_read_into", |b| {
        b.iter(|| {
            safe.read_into(8192, &mut buf).unwrap();
            let mut sum = 0u64;
            for &byte in &buf {
                sum += byte as u64;
            }
            black_box(sum);
        });
    });

    // SafeMmap guard (amortized setup, multiple reads)
    group.bench_function("safe_mmap_shield", |b| {
        b.iter(|| {
            let guard = safe.guard();
            let sum = guard
                .read(8192, 4096, |slice| {
                    let mut s = 0u64;
                    for &byte in slice {
                        s += byte as u64;
                    }
                    s
                })
                .unwrap();
            black_box(sum);
        });
    });

    // unsafe as_slice (unprotected, for comparison)
    group.bench_function("safe_mmap_as_slice_unsafe", |b| {
        b.iter(|| {
            let slice = unsafe { safe.as_slice() };
            let mut sum = 0u64;
            for &byte in &slice[8192..8192 + 4096] {
                sum += byte as u64;
            }
            black_box(sum);
        });
    });

    drop(safe);

    // pread fallback
    let reader = PreadReader::open(&path).unwrap();

    group.bench_function("pread_fallback", |b| {
        b.iter(|| {
            let sum = reader
                .read(8192..8192 + 4096, |slice| {
                    let mut s = 0u64;
                    for &byte in slice {
                        s += byte as u64;
                    }
                    s
                })
                .unwrap();
            black_box(sum);
        });
    });

    group.finish();
}

// ─── Read size scaling ───────────────────────────────────────────

fn bench_read_sizes(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = create_test_file(dir.path());

    let safe = SafeMmap::open(&path).unwrap();
    let file = fs::File::open(&path).unwrap();
    let raw = unsafe { RawMmap::map(file.as_raw_fd(), 0, FILE_SIZE).unwrap() };
    let reader = PreadReader::open(&path).unwrap();

    let sizes: Vec<usize> = vec![64, 512, 4096, 65536, 1024 * 1024];

    let mut group = c.benchmark_group("read_size_scaling");

    for &size in &sizes {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("bare_metal", size), &size, |b, &sz| {
            b.iter(|| {
                let slice = unsafe { std::slice::from_raw_parts(raw.as_ptr(), sz) };
                let mut sum = 0u64;
                for &byte in slice {
                    sum += byte as u64;
                }
                black_box(sum);
            });
        });

        group.bench_with_input(BenchmarkId::new("safe_mmap_read", size), &size, |b, &sz| {
            b.iter(|| {
                let sum = safe
                    .read(0..sz, |slice| {
                        let mut s = 0u64;
                        for &byte in slice {
                            s += byte as u64;
                        }
                        s
                    })
                    .unwrap();
                black_box(sum);
            });
        });

        group.bench_with_input(BenchmarkId::new("pread", size), &size, |b, &sz| {
            b.iter(|| {
                let sum = reader
                    .read(0..sz, |slice| {
                        let mut s = 0u64;
                        for &byte in slice {
                            s += byte as u64;
                        }
                        s
                    })
                    .unwrap();
                black_box(sum);
            });
        });
    }

    group.finish();
}

// ─── Random access pattern (chunk simulation) ─────────────────────

fn bench_random_chunk_access(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = create_test_file(dir.path());

    let safe = SafeMmap::open(&path).unwrap();
    safe.advise(mmap_shield::Advice::Random).unwrap();

    let file = fs::File::open(&path).unwrap();
    let raw = unsafe { RawMmap::map(file.as_raw_fd(), 0, FILE_SIZE).unwrap() };

    let reader = PreadReader::open(&path).unwrap();

    let chunk_size = 256 * 1024; // 256 KB chunks
    let num_chunks = FILE_SIZE / chunk_size;

    // Pre-generate random chunk indices (deterministic)
    let chunk_indices: Vec<usize> = (0..100).map(|i| (i * 7 + 3) % num_chunks).collect();

    let mut group = c.benchmark_group("random_chunk_256kb");
    group.throughput(Throughput::Bytes(chunk_size as u64));

    group.bench_function("bare_metal", |b| {
        let mut idx = 0;
        b.iter(|| {
            let chunk_idx = chunk_indices[idx % chunk_indices.len()];
            let offset = chunk_idx * chunk_size;
            let slice = unsafe { std::slice::from_raw_parts(raw.as_ptr().add(offset), chunk_size) };
            let mut sum = 0u64;
            for &byte in slice {
                sum += byte as u64;
            }
            idx += 1;
            black_box(sum);
        });
    });

    group.bench_function("safe_mmap_read", |b| {
        let mut idx = 0;
        b.iter(|| {
            let chunk_idx = chunk_indices[idx % chunk_indices.len()];
            let offset = chunk_idx * chunk_size;
            let sum = safe
                .read(offset..offset + chunk_size, |slice| {
                    let mut s = 0u64;
                    for &byte in slice {
                        s += byte as u64;
                    }
                    s
                })
                .unwrap();
            idx += 1;
            black_box(sum);
        });
    });

    group.bench_function("pread", |b| {
        let mut idx = 0;
        b.iter(|| {
            let chunk_idx = chunk_indices[idx % chunk_indices.len()];
            let offset = chunk_idx * chunk_size;
            let sum = reader
                .read(offset..offset + chunk_size, |slice| {
                    let mut s = 0u64;
                    for &byte in slice {
                        s += byte as u64;
                    }
                    s
                })
                .unwrap();
            idx += 1;
            black_box(sum);
        });
    });

    group.finish();
}

// ─── Protection overhead (sigsetjmp cost) ────────────────────────

fn bench_protection_overhead(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = create_test_file(dir.path());

    let safe = SafeMmap::open(&path).unwrap();

    let mut group = c.benchmark_group("protection_overhead");

    // Measure the cost of sigsetjmp + trampoline by reading 1 byte
    // (minimal data processing, maximum protection overhead ratio)
    group.bench_function("read_1_byte", |b| {
        b.iter(|| {
            let val = safe.read(0..1, |b| b[0]).unwrap();
            black_box(val);
        });
    });

    // Same via guard
    group.bench_function("guard_read_1_byte", |b| {
        b.iter(|| {
            let guard = safe.guard();
            let val = guard.read(0, 1, |b| b[0]).unwrap();
            black_box(val);
        });
    });

    // Multiple reads through a single guard (amortized)
    group.bench_function("guard_10_reads_1_byte", |b| {
        b.iter(|| {
            let guard = safe.guard();
            let mut sum = 0u8;
            for i in 0..10 {
                sum = sum.wrapping_add(guard.read(i * 100, 1, |b| b[0]).unwrap());
            }
            black_box(sum);
        });
    });

    // Bare metal 1-byte read for comparison
    let file = fs::File::open(&path).unwrap();
    let raw = unsafe { RawMmap::map(file.as_raw_fd(), 0, FILE_SIZE).unwrap() };

    group.bench_function("bare_metal_1_byte", |b| {
        b.iter(|| {
            let val = unsafe { *raw.as_ptr() };
            black_box(val);
        });
    });

    group.finish();
}

// ─── Evict + re-read cost ────────────────────────────────────────

fn bench_evict_reread(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = create_test_file(dir.path());

    let safe = SafeMmap::open(&path).unwrap();

    let mut group = c.benchmark_group("evict_reread");
    group.throughput(Throughput::Bytes(4096));
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("read_only", |b| {
        b.iter(|| {
            let sum = safe
                .read(0..4096, |s| {
                    let mut v = 0u64;
                    for &b in s {
                        v += b as u64;
                    }
                    v
                })
                .unwrap();
            black_box(sum);
        });
    });

    group.bench_function("evict_then_read", |b| {
        b.iter(|| {
            safe.evict(0, 4096).unwrap();
            let sum = safe
                .read(0..4096, |s| {
                    let mut v = 0u64;
                    for &b in s {
                        v += b as u64;
                    }
                    v
                })
                .unwrap();
            black_box(sum);
        });
    });

    group.finish();
}

// ─── Prefetch cost ───────────────────────────────────────────────

fn bench_prefetch(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = create_test_file(dir.path());

    let safe = SafeMmap::open(&path).unwrap();

    let mut group = c.benchmark_group("prefetch");

    group.bench_function("madvise_willneed_4kb", |b| {
        b.iter(|| {
            safe.prefetch(0, 4096).unwrap();
        });
    });

    group.bench_function("madvise_willneed_1mb", |b| {
        b.iter(|| {
            safe.prefetch(0, 1024 * 1024).unwrap();
        });
    });

    group.bench_function("prefetch_with_timeout_4kb", |b| {
        b.iter(|| {
            safe.prefetch_with_timeout(0, 4096, Duration::from_secs(5))
                .unwrap();
        });
    });

    group.bench_function("probe_4kb", |b| {
        b.iter(|| {
            safe.probe(0, 4096).unwrap();
        });
    });

    group.bench_function("resident_pages_4kb", |b| {
        b.iter(|| {
            let r = safe.resident_pages(0, 4096).unwrap();
            black_box(r);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_read,
    bench_read_sizes,
    bench_random_chunk_access,
    bench_protection_overhead,
    bench_evict_reread,
    bench_prefetch,
);
criterion_main!(benches);
