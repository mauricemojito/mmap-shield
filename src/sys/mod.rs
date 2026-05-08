//! Platform syscall wrappers and system utilities.
//!
//! Low-level building blocks used by the higher-level `mmap` and
//! `fallback` modules. Each submodule wraps a single syscall family
//! or system concept.
//!
//! # Submodules
//!
//! - [`advice`] — `madvise(2)` hint values.
//! - [`fs_detect`] — Network filesystem detection via `statfs(2)`.
//! - [`mmap`] — `mmap(2)` / `munmap(2)` / `madvise(2)` owning wrapper.
//! - [`page`] — System page size query.
//! - [`pread`] — Positional read via `pread(2)`.

pub mod advice;
pub mod fs_detect;
pub mod mmap;
pub mod page;
pub mod pread;
