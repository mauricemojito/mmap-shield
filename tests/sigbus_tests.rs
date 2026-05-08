//! Subprocess-based integration tests for SIGBUS protection.
//!
//! Each test scenario runs in a child process via the `sigbus_victim`
//! binary. If protection fails and the child is killed by SIGBUS,
//! the test reports the signal without crashing the test runner.

use std::process::Command;

fn victim_binary() -> String {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sigbus_victim"));
    path.to_string_lossy().to_string()
}

fn run_scenario(scenario: &str) -> (bool, String, String) {
    let dir = tempfile::tempdir().expect("create temp dir");

    let output = Command::new(victim_binary())
        .arg(format!("--scenario={scenario}"))
        .arg(format!("--dir={}", dir.path().display()))
        .output()
        .expect("spawn victim");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (output.status.success(), stdout, stderr)
}

/// Verifies that a SIGBUS from accessing beyond file size
/// is caught and converted to an error instead of crashing.
#[test]
fn sigbus_basic_recovers() {
    let (success, stdout, stderr) = run_scenario("sigbus_basic");
    assert!(
        success,
        "child died — SIGBUS not caught.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("recovered"),
        "expected 'recovered' in stdout, got: {stdout}"
    );
}

/// Verifies that multiple threads can independently recover from
/// SIGBUS faults on the same mapping.
#[test]
fn multi_thread_recovers() {
    let (success, stdout, stderr) = run_scenario("multi_thread");
    assert!(
        success,
        "child died — multi-thread SIGBUS not caught.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("recovered"),
        "expected 'recovered' in stdout, got: {stdout}"
    );
}

/// Verifies that repeated SIGBUS faults are correctly counted,
/// validating the foundation for poison detection.
#[test]
fn poison_after_threshold() {
    let (success, stdout, stderr) = run_scenario("poison");
    assert!(
        success,
        "child died — poison scenario failed.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("poisoned"),
        "expected 'poisoned' in stdout, got: {stdout}"
    );
}

/// Verifies that prefetch_with_timeout completes successfully
/// in a subprocess (validates the worker thread + condvar path).
#[test]
fn prefetch_with_timeout_in_subprocess() {
    let (success, stdout, stderr) = run_scenario("prefetch_sigbus");
    assert!(
        success,
        "child died — prefetch scenario failed.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("prefetch_ok"),
        "expected 'prefetch_ok' in stdout, got: {stdout}"
    );
}
