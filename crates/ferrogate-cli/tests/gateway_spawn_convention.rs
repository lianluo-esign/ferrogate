// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Convention guard for issue #568 -- test-spawned ferrogate
// processes must be constructed through tests/support so the lifetime policy,
// inherited test guardian environment, and backlog sweep cannot be bypassed.

use std::path::{Path, PathBuf};

const DIRECT_FERROGATE_CONSTRUCTOR: &str = "Command::new(env!(\"CARGO_BIN_EXE_ferrogate\"))";

#[test]
fn ferrogate_test_processes_are_constructed_through_support() {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut offenders = Vec::new();
    for path in rust_test_files(&tests_dir) {
        if is_allowed_source(&tests_dir, &path) {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        for (line_index, line) in source.lines().enumerate() {
            if line.contains(DIRECT_FERROGATE_CONSTRUCTOR) {
                offenders.push(format!(
                    "{}:{}",
                    path.strip_prefix(&tests_dir).unwrap().display(),
                    line_index + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "test-spawned ferrogate processes must use support::ferrogate_command() \
         or support::start_gateway(); direct constructors bypass #568 reaping \
         and sweep policy: {offenders:?}"
    );
}

#[test]
fn backlog_sweep_signals_through_pidfd_not_a_reclassified_raw_pid() {
    let support_source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/mod.rs"))
            .unwrap();
    let sweep = function_source(&support_source, "pub fn sweep_orphaned_gateways");

    assert!(
        sweep.contains("SYS_pidfd_open"),
        "the #568 machine-wide sweep must hold a stable pidfd before signalling; \
         classifying a numeric pid and later calling kill(pid) has a PID reuse race"
    );
    assert!(
        sweep.contains("SYS_pidfd_send_signal"),
        "the #568 machine-wide sweep must send SIGKILL through the held pidfd"
    );
    assert!(
        !sweep.contains("libc::kill(pid as libc::pid_t, libc::SIGKILL)"),
        "sweep_orphaned_gateways must not signal the classified raw pid directly"
    );
}

fn rust_test_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files);
    files.sort();
    files
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn is_allowed_source(tests_dir: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(tests_dir).unwrap();
    relative == Path::new("support/mod.rs") || relative == Path::new("gateway_spawn_convention.rs")
}

fn function_source<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source.find(signature).expect("function signature exists");
    let rest = &source[start..];
    let next_cfg = rest.find("\n#[cfg(").unwrap_or(rest.len());
    &rest[..next_cfg]
}
