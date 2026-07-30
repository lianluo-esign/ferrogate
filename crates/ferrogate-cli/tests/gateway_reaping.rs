// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Regression gate for issue #568 -- a gateway spawned by a test
// must die with that test, including on the paths that run no destructors.
// A load average of 308 was traced to 106 `ferrogate run` processes reparented
// to init, the oldest 14 hours old, because `std::process::Child`'s `Drop`
// detaches instead of killing and every cleanup in this suite is a plain
// `gateway.kill()` statement that a panic jumps straight over.
//
// The two cases below are the ones no `Drop` guard could have reached:
//
//   * a test that panics after spawning -- the `kill()` line never runs;
//   * a test binary killed with SIGKILL -- no destructor runs at all.
//
// Both are driven by re-invoking THIS test binary with `--ignored --exact` on
// one of the `inner_*` fixtures, so the fixture really is a libtest test in a
// libtest thread, not a hand-rolled imitation of one. The fixture prints the
// gateway pid; the outer test then asserts against `/proc`.
//
// The backlog sweep lives in `gateway_backlog_sweep.rs` and not here on
// purpose: a sweep kills every orphan on the box, so running one in this binary
// would clean up after these tests and hold them green with the fix removed.
//
// Linux only: `/proc` is the observation surface and PR_SET_PDEATHSIG is the
// mechanism under test.
#![cfg(target_os = "linux")]

// Only the spawn helpers and the /proc readers are used here; the rest of
// `support` is the HTTP client surface the other targets need.
#[allow(dead_code)]
mod support;

use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use support::{gateway_process_alive, parent_pid};

/// Printed by the inner fixtures so the outer test knows which pid to watch.
const PID_MARKER: &str = "FERROGATE_568_GATEWAY_PID=";

/// Spawns a gateway the way every test in this crate does and reports its pid on
/// stdout. Returns the live child so the caller decides how to die.
fn spawn_reported_gateway() -> std::process::Child {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    let (child, _addr) = support::start_ready_gateway(&config, |addr| {
        std::fs::write(&config, support::minimal_listening_config(addr)).unwrap();
    });
    println!("{PID_MARKER}{}", child.id());
    std::io::stdout().flush().unwrap();
    // The gateway has already read the config; the directory may go.
    drop(dir);
    child
}

/// Fixture: the panic path. A live gateway, then a panic before any cleanup --
/// exactly what a failed `assert!` does in any of this crate's ~250 gateway
/// tests.
#[test]
#[ignore = "fixture: driven by panicking_test_leaves_no_gateway_behind"]
// Not waiting on the child is the whole point: this fixture must leave a live
// gateway behind for the outer test to prove it gets reaped anyway (#568).
#[allow(clippy::zombie_processes)]
fn inner_spawn_then_panic() {
    let _child = spawn_reported_gateway();
    panic!("#568 fixture: this gateway must not outlive the test that spawned it");
}

/// Fixture: the SIGKILL path. A live gateway, then a wait long enough that the
/// outer test is certainly the one that ends this process.
#[test]
#[ignore = "fixture: driven by sigkilled_test_binary_leaves_no_gateway_behind"]
// Not waiting on the child is the whole point: this fixture must leave a live
// gateway behind for the outer test to prove it gets reaped anyway (#568).
#[allow(clippy::zombie_processes)]
fn inner_spawn_then_hang() {
    let _child = spawn_reported_gateway();
    std::thread::sleep(Duration::from_secs(600));
}

#[test]
#[ignore = "fixture: driven by graceful_upgrade_replacement_leaves_no_gateway_behind"]
fn inner_graceful_upgrade_then_panic() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    let pid_file = dir.path().join("ferrogate.pid");
    let upgrade_sock = dir.path().join("ferrogate_upgrade.sock");
    let gateway_addr = support::free_addr();
    write_graceful_upgrade_config(&config, &gateway_addr, &pid_file, &upgrade_sock);

    let mut old_gateway = support::start_gateway(&config);
    support::wait_for_gateway(&gateway_addr);
    let old_pid = old_gateway.id();
    write_graceful_upgrade_config(&config, &gateway_addr, &pid_file, &upgrade_sock);

    let reload = support::ferrogate_command()
        .args([
            "reload",
            "--config",
            config.to_str().unwrap(),
            "--graceful-upgrade",
        ])
        .output()
        .unwrap();
    assert!(
        reload.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&reload.stderr)
    );

    let new_pid = wait_for_pid_file_to_change(&pid_file, old_pid);
    println!("{PID_MARKER}{new_pid}");
    std::io::stdout().flush().unwrap();

    let _ = old_gateway.wait();
    panic!("#568 fixture: upgraded gateway must not outlive the test that spawned reload");
}

fn wait_for_pid_file_to_change(path: &std::path::Path, old_pid: u32) -> u32 {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        let pid = std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok());
        if let Some(pid) = pid {
            if pid != old_pid && gateway_process_alive(pid) {
                return pid;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "pid file {} did not change from old pid {old_pid}",
        path.display()
    );
}

/// Re-invocation of this very test binary, running one fixture and nothing else.
fn inner_harness(fixture: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([fixture, "--exact", "--ignored", "--nocapture"])
        // More than one thread so libtest runs the fixture on a spawned test
        // thread, which is how every real run of this suite executes it.
        .args(["--test-threads", "2"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

/// Reads the fixture's stdout until it reports its gateway pid. Fails loudly
/// rather than hanging if the fixture never gets that far.
fn read_reported_pid(stdout: impl std::io::Read) -> u32 {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).unwrap();
        assert!(read > 0, "fixture exited without reporting a gateway pid");
        if let Some(pid) = line.trim().strip_prefix(PID_MARKER) {
            return pid.parse().unwrap();
        }
    }
}

/// Waits up to `limit` for the gateway to disappear, then reports whether it
/// did. Never asserts -- callers kill the survivor before asserting, so a red
/// run does not itself leak the process it is complaining about.
fn wait_until_gone(pid: u32, limit: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if !gateway_process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !gateway_process_alive(pid)
}

fn kill_survivor(pid: u32) {
    if gateway_process_alive(pid) {
        // SAFETY: plain kill(2) on a pid this test confirmed is a ferrogate
        // gateway; SIGKILL takes no handler and touches no process state here.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
}

/// The panic path. Before #568 the fixture's `Child` was dropped by the unwind,
/// `Child::drop` detached instead of killing, and the gateway was still running
/// -- reparented to init -- long after its test binary had exited.
#[test]
fn panicking_test_leaves_no_gateway_behind() {
    let mut harness = inner_harness("inner_spawn_then_panic").spawn().unwrap();
    let pid = read_reported_pid(harness.stdout.take().unwrap());
    let status = harness.wait().unwrap();
    assert!(
        !status.success(),
        "fixture was supposed to panic, so its harness must report failure"
    );

    let gone = wait_until_gone(pid, Duration::from_secs(15));
    let orphaned_to = parent_pid(pid);
    kill_survivor(pid);
    assert!(
        gone,
        "gateway {pid} outlived the panicking test that spawned it \
         (now parented to {orphaned_to:?}); this is the #568 leak"
    );
}

/// The SIGKILL path -- `timeout`, Ctrl-C, or a harness fail-fast. No Rust
/// destructor runs, so nothing in userspace can clean up: only a kernel-side
/// mechanism can. This is the case that decides between killing the process
/// group from `Drop` and PR_SET_PDEATHSIG.
#[test]
fn sigkilled_test_binary_leaves_no_gateway_behind() {
    let mut harness = inner_harness("inner_spawn_then_hang").spawn().unwrap();
    let pid = read_reported_pid(harness.stdout.take().unwrap());
    assert!(
        gateway_process_alive(pid),
        "fixture reported gateway {pid} but it is not running; the assertion \
         below would pass for the wrong reason"
    );

    // SAFETY: SIGKILL to a child of this process, whose pid we own until wait().
    unsafe { libc::kill(harness.id() as libc::pid_t, libc::SIGKILL) };
    harness.wait().unwrap();

    let gone = wait_until_gone(pid, Duration::from_secs(15));
    let orphaned_to = parent_pid(pid);
    kill_survivor(pid);
    assert!(
        gone,
        "gateway {pid} outlived the SIGKILLed test binary that spawned it \
         (now parented to {orphaned_to:?}); this is the #568 leak"
    );
}

#[test]
fn graceful_upgrade_replacement_leaves_no_gateway_behind() {
    let mut harness = inner_harness("inner_graceful_upgrade_then_panic")
        .spawn()
        .unwrap();
    let pid = read_reported_pid(harness.stdout.take().unwrap());
    let status = harness.wait().unwrap();
    assert!(
        !status.success(),
        "fixture was supposed to panic, so its harness must report failure"
    );

    let gone = wait_until_gone(pid, Duration::from_secs(15));
    let orphaned_to = parent_pid(pid);
    kill_survivor(pid);
    assert!(
        gone,
        "graceful-upgrade replacement gateway {pid} outlived the panicking test \
         that spawned reload (now parented to {orphaned_to:?}); this is the \
         #568 grandchild leak"
    );
}

fn write_graceful_upgrade_config(
    path: &std::path::Path,
    gateway_addr: &str,
    pid_file: &std::path::Path,
    upgrade_sock: &std::path::Path,
) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[auth]
disabled = true

[reliability]
graceful_shutdown_grace_period_secs = 1
graceful_shutdown_timeout_secs = 1
graceful_upgrade_pid_file = "{}"
graceful_upgrade_sock = "{}"
graceful_upgrade_sock_retries = 8
"#,
            pid_file.display(),
            upgrade_sock.display()
        ),
    )
    .unwrap();
}
