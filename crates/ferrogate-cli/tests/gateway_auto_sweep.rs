// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Regression gate for issue #568 -- the backlog sweep must be
// invoked automatically through the governed ferrogate command helper, not only
// through tests that call sweep_orphaned_gateways() manually.

#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use std::{
    process::Command,
    time::{Duration, Instant},
};

const FIXTURE_AGE: Duration = Duration::from_secs(2);

#[test]
fn first_governed_gateway_spawn_runs_the_backlog_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let orphan_config = dir.path().join("orphan.toml");
    std::fs::write(
        &orphan_config,
        support::minimal_listening_config(&support::free_addr()),
    )
    .unwrap();
    let orphan = orphan_reparented_to_init(&orphan_config);

    std::thread::sleep(FIXTURE_AGE);
    std::env::set_var("FERROGATE_TEST_ORPHAN_SWEEP_MIN_AGE_MS", "1000");

    let live_config = dir.path().join("live.toml");
    let (mut live, _addr) = support::start_ready_gateway(&live_config, |addr| {
        std::fs::write(&live_config, support::minimal_listening_config(addr)).unwrap();
    });

    let orphan_gone = wait_until_gone(orphan, Duration::from_secs(10));
    kill_survivor(orphan);
    let _ = live.kill();
    let _ = live.wait();
    std::env::remove_var("FERROGATE_TEST_ORPHAN_SWEEP_MIN_AGE_MS");

    assert!(
        orphan_gone,
        "the first governed gateway spawn did not run the automatic #568 backlog sweep"
    );
}

fn orphan_reparented_to_init(config: &std::path::Path) -> u32 {
    let launcher = Command::new("sh")
        .arg("-c")
        .arg(r#""$1" run --config "$2" >/dev/null 2>&1 & echo $!"#)
        .arg("sh")
        .arg(env!("CARGO_BIN_EXE_ferrogate"))
        .arg(config)
        .output()
        .unwrap();
    let pid: u32 = String::from_utf8_lossy(&launcher.stdout)
        .trim()
        .parse()
        .unwrap();

    let started = Instant::now();
    while support::parent_pid(pid) != Some(1) && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        support::parent_pid(pid),
        Some(1),
        "fixture gateway {pid} was never adopted by init"
    );
    assert!(
        support::gateway_process_alive(pid),
        "fixture orphan {pid} is not running"
    );
    pid
}

fn wait_until_gone(pid: u32, limit: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if !support::gateway_process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !support::gateway_process_alive(pid)
}

fn kill_survivor(pid: u32) {
    if support::gateway_process_alive(pid) {
        // SAFETY: plain kill(2) on a pid this test confirmed is a ferrogate
        // gateway; SIGKILL takes no handler and touches no process state here.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
}
