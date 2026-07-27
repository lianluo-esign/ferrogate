// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Regression gate for the backlog half of issue #568. The parent
// death signal armed in `support::reap_with_test` stops the leak from the
// moment it lands, but it cannot touch the orphans a box is already carrying --
// 106 of them when #568 was filed, most spawned by a checkout that no longer
// exists, the oldest 14 hours old, and none of them behind a systemd unit that
// would ever reap them. `support::sweep_orphaned_gateways` clears those on the
// first gateway spawn of each test binary.
//
// A sweep kills processes this suite does not own, so both directions are
// gated: the orphan goes, and a gateway that still belongs to a running test
// does not. Getting the second wrong would land as somebody else's flaky test,
// which #568 names as the reason this whole class of bug stays invisible.
//
// This lives apart from `gateway_reaping.rs` deliberately. A sweep is global,
// so running one in that binary would clean up after the panic and SIGKILL
// fixtures and hold them green with the fix removed -- which it did, until the
// two were split.
#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use std::{
    process::Command,
    time::{Duration, Instant},
};

use support::{gateway_process_alive, parent_pid};

/// Old enough that a fresh orphan from a concurrently running target -- one
/// this test must not reap out from under its own assertions -- is out of
/// range, but short enough to wait for.
const FIXTURE_AGE: Duration = Duration::from_secs(2);

/// A sweep is global, so two tests in this binary running at once would reap
/// each other's fixtures and each would then pass for the other's reason.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serialised() -> std::sync::MutexGuard<'static, ()> {
    // A panicking test poisons the lock; the next one still needs to run.
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn sweep_reaps_an_orphan_and_spares_a_running_test_s_gateway() {
    let _serial = serialised();
    let dir = tempfile::tempdir().unwrap();

    // The gateway that must survive: spawned by this test, still parented to it.
    let live_config = dir.path().join("live.toml");
    let (mut live, _addr) = support::start_ready_gateway(&live_config, |addr| {
        std::fs::write(&live_config, support::minimal_listening_config(addr)).unwrap();
    });

    // The gateway that must not: reparented to init before the sweep runs.
    let orphan_config = dir.path().join("orphan.toml");
    std::fs::write(
        &orphan_config,
        support::minimal_listening_config(&support::free_addr()),
    )
    .unwrap();
    let orphan = orphan_reparented_to_init(&orphan_config);

    assert!(
        support::is_orphaned_test_gateway(orphan),
        "fixture orphan {orphan} was not classified as sweepable; the sweep \
         below would prove nothing"
    );
    assert!(
        !support::is_orphaned_test_gateway(live.id()),
        "the running test's own gateway {} was classified as sweepable -- the \
         sweep would kill live gateways and land as an unrelated flake",
        live.id()
    );

    std::thread::sleep(FIXTURE_AGE);
    let swept = support::sweep_orphaned_gateways(FIXTURE_AGE);
    let orphan_gone = wait_until_gone(orphan, Duration::from_secs(10));
    let live_survived = gateway_process_alive(live.id());
    kill_survivor(orphan);
    let _ = live.kill();
    let _ = live.wait();

    assert!(
        swept.contains(&orphan),
        "sweep did not claim the orphan it was pointed at: {swept:?}"
    );
    assert!(orphan_gone, "orphaned gateway {orphan} survived the sweep");
    assert!(
        live_survived,
        "the sweep killed a gateway that still belonged to a running test"
    );
}

/// The age floor is what keeps the automatic sweep off a gateway that a sibling
/// suite reparented seconds ago while tearing itself down.
#[test]
fn sweep_leaves_an_orphan_younger_than_the_floor_alone() {
    let _serial = serialised();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("orphan.toml");
    std::fs::write(
        &config,
        support::minimal_listening_config(&support::free_addr()),
    )
    .unwrap();
    let orphan = orphan_reparented_to_init(&config);

    let swept = support::sweep_orphaned_gateways(Duration::from_secs(3600));
    let survived = gateway_process_alive(orphan);
    kill_survivor(orphan);

    assert!(
        !swept.contains(&orphan),
        "sweep claimed an orphan far younger than its age floor: {swept:?}"
    );
    assert!(
        survived,
        "orphan {orphan} was killed despite being younger than the age floor"
    );
}

/// Starts a gateway through a shell that exits immediately, so the kernel
/// reparents it -- the way the real backlog arises. Returns its pid once that
/// has actually happened.
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
    while parent_pid(pid) != Some(1) && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        parent_pid(pid),
        Some(1),
        "fixture gateway {pid} was never adopted by init"
    );
    assert!(
        gateway_process_alive(pid),
        "fixture orphan {pid} is not running"
    );
    pid
}

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
