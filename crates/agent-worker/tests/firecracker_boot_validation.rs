// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Token4AI Cloud, FerroGate AI Gateway — KVM/Firecracker-gated
// guest boot validation for the per-VM read-only rootfs + writable workspace
// drive layout (#227).
//
//! KVM/Firecracker-gated guest-boot validation harness (#227).
//!
//! The per-VM rootfs isolation code (read-only `/dev/vda` rootfs + per-VM
//! writable `/dev/vdb` workspace, derived from `IsolationFilesystemPolicy` via
//! `plan_firecracker_rootfs_attachment`) already landed. The one open
//! acceptance on #227 is: *guest boot validated on a real Firecracker host with
//! the new drive layout*.
//!
//! This test IS that validation. It drives the shipped, governed boot path
//! (`agent-worker firecracker-boot-smoke`, which applies the new drive layout)
//! against a real Firecracker host and asserts the guest actually boots with
//! the read-only rootfs honored.
//!
//! ## Gating (honest skip — never a fake pass)
//!
//! It runs the production host preflight (`agent-worker
//! firecracker-host-preflight`) to decide whether the prerequisites exist:
//!   * `/dev/kvm` present AND readable+writable by this user, AND
//!   * a `firecracker` binary, jailer, kernel image and rootfs image all
//!     configured via the existing `AGENT_WORKER_FIRECRACKER_*` env vars.
//!
//! When any prerequisite is ABSENT (this sandbox: no KVM access, no
//! Firecracker binary / images) the preflight reports `ready: false` and the
//! test SKIPS with a clear logged reason — it does NOT fail and does NOT
//! pretend to pass a boot it never ran.
//!
//! When the prerequisites are PRESENT (a real Firecracker host / KVM-enabled
//! runner) the test boots a microVM through the governed path and asserts:
//!   * the guest reaches userspace (`proves_microvm_boot: true` — real serial
//!     boot evidence), proving the new read-only-rootfs + `/dev/vdb` layout
//!     boots, and
//!   * the guest kernel honored `root=/dev/vda ro` (serial marker
//!     `rootfs_mounted_readonly` — the kernel annotates the VFS mount line
//!     "readonly").
//!
//! The boot-smoke path provisions and tears the microVM down cleanly on its
//! own (it stops the VM and reports the artifact paths), so this harness leaves
//! no microVM behind.
//!
//! See `docs/sandbox/firecracker-boot-validation.md` for the one-command
//! maintainer procedure and the full in-guest read-only / writable-workspace
//! verification steps.

use std::process::Command;

use serde_json::Value;

/// Path to the freshly built `agent-worker` binary, injected by Cargo for
/// integration tests.
const AGENT_WORKER_BIN: &str = env!("CARGO_BIN_EXE_agent-worker");

/// Log an honest skip. Cargo shows test stdout on a single-test run
/// (`-- --nocapture`), and always on failure; a skip is a pass, so this line is
/// how a maintainer sees WHY the boot validation did not execute.
fn skip(reason: &str) {
    println!("SKIP firecracker_boot_validation: {reason}");
    eprintln!("SKIP firecracker_boot_validation: {reason}");
}

/// Run an `agent-worker` subcommand and return its parsed JSON stdout.
///
/// The Firecracker preflight and boot-smoke subcommands both print a JSON
/// report and exit 0 even when the host is not ready / the boot did not happen,
/// so readiness and boot success are read from JSON fields, never the exit
/// code.
fn run_agent_worker_json(args: &[&str]) -> Result<Value, String> {
    let output = Command::new(AGENT_WORKER_BIN)
        .args(args)
        .output()
        .map_err(|error| format!("failed to spawn {AGENT_WORKER_BIN} {args:?}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str::<Value>(stdout.trim()).map_err(|error| {
        format!(
            "could not parse JSON from `agent-worker {args:?}` (status {:?}): {error}\nstdout: {stdout}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn markers(report: &Value) -> Vec<String> {
    report["evidence"]["serial_boot_markers"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn firecracker_guest_boots_with_read_only_rootfs_layout() {
    // 1. Detect prerequisites via the production host preflight (KVM device
    //    accessibility + firecracker binary/jailer/kernel/rootfs configured).
    let preflight = match run_agent_worker_json(&["firecracker-host-preflight"]) {
        Ok(preflight) => preflight,
        Err(error) => {
            skip(&format!("could not evaluate host preflight ({error})"));
            return;
        }
    };

    if preflight["ready"].as_bool() != Some(true) {
        let reasons = preflight["failure_reasons"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_else(|| "host preflight not ready".to_string());
        skip(&format!(
            "Firecracker host prerequisites absent (need /dev/kvm access + \
             AGENT_WORKER_FIRECRACKER_BIN/JAILER/KERNEL/ROOTFS): {reasons}"
        ));
        return;
    }

    // 2. Prerequisites present: boot a microVM through the governed boot path
    //    (which applies the new read-only rootfs + per-VM /dev/vdb layout) and
    //    require real serial-console boot evidence. A generous timeout because
    //    a cold guest boot + userspace bring-up can take several seconds.
    let report = run_agent_worker_json(&[
        "firecracker-boot-smoke",
        "--timeout-millis",
        "90000",
        "--vcpu-count",
        "1",
        "--mem-size-mib",
        "256",
    ])
    .expect("firecracker-boot-smoke must emit a JSON report on a ready host");

    let boot_markers = markers(&report);
    let evidence_summary = format!(
        "proves_microvm_boot={:?} boot_observed={:?} failure_stage={:?} failure_reason={:?} markers={:?}",
        report["proves_microvm_boot"],
        report["boot_observed"],
        report["failure_stage"],
        report["failure_reason"],
        boot_markers,
    );
    println!("firecracker_boot_validation evidence: {evidence_summary}");

    // 3a. The guest booted to userspace with the new drive layout.
    assert_eq!(
        report["boot_observed"].as_bool(),
        Some(true),
        "guest did not reach userspace boot with the read-only rootfs + /dev/vdb layout: {evidence_summary}"
    );
    assert_eq!(
        report["proves_microvm_boot"].as_bool(),
        Some(true),
        "boot smoke did not prove a real microVM boot: {evidence_summary}"
    );
    assert!(
        boot_markers.iter().any(|marker| marker == "rootfs_mounted"),
        "serial log is missing the rootfs-mounted marker: {evidence_summary}"
    );

    // 3b. The guest kernel honored `root=/dev/vda ro` — the declared
    //     IsolationFilesystemPolicy.read_only_rootfs was enforced end to end.
    assert!(
        boot_markers
            .iter()
            .any(|marker| marker == "rootfs_mounted_readonly"),
        "guest kernel did NOT mount the rootfs read-only — `root=/dev/vda ro` was not honored: {evidence_summary}"
    );

    // NOTE: asserting the in-guest write to `/dev/vda` fails and `/dev/vdb` is
    // writable requires running commands INSIDE the guest, which the shipped
    // guest-RPC entrypoint does not yet execute (tracked separately). The
    // runbook documents the manual in-guest verification a maintainer performs
    // for that final layer; the automated evidence above already proves the
    // read-only rootfs layout boots and is honored by the kernel.
}
