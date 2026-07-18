// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Token4AI Cloud, FerroGate AI Gateway — KVM/Firecracker-gated
// report-only self-hosted execution validation (#247).
//
//! KVM/Firecracker-gated report-only self-hosted execution harness (#247).
//!
//! This is the Firecracker analog of the #242 local-process report-only slice:
//! a self-hosted worker boots a microVM through the GOVERNED Firecracker backend
//! under a capability policy that would DENY the workload, and records the
//! decision as report-only telemetry (`enforcement_boundary=customer_owned_host`,
//! `trust_level=reported_by_self_hosted_worker`, server-clock identity expiry)
//! WITHOUT blocking — the microVM boots anyway. Cloud stays enforced (covered by
//! the `cloud_enforces_and_blocks_a_denied_firecracker_workload_before_any_boot`
//! unit test, which blocks before any boot and needs no KVM).
//!
//! ## Gating (honest skip — never a fake pass)
//!
//! Prerequisites are detected exactly like `firecracker_boot_validation`: the
//! production host preflight (`agent-worker firecracker-host-preflight`) decides
//! whether `/dev/kvm` is accessible AND a firecracker binary/jailer/kernel/rootfs
//! are configured via `AGENT_WORKER_FIRECRACKER_*`. When ANY prerequisite is
//! absent (e.g. plain `cargo test` with no KVM group / no images) the test SKIPS
//! with a logged reason — it does NOT fail and does NOT pretend to boot.
//!
//! When prerequisites are PRESENT (run via `sg kvm -c` with the firecracker env
//! sourced) the report-only smoke boots a real microVM and this test asserts the
//! full customer-owned-host report-only contract plus real serial-console boot
//! evidence.

use std::process::Command;

use serde_json::Value;

const AGENT_WORKER_BIN: &str = env!("CARGO_BIN_EXE_agent-worker");

fn skip(reason: &str) {
    println!("SKIP self_hosted_firecracker_report_only: {reason}");
    eprintln!("SKIP self_hosted_firecracker_report_only: {reason}");
}

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

#[test]
fn self_hosted_worker_boots_a_microvm_report_only_while_cloud_stays_enforced() {
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

    // 2. Prerequisites present: boot a microVM report-only under self-hosted. A
    //    DENY policy (cloud would block) that still runs the workload and records
    //    it as report-only — the exact "cloud would block, self-hosted records"
    //    behavior, now through the Firecracker isolation backend.
    let evidence = run_agent_worker_json(&[
        "--worker-type",
        "self-hosted",
        "self-hosted-firecracker-execution-smoke",
        "--timeout-millis",
        "90000",
        "--vcpu-count",
        "1",
        "--mem-size-mib",
        "256",
        "--now-unix-millis",
        "1000",
    ])
    .expect("self-hosted firecracker report-only smoke must emit JSON on a ready host");

    let summary = serde_json::to_string(&evidence).unwrap_or_default();
    println!("self_hosted_firecracker_report_only evidence: {summary}");

    // 2a. Report-only customer-owned-host contract (never enforced).
    assert_eq!(evidence["worker_type"], "self-hosted", "{summary}");
    assert_eq!(evidence["capability_enforcement"], "reported", "{summary}");
    assert_eq!(
        evidence["enforcement_boundary"], "customer_owned_host",
        "{summary}"
    );
    assert_eq!(evidence["execution_owner"], "customer", "{summary}");
    assert_eq!(
        evidence["trust_level"], "reported_by_self_hosted_worker",
        "{summary}"
    );
    assert_eq!(evidence["report_only"], true, "{summary}");
    assert_eq!(evidence["cloud_would_block"], true, "{summary}");
    assert_eq!(evidence["identity_expiry_clock"], "server", "{summary}");
    // Server-clock-stamped identity expiry: 1000 + 15min TTL.
    assert_eq!(
        evidence["identity_expiry_unix_millis"].as_u64(),
        Some(1_000 + 15 * 60 * 1000),
        "{summary}"
    );

    // 2b. The microVM really booted through the governed Firecracker backend.
    assert_eq!(evidence["isolation_backend"], "firecracker", "{summary}");
    assert_eq!(evidence["workload_ran"], true, "{summary}");
    assert_eq!(
        evidence["workload_exit_code"].as_i64(),
        Some(0),
        "{summary}"
    );
    let output = evidence["workload_output"].as_str().unwrap_or_default();
    assert!(
        output.contains("firecracker microvm booted"),
        "workload output missing boot evidence: {summary}"
    );
    assert!(
        output.contains("rootfs_mounted"),
        "workload output missing serial boot markers: {summary}"
    );
}
