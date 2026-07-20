// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Token4AI Cloud, FerroGate AI Gateway — KVM/Firecracker-gated
// real agent execution + capability-denial enforcement inside a microVM, and
// ungated fail-closed degradation for microVM-required workloads (#280).
//
//! #280 acceptance harness.
//!
//! Three layers, gated honestly:
//!
//! 1. **KVM-gated real execution** (`agent_run_executes_inside_microvm_...`):
//!    on a KVM host with the Firecracker bundle configured AND the guest agent
//!    staged in the rootfs (see `docs/sandbox/firecracker-agent-execution.md`),
//!    `agent-worker firecracker-agent-exec-smoke` boots a real microVM and
//!    proves (a) an allowed workload really executes inside the guest and
//!    (b) a workload whose capability is withheld by the gateway envelope is
//!    DENIED by the guest agent inside the VM boundary — enforced, never
//!    report-only. Without KVM/bundle/staged-guest the test SKIPS with an
//!    explicit reason; it never fake-passes.
//!
//! 2. **Ungated fail-closed degradation** (acceptance 2 — provable in this
//!    sandbox): on a host WITHOUT KVM the same microVM-required smoke fails
//!    closed with the distinct `microvm_required_backend_unavailable`
//!    degradation evidence and explicitly records that no local_process
//!    fallback happened.
//!
//! 3. **Ungated local-process fallback** (the accepted sandbox-CI substitute):
//!    the #242 report-only local-process path remains the working ungated
//!    harness fallback; it skips cleanly when the host lacks the unprivileged
//!    namespace stack.

use std::process::Command;

use serde_json::Value;

const AGENT_WORKER_BIN: &str = env!("CARGO_BIN_EXE_agent-worker");

/// Set on a KVM host after staging the guest agent into the rootfs per
/// `docs/sandbox/firecracker-agent-execution.md`. Host preflight cannot see
/// inside the rootfs image, so staging is declared explicitly.
const GUEST_AGENT_STAGED_ENV: &str = "AGENT_WORKER_FIRECRACKER_GUEST_AGENT_STAGED";

fn skip(test: &str, reason: &str) {
    println!("SKIP {test}: {reason}");
    eprintln!("SKIP {test}: {reason}");
}

fn run_agent_worker_json(args: &[&str], envs: &[(&str, &str)]) -> Result<Value, String> {
    let mut command = Command::new(AGENT_WORKER_BIN);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
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

fn host_preflight_ready() -> Result<bool, String> {
    let preflight = run_agent_worker_json(&["firecracker-host-preflight"], &[])?;
    Ok(preflight["ready"].as_bool() == Some(true))
}

fn preflight_failure_reasons() -> String {
    run_agent_worker_json(&["firecracker-host-preflight"], &[])
        .ok()
        .and_then(|preflight| {
            preflight["failure_reasons"].as_array().map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
        })
        .unwrap_or_else(|| "host preflight not evaluable".to_string())
}

/// Acceptance 1 (KVM host only): a real agent run executes inside a
/// Firecracker microVM and capability denials are enforced at the VM
/// boundary.
#[test]
fn agent_run_executes_inside_microvm_and_capability_denial_is_enforced() {
    const TEST: &str = "firecracker_agent_execution";
    match host_preflight_ready() {
        Ok(true) => {}
        Ok(false) => {
            skip(
                TEST,
                &format!(
                    "Firecracker host prerequisites absent (need /dev/kvm access + \
                     AGENT_WORKER_FIRECRACKER_BIN/JAILER/KERNEL/ROOTFS): {}",
                    preflight_failure_reasons()
                ),
            );
            return;
        }
        Err(error) => {
            skip(
                TEST,
                &format!("could not evaluate host preflight ({error})"),
            );
            return;
        }
    }
    if std::env::var(GUEST_AGENT_STAGED_ENV).map(|value| value == "1") != Ok(true) {
        skip(
            TEST,
            &format!(
                "guest agent not staged in the rootfs (export {GUEST_AGENT_STAGED_ENV}=1 after \
                 staging per docs/sandbox/firecracker-agent-execution.md)"
            ),
        );
        return;
    }

    let report = run_agent_worker_json(
        &[
            "firecracker-agent-exec-smoke",
            "--timeout-millis",
            "90000",
            "--vcpu-count",
            "1",
            "--mem-size-mib",
            "256",
        ],
        &[],
    )
    .expect("firecracker-agent-exec-smoke must emit JSON on a ready host");
    let summary = serde_json::to_string(&report).unwrap_or_default();
    println!("firecracker_agent_execution evidence: {summary}");

    // The microVM really booted and the smoke did not fail closed.
    assert_eq!(report["ready"], true, "{summary}");
    assert_eq!(report["fail_closed"], false, "{summary}");
    assert_eq!(report["proves_microvm_boot"], true, "{summary}");

    // (a) The allowed workload really executed INSIDE the guest.
    assert_eq!(report["allowed"]["status"], "completed", "{summary}");
    assert_eq!(
        report["allowed"]["proves_handler_execution"], true,
        "{summary}"
    );
    assert_eq!(
        report["allowed"]["workload_result"]["executed"], true,
        "{summary}"
    );
    assert_eq!(
        report["allowed"]["workload_result"]["exit_code"], 0,
        "{summary}"
    );
    assert!(
        report["allowed"]["workload_result"]["output_excerpt"]
            .as_str()
            .unwrap_or_default()
            .contains("ferrogate-firecracker-guest-exec-allowed"),
        "{summary}"
    );

    // (b) The denied workload was ENFORCED at the VM boundary: never spawned,
    // denial recorded as evidence — not report-only.
    assert_eq!(report["denied"]["status"], "capability_denied", "{summary}");
    assert_eq!(
        report["denied"]["workload_result"]["executed"], false,
        "{summary}"
    );
    assert_eq!(
        report["denied"]["workload_result"]["capability_denial_enforced"], true,
        "{summary}"
    );
    assert_eq!(
        report["denied"]["proves_handler_execution"], false,
        "{summary}"
    );
    assert!(
        report["denied"]["event_kinds"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "capability.denied")),
        "{summary}"
    );
}

/// Acceptance 2 (provable WITHOUT KVM — this sandbox): a microVM-required
/// workload degrades explicitly and fails closed; it never silently runs on
/// local_process.
#[test]
fn microvm_required_workload_fails_closed_without_kvm_never_local_process() {
    const TEST: &str = "firecracker_agent_execution_fail_closed";
    match host_preflight_ready() {
        Ok(false) => {}
        Ok(true) => {
            // On a real KVM host this negative test is not meaningful; the
            // positive acceptance above covers that environment.
            skip(
                TEST,
                "host preflight is ready; fail-closed degradation covered on non-KVM hosts",
            );
            return;
        }
        Err(error) => {
            skip(
                TEST,
                &format!("could not evaluate host preflight ({error})"),
            );
            return;
        }
    }

    // Enable the local-process backend ON PURPOSE: it must NOT be used.
    let report = run_agent_worker_json(
        &["firecracker-agent-exec-smoke", "--timeout-millis", "2000"],
        &[
            ("AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND", "1"),
            ("AGENT_WORKER_REQUIRE_MICROVM_ISOLATION", "1"),
        ],
    )
    .expect("firecracker-agent-exec-smoke must emit fail-closed JSON without KVM");
    let summary = serde_json::to_string(&report).unwrap_or_default();
    println!("firecracker_agent_execution fail-closed evidence: {summary}");

    assert_eq!(report["ready"], false, "{summary}");
    assert_eq!(report["fail_closed"], true, "{summary}");
    // The distinct degradation marker: explicit, preflight-gated, and never a
    // silent local_process fallback.
    assert_eq!(
        report["degradation"], "microvm_required_backend_unavailable",
        "{summary}"
    );
    assert_eq!(report["local_process_fallback"], false, "{summary}");
    assert_eq!(report["backend_name"], "firecracker", "{summary}");
    assert_eq!(report["failure_stage"], "preflight_failed", "{summary}");
    assert_eq!(report["proves_microvm_boot"], false, "{summary}");
    assert_eq!(report["proves_handler_execution"], false, "{summary}");
}

/// The accepted ungated fallback for sandbox CI: the #242 report-only
/// local-process execution path. Skips cleanly when the host cannot provide
/// the unprivileged namespace stack.
#[test]
fn local_process_fallback_path_still_works_ungated() {
    const TEST: &str = "firecracker_agent_execution_local_process_fallback";
    let evidence = match run_agent_worker_json(
        &[
            "--worker-type",
            "self-hosted",
            "self-hosted-governed-execution-smoke",
            "--now-unix-millis",
            "1000",
        ],
        &[("AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND", "1")],
    ) {
        Ok(evidence) => evidence,
        Err(error) => {
            // The smoke exits non-zero without JSON when the namespace stack
            // is unavailable; that is a skip, not a failure, per the accepted
            // local-E2E policy.
            skip(
                TEST,
                &format!("local-process backend unavailable on this host: {error}"),
            );
            return;
        }
    };
    let summary = serde_json::to_string(&evidence).unwrap_or_default();
    println!("local_process_fallback evidence: {summary}");
    assert!(
        evidence["isolation_backend"].as_str().is_some(),
        "{summary}"
    );
    assert_eq!(evidence["workload_ran"], true, "{summary}");
    assert_eq!(evidence["capability_enforcement"], "reported", "{summary}");
}
