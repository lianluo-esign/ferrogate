// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Adversarial containment suite for a real isolation backend, driven through
//! the governed Agent action path (issue #205).
//!
//! The suite provisions a workload on the local-process (Linux namespace)
//! backend via signed management envelopes — the exact path the gateway uses —
//! and then attacks every containment dimension from inside the workload:
//! filesystem escape, network egress, host process visibility, namespace
//! identity, resource limits, and host secret leakage. The documented matrix
//! for each dimension lives in `docs/sandbox/isolation-adversarial-suite.md`.
//!
//! Fail-closed guarantee: on hosts where the unprivileged namespace stack is
//! unavailable, the suite instead asserts that the governed Provision action
//! is REJECTED (non-retryable `incompatible_backend`) before any host work
//! runs — the backend never silently runs unconfined.

use super::*;
use crate::test_support::lock_firecracker_env;
use ferrogate_runtime::{
    IsolationBackendLifecycle, IsolationExecRequest, ManagedWorkerSessionStatus,
};
use std::path::Path;

const PREFIX: &str = "agent-worker-local-process-adversarial";

/// Removes the suite's env toggles on drop so a panicking assert can never
/// leak configuration into other tests (the firecracker env lock serializes
/// all env-mutating tests, but cleanup must still be unconditional).
struct SuiteEnvGuard;

impl SuiteEnvGuard {
    fn engage() -> Self {
        for var in [
            "AGENT_WORKER_FIRECRACKER_BIN",
            "AGENT_WORKER_FIRECRACKER_JAILER",
            "AGENT_WORKER_FIRECRACKER_KERNEL",
            "AGENT_WORKER_FIRECRACKER_ROOTFS",
            "AGENT_WORKER_FIRECRACKER_KVM_DEVICE",
            "AGENT_WORKER_ENABLE_DOCKER_BACKEND",
        ] {
            std::env::remove_var(var);
        }
        std::env::set_var("AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND", "1");
        // Short wall-clock budget so the resource-containment kill probe is
        // fast; every legitimate probe in this suite finishes well under it.
        std::env::set_var("AGENT_WORKER_LOCAL_PROCESS_MAX_RUNTIME_MILLIS", "1500");
        Self
    }
}

impl Drop for SuiteEnvGuard {
    fn drop(&mut self) {
        for var in [
            "AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND",
            "AGENT_WORKER_LOCAL_PROCESS_MAX_RUNTIME_MILLIS",
            "AGENT_WORKER_LOCAL_PROCESS_UNSHARE_BIN",
            "FERROGATE_TEST_HOST_SECRET",
        ] {
            std::env::remove_var(var);
        }
    }
}

fn adversarial_envelope(
    action: AgentWorkerManagementAction,
    request: &str,
) -> AgentWorkerManagementEnvelope {
    let mut envelope = smoke_envelope().unwrap();
    envelope.action = action;
    envelope.request_id = format!("{PREFIX}-{request}-request");
    envelope.idempotency_key = format!("{PREFIX}-{request}-idempotency");
    envelope.session_id = Some(format!("{PREFIX}-session"));
    envelope.run_id = Some(format!("{PREFIX}-run"));
    envelope.framework_adapter = None;
    envelope.security.nonce = format!("{PREFIX}-{request}-nonce");
    envelope.security.signature = envelope
        .shared_secret_signature(SMOKE_SHARED_SECRET)
        .unwrap();
    envelope
}

fn suite_transport() -> InMemoryAgentWorkerManagementTransport {
    InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: "agent-worker-smoke-key".to_string(),
            shared_secret: SMOKE_SHARED_SECRET.to_string(),
        }])
        .unwrap(),
    )
}

fn expect_lifecycle(
    response: &AgentWorkerManagementResponse,
    context: &str,
) -> ferrogate_runtime::AgentWorkerLifecycleResult {
    assert!(response.accepted, "{context}: {:?}", response.error);
    match &response.result {
        Some(AgentWorkerManagementResult::Lifecycle { lifecycle }) => lifecycle.clone(),
        other => panic!("{context}: expected lifecycle result, got {other:?}"),
    }
}

/// Run one adversarial probe inside the governed-provisioned instance through
/// the same `IsolationBackendLifecycle` contract the governed exec path uses.
fn probe(
    state: &mut InMemoryAgentWorkerStateStore,
    args: &[&str],
) -> ferrogate_runtime::IsolationExecOutcome {
    let session_id = format!("{PREFIX}-session");
    let run_id = format!("{PREFIX}-run");
    let backend = state
        .get_local_process_backend_mut(&session_id, &run_id)
        .expect("governed provision must have stored the local-process backend");
    let instance_id = backend.instance_id().unwrap().to_string();
    backend
        .exec_or_attach(IsolationExecRequest {
            instance_id,
            workload_ref: "agent://adversarial/probe".to_string(),
            args: args.iter().map(ToString::to_string).collect(),
        })
        .expect("adversarial probe exec must not error at the backend layer")
}

#[test]
fn local_process_backend_passes_adversarial_containment_suite_through_governed_action_path() {
    let _env_lock = lock_firecracker_env();
    let _guard = SuiteEnvGuard::engage();
    // A fake host secret that must never be visible inside the workload.
    std::env::set_var("FERROGATE_TEST_HOST_SECRET", "supersecret-host-credential");

    // Fail-closed acceptance branch: a host without the unprivileged namespace
    // stack must reject the governed Provision before any host work runs.
    if let Err(reason) = crate::local_process_backend::local_process_backend_readiness() {
        eprintln!(
            "adversarial suite: unprivileged namespace stack unavailable ({reason}); \
             asserting fail-closed governed provision instead of the containment matrix"
        );
        assert_governed_provision_fails_closed("unavailable-stack");
        return;
    }

    let mut transport = suite_transport();
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();

    // ---- Provision through the governed Agent action path ----
    let provision = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        adversarial_envelope(AgentWorkerManagementAction::Provision, "provision"),
        1_000,
    );
    let lifecycle = expect_lifecycle(&provision, "governed provision");
    assert_eq!(lifecycle.backend_name, "local-process");
    assert_eq!(lifecycle.backend_kind, "local_process");
    assert_eq!(lifecycle.status, ManagedWorkerSessionStatus::Running);
    assert_eq!(lifecycle.outcome, "provisioned");
    // Backend-version evidence: the real probed `unshare --version`, never a
    // placeholder.
    assert!(
        !lifecycle.backend_version.is_empty()
            && lifecycle.backend_version != "disabled"
            && lifecycle.backend_version != "unknown",
        "backend_version evidence missing: {lifecycle:?}"
    );
    // Containment + degraded-control evidence is loud in the run report.
    for needle in [
        "namespaces=user,mount,pid,net",
        "env_fingerprint=sha256:",
        "image_digest=none(host-userspace-no-image)",
        "degraded_controls=[rootfs_not_remounted_read_only",
        "network=netns-loopback-only-no-egress",
    ] {
        assert!(
            lifecycle.message.contains(needle),
            "provision evidence missing {needle}: {}",
            lifecycle.message
        );
    }
    let instance_id = lifecycle.isolation_instance_id.clone().unwrap();
    assert!(instance_id.starts_with("local-process-"));

    // ---- Governed exec readiness probe ----
    let exec = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        adversarial_envelope(AgentWorkerManagementAction::ExecOrAttach, "exec"),
        1_000,
    );
    let lifecycle = expect_lifecycle(&exec, "governed exec");
    assert_eq!(lifecycle.outcome, "executed");
    assert!(lifecycle
        .message
        .contains("agent-worker-local-process-ready"));

    // Capture host-side facts for the adversarial probes.
    let (workspace, env_fingerprint) = {
        let backend = state
            .get_local_process_backend_mut(&format!("{PREFIX}-session"), &format!("{PREFIX}-run"))
            .unwrap();
        (
            backend.workspace_dir().unwrap().to_path_buf(),
            backend.env_fingerprint().unwrap().to_string(),
        )
    };
    assert_eq!(env_fingerprint.len(), 64, "fingerprint must be sha256 hex");
    assert!(provision_message_contains_fingerprint(
        &provision,
        &env_fingerprint
    ));

    // ================= 1. FILESYSTEM containment =================
    let host_tmp_marker = std::env::temp_dir().join(format!("{PREFIX}-host-tmp-marker"));
    std::fs::write(&host_tmp_marker, b"host-only").unwrap();
    let mut script = String::from(
        "[ \"$(pwd)\" = \"/mnt\" ] || exit 10\n\
         echo adversarial-artifact-data > /mnt/adversarial-artifact.txt || exit 11\n\
         touch /etc/ferrogate-escape 2>/dev/null && exit 12\n\
         touch /usr/ferrogate-escape 2>/dev/null && exit 13\n\
         touch /home/ferrogate-escape 2>/dev/null && exit 14\n\
         [ -z \"$(ls -A /home)\" ] || exit 15\n",
    );
    if std::env::temp_dir() == Path::new("/tmp") {
        script.push_str(&format!(
            "[ ! -e \"{}\" ] || exit 16\n",
            host_tmp_marker.display()
        ));
    }
    if let Ok(host_home) = std::env::var("HOME") {
        if host_home.starts_with("/home/") {
            script.push_str(&format!("[ ! -e \"{host_home}\" ] || exit 17\n"));
        }
    }
    script.push_str("echo filesystem-containment-ok\n");
    let outcome = probe(&mut state, &["sh", "-c", &script]);
    std::fs::remove_file(&host_tmp_marker).unwrap();
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "filesystem containment breached (exit={:?}): {}",
        outcome.exit_code,
        outcome.message
    );
    assert!(outcome.message.contains("filesystem-containment-ok"));
    // The only writable escape hatch is the prepared workspace: the write is
    // visible on the host exactly there.
    let artifact = workspace.join("adversarial-artifact.txt");
    assert_eq!(
        std::fs::read_to_string(&artifact).unwrap().trim(),
        "adversarial-artifact-data"
    );

    // ================= 2. NETWORK containment =================
    let outcome = probe(
        &mut state,
        &[
            "sh",
            "-c",
            "grep -q \" *lo:\" /proc/net/dev || exit 20\n\
             [ \"$(tail -n +3 /proc/net/dev | wc -l)\" = \"1\" ] || exit 21\n\
             echo network-containment-ok",
        ],
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "network namespace has more than loopback: {}",
        outcome.message
    );
    // Adversarial egress attempt against a REAL host listener must fail.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let bash = ["/usr/bin/bash", "/bin/bash"]
        .into_iter()
        .find(|path| Path::new(path).is_file());
    if let Some(bash) = bash {
        let outcome = probe(
            &mut state,
            &[
                bash,
                "-c",
                &format!("exec 3<>/dev/tcp/127.0.0.1/{port} && echo egress-escaped"),
            ],
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "workload reached a host loopback listener from inside the network namespace: {}",
            outcome.message
        );
        assert!(!outcome.message.contains("egress-escaped"));
    } else {
        eprintln!("adversarial suite: bash unavailable; /dev/tcp egress attempt skipped (interface-list assertion still enforced)");
    }
    drop(listener);

    // ================= 3. PROCESS containment =================
    let mut host_marker = std::process::Command::new("sleep")
        .arg("300")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let host_pid = host_marker.id();
    let outcome = probe(
        &mut state,
        &[
            "sh",
            "-c",
            &format!(
                "[ ! -d /proc/{host_pid} ] || exit 30\n\
                 count=$(ls /proc | grep -c \"^[0-9]\")\n\
                 [ \"$count\" -le 5 ] || exit 31\n\
                 echo process-containment-ok:$count"
            ),
        ],
    );
    let _ = host_marker.kill();
    let _ = host_marker.wait();
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "host process table leaked into the pid namespace: {}",
        outcome.message
    );
    assert!(outcome.message.contains("process-containment-ok"));

    // ================= 4. NAMESPACE containment =================
    let outcome = probe(
        &mut state,
        &[
            "sh",
            "-c",
            "readlink /proc/self/ns/user; readlink /proc/self/ns/net; \
             readlink /proc/self/ns/pid; readlink /proc/self/ns/mnt",
        ],
    );
    assert_eq!(outcome.exit_code, Some(0), "{}", outcome.message);
    let inside: Vec<&str> = outcome.message.lines().collect();
    assert_eq!(inside.len(), 4, "{}", outcome.message);
    for (index, name) in ["user", "net", "pid", "mnt"].iter().enumerate() {
        let host = std::fs::read_link(format!("/proc/self/ns/{name}"))
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_ne!(
            inside[index], host,
            "{name} namespace was not unshared from the host"
        );
    }

    // ================= 5. RESOURCE containment =================
    // rlimits derived from the governed policy are applied inside.
    let outcome = probe(&mut state, &["sh", "-c", "ulimit -v; ulimit -t"]);
    assert_eq!(outcome.exit_code, Some(0), "{}", outcome.message);
    let limits: Vec<&str> = outcome.message.lines().map(str::trim).collect();
    // Default managed policy: 512 MiB address-space budget -> 524288 KiB, and
    // the 1500 ms wall clock rounds up to a 2 s cpu rlimit.
    assert_eq!(limits, vec!["524288", "2"], "{}", outcome.message);
    // A runaway workload is killed by the wall-clock budget, not left running.
    let started = std::time::Instant::now();
    let outcome = probe(&mut state, &["sleep", "30"]);
    let elapsed = started.elapsed();
    assert_eq!(
        outcome.exit_code, None,
        "runaway workload was not killed: {}",
        outcome.message
    );
    assert!(outcome.message.contains("wall-clock resource limit"));
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "wall-clock enforcement took {elapsed:?}"
    );

    // ================= 6. SECRET containment =================
    let outcome = probe(&mut state, &["sh", "-c", "env | sort"]);
    assert_eq!(outcome.exit_code, Some(0), "{}", outcome.message);
    let allowed_keys = [
        "FERROGATE_CAPABILITY_ENVELOPE_ID",
        "FERROGATE_HOST_WORKSPACE",
        "FERROGATE_WORKSPACE",
        "HOME",
        "OLDPWD",
        "PATH",
        "PWD",
        "SHLVL",
        "TMPDIR",
        "_",
    ];
    assert!(
        !outcome.message.contains("FERROGATE_TEST_HOST_SECRET")
            && !outcome.message.contains("supersecret-host-credential"),
        "host secret leaked into the workload environment: {}",
        outcome.message
    );
    for line in outcome.message.lines().filter(|line| !line.is_empty()) {
        let key = line.split('=').next().unwrap_or_default();
        assert!(
            allowed_keys.contains(&key),
            "unexpected environment variable {key} inside workload: {}",
            outcome.message
        );
    }
    assert!(outcome.message.contains("HOME=/mnt"));

    // ---- Remaining governed lifecycle: snapshot, artifacts, status, stop, cleanup ----
    let snapshot = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        adversarial_envelope(
            AgentWorkerManagementAction::SnapshotOrCheckpoint,
            "snapshot",
        ),
        1_000,
    );
    let lifecycle = expect_lifecycle(&snapshot, "governed snapshot");
    assert_eq!(lifecycle.outcome, "checkpointed");
    let checkpoint_path = lifecycle
        .message
        .rsplit("checkpoint_id=")
        .next()
        .unwrap()
        .trim()
        .to_string();
    assert!(
        Path::new(&checkpoint_path)
            .join("adversarial-artifact.txt")
            .is_file(),
        "checkpoint did not capture the workspace artifact: {checkpoint_path}"
    );

    let artifacts = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        adversarial_envelope(AgentWorkerManagementAction::CollectArtifacts, "artifacts"),
        1_000,
    );
    assert!(artifacts.accepted);
    let Some(AgentWorkerManagementResult::HandlerArtifacts {
        artifacts: collected,
        ..
    }) = &artifacts.result
    else {
        panic!("expected artifacts result, got {:?}", artifacts.result);
    };
    assert!(
        collected
            .iter()
            .any(|artifact| artifact.name == "/mnt/adversarial-artifact.txt"),
        "{collected:?}"
    );

    let status = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        adversarial_envelope(AgentWorkerManagementAction::StreamStatus, "status"),
        1_000,
    );
    let lifecycle = expect_lifecycle(&status, "governed status");
    assert_eq!(lifecycle.outcome, "running");
    assert_eq!(lifecycle.backend_name, "local-process");

    let stop = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        adversarial_envelope(AgentWorkerManagementAction::Stop, "stop"),
        1_000,
    );
    let lifecycle = expect_lifecycle(&stop, "governed stop");
    assert_eq!(lifecycle.outcome, "stopped");
    assert_eq!(lifecycle.status, ManagedWorkerSessionStatus::Cancelled);

    let cleanup = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        adversarial_envelope(AgentWorkerManagementAction::Cleanup, "cleanup"),
        1_000,
    );
    let lifecycle = expect_lifecycle(&cleanup, "governed cleanup");
    assert_eq!(lifecycle.outcome, "cleaned_up");
    assert_eq!(lifecycle.status, ManagedWorkerSessionStatus::CleanedUp);
    assert!(
        !workspace.exists(),
        "cleanup leaked the workspace on the host: {}",
        workspace.display()
    );
    assert!(!Path::new(&checkpoint_path).exists());

    // Run report: the containment matrix outcome for this host.
    eprintln!(
        "containment-matrix: filesystem=PASS-enforced network=PASS-enforced \
         process=PASS-enforced namespace=PASS-enforced resource=PASS-enforced \
         secret=PASS-enforced; degraded(prod-gated)=rootfs_ro_remount,cgroup_pids_io; \
         backend=local-process instance={instance_id} env_fingerprint=sha256:{env_fingerprint}"
    );
}

fn provision_message_contains_fingerprint(
    provision: &AgentWorkerManagementResponse,
    fingerprint: &str,
) -> bool {
    matches!(
        &provision.result,
        Some(AgentWorkerManagementResult::Lifecycle { lifecycle })
            if lifecycle.message.contains(&format!("env_fingerprint=sha256:{fingerprint}"))
    )
}

fn assert_governed_provision_fails_closed(request: &str) {
    let mut transport = suite_transport();
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();
    let response = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        adversarial_envelope(
            AgentWorkerManagementAction::Provision,
            &format!("fail-closed-{request}"),
        ),
        1_000,
    );
    assert!(!response.accepted, "{response:?}");
    let error = response.error.as_ref().expect("rejection must carry error");
    assert_eq!(
        error.code,
        AgentWorkerManagementErrorCode::IncompatibleBackend
    );
    assert!(!error.retryable);
    // No lifecycle result: provisioning never ran, so no unisolated host work
    // was ever attempted.
    assert!(response.result.is_none());
    assert!(state
        .get_local_process_backend_mut(&format!("{PREFIX}-session"), &format!("{PREFIX}-run"))
        .is_none());
}

#[test]
fn local_process_provision_fails_closed_through_governed_path_when_stack_unavailable() {
    // Companion negative to the containment suite: local-process ENABLED but
    // the namespace stack is unavailable (unshare missing). The signed
    // Provision must be rejected non-retryably before any host work runs —
    // never silently executed unconfined.
    let _env_lock = lock_firecracker_env();
    let _guard = SuiteEnvGuard::engage();
    std::env::set_var(
        "AGENT_WORKER_LOCAL_PROCESS_UNSHARE_BIN",
        "/nonexistent/ferrogate-unshare",
    );

    assert!(crate::local_process_backend::local_process_backend_readiness().is_err());
    assert_governed_provision_fails_closed("missing-unshare");
}
