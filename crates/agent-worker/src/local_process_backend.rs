// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Local-process (Linux namespace) isolation backend.
//!
//! This is the third real implementation of the runtime
//! [`IsolationBackendLifecycle`] contract, next to Firecracker and Docker. It
//! exists for daemon-less, unprivileged environments (sandboxes / plain CI
//! runners) where neither a hypervisor nor a container daemon is available,
//! and it is the sanctioned in-sandbox substitute for the production
//! gVisor/Firecracker adversarial containment proof (#205).
//!
//! Enforced controls (all applied unprivileged, per-exec, via `unshare`):
//! - **namespace**: new user, mount, pid (+`--mount-proc`), and network
//!   namespaces for every workload (`unshare -U -r -m -n -p -f`).
//! - **network**: the network namespace has only a loopback device and no
//!   routes, so there is no direct public egress; gateway-mediated egress is
//!   the only sanctioned path (same posture as `docker --network none`).
//! - **filesystem**: the workload runs inside a private mount namespace with
//!   the prepared workspace bind-mounted at `/mnt`, a read-only tmpfs shroud
//!   over `/home`, and a fresh private tmpfs over `/tmp`. Everything else on
//!   the host rootfs is protected by DAC (the workload's uid maps to the
//!   unprivileged worker uid). A full read-only rootfs remount is NOT possible
//!   unprivileged and is loudly reported as a degraded, production-gated
//!   control.
//! - **resource**: RLIMIT_AS (`ulimit -v`) from the policy memory budget,
//!   RLIMIT_CPU (`ulimit -t`) and a wall-clock kill derived from the policy
//!   max runtime. cgroup pids/IO limits are production-gated and loudly
//!   reported as degraded.
//! - **secret**: the workload environment is fully cleared and replaced by a
//!   small, fixed, fingerprinted set of FERROGATE_* variables; the SHA-256
//!   fingerprint of the injected environment is recorded as evidence.
//!
//! Every mount/limit step in the confinement script runs under `set -e`
//! before the workload is exec'd, so if any containment step fails the
//! workload never runs unconfined — the exec fails closed instead.

use std::{
    env,
    fs::{self},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use ferrogate_runtime::{
    CollectedIsolationArtifacts, CollectedIsolationLogs, IsolationArtifact,
    IsolationBackendCapabilities, IsolationBackendDescriptor, IsolationBackendKind,
    IsolationBackendLifecycle, IsolationCleanupOutcome, IsolationError, IsolationExecOutcome,
    IsolationExecRequest, IsolationLifecycleEvidence, IsolationPolicy, IsolationPrepareRequest,
    IsolationPrepared, IsolationResult, IsolationSnapshotOutcome, IsolationStarted,
    IsolationStopOutcome,
};
use sha2::{Digest, Sha256};

/// Controls the local backend can NOT enforce unprivileged. They are reported
/// in every piece of lifecycle evidence so a degraded control is loud, never
/// silent, and the production promotion criteria stay visible.
pub(crate) const DEGRADED_CONTROLS: &str =
    "degraded_controls=[rootfs_not_remounted_read_only(prod-gated:gvisor/firecracker),\
     no_cgroup_pids_or_io_limit(prod-gated:cgroup-v2-runner)]";

/// In-namespace mountpoint of the prepared workspace.
pub(crate) const WORKSPACE_MOUNTPOINT: &str = "/mnt";

static INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Whether an operator has explicitly enabled the local-process tier. Like
/// Docker, this backend is weaker isolation than Firecracker and must never be
/// selected by accident: absent the flag it is registered but not selectable,
/// keeping backend selection fail-closed.
pub(crate) fn local_process_backend_enabled() -> bool {
    env::var("AGENT_WORKER_ENABLE_LOCAL_PROCESS_BACKEND")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn unshare_bin() -> String {
    env::var("AGENT_WORKER_LOCAL_PROCESS_UNSHARE_BIN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/unshare".to_string())
}

fn sh_bin() -> String {
    env::var("AGENT_WORKER_LOCAL_PROCESS_SH_BIN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/bin/sh".to_string())
}

/// Optional worker-level override of the per-exec wall-clock kill budget.
fn max_runtime_override_millis() -> Option<u64> {
    env::var("AGENT_WORKER_LOCAL_PROCESS_MAX_RUNTIME_MILLIS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
}

/// What the host actually proved it can isolate, probed with real `unshare`
/// invocations. Every probe must pass or the backend is not ready — a partial
/// namespace stack is a fail-closed condition, never a silent downgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalProcessReadiness {
    pub(crate) unshare_bin: String,
    pub(crate) sh_bin: String,
    /// `unshare --version` output; recorded as the backend version evidence.
    pub(crate) version: String,
    /// Namespaces the probes proved usable, in evidence order.
    pub(crate) namespaces: Vec<&'static str>,
}

/// Probe whether the host permits the full unprivileged namespace stack this
/// backend requires. Used by the backend registry (readiness) and re-checked
/// at `start` so a workload can never be launched on a host that lost the
/// capability after registration.
pub(crate) fn local_process_backend_readiness() -> Result<LocalProcessReadiness, String> {
    let unshare = unshare_bin();
    let sh = sh_bin();
    if !Path::new(&unshare).is_file() {
        return Err(format!(
            "unshare binary {unshare} is not available; local-process backend fails closed"
        ));
    }
    if !Path::new(&sh).is_file() {
        return Err(format!(
            "sh binary {sh} is not available; local-process backend fails closed"
        ));
    }
    let version_output = Command::new(&unshare)
        .arg("--version")
        .output()
        .map_err(|error| format!("{unshare} --version could not be executed: {error}"))?;
    if !version_output.status.success() {
        return Err(format!(
            "{unshare} --version failed: {}",
            String::from_utf8_lossy(&version_output.stderr).trim()
        ));
    }
    let version = String::from_utf8_lossy(&version_output.stdout)
        .trim()
        .to_string();
    if version.is_empty() {
        return Err(format!("{unshare} did not report a version"));
    }

    // Each probe exercises the exact flag set the workload path uses. All must
    // pass; a host that cannot provide one of the namespaces is not ready.
    let probes: [(&'static str, Vec<&str>); 4] = [
        ("user", vec!["-U", "-r", "true"]),
        ("net", vec!["-U", "-r", "-n", "true"]),
        (
            "pid",
            vec![
                "-U",
                "-r",
                "-p",
                "-f",
                "--mount-proc",
                "--kill-child",
                "true",
            ],
        ),
        (
            "mount",
            vec![
                "-U",
                "-r",
                "-m",
                &sh,
                "-c",
                "mount -t tmpfs -o ro,nosuid,nodev ferrogate-shroud /home",
            ],
        ),
    ];
    let mut namespaces = Vec::new();
    for (name, args) in probes {
        let output = Command::new(&unshare)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| {
                format!("unprivileged {name} namespace probe could not be executed: {error}")
            })?;
        if !output.status.success() {
            return Err(format!(
                "unprivileged {name} namespace is not available on this host ({}); \
                 local-process backend fails closed",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        namespaces.push(name);
    }
    namespaces.push("proc(remounted)");
    Ok(LocalProcessReadiness {
        unshare_bin: unshare,
        sh_bin: sh,
        version,
        namespaces,
    })
}

/// Capabilities the local-process backend actually implements. Snapshot is a
/// workspace filesystem copy, not a live memory checkpoint; secret injection
/// stays with the gateway-mediated path, so it is off.
pub(crate) fn local_process_backend_capabilities() -> IsolationBackendCapabilities {
    IsolationBackendCapabilities {
        prepare: true,
        start: true,
        exec_or_attach: true,
        stop: true,
        snapshot_or_checkpoint: true,
        collect_logs: true,
        collect_artifacts: true,
        cleanup: true,
        governed_egress: true,
        secret_injection: false,
    }
}

pub(crate) fn local_process_backend_descriptor(version: &str) -> IsolationBackendDescriptor {
    IsolationBackendDescriptor {
        backend_name: "local-process".to_string(),
        backend_version: version.to_string(),
        kind: IsolationBackendKind::LocalProcess,
        host_lifecycle_owner: "agent-worker".to_string(),
        gateway_controls_backend: false,
        capabilities: local_process_backend_capabilities(),
    }
}

/// A worker-owned namespaced local-process isolation backend. One instance per
/// managed session/run; every exec launches the workload inside a fresh full
/// namespace stack rooted at the prepared workspace.
#[derive(Debug)]
pub(crate) struct LocalProcessIsolationBackend {
    descriptor: IsolationBackendDescriptor,
    agent_worker_id: String,
    unshare_bin: String,
    sh_bin: String,
    policy: Option<IsolationPolicy>,
    capability_envelope_id: Option<String>,
    workspace_dir: Option<PathBuf>,
    instance_id: Option<String>,
    running: bool,
    env_fingerprint: Option<String>,
    log_lines: Vec<String>,
    checkpoint_dirs: Vec<PathBuf>,
}

impl LocalProcessIsolationBackend {
    pub(crate) fn new(agent_worker_id: &str, readiness: &LocalProcessReadiness) -> Self {
        Self {
            descriptor: local_process_backend_descriptor(&readiness.version),
            agent_worker_id: agent_worker_id.to_string(),
            unshare_bin: readiness.unshare_bin.clone(),
            sh_bin: readiness.sh_bin.clone(),
            policy: None,
            capability_envelope_id: None,
            workspace_dir: None,
            instance_id: None,
            running: false,
            env_fingerprint: None,
            log_lines: Vec::new(),
            checkpoint_dirs: Vec::new(),
        }
    }

    pub(crate) fn backend_descriptor(&self) -> &IsolationBackendDescriptor {
        &self.descriptor
    }

    pub(crate) fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }

    pub(crate) fn is_running(&self) -> bool {
        self.running
    }

    /// Host path of the prepared workspace (bind-mounted at `/mnt` in-ns).
    #[cfg(test)]
    pub(crate) fn workspace_dir(&self) -> Option<&Path> {
        self.workspace_dir.as_deref()
    }

    /// SHA-256 fingerprint of the exact environment injected into workloads.
    #[cfg(test)]
    pub(crate) fn env_fingerprint(&self) -> Option<&str> {
        self.env_fingerprint.as_deref()
    }

    /// One-line containment evidence for lifecycle results: backend version,
    /// namespace stack, filesystem/resource/secret posture, and the loudly
    /// reported degraded (production-gated) controls. There is no image, so
    /// image digest evidence is explicit about that instead of being omitted.
    pub(crate) fn containment_summary(&self) -> String {
        let policy = self.policy.clone().unwrap_or_default();
        format!(
            "backend_version={}; image_digest=none(host-userspace-no-image); \
             namespaces=user,mount,pid,net,proc; \
             filesystem=workspace-bind({WORKSPACE_MOUNTPOINT})+ro-tmpfs(/home)+private-tmpfs(/tmp)+host-dac; \
             network=netns-loopback-only-no-egress; \
             resource=rlimit_as:{}MiB,rlimit_cpu:{}s,wall_clock:{}ms; \
             secret=env-cleared,env_fingerprint=sha256:{}; {}",
            self.descriptor.backend_version,
            policy.resource_limits.memory_mib,
            self.cpu_seconds_limit(&policy),
            self.effective_max_runtime_millis(&policy),
            self.env_fingerprint.as_deref().unwrap_or("unfingerprinted"),
            DEGRADED_CONTROLS,
        )
    }

    fn policy(&self) -> IsolationResult<&IsolationPolicy> {
        self.policy.as_ref().ok_or_else(|| {
            IsolationError::Backend("local-process backend was not prepared".to_string())
        })
    }

    fn workspace(&self) -> IsolationResult<&Path> {
        self.workspace_dir.as_deref().ok_or_else(|| {
            IsolationError::Backend("local-process backend has no prepared workspace".to_string())
        })
    }

    fn effective_max_runtime_millis(&self, policy: &IsolationPolicy) -> u64 {
        max_runtime_override_millis()
            .or(policy.resource_limits.max_runtime_millis)
            .unwrap_or(30_000)
    }

    fn cpu_seconds_limit(&self, policy: &IsolationPolicy) -> u64 {
        self.effective_max_runtime_millis(policy)
            .div_ceil(1000)
            .max(1)
    }

    /// The full environment injected into every workload, sorted by key. This
    /// is the ONLY environment the workload sees: the parent environment is
    /// cleared, so no host secret can leak in.
    fn injected_env(&self, workspace: &Path) -> Vec<(String, String)> {
        let mut pairs = vec![
            (
                "FERROGATE_CAPABILITY_ENVELOPE_ID".to_string(),
                self.capability_envelope_id.clone().unwrap_or_default(),
            ),
            (
                "FERROGATE_HOST_WORKSPACE".to_string(),
                workspace.display().to_string(),
            ),
            (
                "FERROGATE_WORKSPACE".to_string(),
                WORKSPACE_MOUNTPOINT.to_string(),
            ),
            ("HOME".to_string(), WORKSPACE_MOUNTPOINT.to_string()),
            (
                "PATH".to_string(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            ),
            ("TMPDIR".to_string(), "/tmp".to_string()),
        ];
        pairs.sort();
        pairs
    }

    fn fingerprint_env(pairs: &[(String, String)]) -> String {
        let mut hasher = Sha256::new();
        for (key, value) in pairs {
            hasher.update(key.as_bytes());
            hasher.update(b"=");
            hasher.update(value.as_bytes());
            hasher.update(b"\n");
        }
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The confinement script that runs inside the namespace stack before the
    /// workload. `set -e` guarantees fail-closed behavior: if any mount or
    /// rlimit step fails, the workload is never exec'd unconfined.
    fn confinement_script(&self, policy: &IsolationPolicy) -> String {
        let memory_kib = u64::from(policy.resource_limits.memory_mib) * 1024;
        let cpu_seconds = self.cpu_seconds_limit(policy);
        format!(
            "set -e\n\
             mount --rbind \"$FERROGATE_HOST_WORKSPACE\" {WORKSPACE_MOUNTPOINT}\n\
             mount -t tmpfs -o ro,nosuid,nodev ferrogate-shroud /home\n\
             mount -t tmpfs -o nosuid,nodev ferrogate-tmp /tmp\n\
             cd {WORKSPACE_MOUNTPOINT}\n\
             ulimit -v {memory_kib}\n\
             ulimit -t {cpu_seconds}\n\
             exec \"$0\" \"$@\"\n"
        )
    }

    /// Run one workload fully confined. Applies the namespace stack, mount
    /// shrouds, rlimits, and the fingerprinted cleared environment; enforces
    /// the wall-clock budget by killing the whole namespace (`--kill-child`).
    fn run_confined(&mut self, workload_args: &[String]) -> IsolationResult<(Option<i32>, String)> {
        let policy = self.policy()?.clone();
        let workspace = self.workspace()?.to_path_buf();
        if workload_args.is_empty() {
            return Err(IsolationError::Backend(
                "local-process exec requires workload args".to_string(),
            ));
        }
        let script = self.confinement_script(&policy);
        let env_pairs = self.injected_env(&workspace);
        let max_runtime = Duration::from_millis(self.effective_max_runtime_millis(&policy));

        let mut command = Command::new(&self.unshare_bin);
        command
            .args([
                "-U",
                "-r",
                "-m",
                "-n",
                "-p",
                "-f",
                "--mount-proc",
                "--kill-child",
            ])
            .arg(&self.sh_bin)
            .arg("-c")
            .arg(&script)
            .args(workload_args)
            .current_dir(&workspace)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in &env_pairs {
            command.env(key, value);
        }
        let mut child = command.spawn().map_err(|error| {
            IsolationError::Backend(format!(
                "local-process workload failed to spawn via {}: {error}",
                self.unshare_bin
            ))
        })?;
        let started_at = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    let output = child.wait_with_output().map_err(|error| {
                        IsolationError::Backend(format!(
                            "local-process workload output collection failed: {error}"
                        ))
                    })?;
                    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    self.log_lines.extend(
                        stdout
                            .lines()
                            .chain(stderr.lines())
                            .filter(|line| !line.is_empty())
                            .map(ToOwned::to_owned),
                    );
                    let message = if output.status.success() || stderr.is_empty() {
                        stdout
                    } else {
                        stderr
                    };
                    return Ok((output.status.code(), message));
                }
                Ok(None) if started_at.elapsed() >= max_runtime => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let message = format!(
                        "local-process workload killed by wall-clock resource limit after \
                         max_runtime_millis={}",
                        max_runtime.as_millis()
                    );
                    self.log_lines.push(message.clone());
                    return Ok((None, message));
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(IsolationError::Backend(format!(
                        "local-process workload status check failed: {error}"
                    )));
                }
            }
        }
    }

    fn evidence(
        &self,
        instance_id: Option<&str>,
        outcome: &str,
    ) -> IsolationResult<IsolationLifecycleEvidence> {
        let policy = self.policy()?;
        Ok(IsolationLifecycleEvidence {
            backend_name: self.descriptor.backend_name.clone(),
            backend_version: self.descriptor.backend_version.clone(),
            agent_worker_id: self.agent_worker_id.clone(),
            isolation_instance_id: instance_id.map(ToOwned::to_owned),
            resource_limits: policy.resource_limits.clone(),
            network_policy: policy.network_policy.clone(),
            filesystem_policy: policy.filesystem_policy.clone(),
            capability_envelope_id: self.capability_envelope_id.clone().unwrap_or_default(),
            outcome: outcome.to_string(),
            failure_reason: None,
        })
    }
}

impl IsolationBackendLifecycle for LocalProcessIsolationBackend {
    fn descriptor(&self) -> &IsolationBackendDescriptor {
        &self.descriptor
    }

    fn prepare(&mut self, request: IsolationPrepareRequest) -> IsolationResult<IsolationPrepared> {
        request.policy.validate()?;
        let workspace = env::temp_dir().join(format!(
            "ferrogate-local-process-{}-{}-{}",
            sanitize_id(&request.session_id),
            sanitize_id(&request.run_id),
            INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&workspace).map_err(|error| {
            IsolationError::Backend(format!(
                "local-process workspace {} could not be created: {error}",
                workspace.display()
            ))
        })?;
        self.capability_envelope_id = Some(request.capability_envelope_id.clone());
        self.policy = Some(request.policy);
        let env_pairs = self.injected_env(&workspace);
        self.env_fingerprint = Some(Self::fingerprint_env(&env_pairs));
        self.workspace_dir = Some(workspace);
        Ok(IsolationPrepared {
            prepared_id: format!("local-process-prepared-{}", request.run_id),
            evidence: self.evidence(None, "prepared")?,
        })
    }

    fn start(&mut self, prepared: IsolationPrepared) -> IsolationResult<IsolationStarted> {
        // Re-probe the namespace stack at start so a host that lost the
        // capability after registration fails closed here, before any
        // workload runs.
        let readiness = local_process_backend_readiness().map_err(IsolationError::Backend)?;
        // Prove the full confinement path works with a no-op workload before
        // declaring the instance started.
        let instance_id = format!(
            "local-process-{}",
            INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let (exit_code, message) = self.run_confined(&["true".to_string()])?;
        if exit_code != Some(0) {
            return Err(IsolationError::Backend(format!(
                "local-process confinement self-check failed (exit_code={exit_code:?}): {message}; \
                 refusing to start unconfined (unshare={})",
                readiness.version
            )));
        }
        self.instance_id = Some(instance_id.clone());
        self.running = true;
        let _ = prepared;
        let evidence = self.evidence(Some(&instance_id), "started")?;
        Ok(IsolationStarted {
            instance_id,
            evidence,
        })
    }

    fn exec_or_attach(
        &mut self,
        request: IsolationExecRequest,
    ) -> IsolationResult<IsolationExecOutcome> {
        if !self.running {
            return Err(IsolationError::Backend(
                "local-process backend has no started instance".to_string(),
            ));
        }
        let (exit_code, message) = self.run_confined(&request.args)?;
        let evidence = self.evidence(Some(&request.instance_id), "executed")?;
        Ok(IsolationExecOutcome {
            instance_id: request.instance_id,
            exit_code,
            message,
            evidence,
        })
    }

    fn stop(&mut self, instance_id: &str, reason: &str) -> IsolationResult<IsolationStopOutcome> {
        self.running = false;
        let evidence = self.evidence(Some(instance_id), &format!("stopped:{reason}"))?;
        Ok(IsolationStopOutcome {
            instance_id: instance_id.to_string(),
            evidence,
        })
    }

    fn snapshot_or_checkpoint(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<IsolationSnapshotOutcome> {
        let workspace = self.workspace()?.to_path_buf();
        let checkpoint_dir = workspace.with_file_name(format!(
            "{}-checkpoint-{}",
            workspace
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("workspace"),
            INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&checkpoint_dir).map_err(|error| {
            IsolationError::Backend(format!(
                "local-process checkpoint dir {} could not be created: {error}",
                checkpoint_dir.display()
            ))
        })?;
        let entries = fs::read_dir(&workspace).map_err(|error| {
            IsolationError::Backend(format!(
                "local-process workspace {} could not be read for checkpoint: {error}",
                workspace.display()
            ))
        })?;
        for entry in entries.flatten() {
            if entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
            {
                let target = checkpoint_dir.join(entry.file_name());
                fs::copy(entry.path(), &target).map_err(|error| {
                    IsolationError::Backend(format!(
                        "local-process checkpoint copy of {} failed: {error}",
                        entry.path().display()
                    ))
                })?;
            }
        }
        let checkpoint_id = checkpoint_dir.display().to_string();
        self.checkpoint_dirs.push(checkpoint_dir);
        let evidence = self.evidence(Some(instance_id), "checkpointed")?;
        Ok(IsolationSnapshotOutcome {
            instance_id: instance_id.to_string(),
            checkpoint_id: Some(checkpoint_id),
            evidence,
        })
    }

    fn collect_logs(&mut self, instance_id: &str) -> IsolationResult<CollectedIsolationLogs> {
        let evidence = self.evidence(Some(instance_id), "logs_collected")?;
        Ok(CollectedIsolationLogs {
            instance_id: instance_id.to_string(),
            lines: self.log_lines.clone(),
            evidence,
        })
    }

    fn collect_artifacts(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<CollectedIsolationArtifacts> {
        let workspace = self.workspace()?.to_path_buf();
        let entries = fs::read_dir(&workspace).map_err(|error| {
            IsolationError::Backend(format!(
                "local-process workspace {} could not be read: {error}",
                workspace.display()
            ))
        })?;
        let mut artifacts = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            artifacts.push(IsolationArtifact {
                id: format!("artifact-{instance_id}-{name}"),
                path: format!("{WORKSPACE_MOUNTPOINT}/{name}"),
                content_type: None,
            });
        }
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        let evidence = self.evidence(Some(instance_id), "artifacts_collected")?;
        Ok(CollectedIsolationArtifacts {
            instance_id: instance_id.to_string(),
            artifacts,
            evidence,
        })
    }

    fn cleanup(&mut self, instance_id: &str) -> IsolationResult<IsolationCleanupOutcome> {
        self.running = false;
        for checkpoint in self.checkpoint_dirs.drain(..) {
            let _ = fs::remove_dir_all(&checkpoint);
        }
        if let Some(workspace) = self.workspace_dir.take() {
            fs::remove_dir_all(&workspace).map_err(|error| {
                IsolationError::Backend(format!(
                    "local-process workspace {} could not be removed: {error}",
                    workspace.display()
                ))
            })?;
        }
        self.instance_id = None;
        let evidence = self.evidence(Some(instance_id), "cleaned_up")?;
        Ok(IsolationCleanupOutcome {
            instance_id: instance_id.to_string(),
            evidence,
        })
    }
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "local_process_backend_test.rs"]
mod tests;
