// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Cloudflare Containers / Sandbox isolation backend for agent-worker (issue #415).
//   Implements the runtime IsolationBackendLifecycle contract by driving the fronting
//   agent-gateway Worker's /container/* routes through the ferrogate-runtime
//   ContainerControlClient — the "just another sandbox", per-tenant isolated tier.

//! Cloudflare Containers / Sandbox isolation backend (issue #415).
//!
//! A fourth implementation of the runtime [`IsolationBackendLifecycle`] contract
//! next to Firecracker, Docker, and local-process — but the FIRST whose host
//! lifecycle is **not owned by this `agent-worker` host**. Cloudflare exposes no
//! public container lifecycle REST API, so every operation is driven REMOTELY
//! through the fronting agent-gateway Worker's authenticated `/container/*`
//! routes (the #413 tethered pattern), via the ferrogate-runtime
//! [`ContainerControlClient`]. That is why the descriptor reports
//! `gateway_controls_backend = true` and a remote `host_lifecycle_owner`, and
//! why the registry marks it [`GatewayDriven`](crate::backends) rather than
//! host-implemented: the on-host provisioning path never runs it, but the
//! gateway/control plane can select it through the runtime contract.
//!
//! Fail-closed by construction:
//!
//! * **Egress** is governed by construction (#471): the start spec's
//!   [`ContainerEgressPosture`] has no inhabitant that grants direct public
//!   egress, so the tier cannot be started open. It defaults to *sealed*; an
//!   operator tethers it to one validated gateway host through
//!   `AGENT_WORKER_CF_CONTAINER_EGRESS_GATEWAY_HOST`. The Worker must attest the
//!   posture it applied or the start fails closed.
//! * **Snapshot/checkpoint** has no Cloudflare primitive, so
//!   [`cloudflare_container_capabilities`] advertises it `false` and
//!   [`snapshot_or_checkpoint`](CloudflareContainerIsolationBackend::snapshot_or_checkpoint)
//!   returns an honest [`IsolationError::Backend`] — selection can never route
//!   that op here.
//!
//! Implemented lifecycle ops: prepare, start, exec_or_attach, stop,
//! collect_logs, collect_artifacts, cleanup. Not implemented:
//! snapshot_or_checkpoint (no CF primitive; advertised off) and secret
//! injection (left to the gateway-mediated capability path).
//!
//! The REMOTE-provisioning dispatch that constructs this backend from a
//! production [`ferrogate_runtime::BlockingHttpControlTransport`] and drives it
//! from the management lifecycle lands in issue #442: an operator pins the
//! Cloudflare container tier explicitly and the provision path mirrors
//! `provision_docker` in `lifecycle.rs` (through the split
//! `cloudflare_container_lifecycle.rs` module), with per-session storage in
//! `state.rs`. Because that dispatch has to hold backends built from different
//! transports (the production block-on bridge, or a mock in offline tests)
//! behind one in-memory map, it stores them through the object-safe
//! [`ManagedContainerBackend`] handle below.

use std::env;

use ferrogate_runtime::{
    cloudflare_container_descriptor, AgentInstanceIdentity, CollectedIsolationArtifacts,
    CollectedIsolationLogs, ContainerControlClient, ContainerControlError, ContainerEgressPosture,
    ContainerExecSpec, ContainerInstanceTier, ContainerPrepareSpec, ContainerSignal,
    ContainerStartSpec, GatewayControlTransport, IsolationArtifact, IsolationBackendDescriptor,
    IsolationCleanupOutcome, IsolationError, IsolationExecOutcome, IsolationExecRequest,
    IsolationLifecycleEvidence, IsolationPolicy, IsolationPrepareRequest, IsolationPrepared,
    IsolationResult, IsolationStarted, IsolationStopOutcome,
};

const DEFAULT_WORKER_IMAGE: &str = "ferrogate/agent-sandbox:latest";
/// Operator-pinned governed gateway host the container is tethered to (issue
/// #471). Unset ⇒ the container starts SEALED (no egress at all), never open.
const CF_CONTAINER_EGRESS_GATEWAY_HOST_VAR: &str = "AGENT_WORKER_CF_CONTAINER_EGRESS_GATEWAY_HOST";
const DEFAULT_TIER: ContainerInstanceTier = ContainerInstanceTier::Standard1;

/// Whether an operator has explicitly enabled the Cloudflare container tier.
/// Like the Docker tier, this is opt-in: absent the flag the backend is
/// registered (so the gateway sees the replaceable contract) but never ready.
pub(crate) fn cloudflare_container_backend_enabled() -> bool {
    env::var("AGENT_WORKER_ENABLE_CF_CONTAINER_BACKEND")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Resolved configuration for driving the fronting Worker's container routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloudflareContainerConfig {
    pub(crate) gateway_url: String,
    pub(crate) control_token: String,
    pub(crate) image: String,
    pub(crate) tier: ContainerInstanceTier,
}

/// Read the container backend configuration from the environment. Requires the
/// fronting-Worker base URL and the DIY control token; image/tier fall back to
/// defaults. Never makes a network call — readiness here means "configured",
/// exactly like the Docker/Firecracker preflights.
pub(crate) fn cloudflare_container_backend_config() -> Result<CloudflareContainerConfig, String> {
    let gateway_url = required_env(
        "AGENT_WORKER_CF_CONTAINER_GATEWAY_URL",
        "Cloudflare agent-gateway base URL",
    )?;
    let control_token = required_env(
        "AGENT_WORKER_CF_CONTAINER_CONTROL_TOKEN",
        "Cloudflare agent-gateway control token",
    )?;
    let image = env::var("AGENT_WORKER_CF_CONTAINER_IMAGE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WORKER_IMAGE.to_string());
    let tier = match env::var("AGENT_WORKER_CF_CONTAINER_TIER") {
        Ok(value) if !value.trim().is_empty() => ContainerInstanceTier::from_wire(&value)
            .ok_or_else(|| format!("AGENT_WORKER_CF_CONTAINER_TIER {value:?} is not a valid tier (lite..standard-4)"))?,
        _ => DEFAULT_TIER,
    };
    Ok(CloudflareContainerConfig {
        gateway_url,
        control_token,
        image,
        tier,
    })
}

fn required_env(var: &str, label: &str) -> Result<String, String> {
    match env::var(var) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => Err(format!("{label} was not configured (set {var})")),
    }
}

/// Probe readiness: the backend is ready when the fronting-Worker URL + control
/// token are configured. Returns the version marker used in the descriptor.
pub(crate) fn cloudflare_container_backend_readiness() -> Result<(String, String), String> {
    let config = cloudflare_container_backend_config()?;
    Ok((
        "gateway-driven".to_string(),
        format!(
            "Cloudflare container backend configured against {} (tier {})",
            config.gateway_url,
            config.tier.as_wire()
        ),
    ))
}

/// A Cloudflare container/sandbox isolation backend. Each instance drives one
/// per-tenant container lifecycle through the fronting Worker's `/container/*`
/// routes via [`ContainerControlClient`].
pub(crate) struct CloudflareContainerIsolationBackend<T: GatewayControlTransport> {
    descriptor: IsolationBackendDescriptor,
    agent_worker_id: String,
    tenant_id: String,
    client: ContainerControlClient<T>,
    image: String,
    tier: ContainerInstanceTier,
    policy: Option<IsolationPolicy>,
    capability_envelope_id: Option<String>,
    identity: Option<AgentInstanceIdentity>,
    instance_id: Option<String>,
}

impl<T: GatewayControlTransport> CloudflareContainerIsolationBackend<T> {
    /// Build a backend for `tenant_id`, driving the fronting Worker through
    /// `client`, launching `image` at `tier`.
    pub(crate) fn new(
        tenant_id: &str,
        agent_worker_id: &str,
        version: &str,
        client: ContainerControlClient<T>,
        image: &str,
        tier: ContainerInstanceTier,
    ) -> Self {
        Self {
            descriptor: cloudflare_container_descriptor(version),
            agent_worker_id: agent_worker_id.to_string(),
            tenant_id: tenant_id.to_string(),
            client,
            image: image.to_string(),
            tier,
            policy: None,
            capability_envelope_id: None,
            identity: None,
            instance_id: None,
        }
    }

    /// The descriptor this backend was constructed from, for evidence/identity.
    /// The remote-provisioning dispatch reads the descriptor through the runtime
    /// [`ferrogate_runtime::IsolationBackendLifecycle::descriptor`] contract on
    /// the [`ManagedContainerBackend`] handle, so this inherent accessor is only
    /// used by the backend's own tests.
    #[cfg(test)]
    pub(crate) fn backend_descriptor(&self) -> &IsolationBackendDescriptor {
        &self.descriptor
    }

    /// The isolation instance id assigned at `start`, if the instance is up.
    pub(crate) fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }

    /// Borrow the underlying container client (tests inspect the transport
    /// through this to assert which fronting-Worker routes were called).
    #[cfg(test)]
    pub(crate) fn client(&self) -> &ContainerControlClient<T> {
        &self.client
    }

    fn policy(&self) -> IsolationResult<&IsolationPolicy> {
        self.policy.as_ref().ok_or_else(|| {
            IsolationError::Backend("cloudflare container backend was not prepared".to_string())
        })
    }

    fn identity(&self) -> IsolationResult<&AgentInstanceIdentity> {
        self.identity.as_ref().ok_or_else(|| {
            IsolationError::Backend("cloudflare container backend was not prepared".to_string())
        })
    }

    fn map_client_error(operation: &str, error: ContainerControlError) -> IsolationError {
        IsolationError::Backend(format!("cloudflare container {operation} failed: {error}"))
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

    /// Governed start spec, derived from the session's isolation network policy
    /// (issue #471).
    ///
    /// The posture is a [`ContainerEgressPosture`], which has **no inhabitant
    /// that grants direct public egress** — so this cannot produce an open
    /// container even if the policy were tampered with; a policy carrying
    /// `direct_public_egress = true` (or `governed_egress = false`) fails the
    /// start outright rather than downgrading silently.
    ///
    /// Default posture is **sealed**. When the operator pins the governed
    /// gateway host via `AGENT_WORKER_CF_CONTAINER_EGRESS_GATEWAY_HOST`, the
    /// container is tethered to exactly that host — the agent's LLM base URL
    /// points there and nothing else is reachable. That host is validated: a
    /// wildcard or a provider endpoint is rejected.
    fn start_spec(&self) -> IsolationResult<ContainerStartSpec> {
        let policy = self.policy()?;
        let gateway_host = env::var(CF_CONTAINER_EGRESS_GATEWAY_HOST_VAR).ok();
        let egress = ContainerEgressPosture::from_network_policy(
            &policy.network_policy,
            gateway_host.as_deref(),
        )
        .map_err(|e| {
            IsolationError::Backend(format!("cloudflare container egress posture rejected: {e}"))
        })?;
        Ok(ContainerStartSpec {
            egress,
            ..ContainerStartSpec::default()
        })
    }
}

impl<T: GatewayControlTransport> ferrogate_runtime::IsolationBackendLifecycle
    for CloudflareContainerIsolationBackend<T>
{
    fn descriptor(&self) -> &IsolationBackendDescriptor {
        &self.descriptor
    }

    fn prepare(&mut self, request: IsolationPrepareRequest) -> IsolationResult<IsolationPrepared> {
        request.policy.validate()?;
        let identity =
            AgentInstanceIdentity::new(&self.tenant_id, &request.session_id, &request.run_id);
        // Fail fast on an unusable instance identity, before any remote call.
        identity
            .instance_name()
            .map_err(|e| IsolationError::Backend(format!("invalid instance identity: {e}")))?;
        let spec = ContainerPrepareSpec::new(&self.image, self.tier);
        self.capability_envelope_id = Some(request.capability_envelope_id.clone());
        self.policy = Some(request.policy);
        let prepared = self
            .client
            .prepare(&identity, &spec)
            .map_err(|e| Self::map_client_error("prepare", e))?;
        self.identity = Some(identity);
        Ok(IsolationPrepared {
            prepared_id: prepared.prepared_id,
            evidence: self.evidence(None, "prepared")?,
        })
    }

    fn start(&mut self, prepared: IsolationPrepared) -> IsolationResult<IsolationStarted> {
        let identity = self.identity()?.clone();
        let spec = self.start_spec()?;
        let started = self
            .client
            .start(&identity, &spec)
            .map_err(|e| Self::map_client_error("start", e))?;
        let _ = prepared;
        self.instance_id = Some(started.instance_id.clone());
        let evidence = self.evidence(Some(&started.instance_id), "started")?;
        Ok(IsolationStarted {
            instance_id: started.instance_id,
            evidence,
        })
    }

    fn exec_or_attach(
        &mut self,
        request: IsolationExecRequest,
    ) -> IsolationResult<IsolationExecOutcome> {
        let identity = self.identity()?.clone();
        if request.args.is_empty() {
            return Err(IsolationError::Backend(
                "cloudflare container exec_or_attach requires a non-empty command".to_string(),
            ));
        }
        let spec = ContainerExecSpec::command(request.args.clone());
        let output = self
            .client
            .exec(&identity, &spec)
            .map_err(|e| Self::map_client_error("exec_or_attach", e))?;
        let message = if output.stderr.is_empty() {
            output.stdout.clone()
        } else {
            format!("{}{}", output.stdout, output.stderr)
        };
        let evidence = self.evidence(Some(&request.instance_id), "executed")?;
        Ok(IsolationExecOutcome {
            instance_id: request.instance_id,
            exit_code: output.exit_code,
            message,
            evidence,
        })
    }

    fn stop(&mut self, instance_id: &str, reason: &str) -> IsolationResult<IsolationStopOutcome> {
        let identity = self.identity()?.clone();
        self.client
            .stop(&identity, ContainerSignal::Term)
            .map_err(|e| Self::map_client_error("stop", e))?;
        let evidence = self.evidence(Some(instance_id), &format!("stopped:{reason}"))?;
        Ok(IsolationStopOutcome {
            instance_id: instance_id.to_string(),
            evidence,
        })
    }

    fn snapshot_or_checkpoint(
        &mut self,
        _instance_id: &str,
    ) -> IsolationResult<ferrogate_runtime::IsolationSnapshotOutcome> {
        // No Cloudflare container checkpoint primitive exists. The descriptor
        // advertises snapshot_or_checkpoint = false, so `select_isolation_backend`
        // never routes this op here; if reached directly it fails honestly
        // rather than fabricating a checkpoint.
        Err(IsolationError::Backend(
            "cloudflare container backend does not implement snapshot/checkpoint; \
             Cloudflare exposes no container checkpoint primitive"
                .to_string(),
        ))
    }

    fn collect_logs(&mut self, instance_id: &str) -> IsolationResult<CollectedIsolationLogs> {
        let identity = self.identity()?.clone();
        let logs = self
            .client
            .collect_logs(&identity, None)
            .map_err(|e| Self::map_client_error("collect_logs", e))?;
        let evidence = self.evidence(Some(instance_id), "logs_collected")?;
        Ok(CollectedIsolationLogs {
            instance_id: instance_id.to_string(),
            lines: logs.lines,
            evidence,
        })
    }

    fn collect_artifacts(
        &mut self,
        instance_id: &str,
    ) -> IsolationResult<CollectedIsolationArtifacts> {
        let identity = self.identity()?.clone();
        let collected = self
            .client
            .collect_artifacts(&identity, None)
            .map_err(|e| Self::map_client_error("collect_artifacts", e))?;
        let artifacts = collected
            .artifacts
            .into_iter()
            .map(|entry| IsolationArtifact {
                id: format!("artifact-{instance_id}-{}", entry.path),
                path: entry.path,
                content_type: entry.content_type,
            })
            .collect();
        let evidence = self.evidence(Some(instance_id), "artifacts_collected")?;
        Ok(CollectedIsolationArtifacts {
            instance_id: instance_id.to_string(),
            artifacts,
            evidence,
        })
    }

    fn cleanup(&mut self, instance_id: &str) -> IsolationResult<IsolationCleanupOutcome> {
        let identity = self.identity()?.clone();
        self.client
            .cleanup(&identity)
            .map_err(|e| Self::map_client_error("cleanup", e))?;
        self.instance_id = None;
        let evidence = self.evidence(Some(instance_id), "cleaned_up")?;
        Ok(IsolationCleanupOutcome {
            instance_id: instance_id.to_string(),
            evidence,
        })
    }
}

/// Object-safe handle for a provisioned Cloudflare container backend kept in the
/// agent-worker session state (issue #442).
///
/// The remote-provisioning dispatch stores the backend behind this trait so the
/// in-memory state can keep a single concrete map regardless of the
/// [`GatewayControlTransport`] `T` the backend was built from — the production
/// block-on HTTP bridge, or a scripted mock in offline unit tests. It extends
/// the runtime [`ferrogate_runtime::IsolationBackendLifecycle`] contract with
/// the instance id assigned at `start`, so the exec/stop/logs/artifacts/cleanup
/// dispatch threads the same evidence id the Docker and local-process tiers do.
/// `Send` is required because the state store is shared across the worker's
/// serving threads behind an `Arc<Mutex<…>>`.
pub(crate) trait ManagedContainerBackend:
    ferrogate_runtime::IsolationBackendLifecycle + Send
{
    /// The isolation instance id assigned at `start`, if the instance is up.
    fn stored_instance_id(&self) -> Option<&str>;
}

impl<T: GatewayControlTransport + 'static> ManagedContainerBackend
    for CloudflareContainerIsolationBackend<T>
{
    fn stored_instance_id(&self) -> Option<&str> {
        self.instance_id()
    }
}

#[cfg(test)]
#[path = "cloudflare_container_backend_test.rs"]
mod tests;
