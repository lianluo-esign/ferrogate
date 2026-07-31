// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Cloudflare-hosted agent runtime control client for the managed-worker scheduler.

//! Cloudflare-hosted agent runtime control client (issue #412).
//!
//! FerroGate can initiate an agent run that is **hosted and lifecycle-managed on
//! Cloudflare** rather than on a local `agent-worker` process. The managed-worker
//! scheduler ([`crate::ManagedWorkerScheduler`]) is generic over
//! [`crate::AgentWorkerControlClient`], so a new transport that talks to a
//! Cloudflare control surface plugs in unchanged: the run-lifecycle state
//! machine, the tenant/workspace concurrency limits, worker templates, and the
//! persistence types (`ferrogate_storage::StoredManagedWorkerSession` /
//! `ferrogate_storage::StoredAgentRun`, persisted by the CLI layer) all reuse.
//!
//! ## The control-surface seam
//!
//! Cloudflare's Agents SDK / Durable Objects / Containers expose **no public
//! lifecycle REST API**, so this issue does not talk to Cloudflare directly.
//! Instead it defines the [`CloudflareControlSurface`] seam — the small set of
//! CF-side operations a hosted run needs (start / exec-or-attach / stop /
//! cancel / cleanup / status) — and maps the scheduler's isolation lifecycle
//! onto it. The real implementation and its refinement are sibling sub-issues:
//!
//! - **#413** — a fronting deploy-Worker that exposes the `/control/*` routes,
//!   implemented by [`crate::WorkerGatewayControlSurface`].
//! - **#414** — refines the verb→primitive mapping onto the *actual* Cloudflare
//!   agent primitives (lazy create, props resolved at start, hibernation-as-stop,
//!   **cooperative** cancel, `this.destroy()`, custom status) and threads per-run
//!   `props` (model/tools/prompt + placement) into the run's resolved
//!   configuration. See [`CloudflareRunProps`] and the module docs of
//!   [`crate::WorkerGatewayControlSurface`].
//!
//! Both bridge onto `ferrogate_cloudflare::CloudflareClient` (issue #405). The
//! seam is intentionally **synchronous** to match [`AgentWorkerControlClient`];
//! an async CF implementation bridges to sync at its own boundary (as the CLI
//! does elsewhere with a block-on bridge). [`MockCloudflareControlSurface`]
//! provides a no-network implementation for tests.

use std::collections::HashMap;
use std::sync::Arc;
use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    AgentWorkerControlClient, AgentWorkerFrameworkHandler, IsolationBackendCapabilities,
    IsolationBackendDescriptor, IsolationBackendKind, IsolationCleanupOutcome,
    IsolationExecOutcome, IsolationExecRequest, IsolationFilesystemPolicy,
    IsolationLifecycleEvidence, IsolationNetworkPolicy, IsolationPrepareRequest,
    IsolationResourceLimits, IsolationStarted, IsolationStopOutcome, ManagedWorkerError,
    ManagedWorkerSessionStatus, ManagedWorkerStopKind,
};

/// Advertised `backend_name` for the Cloudflare-hosted runtime.
pub const CLOUDFLARE_BACKEND_NAME: &str = "cloudflare";
/// `host_lifecycle_owner` recorded for CF-hosted runs: unlike the local
/// `agent-worker`, Cloudflare owns the host, and FerroGate drives lifecycle
/// through the control surface (hence `gateway_controls_backend = true`).
pub const CLOUDFLARE_HOST_LIFECYCLE_OWNER: &str = "cloudflare";
/// Default backend version tag until the sibling sub-issues pin the deployed
/// Worker / Workflows definition version.
pub const CLOUDFLARE_BACKEND_VERSION: &str = "cloudflare-hosted-run-v1";

/// Build the [`IsolationBackendDescriptor`] advertised for the Cloudflare-hosted
/// runtime so a worker template can select it.
///
/// The descriptor's [`IsolationBackendKind`] is an **operator-supplied policy
/// key**: it names the isolation tier the operator's CF runtime provides so a
/// template's `allowed_kinds` and this descriptor agree during selection. A
/// dedicated `IsolationBackendKind::CloudflareHostedRun` variant is deliberately
/// **not** added here — that enum is matched exhaustively across downstream
/// crates, so introducing a variant is a separate, coordinated change. Operators
/// pick the kind whose isolation guarantees best match their CF runtime
/// (Cloudflare Containers are a managed-sandbox tier, so [`Gvisor`] is a sane
/// default via [`cloudflare_backend_descriptor_default`]).
///
/// [`Gvisor`]: IsolationBackendKind::Gvisor
pub fn cloudflare_backend_descriptor(
    kind: IsolationBackendKind,
    version: impl Into<String>,
) -> IsolationBackendDescriptor {
    IsolationBackendDescriptor {
        backend_name: CLOUDFLARE_BACKEND_NAME.to_string(),
        backend_version: version.into(),
        kind,
        host_lifecycle_owner: CLOUDFLARE_HOST_LIFECYCLE_OWNER.to_string(),
        gateway_controls_backend: true,
        capabilities: IsolationBackendCapabilities::full(),
    }
}

/// The default Cloudflare-hosted descriptor: a managed-sandbox (`Gvisor`) tier at
/// [`CLOUDFLARE_BACKEND_VERSION`].
pub fn cloudflare_backend_descriptor_default() -> IsolationBackendDescriptor {
    cloudflare_backend_descriptor(IsolationBackendKind::Gvisor, CLOUDFLARE_BACKEND_VERSION)
}

/// Lifecycle status of a Cloudflare-hosted run as reported by the control
/// surface. Distinct from [`ManagedWorkerSessionStatus`] because the CF side has
/// its own vocabulary (a run can be `Queued` before it is `Running`); reconcile
/// via [`CloudflareRunStatus::managed_session_status`].
///
/// The serde form is the Worker's own control-route vocabulary — the exact set
/// `cloudflare_gateway_control::parse_status` accepts — so a status recorded on
/// a durable receipt reads the same as the wire value it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareRunStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Stopped,
    CleanedUp,
}

impl CloudflareRunStatus {
    /// Reconcile the CF-side status onto the scheduler's
    /// [`ManagedWorkerSessionStatus`], which is what persistence records.
    pub fn managed_session_status(self) -> ManagedWorkerSessionStatus {
        match self {
            Self::Queued | Self::Running => ManagedWorkerSessionStatus::Running,
            Self::Completed => ManagedWorkerSessionStatus::Completed,
            Self::Failed => ManagedWorkerSessionStatus::Failed,
            Self::Stopped => ManagedWorkerSessionStatus::Cancelled,
            Self::CleanedUp => ManagedWorkerSessionStatus::CleanedUp,
        }
    }

    /// The `status` string persisted on `ferrogate_storage::StoredAgentRun`.
    pub fn agent_run_status(self) -> &'static str {
        match self {
            Self::Queued | Self::Running => "running",
            Self::Completed | Self::CleanedUp => "completed",
            Self::Failed => "failed",
            Self::Stopped => "cancelled",
        }
    }
}

/// The `status` string persisted on
/// `ferrogate_storage::StoredManagedWorkerSession`. Mirrors the snake-case
/// wire form of [`ManagedWorkerSessionStatus`].
pub fn managed_worker_session_status_wire(status: ManagedWorkerSessionStatus) -> &'static str {
    match status {
        ManagedWorkerSessionStatus::Running => "running",
        ManagedWorkerSessionStatus::Completed => "completed",
        ManagedWorkerSessionStatus::Cancelled => "cancelled",
        ManagedWorkerSessionStatus::Failed => "failed",
        ManagedWorkerSessionStatus::CleanedUp => "cleaned_up",
    }
}

/// Per-run **initialization props** delivered to the agent's `onStart(props)` on
/// the Cloudflare side.
///
/// These are the runtime-selectable dials for a single run. In the Cloudflare
/// Agents model there is **no deploy-time `model` field**: the agent chooses its
/// model/tools/system-prompt *in code* at start, reading them from the props it
/// is handed. FerroGate therefore threads the per-run selection here and the
/// gateway Worker's `onStart(props)` reads them — making the model (and tools /
/// system prompt) selectable per run without redeploying the Worker.
///
/// Props are **transient**: they are the input to a run's `onStart`, distinct
/// from the agent's **persistent state** (the DO's SQLite rows). Re-addressing a
/// hibernated agent by name does not re-deliver props; the agent reads its
/// already-resolved selections from persistent state on wake.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareRunProps {
    /// Runtime-selected model id (e.g. an Anthropic model). `None` = the agent's
    /// coded default. There is no deploy-time model field on Cloudflare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Runtime-selected tool set for this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    /// Runtime-selected system prompt for this run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Placement hint for the agent's Durable Object (`wnam`/`enam`/`weur`/…).
    ///
    /// **HONORED**: the gateway Worker passes it to
    /// `getAgentByName(ns, name, { locationHint })` on `POST /control/start`,
    /// which is where Cloudflare places the instance. It is identity-neutral
    /// (`idFromName` never sees it), so later calls resolve the same object
    /// without repeating it. An unrecognized value is **refused** (HTTP 422)
    /// rather than dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_hint: Option<String>,
    /// Data-jurisdiction constraint (`eu`/`fedramp`).
    ///
    /// **REFUSED** by the gateway Worker (HTTP 422 `jurisdiction_unsupported`),
    /// which surfaces here as [`CloudflareControlSurfaceError::StartFailed`].
    ///
    /// A jurisdiction is applied as `namespace.jurisdiction(j).idFromName(name)`
    /// — it changes the Durable Object's **identity**, not just its placement.
    /// FerroGate addresses a run by name from call sites that do not share
    /// per-run state (this scheduler client, the #428 cost governor's kill
    /// switch, the #426/#427 schedule and memory clients), so honoring it on
    /// `start` alone would leave the instance reachable from the starter and
    /// invisible to everyone else — including the over-budget kill path. It
    /// belongs on the deployment (one gateway Worker per jurisdiction). The
    /// field is kept so the refusal is explicit and testable instead of the
    /// value being silently ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    /// Dispatch routing-retry budget for reaching the agent instance.
    ///
    /// **RECORDED ONLY**: the Worker persists it and reports it back on
    /// `status`, but performs no retry of its own — retrying a control call is
    /// this side's concern (it owns the timeout, the backoff and the
    /// idempotency), and a second retry loop inside the Worker would multiply
    /// rather than bound the attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_retry: Option<u32>,
}

/// Request to start a Cloudflare-hosted run. Derived from the scheduler's
/// [`IsolationPrepareRequest`], plus the per-run [`CloudflareRunProps`] that the
/// gateway Worker delivers to the agent's `onStart(props)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRunStartRequest {
    pub session_id: String,
    pub run_id: String,
    pub worker_template_id: String,
    pub framework_adapter: String,
    pub capability_envelope_id: String,
    /// Transient per-run init props (model/tools/prompt + placement) handed to
    /// `onStart(props)`. Resolved from the run request via the client's
    /// [`CloudflareRunPropsResolver`].
    pub props: CloudflareRunProps,
}

/// A handle to a started CF-hosted run. `run_ref` is the Cloudflare-side
/// instance identifier (the agent instance **name** the fronting Worker
/// addresses by `getAgentByName`) and becomes the scheduler's `instance_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRunHandle {
    pub run_ref: String,
    pub status: CloudflareRunStatus,
}

/// Request to exec-or-attach against a started CF-hosted run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRunExecRequest {
    pub run_ref: String,
    pub workload_ref: String,
    pub args: Vec<String>,
}

/// Outcome of driving a CF-hosted run to (or toward) completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRunExecOutcome {
    pub run_ref: String,
    pub status: CloudflareRunStatus,
    pub exit_code: Option<i32>,
    pub message: String,
}

/// Failure surfaced by a [`CloudflareControlSurface`] operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareControlSurfaceError {
    /// The CF runtime is not deployed / not reachable yet (e.g. sibling
    /// sub-issue not wired).
    NotReady(String),
    StartFailed(String),
    ExecFailed(String),
    StopFailed(String),
    CleanupFailed(String),
    /// The CF side has no run bound to this `run_ref` (the gateway Worker's
    /// `not_found` refusal, HTTP 404).
    ///
    /// Distinct from every other failure because it is the one that must NOT be
    /// reported as success: addressing a Durable Object by name always yields a
    /// stub, so before this refusal existed a `cleanup_run` against a typo'd or
    /// already-destroyed `run_ref` returned `CleanedUp` and FerroGate recorded
    /// [`IsolationLifecycleEvidence`] for a run that never existed (issue #414).
    RunNotFound(String),
    /// The run exists but has been cancelled, so it accepts no further work
    /// (the gateway Worker's `run_cancelled` refusal, HTTP 409).
    ///
    /// Distinct from [`Self::ExecFailed`] because the run did not fail — it
    /// refused, and refusing is not executing. The Worker used to answer a
    /// latch-refused `invoke` with HTTP 200 and an exec success envelope whose
    /// only distinguishing mark was its free-text `message`, so
    /// [`CloudflareAgentControlClient::exec_or_attach`] recorded
    /// [`IsolationLifecycleEvidence`] with `outcome = "executed"` for an
    /// invocation that never ran (issue #414).
    RunCancelled(String),
    /// Transport/decoding failure talking to the CF control API.
    Transport(String),
}

impl fmt::Display for CloudflareControlSurfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady(m) => write!(f, "cloudflare control surface not ready: {m}"),
            Self::StartFailed(m) => write!(f, "cloudflare run start failed: {m}"),
            Self::ExecFailed(m) => write!(f, "cloudflare run exec/attach failed: {m}"),
            Self::StopFailed(m) => write!(f, "cloudflare run stop failed: {m}"),
            Self::CleanupFailed(m) => write!(f, "cloudflare run cleanup failed: {m}"),
            Self::RunNotFound(m) => write!(f, "cloudflare run not found: {m}"),
            Self::RunCancelled(m) => write!(f, "cloudflare run already cancelled: {m}"),
            Self::Transport(m) => write!(f, "cloudflare control transport failed: {m}"),
        }
    }
}

impl Error for CloudflareControlSurfaceError {}

impl From<CloudflareControlSurfaceError> for ManagedWorkerError {
    fn from(error: CloudflareControlSurfaceError) -> Self {
        ManagedWorkerError::AgentWorker(error.to_string())
    }
}

/// The Cloudflare-side control surface the [`CloudflareAgentControlClient`] maps
/// the scheduler lifecycle onto. Real implementations are sibling sub-issues
/// (#413 fronting Worker; #414 refines the verb→primitive mapping) built on
/// `ferrogate_cloudflare::CloudflareClient`. Synchronous to match
/// [`AgentWorkerControlClient`].
pub trait CloudflareControlSurface {
    /// Start a hosted run and return its CF-side handle. Maps `provision`.
    fn start_run(
        &mut self,
        request: CloudflareRunStartRequest,
    ) -> Result<CloudflareRunHandle, CloudflareControlSurfaceError>;

    /// Exec (or attach to) the hosted run and drive it. Maps `exec_or_attach`.
    fn exec_run(
        &mut self,
        request: CloudflareRunExecRequest,
    ) -> Result<CloudflareRunExecOutcome, CloudflareControlSurfaceError>;

    /// Model a terminal **stop** for the hosted run.
    ///
    /// Cloudflare has **no stop/pause primitive**: an idle agent hibernates
    /// automatically (~70–140s idle → zero compute, state retained) and is woken
    /// simply by re-addressing it by name. So a normal terminal stop is a
    /// **hibernate / no-op**: implementations should NOT invoke a "stop" control
    /// route (there is none). Real in-flight cancellation goes through
    /// [`Self::cancel_run`], not here.
    fn stop_run(
        &mut self,
        run_ref: &str,
        reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError>;

    /// Actively **cancel** in-flight work for the hosted run.
    ///
    /// **COOPERATIVE, AND BEST-EFFORT.** Cloudflare documents fibers
    /// (`startFiber().cancel` / `abortSubAgent`) as the in-run cancellation
    /// primitive, but the pinned Agents SDK (`agents@0.0.109`) ships **no fiber
    /// API at all**. The gateway Worker therefore implements cancel with the
    /// mechanism the runtime does provide: it aborts an `AbortSignal` the
    /// workload observes, and sets a durable latch that refuses any later
    /// `invoke` on the run. See `workers/agent-gateway/src/index.ts`.
    ///
    /// What that means for a caller: work that **observes** the signal stops;
    /// work that ignores it, or that runs outside the agent's Durable Object,
    /// does not. A caller for whom "stopped" must be a guarantee — notably the
    /// #428 cost governor's over-budget kill — must VERIFY with
    /// [`Self::run_status`] and escalate to [`Self::cleanup_run`], which is what
    /// [`crate::KillMode::Cancel`] does.
    ///
    /// Distinct from [`Self::stop_run`] (hibernation) and [`Self::cleanup_run`]
    /// (`this.destroy()`).
    fn cancel_run(
        &mut self,
        run_ref: &str,
        reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError>;

    /// [`Self::cancel_run`], plus whether anything was actually **signalled**.
    ///
    /// The status alone cannot answer that. The Worker deliberately reports
    /// `running` both for "never cancelled" and for "cancelled, and the workload
    /// has not unwound yet", because collapsing the two is what made
    /// [`crate::KillMode::Cancel`]'s verification vacuous. A caller that
    /// escalates on the second case therefore cannot, from the status, tell an
    /// escalation from a destroy of a run nobody tried to cancel — on the exact
    /// path whose past failures were invisible for that reason.
    ///
    /// `signalled: None` means the implementation does not report it, which is
    /// distinct from `Some(false)` ("nothing was in flight"). The default
    /// delegates to [`Self::cancel_run`] and reports `None`.
    fn cancel_run_observed(
        &mut self,
        run_ref: &str,
        reason: &str,
    ) -> Result<CloudflareCancelObservation, CloudflareControlSurfaceError> {
        Ok(CloudflareCancelObservation {
            status: self.cancel_run(run_ref, reason)?,
            signalled: None,
        })
    }

    /// Tear down the hosted run's resources (`this.destroy()`). Maps `cleanup`.
    fn cleanup_run(
        &mut self,
        run_ref: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError>;

    /// Fetch the current status of a hosted run (for out-of-band reconcile).
    fn run_status(
        &mut self,
        run_ref: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError>;

    /// [`Self::run_status`], plus the run's durable **cancel latch**.
    ///
    /// The companion to [`Self::cancel_run_observed`]: `cancel_latched` is what
    /// separates a `running` run that was cancelled and has not unwound from one
    /// nobody cancelled. `None` means the implementation does not report it. The
    /// default delegates to [`Self::run_status`] and reports `None`.
    fn run_status_observed(
        &mut self,
        run_ref: &str,
    ) -> Result<CloudflareRunObservation, CloudflareControlSurfaceError> {
        Ok(CloudflareRunObservation {
            status: self.run_status(run_ref)?,
            cancel_latched: None,
        })
    }
}

/// What a [`CloudflareControlSurface::cancel_run_observed`] call observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudflareCancelObservation {
    /// The run's status after the cancel. **Not** a claim that it stopped — see
    /// [`CloudflareControlSurface::cancel_run`].
    pub status: CloudflareRunStatus,
    /// Whether in-flight work on the instance was actually signalled.
    /// `None` when the surface does not report it.
    pub signalled: Option<bool>,
}

/// What a [`CloudflareControlSurface::run_status_observed`] call observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudflareRunObservation {
    /// The run's current status.
    pub status: CloudflareRunStatus,
    /// Whether the run's durable cancel latch is set. `None` when the surface
    /// does not report it.
    pub cancel_latched: Option<bool>,
}

/// Per-run context the client keeps so lifecycle calls that only carry the
/// `instance_id` (`stop`/`cleanup`) can still emit complete evidence and can be
/// reconciled against persisted rows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CloudflareRunContext {
    session_id: String,
    run_id: String,
    capability_envelope_id: String,
    framework_adapter: String,
    status: CloudflareRunStatus,
}

/// An [`AgentWorkerControlClient`] that hosts managed-worker runs on Cloudflare
/// via a [`CloudflareControlSurface`].
///
/// It is a drop-in transport for [`crate::ManagedWorkerScheduler`]: the scheduler
/// is generic over the control client, so wiring this in makes a hosted run go
/// through the same `start_session` -> `run_to_completion` state machine, the
/// same concurrency limits, and the same evidence/persistence path as the local
/// `agent-worker` transports.
pub struct CloudflareAgentControlClient<S: CloudflareControlSurface> {
    surface: S,
    worker_id: String,
    backends: Vec<IsolationBackendDescriptor>,
    framework_handlers: Vec<AgentWorkerFrameworkHandler>,
    runs: HashMap<String, CloudflareRunContext>,
    props_resolver: CloudflareRunPropsResolver,
}

/// Resolves a run's transient [`CloudflareRunProps`] (model/tools/system-prompt +
/// placement) from the scheduler's [`IsolationPrepareRequest`].
///
/// This is the injection point for FerroGate's **per-run parameterization**: the
/// scheduler seam ([`AgentWorkerControlClient`]) is left unchanged — it still only
/// carries the `IsolationPrepareRequest` — while this resolver maps that request
/// (e.g. its `worker_template_id`) onto the model/tools/prompt selection handed to
/// the agent's `onStart(props)`. The default resolver yields
/// [`CloudflareRunProps::default`] (the agent's coded defaults).
pub type CloudflareRunPropsResolver =
    Arc<dyn Fn(&IsolationPrepareRequest) -> CloudflareRunProps + Send + Sync>;

/// Whether a scheduler stop is a natural terminal transition (→ hibernation)
/// rather than an active operator cancel (→ the cancel route).
///
/// Discriminated on the scheduler's typed [`ManagedWorkerStopKind`], NOT on the
/// stop `reason`. The reason is caller-supplied free text
/// ([`crate::ManagedWorkerScheduler::cancel_session`] takes it verbatim), so the
/// previous `reason ∈ {"completed","failed"}` match let an operator cancel with
/// reason `"completed"` take the hibernation path and send no control call at
/// all while still reporting `Stopped` (issue #414).
fn stop_is_hibernation(kind: ManagedWorkerStopKind) -> bool {
    matches!(kind, ManagedWorkerStopKind::Terminal)
}

impl<S: CloudflareControlSurface> CloudflareAgentControlClient<S> {
    /// Build a client advertising the default (`Gvisor`-tier) Cloudflare
    /// descriptor.
    pub fn new(
        surface: S,
        worker_id: impl Into<String>,
        framework_handlers: Vec<AgentWorkerFrameworkHandler>,
    ) -> Self {
        Self::with_descriptor(
            surface,
            worker_id,
            cloudflare_backend_descriptor_default(),
            framework_handlers,
        )
    }

    /// Build a client advertising a specific Cloudflare descriptor (so its
    /// [`IsolationBackendKind`] matches the operator's worker-template policy).
    pub fn with_descriptor(
        surface: S,
        worker_id: impl Into<String>,
        descriptor: IsolationBackendDescriptor,
        framework_handlers: Vec<AgentWorkerFrameworkHandler>,
    ) -> Self {
        Self {
            surface,
            worker_id: worker_id.into(),
            backends: vec![descriptor],
            framework_handlers,
            runs: HashMap::new(),
            props_resolver: Arc::new(|_| CloudflareRunProps::default()),
        }
    }

    /// Install a [`CloudflareRunPropsResolver`] that derives each run's
    /// `onStart(props)` selection (model/tools/prompt + placement) from the
    /// scheduler's prepare request. Leaves [`ManagedWorkerScheduler`] unchanged.
    ///
    /// [`ManagedWorkerScheduler`]: crate::ManagedWorkerScheduler
    pub fn with_props_resolver(mut self, resolver: CloudflareRunPropsResolver) -> Self {
        self.props_resolver = resolver;
        self
    }

    /// The advertised Cloudflare descriptor.
    pub fn descriptor(&self) -> &IsolationBackendDescriptor {
        &self.backends[0]
    }

    /// Borrow the underlying control surface (tests inspect the mock through
    /// this).
    pub fn surface(&self) -> &S {
        &self.surface
    }

    /// The last CF-side status observed for `run_ref`, if this client started it.
    pub fn observed_status(&self, run_ref: &str) -> Option<CloudflareRunStatus> {
        self.runs.get(run_ref).map(|context| context.status)
    }

    /// Reconcile the last observed CF status for `run_ref` onto the scheduler's
    /// [`ManagedWorkerSessionStatus`] — the value persisted on
    /// `ferrogate_storage::StoredManagedWorkerSession`.
    pub fn reconciled_session_status(&self, run_ref: &str) -> Option<ManagedWorkerSessionStatus> {
        self.observed_status(run_ref)
            .map(CloudflareRunStatus::managed_session_status)
    }

    /// Force-refresh the CF status for `run_ref` from the control surface and
    /// return the reconciled session status. Used when reconciling a persisted
    /// session against the live CF run out of band.
    pub fn refresh_reconciled_status(
        &mut self,
        run_ref: &str,
    ) -> Result<ManagedWorkerSessionStatus, ManagedWorkerError> {
        let status = self.surface.run_status(run_ref)?;
        if let Some(context) = self.runs.get_mut(run_ref) {
            context.status = status;
        }
        Ok(status.managed_session_status())
    }

    fn evidence(
        &self,
        run_ref: &str,
        capability_envelope_id: &str,
        outcome: &str,
        failure_reason: Option<String>,
    ) -> IsolationLifecycleEvidence {
        let descriptor = self.descriptor();
        IsolationLifecycleEvidence {
            backend_name: descriptor.backend_name.clone(),
            backend_version: descriptor.backend_version.clone(),
            agent_worker_id: self.worker_id.clone(),
            isolation_instance_id: Some(run_ref.to_string()),
            resource_limits: IsolationResourceLimits::default(),
            network_policy: IsolationNetworkPolicy::default(),
            filesystem_policy: IsolationFilesystemPolicy::default(),
            capability_envelope_id: capability_envelope_id.to_string(),
            outcome: outcome.to_string(),
            failure_reason,
        }
    }

    fn capability_envelope_id_for(&self, run_ref: &str) -> String {
        self.runs
            .get(run_ref)
            .map(|context| context.capability_envelope_id.clone())
            .unwrap_or_default()
    }
}

impl<S: CloudflareControlSurface> AgentWorkerControlClient for CloudflareAgentControlClient<S> {
    fn framework_handlers(&mut self) -> &[AgentWorkerFrameworkHandler] {
        &self.framework_handlers
    }

    fn backends(&mut self) -> &[IsolationBackendDescriptor] {
        &self.backends
    }

    fn provision_managed_worker(
        &mut self,
        request: IsolationPrepareRequest,
    ) -> Result<IsolationStarted, ManagedWorkerError> {
        // Resolve the per-run props (model/tools/prompt + placement) that the
        // gateway Worker will deliver to `onStart(props)`. "create" is LAZY on
        // Cloudflare: `start_run` addresses the agent by name — first addressing
        // instantiates it — so there is no separate create call.
        let props = (self.props_resolver)(&request);
        let handle = self.surface.start_run(CloudflareRunStartRequest {
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            worker_template_id: request.worker_template_id.clone(),
            framework_adapter: request.framework_adapter.clone(),
            capability_envelope_id: request.capability_envelope_id.clone(),
            props,
        })?;
        self.runs.insert(
            handle.run_ref.clone(),
            CloudflareRunContext {
                session_id: request.session_id,
                run_id: request.run_id,
                capability_envelope_id: request.capability_envelope_id.clone(),
                framework_adapter: request.framework_adapter,
                status: handle.status,
            },
        );
        let evidence = self.evidence(
            &handle.run_ref,
            &request.capability_envelope_id,
            "started",
            None,
        );
        Ok(IsolationStarted {
            instance_id: handle.run_ref,
            evidence,
        })
    }

    fn exec_or_attach(
        &mut self,
        request: IsolationExecRequest,
    ) -> Result<IsolationExecOutcome, ManagedWorkerError> {
        let outcome = self.surface.exec_run(CloudflareRunExecRequest {
            run_ref: request.instance_id.clone(),
            workload_ref: request.workload_ref.clone(),
            args: request.args,
        })?;
        if let Some(context) = self.runs.get_mut(&request.instance_id) {
            context.status = outcome.status;
        }
        let capability_envelope_id = self.capability_envelope_id_for(&request.instance_id);
        let evidence = self.evidence(
            &request.instance_id,
            &capability_envelope_id,
            "executed",
            None,
        );
        Ok(IsolationExecOutcome {
            instance_id: request.instance_id,
            exit_code: outcome.exit_code,
            message: outcome.message,
            evidence,
        })
    }

    fn stop_managed_worker(
        &mut self,
        instance_id: &str,
        kind: ManagedWorkerStopKind,
        reason: &str,
    ) -> Result<IsolationStopOutcome, ManagedWorkerError> {
        // CF reality: no "stop" primitive. A natural terminal transition is
        // modeled as HIBERNATION (`stop_run`, a no-op — the idle agent goes to
        // zero compute, re-addressable by name). An operator cancel goes to the
        // cancel route (`cancel_run`), which signals in-flight work and latches
        // the run against further work.
        let status = if stop_is_hibernation(kind) {
            self.surface.stop_run(instance_id, reason)?
        } else {
            self.surface.cancel_run(instance_id, reason)?
        };
        if let Some(context) = self.runs.get_mut(instance_id) {
            context.status = status;
        }
        let capability_envelope_id = self.capability_envelope_id_for(instance_id);
        let evidence = self.evidence(
            instance_id,
            &capability_envelope_id,
            &format!("stopped:{reason}"),
            None,
        );
        Ok(IsolationStopOutcome {
            instance_id: instance_id.to_string(),
            evidence,
        })
    }

    fn cleanup_managed_worker(
        &mut self,
        instance_id: &str,
    ) -> Result<IsolationCleanupOutcome, ManagedWorkerError> {
        let status = self.surface.cleanup_run(instance_id)?;
        if let Some(context) = self.runs.get_mut(instance_id) {
            context.status = status;
        }
        let capability_envelope_id = self.capability_envelope_id_for(instance_id);
        let evidence = self.evidence(instance_id, &capability_envelope_id, "cleaned_up", None);
        Ok(IsolationCleanupOutcome {
            instance_id: instance_id.to_string(),
            evidence,
        })
    }
}

/// A record of one [`CloudflareControlSurface`] call, captured by
/// [`MockCloudflareControlSurface`] so tests can assert the exact mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockCloudflareCall {
    StartRun(CloudflareRunStartRequest),
    ExecRun(CloudflareRunExecRequest),
    StopRun { run_ref: String, reason: String },
    CancelRun { run_ref: String, reason: String },
    CleanupRun { run_ref: String },
    RunStatus { run_ref: String },
}

/// An in-memory [`CloudflareControlSurface`] for tests: it fabricates a
/// deterministic `run_ref`, records every call, and advances a simple status
/// machine (`Running` -> exec `Completed` -> stop `Stopped` -> cleanup
/// `CleanedUp`). No network. The live surfaces are sibling sub-issues #413/#414.
#[derive(Debug, Default, Clone)]
pub struct MockCloudflareControlSurface {
    calls: Vec<MockCloudflareCall>,
    fail_start: bool,
    fail_exec: bool,
    exec_exit_code: Option<i32>,
    /// What [`CloudflareControlSurface::run_status`] reports. `None` = `Running`.
    reported_status: Option<CloudflareRunStatus>,
}

impl MockCloudflareControlSurface {
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            fail_start: false,
            fail_exec: false,
            exec_exit_code: Some(0),
            reported_status: None,
        }
    }

    /// Make `start_run` fail (simulates the CF surface being unavailable).
    pub fn failing_start() -> Self {
        Self {
            fail_start: true,
            ..Self::new()
        }
    }

    /// Make `exec_run` fail (simulates a hosted run that cannot be driven).
    pub fn failing_exec() -> Self {
        Self {
            fail_exec: true,
            ..Self::new()
        }
    }

    /// Report `status` from `run_status` instead of the default `Running`.
    ///
    /// Exists so a test can distinguish the two outcomes of a COOPERATIVE
    /// cancel: a workload that honored the abort signal (`Stopped`) from one
    /// that ignored it and is still burning (`Running`). [`crate::KillMode`]
    /// `Cancel` behaves differently in each case.
    pub fn reporting_status(mut self, status: CloudflareRunStatus) -> Self {
        self.reported_status = Some(status);
        self
    }

    /// The recorded calls, in order.
    pub fn calls(&self) -> &[MockCloudflareCall] {
        &self.calls
    }

    fn run_ref(request: &CloudflareRunStartRequest) -> String {
        format!("cf-run-{}", request.run_id)
    }
}

impl CloudflareControlSurface for MockCloudflareControlSurface {
    fn start_run(
        &mut self,
        request: CloudflareRunStartRequest,
    ) -> Result<CloudflareRunHandle, CloudflareControlSurfaceError> {
        self.calls
            .push(MockCloudflareCall::StartRun(request.clone()));
        if self.fail_start {
            return Err(CloudflareControlSurfaceError::NotReady(
                "mock cloudflare control surface configured to fail start".to_string(),
            ));
        }
        Ok(CloudflareRunHandle {
            run_ref: Self::run_ref(&request),
            status: CloudflareRunStatus::Running,
        })
    }

    fn exec_run(
        &mut self,
        request: CloudflareRunExecRequest,
    ) -> Result<CloudflareRunExecOutcome, CloudflareControlSurfaceError> {
        self.calls
            .push(MockCloudflareCall::ExecRun(request.clone()));
        if self.fail_exec {
            return Err(CloudflareControlSurfaceError::ExecFailed(
                "mock cloudflare control surface configured to fail exec".to_string(),
            ));
        }
        Ok(CloudflareRunExecOutcome {
            run_ref: request.run_ref.clone(),
            status: CloudflareRunStatus::Completed,
            exit_code: self.exec_exit_code,
            message: format!("cloudflare hosted run executed {}", request.workload_ref),
        })
    }

    fn stop_run(
        &mut self,
        run_ref: &str,
        reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        // Models hibernation: no stop RPC exists on Cloudflare. The mock records
        // the intent and reports `Stopped` without contacting a control route.
        self.calls.push(MockCloudflareCall::StopRun {
            run_ref: run_ref.to_string(),
            reason: reason.to_string(),
        });
        Ok(CloudflareRunStatus::Stopped)
    }

    fn cancel_run(
        &mut self,
        run_ref: &str,
        reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        // Models the cooperative cancel route (see `cancel_run`'s contract:
        // signal in-flight work + latch the run; NOT a fiber cancel).
        self.calls.push(MockCloudflareCall::CancelRun {
            run_ref: run_ref.to_string(),
            reason: reason.to_string(),
        });
        Ok(CloudflareRunStatus::Stopped)
    }

    fn cleanup_run(
        &mut self,
        run_ref: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        self.calls.push(MockCloudflareCall::CleanupRun {
            run_ref: run_ref.to_string(),
        });
        Ok(CloudflareRunStatus::CleanedUp)
    }

    fn run_status(
        &mut self,
        run_ref: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        self.calls.push(MockCloudflareCall::RunStatus {
            run_ref: run_ref.to_string(),
        });
        Ok(self.reported_status.unwrap_or(CloudflareRunStatus::Running))
    }
}

#[cfg(test)]
#[path = "cloudflare_worker_test.rs"]
mod tests;
