// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Typed container/sandbox isolation verbs over the agent-gateway Worker's
//   /container/* routes (issue #415): prepare/start/exec/stop/logs/artifacts/cleanup for a
//   Cloudflare Container or @cloudflare/sandbox instance, reusing the #413 transport seam and
//   the #427 instance-naming scheme, with fail-closed egress governance.

//! FerroGate access to a Cloudflare **Containers / Sandbox** isolation instance
//! (issue #415).
//!
//! Cloudflare exposes **no public REST API** to start/exec/stop/inspect an
//! individual container or sandbox: the low-level lifecycle
//! (`this.ctx.container.start/exec/signal/monitor/destroy`, or the
//! `@cloudflare/sandbox` `getSandbox(...).exec/runCode/…`) is only reachable
//! from Worker code. So — exactly like the #413 control, #427 memory, and #426
//! schedule surfaces — every container operation FerroGate performs is a
//! governed call to the agent-gateway Worker's authenticated `/container/*`
//! routes (the tethered principle). This module is the Rust client for those
//! routes; the Worker side lives in `workers/agent-gateway/src/container.ts`.
//!
//! This is the "just another sandbox" isolation tier for agent runs that must
//! execute arbitrary / untrusted code: each named instance is a per-tenant
//! isolated Durable Object (isolation IS tenant isolation, per the #427 naming
//! scheme `fg.{tenant}.{session}.{run}`), scales to zero, and — critically —
//! starts with **no internet** (`enableInternet=false`).
//!
//! **Egress posture (issue #471).** `direct_public_egress = false` is enforced
//! *by construction*: [`ContainerStartSpec::egress`] is a
//! [`ContainerEgressPosture`], and no inhabitant of that type grants open
//! internet — the old `enable_internet: bool` / `egress_allowlist: Vec<String>`
//! pair (which let a caller legally ask for internet plus an allowlist of
//! `api.anthropic.com`, i.e. the exact bypass) no longer exists. A tethered
//! posture can only be built from hosts that are neither wildcards nor provider
//! endpoints. The wire body always carries `enableInternet: false` plus the
//! provider denylist, the Worker independently re-enforces both, and
//! [`ContainerControlClient::start`] refuses the start unless the Worker
//! **attests** the posture it actually applied
//! ([`ContainerControlError::EgressNotGoverned`]). See
//! [`crate::cloudflare_container_egress`] for what Cloudflare does and does not
//! enforce, and [`crate::cloudflare_container_tether_audit`] for the detection
//! path that covers what prevention cannot.
//!
//! The lifecycle maps onto the runtime [`crate::IsolationBackendLifecycle`]
//! contract (the `agent-worker` backend in `cloudflare_container_backend.rs`
//! drives this client): `prepare` → `start` → `exec` → `collect_logs` /
//! `collect_artifacts` → `stop` → `cleanup`. There is **no snapshot/checkpoint
//! verb**: Cloudflare containers hibernate/scale-to-zero but expose no live
//! checkpoint primitive, so [`cloudflare_container_capabilities`] advertises
//! `snapshot_or_checkpoint = false` and selection can never route that op here
//! (fail-closed by construction — see [`cloudflare_container_descriptor`]).
//!
//! HTTP reuses the synchronous [`GatewayControlTransport`] seam from #413, so
//! every verb is unit-tested against a scripted mock with **no network**.

use std::collections::BTreeMap;
use std::{error::Error, fmt};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cloudflare_agent_memory::AgentInstanceIdentity;
use crate::cloudflare_container_egress::{ContainerEgressPosture, EgressPostureAttestation};
use crate::cloudflare_gateway_control::GatewayControlTransport;
use crate::isolation::{
    IsolationBackendCapabilities, IsolationBackendDescriptor, IsolationBackendKind,
};
use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse};

/// Stable backend name advertised by the descriptor / wire report.
pub const CLOUDFLARE_CONTAINER_BACKEND_NAME: &str = "cloudflare-container";
/// The lifecycle is driven through the fronting agent-gateway Worker, NOT the
/// local `agent-worker` host — the descriptor records that owner honestly.
pub const CLOUDFLARE_CONTAINER_HOST_LIFECYCLE_OWNER: &str = "cloudflare-agent-gateway";

/// Capabilities the Cloudflare container/sandbox backend actually implements
/// through the fronting Worker. `snapshot_or_checkpoint` is OFF (Cloudflare
/// exposes no container checkpoint primitive) and `secret_injection` is OFF
/// (left to the gateway-mediated capability path, like the Docker tier). This
/// set is the single source of truth: the advertised capabilities are a strict
/// subset of the implemented lifecycle ops, so `select_isolation_backend` can
/// never pick this backend for an op it cannot perform.
pub fn cloudflare_container_capabilities() -> IsolationBackendCapabilities {
    IsolationBackendCapabilities {
        prepare: true,
        start: true,
        exec_or_attach: true,
        stop: true,
        snapshot_or_checkpoint: false,
        collect_logs: true,
        collect_artifacts: true,
        cleanup: true,
        governed_egress: true,
        secret_injection: false,
    }
}

/// The isolation descriptor for the Cloudflare container/sandbox tier. Unlike
/// the host-owned backends it sets `gateway_controls_backend = true` and a
/// remote `host_lifecycle_owner`, reflecting that its lifecycle runs through
/// the fronting Worker.
pub fn cloudflare_container_descriptor(version: &str) -> IsolationBackendDescriptor {
    IsolationBackendDescriptor {
        backend_name: CLOUDFLARE_CONTAINER_BACKEND_NAME.to_string(),
        backend_version: version.to_string(),
        kind: IsolationBackendKind::CloudflareContainer,
        host_lifecycle_owner: CLOUDFLARE_CONTAINER_HOST_LIFECYCLE_OWNER.to_string(),
        gateway_controls_backend: true,
        capabilities: cloudflare_container_capabilities(),
    }
}

/// Cloudflare container instance tier (vCPU/memory class). Bounded to the GA
/// range `lite`..`standard-4` (≤ 4 vCPU / 12 GiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerInstanceTier {
    Lite,
    Basic,
    Standard1,
    Standard2,
    Standard3,
    Standard4,
}

impl ContainerInstanceTier {
    /// Wire spelling used by the Worker routes.
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Lite => "lite",
            Self::Basic => "basic",
            Self::Standard1 => "standard-1",
            Self::Standard2 => "standard-2",
            Self::Standard3 => "standard-3",
            Self::Standard4 => "standard-4",
        }
    }

    /// Parse a wire tier string; `None` for any value outside the GA range.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value.trim() {
            "lite" => Some(Self::Lite),
            "basic" => Some(Self::Basic),
            "standard-1" => Some(Self::Standard1),
            "standard-2" => Some(Self::Standard2),
            "standard-3" => Some(Self::Standard3),
            "standard-4" => Some(Self::Standard4),
            _ => None,
        }
    }
}

/// POSIX signal used to stop an instance (maps onto `this.ctx.container.signal`
/// / the sandbox `.stop()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerSignal {
    /// Graceful termination.
    Term,
    /// Forced kill.
    Kill,
}

impl ContainerSignal {
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Term => "SIGTERM",
            Self::Kill => "SIGKILL",
        }
    }
}

/// `prepare` spec: pin the image/template and instance class before start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerPrepareSpec {
    /// Container image reference (Wrangler-built) or sandbox template id.
    pub image: String,
    pub tier: ContainerInstanceTier,
    /// Writable workspace mount inside the instance (default `/workspace`).
    pub workspace_path: Option<String>,
}

impl ContainerPrepareSpec {
    pub fn new(image: impl Into<String>, tier: ContainerInstanceTier) -> Self {
        Self {
            image: image.into(),
            tier,
            workspace_path: None,
        }
    }
}

/// `start` spec: launch the prepared instance.
///
/// **There is no `enable_internet` field (issue #471).** The network posture is
/// a [`ContainerEgressPosture`], which cannot express direct public egress in
/// any variant; the default is [`ContainerEgressPosture::Sealed`]. That is what
/// makes `direct_public_egress = false` structural rather than documented: a
/// caller cannot construct a start spec that opens the internet, and cannot
/// allowlist a wildcard or a provider endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerStartSpec {
    /// Optional entrypoint override (argv).
    pub entrypoint: Vec<String>,
    /// Environment injected into the instance (deterministic order on the wire).
    pub env: BTreeMap<String, String>,
    /// The governed egress posture: sealed, or tethered to a validated host set.
    pub egress: ContainerEgressPosture,
}

/// What to execute in a running instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerExecKind {
    /// A process command (argv) run via `exec`.
    Command(Vec<String>),
    /// A code step run via the sandbox `createCodeContext` + `runCode` path —
    /// the untrusted-agent-generated-code case.
    Code { language: String, source: String },
}

/// `exec` spec: one command or code step, with an optional timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerExecSpec {
    pub kind: ContainerExecKind,
    pub timeout_millis: Option<u64>,
}

impl ContainerExecSpec {
    pub fn command<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            kind: ContainerExecKind::Command(args.into_iter().map(Into::into).collect()),
            timeout_millis: None,
        }
    }

    pub fn code(language: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            kind: ContainerExecKind::Code {
                language: language.into(),
                source: source.into(),
            },
            timeout_millis: None,
        }
    }

    pub fn with_timeout_millis(mut self, timeout_millis: u64) -> Self {
        self.timeout_millis = Some(timeout_millis);
        self
    }
}

/// Outcome of `prepare`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContainerPrepared {
    pub instance: String,
    #[serde(rename = "preparedId")]
    pub prepared_id: String,
}

/// Outcome of `start`.
///
/// `egress` is the Worker's **attestation** of the posture it actually applied
/// (issue #471). It is `Option` only so a response from a Worker deployment that
/// predates the attestation contract decodes rather than erroring at the serde
/// layer — [`ContainerControlClient::start`] then rejects the `None` case as an
/// unattested (therefore ungoverned) start.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContainerStarted {
    pub instance: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    pub running: bool,
    #[serde(default)]
    pub egress: Option<EgressPostureAttestation>,
}

/// Outcome of `exec` — stdout/stderr/exit captured from the instance.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContainerExecOutput {
    pub instance: String,
    #[serde(rename = "exitCode")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub truncated: bool,
}

/// Outcome of `stop`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContainerStopped {
    pub instance: String,
    pub signal: String,
    pub running: bool,
}

/// Outcome of `collect_logs`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContainerLogs {
    pub instance: String,
    #[serde(default)]
    pub lines: Vec<String>,
}

/// One artifact discovered under the instance workspace.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContainerArtifactEntry {
    pub path: String,
    #[serde(rename = "sizeBytes", default)]
    pub size_bytes: u64,
    #[serde(rename = "contentType", default)]
    pub content_type: Option<String>,
}

/// Outcome of `collect_artifacts`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContainerArtifacts {
    pub instance: String,
    #[serde(default)]
    pub artifacts: Vec<ContainerArtifactEntry>,
}

/// Outcome of `cleanup`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContainerCleaned {
    pub instance: String,
    #[serde(default)]
    pub destroyed: bool,
}

/// Failure surfaced by a container verb.
#[derive(Debug, Clone, PartialEq)]
pub enum ContainerControlError {
    /// The identity triple cannot be turned into a safe instance name.
    InvalidIdentity(String),
    /// The spec is invalid (client-side, or the Worker's 422 `invalid_spec`).
    InvalidSpec(String),
    /// The instance is not provably running under a governed egress posture
    /// (issue #471): the Worker did not attest the posture it applied, or
    /// attested one that diverges from the requested
    /// [`ContainerEgressPosture`]. Fail-closed — the run does not proceed.
    EgressNotGoverned(String),
    /// The Worker has no container/sandbox binding configured (HTTP 501).
    Unbound(String),
    /// An op requiring a running instance found none (HTTP 409 `not_running`).
    NotRunning(String),
    /// The Worker rejected the bearer credential (HTTP 401/403).
    Denied(String),
    /// Any other non-2xx from a container route.
    RequestFailed {
        verb: &'static str,
        status: u16,
        body: String,
    },
    /// Connect/decoding failure talking to the Worker.
    Transport(String),
}

impl fmt::Display for ContainerControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(m) => write!(f, "invalid agent instance identity: {m}"),
            Self::InvalidSpec(m) => write!(f, "invalid container spec: {m}"),
            Self::EgressNotGoverned(m) => write!(f, "container egress is not governed: {m}"),
            Self::Unbound(m) => write!(f, "container backend unbound on Worker: {m}"),
            Self::NotRunning(m) => write!(f, "container instance is not running: {m}"),
            Self::Denied(m) => write!(f, "container access denied: {m}"),
            Self::RequestFailed { verb, status, body } => {
                write!(f, "container {verb} failed: HTTP {status}: {body}")
            }
            Self::Transport(m) => write!(f, "container transport failed: {m}"),
        }
    }
}

impl Error for ContainerControlError {}

#[derive(Debug, Deserialize)]
struct ContainerErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

/// Typed client for the gateway Worker's `/container/*` routes.
///
/// Reuses the synchronous [`GatewayControlTransport`] seam (and its production
/// block-on bridge) from the #413 control surface, and presents the same DIY
/// bearer credential — container isolation rides the exact governed channel the
/// lifecycle, memory, and schedule verbs do.
pub struct ContainerControlClient<T: GatewayControlTransport> {
    base_url: String,
    control_token: String,
    transport: T,
}

impl<T: GatewayControlTransport> ContainerControlClient<T> {
    /// Build a container client for a Worker at `base_url` presenting
    /// `control_token`.
    pub fn new(
        base_url: impl Into<String>,
        control_token: impl Into<String>,
        transport: T,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            control_token: control_token.into(),
            transport,
        }
    }

    /// Borrow the underlying transport (tests inspect the mock through this).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn post(&self, path: &str, body: Value) -> Result<HttpResponse, ContainerControlError> {
        let bytes = serde_json::to_vec(&body)
            .map_err(|e| ContainerControlError::Transport(format!("failed to encode body: {e}")))?;
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        self.transport
            .send(HttpRequest {
                method: HttpMethod::Post,
                url,
                bearer_token: self.control_token.clone(),
                body: Some(bytes),
                content_type: None,
            })
            .map_err(|e| ContainerControlError::Transport(e.to_string()))
    }

    fn call<R: for<'de> Deserialize<'de>>(
        &self,
        verb: &'static str,
        path: &str,
        body: Value,
    ) -> Result<R, ContainerControlError> {
        let response = self.post(path, body)?;
        if !(200..300).contains(&response.status) {
            return Err(map_error(verb, &response));
        }
        serde_json::from_slice(&response.body)
            .map_err(|e| ContainerControlError::Transport(format!("failed to decode {verb}: {e}")))
    }

    fn instance_name(
        &self,
        identity: &AgentInstanceIdentity,
    ) -> Result<String, ContainerControlError> {
        identity
            .instance_name()
            .map_err(|e| ContainerControlError::InvalidIdentity(e.to_string()))
    }

    /// Pin the image/tier/workspace for a per-tenant instance.
    pub fn prepare(
        &self,
        identity: &AgentInstanceIdentity,
        spec: &ContainerPrepareSpec,
    ) -> Result<ContainerPrepared, ContainerControlError> {
        let instance = self.instance_name(identity)?;
        if spec.image.trim().is_empty() {
            return Err(ContainerControlError::InvalidSpec(
                "image must not be empty".into(),
            ));
        }
        let mut container = json!({
            "image": spec.image,
            "tier": spec.tier.as_wire(),
        });
        if let Some(workspace) = &spec.workspace_path {
            container["workspacePath"] = json!(workspace);
        }
        self.call(
            "prepare",
            "container/prepare",
            json!({ "instance": instance, "container": container }),
        )
    }

    /// Start the prepared instance under a **governed egress posture**
    /// (issue #471).
    ///
    /// The wire body always asserts `enableInternet: false` and
    /// `directPublicEgress: false` — the posture type has no other inhabitant —
    /// and carries the provider denylist so the Worker applies `setDeniedHosts`,
    /// which Cloudflare evaluates ahead of (and overriding) any allowlist.
    ///
    /// The response is not trusted blindly: the Worker must **attest** the
    /// posture it applied, and a missing or divergent attestation fails the
    /// start with [`ContainerControlError::EgressNotGoverned`]. A run therefore
    /// never proceeds on an instance whose egress configuration was silently
    /// dropped.
    pub fn start(
        &self,
        identity: &AgentInstanceIdentity,
        spec: &ContainerStartSpec,
    ) -> Result<ContainerStarted, ContainerControlError> {
        let instance = self.instance_name(identity)?;
        let body = json!({
            "instance": instance,
            "entrypoint": spec.entrypoint,
            "env": spec.env,
            // Structural, not configurable: this tier has no open-internet mode.
            "enableInternet": false,
            "directPublicEgress": false,
            "egressPosture": spec.egress.wire_label(),
            "egressAllowlist": spec.egress.allowed_hosts(),
            "egressDenylist": spec.egress.denied_hosts(),
        });
        let started: ContainerStarted = self.call("start", "container/start", body)?;
        match &started.egress {
            None => Err(ContainerControlError::EgressNotGoverned(
                "the agent-gateway Worker did not attest the applied egress posture; \
                 refusing to run an unattested container (deploy a Worker with the #471 \
                 container routes)"
                    .into(),
            )),
            Some(attestation) => match attestation.verify(&spec.egress) {
                Ok(()) => Ok(started),
                Err(e) => Err(ContainerControlError::EgressNotGoverned(e.to_string())),
            },
        }
    }

    /// Execute a command or code step in the running instance and capture
    /// stdout/stderr/exit.
    pub fn exec(
        &self,
        identity: &AgentInstanceIdentity,
        spec: &ContainerExecSpec,
    ) -> Result<ContainerExecOutput, ContainerControlError> {
        let instance = self.instance_name(identity)?;
        let mut step = match &spec.kind {
            ContainerExecKind::Command(argv) => {
                if argv.is_empty() {
                    return Err(ContainerControlError::InvalidSpec(
                        "command argv must not be empty".into(),
                    ));
                }
                json!({ "mode": "command", "command": argv })
            }
            ContainerExecKind::Code { language, source } => {
                if language.trim().is_empty() {
                    return Err(ContainerControlError::InvalidSpec(
                        "code language must not be empty".into(),
                    ));
                }
                json!({ "mode": "code", "language": language, "source": source })
            }
        };
        if let Some(timeout) = spec.timeout_millis {
            step["timeoutMillis"] = json!(timeout);
        }
        self.call(
            "exec",
            "container/exec",
            json!({ "instance": instance, "step": step }),
        )
    }

    /// Stop the running instance with the given signal (SIGTERM/SIGKILL).
    pub fn stop(
        &self,
        identity: &AgentInstanceIdentity,
        signal: ContainerSignal,
    ) -> Result<ContainerStopped, ContainerControlError> {
        let instance = self.instance_name(identity)?;
        self.call(
            "stop",
            "container/stop",
            json!({ "instance": instance, "signal": signal.as_wire() }),
        )
    }

    /// Collect recent instance logs (`tail` lines when provided).
    pub fn collect_logs(
        &self,
        identity: &AgentInstanceIdentity,
        tail: Option<u32>,
    ) -> Result<ContainerLogs, ContainerControlError> {
        let instance = self.instance_name(identity)?;
        let mut body = json!({ "instance": instance });
        if let Some(tail) = tail {
            body["tail"] = json!(tail);
        }
        self.call("logs", "container/logs", body)
    }

    /// List artifacts under the instance workspace (default) or `path`.
    pub fn collect_artifacts(
        &self,
        identity: &AgentInstanceIdentity,
        path: Option<&str>,
    ) -> Result<ContainerArtifacts, ContainerControlError> {
        let instance = self.instance_name(identity)?;
        let mut body = json!({ "instance": instance });
        if let Some(path) = path {
            body["path"] = json!(path);
        }
        self.call("artifacts", "container/artifacts", body)
    }

    /// Destroy the instance and free its resources.
    pub fn cleanup(
        &self,
        identity: &AgentInstanceIdentity,
    ) -> Result<ContainerCleaned, ContainerControlError> {
        let instance = self.instance_name(identity)?;
        self.call(
            "cleanup",
            "container/cleanup",
            json!({ "instance": instance }),
        )
    }
}

impl ContainerControlClient<crate::cloudflare_gateway_control::BlockingHttpControlTransport> {
    /// Build a **production** container client that drives the deployed
    /// agent-gateway Worker over real HTTP.
    ///
    /// This is the constructor the `agent-worker` remote-provisioning dispatch
    /// (issue #442) uses: it wraps the reqwest [`crate::HttpTransport`] in the
    /// synchronous block-on bridge ([`crate::BlockingHttpControlTransport`]) so
    /// the whole `/container/*` verb set is reachable from the worker's
    /// non-async lifecycle path without that crate taking a direct
    /// `ferrogate-cloudflare`/`tokio` dependency. Offline unit tests construct
    /// the client with [`ContainerControlClient::new`] and a mock
    /// [`GatewayControlTransport`] instead, so this bridge is only exercised
    /// against a live Worker (the test gate's coverage).
    pub fn production(
        base_url: impl Into<String>,
        control_token: impl Into<String>,
    ) -> Result<Self, ContainerControlError> {
        let http = ferrogate_cloudflare::ReqwestTransport::new().map_err(|e| {
            ContainerControlError::Transport(format!(
                "failed to build the Cloudflare container HTTP transport: {e}"
            ))
        })?;
        let transport = crate::cloudflare_gateway_control::BlockingHttpControlTransport::new(
            std::sync::Arc::new(http),
        )
        .map_err(|e| {
            ContainerControlError::Transport(format!(
                "failed to build the Cloudflare container control transport bridge: {e}"
            ))
        })?;
        Ok(Self::new(base_url, control_token, transport))
    }
}

/// Map a non-2xx container-route response onto the typed error vocabulary.
fn map_error(verb: &'static str, response: &HttpResponse) -> ContainerControlError {
    let body_text = String::from_utf8_lossy(&response.body).into_owned();
    let parsed: ContainerErrorBody =
        serde_json::from_slice(&response.body).unwrap_or(ContainerErrorBody {
            error: String::new(),
            message: String::new(),
        });
    let detail = if parsed.message.is_empty() {
        body_text.clone()
    } else {
        parsed.message
    };
    match (response.status, parsed.error.as_str()) {
        (401 | 403, _) => {
            ContainerControlError::Denied(format!("HTTP {}: {body_text}", response.status))
        }
        (422, _) | (_, "invalid_spec") => ContainerControlError::InvalidSpec(detail),
        (501, _) | (_, "container_unbound") => ContainerControlError::Unbound(detail),
        (409, _) | (_, "not_running") => ContainerControlError::NotRunning(detail),
        (status, _) => ContainerControlError::RequestFailed {
            verb,
            status,
            body: body_text,
        },
    }
}

#[cfg(test)]
#[path = "cloudflare_container_test.rs"]
mod tests;
