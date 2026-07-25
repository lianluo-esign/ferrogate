// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, coding-agent adapter contract (issue #472),
//   phase 2: agent bootstrap — task brief plus a governed-egress posture that points LLM traffic
//   at the tethered FerroGate gateway and cannot claim enforcement it does not have.

//! **Phase 2 — agent bootstrap.**
//!
//! Launch the coding agent against the materialized workspace, hand it the
//! task, and point its model traffic at the governed gateway.
//!
//! The load-bearing type here is [`EgressPosture`]. Decision #470 keeps the
//! governed data plane as **Pingora in a Cloudflare Container** — one Rust
//! implementation, one governed decision path — and the agent's container
//! reaches it *tethered*, without leaving Cloudflare. That only holds if the
//! container cannot open a direct connection to a model provider, which is a
//! property of the egress configuration, not of the agent's good behaviour.
//!
//! So enforcement is **derived from the posture**
//! ([`EgressPosture::enforcement`]) rather than declared alongside it. There is
//! no field an implementation can set to "enforced" while running with open
//! egress; the only way to record a cooperative (bypassable) posture is
//! [`EgressPosture::OpenWithDetection`], which requires a named principal to
//! sign for the weakening and carries that acknowledgement into the run
//! receipt. That is issue #471's problem stated in the type system instead of
//! in a comment.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::coding_agent::error::{CodingAgentError, CodingAgentPhase};
use crate::coding_agent::materialize::{CredentialReference, MaterializedWorkspace};
use crate::coding_agent::run::CodingRunIdentity;
use crate::ActingPrincipal;

/// How the coding agent gets into the instance.
///
/// `agent_name` is a free string, and there is deliberately no enum of
/// supported coding agents — see the contract note in
/// [`crate::coding_agent`] on why a closed vendor list is how a wrong
/// contract gets frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingAgentImage {
    pub agent_name: String,
    pub agent_version: String,
    /// Container image or sandbox template holding the agent. It must not
    /// contain any credential; phase 1 delivers those at run time.
    pub image_ref: String,
    /// argv used to launch the agent inside the workspace.
    pub entrypoint: Vec<String>,
}

impl CodingAgentImage {
    pub fn new(
        agent_name: impl Into<String>,
        agent_version: impl Into<String>,
        image_ref: impl Into<String>,
        entrypoint: Vec<String>,
    ) -> Result<Self, CodingAgentError> {
        let image = Self {
            agent_name: agent_name.into(),
            agent_version: agent_version.into(),
            image_ref: image_ref.into(),
            entrypoint,
        };
        if image.agent_name.trim().is_empty() {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Bootstrap,
                "agent_name",
                "must not be empty",
            ));
        }
        if image.image_ref.trim().is_empty() {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Bootstrap,
                "image_ref",
                "must not be empty",
            ));
        }
        if image.entrypoint.is_empty() {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Bootstrap,
                "entrypoint",
                "must not be empty",
            ));
        }
        Ok(image)
    }
}

/// What the run is for, in the requester's words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskBrief {
    pub task_id: String,
    /// The requester's instruction, verbatim. Recorded so the run's output can
    /// be judged against what was actually asked.
    pub instruction: String,
    /// Paths the requester pointed at. Advisory scoping, not an access
    /// boundary — the filesystem boundary is the isolation tier's job.
    pub context_paths: Vec<String>,
    pub acceptance_note: Option<String>,
}

impl TaskBrief {
    pub fn new(
        task_id: impl Into<String>,
        instruction: impl Into<String>,
    ) -> Result<Self, CodingAgentError> {
        let brief = Self {
            task_id: task_id.into(),
            instruction: instruction.into(),
            context_paths: Vec::new(),
            acceptance_note: None,
        };
        if brief.instruction.trim().is_empty() {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Bootstrap,
                "instruction",
                "a coding run needs a task",
            ));
        }
        Ok(brief)
    }
}

/// Whether the gateway is a wall or a suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressEnforcement {
    /// The network configuration makes direct provider access impossible.
    NetworkEnforced,
    /// The agent is *asked* to use the gateway and could go around it. Every
    /// downstream guarantee — metering, spend caps, guardrails, audit — is
    /// only as good as the agent's cooperation.
    Cooperative,
}

impl EgressEnforcement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NetworkEnforced => "network_enforced",
            Self::Cooperative => "cooperative",
        }
    }
}

/// Signed acknowledgement that a run is being executed with a bypassable
/// gateway. Required to construct [`EgressPosture::OpenWithDetection`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnenforcedEgressAcknowledgement {
    pub approved_by: ActingPrincipal,
    pub reason: String,
    pub acknowledged_at_unix: u64,
}

impl UnenforcedEgressAcknowledgement {
    pub fn new(
        approved_by: ActingPrincipal,
        reason: impl Into<String>,
        acknowledged_at_unix: u64,
    ) -> Result<Self, CodingAgentError> {
        let reason = reason.into();
        if approved_by.subject.trim().is_empty() || reason.trim().is_empty() {
            return Err(CodingAgentError::EgressNotGoverned {
                detail: "running with bypassable egress requires a named approver and a reason"
                    .to_string(),
            });
        }
        Ok(Self {
            approved_by,
            reason,
            acknowledged_at_unix,
        })
    }
}

/// The instance's outbound network posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "posture", rename_all = "snake_case")]
pub enum EgressPosture {
    /// Public egress off. Model traffic *and* git traffic are proxied through
    /// the governed gateway. Strongest, and the shape #470's tethering
    /// argument assumes.
    GatewayProxied,
    /// Public egress restricted to an explicit host allowlist that must
    /// include the gateway host. Reachability of anything else is a decision
    /// someone made, visible in the list.
    Allowlist { hosts: BTreeSet<String> },
    /// Open egress. The gateway is cooperative and the #471 bypass is live;
    /// only divergence detection stands between the run and unmetered tokens.
    OpenWithDetection {
        acknowledgement: UnenforcedEgressAcknowledgement,
    },
}

impl EgressPosture {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GatewayProxied => "gateway_proxied",
            Self::Allowlist { .. } => "allowlist",
            Self::OpenWithDetection { .. } => "open_with_detection",
        }
    }

    /// Enforcement is *derived*, never declared. This is the whole point: an
    /// implementation cannot record `network_enforced` for an open-egress run.
    pub fn enforcement(&self) -> EgressEnforcement {
        match self {
            Self::GatewayProxied | Self::Allowlist { .. } => EgressEnforcement::NetworkEnforced,
            Self::OpenWithDetection { .. } => EgressEnforcement::Cooperative,
        }
    }

    fn validate(&self, gateway_host: &str) -> Result<(), CodingAgentError> {
        match self {
            Self::GatewayProxied | Self::OpenWithDetection { .. } => Ok(()),
            Self::Allowlist { hosts } => {
                if hosts.is_empty() {
                    return Err(CodingAgentError::EgressNotGoverned {
                        detail: "an empty allowlist with public egress enabled is open egress"
                            .to_string(),
                    });
                }
                if !hosts.iter().any(|host| host == gateway_host) {
                    return Err(CodingAgentError::EgressNotGoverned {
                        detail: format!(
                            "allowlist does not include the governed gateway host {gateway_host}; \
                             the agent would have egress but no way to reach the gateway"
                        ),
                    });
                }
                Ok(())
            }
        }
    }
}

/// Where the agent's model traffic goes.
///
/// The run token is a [`CredentialReference`], not a token: the control plane
/// resolves and injects it, and this contract never holds the material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedLlmEgress {
    /// Base URL of the governed FerroGate endpoint the container is tethered
    /// to (#470: Pingora in a Cloudflare Container, near the agent).
    pub gateway_base_url: String,
    /// Host component, used to check the allowlist actually admits the gateway.
    pub gateway_host: String,
    /// Reference to the per-run gateway credential.
    pub run_token_ref: CredentialReference,
}

impl GovernedLlmEgress {
    pub fn new(
        gateway_base_url: impl Into<String>,
        gateway_host: impl Into<String>,
        run_token_ref: CredentialReference,
    ) -> Result<Self, CodingAgentError> {
        let egress = Self {
            gateway_base_url: gateway_base_url.into(),
            gateway_host: gateway_host.into().trim().to_ascii_lowercase(),
            run_token_ref,
        };
        if !egress.gateway_base_url.starts_with("https://") {
            return Err(CodingAgentError::EgressNotGoverned {
                detail: "gateway base URL must be https".to_string(),
            });
        }
        if egress.gateway_host.is_empty() {
            return Err(CodingAgentError::EgressNotGoverned {
                detail: "gateway host must be known so the allowlist can be checked".to_string(),
            });
        }
        Ok(egress)
    }
}

/// Phase-2 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBootstrapRequest {
    pub run: CodingRunIdentity,
    pub workspace: MaterializedWorkspace,
    pub image: CodingAgentImage,
    pub task: TaskBrief,
    pub llm_egress: GovernedLlmEgress,
    pub egress: EgressPosture,
}

impl AgentBootstrapRequest {
    /// Structural validation before the agent is launched.
    pub fn validate(&self) -> Result<(), CodingAgentError> {
        if self.workspace.run.run_id != self.run.run_id {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Bootstrap,
                "workspace",
                "workspace belongs to a different run",
            ));
        }
        self.egress.validate(&self.llm_egress.gateway_host)
    }
}

/// Phase-2 result: the running agent, and the posture it is running under —
/// recorded so a later incident can answer "was the gateway a wall for this
/// run?" without re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrappedAgent {
    pub run: CodingRunIdentity,
    /// #427 instance name (`fg.{tenant}.{session}.{run}`).
    pub instance_name: String,
    pub agent_name: String,
    pub agent_version: String,
    pub workspace_path: String,
    pub egress_posture: EgressPosture,
    pub egress_enforcement: EgressEnforcement,
    pub bootstrapped_at_unix: u64,
}

impl BootstrappedAgent {
    pub fn new(
        request: &AgentBootstrapRequest,
        instance_name: impl Into<String>,
        bootstrapped_at_unix: u64,
    ) -> Result<Self, CodingAgentError> {
        request.validate()?;
        Ok(Self {
            run: request.run.clone(),
            instance_name: instance_name.into(),
            agent_name: request.image.agent_name.clone(),
            agent_version: request.image.agent_version.clone(),
            workspace_path: request.workspace.workspace_path.clone(),
            egress_posture: request.egress.clone(),
            egress_enforcement: request.egress.enforcement(),
            bootstrapped_at_unix,
        })
    }

    /// True when the run's model traffic could have bypassed the gateway.
    pub fn egress_is_bypassable(&self) -> bool {
        matches!(self.egress_enforcement, EgressEnforcement::Cooperative)
    }
}
