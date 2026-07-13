// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Gateway-mediated capability boundary for managed workers.
//!
//! Managed worker adapters must request capabilities through FerroGate before
//! executing external actions. A sandbox is an execution boundary, not an
//! authorization boundary.

use std::{collections::BTreeSet, error::Error, fmt};

use crate::{
    CanonicalCapabilityTarget, CapabilityTargetSelector, ClassOnlyPolicyMode, FrameworkAdapterMode,
    SelfHostedTelemetryTrustLevel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityAction {
    Tool,
    McpTool,
    Cli,
    Skill,
    Filesystem,
    Browser,
    Rest,
    Secret,
    MemoryRead,
    MemoryWrite,
    NetworkEgress,
}

impl CapabilityAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::McpTool => "mcp.tool",
            Self::Cli => "cli",
            Self::Skill => "skill",
            Self::Filesystem => "filesystem",
            Self::Browser => "browser",
            Self::Rest => "rest",
            Self::Secret => "secret",
            Self::MemoryRead => "memory.read",
            Self::MemoryWrite => "memory.write",
            Self::NetworkEgress => "network.egress",
        }
    }

    fn requires_canonical_target(self) -> bool {
        matches!(
            self,
            Self::McpTool
                | Self::Cli
                | Self::Filesystem
                | Self::Rest
                | Self::Secret
                | Self::NetworkEgress
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCapabilityRequest {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: String,
    pub run_id: String,
    pub adapter_name: String,
    pub isolation_backend: String,
    pub action: CapabilityAction,
    pub target: String,
    pub canonical_target: Option<CanonicalCapabilityTarget>,
    pub high_risk: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityPolicy {
    pub allowed_actions: BTreeSet<CapabilityAction>,
    pub approval_required_actions: BTreeSet<CapabilityAction>,
    pub allow_direct_network_egress: bool,
    pub target_grants: Vec<CapabilityTargetGrant>,
    pub class_only_policy_mode: ClassOnlyPolicyMode,
    pub revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityTargetGrant {
    pub action: CapabilityAction,
    pub selector_id: String,
    pub selector: CapabilityTargetSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityAuthorizationDecision {
    Allowed,
    Denied,
    ApprovalRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAuthorizationOutcome {
    pub decision: CapabilityAuthorizationDecision,
    pub evidence: CapabilityAuthorizationEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAuthorizationEvidence {
    pub subject: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: String,
    pub run_id: String,
    pub adapter_name: String,
    pub isolation_backend: String,
    pub action: CapabilityAction,
    pub target: String,
    pub selector: String,
    pub canonical_target: String,
    /// Stable exact-action contract consumed by approval/Guardrail layers.
    /// This authorizer produces the value; approval persistence/enforcement is
    /// owned by the control-plane workflow tracked in issue #200.
    pub action_fingerprint: String,
    pub policy_revision: String,
    pub request_id: String,
    pub trace_id: String,
    pub decision: CapabilityAuthorizationDecision,
    pub reason: String,
}

pub trait CapabilityAuthorizer {
    fn authorize(
        &self,
        request: ManagedCapabilityRequest,
    ) -> Result<CapabilityAuthorizationOutcome, CapabilityBoundaryError>;
}

#[derive(Debug, Clone, Default)]
pub struct SimpleCapabilityAuthorizer {
    policy: CapabilityPolicy,
}

impl SimpleCapabilityAuthorizer {
    pub fn new(policy: CapabilityPolicy) -> Self {
        Self { policy }
    }
}

impl CapabilityAuthorizer for SimpleCapabilityAuthorizer {
    fn authorize(
        &self,
        request: ManagedCapabilityRequest,
    ) -> Result<CapabilityAuthorizationOutcome, CapabilityBoundaryError> {
        validate_request(&request)?;
        let target_decision = evaluate_target_grants(&self.policy, &request);
        let (decision, reason, selector, canonical_target, action_fingerprint) = if request.action
            == CapabilityAction::NetworkEgress
            && !self.policy.allow_direct_network_egress
        {
            (
                CapabilityAuthorizationDecision::Denied,
                "managed workers cannot use direct network egress".to_string(),
                "network_egress_disabled".to_string(),
                canonical_target_json(&request),
                canonical_target_fingerprint(&request),
            )
        } else if let TargetGrantDecision::Denied(reason) = &target_decision {
            (
                CapabilityAuthorizationDecision::Denied,
                reason.clone(),
                "none".to_string(),
                canonical_target_json(&request),
                canonical_target_fingerprint(&request),
            )
        } else if self
            .policy
            .approval_required_actions
            .contains(&request.action)
            || request.high_risk
            || target_decision.approval_required()
        {
            (
                CapabilityAuthorizationDecision::ApprovalRequired,
                format!("{} requires approval", request.action.as_str()),
                target_decision.selector().to_string(),
                target_decision.canonical_target(&request),
                target_decision.action_fingerprint(&request),
            )
        } else if target_decision.allowed() {
            let reason = if target_decision.selector() == "legacy_class_wide" {
                format!("{} allowed by capability policy", request.action.as_str())
            } else {
                format!(
                    "{} target allowed by capability policy",
                    request.action.as_str()
                )
            };
            (
                CapabilityAuthorizationDecision::Allowed,
                reason,
                target_decision.selector().to_string(),
                target_decision.canonical_target(&request),
                target_decision.action_fingerprint(&request),
            )
        } else {
            (
                CapabilityAuthorizationDecision::Denied,
                format!(
                    "{} is not allowed by capability policy",
                    request.action.as_str()
                ),
                "none".to_string(),
                canonical_target_json(&request),
                canonical_target_fingerprint(&request),
            )
        };
        let policy_revision = if self.policy.revision.trim().is_empty() {
            "unversioned".to_string()
        } else {
            self.policy.revision.clone()
        };
        let subject = format!(
            "tenant:{}/workspace:{}/worker:{}",
            request.tenant_id, request.workspace_id, request.worker_id
        );
        let request_id = format!("{}:{}", request.run_id, request.session_id);
        let trace_id = request.run_id.clone();
        let evidence = CapabilityAuthorizationEvidence {
            subject,
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            worker_id: request.worker_id,
            session_id: request.session_id,
            run_id: request.run_id,
            adapter_name: request.adapter_name,
            isolation_backend: request.isolation_backend,
            action: request.action,
            target: request.target,
            selector,
            canonical_target,
            action_fingerprint,
            policy_revision,
            request_id,
            trace_id,
            decision,
            reason,
        };
        Ok(CapabilityAuthorizationOutcome { decision, evidence })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetGrantDecision {
    Allowed {
        selector: String,
        canonical_target: String,
        action_fingerprint: String,
        approval_required: bool,
    },
    Denied(String),
}

impl TargetGrantDecision {
    fn allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    fn selector(&self) -> &str {
        match self {
            Self::Allowed { selector, .. } => selector,
            Self::Denied(_) => "none",
        }
    }

    fn approval_required(&self) -> bool {
        matches!(
            self,
            Self::Allowed {
                approval_required: true,
                ..
            }
        )
    }

    fn canonical_target(&self, request: &ManagedCapabilityRequest) -> String {
        match self {
            Self::Allowed {
                canonical_target, ..
            } => canonical_target.clone(),
            Self::Denied(_) => canonical_target_json(request),
        }
    }

    fn action_fingerprint(&self, request: &ManagedCapabilityRequest) -> String {
        match self {
            Self::Allowed {
                action_fingerprint, ..
            } => action_fingerprint.clone(),
            Self::Denied(_) => canonical_target_fingerprint(request),
        }
    }
}

fn evaluate_target_grants(
    policy: &CapabilityPolicy,
    request: &ManagedCapabilityRequest,
) -> TargetGrantDecision {
    let class_granted = policy.allowed_actions.contains(&request.action)
        || policy.approval_required_actions.contains(&request.action);
    let legacy_class_wide =
        class_granted && policy.class_only_policy_mode == ClassOnlyPolicyMode::LegacyClassWide;
    let action_grants = policy
        .target_grants
        .iter()
        .filter(|grant| grant.action == request.action)
        .collect::<Vec<_>>();
    if action_grants.is_empty() {
        return if legacy_class_wide {
            TargetGrantDecision::Allowed {
                selector: "legacy_class_wide".to_string(),
                canonical_target: canonical_target_json(request),
                action_fingerprint: canonical_target_fingerprint(request),
                approval_required: false,
            }
        } else if class_granted {
            TargetGrantDecision::Denied(
                "class-only policy requires explicit legacy_class_wide migration mode or typed target grants"
                    .to_string(),
            )
        } else {
            TargetGrantDecision::Denied(format!(
                "{} is not allowed by capability policy",
                request.action.as_str()
            ))
        };
    }
    if request.canonical_target.is_none() && request.action.requires_canonical_target() {
        return TargetGrantDecision::Denied(
            "target-level action requires an unambiguous canonical execution target".to_string(),
        );
    }
    let Some(target) = request.canonical_target.as_ref() else {
        return if legacy_class_wide {
            TargetGrantDecision::Allowed {
                selector: "legacy_class_wide".to_string(),
                canonical_target: canonical_target_json(request),
                action_fingerprint: canonical_target_fingerprint(request),
                approval_required: false,
            }
        } else {
            TargetGrantDecision::Denied(
                "typed target grant requires an unambiguous canonical target".to_string(),
            )
        };
    };
    let mut matched = Vec::new();
    for grant in action_grants {
        match target.bind(&grant.selector) {
            Ok(Some(bound)) => matched.push((grant.selector_id.as_str(), bound)),
            Ok(None) => {}
            Err(reason) => return TargetGrantDecision::Denied(reason),
        }
    }
    if matched.is_empty() {
        return if legacy_class_wide {
            TargetGrantDecision::Allowed {
                selector: "legacy_class_wide".to_string(),
                canonical_target: canonical_target_json(request),
                action_fingerprint: canonical_target_fingerprint(request),
                approval_required: false,
            }
        } else {
            TargetGrantDecision::Denied("canonical target does not match a typed grant".to_string())
        };
    }
    let canonical_target = matched[0].1.canonical_target.clone();
    let action_fingerprint = matched[0].1.action_fingerprint.clone();
    if matched.iter().any(|(_, bound)| {
        bound.canonical_target != canonical_target || bound.action_fingerprint != action_fingerprint
    }) {
        return TargetGrantDecision::Denied(
            "canonical target matches grants with conflicting execution targets".to_string(),
        );
    }
    let mut selectors = matched.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    selectors.sort_unstable();
    selectors.dedup();
    TargetGrantDecision::Allowed {
        selector: selectors.join(","),
        canonical_target,
        action_fingerprint,
        approval_required: matched.iter().any(|(_, bound)| bound.approval_required),
    }
}

fn canonical_target_json(request: &ManagedCapabilityRequest) -> String {
    request
        .canonical_target
        .as_ref()
        .map(CanonicalCapabilityTarget::canonical_json)
        .unwrap_or_else(|| request.target.clone())
}

fn canonical_target_fingerprint(request: &ManagedCapabilityRequest) -> String {
    request
        .canonical_target
        .as_ref()
        .map(CanonicalCapabilityTarget::fingerprint)
        .unwrap_or_default()
}

pub fn self_hosted_trust_level_for_capability_report(
    mode: FrameworkAdapterMode,
) -> Option<SelfHostedTelemetryTrustLevel> {
    match mode {
        FrameworkAdapterMode::Managed => None,
        FrameworkAdapterMode::SelfHosted => {
            Some(SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityBoundaryError {
    InvalidRequest(String),
}

impl fmt::Display for CapabilityBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid capability request: {message}")
            }
        }
    }
}

impl Error for CapabilityBoundaryError {}

fn validate_request(request: &ManagedCapabilityRequest) -> Result<(), CapabilityBoundaryError> {
    require_non_empty("tenant_id", &request.tenant_id)?;
    require_non_empty("workspace_id", &request.workspace_id)?;
    require_non_empty("worker_id", &request.worker_id)?;
    require_non_empty("session_id", &request.session_id)?;
    require_non_empty("run_id", &request.run_id)?;
    require_non_empty("adapter_name", &request.adapter_name)?;
    require_non_empty("isolation_backend", &request.isolation_backend)?;
    require_non_empty("target", &request.target)?;
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), CapabilityBoundaryError> {
    if value.trim().is_empty() {
        return Err(CapabilityBoundaryError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "capability_boundary_test.rs"]
mod tests;
