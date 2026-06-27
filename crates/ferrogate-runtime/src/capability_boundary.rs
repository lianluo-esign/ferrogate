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

use crate::{FrameworkAdapterMode, SelfHostedTelemetryTrustLevel};

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
    pub high_risk: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityPolicy {
    pub allowed_actions: BTreeSet<CapabilityAction>,
    pub approval_required_actions: BTreeSet<CapabilityAction>,
    pub allow_direct_network_egress: bool,
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
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub session_id: String,
    pub run_id: String,
    pub adapter_name: String,
    pub isolation_backend: String,
    pub action: CapabilityAction,
    pub target: String,
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
        let (decision, reason) = if request.action == CapabilityAction::NetworkEgress
            && !self.policy.allow_direct_network_egress
        {
            (
                CapabilityAuthorizationDecision::Denied,
                "managed workers cannot use direct network egress".to_string(),
            )
        } else if self
            .policy
            .approval_required_actions
            .contains(&request.action)
            || request.high_risk
        {
            (
                CapabilityAuthorizationDecision::ApprovalRequired,
                format!("{} requires approval", request.action.as_str()),
            )
        } else if self.policy.allowed_actions.contains(&request.action) {
            (
                CapabilityAuthorizationDecision::Allowed,
                format!("{} allowed by capability policy", request.action.as_str()),
            )
        } else {
            (
                CapabilityAuthorizationDecision::Denied,
                format!(
                    "{} is not allowed by capability policy",
                    request.action.as_str()
                ),
            )
        };
        let evidence = CapabilityAuthorizationEvidence {
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            worker_id: request.worker_id,
            session_id: request.session_id,
            run_id: request.run_id,
            adapter_name: request.adapter_name,
            isolation_backend: request.isolation_backend,
            action: request.action,
            target: request.target,
            decision,
            reason,
        };
        Ok(CapabilityAuthorizationOutcome { decision, evidence })
    }
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
mod tests {
    use super::*;

    #[test]
    fn allows_managed_worker_action_when_policy_allows_it() {
        let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
            ..CapabilityPolicy::default()
        });

        let outcome = authorizer
            .authorize(request(CapabilityAction::Tool))
            .unwrap();

        assert_eq!(outcome.decision, CapabilityAuthorizationDecision::Allowed);
        assert_eq!(outcome.evidence.tenant_id, "tenant-1");
        assert_eq!(outcome.evidence.workspace_id, "workspace-1");
        assert_eq!(outcome.evidence.worker_id, "worker-1");
        assert_eq!(outcome.evidence.session_id, "session-1");
        assert_eq!(outcome.evidence.run_id, "run-1");
        assert_eq!(outcome.evidence.adapter_name, "native-harness");
        assert_eq!(outcome.evidence.isolation_backend, "firecracker");
    }

    #[test]
    fn denies_managed_worker_action_when_policy_does_not_allow_it() {
        let authorizer = SimpleCapabilityAuthorizer::default();

        let outcome = authorizer
            .authorize(request(CapabilityAction::Cli))
            .unwrap();

        assert_eq!(outcome.decision, CapabilityAuthorizationDecision::Denied);
        assert!(outcome.evidence.reason.contains("not allowed"));
    }

    #[test]
    fn requires_approval_for_high_risk_or_policy_shaped_actions() {
        let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
            approval_required_actions: BTreeSet::from([CapabilityAction::Cli]),
            ..CapabilityPolicy::default()
        });

        let outcome = authorizer
            .authorize(request(CapabilityAction::Cli))
            .unwrap();

        assert_eq!(
            outcome.decision,
            CapabilityAuthorizationDecision::ApprovalRequired
        );
        assert!(outcome.evidence.reason.contains("requires approval"));
    }

    #[test]
    fn denies_direct_unmanaged_network_egress_even_when_action_is_allowlisted() {
        let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
            allow_direct_network_egress: false,
            ..CapabilityPolicy::default()
        });

        let outcome = authorizer
            .authorize(request(CapabilityAction::NetworkEgress))
            .unwrap();

        assert_eq!(outcome.decision, CapabilityAuthorizationDecision::Denied);
        assert!(outcome.evidence.reason.contains("direct network egress"));
    }

    #[test]
    fn self_hosted_capability_reports_are_not_managed_authorization_evidence() {
        assert_eq!(
            self_hosted_trust_level_for_capability_report(FrameworkAdapterMode::SelfHosted),
            Some(SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker)
        );
        assert_eq!(
            self_hosted_trust_level_for_capability_report(FrameworkAdapterMode::Managed),
            None
        );
    }

    fn request(action: CapabilityAction) -> ManagedCapabilityRequest {
        ManagedCapabilityRequest {
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            adapter_name: "native-harness".to_string(),
            isolation_backend: "firecracker".to_string(),
            action,
            target: "target-1".to_string(),
            high_risk: false,
        }
    }
}
