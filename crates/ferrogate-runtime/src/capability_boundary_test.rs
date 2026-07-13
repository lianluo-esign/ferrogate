use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::{
    canonical_cli_target, canonical_mcp_target, CapabilityTargetSelector, ClassOnlyPolicyMode,
    JsonShape, McpRisk,
};

#[test]
fn class_only_policy_is_denied_without_explicit_migration_mode() {
    let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
        revision: "revision-7".into(),
        ..CapabilityPolicy::default()
    });
    let outcome = authorizer
        .authorize(request(CapabilityAction::Cli, None))
        .unwrap();
    assert_eq!(outcome.decision, CapabilityAuthorizationDecision::Denied);
    assert!(outcome.evidence.reason.contains("class-only"));
}

#[test]
fn legacy_class_wide_policy_is_explicit_and_visible_in_evidence() {
    let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
        class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
        revision: "legacy-migration-1".into(),
        ..CapabilityPolicy::default()
    });
    let outcome = authorizer
        .authorize(request(CapabilityAction::Tool, None))
        .unwrap();
    assert_eq!(outcome.decision, CapabilityAuthorizationDecision::Allowed);
    assert_eq!(outcome.evidence.selector, "legacy_class_wide");
    assert_eq!(outcome.evidence.policy_revision, "legacy-migration-1");
}

#[test]
fn semantically_identical_target_grants_are_additive() {
    let target = canonical_mcp_target("crm", "lookup", r#"{"id":"42"}"#, false).unwrap();
    let selector = CapabilityTargetSelector::Mcp {
        server: "crm".into(),
        tool: "lookup".into(),
        risk: McpRisk::Read,
        argument_schema: object_shape([("id", JsonShape::String)]),
        allow_extra_arguments: false,
    };
    let grants = ["grant-a", "grant-b"]
        .into_iter()
        .map(|selector_id| CapabilityTargetGrant {
            action: CapabilityAction::McpTool,
            selector_id: selector_id.into(),
            selector: selector.clone(),
        })
        .collect();
    let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        target_grants: grants,
        revision: "revision-8".into(),
        ..CapabilityPolicy::default()
    });
    let outcome = authorizer
        .authorize(request(CapabilityAction::McpTool, Some(target)))
        .unwrap();
    assert_eq!(outcome.decision, CapabilityAuthorizationDecision::Allowed);
    assert_eq!(outcome.evidence.selector, "grant-a,grant-b");
}

#[test]
fn legacy_class_and_typed_target_grants_form_an_additive_union() {
    let selector = CapabilityTargetSelector::Mcp {
        server: "crm".into(),
        tool: "lookup".into(),
        risk: McpRisk::Read,
        argument_schema: object_shape([("id", JsonShape::String)]),
        allow_extra_arguments: false,
    };
    let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: BTreeSet::from([CapabilityAction::McpTool]),
        target_grants: vec![CapabilityTargetGrant {
            action: CapabilityAction::McpTool,
            selector_id: "crm-lookup".into(),
            selector,
        }],
        class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    });

    let narrow = authorizer
        .authorize(request(
            CapabilityAction::McpTool,
            Some(canonical_mcp_target("crm", "lookup", r#"{"id":"42"}"#, false).unwrap()),
        ))
        .unwrap();
    let legacy_sibling = authorizer
        .authorize(request(
            CapabilityAction::McpTool,
            Some(canonical_mcp_target("crm", "search", r#"{"id":"42"}"#, false).unwrap()),
        ))
        .unwrap();

    assert_eq!(narrow.decision, CapabilityAuthorizationDecision::Allowed);
    assert_eq!(narrow.evidence.selector, "crm-lookup");
    assert_eq!(
        legacy_sibling.decision,
        CapabilityAuthorizationDecision::Allowed
    );
    assert_eq!(legacy_sibling.evidence.selector, "legacy_class_wide");
}

#[test]
fn mcp_write_risk_requires_approval_even_when_caller_claims_low_risk() {
    let target = canonical_mcp_target("crm", "delete", r#"{"id":"42"}"#, false).unwrap();
    let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        target_grants: vec![CapabilityTargetGrant {
            action: CapabilityAction::McpTool,
            selector_id: "crm-delete".into(),
            selector: CapabilityTargetSelector::Mcp {
                server: "crm".into(),
                tool: "delete".into(),
                risk: McpRisk::Write,
                argument_schema: object_shape([("id", JsonShape::String)]),
                allow_extra_arguments: false,
            },
        }],
        ..CapabilityPolicy::default()
    });

    let outcome = authorizer
        .authorize(request(CapabilityAction::McpTool, Some(target)))
        .unwrap();

    assert_eq!(
        outcome.decision,
        CapabilityAuthorizationDecision::ApprovalRequired
    );
}

#[test]
fn approval_required_and_allowed_decisions_emit_the_same_candidate_action_fingerprint() {
    let repo = tempfile::tempdir().unwrap();
    let repo = repo.path().display().to_string();
    let target =
        canonical_cli_target("/usr/bin/git", &["status".into()], &repo, 1_000, 1024, 1024).unwrap();
    let grant = CapabilityTargetGrant {
        action: CapabilityAction::Cli,
        selector_id: "git-status".into(),
        selector: CapabilityTargetSelector::Cli {
            executable: "/usr/bin/git".into(),
            argv: vec!["status".into()],
            environment: BTreeMap::new(),
            cwd_glob: repo,
            max_timeout_millis: 1_000,
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
        },
    };
    let approval = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        target_grants: vec![grant.clone()],
        approval_required_actions: BTreeSet::from([CapabilityAction::Cli]),
        revision: "revision-9".into(),
        ..CapabilityPolicy::default()
    })
    .authorize(request(CapabilityAction::Cli, Some(target.clone())))
    .unwrap();
    let execution = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        target_grants: vec![grant],
        revision: "revision-9".into(),
        ..CapabilityPolicy::default()
    })
    .authorize(request(CapabilityAction::Cli, Some(target)))
    .unwrap();
    assert_eq!(
        approval.decision,
        CapabilityAuthorizationDecision::ApprovalRequired
    );
    assert_eq!(execution.decision, CapabilityAuthorizationDecision::Allowed);
    assert_eq!(
        approval.evidence.action_fingerprint,
        execution.evidence.action_fingerprint
    );
    assert!(!approval.evidence.action_fingerprint.is_empty());
    assert_eq!(
        approval.evidence.subject,
        "tenant:tenant-1/workspace:workspace-1/worker:worker-1"
    );
    assert_eq!(approval.evidence.request_id, "run-1:session-1");
    assert_eq!(approval.evidence.trace_id, "run-1");
}

#[test]
fn direct_network_egress_still_needs_the_independent_gate() {
    let authorizer = SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
        class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    });
    let outcome = authorizer
        .authorize(request(CapabilityAction::NetworkEgress, None))
        .unwrap();
    assert_eq!(outcome.decision, CapabilityAuthorizationDecision::Denied);
    assert!(outcome.evidence.reason.contains("direct network egress"));
}

#[test]
fn self_hosted_reports_are_not_managed_authorization_evidence() {
    assert_eq!(
        self_hosted_trust_level_for_capability_report(FrameworkAdapterMode::SelfHosted),
        Some(SelfHostedTelemetryTrustLevel::ReportedBySelfHostedWorker)
    );
    assert_eq!(
        self_hosted_trust_level_for_capability_report(FrameworkAdapterMode::Managed),
        None
    );
}

fn request(
    action: CapabilityAction,
    canonical_target: Option<CanonicalCapabilityTarget>,
) -> ManagedCapabilityRequest {
    ManagedCapabilityRequest {
        tenant_id: "tenant-1".into(),
        workspace_id: "workspace-1".into(),
        worker_id: "worker-1".into(),
        session_id: "session-1".into(),
        run_id: "run-1".into(),
        adapter_name: "native-harness".into(),
        isolation_backend: "firecracker".into(),
        action,
        target: "caller-target".into(),
        canonical_target,
        high_risk: false,
    }
}

fn object_shape<const N: usize>(fields: [(&str, JsonShape); N]) -> JsonShape {
    JsonShape::Object {
        fields: fields
            .into_iter()
            .map(|(name, shape)| (name.to_string(), shape))
            .collect(),
    }
}
