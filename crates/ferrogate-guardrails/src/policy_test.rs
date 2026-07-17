// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for guardrail policy selection, kept outside business logic.

use super::*;

fn policy(policy_id: &str, scope: PolicyScopeSelector) -> PolicyRevision {
    PolicyRevision {
        policy_id: policy_id.to_string(),
        revision: 1,
        name: policy_id.to_string(),
        description: None,
        enforced: true,
        scope,
        checks: vec![CheckBinding {
            id: "check".to_string(),
            enabled: true,
            stage: DetectorStage::Request,
            sources: all_content_sources(),
            detector: DetectorDefinition::local(vec!["secret".to_string()], vec![], None),
            fallback_detector: None,
        }],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode: PolicyMode::Enforce,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![PolicyAction::block("guardrail_blocked", "blocked")],
        on_error: vec![PolicyAction::block("guardrail_unavailable", "unavailable")],
        deadline_ms: 2_000,
        created_at_unix: 1,
        created_by: "admin".to_string(),
    }
}

#[test]
fn aggregation_truth_tables_are_deterministic() {
    use AggregateOutcome::{Error, Fail, Pass};
    use CheckOutcome::{Disabled, Error as CheckError, Fail as CheckFail, Pass as CheckPass};

    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[CheckPass, CheckPass]),
        Pass
    );
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[CheckPass, CheckFail]),
        Fail
    );
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[CheckPass, CheckError]),
        Error
    );
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[CheckFail, CheckError]),
        Fail
    );

    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::Any, &[CheckFail, CheckPass, CheckError]),
        Pass
    );
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::Any, &[CheckFail, CheckFail]),
        Fail
    );
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::Any, &[CheckFail, CheckError]),
        Error
    );

    let threshold = PolicyAggregation::Threshold { minimum: 2 };
    assert_eq!(
        aggregate_check_outcomes(&threshold, &[CheckFail, CheckFail, CheckPass]),
        Fail
    );
    assert_eq!(
        aggregate_check_outcomes(&threshold, &[CheckFail, CheckError, CheckPass]),
        Error
    );
    assert_eq!(
        aggregate_check_outcomes(&threshold, &[CheckFail, CheckPass, CheckPass]),
        Pass
    );
    assert_eq!(
        aggregate_check_outcomes(&threshold, &[Disabled, CheckFail, CheckPass, CheckPass]),
        Pass
    );
    assert_eq!(
        aggregate_check_outcomes(&PolicyAggregation::All, &[Disabled]),
        Error
    );
}

#[test]
fn organization_and_lower_scope_policies_merge_additively() {
    let policies = vec![
        policy(
            "organization-enforced",
            PolicyScopeSelector {
                organization_ids: vec!["org-a".to_string()],
                ..Default::default()
            },
        ),
        policy(
            "project-enforced",
            PolicyScopeSelector {
                project_ids: vec!["project-a".to_string()],
                ..Default::default()
            },
        ),
        policy(
            "other-organization",
            PolicyScopeSelector {
                organization_ids: vec!["org-b".to_string()],
                ..Default::default()
            },
        ),
        policy(
            "profile-selected",
            PolicyScopeSelector {
                gateway_config_ids: vec!["approved-profile".to_string()],
                ..Default::default()
            },
        ),
    ];
    let selected = select_policy_revisions(
        &policies,
        PolicySelectionContext {
            organization_id: Some("org-a"),
            project_id: Some("project-a"),
            workspace_id: None,
            api_key_id: None,
            service_account_id: None,
            gateway_config_id: Some("approved-profile"),
            model: Some("fast-chat"),
            provider: Some("openai"),
        },
    );
    assert_eq!(
        selected
            .iter()
            .map(|policy| policy.policy_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "organization-enforced",
            "project-enforced",
            "profile-selected"
        ]
    );
}

#[test]
fn policy_validation_rejects_invalid_threshold_and_fallback() {
    let mut invalid_sources = policy("invalid-sources", PolicyScopeSelector::default());
    invalid_sources.checks[0].sources.clear();
    assert!(invalid_sources.validate().is_err());

    let mut revision = policy("policy", PolicyScopeSelector::default());
    revision.aggregation = PolicyAggregation::Threshold { minimum: 2 };
    assert!(revision.validate().is_err());

    revision.aggregation = PolicyAggregation::All;
    revision.checks[0].fallback_detector = Some(DetectorDefinition::CustomHttp {
        endpoint: "https://guardrail.example/check".to_string(),
        timeout_ms: 2_000,
        max_concurrency: 1,
        circuit_failure_threshold: 1,
        circuit_cooldown_ms: 1_000,
        max_retries: 0,
        max_payload_bytes: 1_024,
        max_response_bytes: 1_024,
        allow_private_network: false,
        secret_ref: None,
    });
    assert!(revision.validate().is_err());
}

#[test]
fn sequential_and_parallel_selection_preserve_declared_check_order() {
    let mut revision = policy("policy", PolicyScopeSelector::default());
    revision.checks.push(CheckBinding {
        id: "disabled".to_string(),
        enabled: false,
        stage: DetectorStage::Request,
        sources: all_content_sources(),
        detector: DetectorDefinition::local(vec!["x".to_string()], vec![], None),
        fallback_detector: None,
    });
    revision.checks.push(CheckBinding {
        id: "response".to_string(),
        enabled: true,
        stage: DetectorStage::Response,
        sources: all_content_sources(),
        detector: DetectorDefinition::local(vec!["x".to_string()], vec![], None),
        fallback_detector: None,
    });
    for execution in [PolicyExecution::Sequential, PolicyExecution::Parallel] {
        revision.execution = execution;
        assert_eq!(
            revision.selected_check_ids(DetectorStage::Request),
            vec!["check"]
        );
    }
}

#[test]
fn managed_action_kinds_round_trip_serde_in_snake_case() {
    // #200: RequireApproval/Quarantine serialize snake_case, matching the
    // existing action kinds' wire format, and round-trip cleanly.
    for (kind, wire) in [
        (ActionKind::RequireApproval, "\"require_approval\""),
        (ActionKind::Quarantine, "\"quarantine\""),
        (ActionKind::Block, "\"block\""),
    ] {
        assert_eq!(serde_json::to_string(&kind).unwrap(), wire);
        assert_eq!(serde_json::from_str::<ActionKind>(wire).unwrap(), kind);
    }
    // A stored policy action using the new kind deserializes into the whole
    // PolicyAction unchanged.
    let action: PolicyAction = serde_json::from_str(
        r#"{"kind":"require_approval","code":"needs_review","message":"human approval required"}"#,
    )
    .unwrap();
    assert_eq!(action.kind, ActionKind::RequireApproval);
    assert_eq!(action.code.as_deref(), Some("needs_review"));
}

#[test]
fn managed_action_kinds_require_code_and_message_and_fail_closed_without_them() {
    // Every enforcing action must carry an operator-facing code + message.
    assert!(
        PolicyAction::require_approval("needs_review", "human approval required")
            .validate()
            .is_ok()
    );
    assert!(
        PolicyAction::quarantine("held", "output withheld pending review")
            .validate()
            .is_ok()
    );
    for bad in [
        PolicyAction {
            kind: ActionKind::RequireApproval,
            code: None,
            message: Some("m".into()),
        },
        PolicyAction {
            kind: ActionKind::Quarantine,
            code: Some("c".into()),
            message: None,
        },
        PolicyAction {
            kind: ActionKind::RequireApproval,
            code: Some(String::new()),
            message: Some(String::new()),
        },
    ] {
        assert!(
            bad.validate().is_err(),
            "enforcing action without code+message must be rejected"
        );
    }
    // Allow/Record still validate with no code/message (backward compatible).
    assert!(PolicyAction::allow().validate().is_ok());
    assert!(PolicyAction::record().validate().is_ok());
}

#[test]
fn managed_action_constructors_set_the_expected_kind() {
    let approval = PolicyAction::require_approval("c", "m");
    assert_eq!(approval.kind, ActionKind::RequireApproval);
    assert_eq!(approval.code.as_deref(), Some("c"));
    assert_eq!(approval.message.as_deref(), Some("m"));
    let quarantine = PolicyAction::quarantine("c", "m");
    assert_eq!(quarantine.kind, ActionKind::Quarantine);
}
