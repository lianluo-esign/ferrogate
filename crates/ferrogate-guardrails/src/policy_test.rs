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
