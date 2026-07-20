// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for Guardrail evidence queries and investigation sanitization.

use std::collections::BTreeMap;

use super::*;

fn evaluation(tenant_id: &str) -> StoredGuardrailEvaluation {
    StoredGuardrailEvaluation {
        id: format!("evaluation-{tenant_id}"),
        request_id: "request-shared".into(),
        trace_id: None,
        agent_run_id: None,
        subject_id: Some("key-1".into()),
        tenant: ferrogate_core::TenantContext {
            organization_id: Some(tenant_id.into()),
            ..ferrogate_core::TenantContext::default()
        },
        scope_type: "tenant".into(),
        scope_id: tenant_id.into(),
        target: "model=fast-chat;provider=test".into(),
        protocol: "chat_completions".into(),
        stage: "request".into(),
        mode: "enforce".into(),
        policy_id: "policy-1".into(),
        policy_revision: 1,
        verdict: "fail".into(),
        action: "block".into(),
        enforcement_status: "enforced".into(),
        latency_ms: 1,
        finding_category_counts: BTreeMap::new(),
        finding_count: 0,
        transformed: false,
        input_fingerprint: "hmac-sha256:test".into(),
        occurred_at_unix: 1,
    }
}

#[test]
fn evidence_filter_rejects_a_matching_request_from_another_tenant() {
    let filter = GuardrailEvidenceFilter {
        tenant_id: Some("tenant-allowed".into()),
        request_id: Some("request-shared".into()),
        ..GuardrailEvidenceFilter::default()
    };

    assert!(filter.matches(&evaluation("tenant-allowed"), &[]));
    assert!(!filter.matches(&evaluation("tenant-other"), &[]));
}

#[test]
fn investigation_dtos_omit_raw_bodies_tool_arguments_and_billing_metadata() {
    let request = sanitize_investigation_request(StoredRequestLog {
        request_id: "request-1".into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        route: None,
        provider: None,
        logical_model: None,
        provider_model: None,
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code: 200,
        error_code: None,
        prompt_recorded: true,
        response_recorded: true,
        prompt_body: Some("raw-prompt-secret".into()),
        response_body: Some("raw-response-secret".into()),
        cache_status: None,
        started_at_unix: None,
        completed_at_unix: None,
    });
    let approval = sanitize_investigation_approval(ToolApprovalRecord {
        id: "approval-1".into(),
        request_id: "request-1".into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_node_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        actor_api_key_id: None,
        tool_name: "tool".into(),
        server_name: None,
        route: None,
        approval_policy: ferrogate_core::ApprovalPolicy::Always,
        approval_timeout_secs: 60,
        fingerprint: "argument-fingerprint".into(),
        arguments_summary: "raw-tool-argument-secret".into(),
        risk_reason: "test".into(),
        status: ApprovalStatus::Pending,
        reviewer_api_key_id: None,
        reviewer_authority: None,
        terminal_reason: None,
        requested_at_unix: 1,
        expires_at_unix: 61,
        decided_at_unix: None,
    });
    let billing = sanitize_investigation_billing(BillingEvent {
        request_id: "request-1".into(),
        trace_id: None,
        provider_attempt: ferrogate_billing::ProviderAttempt::for_request("request-1", 0),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        logical_model: "model".into(),
        provider: "provider".into(),
        provider_model: "provider-model".into(),
        usage: BillingTokenUsage::default(),
        usage_source: ferrogate_billing::BillingUsageSource::default(),
        status_code: 200,
        occurred_at_unix: Some(1),
        cost_usd: Some(0.01),
        latency_ms: Some(1),
        metadata: BTreeMap::from([("customer".into(), "raw-metadata-secret".into())]),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    });
    let encoded = serde_json::to_string(&(request, approval, billing)).unwrap();
    for forbidden in [
        "raw-prompt-secret",
        "raw-response-secret",
        "raw-tool-argument-secret",
        "argument-fingerprint",
        "raw-metadata-secret",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

fn matcher_approval(
    request_id: &str,
    agent_run_id: Option<&str>,
) -> crate::approval::ToolApprovalRecord {
    crate::approval::ToolApprovalRecord {
        id: "approval-matcher".into(),
        request_id: request_id.into(),
        trace_id: None,
        agent_run_id: agent_run_id.map(str::to_string),
        workflow_id: None,
        workflow_node_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        actor_api_key_id: None,
        tool_name: "tool".into(),
        server_name: None,
        route: None,
        approval_policy: ferrogate_core::ApprovalPolicy::Always,
        approval_timeout_secs: 60,
        fingerprint: "fingerprint".into(),
        arguments_summary: "{}".into(),
        risk_reason: "test".into(),
        status: ApprovalStatus::Pending,
        reviewer_api_key_id: None,
        reviewer_authority: None,
        terminal_reason: None,
        requested_at_unix: 1,
        expires_at_unix: 61,
        decided_at_unix: None,
    }
}

/// #305 acceptance: an approval that carries agent_run_id matches an
/// investigation by that run id DIRECTLY — with zero request-id/trace-id
/// overlap against any related row (empty back-fill sets).
#[test]
fn investigation_by_agent_run_id_matches_approval_without_related_id_overlap() {
    let filter = GuardrailEvidenceFilter {
        agent_run_id: Some("run-corr".into()),
        ..GuardrailEvidenceFilter::default()
    };
    let approval = matcher_approval("request-only-on-approval", Some("run-corr"));
    assert!(investigation_matches_approval(
        &filter,
        &approval,
        &HashSet::new(),
        &HashSet::new(),
    ));
}

/// #305: legacy approvals (no agent_run_id) keep the related-id back-fill.
#[test]
fn investigation_by_agent_run_id_backfills_legacy_approvals_via_related_ids() {
    let filter = GuardrailEvidenceFilter {
        agent_run_id: Some("run-corr".into()),
        ..GuardrailEvidenceFilter::default()
    };
    let legacy = matcher_approval("request-shared", None);
    assert!(investigation_matches_approval(
        &filter,
        &legacy,
        &HashSet::from(["request-shared"]),
        &HashSet::new(),
    ));
    // Without any overlap, a legacy approval still does not match.
    assert!(!investigation_matches_approval(
        &filter,
        &legacy,
        &HashSet::new(),
        &HashSet::new(),
    ));
}

/// #305: an approval bound to a DIFFERENT run must not leak into another run's
/// investigation through the related-id back-fill.
#[test]
fn investigation_by_agent_run_id_excludes_approvals_bound_to_other_runs() {
    let filter = GuardrailEvidenceFilter {
        agent_run_id: Some("run-corr".into()),
        ..GuardrailEvidenceFilter::default()
    };
    let other_run = matcher_approval("request-shared", Some("run-other"));
    assert!(!investigation_matches_approval(
        &filter,
        &other_run,
        &HashSet::from(["request-shared"]),
        &HashSet::new(),
    ));
}

/// #305 acceptance (full investigation path): investigating by agent_run_id
/// surfaces an approval whose request id appears on NO other evidence row —
/// before this change the approval only appeared via related-request-id
/// back-fill and this investigation returned nothing.
#[test]
fn full_investigation_by_agent_run_id_finds_the_approval_directly() {
    let state = AppState::new(crate::config::Config::default());
    state
        .create_tool_approval(crate::state::ToolApprovalCreateRequest {
            tool: &crate::state::ToolExecutionRequest {
                name: "tool.echo".into(),
                arguments: serde_json::json!({"message":"hello"}),
                route: None,
                session_id: None,
            },
            request_id: "fg-approval-only",
            trace_id: None,
            agent_run_id: Some("run-corr".into()),
            workflow_id: None,
            workflow_node_id: None,
            tenant: ferrogate_core::TenantContext::default(),
            actor_api_key_id: None,
            server_name: None,
            approval_policy: ferrogate_core::ApprovalPolicy::Always,
            can_log_bodies: false,
        })
        .expect("create approval");

    let timeline = state
        .guardrail_investigation(GuardrailEvidenceFilter {
            agent_run_id: Some("run-corr".into()),
            ..GuardrailEvidenceFilter::default()
        })
        .expect("investigation query succeeds")
        .expect("the approval alone must surface the investigation");
    assert_eq!(timeline.approvals.len(), 1);
    assert_eq!(timeline.approvals[0].request_id, "fg-approval-only");
    assert_eq!(
        timeline.approvals[0].agent_run_id.as_deref(),
        Some("run-corr")
    );
}

#[test]
fn investigation_cost_normalizes_negative_zero_to_positive_zero() {
    // Rust's `Sum` for f64 folds from `-0.0`, so an empty billing-events
    // list (a pre-provider guardrail block) sums to negative zero.
    let empty_sum: f64 = Vec::<f64>::new().into_iter().sum();
    assert!(
        empty_sum.is_sign_negative(),
        "precondition: empty f64 sum is -0.0"
    );

    let normalized = normalize_investigation_cost(empty_sum);
    assert!(
        normalized.is_sign_positive() && normalized == 0.0,
        "negative zero must normalize to positive zero"
    );
    // The whole point: the serialized JSON reads `0.0`, never `-0.0`.
    assert_eq!(serde_json::to_string(&normalized).unwrap(), "0.0");

    // A real cost is passed through unchanged.
    assert_eq!(normalize_investigation_cost(0.0375), 0.0375);
}
