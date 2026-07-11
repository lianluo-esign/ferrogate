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
