// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for durable and in-memory Guardrail evidence repositories.

use super::*;

fn evaluation(id: &str, request_id: &str) -> StoredGuardrailEvaluation {
    StoredGuardrailEvaluation {
        id: id.to_string(),
        request_id: request_id.to_string(),
        trace_id: Some("trace-1".to_string()),
        agent_run_id: None,
        subject_id: Some("key-1".to_string()),
        tenant: TenantContext {
            organization_id: Some("tenant-1".to_string()),
            api_key_id: Some("key-1".to_string()),
            ..TenantContext::default()
        },
        scope_type: "api_key".to_string(),
        scope_id: "key-1".to_string(),
        target: "model=fast-chat;provider=test".to_string(),
        protocol: "chat_completions".to_string(),
        stage: "request".to_string(),
        mode: "enforce".to_string(),
        policy_id: "policy-1".to_string(),
        policy_revision: 1,
        verdict: "fail".to_string(),
        action: "block".to_string(),
        enforcement_status: "enforced".to_string(),
        latency_ms: 3,
        finding_category_counts: BTreeMap::from([("secret".to_string(), 1)]),
        finding_count: 1,
        transformed: false,
        input_fingerprint: "hmac-sha256:abcdef".to_string(),
        occurred_at_unix: 100,
    }
}

fn check(evaluation_id: &str) -> StoredGuardrailCheckEvaluation {
    StoredGuardrailCheckEvaluation {
        id: format!("{evaluation_id}/check-1"),
        evaluation_id: evaluation_id.to_string(),
        check_id: "check-1".to_string(),
        detector_id: "ferrogate.local".to_string(),
        detector_version: "ferrogate-local-v1".to_string(),
        config_digest: "sha256:1234".to_string(),
        verdict: "fail".to_string(),
        action: "block".to_string(),
        enforcement_status: "enforced".to_string(),
        latency_ms: 2,
        finding_category_counts: BTreeMap::from([("secret".to_string(), 1)]),
        finding_count: 1,
        transformed: false,
        used_fallback: false,
        error_kind: None,
    }
}

#[test]
fn in_memory_guardrail_evidence_retains_complete_overall_and_check_records() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 10, 10);
    repositories.set_guardrail_evaluation_retention_records(1);
    repositories
        .append_guardrail_evaluation(evaluation("eval-1", "request-1"), vec![check("eval-1")])
        .unwrap();
    repositories
        .append_guardrail_evaluation(evaluation("eval-2", "request-2"), vec![check("eval-2")])
        .unwrap();

    let evaluations = repositories.list_guardrail_evaluations(None).unwrap();
    let checks = repositories.list_guardrail_check_evaluations(None).unwrap();
    assert_eq!(evaluations.len(), 1);
    assert_eq!(evaluations[0].id, "eval-2");
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].evaluation_id, "eval-2");
}

#[test]
fn guardrail_evidence_document_has_no_raw_content_or_credentials_fields() {
    let encoded =
        serde_json::to_string(&(evaluation("eval-1", "request-1"), vec![check("eval-1")])).unwrap();
    for forbidden in [
        "prompt",
        "matched_text",
        "authorization",
        "credential",
        "detector_secret",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn guardrail_evidence_repository_filters_tenant_before_returning_rows() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 10, 10);
    repositories
        .append_guardrail_evaluation(evaluation("eval-1", "request-1"), vec![check("eval-1")])
        .unwrap();
    let mut other = evaluation("eval-2", "request-2");
    other.tenant.organization_id = Some("tenant-2".into());
    repositories
        .append_guardrail_evaluation(other, vec![check("eval-2")])
        .unwrap();

    let evaluations = repositories
        .list_guardrail_evaluations(Some("tenant-1"))
        .unwrap();
    let checks = repositories
        .list_guardrail_check_evaluations(Some("tenant-1"))
        .unwrap();
    assert_eq!(evaluations.len(), 1);
    assert_eq!(evaluations[0].id, "eval-1");
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].evaluation_id, "eval-1");
}

#[test]
fn guardrail_evidence_query_filters_counts_and_fetches_only_page_checks() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 10, 10);
    let mut first = evaluation("eval-1", "request-1");
    first.agent_run_id = Some("run-1".into());
    let mut first_check = check("eval-1");
    first_check.error_kind = Some("timeout".into());
    repositories
        .append_guardrail_evaluation(first, vec![first_check])
        .unwrap();
    let mut second = evaluation("eval-2", "request-2");
    second.occurred_at_unix = 200;
    repositories
        .append_guardrail_evaluation(second, vec![check("eval-2")])
        .unwrap();

    let filtered = repositories
        .query_guardrail_evaluations(&GuardrailEvaluationQuery {
            tenant_id: Some("tenant-1".into()),
            request_id: Some("request-1".into()),
            trace_id: Some("trace-1".into()),
            agent_run_id: Some("run-1".into()),
            scope_type: Some("api_key".into()),
            scope_id: Some("key-1".into()),
            subject_id: Some("key-1".into()),
            policy_id: Some("policy-1".into()),
            policy_revision: Some(1),
            detector_id: Some("ferrogate.local".into()),
            category: Some("secret".into()),
            verdict: Some("fail".into()),
            action: Some("block".into()),
            error_kind: Some("timeout".into()),
            since_unix: Some(100),
            until_unix: Some(100),
            offset: 0,
            limit: 10,
        })
        .unwrap();
    assert_eq!(filtered.total, 1);
    assert_eq!(filtered.evaluations[0].id, "eval-1");
    assert_eq!(filtered.checks.len(), 1);
    assert_eq!(filtered.checks[0].evaluation_id, "eval-1");

    let paged = repositories
        .query_guardrail_evaluations(&GuardrailEvaluationQuery {
            tenant_id: Some("tenant-1".into()),
            offset: 1,
            limit: 1,
            ..GuardrailEvaluationQuery::default()
        })
        .unwrap();
    assert_eq!(paged.total, 2);
    assert_eq!(paged.evaluations[0].id, "eval-1");
    assert_eq!(paged.checks.len(), 1);
    assert_eq!(paged.checks[0].evaluation_id, "eval-1");
}
