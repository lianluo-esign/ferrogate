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
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
    }
}

/// A minimal request-log row for #307 parent → child traversal tests: no
/// parent declared (tests attach one explicitly where needed).
fn request_log(request_id: &str, status_code: u16) -> StoredRequestLog {
    StoredRequestLog {
        request_id: request_id.into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        route: Some("a2a.message".into()),
        provider: Some("planner".into()),
        logical_model: Some("a2a:planner".into()),
        provider_model: None,
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code,
        error_code: None,
        prompt_recorded: false,
        response_recorded: false,
        prompt_body: None,
        response_body: None,
        cache_status: None,
        started_at_unix: Some(1),
        completed_at_unix: Some(2),
        parent_action_fingerprint: None,
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

/// #522 box 5 — client-declared run-id namespacing. Tenant A's audit row (its
/// `tenant.organization_id` is stamped from the AUTHENTICATED context, never
/// from the client) that *borrows* tenant B's run-id string can never surface
/// under B's chain: B's investigation join filters on `tenant_id == B` AND the
/// run id, so A's row (tenant A) is excluded even though the run id matches. It
/// still joins under A's own chain.
///
/// Mutation: dropping the `investigation_matches_tenant(...)` conjunct from
/// `investigation_matches_audit` (leaving only the id match) reds the second
/// assertion — B would then see A's borrowed-run-id row.
#[test]
fn borrowed_run_id_from_another_tenant_never_joins_the_victims_chain() {
    let borrowed_run_id = "run-belongs-to-tenant-b";
    // Written by tenant A: the tenant column is the authenticated tenant (A),
    // and the agent_run_id is the string A declared — here deliberately B's.
    let audit_row = ferrogate_storage::StoredAuditEvent {
        id: "audit-a".into(),
        request_id: "request-a".into(),
        trace_id: None,
        agent_run_id: Some(borrowed_run_id.into()),
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        actor_api_key_id: None,
        tenant: ferrogate_core::TenantContext {
            organization_id: Some("tenant-a".into()),
            ..ferrogate_core::TenantContext::default()
        },
        action: "asset.pull".into(),
        target: "asset-x".into(),
        outcome: "served".into(),
        message: "downloaded".into(),
        occurred_at_unix: Some(1),
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
        output_disposition: None,
        parent_action_fingerprint: None,
    };

    // Victim tenant B investigates its own run id: A's row must NOT appear.
    let victim_filter = GuardrailEvidenceFilter {
        tenant_id: Some("tenant-b".into()),
        agent_run_id: Some(borrowed_run_id.into()),
        ..GuardrailEvidenceFilter::default()
    };
    assert!(
        !investigation_matches_audit(&victim_filter, &audit_row),
        "tenant B must never see tenant A's row even when A borrowed B's run id"
    );

    // The row still joins under its OWN tenant's chain (A), so declaring a run
    // id remains useful for the declaring tenant.
    let owner_filter = GuardrailEvidenceFilter {
        tenant_id: Some("tenant-a".into()),
        agent_run_id: Some(borrowed_run_id.into()),
        ..GuardrailEvidenceFilter::default()
    };
    assert!(investigation_matches_audit(&owner_filter, &audit_row));
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
        parent_action_fingerprint: None,
    });
    let approval = sanitize_investigation_approval(ToolApprovalRecord {
        id: "approval-1".into(),
        request_id: "request-1".into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_node_id: None,
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
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
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
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
    let state = AppState::new(ferrogate_config::Config::default());
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
            action_fingerprint: None,
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

fn evaluation_view(evaluation: StoredGuardrailEvaluation) -> GuardrailEvaluationView {
    GuardrailEvaluationView {
        evaluation,
        checks: Vec::new(),
    }
}

/// #306 stored-decision path: a NEW row (stored `decision` present) drives
/// `final_outcome` from the stored canonical decision, NOT from the
/// verdict/action/enforcement heuristic. A shadow-only "block" records
/// verdict=fail/action=block but decision=allow — the heuristic would call
/// the legacy-shaped equivalent "blocked" (verdict!=pass && action=block, but
/// enforcement=shadow_only saves it)… so pin the sharper case: an ENFORCED
/// triple whose stored decision says allow must NOT read as blocked, and a
/// stored deny must read as blocked even when the string triple alone would
/// not trip the legacy heuristic.
#[test]
fn final_outcome_reads_the_stored_decision_for_new_rows() {
    // Stored deny → blocked, regardless of the recorded action string (a
    // require-approval policy surfaces action="block" only via the stored
    // decision mapping; here the strings alone would NOT trip the heuristic).
    let mut denied = evaluation("tenant-allowed");
    denied.verdict = "fail".into();
    denied.action = "record".into();
    denied.enforcement_status = "enforced".into();
    denied.decision = Some("deny".into());
    denied.decision_reason = Some("guardrail:fail:block:enforced".into());
    assert_eq!(
        investigation_final_outcome(&[], &[evaluation_view(denied)]),
        "blocked"
    );

    // Stored allow → NOT blocked, even though the string triple
    // (fail/block/enforced) would trip the legacy heuristic.
    let mut allowed = evaluation("tenant-allowed");
    allowed.verdict = "fail".into();
    allowed.action = "block".into();
    allowed.enforcement_status = "enforced".into();
    allowed.decision = Some("allow".into());
    allowed.decision_reason = Some("guardrail:fail:block:shadow_only".into());
    assert_eq!(
        investigation_final_outcome(&[], &[evaluation_view(allowed)]),
        "decision_only"
    );

    // Stored degrade (enforced redaction) is not a terminal refusal.
    let mut degraded = evaluation("tenant-allowed");
    degraded.verdict = "fail".into();
    degraded.action = "redact".into();
    degraded.enforcement_status = "enforced".into();
    degraded.decision = Some("degrade".into());
    degraded.decision_reason = Some("guardrail:fail:redact:enforced".into());
    assert_eq!(
        investigation_final_outcome(&[], &[evaluation_view(degraded)]),
        "decision_only"
    );
}

/// #306 legacy fallback: rows persisted before migration 047 carry NO stored
/// decision — `final_outcome` keeps deriving from the
/// verdict/action/enforcement heuristic for exactly those rows.
#[test]
fn final_outcome_falls_back_to_the_heuristic_for_legacy_rows() {
    // Legacy enforced non-pass block → blocked (heuristic path).
    let legacy_blocked = evaluation("tenant-allowed");
    assert_eq!(legacy_blocked.decision, None, "precondition: legacy row");
    assert_eq!(legacy_blocked.verdict, "fail");
    assert_eq!(legacy_blocked.action, "block");
    assert_eq!(legacy_blocked.enforcement_status, "enforced");
    assert_eq!(
        investigation_final_outcome(&[], &[evaluation_view(legacy_blocked)]),
        "blocked"
    );

    // Legacy shadow-only block did not gate traffic → not blocked.
    let mut legacy_shadow = evaluation("tenant-allowed");
    legacy_shadow.enforcement_status = "shadow_only".into();
    assert_eq!(
        investigation_final_outcome(&[], &[evaluation_view(legacy_shadow)]),
        "decision_only"
    );

    // Legacy pass never blocks.
    let mut legacy_pass = evaluation("tenant-allowed");
    legacy_pass.verdict = "pass".into();
    assert_eq!(
        investigation_final_outcome(&[], &[evaluation_view(legacy_pass)]),
        "decision_only"
    );
}

/// #306 fingerprint-based joining: rows sharing one
/// `canonical_target_sha256` fingerprint across guardrail evidence,
/// approvals, timeline events and audit events group into ONE correlation;
/// rows without a fingerprint never appear; distinct fingerprints stay
/// distinct (sorted deterministically).
#[test]
fn investigation_groups_evidence_rows_by_shared_action_fingerprint() {
    let shared = format!("sha256:{}", "aa".repeat(32));
    let other = format!("sha256:{}", "bb".repeat(32));

    let mut guardrail_row = evaluation("tenant-allowed");
    guardrail_row.id = "eval-shared".into();
    guardrail_row.action_fingerprint = Some(shared.clone());
    let mut legacy_guardrail_row = evaluation("tenant-allowed");
    legacy_guardrail_row.id = "eval-legacy".into();

    let mut approval = matcher_approval("request-shared", Some("run-corr"));
    approval.id = "approval-shared".into();
    approval.action_fingerprint = Some(shared.clone());

    let agent_event = ferrogate_storage::StoredAgentRunEvent {
        id: "agent-event-shared".into(),
        run_id: "run-corr".into(),
        request_id: "request-shared".into(),
        trace_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        turn: 0,
        kind: "capability.allowed".into(),
        target: "mcp:local:echo".into(),
        outcome: "allowed".into(),
        tool_call_id: None,
        message: None,
        occurred_at_unix: Some(1),
        action_fingerprint: Some(shared.clone()),
        decision: Some("allow".into()),
        decision_reason: Some("capability_allowed".into()),
        output_disposition: None,
    };
    let audit_event = ferrogate_storage::StoredAuditEvent {
        id: "audit-shared".into(),
        request_id: "request-shared".into(),
        trace_id: None,
        agent_run_id: Some("run-corr".into()),
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        actor_api_key_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        action: "tool.execute".into(),
        target: "mcp:local:echo".into(),
        outcome: "success".into(),
        message: "executed".into(),
        occurred_at_unix: Some(1),
        action_fingerprint: Some(shared.clone()),
        decision: Some("allow".into()),
        decision_reason: Some("audit_success".into()),
        output_disposition: Some("returned".into()),
        parent_action_fingerprint: None,
    };
    let mut other_audit_event = audit_event.clone();
    other_audit_event.id = "audit-other".into();
    other_audit_event.action_fingerprint = Some(other.clone());

    let correlations = investigation_action_correlations(
        &[
            evaluation_view(guardrail_row),
            evaluation_view(legacy_guardrail_row),
        ],
        &[approval],
        &[agent_event],
        &[audit_event, other_audit_event],
        &[],
        &HashSet::new(),
        &[],
        &HashSet::new(),
    );
    assert_eq!(correlations.len(), 2, "{correlations:?}");
    let shared_group = &correlations[0];
    assert_eq!(shared_group.action_fingerprint, shared);
    assert_eq!(shared_group.guardrail_evaluation_ids, vec!["eval-shared"]);
    assert_eq!(shared_group.approval_ids, vec!["approval-shared"]);
    assert_eq!(shared_group.agent_event_ids, vec!["agent-event-shared"]);
    assert_eq!(shared_group.audit_event_ids, vec!["audit-shared"]);
    // #307: without child rows the parent → child link lists stay empty (and
    // are omitted from the serialized payload, keeping pre-#307 shapes).
    assert!(shared_group.child_request_ids.is_empty());
    assert!(shared_group.child_dispatch_ids.is_empty());
    let encoded = serde_json::to_value(shared_group).unwrap();
    assert!(encoded.get("child_request_ids").is_none());
    assert!(encoded.get("child_dispatch_ids").is_none());
    let other_group = &correlations[1];
    assert_eq!(other_group.action_fingerprint, other);
    assert_eq!(other_group.audit_event_ids, vec!["audit-other"]);
    assert!(other_group.guardrail_evaluation_ids.is_empty());
    assert!(other_group.approval_ids.is_empty());
    assert!(other_group.agent_event_ids.is_empty());
}

/// #307 parent → child traversal: request-log rows and dispatch rows that
/// declared a `parent_action_fingerprint` join the correlation group KEYED BY
/// that parent fingerprint — creating the group when only the child is under
/// investigation — while rows without a parent never appear as children.
#[test]
fn investigation_links_child_rows_to_their_parent_action_fingerprint() {
    let parent = format!("sha256:{}", "aa".repeat(32));

    // The parent action's own evidence: one audit row carrying the fingerprint.
    let mut parent_audit = ferrogate_storage::StoredAuditEvent {
        id: "audit-parent".into(),
        request_id: "request-parent".into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        actor_api_key_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        action: "tool.execute".into(),
        target: "mcp:local:echo".into(),
        outcome: "success".into(),
        message: "executed".into(),
        occurred_at_unix: Some(1),
        action_fingerprint: Some(parent.clone()),
        decision: Some("allow".into()),
        decision_reason: Some("audit_success".into()),
        output_disposition: Some("returned".into()),
        parent_action_fingerprint: None,
    };

    // Child A2A exchange rows: one declaring the parent, one absent-parent.
    let mut child_log = request_log("request-child-a2a", 200);
    child_log.parent_action_fingerprint = Some(parent.clone());
    let orphan_log = request_log("request-orphan", 200);
    assert_eq!(orphan_log.parent_action_fingerprint, None);

    // Child dispatch rows: one declaring the parent, one absent-parent (the
    // absent one is filtered before the walk, mirroring the read path).
    let child_dispatch = ferrogate_storage::StoredSelfHostedRunDispatch {
        dispatch_id: "dispatch-child".into(),
        action: "start_run".into(),
        tenant_id: "org".into(),
        workspace_id: "ws".into(),
        session_id: "session".into(),
        run_id: "run-child".into(),
        framework_adapter: "codex".into(),
        required_capabilities: vec![],
        workload_ref: "queue://runs/run-child".into(),
        queued_at_unix: Some(1),
        assigned_worker_id: None,
        lease_id: None,
        lease_expires_at_unix: None,
        attempt: 0,
        acknowledged_status: None,
        acknowledged_at_unix: None,
        request_id: None,
        trace_id: None,
        agent_run_id: Some("run-child".into()),
        parent_action_fingerprint: Some(parent.clone()),
    };

    // An UNRELATED parent/child pair elsewhere in the store: its parent is
    // not in scope and the child is not selected, so it must never leak into
    // this investigation's correlations.
    let mut unrelated_log = request_log("request-unrelated", 200);
    unrelated_log.parent_action_fingerprint = Some(format!("sha256:{}", "ee".repeat(32)));

    // Investigating the PARENT (its audit evidence is in scope; no child row
    // is selected): every child of the in-scope fingerprint attaches.
    let correlations = investigation_action_correlations(
        &[],
        &[],
        &[],
        std::slice::from_ref(&parent_audit),
        &[child_log.clone(), orphan_log.clone(), unrelated_log.clone()],
        &HashSet::new(),
        std::slice::from_ref(&child_dispatch),
        &HashSet::new(),
    );
    assert_eq!(correlations.len(), 1, "{correlations:?}");
    let group = &correlations[0];
    assert_eq!(group.action_fingerprint, parent);
    assert_eq!(group.audit_event_ids, vec!["audit-parent"]);
    assert_eq!(group.child_request_ids, vec!["request-child-a2a"]);
    assert_eq!(group.child_dispatch_ids, vec!["dispatch-child"]);

    // Investigating only the CHILD (it is selected; none of the parent's own
    // evidence is in scope): the parent-keyed group still surfaces to pivot
    // on, while the unrelated pair stays invisible.
    parent_audit.action_fingerprint = None;
    let child_only = investigation_action_correlations(
        &[],
        &[],
        &[],
        &[],
        &[child_log.clone(), unrelated_log],
        &HashSet::from(["request-child-a2a".to_string()]),
        &[],
        &HashSet::new(),
    );
    assert_eq!(child_only.len(), 1, "{child_only:?}");
    assert_eq!(child_only[0].action_fingerprint, parent);
    assert_eq!(child_only[0].child_request_ids, vec!["request-child-a2a"]);
    assert!(child_only[0].audit_event_ids.is_empty());

    // Investigating a SELECTED child dispatch surfaces the parent group too.
    let dispatch_only = investigation_action_correlations(
        &[],
        &[],
        &[],
        &[],
        &[],
        &HashSet::new(),
        std::slice::from_ref(&child_dispatch),
        &HashSet::from(["dispatch-child".to_string()]),
    );
    assert_eq!(dispatch_only.len(), 1, "{dispatch_only:?}");
    assert_eq!(dispatch_only[0].action_fingerprint, parent);
    assert_eq!(dispatch_only[0].child_dispatch_ids, vec!["dispatch-child"]);
}

/// #307: the investigation request DTO surfaces the declared parent (and
/// omits the key entirely for absent-parent rows — NULL is explicit, not "").
#[test]
fn investigation_request_dto_surfaces_the_declared_parent_action() {
    let parent = format!("sha256:{}", "dd".repeat(32));
    let mut log = request_log("request-child", 200);
    log.parent_action_fingerprint = Some(parent.clone());
    let sanitized = sanitize_investigation_request(log);
    assert_eq!(
        sanitized.parent_action_fingerprint.as_deref(),
        Some(&*parent)
    );
    let encoded = serde_json::to_value(&sanitized).unwrap();
    assert_eq!(encoded["parent_action_fingerprint"], parent.as_str());

    let orphan = sanitize_investigation_request(request_log("request-orphan", 200));
    assert_eq!(orphan.parent_action_fingerprint, None);
    let encoded = serde_json::to_value(&orphan).unwrap();
    assert!(
        encoded.get("parent_action_fingerprint").is_none(),
        "absent parent must be omitted: {encoded}"
    );
}

/// #306: investigation approval DTOs surface the shared action identity and
/// stored decision, while the invocation-binding approval fingerprint stays
/// redacted.
#[test]
fn investigation_approval_dto_surfaces_the_action_identity_but_not_the_binding_fingerprint() {
    let mut approval = matcher_approval("request-1", Some("run-corr"));
    approval.fingerprint = "invocation-binding-fingerprint".into();
    approval.action_fingerprint = Some(format!("sha256:{}", "cc".repeat(32)));
    approval.decision = Some("ask".into());
    approval.decision_reason = Some("approval_pending".into());
    let sanitized = sanitize_investigation_approval(approval.clone());
    assert_eq!(sanitized.action_fingerprint, approval.action_fingerprint);
    assert_eq!(sanitized.decision.as_deref(), Some("ask"));
    assert_eq!(
        sanitized.decision_reason.as_deref(),
        Some("approval_pending")
    );
    let encoded = serde_json::to_string(&sanitized).unwrap();
    assert!(!encoded.contains("invocation-binding-fingerprint"));
}
