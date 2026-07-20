// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Guardrail evidence queries and unified investigation timelines.

use super::*;

const GUARDRAIL_INVESTIGATION_EVALUATION_LIMIT: usize = 1_000;

impl AppState {
    pub(crate) fn guardrail_evaluations_page(
        &self,
        pagination: AdminPagination,
        filter: GuardrailEvidenceFilter,
    ) -> anyhow::Result<AdminPage<GuardrailEvaluationView>> {
        let (data, total) =
            self.guardrail_evaluation_views_page(&filter, pagination.offset, pagination.limit)?;
        Ok(AdminPage {
            data,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }

    pub(crate) fn guardrail_investigation(
        &self,
        filter: GuardrailEvidenceFilter,
    ) -> anyhow::Result<Option<GuardrailInvestigationTimeline>> {
        if !filter.has_investigation_selector() {
            anyhow::bail!("request_id, trace_id, or agent_run_id is required");
        }
        let (guardrail_evaluations, _) = self.guardrail_evaluation_views_page(
            &filter,
            0,
            GUARDRAIL_INVESTIGATION_EVALUATION_LIMIT,
        )?;
        let mut requests = crate::gateway::block_on_sync_bridge(self.repositories.request_logs())
            .into_iter()
            .filter(|log| investigation_matches_request(&filter, log))
            .collect::<Vec<_>>();
        let mut agent_runs = crate::gateway::block_on_sync_bridge(self.repositories.agent_runs())
            .into_iter()
            .filter(|run| investigation_matches_agent_run(&filter, run))
            .collect::<Vec<_>>();
        let mut agent_events =
            crate::gateway::block_on_sync_bridge(self.repositories.agent_run_events())
                .into_iter()
                .filter(|event| investigation_matches_agent_event(&filter, event))
                .collect::<Vec<_>>();
        let mut audit_events =
            crate::gateway::block_on_sync_bridge(self.repositories.audit_events())
                .into_iter()
                .filter(|event| investigation_matches_audit(&filter, event))
                .collect::<Vec<_>>();
        let related_request_ids = requests
            .iter()
            .map(|request| request.request_id.as_str())
            .chain(agent_runs.iter().map(|run| run.request_id.as_str()))
            .chain(agent_events.iter().map(|event| event.request_id.as_str()))
            .collect::<HashSet<_>>();
        let related_trace_ids = requests
            .iter()
            .filter_map(|request| request.trace_id.as_deref())
            .chain(agent_runs.iter().filter_map(|run| run.trace_id.as_deref()))
            .chain(
                agent_events
                    .iter()
                    .filter_map(|event| event.trace_id.as_deref()),
            )
            .collect::<HashSet<_>>();
        let mut approvals = self
            .tool_approvals()
            .into_iter()
            .filter(|approval| {
                investigation_matches_approval(
                    &filter,
                    approval,
                    &related_request_ids,
                    &related_trace_ids,
                )
            })
            .collect::<Vec<_>>();
        let mut seen_billing_events = HashSet::new();
        let mut billing_events = Vec::new();
        for event in crate::gateway::block_on_sync_bridge(self.repositories.billing_events())
            .into_iter()
            .chain(self.metering_events.list())
            .filter(|event| investigation_matches_billing(&filter, event))
        {
            let key = serde_json::to_string(&event).unwrap_or_default();
            if seen_billing_events.insert(key) {
                billing_events.push(event);
            }
        }

        if guardrail_evaluations.is_empty()
            && agent_runs.is_empty()
            && agent_events.is_empty()
            && requests.is_empty()
            && audit_events.is_empty()
            && approvals.is_empty()
            && billing_events.is_empty()
        {
            return Ok(None);
        }
        agent_runs.sort_by_key(|run| run.started_at_unix.unwrap_or_default());
        agent_events.sort_by_key(|event| event.occurred_at_unix.unwrap_or_default());
        requests.sort_by_key(|log| log.started_at_unix.unwrap_or_default());
        audit_events.sort_by_key(|event| event.occurred_at_unix.unwrap_or_default());
        approvals.sort_by_key(|approval| approval.requested_at_unix);
        billing_events.sort_by_key(|event| event.occurred_at_unix.unwrap_or_default());
        let identity = guardrail_evaluations
            .first()
            .map(|view| view.evaluation.tenant.clone())
            .or_else(|| agent_runs.first().map(|run| run.tenant.clone()))
            .or_else(|| agent_events.first().map(|event| event.tenant.clone()))
            .or_else(|| requests.first().map(|log| log.tenant.clone()))
            .or_else(|| audit_events.first().map(|event| event.tenant.clone()))
            .or_else(|| billing_events.first().map(|event| event.tenant.clone()));
        let total_cost_usd = normalize_investigation_cost(
            billing_events
                .iter()
                .filter_map(|event| event.cost_usd)
                .sum(),
        );
        let final_outcome = investigation_final_outcome(&requests, &guardrail_evaluations);
        let requests = requests
            .into_iter()
            .map(sanitize_investigation_request)
            .collect();
        let approvals = approvals
            .into_iter()
            .map(sanitize_investigation_approval)
            .collect();
        let billing_events = billing_events
            .into_iter()
            .map(sanitize_investigation_billing)
            .collect();
        Ok(Some(GuardrailInvestigationTimeline {
            object: "guardrail_investigation",
            selector: investigation_selector(&filter),
            identity,
            agent_runs,
            agent_events,
            requests,
            guardrail_evaluations,
            audit_events,
            approvals,
            billing_events,
            total_cost_usd,
            final_outcome,
        }))
    }

    fn guardrail_evaluation_views_page(
        &self,
        filter: &GuardrailEvidenceFilter,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<(Vec<GuardrailEvaluationView>, usize)> {
        let page = self
            .repositories
            .query_guardrail_evaluations(&filter.storage_query(offset, limit))?;
        let mut checks_by_evaluation: HashMap<String, Vec<StoredGuardrailCheckEvaluation>> =
            HashMap::new();
        for check in page.checks {
            checks_by_evaluation
                .entry(check.evaluation_id.clone())
                .or_default()
                .push(check);
        }
        let views = page
            .evaluations
            .into_iter()
            .map(|evaluation| {
                let mut checks = checks_by_evaluation
                    .remove(&evaluation.id)
                    .unwrap_or_default();
                checks.sort_by(|left, right| left.check_id.cmp(&right.check_id));
                GuardrailEvaluationView { evaluation, checks }
            })
            .collect();
        Ok((views, page.total))
    }
}

fn investigation_matches_tenant(
    filter: &GuardrailEvidenceFilter,
    tenant: &ferrogate_core::TenantContext,
) -> bool {
    filter
        .tenant_id
        .as_ref()
        .is_none_or(|tenant_id| tenant.organization_id.as_ref() == Some(tenant_id))
}

fn investigation_matches_ids(
    filter: &GuardrailEvidenceFilter,
    request_id: &str,
    trace_id: Option<&str>,
    agent_run_id: Option<&str>,
) -> bool {
    filter
        .request_id
        .as_deref()
        .is_none_or(|expected| request_id == expected)
        && filter
            .trace_id
            .as_deref()
            .is_none_or(|expected| trace_id == Some(expected))
        && filter
            .agent_run_id
            .as_deref()
            .is_none_or(|expected| agent_run_id == Some(expected))
}

fn investigation_matches_request(filter: &GuardrailEvidenceFilter, log: &StoredRequestLog) -> bool {
    investigation_matches_tenant(filter, &log.tenant)
        && investigation_matches_ids(
            filter,
            &log.request_id,
            log.trace_id.as_deref(),
            log.agent_run_id.as_deref(),
        )
}

fn investigation_matches_agent_run(filter: &GuardrailEvidenceFilter, run: &StoredAgentRun) -> bool {
    investigation_matches_tenant(filter, &run.tenant)
        && investigation_matches_ids(
            filter,
            &run.request_id,
            run.trace_id.as_deref(),
            Some(&run.id),
        )
}

fn investigation_matches_agent_event(
    filter: &GuardrailEvidenceFilter,
    event: &StoredAgentRunEvent,
) -> bool {
    investigation_matches_tenant(filter, &event.tenant)
        && investigation_matches_ids(
            filter,
            &event.request_id,
            event.trace_id.as_deref(),
            Some(&event.run_id),
        )
}

fn investigation_matches_audit(filter: &GuardrailEvidenceFilter, event: &StoredAuditEvent) -> bool {
    investigation_matches_tenant(filter, &event.tenant)
        && investigation_matches_ids(
            filter,
            &event.request_id,
            event.trace_id.as_deref(),
            event.agent_run_id.as_deref(),
        )
}

fn investigation_matches_approval(
    filter: &GuardrailEvidenceFilter,
    approval: &ToolApprovalRecord,
    related_request_ids: &HashSet<&str>,
    related_trace_ids: &HashSet<&str>,
) -> bool {
    investigation_matches_tenant(filter, &approval.tenant)
        && filter
            .request_id
            .as_deref()
            .is_none_or(|expected| approval.request_id == expected)
        && filter
            .trace_id
            .as_deref()
            .is_none_or(|expected| approval.trace_id.as_deref() == Some(expected))
        && filter.agent_run_id.as_deref().is_none_or(|expected| {
            // #305: approvals now carry agent_run_id directly — match on it
            // first. The related-id back-fill below is kept ONLY as a
            // fallback for legacy records persisted before the field existed.
            approval.agent_run_id.as_deref() == Some(expected)
                || (approval.agent_run_id.is_none()
                    && (related_request_ids.contains(approval.request_id.as_str())
                        || approval
                            .trace_id
                            .as_deref()
                            .is_some_and(|trace_id| related_trace_ids.contains(trace_id))))
        })
}

fn investigation_matches_billing(filter: &GuardrailEvidenceFilter, event: &BillingEvent) -> bool {
    investigation_matches_tenant(filter, &event.tenant)
        && investigation_matches_ids(
            filter,
            &event.request_id,
            event.trace_id.as_deref(),
            event.agent_run_id.as_deref(),
        )
}

fn investigation_selector(filter: &GuardrailEvidenceFilter) -> String {
    if let Some(request_id) = &filter.request_id {
        format!("request_id={request_id}")
    } else if let Some(trace_id) = &filter.trace_id {
        format!("trace_id={trace_id}")
    } else if let Some(agent_run_id) = &filter.agent_run_id {
        format!("agent_run_id={agent_run_id}")
    } else {
        "unknown".to_string()
    }
}

fn investigation_final_outcome(
    requests: &[StoredRequestLog],
    guardrails: &[GuardrailEvaluationView],
) -> String {
    if guardrails.iter().any(|view| {
        view.evaluation.action == "block"
            && view.evaluation.enforcement_status == "enforced"
            && view.evaluation.verdict != "pass"
    }) {
        return "blocked".to_string();
    }
    if requests.iter().any(|request| request.status_code >= 500) {
        "failed".to_string()
    } else if requests.iter().any(|request| request.status_code >= 400) {
        "blocked".to_string()
    } else if requests.is_empty() {
        "decision_only".to_string()
    } else {
        "succeeded".to_string()
    }
}

fn sanitize_investigation_request(log: StoredRequestLog) -> InvestigationRequestEvidence {
    InvestigationRequestEvidence {
        request_id: log.request_id,
        trace_id: log.trace_id,
        agent_run_id: log.agent_run_id,
        workflow_id: log.workflow_id,
        workflow_version: log.workflow_version,
        workflow_node_id: log.workflow_node_id,
        tenant: log.tenant,
        route: log.route,
        provider: log.provider,
        logical_model: log.logical_model,
        provider_model: log.provider_model,
        status_code: log.status_code,
        error_code: log.error_code,
        cache_status: log.cache_status,
        started_at_unix: log.started_at_unix,
        completed_at_unix: log.completed_at_unix,
    }
}

fn sanitize_investigation_approval(approval: ToolApprovalRecord) -> InvestigationApprovalEvidence {
    InvestigationApprovalEvidence {
        id: approval.id,
        request_id: approval.request_id,
        trace_id: approval.trace_id,
        agent_run_id: approval.agent_run_id,
        workflow_id: approval.workflow_id,
        workflow_node_id: approval.workflow_node_id,
        tenant: approval.tenant,
        actor_api_key_id: approval.actor_api_key_id,
        tool_name: approval.tool_name,
        server_name: approval.server_name,
        route: approval.route,
        status: approval.status,
        reviewer_api_key_id: approval.reviewer_api_key_id,
        reviewer_authority: approval.reviewer_authority,
        terminal_reason: approval.terminal_reason,
        requested_at_unix: approval.requested_at_unix,
        expires_at_unix: approval.expires_at_unix,
        decided_at_unix: approval.decided_at_unix,
    }
}

fn sanitize_investigation_billing(event: BillingEvent) -> InvestigationBillingEvidence {
    InvestigationBillingEvidence {
        request_id: event.request_id,
        trace_id: event.trace_id,
        agent_run_id: event.agent_run_id,
        tenant: event.tenant,
        logical_model: event.logical_model,
        provider: event.provider,
        provider_model: event.provider_model,
        usage: event.usage,
        status_code: event.status_code,
        occurred_at_unix: event.occurred_at_unix,
        cost_usd: event.cost_usd,
        latency_ms: event.latency_ms,
        wallet_delta_credits: event.wallet_delta_credits,
        wallet_balance_after_credits: event.wallet_balance_after_credits,
    }
}

/// Normalize the investigation cost total so a zero-cost blocked request
/// serializes as `0.0`, never IEEE-754 negative zero (`-0.0`). Rust's
/// `Sum` for `f64` folds from `-0.0`, so summing an empty (or all-zero)
/// `billing_events` list yields `-0.0`, which `serde_json` renders as
/// `-0.0` -- cosmetically confusing in the `total_cost_usd` field of a
/// pre-provider guardrail block (issue #236). Adding `+ 0.0` maps `-0.0`
/// to `+0.0` while leaving every other value untouched.
fn normalize_investigation_cost(total: f64) -> f64 {
    total + 0.0
}

#[cfg(test)]
#[path = "state_guardrail_evidence_test.rs"]
mod state_guardrail_evidence_test;
