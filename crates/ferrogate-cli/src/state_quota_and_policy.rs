// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the P1-3/P1-4 quota/policy
// enforcement engine -- usage reports, effective-quota resolution,
// api-key token accounting, guardrail policy evaluation and matching.

use super::*;
use futures_util::future::join_all;

impl AppState {
    pub(crate) fn guardrail_policy_revision_views(
        &self,
        policy_id: Option<&str>,
    ) -> anyhow::Result<Vec<PolicyRevisionView>> {
        let bindings = self
            .repositories
            .list_guardrail_policy_bindings()?
            .into_iter()
            .map(|binding| (binding.policy_id.clone(), binding))
            .collect::<HashMap<_, _>>();
        let mut views = self
            .repositories
            .list_guardrail_policy_revisions(policy_id)?
            .into_iter()
            .map(|stored| {
                let revision = deserialize_guardrail_policy_revision(&stored)?;
                let status = bindings
                    .get(&revision.policy_id)
                    .map(|binding| {
                        if binding.active_revision == Some(revision.revision) {
                            PolicyRevisionStatus::Active
                        } else if binding.archived_revisions.contains(&revision.revision) {
                            PolicyRevisionStatus::Archived
                        } else {
                            PolicyRevisionStatus::Draft
                        }
                    })
                    .unwrap_or(PolicyRevisionStatus::Draft);
                Ok(PolicyRevisionView { revision, status })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        views.extend(
            self.guardrail_policies
                .iter()
                .filter(|policy| policy.revision.created_by == "static_config")
                .filter(|policy| {
                    policy_id.is_none_or(|policy_id| policy.revision.policy_id == policy_id)
                })
                .map(|policy| PolicyRevisionView {
                    revision: policy.revision.clone(),
                    status: PolicyRevisionStatus::Active,
                }),
        );
        views.sort_by(|left, right| {
            left.revision
                .policy_id
                .cmp(&right.revision.policy_id)
                .then_with(|| left.revision.revision.cmp(&right.revision.revision))
        });
        Ok(views)
    }

    pub(crate) fn guardrail_policy_revision_view(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> anyhow::Result<Option<PolicyRevisionView>> {
        Ok(self
            .guardrail_policy_revision_views(Some(policy_id))?
            .into_iter()
            .find(|view| view.revision.revision == revision))
    }

    pub(crate) fn guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> anyhow::Result<Option<StoredGuardrailPolicyBinding>> {
        Ok(self.repositories.get_guardrail_policy_binding(policy_id)?)
    }

    pub(crate) fn next_guardrail_policy_revision(&self, policy_id: &str) -> anyhow::Result<u32> {
        self.guardrail_policy_revision_views(Some(policy_id))?
            .into_iter()
            .map(|view| view.revision.revision)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("guardrail policy revision overflow"))
    }

    /// Filters (and optionally aggregates) the P1-4 monthly usage/cost
    /// rollups for the `/admin/v1/usage-reports` surface. `YYYY-MM` period
    /// strings sort and compare lexicographically, so `from_month`/
    /// `to_month` range bounds are plain string comparisons.
    pub(crate) fn usage_report(
        &self,
        filter: &UsageReportFilter,
    ) -> anyhow::Result<Vec<crate::responses::AdminUsageReportRow>> {
        if let Some(UsageReportGroupBy::Metadata(metadata_key)) = &filter.group_by {
            return Ok(self.metadata_usage_report(metadata_key, filter));
        }
        let rollups: Vec<StoredUsageMonthlyRollup> = self
            .list_usage_monthly_rollups()?
            .into_iter()
            .filter(|rollup| filter.matches(rollup))
            .collect();
        Ok(match &filter.group_by {
            None => rollups.into_iter().map(usage_report_row_raw).collect(),
            Some(UsageReportGroupBy::Metadata(_)) => unreachable!("handled above"),
            Some(UsageReportGroupBy::Scope) => {
                let mut groups: std::collections::BTreeMap<
                    (String, String),
                    crate::responses::AdminUsageReportRow,
                > = std::collections::BTreeMap::new();
                for rollup in rollups {
                    let key = (
                        rollup.scope_type.as_str().to_string(),
                        rollup.scope_id.clone(),
                    );
                    accumulate_usage_report_row(
                        groups.entry(key).or_insert_with(|| {
                            usage_report_row_zero(
                                Some(rollup.scope_type),
                                Some(&rollup.scope_id),
                                None,
                            )
                        }),
                        &rollup,
                    );
                }
                groups.into_values().collect()
            }
            Some(UsageReportGroupBy::PeriodMonth) => {
                let mut groups: std::collections::BTreeMap<
                    String,
                    crate::responses::AdminUsageReportRow,
                > = std::collections::BTreeMap::new();
                for rollup in rollups {
                    accumulate_usage_report_row(
                        groups
                            .entry(rollup.period_month.clone())
                            .or_insert_with(|| {
                                usage_report_row_zero(None, None, Some(&rollup.period_month))
                            }),
                        &rollup,
                    );
                }
                groups.into_values().collect()
            }
        })
    }

    /// `group_by=metadata.<key>` usage report (issue #171): one row per
    /// distinct value ever seen for `metadata_key`, summed across every
    /// period_month within `filter`'s range. Sourced from
    /// `usage_metadata_rollups`, an aggregation dimension orthogonal to the
    /// tenant/project/workspace/key scope chain `usage_monthly_rollups`
    /// covers -- `filter.scope_type`/`scope_id` don't apply here (a
    /// metadata rollup has no scope), only the period range does.
    fn metadata_usage_report(
        &self,
        metadata_key: &str,
        filter: &UsageReportFilter,
    ) -> Vec<crate::responses::AdminUsageReportRow> {
        let rollups = self
            .repositories
            .list_usage_metadata_rollups(metadata_key)
            .unwrap_or_default();
        let mut groups: std::collections::BTreeMap<String, crate::responses::AdminUsageReportRow> =
            std::collections::BTreeMap::new();
        for rollup in rollups {
            if let Some(from_month) = &filter.from_month {
                if rollup.period_month < *from_month {
                    continue;
                }
            }
            if let Some(to_month) = &filter.to_month {
                if rollup.period_month > *to_month {
                    continue;
                }
            }
            let row = groups
                .entry(rollup.metadata_value.clone())
                .or_insert_with(|| {
                    usage_metadata_report_row_zero(metadata_key, &rollup.metadata_value)
                });
            row.prompt_tokens += rollup.prompt_tokens;
            row.completion_tokens += rollup.completion_tokens;
            row.total_tokens += rollup.total_tokens;
            row.cost_usd += rollup.cost_usd;
            row.request_count += rollup.request_count;
            row.error_count += rollup.error_count;
        }
        groups.into_values().collect()
    }

    /// Resolve the effective (merged, capped) quota for a request's tenant
    /// attribution chain. Fetches at most 4 point-lookups (tenant/project/
    /// workspace/key), one per non-empty scope in `tenant`; any storage
    /// error here must be treated as fail-closed by the caller.
    pub(crate) fn resolve_effective_quota(
        &self,
        tenant: &ferrogate_core::TenantContext,
    ) -> anyhow::Result<EffectiveQuota> {
        let scopes: [(QuotaScopeKind, Option<&str>); 4] = [
            (QuotaScopeKind::Tenant, tenant.organization_id.as_deref()),
            (QuotaScopeKind::Project, tenant.project_id.as_deref()),
            (QuotaScopeKind::Workspace, tenant.workspace_id.as_deref()),
            (QuotaScopeKind::Key, tenant.api_key_id.as_deref()),
        ];
        let mut fetched: HashMap<(QuotaScopeKind, String), StoredQuotaPolicy> = HashMap::new();
        for (scope_type, scope_id) in scopes {
            let Some(scope_id) = scope_id else {
                continue;
            };
            if let Some(policy) = self.repositories.get_quota_policy(scope_type, scope_id)? {
                fetched.insert((scope_type, scope_id.to_string()), policy);
            }
        }
        let plan = match tenant.organization_id.as_deref() {
            Some(tenant_id) => self.resolve_tenant_plan(tenant_id)?,
            None => None,
        };
        Ok(resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: tenant.organization_id.as_deref(),
                project_id: tenant.project_id.as_deref(),
                workspace_id: tenant.workspace_id.as_deref(),
                key_id: tenant.api_key_id.as_deref(),
            },
            |scope_type, scope_id| fetched.get(&(scope_type, scope_id.to_string())).cloned(),
            plan.as_ref(),
        ))
    }

    pub(crate) fn api_key_total_tokens_used(&self, api_key_id: &str) -> u64 {
        self.repositories
            .usage_aggregates()
            .into_iter()
            .filter(|aggregate| aggregate.api_key_id.as_deref() == Some(api_key_id))
            .map(|aggregate| aggregate.usage.total_tokens)
            .sum()
    }

    #[cfg(test)]
    pub(crate) fn api_key_tokens_committed_or_reserved(
        &self,
        api_key_id: &str,
    ) -> anyhow::Result<u64> {
        self.cluster_counters
            .committed_or_reserved(api_key_id, self.api_key_total_tokens_used(api_key_id))
    }

    pub(crate) fn try_reserve_api_key_tokens(
        &self,
        api_key_id: &str,
        budget: u64,
        estimated_tokens: u64,
    ) -> anyhow::Result<Option<ApiKeyTokenReservation>> {
        let committed = self.api_key_total_tokens_used(api_key_id);
        self.cluster_counters
            .try_reserve_tokens(api_key_id, committed, budget, estimated_tokens)
    }

    pub(crate) fn evaluate_policy(
        &self,
        request: &RequestContext,
        model: Option<&str>,
        provider: Option<&str>,
    ) -> PolicyDecision {
        self.policy_engine.evaluate(request, model, provider)
    }

    pub(crate) async fn match_guardrail(
        &self,
        stage: GuardrailStage,
        context: GuardrailEvaluationContext<'_>,
    ) -> Option<GuardrailMatch> {
        let detector_stage = match stage {
            GuardrailStage::Request => DetectorStage::Request,
            GuardrailStage::Response => DetectorStage::Response,
        };
        let selection = PolicySelectionContext {
            organization_id: context.tenant.organization_id.as_deref(),
            project_id: context.tenant.project_id.as_deref(),
            workspace_id: context.tenant.workspace_id.as_deref(),
            api_key_id: context.tenant.api_key_id.as_deref(),
            service_account_id: context.service_account_id,
            gateway_config_id: context.gateway_config_id,
            model: context.model,
            provider: context.provider,
        };
        let mut enforcement = None;
        for policy in self
            .guardrail_policies
            .iter()
            .filter(|policy| policy.revision.scope.matches(selection))
        {
            if context.streaming
                && policy.revision.streaming == PolicyStreamingMode::RejectStreaming
            {
                let shadow = policy.revision.mode == PolicyMode::Shadow;
                self.record_guardrail_audit_event(AdminAuditEventDraft {
                    request_id: context.request_id.to_string(),
                    trace_id: context.trace_id.map(str::to_string),
                    agent_run_id: context.agent_run_id.map(str::to_string),
                    workflow_id: context.workflow_id.map(str::to_string),
                    workflow_version: context.workflow_version,
                    workflow_node_id: context.workflow_node_id.map(str::to_string),
                    actor_api_key_id: context.actor_api_key_id.map(str::to_string),
                    tenant: context.tenant.clone(),
                    action: "guardrail.policy_evaluate".to_string(),
                    target: policy.revision.immutable_id(),
                    outcome: if shadow { "shadow_fail" } else { "fail" }.to_string(),
                    message: "guardrail policy rejected streaming before provider dispatch"
                        .to_string(),
                })
                .await;
                if !shadow {
                    enforcement = Some(GuardrailMatch {
                        rule_id: policy.revision.policy_id.clone(),
                        rule_name: policy.revision.name.clone(),
                        policy_revision: policy.revision.revision,
                        check_id: None,
                        effect: GuardrailEffect::Deny,
                        matched_text: String::new(),
                        segment_id: None,
                        byte_start: None,
                        byte_end: None,
                        redaction_regex: None,
                        content_patches: Vec::new(),
                        code: "guardrail_streaming_unsupported".to_string(),
                        message: format!(
                            "guardrail policy '{}' does not allow streaming",
                            policy.revision.name
                        ),
                    });
                }
                continue;
            }
            let stage_checks = policy
                .checks
                .iter()
                .filter(|check| check.stage == detector_stage)
                .collect::<Vec<_>>();
            if !stage_checks.iter().any(|check| check.enabled) {
                continue;
            }
            let deadline = Instant::now() + Duration::from_millis(policy.revision.deadline_ms);
            let evaluations = match policy.revision.execution {
                PolicyExecution::Sequential => {
                    let mut evaluations = Vec::with_capacity(stage_checks.len());
                    for check in stage_checks {
                        evaluations.push(
                            evaluate_guardrail_check(check, detector_stage, context, deadline)
                                .await,
                        );
                    }
                    evaluations
                }
                PolicyExecution::Parallel => {
                    join_all(stage_checks.into_iter().map(|check| {
                        evaluate_guardrail_check(check, detector_stage, context, deadline)
                    }))
                    .await
                }
            };
            for evaluation in &evaluations {
                if let Some(error) = &evaluation.detector_error {
                    let detector_error_outcome = if evaluation.used_fallback {
                        "fallback"
                    } else if policy.revision.on_error.iter().any(|action| {
                        matches!(
                            action.kind,
                            GuardrailActionKind::Block | GuardrailActionKind::Redact
                        )
                    }) {
                        "blocked"
                    } else {
                        "recorded"
                    };
                    self.record_guardrail_detector_error(
                        policy,
                        &evaluation.check_id,
                        &context,
                        error,
                        detector_error_outcome,
                    )
                    .await;
                }
            }
            let aggregate = ferrogate_guardrails::aggregate_check_outcomes(
                &policy.revision.aggregation,
                &evaluations
                    .iter()
                    .map(|evaluation| evaluation.outcome)
                    .collect::<Vec<_>>(),
            );
            let actions = match aggregate {
                AggregateOutcome::Pass => &policy.revision.on_pass,
                AggregateOutcome::Fail => &policy.revision.on_fail,
                AggregateOutcome::Error => &policy.revision.on_error,
            };
            let effective_shadow = policy.revision.mode == PolicyMode::Shadow
                || (context.streaming
                    && detector_stage == DetectorStage::Response
                    && policy.revision.streaming == PolicyStreamingMode::ShadowAfterComplete);
            let not_enforced =
                context.streaming && detector_stage == DetectorStage::Response && effective_shadow;
            let outcome = match (not_enforced, effective_shadow, aggregate) {
                (true, _, _) => "not_enforced",
                (false, true, AggregateOutcome::Pass) => "shadow_pass",
                (false, true, AggregateOutcome::Fail) => "shadow_fail",
                (false, true, AggregateOutcome::Error) => "shadow_error",
                (false, false, AggregateOutcome::Pass) => "pass",
                (false, false, AggregateOutcome::Fail) => "fail",
                (false, false, AggregateOutcome::Error) => "error",
            };
            self.record_guardrail_audit_event(AdminAuditEventDraft {
                request_id: context.request_id.to_string(),
                trace_id: context.trace_id.map(str::to_string),
                agent_run_id: context.agent_run_id.map(str::to_string),
                workflow_id: context.workflow_id.map(str::to_string),
                workflow_version: context.workflow_version,
                workflow_node_id: context.workflow_node_id.map(str::to_string),
                actor_api_key_id: context.actor_api_key_id.map(str::to_string),
                tenant: context.tenant.clone(),
                action: "guardrail.policy_evaluate".to_string(),
                target: policy.revision.immutable_id(),
                outcome: outcome.to_string(),
                message: if not_enforced {
                    format!(
                        "streaming output completed before shadow evaluation; aggregate {aggregate:?} was not enforced"
                    )
                } else {
                    format!(
                        "guardrail policy evaluated {} checks with {} action(s)",
                        evaluations.len(),
                        actions.len()
                    )
                },
            })
            .await;
            if effective_shadow {
                continue;
            }
            if let Some(candidate) = guardrail_enforcement(policy, &evaluations, aggregate, actions)
            {
                let candidate_is_block = candidate.effect == GuardrailEffect::Deny;
                let current_is_block =
                    enforcement
                        .as_ref()
                        .is_some_and(|current: &GuardrailMatch| {
                            current.effect == GuardrailEffect::Deny
                        });
                if enforcement.is_none() || (candidate_is_block && !current_is_block) {
                    enforcement = Some(candidate);
                }
            }
        }
        enforcement
    }

    pub(crate) fn streaming_guardrail_plan(
        &self,
        selection: PolicySelectionContext<'_>,
    ) -> StreamingGuardrailPlan {
        let mut plan = StreamingGuardrailPlan::None;
        for policy in self
            .guardrail_policies
            .iter()
            .filter(|policy| policy.revision.scope.matches(selection))
            .filter(|policy| {
                policy
                    .checks
                    .iter()
                    .any(|check| check.enabled && check.stage == DetectorStage::Response)
            })
        {
            if policy.revision.streaming == PolicyStreamingMode::RejectStreaming {
                continue;
            }
            if policy.revision.mode == PolicyMode::Enforce
                && policy.revision.streaming == PolicyStreamingMode::BufferAndEnforce
            {
                return StreamingGuardrailPlan::BufferAndEnforce;
            }
            plan = StreamingGuardrailPlan::ShadowAfterComplete;
        }
        plan
    }

    pub(crate) fn record_guardrail_match(&self, guardrail: &GuardrailMatch) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_guardrail_match(guardrail.effect);
        }
    }

    pub(crate) async fn record_guardrail_stream_capture_overflow(
        &self,
        context: GuardrailEvaluationContext<'_>,
    ) {
        let selection = PolicySelectionContext {
            organization_id: context.tenant.organization_id.as_deref(),
            project_id: context.tenant.project_id.as_deref(),
            workspace_id: context.tenant.workspace_id.as_deref(),
            api_key_id: context.tenant.api_key_id.as_deref(),
            service_account_id: context.service_account_id,
            gateway_config_id: context.gateway_config_id,
            model: context.model,
            provider: context.provider,
        };
        let policies = self
            .guardrail_policies
            .iter()
            .filter(|policy| policy.revision.scope.matches(selection))
            .filter(|policy| {
                policy.revision.mode == PolicyMode::Shadow
                    || policy.revision.streaming == PolicyStreamingMode::ShadowAfterComplete
            })
            .filter(|policy| {
                policy
                    .checks
                    .iter()
                    .any(|check| check.enabled && check.stage == DetectorStage::Response)
            })
            .map(|policy| policy.revision.immutable_id())
            .collect::<Vec<_>>();
        for target in policies {
            self.record_guardrail_audit_event(AdminAuditEventDraft {
                request_id: context.request_id.to_string(),
                trace_id: context.trace_id.map(str::to_string),
                agent_run_id: context.agent_run_id.map(str::to_string),
                workflow_id: context.workflow_id.map(str::to_string),
                workflow_version: context.workflow_version,
                workflow_node_id: context.workflow_node_id.map(str::to_string),
                actor_api_key_id: context.actor_api_key_id.map(str::to_string),
                tenant: context.tenant.clone(),
                action: "guardrail.policy_evaluate".to_string(),
                target,
                outcome: "not_enforced".to_string(),
                message:
                    "streaming shadow capture exceeded its byte limit; evaluation was not enforced"
                        .to_string(),
            })
            .await;
        }
    }

    pub(crate) async fn guardrail_streaming_buffer_failure(
        &self,
        context: GuardrailEvaluationContext<'_>,
        error_code: &str,
    ) -> Option<GuardrailMatch> {
        let selection = PolicySelectionContext {
            organization_id: context.tenant.organization_id.as_deref(),
            project_id: context.tenant.project_id.as_deref(),
            workspace_id: context.tenant.workspace_id.as_deref(),
            api_key_id: context.tenant.api_key_id.as_deref(),
            service_account_id: context.service_account_id,
            gateway_config_id: context.gateway_config_id,
            model: context.model,
            provider: context.provider,
        };
        let policies = self
            .guardrail_policies
            .iter()
            .filter(|policy| policy.revision.scope.matches(selection))
            .filter(|policy| {
                policy.revision.mode == PolicyMode::Enforce
                    && policy.revision.streaming == PolicyStreamingMode::BufferAndEnforce
            })
            .filter(|policy| {
                policy
                    .checks
                    .iter()
                    .any(|check| check.enabled && check.stage == DetectorStage::Response)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut enforcement = None;
        for policy in policies {
            let selected_action = policy.revision.on_error.iter().find(|action| {
                matches!(
                    action.kind,
                    GuardrailActionKind::Block | GuardrailActionKind::Redact
                )
            });
            self.record_guardrail_audit_event(AdminAuditEventDraft {
                request_id: context.request_id.to_string(),
                trace_id: context.trace_id.map(str::to_string),
                agent_run_id: context.agent_run_id.map(str::to_string),
                workflow_id: context.workflow_id.map(str::to_string),
                workflow_version: context.workflow_version,
                workflow_node_id: context.workflow_node_id.map(str::to_string),
                actor_api_key_id: context.actor_api_key_id.map(str::to_string),
                tenant: context.tenant.clone(),
                action: "guardrail.policy_evaluate".to_string(),
                target: policy.revision.immutable_id(),
                outcome: "error".to_string(),
                message: format!(
                    "guarded streaming output failed before first-byte release with {error_code}"
                ),
            })
            .await;
            if enforcement.is_none() {
                if let Some(action) = selected_action {
                    enforcement = Some(GuardrailMatch {
                        rule_id: policy.revision.policy_id.clone(),
                        rule_name: policy.revision.name.clone(),
                        policy_revision: policy.revision.revision,
                        check_id: None,
                        effect: GuardrailEffect::Deny,
                        matched_text: String::new(),
                        segment_id: None,
                        byte_start: None,
                        byte_end: None,
                        redaction_regex: None,
                        content_patches: Vec::new(),
                        code: action
                            .code
                            .clone()
                            .unwrap_or_else(|| error_code.to_string()),
                        message: action.message.clone().unwrap_or_else(|| {
                            "guarded streaming output could not be evaluated safely".to_string()
                        }),
                    });
                }
            }
        }
        enforcement
    }

    async fn record_guardrail_detector_error(
        &self,
        policy: &GuardrailPolicyRuntime,
        check_id: &str,
        context: &GuardrailEvaluationContext<'_>,
        error: &DetectorError,
        outcome: &str,
    ) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_guardrail_detector_error();
        }
        warn!(
            request_id = %context.request_id,
            policy_revision = %policy.revision.immutable_id(),
            check_id,
            error_kind = error.kind.as_str(),
            outcome,
            "guardrail detector evaluation failed"
        );
        self.record_guardrail_audit_event(AdminAuditEventDraft {
            request_id: context.request_id.to_string(),
            trace_id: context.trace_id.map(str::to_string),
            agent_run_id: context.agent_run_id.map(str::to_string),
            workflow_id: context.workflow_id.map(str::to_string),
            workflow_version: context.workflow_version,
            workflow_node_id: context.workflow_node_id.map(str::to_string),
            actor_api_key_id: context.actor_api_key_id.map(str::to_string),
            tenant: context.tenant.clone(),
            action: "guardrail.detector_error".to_string(),
            target: format!("{}/{}", policy.revision.immutable_id(), check_id),
            outcome: outcome.to_string(),
            message: format!(
                "guardrail detector for policy {} check {} failed with {}",
                policy.revision.name,
                check_id,
                error.kind.as_str()
            ),
        })
        .await;
    }

    async fn record_guardrail_audit_event(&self, event: AdminAuditEventDraft) {
        if self.storage_status().durable {
            let state = self.clone();
            if let Err(error) =
                tokio::task::spawn_blocking(move || state.record_admin_audit_event(event)).await
            {
                warn!(error = %error, "guardrail audit persistence task failed");
            }
        } else {
            self.record_admin_audit_event(event);
        }
    }
}

#[derive(Debug)]
struct GuardrailCheckEvaluation {
    check_id: String,
    outcome: CheckOutcome,
    matched_text: String,
    segment_id: Option<String>,
    byte_start: Option<usize>,
    byte_end: Option<usize>,
    redaction_regex: Option<Regex>,
    content_patches: Vec<ContentPatch>,
    detector_error: Option<DetectorError>,
    used_fallback: bool,
}

async fn evaluate_guardrail_check(
    check: &GuardrailCheckRuntime,
    stage: DetectorStage,
    context: GuardrailEvaluationContext<'_>,
    deadline: Instant,
) -> GuardrailCheckEvaluation {
    if !check.enabled {
        return GuardrailCheckEvaluation::disabled(&check.id);
    }
    match &check.detector {
        GuardrailDetectorRuntime::Local(detector) => {
            local_guardrail_evaluation(&check.id, detector, &check.sources, context.envelope)
        }
        GuardrailDetectorRuntime::External(detector) => {
            let detector_text = context.envelope.flattened_text();
            let input = DetectorInput {
                stage,
                tenant: DetectorTenant {
                    organization_id: context.tenant.organization_id.as_deref(),
                    team_id: context.tenant.team_id.as_deref(),
                    project_id: context.tenant.project_id.as_deref(),
                    user_id: context.tenant.user_id.as_deref(),
                    api_key_id: context.tenant.api_key_id.as_deref(),
                },
                model: context.model,
                provider: context.provider,
                text: &detector_text,
                segments: &context.envelope.segments,
            };
            match detector.evaluate(&input, deadline).await {
                Ok(result) => external_guardrail_evaluation(&check.id, result, context.envelope),
                Err(error) => {
                    if let Some(fallback) = &check.fallback_detector {
                        let mut evaluation = local_guardrail_evaluation(
                            &check.id,
                            fallback,
                            &check.sources,
                            context.envelope,
                        );
                        evaluation.detector_error = Some(error);
                        evaluation.used_fallback = true;
                        evaluation
                    } else {
                        GuardrailCheckEvaluation {
                            check_id: check.id.clone(),
                            outcome: CheckOutcome::Error,
                            matched_text: String::new(),
                            segment_id: None,
                            byte_start: None,
                            byte_end: None,
                            redaction_regex: None,
                            content_patches: Vec::new(),
                            detector_error: Some(error),
                            used_fallback: false,
                        }
                    }
                }
            }
        }
    }
}

impl GuardrailCheckEvaluation {
    fn disabled(check_id: &str) -> Self {
        Self {
            check_id: check_id.to_string(),
            outcome: CheckOutcome::Disabled,
            matched_text: String::new(),
            segment_id: None,
            byte_start: None,
            byte_end: None,
            redaction_regex: None,
            content_patches: Vec::new(),
            detector_error: None,
            used_fallback: false,
        }
    }
}

fn external_guardrail_evaluation(
    check_id: &str,
    result: DetectorResult,
    envelope: &ferrogate_guardrails::GuardrailEnvelope,
) -> GuardrailCheckEvaluation {
    let finding = result.findings.first();
    let segment_id = finding
        .and_then(|finding| finding.segment_id.clone())
        .or_else(|| {
            (envelope.segments.len() == 1).then(|| envelope.segments[0].segment_id.clone())
        });
    GuardrailCheckEvaluation {
        check_id: check_id.to_string(),
        outcome: match result.verdict {
            DetectorVerdict::Pass => CheckOutcome::Pass,
            DetectorVerdict::Fail => CheckOutcome::Fail,
        },
        matched_text: result.first_matched_text().unwrap_or_default().to_string(),
        segment_id,
        byte_start: finding.and_then(|finding| finding.byte_start),
        byte_end: finding.and_then(|finding| finding.byte_end),
        redaction_regex: None,
        content_patches: result.patches,
        detector_error: None,
        used_fallback: false,
    }
}

fn local_guardrail_evaluation(
    check_id: &str,
    detector: &LocalGuardrailDetectorRuntime,
    sources: &[ferrogate_guardrails::ContentSource],
    envelope: &ferrogate_guardrails::GuardrailEnvelope,
) -> GuardrailCheckEvaluation {
    let matched = if let Some(max_input_bytes) = detector.max_input_bytes {
        let selected_bytes = envelope
            .segments
            .iter()
            .filter(|segment| sources.contains(&segment.source))
            .map(|segment| segment.text.len())
            .sum::<usize>();
        if selected_bytes > max_input_bytes {
            Some(("length".to_string(), None, None, None, None))
        } else {
            None
        }
    } else {
        None
    }
    .or_else(|| {
        envelope
            .segments
            .iter()
            .filter(|segment| sources.contains(&segment.source))
            .find_map(|segment| {
                detector.keywords.iter().find_map(|keyword| {
                    segment.text.find(keyword.as_str()).map(|start| {
                        (
                            keyword.clone(),
                            None,
                            Some(segment.segment_id.clone()),
                            Some(start),
                            Some(start + keyword.len()),
                        )
                    })
                })
            })
    })
    .or_else(|| {
        envelope
            .segments
            .iter()
            .filter(|segment| sources.contains(&segment.source))
            .find_map(|segment| {
                detector.regex.iter().find_map(|regex| {
                    regex.find(&segment.text).map(|matched| {
                        (
                            matched.as_str().to_string(),
                            Some(regex.clone()),
                            Some(segment.segment_id.clone()),
                            Some(matched.start()),
                            Some(matched.end()),
                        )
                    })
                })
            })
    });
    GuardrailCheckEvaluation {
        check_id: check_id.to_string(),
        outcome: if matched.is_some() {
            CheckOutcome::Fail
        } else {
            CheckOutcome::Pass
        },
        matched_text: matched
            .as_ref()
            .map(|matched| matched.0.clone())
            .unwrap_or_default(),
        segment_id: matched.as_ref().and_then(|matched| matched.2.clone()),
        byte_start: matched.as_ref().and_then(|matched| matched.3),
        byte_end: matched.as_ref().and_then(|matched| matched.4),
        redaction_regex: matched.and_then(|matched| matched.1),
        content_patches: Vec::new(),
        detector_error: None,
        used_fallback: false,
    }
}

fn guardrail_enforcement(
    policy: &GuardrailPolicyRuntime,
    evaluations: &[GuardrailCheckEvaluation],
    aggregate: AggregateOutcome,
    actions: &[PolicyAction],
) -> Option<GuardrailMatch> {
    let evidence = match aggregate {
        AggregateOutcome::Fail => evaluations
            .iter()
            .find(|evaluation| evaluation.outcome == CheckOutcome::Fail),
        AggregateOutcome::Error => evaluations
            .iter()
            .find(|evaluation| evaluation.outcome == CheckOutcome::Error),
        AggregateOutcome::Pass => evaluations.first(),
    };
    let mut selected = None;
    for action in actions {
        let effect = match action.kind {
            GuardrailActionKind::Allow | GuardrailActionKind::Record => continue,
            GuardrailActionKind::Block => GuardrailEffect::Deny,
            GuardrailActionKind::Redact => GuardrailEffect::Redact,
        };
        let mut candidate = GuardrailMatch {
            rule_id: policy.revision.policy_id.clone(),
            rule_name: policy.revision.name.clone(),
            policy_revision: policy.revision.revision,
            check_id: evidence.map(|evaluation| evaluation.check_id.clone()),
            effect,
            matched_text: evidence
                .map(|evaluation| evaluation.matched_text.clone())
                .unwrap_or_default(),
            segment_id: evidence.and_then(|evaluation| evaluation.segment_id.clone()),
            byte_start: evidence.and_then(|evaluation| evaluation.byte_start),
            byte_end: evidence.and_then(|evaluation| evaluation.byte_end),
            redaction_regex: evidence.and_then(|evaluation| evaluation.redaction_regex.clone()),
            content_patches: evidence
                .map(|evaluation| evaluation.content_patches.clone())
                .unwrap_or_default(),
            code: action
                .code
                .clone()
                .unwrap_or_else(|| "guardrail_blocked".to_string()),
            message: action
                .message
                .clone()
                .unwrap_or_else(|| "request blocked by guardrail policy".to_string()),
        };
        if candidate.effect == GuardrailEffect::Redact
            && candidate.content_patches.is_empty()
            && candidate.matched_text.is_empty()
        {
            candidate.effect = GuardrailEffect::Deny;
            candidate.code = "guardrail_invalid_redaction".to_string();
            candidate.message = format!(
                "guardrail policy '{}' could not produce safe redaction evidence",
                policy.revision.name
            );
        }
        if selected.is_none() || candidate.effect == GuardrailEffect::Deny {
            selected = Some(candidate);
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn match_guardrail_for_test<'a>(
        state: &AppState,
        stage: crate::config::GuardrailStage,
        tenant: &'a ferrogate_core::TenantContext,
        model: Option<&'a str>,
        provider: Option<&'a str>,
        body: &'a str,
    ) -> Option<GuardrailMatch> {
        match_guardrail_for_test_with_streaming(state, stage, tenant, model, provider, body, false)
    }

    fn match_guardrail_for_test_with_streaming<'a>(
        state: &AppState,
        stage: crate::config::GuardrailStage,
        tenant: &'a ferrogate_core::TenantContext,
        model: Option<&'a str>,
        provider: Option<&'a str>,
        body: &'a str,
        streaming: bool,
    ) -> Option<GuardrailMatch> {
        let detector_stage = match stage {
            crate::config::GuardrailStage::Request => DetectorStage::Request,
            crate::config::GuardrailStage::Response => DetectorStage::Response,
        };
        let envelope = ferrogate_guardrails::GuardrailEnvelope::from_text(
            ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
            detector_stage,
            ferrogate_guardrails::ContentSource::User,
            "test.body",
            body,
        );
        tokio::runtime::Runtime::new()
            .expect("test runtime")
            .block_on(state.match_guardrail(
                stage,
                GuardrailEvaluationContext {
                    request_id: "test-request",
                    trace_id: Some("test-trace"),
                    agent_run_id: None,
                    workflow_id: None,
                    workflow_version: None,
                    workflow_node_id: None,
                    actor_api_key_id: None,
                    tenant,
                    service_account_id: None,
                    gateway_config_id: None,
                    model,
                    provider,
                    streaming,
                    envelope: &envelope,
                },
            ))
    }

    fn test_provider() -> Provider {
        Provider {
            region: None,
            aws_access_key_id: None,
            aws_secret_access_key_env: None,
            aws_session_token_env: None,
            gcp_project_id: None,
            gcp_access_token_env: None,
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "http://127.0.0.1:10001/v1".into(),
            api_key_env: None,
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }
    }

    fn test_model() -> Model {
        Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-test".into(),
            routing_strategy: RoutingStrategy::default(),
            fallbacks: Vec::new(),
            visible_organization_ids: Vec::new(),
            visible_project_ids: Vec::new(),
            capabilities: Vec::new(),
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }
    }

    fn durable_guardrail_revision(
        policy_id: &str,
        revision: u32,
        keyword: &str,
        scope: PolicyScopeSelector,
    ) -> PolicyRevision {
        PolicyRevision {
            policy_id: policy_id.to_string(),
            revision,
            name: format!("{policy_id} revision {revision}"),
            description: None,
            enforced: true,
            scope,
            checks: vec![CheckBinding {
                id: "keyword".to_string(),
                enabled: true,
                stage: DetectorStage::Request,
                sources: ferrogate_guardrails::all_content_sources(),
                detector: DetectorDefinition::local(vec![keyword.to_string()], Vec::new(), None),
                fallback_detector: None,
            }],
            aggregation: PolicyAggregation::All,
            execution: PolicyExecution::Sequential,
            mode: PolicyMode::Enforce,
            streaming: PolicyStreamingMode::BufferAndEnforce,
            on_pass: vec![PolicyAction::allow()],
            on_fail: vec![PolicyAction::block(
                "durable_guardrail_blocked",
                "blocked by durable guardrail policy",
            )],
            on_error: vec![PolicyAction::block(
                "durable_guardrail_unavailable",
                "durable guardrail policy unavailable",
            )],
            deadline_ms: 2_000,
            created_at_unix: u64::from(revision),
            created_by: "test-admin".to_string(),
        }
    }

    #[test]
    fn immutable_policy_activation_and_rollback_change_the_live_evaluator() {
        let shared = SharedAppState::with_source_path(Config::default(), None);
        let first = durable_guardrail_revision(
            "durable-policy",
            1,
            "secret-v1",
            PolicyScopeSelector::default(),
        );
        shared
            .create_guardrail_policy_revision(first.clone())
            .expect("create first revision");
        assert!(shared
            .create_guardrail_policy_revision(first)
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        shared
            .activate_guardrail_policy_revision("durable-policy", 1, "test-admin", 10, false)
            .expect("activate first revision");
        assert!(match_guardrail_for_test(
            &shared.current(),
            GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "contains secret-v1"
        )
        .is_some());

        let second = durable_guardrail_revision(
            "durable-policy",
            2,
            "secret-v2",
            PolicyScopeSelector::default(),
        );
        shared
            .create_guardrail_policy_revision(second)
            .expect("create second revision");
        shared
            .activate_guardrail_policy_revision("durable-policy", 2, "test-admin", 20, false)
            .expect("activate second revision");
        assert!(match_guardrail_for_test(
            &shared.current(),
            GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "contains secret-v1"
        )
        .is_none());
        assert!(match_guardrail_for_test(
            &shared.current(),
            GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "contains secret-v2"
        )
        .is_some());

        shared
            .activate_guardrail_policy_revision("durable-policy", 1, "test-admin", 30, true)
            .expect("roll back first revision");
        assert!(match_guardrail_for_test(
            &shared.current(),
            GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "contains secret-v1"
        )
        .is_some());
        let views = shared
            .current()
            .guardrail_policy_revision_views(Some("durable-policy"))
            .unwrap();
        assert_eq!(views[0].status, PolicyRevisionStatus::Active);
        assert_eq!(views[1].status, PolicyRevisionStatus::Archived);
    }

    #[test]
    fn lower_scope_allow_action_cannot_remove_organization_enforcement() {
        let shared = SharedAppState::with_source_path(Config::default(), None);
        let organization = durable_guardrail_revision(
            "organization-policy",
            1,
            "secret",
            PolicyScopeSelector {
                organization_ids: vec!["org-a".to_string()],
                ..PolicyScopeSelector::default()
            },
        );
        let mut key = durable_guardrail_revision(
            "key-policy",
            1,
            "secret",
            PolicyScopeSelector {
                api_key_ids: vec!["key-a".to_string()],
                ..PolicyScopeSelector::default()
            },
        );
        key.on_fail = vec![PolicyAction::allow()];
        for policy in [organization, key] {
            let policy_id = policy.policy_id.clone();
            shared.create_guardrail_policy_revision(policy).unwrap();
            shared
                .activate_guardrail_policy_revision(&policy_id, 1, "test-admin", 1, false)
                .unwrap();
        }
        let tenant = ferrogate_core::TenantContext {
            organization_id: Some("org-a".to_string()),
            api_key_id: Some("key-a".to_string()),
            ..Default::default()
        };
        let matched = match_guardrail_for_test(
            &shared.current(),
            GuardrailStage::Request,
            &tenant,
            None,
            None,
            "contains secret",
        )
        .expect("organization policy must still block");
        assert_eq!(matched.rule_id, "organization-policy");
        assert_eq!(matched.policy_revision, 1);
    }

    #[test]
    fn sequential_and_parallel_execution_use_the_same_aggregation_semantics() {
        for execution in [PolicyExecution::Sequential, PolicyExecution::Parallel] {
            let shared = SharedAppState::with_source_path(Config::default(), None);
            let mut policy = durable_guardrail_revision(
                "execution-policy",
                1,
                "secret",
                PolicyScopeSelector::default(),
            );
            policy.execution = execution;
            policy.checks.push(CheckBinding {
                id: "non-match".to_string(),
                enabled: true,
                stage: DetectorStage::Request,
                sources: ferrogate_guardrails::all_content_sources(),
                detector: DetectorDefinition::local(
                    vec!["not-present".to_string()],
                    Vec::new(),
                    None,
                ),
                fallback_detector: None,
            });
            shared.create_guardrail_policy_revision(policy).unwrap();
            shared
                .activate_guardrail_policy_revision("execution-policy", 1, "test-admin", 1, false)
                .unwrap();
            assert!(match_guardrail_for_test(
                &shared.current(),
                GuardrailStage::Request,
                &ferrogate_core::TenantContext::default(),
                None,
                None,
                "contains secret"
            )
            .is_some());
        }
    }

    #[test]
    fn streaming_modes_reject_before_dispatch_or_force_shadow_evaluation() {
        let reject_state = SharedAppState::with_source_path(Config::default(), None);
        let mut reject = durable_guardrail_revision(
            "reject-streaming",
            1,
            "secret",
            PolicyScopeSelector::default(),
        );
        reject.streaming = PolicyStreamingMode::RejectStreaming;
        reject_state
            .create_guardrail_policy_revision(reject)
            .unwrap();
        reject_state
            .activate_guardrail_policy_revision("reject-streaming", 1, "test-admin", 1, false)
            .unwrap();
        let rejected = match_guardrail_for_test_with_streaming(
            &reject_state.current(),
            GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "safe",
            true,
        )
        .expect("reject_streaming must block before provider dispatch");
        assert_eq!(rejected.code, "guardrail_streaming_unsupported");

        let shadow_state = SharedAppState::with_source_path(Config::default(), None);
        let mut shadow = durable_guardrail_revision(
            "streaming-shadow",
            1,
            "secret",
            PolicyScopeSelector::default(),
        );
        shadow.streaming = PolicyStreamingMode::ShadowAfterComplete;
        shadow.checks[0].stage = DetectorStage::Response;
        shadow_state
            .create_guardrail_policy_revision(shadow)
            .unwrap();
        shadow_state
            .activate_guardrail_policy_revision("streaming-shadow", 1, "test-admin", 1, false)
            .unwrap();
        assert!(match_guardrail_for_test_with_streaming(
            &shadow_state.current(),
            GuardrailStage::Response,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "contains secret",
            true,
        )
        .is_none());
        assert!(shadow_state.current().audit_events().iter().any(|event| {
            event.action == "guardrail.policy_evaluate"
                && event.target == "streaming-shadow@1"
                && event.outcome == "not_enforced"
        }));
        assert_eq!(
            shadow_state
                .current()
                .streaming_guardrail_plan(PolicySelectionContext {
                    organization_id: None,
                    project_id: None,
                    workspace_id: None,
                    api_key_id: None,
                    service_account_id: None,
                    gateway_config_id: None,
                    model: None,
                    provider: None,
                }),
            StreamingGuardrailPlan::ShadowAfterComplete
        );
        assert!(match_guardrail_for_test(
            &shadow_state.current(),
            GuardrailStage::Response,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "contains secret",
        )
        .is_some());
    }

    #[test]
    fn streaming_buffer_limits_use_configured_error_action_and_sanitized_evidence() {
        let shared = SharedAppState::with_source_path(Config::default(), None);
        let mut policy = durable_guardrail_revision(
            "buffer-errors",
            1,
            "secret",
            PolicyScopeSelector::default(),
        );
        policy.checks[0].stage = DetectorStage::Response;
        shared.create_guardrail_policy_revision(policy).unwrap();
        shared
            .activate_guardrail_policy_revision("buffer-errors", 1, "test-admin", 1, false)
            .unwrap();

        let state = shared.current();
        let tenant = ferrogate_core::TenantContext::default();
        let envelope = ferrogate_guardrails::GuardrailEnvelope::from_text(
            ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
            DetectorStage::Response,
            ferrogate_guardrails::ContentSource::Assistant,
            "test.response",
            "sensitive-stream-body",
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for error_code in [
            "guardrail_stream_buffer_limit_exceeded",
            "guardrail_stream_buffer_timeout",
        ] {
            let matched = runtime
                .block_on(state.guardrail_streaming_buffer_failure(
                    GuardrailEvaluationContext {
                        request_id: error_code,
                        trace_id: None,
                        agent_run_id: None,
                        workflow_id: None,
                        workflow_version: None,
                        workflow_node_id: None,
                        actor_api_key_id: None,
                        tenant: &tenant,
                        service_account_id: None,
                        gateway_config_id: None,
                        model: Some("fast-chat"),
                        provider: Some("openai"),
                        streaming: true,
                        envelope: &envelope,
                    },
                    error_code,
                ))
                .expect("buffer failure must follow the configured block action");
            assert_eq!(matched.code, "durable_guardrail_unavailable");
        }

        let events = state
            .audit_events()
            .into_iter()
            .filter(|event| event.target == "buffer-errors@1")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| {
            event.action == "guardrail.policy_evaluate"
                && event.outcome == "error"
                && !event.message.contains("sensitive-stream-body")
        }));
        assert!(events.iter().any(|event| {
            event
                .message
                .contains("guardrail_stream_buffer_limit_exceeded")
        }));
        assert!(events
            .iter()
            .any(|event| { event.message.contains("guardrail_stream_buffer_timeout") }));
    }

    #[test]
    fn normalized_segments_inspect_every_chat_role_and_report_utf8_byte_ranges() {
        let envelope = ferrogate_guardrails::normalize_request(
            ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
            &serde_json::json!({
                "messages": [
                    {"role": "system", "content": "前缀秘密"},
                    {"role": "developer", "content": "developer-secret"},
                    {"role": "user", "content": "user-secret"},
                    {"role": "assistant", "tool_calls": [{"function": {"arguments": "{\"token\":\"argument-secret\"}"}}]},
                    {"role": "tool", "content": "result-secret"}
                ],
                "tools": [{"type": "function", "function": {"name": "schema-secret"}}],
                "metadata": {"case": "metadata-secret"}
            }),
        );
        for (keyword, expected_source) in [
            ("秘密", ferrogate_guardrails::ContentSource::System),
            (
                "developer-secret",
                ferrogate_guardrails::ContentSource::Developer,
            ),
            ("user-secret", ferrogate_guardrails::ContentSource::User),
            (
                "argument-secret",
                ferrogate_guardrails::ContentSource::ToolArguments,
            ),
            (
                "result-secret",
                ferrogate_guardrails::ContentSource::ToolResult,
            ),
            (
                "schema-secret",
                ferrogate_guardrails::ContentSource::ToolSchema,
            ),
            (
                "metadata-secret",
                ferrogate_guardrails::ContentSource::Metadata,
            ),
        ] {
            let evaluation = local_guardrail_evaluation(
                "normalized",
                &LocalGuardrailDetectorRuntime {
                    keywords: vec![keyword.to_string()],
                    regex: Vec::new(),
                    max_input_bytes: None,
                },
                &[expected_source],
                &envelope,
            );
            assert_eq!(evaluation.outcome, CheckOutcome::Fail, "{keyword}");
            let segment = envelope
                .segments
                .iter()
                .find(|segment| Some(&segment.segment_id) == evaluation.segment_id.as_ref())
                .expect("matched segment must exist");
            assert_eq!(segment.source, expected_source, "{keyword}");
            let start = segment.text.find(keyword).unwrap();
            assert_eq!(evaluation.byte_start, Some(start), "{keyword}");
            assert_eq!(
                evaluation.byte_end,
                Some(start + keyword.len()),
                "{keyword}"
            );
        }

        let excluded = local_guardrail_evaluation(
            "normalized",
            &LocalGuardrailDetectorRuntime {
                keywords: vec!["developer-secret".to_string()],
                regex: Vec::new(),
                max_input_bytes: None,
            },
            &[ferrogate_guardrails::ContentSource::User],
            &envelope,
        );
        assert_eq!(excluded.outcome, CheckOutcome::Pass);
    }

    #[test]
    fn matches_request_guardrail_by_tenant_model_provider_and_keyword() {
        let config = Config {
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: None,
                output_price_per_1m: None,
                enabled: true,
                cache_enabled: None,
            }],
            guardrails: vec![crate::config::GuardrailRule {
                id: "block-secret".into(),
                name: "Block secret".into(),
                enabled: true,
                stage: crate::config::GuardrailStage::Request,
                sources: ferrogate_guardrails::all_content_sources(),
                organization_ids: vec!["org_demo".into()],
                project_ids: vec!["project_demo".into()],
                api_key_ids: vec!["key_demo".into()],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                keywords: vec!["secret".into()],
                regex: vec![],
                max_input_bytes: None,
                provider: GuardrailProviderKind::None,
                provider_endpoint: None,
                provider_timeout_ms: 2_000,
                provider_runtime: Default::default(),
                effect: crate::config::GuardrailEffect::Deny,
                code: "guardrail_blocked".into(),
                message: "blocked by guardrail".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);
        let tenant = ferrogate_core::TenantContext {
            organization_id: Some("org_demo".into()),
            project_id: Some("project_demo".into()),
            api_key_id: Some("key_demo".into()),
            ..Default::default()
        };

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &tenant,
            Some("fast-chat"),
            Some("openai"),
            "contains secret",
        )
        .expect("guardrail should match");

        assert_eq!(matched.rule_id, "block-secret");
        assert_eq!(matched.rule_name, "Block secret");
        assert_eq!(matched.effect, crate::config::GuardrailEffect::Deny);
        assert_eq!(matched.matched_text, "secret");
        assert_eq!(matched.code, "guardrail_blocked");
        assert_eq!(matched.message, "blocked by guardrail");
    }

    #[test]
    fn ignores_disabled_guardrails() {
        let config = Config {
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: None,
                output_price_per_1m: None,
                enabled: true,
                cache_enabled: None,
            }],
            guardrails: vec![crate::config::GuardrailRule {
                id: "block-secret".into(),
                name: "Block secret".into(),
                enabled: false,
                stage: crate::config::GuardrailStage::Request,
                sources: ferrogate_guardrails::all_content_sources(),
                organization_ids: vec![],
                project_ids: vec![],
                api_key_ids: vec![],
                models: vec![],
                providers: vec![],
                keywords: vec!["secret".into()],
                regex: vec![],
                max_input_bytes: None,
                provider: GuardrailProviderKind::None,
                provider_endpoint: None,
                provider_timeout_ms: 2_000,
                provider_runtime: Default::default(),
                effect: crate::config::GuardrailEffect::Deny,
                code: "guardrail_blocked".into(),
                message: "blocked by guardrail".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        assert!(match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "contains secret"
        )
        .is_none());
    }

    #[test]
    fn matches_response_guardrail_with_redact_effect() {
        let config = Config {
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: None,
                output_price_per_1m: None,
                enabled: true,
                cache_enabled: None,
            }],
            guardrails: vec![crate::config::GuardrailRule {
                id: "redact-secret".into(),
                name: "Redact secret".into(),
                enabled: true,
                stage: crate::config::GuardrailStage::Response,
                sources: ferrogate_guardrails::all_content_sources(),
                organization_ids: vec![],
                project_ids: vec![],
                api_key_ids: vec![],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                keywords: vec!["secret".into()],
                regex: vec![],
                max_input_bytes: None,
                provider: GuardrailProviderKind::None,
                provider_endpoint: None,
                provider_timeout_ms: 2_000,
                provider_runtime: Default::default(),
                effect: crate::config::GuardrailEffect::Redact,
                code: "guardrail_redacted".into(),
                message: "redacted by guardrail".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Response,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "provider returned secret",
        )
        .expect("response guardrail should match");

        assert_eq!(matched.rule_id, "redact-secret");
        assert_eq!(matched.effect, crate::config::GuardrailEffect::Redact);
        state.record_guardrail_match(&matched);
        let snapshot = state.prometheus_metrics_snapshot();
        assert_eq!(snapshot.guardrail_match_total, 1);
        assert_eq!(snapshot.guardrail_denial_total, 0);
        assert_eq!(snapshot.guardrail_redaction_total, 1);
    }

    /// Spawns a one-shot plain-HTTP mock guardrail provider on `127.0.0.1`
    /// that reads a single `Content-Length`-bounded request, records its
    /// JSON body, and replies with `response_body`.
    fn spawn_guardrail_provider_mock(
        response_body: &'static str,
    ) -> (String, Arc<Mutex<Option<serde_json::Value>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(None));
        let server_captured = Arc::clone(&captured);

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "connection closed before request was complete");
                raw.extend_from_slice(&buffer[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let content_length: usize = String::from_utf8_lossy(&raw[..header_end])
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            while raw.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "connection closed before body was complete");
                raw.extend_from_slice(&buffer[..read]);
            }
            let body = &raw[header_end..header_end + content_length];
            *server_captured.lock().unwrap() = Some(serde_json::from_slice(body).unwrap());

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        (endpoint, captured)
    }

    fn custom_http_guardrail_rule(provider_endpoint: String) -> crate::config::GuardrailRule {
        crate::config::GuardrailRule {
            id: "pii-detector".into(),
            name: "External PII detector".into(),
            enabled: true,
            stage: crate::config::GuardrailStage::Request,
            sources: ferrogate_guardrails::all_content_sources(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec![],
            models: vec![],
            providers: vec![],
            keywords: vec![],
            regex: vec![],
            max_input_bytes: None,
            provider: GuardrailProviderKind::CustomHttp,
            provider_endpoint: Some(provider_endpoint),
            provider_timeout_ms: 2_000,
            provider_runtime: crate::config::GuardrailProviderRuntimeConfig {
                provider_allow_private_network: true,
                ..Default::default()
            },
            effect: crate::config::GuardrailEffect::Deny,
            code: "guardrail_pii_detected".into(),
            message: "blocked by external PII detector".into(),
        }
    }

    #[test]
    fn matches_guardrail_via_custom_http_provider_and_sends_request_context() {
        let (endpoint, captured) = spawn_guardrail_provider_mock(
            r#"{"match":true,"matched_text":"john@example.com","category":"pii"}"#,
        );
        let config = Config {
            providers: vec![test_provider()],
            models: vec![test_model()],
            guardrails: vec![custom_http_guardrail_rule(endpoint)],
            ..Config::default()
        };
        let state = AppState::new(config);
        let tenant = ferrogate_core::TenantContext {
            organization_id: Some("org_demo".into()),
            project_id: Some("project_demo".into()),
            ..Default::default()
        };

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &tenant,
            Some("fast-chat"),
            Some("openai"),
            "my email is john@example.com",
        )
        .expect("custom_http provider should report a match");

        assert_eq!(matched.rule_id, "pii-detector");
        assert_eq!(matched.effect, crate::config::GuardrailEffect::Deny);
        assert_eq!(matched.matched_text, "john@example.com");
        assert_eq!(
            matched.redact_text("my email is john@example.com"),
            "my email is [REDACTED]"
        );

        let request = captured.lock().unwrap().take().expect("request captured");
        assert_eq!(request["stage"], "request");
        assert_eq!(request["model"], "fast-chat");
        assert_eq!(request["provider"], "openai");
        assert_eq!(request["text"], "my email is john@example.com");
        assert_eq!(request["tenant"]["organization_id"], "org_demo");
        assert_eq!(request["tenant"]["project_id"], "project_demo");
    }

    #[test]
    fn custom_http_provider_no_match_returns_none() {
        let (endpoint, _captured) = spawn_guardrail_provider_mock(r#"{"match":false}"#);
        let config = Config {
            providers: vec![test_provider()],
            models: vec![test_model()],
            guardrails: vec![custom_http_guardrail_rule(endpoint)],
            ..Config::default()
        };
        let state = AppState::new(config);

        assert!(match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "nothing suspicious here",
        )
        .is_none());
    }

    #[test]
    fn custom_http_provider_failure_fails_closed_regardless_of_configured_effect() {
        // Bind then immediately drop the listener: the port is valid but
        // nothing is listening, so the connection is refused.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
        drop(listener);

        let mut rule = custom_http_guardrail_rule(endpoint);
        rule.effect = crate::config::GuardrailEffect::Redact;
        let config = Config {
            providers: vec![test_provider()],
            models: vec![test_model()],
            guardrails: vec![rule],
            ..Config::default()
        };
        let state = AppState::new(config);

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "hello",
        )
        .expect("unreachable provider must fail closed with a match");

        assert_eq!(matched.effect, crate::config::GuardrailEffect::Deny);
        assert_eq!(matched.code, "guardrail_provider_unavailable");
        assert!(matched.message.contains("External PII detector"));
        assert_eq!(
            state
                .prometheus_metrics_snapshot()
                .guardrail_detector_error_total,
            1
        );
        let audit = state.audit_events();
        let detector_error = audit
            .iter()
            .find(|event| event.action == "guardrail.detector_error")
            .expect("detector error audit");
        assert_eq!(detector_error.request_id, "test-request");
        assert_eq!(detector_error.target, "pii-detector@1/static-check");
        assert_eq!(detector_error.outcome, "blocked");
        assert!(audit.iter().any(|event| {
            event.action == "guardrail.policy_evaluate"
                && event.target == "pii-detector@1"
                && event.outcome == "error"
        }));
    }

    #[test]
    fn custom_http_provider_record_mode_audits_and_allows_on_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
        drop(listener);

        let mut rule = custom_http_guardrail_rule(endpoint);
        rule.provider_runtime.provider_on_error = GuardrailProviderErrorMode::Record;
        let state = AppState::new(Config {
            providers: vec![test_provider()],
            models: vec![test_model()],
            guardrails: vec![rule],
            ..Config::default()
        });

        assert!(match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "hello",
        )
        .is_none());
        assert_eq!(
            state
                .prometheus_metrics_snapshot()
                .guardrail_detector_error_total,
            1
        );
        let audit = state.audit_events();
        let detector_error = audit
            .iter()
            .find(|event| event.action == "guardrail.detector_error")
            .expect("detector error audit");
        assert_eq!(detector_error.outcome, "recorded");
        assert!(audit.iter().any(|event| {
            event.action == "guardrail.policy_evaluate"
                && event.target == "pii-detector@1"
                && event.outcome == "error"
        }));
    }

    #[test]
    fn custom_http_provider_fallback_mode_runs_local_detector_on_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
        drop(listener);

        let mut rule = custom_http_guardrail_rule(endpoint);
        rule.keywords = vec!["secret".into()];
        rule.provider_runtime.provider_on_error = GuardrailProviderErrorMode::FallbackDetector;
        let state = AppState::new(Config {
            providers: vec![test_provider()],
            models: vec![test_model()],
            guardrails: vec![rule],
            ..Config::default()
        });

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "contains secret",
        )
        .expect("local fallback detector should match");
        assert_eq!(matched.code, "guardrail_pii_detected");
        assert_eq!(matched.matched_text, "secret");
        assert_eq!(state.audit_events()[0].outcome, "fallback");
    }

    #[test]
    fn custom_http_provider_applies_typed_redaction_patches() {
        let (endpoint, _) = spawn_guardrail_provider_mock(
            r#"{"verdict":"fail","findings":[{"category":"pii","severity":"high","byte_start":6,"byte_end":22}],"patches":[{"byte_start":6,"byte_end":22,"replacement":"[EMAIL]"}],"detector_version":"test-1"}"#,
        );
        let mut rule = custom_http_guardrail_rule(endpoint);
        rule.stage = crate::config::GuardrailStage::Response;
        rule.effect = crate::config::GuardrailEffect::Redact;
        let state = AppState::new(Config {
            providers: vec![test_provider()],
            models: vec![test_model()],
            guardrails: vec![rule],
            ..Config::default()
        });

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Response,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "email john@example.com",
        )
        .expect("typed patch detector should match");
        assert_eq!(
            matched.redact_text("email john@example.com"),
            "email [EMAIL]"
        );
    }

    #[test]
    fn matches_regex_and_redacts_with_compiled_pattern() {
        let config = Config {
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: None,
                output_price_per_1m: None,
                enabled: true,
                cache_enabled: None,
            }],
            guardrails: vec![crate::config::GuardrailRule {
                id: "redact-token".into(),
                name: "Redact token".into(),
                enabled: true,
                stage: crate::config::GuardrailStage::Response,
                sources: ferrogate_guardrails::all_content_sources(),
                organization_ids: vec![],
                project_ids: vec![],
                api_key_ids: vec![],
                models: vec!["fast-chat".into()],
                providers: vec!["openai".into()],
                keywords: vec![],
                regex: vec![r"token-[0-9]+".into()],
                max_input_bytes: None,
                provider: GuardrailProviderKind::None,
                provider_endpoint: None,
                provider_timeout_ms: 2_000,
                provider_runtime: Default::default(),
                effect: crate::config::GuardrailEffect::Redact,
                code: "guardrail_redacted".into(),
                message: "redacted by guardrail".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Response,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "provider returned token-123 and token-456",
        )
        .expect("regex guardrail should match");

        assert_eq!(matched.rule_id, "redact-token");
        assert_eq!(matched.matched_text, "token-123");
        assert_eq!(
            matched.redact_text("provider returned token-123 and token-456"),
            "provider returned [REDACTED] and [REDACTED]"
        );
    }

    #[test]
    fn matches_request_max_input_bytes() {
        let config = Config {
            guardrails: vec![crate::config::GuardrailRule {
                id: "max-input".into(),
                name: "Max input".into(),
                enabled: true,
                stage: crate::config::GuardrailStage::Request,
                sources: ferrogate_guardrails::all_content_sources(),
                organization_ids: vec![],
                project_ids: vec![],
                api_key_ids: vec![],
                models: vec![],
                providers: vec![],
                keywords: vec![],
                regex: vec![],
                max_input_bytes: Some(8),
                provider: GuardrailProviderKind::None,
                provider_endpoint: None,
                provider_timeout_ms: 2_000,
                provider_runtime: Default::default(),
                effect: crate::config::GuardrailEffect::Deny,
                code: "guardrail_input_too_large".into(),
                message: "input is too large".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &ferrogate_core::TenantContext::default(),
            None,
            None,
            "012345678",
        )
        .expect("length guardrail should match");

        assert_eq!(matched.rule_id, "max-input");
        assert_eq!(matched.matched_text, "length");
        assert_eq!(matched.effect, crate::config::GuardrailEffect::Deny);
    }

    #[test]
    fn usage_report_filter_parses_scope_period_and_group_by_from_query() {
        let filter = UsageReportFilter::from_query(Some(
            "scope_type=workspace&scope_id=ws-1&from_month=2026-01&to_month=2026-03&group_by=period_month",
        ));
        assert_eq!(filter.scope_type, Some(QuotaScopeKind::Workspace));
        assert_eq!(filter.scope_id.as_deref(), Some("ws-1"));
        assert_eq!(filter.from_month.as_deref(), Some("2026-01"));
        assert_eq!(filter.to_month.as_deref(), Some("2026-03"));
        assert_eq!(filter.group_by, Some(UsageReportGroupBy::PeriodMonth));

        // `period_month` is a convenience alias that pins both bounds to the
        // same exact month.
        let exact = UsageReportFilter::from_query(Some("period_month=2026-05"));
        assert_eq!(exact.from_month.as_deref(), Some("2026-05"));
        assert_eq!(exact.to_month.as_deref(), Some("2026-05"));

        assert_eq!(
            UsageReportFilter::from_query(None),
            UsageReportFilter::default()
        );

        // group_by=metadata.<key> (issue #171) extracts the key verbatim;
        // an empty key (just "metadata.") or an unrecognized value parses
        // to no group_by rather than panicking.
        let metadata_filter = UsageReportFilter::from_query(Some("group_by=metadata.customer_id"));
        assert_eq!(
            metadata_filter.group_by,
            Some(UsageReportGroupBy::Metadata("customer_id".to_string()))
        );
        assert_eq!(
            UsageReportFilter::from_query(Some("group_by=metadata.")).group_by,
            None
        );
        assert_eq!(
            UsageReportFilter::from_query(Some("group_by=nonsense")).group_by,
            None
        );
    }

    #[test]
    fn usage_report_filters_by_scope_and_aggregates_with_group_by() {
        let config = Config {
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10002/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(2.0),
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        let request_for = |api_key_id: &str| RequestContext {
            request_id: format!("fg-{api_key_id}"),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: ferrogate_core::TenantContext {
                workspace_id: None,
                organization_id: Some("org-shared".into()),
                team_id: None,
                project_id: None,
                user_id: None,
                api_key_id: Some(api_key_id.into()),
            },
        };

        for api_key_id in ["key-a", "key-b"] {
            state
                .record_billing_event(
                    BillingEventDraft {
                        request: &request_for(api_key_id),
                        logical_model: "fast-chat",
                        provider: "openai",
                        provider_model: "gpt-4o-mini",
                        status_code: 200,
                        latency_ms: Some(10),
                        metadata: None,
                    },
                    &ProviderUsage {
                        prompt_tokens: Some(1000),
                        completion_tokens: Some(1000),
                        total_tokens: Some(2000),
                    },
                )
                .unwrap();
        }

        // Scoped to a single key: exactly one row, matching that key's own spend.
        let key_a_rows = state
            .usage_report(&UsageReportFilter {
                scope_type: Some(QuotaScopeKind::Key),
                scope_id: Some("key-a".into()),
                ..UsageReportFilter::default()
            })
            .unwrap();
        assert_eq!(key_a_rows.len(), 1);
        assert_eq!(key_a_rows[0].scope_id.as_deref(), Some("key-a"));
        assert!((key_a_rows[0].cost_usd - 0.003).abs() < 1e-9);
        assert_eq!(key_a_rows[0].request_count, 1);

        // Both keys roll up into a single tenant-scope row.
        let tenant_rows = state
            .usage_report(&UsageReportFilter {
                scope_type: Some(QuotaScopeKind::Tenant),
                scope_id: Some("org-shared".into()),
                ..UsageReportFilter::default()
            })
            .unwrap();
        assert_eq!(tenant_rows.len(), 1);
        assert!((tenant_rows[0].cost_usd - 0.006).abs() < 1e-9);
        assert_eq!(tenant_rows[0].request_count, 2);

        // A future-only window excludes every real (current-month) row.
        let out_of_range = state
            .usage_report(&UsageReportFilter {
                scope_type: Some(QuotaScopeKind::Key),
                from_month: Some("9999-12".into()),
                ..UsageReportFilter::default()
            })
            .unwrap();
        assert!(out_of_range.is_empty());

        // group_by=period_month sums both key-scope rows (same real month)
        // into a single row, dropping the per-scope identity.
        let grouped = state
            .usage_report(&UsageReportFilter {
                scope_type: Some(QuotaScopeKind::Key),
                group_by: Some(UsageReportGroupBy::PeriodMonth),
                ..UsageReportFilter::default()
            })
            .unwrap();
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].scope_type, None);
        assert_eq!(grouped[0].scope_id, None);
        assert!((grouped[0].cost_usd - 0.006).abs() < 1e-9);
        assert_eq!(grouped[0].request_count, 2);
    }
}
