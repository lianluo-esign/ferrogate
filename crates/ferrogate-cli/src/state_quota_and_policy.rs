// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the P1-3/P1-4 quota/policy
// enforcement engine -- usage reports, effective-quota resolution,
// api-key token accounting, guardrail policy evaluation and matching.

use super::*;
use futures_util::future::join_all;
use hmac::{Hmac, Mac};

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
    pub(crate) async fn usage_report(
        &self,
        filter: &UsageReportFilter,
    ) -> anyhow::Result<Vec<crate::responses::AdminUsageReportRow>> {
        if let Some(UsageReportGroupBy::Metadata(metadata_key)) = &filter.group_by {
            return Ok(self.metadata_usage_report(metadata_key, filter).await);
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
    async fn metadata_usage_report(
        &self,
        metadata_key: &str,
        filter: &UsageReportFilter,
    ) -> Vec<crate::responses::AdminUsageReportRow> {
        let rollups = self
            .repositories
            .list_usage_metadata_rollups(metadata_key)
            .await
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
    ///
    /// Stays a sync `fn` (unlike the rest of this file's storage-backed
    /// methods) because its only caller, `auth::finalize_auth`, is itself
    /// sync and shared by ~150 call sites plus a batch of sync `#[test]`
    /// fns -- converting the whole `authenticate` chain to async is out of
    /// scope for this migration slice. Bridges via the same
    /// `block_on_sync_bridge` helper already used for `wallet_balance_exhausted`.
    pub(crate) fn resolve_effective_quota(
        &self,
        tenant: &ferrogate_core::TenantContext,
    ) -> anyhow::Result<EffectiveQuota> {
        crate::gateway::block_on_sync_bridge(async {
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
                if let Some(policy) = self
                    .repositories
                    .get_quota_policy(scope_type, scope_id)
                    .await?
                {
                    fetched.insert((scope_type, scope_id.to_string()), policy);
                }
            }
            let plan = match tenant.organization_id.as_deref() {
                Some(tenant_id) => self.resolve_tenant_plan(tenant_id).await?,
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
        })
    }

    pub(crate) fn api_key_total_tokens_used(&self, api_key_id: &str) -> u64 {
        crate::gateway::block_on_sync_bridge(self.repositories.usage_aggregates())
            .into_iter()
            .filter(|aggregate| aggregate.api_key_id.as_deref() == Some(api_key_id))
            .map(|aggregate| aggregate.usage.total_tokens)
            .sum()
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
            managed_action: context.managed_action,
        };
        let mut enforcement = None;
        let mut pending_evidence = Vec::new();
        for policy in self
            .guardrail_policies
            .iter()
            .filter(|policy| policy.revision.scope.matches(selection))
        {
            if context.streaming
                && policy.revision.streaming == PolicyStreamingMode::RejectStreaming
            {
                let shadow = policy.revision.mode == PolicyMode::Shadow;
                let evidence_stage = policy
                    .checks
                    .iter()
                    .find(|check| check.enabled && check.stage == detector_stage)
                    .map(|check| check.stage)
                    .or_else(|| {
                        policy
                            .checks
                            .iter()
                            .find(|check| check.enabled)
                            .map(|check| check.stage)
                    })
                    .unwrap_or(detector_stage);
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
                let candidate = (!shadow).then(|| GuardrailMatch {
                    rule_id: policy.revision.policy_id.clone(),
                    rule_name: policy.revision.name.clone(),
                    policy_revision: policy.revision.revision,
                    check_id: None,
                    effect: GuardrailEffect::Deny,
                    segment_id: None,
                    byte_start: None,
                    byte_end: None,
                    content_patches: Vec::new(),
                    patch_envelope: None,
                    patch_sources: Vec::new(),
                    code: "guardrail_streaming_unsupported".to_string(),
                    message: format!(
                        "guardrail policy '{}' does not allow streaming",
                        policy.revision.name
                    ),
                });
                if let Some(candidate) = candidate.clone() {
                    merge_guardrail_enforcement(&mut enforcement, candidate);
                }
                pending_evidence.push(PendingGuardrailEvidence {
                    policy: policy.clone(),
                    stage: evidence_stage,
                    aggregate: AggregateOutcome::Fail,
                    actions: policy.revision.on_fail.clone(),
                    effective_shadow: shadow,
                    not_enforced: false,
                    evaluations: Vec::new(),
                    latency: Duration::ZERO,
                    candidate,
                    synthetic_check: Some(("skipped", "streaming_unsupported")),
                });
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
            let evaluation_started = Instant::now();
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
            let candidate = (!effective_shadow)
                .then(|| {
                    guardrail_enforcement(
                        policy,
                        &evaluations,
                        aggregate,
                        actions,
                        context.envelope,
                    )
                })
                .flatten();
            if let Some(candidate) = candidate.clone() {
                merge_guardrail_enforcement(&mut enforcement, candidate);
            }
            pending_evidence.push(PendingGuardrailEvidence {
                policy: policy.clone(),
                stage: detector_stage,
                aggregate,
                actions: actions.clone(),
                effective_shadow,
                not_enforced,
                evaluations,
                latency: evaluation_started.elapsed(),
                candidate,
                synthetic_check: None,
            });
        }
        for pending in pending_evidence {
            let applied = pending.candidate.as_ref().is_some_and(|candidate| {
                enforcement.as_ref().is_some_and(|selected| {
                    selected.rule_id == candidate.rule_id
                        && selected.policy_revision == candidate.policy_revision
                        && selected.effect == candidate.effect
                        && selected.check_id == candidate.check_id
                })
            });
            let evidence_accepted = self
                .record_guardrail_evaluation(
                    &pending.policy,
                    &context,
                    pending.stage,
                    pending.aggregate,
                    &pending.actions,
                    pending.effective_shadow,
                    pending.not_enforced,
                    &pending.evaluations,
                    pending.latency,
                    pending.candidate.as_ref(),
                    applied,
                    pending.synthetic_check,
                )
                .await;
            if !evidence_accepted {
                enforcement = Some(guardrail_evidence_unavailable_match(&pending.policy));
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

    pub(crate) fn record_guardrail_policy_cas_conflict(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_guardrail_policy_cas_conflict();
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
            managed_action: context.managed_action,
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
            .cloned()
            .collect::<Vec<_>>();
        for policy in policies {
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
                outcome: "not_enforced".to_string(),
                message:
                    "streaming shadow capture exceeded its byte limit; evaluation was not enforced"
                        .to_string(),
            })
            .await;
            self.record_guardrail_evaluation(
                &policy,
                &context,
                DetectorStage::Response,
                AggregateOutcome::Error,
                &policy.revision.on_error,
                true,
                true,
                &[],
                Duration::ZERO,
                None,
                false,
                Some(("error", "shadow_capture_overflow")),
            )
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
            managed_action: context.managed_action,
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
        let mut pending_evidence = Vec::new();
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
            let candidate = selected_action.map(|action| GuardrailMatch {
                rule_id: policy.revision.policy_id.clone(),
                rule_name: policy.revision.name.clone(),
                policy_revision: policy.revision.revision,
                check_id: None,
                effect: GuardrailEffect::Deny,
                segment_id: None,
                byte_start: None,
                byte_end: None,
                content_patches: Vec::new(),
                patch_envelope: None,
                patch_sources: Vec::new(),
                code: action
                    .code
                    .clone()
                    .unwrap_or_else(|| error_code.to_string()),
                message: action.message.clone().unwrap_or_else(|| {
                    "guarded streaming output could not be evaluated safely".to_string()
                }),
            });
            if let Some(candidate) = candidate.clone() {
                merge_guardrail_enforcement(&mut enforcement, candidate);
            }
            pending_evidence.push((policy, candidate));
        }
        for (policy, candidate) in pending_evidence {
            let applied = candidate.as_ref().is_some_and(|candidate| {
                enforcement.as_ref().is_some_and(|selected| {
                    selected.rule_id == candidate.rule_id
                        && selected.policy_revision == candidate.policy_revision
                        && selected.effect == candidate.effect
                })
            });
            self.record_guardrail_evaluation(
                &policy,
                &context,
                DetectorStage::Response,
                AggregateOutcome::Error,
                &policy.revision.on_error,
                false,
                false,
                &[],
                Duration::ZERO,
                candidate.as_ref(),
                applied,
                Some(("error", error_code)),
            )
            .await;
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
            let Ok(permit) = Arc::clone(&self.guardrail_evidence_permits).try_acquire_owned()
            else {
                if let Ok(mut metrics) = self.metrics.lock() {
                    metrics.record_guardrail_evidence_persistence_failure();
                }
                warn!("guardrail audit persistence queue is full");
                return;
            };
            let _task = tokio::task::spawn_blocking(move || {
                state.record_admin_audit_event(event);
                drop(permit);
            });
        } else {
            self.record_admin_audit_event(event);
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_guardrail_evaluation(
        &self,
        policy: &GuardrailPolicyRuntime,
        context: &GuardrailEvaluationContext<'_>,
        stage: DetectorStage,
        aggregate: AggregateOutcome,
        actions: &[PolicyAction],
        effective_shadow: bool,
        not_enforced: bool,
        evaluations: &[GuardrailCheckEvaluation],
        latency: Duration,
        candidate: Option<&GuardrailMatch>,
        applied: bool,
        synthetic_check: Option<(&str, &str)>,
    ) -> bool {
        let action = candidate
            .map(|candidate| match candidate.effect {
                GuardrailEffect::Deny => "block",
                GuardrailEffect::Redact => "redact",
            })
            .unwrap_or_else(|| guardrail_evidence_action(actions));
        let enforcement_status = if not_enforced {
            "not_enforced"
        } else if effective_shadow {
            "shadow_only"
        } else if candidate.is_some() && !applied {
            "not_enforced"
        } else {
            "enforced"
        };
        let verdict = guardrail_aggregate_outcome_name(aggregate);
        let evaluation_id =
            guardrail_evaluation_id(context.request_id, &policy.revision.immutable_id(), stage);
        let mut finding_category_counts = BTreeMap::new();
        let mut finding_count = 0_u64;
        for evaluation in evaluations {
            finding_count = finding_count.saturating_add(evaluation.finding_count);
            merge_finding_category_counts(
                &mut finding_category_counts,
                &evaluation.finding_category_counts,
            );
        }
        let (scope_type, scope_id) = guardrail_evidence_scope(context.tenant);
        let evaluation = StoredGuardrailEvaluation {
            id: evaluation_id.clone(),
            request_id: context.request_id.to_string(),
            trace_id: context.trace_id.map(str::to_string),
            agent_run_id: context.agent_run_id.map(str::to_string),
            subject_id: context.actor_api_key_id.map(str::to_string),
            tenant: context.tenant.clone(),
            scope_type,
            scope_id,
            target: guardrail_evidence_target(context.model, context.provider),
            protocol: guardrail_protocol_name(context.envelope.protocol).to_string(),
            stage: detector_stage_name(stage).to_string(),
            mode: guardrail_policy_mode_name(policy.revision.mode).to_string(),
            policy_id: policy.revision.policy_id.clone(),
            policy_revision: policy.revision.revision,
            verdict: verdict.to_string(),
            action: action.to_string(),
            enforcement_status: enforcement_status.to_string(),
            latency_ms: latency.as_millis().min(u128::from(u64::MAX)) as u64,
            finding_category_counts,
            finding_count,
            transformed: applied && action == "redact" && aggregate == AggregateOutcome::Fail,
            input_fingerprint: guardrail_envelope_fingerprint(
                context.envelope,
                context.tenant.organization_id.as_deref(),
                self.guardrail_evidence_hmac_key.as_deref(),
            ),
            occurred_at_unix: now_unix_seconds().unwrap_or_default(),
        };
        let checks = if let Some((verdict, error_kind)) = synthetic_check {
            policy
                .checks
                .iter()
                .filter(|check| check.enabled && check.stage == stage)
                .map(|check| StoredGuardrailCheckEvaluation {
                    id: format!("{evaluation_id}/{}", check.id),
                    evaluation_id: evaluation_id.clone(),
                    check_id: check.id.clone(),
                    detector_id: check.detector_id.clone(),
                    detector_version: "not_executed".to_string(),
                    config_digest: check.detector_config_digest.clone(),
                    verdict: verdict.to_string(),
                    action: action.to_string(),
                    enforcement_status: enforcement_status.to_string(),
                    latency_ms: 0,
                    finding_category_counts: BTreeMap::new(),
                    finding_count: 0,
                    transformed: false,
                    used_fallback: false,
                    error_kind: Some(sanitized_guardrail_evidence_token(
                        error_kind,
                        "streaming_error",
                    )),
                })
                .collect::<Vec<_>>()
        } else {
            evaluations
                .iter()
                .map(|result| {
                    let runtime = policy
                        .checks
                        .iter()
                        .find(|check| check.id == result.check_id);
                    StoredGuardrailCheckEvaluation {
                        id: format!("{evaluation_id}/{}", result.check_id),
                        evaluation_id: evaluation_id.clone(),
                        check_id: result.check_id.clone(),
                        detector_id: runtime
                            .map(|check| check.detector_id.clone())
                            .unwrap_or_else(|| "unknown".to_string()),
                        detector_version: result.detector_version.clone(),
                        config_digest: runtime
                            .map(|check| check.detector_config_digest.clone())
                            .unwrap_or_else(|| "sha256:unknown".to_string()),
                        verdict: guardrail_check_outcome_name(result.outcome).to_string(),
                        action: action.to_string(),
                        enforcement_status: enforcement_status.to_string(),
                        latency_ms: result.latency_ms,
                        finding_category_counts: result.finding_category_counts.clone(),
                        finding_count: result.finding_count,
                        transformed: applied
                            && action == "redact"
                            && candidate.and_then(|candidate| candidate.check_id.as_ref())
                                == Some(&result.check_id)
                            && result.outcome == CheckOutcome::Fail,
                        used_fallback: result.used_fallback,
                        error_kind: result
                            .detector_error
                            .as_ref()
                            .map(|error| error.kind.as_str().to_string()),
                    }
                })
                .collect::<Vec<_>>()
        };

        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_guardrail_evaluation(verdict, enforcement_status);
        }
        if self.storage_status().durable {
            let Ok(permit) = Arc::clone(&self.guardrail_evidence_permits).try_acquire_owned()
            else {
                if let Ok(mut metrics) = self.metrics.lock() {
                    metrics.record_guardrail_evidence_persistence_failure();
                }
                warn!(
                    request_id = %context.request_id,
                    policy_revision = %policy.revision.immutable_id(),
                    "guardrail evaluation persistence queue is full; failing closed"
                );
                return false;
            };
            let repositories = Arc::clone(&self.repositories);
            let metrics = Arc::clone(&self.metrics);
            let request_id = context.request_id.to_string();
            let policy_revision = policy.revision.immutable_id();
            let _task = tokio::task::spawn_blocking(move || {
                let persistence = repositories
                    .append_guardrail_evaluation(evaluation, checks)
                    .map_err(|error| anyhow::anyhow!("{error}"));
                drop(permit);
                if let Err(error) = persistence {
                    if let Ok(mut metrics) = metrics.lock() {
                        metrics.record_guardrail_evidence_persistence_failure();
                    }
                    warn!(
                        request_id = %request_id,
                        policy_revision = %policy_revision,
                        error = %error,
                        "guardrail evaluation evidence persistence failed"
                    );
                }
            });
            return true;
        }
        if let Err(error) = self
            .repositories
            .append_guardrail_evaluation(evaluation, checks)
        {
            if let Ok(mut metrics) = self.metrics.lock() {
                metrics.record_guardrail_evidence_persistence_failure();
            }
            warn!(
                request_id = %context.request_id,
                policy_revision = %policy.revision.immutable_id(),
                error = %error,
                "guardrail evaluation evidence persistence failed"
            );
            return false;
        }
        true
    }
}

fn guardrail_evaluation_id(
    request_id: &str,
    policy_revision: &str,
    stage: DetectorStage,
) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "guardrail-eval-{request_id}-{policy_revision}-{}-{nanos}",
        detector_stage_name(stage)
    )
}

fn guardrail_evidence_scope(tenant: &ferrogate_core::TenantContext) -> (String, String) {
    if let Some(api_key_id) = &tenant.api_key_id {
        ("api_key".to_string(), api_key_id.clone())
    } else if let Some(workspace_id) = &tenant.workspace_id {
        ("workspace".to_string(), workspace_id.clone())
    } else if let Some(project_id) = &tenant.project_id {
        ("project".to_string(), project_id.clone())
    } else if let Some(organization_id) = &tenant.organization_id {
        ("tenant".to_string(), organization_id.clone())
    } else {
        ("global".to_string(), "global".to_string())
    }
}

fn guardrail_evidence_target(model: Option<&str>, provider: Option<&str>) -> String {
    format!(
        "model={};provider={}",
        model.unwrap_or("unknown"),
        provider.unwrap_or("unknown")
    )
}

fn guardrail_evidence_action(actions: &[PolicyAction]) -> &'static str {
    if actions
        .iter()
        .any(|action| action.kind == GuardrailActionKind::Block)
    {
        "block"
    } else if actions
        .iter()
        .any(|action| action.kind == GuardrailActionKind::Redact)
    {
        "redact"
    } else if actions
        .iter()
        .any(|action| action.kind == GuardrailActionKind::Record)
    {
        "record"
    } else {
        "allow"
    }
}

fn guardrail_aggregate_outcome_name(outcome: AggregateOutcome) -> &'static str {
    match outcome {
        AggregateOutcome::Pass => "pass",
        AggregateOutcome::Fail => "fail",
        AggregateOutcome::Error => "error",
    }
}

fn guardrail_check_outcome_name(outcome: CheckOutcome) -> &'static str {
    match outcome {
        CheckOutcome::Pass => "pass",
        CheckOutcome::Fail => "fail",
        CheckOutcome::Error => "error",
        CheckOutcome::Disabled => "skipped",
    }
}

fn detector_stage_name(stage: DetectorStage) -> &'static str {
    match stage {
        DetectorStage::Request => "request",
        DetectorStage::Response => "response",
    }
}

fn guardrail_protocol_name(protocol: ferrogate_guardrails::GuardrailProtocol) -> &'static str {
    match protocol {
        ferrogate_guardrails::GuardrailProtocol::ChatCompletions => "chat_completions",
        ferrogate_guardrails::GuardrailProtocol::Responses => "responses",
        ferrogate_guardrails::GuardrailProtocol::Embeddings => "embeddings",
        ferrogate_guardrails::GuardrailProtocol::ManagedAction => "managed_action",
    }
}

fn guardrail_policy_mode_name(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Enforce => "enforce",
        PolicyMode::Shadow => "shadow",
    }
}

fn guardrail_envelope_fingerprint(
    envelope: &ferrogate_guardrails::GuardrailEnvelope,
    tenant_id: Option<&str>,
    key: Option<&[u8]>,
) -> String {
    let Some(key) = key else {
        return "hmac-sha256:unavailable".to_string();
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return "hmac-sha256:unavailable".to_string();
    };
    mac.update(tenant_id.unwrap_or("platform").as_bytes());
    mac.update(&[0]);
    mac.update(guardrail_protocol_name(envelope.protocol).as_bytes());
    mac.update(&[0]);
    mac.update(detector_stage_name(envelope.stage).as_bytes());
    for segment in &envelope.segments {
        mac.update(&[0]);
        mac.update(segment.fingerprint.as_bytes());
    }
    format!("hmac-sha256:{:x}", mac.finalize().into_bytes())
}

fn merge_finding_category_counts(
    target: &mut BTreeMap<String, u64>,
    source: &BTreeMap<String, u64>,
) {
    for (category, count) in source {
        let current = target.entry(category.clone()).or_insert(0);
        *current = current.saturating_add(*count);
    }
}

#[derive(Debug)]
struct GuardrailCheckEvaluation {
    check_id: String,
    outcome: CheckOutcome,
    segment_id: Option<String>,
    byte_start: Option<usize>,
    byte_end: Option<usize>,
    content_patches: Vec<ContentPatch>,
    detector_error: Option<DetectorError>,
    used_fallback: bool,
    detector_version: String,
    latency_ms: u64,
    finding_category_counts: BTreeMap<String, u64>,
    finding_count: u64,
}

#[derive(Debug)]
struct PendingGuardrailEvidence {
    policy: GuardrailPolicyRuntime,
    stage: DetectorStage,
    aggregate: AggregateOutcome,
    actions: Vec<PolicyAction>,
    effective_shadow: bool,
    not_enforced: bool,
    evaluations: Vec<GuardrailCheckEvaluation>,
    latency: Duration,
    candidate: Option<GuardrailMatch>,
    synthetic_check: Option<(&'static str, &'static str)>,
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
    let started = Instant::now();
    let detector_text = context.envelope.flattened_text();
    let input = DetectorInput {
        protocol: context.envelope.protocol,
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
    let mut evaluation = match check.detector.evaluate(&input, deadline).await {
        Ok(result) => match validate_content_patch_permissions(
            context.envelope,
            &check.sources,
            &result.patches,
        ) {
            Ok(()) => external_guardrail_evaluation(&check.id, result, context.envelope),
            Err(error) => GuardrailCheckEvaluation::error(&check.id, error),
        },
        Err(error) => {
            if let Some(fallback) = &check.fallback_detector {
                match fallback.evaluate(&input, deadline).await {
                    Ok(result) => match validate_content_patch_permissions(
                        context.envelope,
                        &check.sources,
                        &result.patches,
                    ) {
                        Ok(()) => {
                            let mut evaluation =
                                external_guardrail_evaluation(&check.id, result, context.envelope);
                            evaluation.detector_error = Some(error);
                            evaluation.used_fallback = true;
                            evaluation
                        }
                        Err(error) => GuardrailCheckEvaluation::error(&check.id, error),
                    },
                    Err(_) => GuardrailCheckEvaluation::error(&check.id, error),
                }
            } else {
                GuardrailCheckEvaluation::error(&check.id, error)
            }
        }
    };
    evaluation.latency_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    evaluation
}

impl GuardrailCheckEvaluation {
    fn disabled(check_id: &str) -> Self {
        Self {
            check_id: check_id.to_string(),
            outcome: CheckOutcome::Disabled,
            segment_id: None,
            byte_start: None,
            byte_end: None,
            content_patches: Vec::new(),
            detector_error: None,
            used_fallback: false,
            detector_version: "disabled".to_string(),
            latency_ms: 0,
            finding_category_counts: BTreeMap::new(),
            finding_count: 0,
        }
    }

    fn error(check_id: &str, error: DetectorError) -> Self {
        Self {
            check_id: check_id.to_string(),
            outcome: CheckOutcome::Error,
            segment_id: None,
            byte_start: None,
            byte_end: None,
            content_patches: Vec::new(),
            detector_error: Some(error),
            used_fallback: false,
            detector_version: "unavailable".to_string(),
            latency_ms: 0,
            finding_category_counts: BTreeMap::new(),
            finding_count: 0,
        }
    }
}

fn external_guardrail_evaluation(
    check_id: &str,
    result: DetectorResult,
    envelope: &ferrogate_guardrails::GuardrailEnvelope,
) -> GuardrailCheckEvaluation {
    let finding = result.findings.first();
    let finding_count = result.findings.len() as u64;
    let mut finding_category_counts = BTreeMap::new();
    for finding in &result.findings {
        let category = sanitized_guardrail_evidence_token(&finding.category, "uncategorized");
        let count = finding_category_counts.entry(category).or_insert(0_u64);
        *count = count.saturating_add(1);
    }
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
        segment_id,
        byte_start: finding.and_then(|finding| finding.byte_start),
        byte_end: finding.and_then(|finding| finding.byte_end),
        content_patches: result.patches,
        detector_error: None,
        used_fallback: false,
        detector_version: sanitized_guardrail_evidence_token(&result.detector_version, "unknown"),
        latency_ms: 0,
        finding_category_counts,
        finding_count,
    }
}

fn sanitized_guardrail_evidence_token(value: &str, fallback: &str) -> String {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
    {
        return fallback.to_string();
    }
    value.to_string()
}
fn guardrail_enforcement(
    policy: &GuardrailPolicyRuntime,
    evaluations: &[GuardrailCheckEvaluation],
    aggregate: AggregateOutcome,
    actions: &[PolicyAction],
    envelope: &GuardrailEnvelope,
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
            // #200: RequireApproval/Quarantine are managed-action kinds; their
            // real enforcement (approval gating, output quarantine) is wired in
            // #200 slices 3/4. On this model-content path there is no inline
            // approval or output-hold, so they fail closed conservatively:
            // require-approval → deny, quarantine → withhold (redact).
            GuardrailActionKind::RequireApproval => GuardrailEffect::Deny,
            GuardrailActionKind::Quarantine => GuardrailEffect::Redact,
        };
        let mut candidate = GuardrailMatch {
            rule_id: policy.revision.policy_id.clone(),
            rule_name: policy.revision.name.clone(),
            policy_revision: policy.revision.revision,
            check_id: evidence.map(|evaluation| evaluation.check_id.clone()),
            effect,
            segment_id: evidence.and_then(|evaluation| evaluation.segment_id.clone()),
            byte_start: evidence.and_then(|evaluation| evaluation.byte_start),
            byte_end: evidence.and_then(|evaluation| evaluation.byte_end),
            content_patches: evidence
                .map(|evaluation| evaluation.content_patches.clone())
                .unwrap_or_default(),
            patch_envelope: Some(envelope.clone()),
            patch_sources: evidence
                .and_then(|evaluation| {
                    policy
                        .checks
                        .iter()
                        .find(|check| check.id == evaluation.check_id)
                })
                .map(|check| check.sources.clone())
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
        if candidate.effect == GuardrailEffect::Redact && candidate.content_patches.is_empty() {
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

fn merge_guardrail_enforcement(
    enforcement: &mut Option<GuardrailMatch>,
    candidate: GuardrailMatch,
) {
    let candidate_is_block = candidate.effect == GuardrailEffect::Deny;
    let current_is_block = enforcement
        .as_ref()
        .is_some_and(|current| current.effect == GuardrailEffect::Deny);
    if enforcement.is_none() || (candidate_is_block && !current_is_block) {
        *enforcement = Some(candidate);
    }
}

fn guardrail_evidence_unavailable_match(policy: &GuardrailPolicyRuntime) -> GuardrailMatch {
    GuardrailMatch {
        rule_id: policy.revision.policy_id.clone(),
        rule_name: policy.revision.name.clone(),
        policy_revision: policy.revision.revision,
        check_id: None,
        effect: GuardrailEffect::Deny,
        segment_id: None,
        byte_start: None,
        byte_end: None,
        content_patches: Vec::new(),
        patch_envelope: None,
        patch_sources: Vec::new(),
        code: "guardrail_evidence_unavailable".to_string(),
        message: "guardrail evidence capacity is unavailable; request denied".to_string(),
    }
}

#[cfg(test)]
#[path = "state_quota_and_policy_test.rs"]
mod state_quota_and_policy_test;
