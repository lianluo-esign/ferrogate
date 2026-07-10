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
        let envelope = match stage {
            crate::config::GuardrailStage::Request => {
                ferrogate_guardrails::GuardrailEnvelope::from_text(
                    ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
                    detector_stage,
                    ferrogate_guardrails::ContentSource::User,
                    "messages[0].content",
                    body,
                )
            }
            crate::config::GuardrailStage::Response => {
                let response = serde_json::json!({
                    "choices": [{"message": {"role": "assistant", "content": body}}]
                });
                ferrogate_guardrails::normalize_response(
                    ferrogate_guardrails::GuardrailProtocol::ChatCompletions,
                    &serde_json::to_vec(&response).expect("response fixture"),
                    false,
                )
            }
        };
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
    fn guardrail_evidence_records_sanitized_overall_and_per_check_decisions() {
        let shared = SharedAppState::with_source_path(Config::default(), None);
        shared
            .create_guardrail_policy_revision(durable_guardrail_revision(
                "evidence-policy",
                1,
                "raw-secret-must-not-persist",
                PolicyScopeSelector::default(),
            ))
            .unwrap();
        shared
            .activate_guardrail_policy_revision("evidence-policy", 1, "test-admin", 10, false)
            .unwrap();
        let tenant = ferrogate_core::TenantContext {
            organization_id: Some("tenant-evidence".to_string()),
            api_key_id: Some("key-evidence".to_string()),
            ..ferrogate_core::TenantContext::default()
        };
        let state = shared.current();
        assert!(match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Request,
            &tenant,
            Some("fast-chat"),
            Some("openai"),
            "raw-secret-must-not-persist",
        )
        .is_some());

        let evaluations = state.repositories.list_guardrail_evaluations(None).unwrap();
        let checks = state
            .repositories
            .list_guardrail_check_evaluations(None)
            .unwrap();
        assert_eq!(evaluations.len(), 1);
        assert_eq!(evaluations[0].verdict, "fail");
        assert_eq!(evaluations[0].action, "block");
        assert_eq!(evaluations[0].enforcement_status, "enforced");
        assert_eq!(evaluations[0].finding_category_counts["contains"], 1);
        assert!(evaluations[0].input_fingerprint.starts_with("hmac-sha256:"));
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].verdict, "fail");
        assert_eq!(checks[0].detector_id, "ferrogate.local");
        assert_eq!(checks[0].detector_version, "deterministic/1");
        let encoded = serde_json::to_string(&(evaluations, checks)).unwrap();
        assert!(!encoded.contains("raw-secret-must-not-persist"));
        assert!(!encoded.contains("matched_text"));
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
    fn structured_policy_activation_compiles_json_schema_into_live_runtime() {
        let shared = SharedAppState::with_source_path(Config::default(), None);
        let mut revision = durable_guardrail_revision(
            "structured-policy",
            1,
            "unused-legacy-keyword",
            PolicyScopeSelector::default(),
        );
        revision.checks[0].sources = vec![ferrogate_guardrails::ContentSource::Metadata];
        revision.checks[0].detector = serde_json::from_value(serde_json::json!({
            "kind": "local",
            "json": {
                "schema": {
                    "type": "object",
                    "required": ["safe"],
                    "properties": {"safe": {"type": "boolean"}}
                },
                "required_keys": ["/safe"],
                "forbidden_keys": ["/credential"]
            }
        }))
        .unwrap();
        shared
            .create_guardrail_policy_revision(revision)
            .expect("create structured revision");
        shared
            .activate_guardrail_policy_revision("structured-policy", 1, "test-admin", 10, false)
            .expect("compile and activate structured revision");
        assert_eq!(
            shared
                .current()
                .guardrail_policy_binding("structured-policy")
                .unwrap()
                .unwrap()
                .active_revision,
            Some(1)
        );
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
        reject.checks[0].stage = DetectorStage::Response;
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
        let rejected_checks = reject_state
            .current()
            .repositories
            .list_guardrail_check_evaluations(None)
            .unwrap();
        assert_eq!(rejected_checks.len(), 1);
        assert_eq!(rejected_checks[0].verdict, "skipped");
        assert_eq!(
            rejected_checks[0].error_kind.as_deref(),
            Some("streaming_unsupported")
        );

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
            let detector = DeterministicDetector::new(DeterministicDetectorConfig {
                id: "normalized".to_string(),
                supported_sources: vec![expected_source],
                keywords: vec![keyword.to_string()],
                regex: Vec::new(),
                max_input_bytes: None,
                json: None,
                request: None,
                secret_patterns: Vec::new(),
                fingerprint_key: None,
            })
            .unwrap();
            let text = envelope.flattened_text();
            let result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(detector.evaluate(
                    &DetectorInput {
                        protocol: envelope.protocol,
                        stage: envelope.stage,
                        tenant: DetectorTenant {
                            organization_id: None,
                            team_id: None,
                            project_id: None,
                            user_id: None,
                            api_key_id: None,
                        },
                        model: None,
                        provider: None,
                        text: &text,
                        segments: &envelope.segments,
                    },
                    Instant::now() + Duration::from_secs(1),
                ))
                .unwrap();
            let evaluation = external_guardrail_evaluation("normalized", result, &envelope);
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

        let excluded_detector = DeterministicDetector::new(DeterministicDetectorConfig {
            id: "normalized".to_string(),
            supported_sources: vec![ferrogate_guardrails::ContentSource::User],
            keywords: vec!["developer-secret".to_string()],
            regex: Vec::new(),
            max_input_bytes: None,
            json: None,
            request: None,
            secret_patterns: Vec::new(),
            fingerprint_key: None,
        })
        .unwrap();
        let text = envelope.flattened_text();
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(excluded_detector.evaluate(
                &DetectorInput {
                    protocol: envelope.protocol,
                    stage: envelope.stage,
                    tenant: DetectorTenant {
                        organization_id: None,
                        team_id: None,
                        project_id: None,
                        user_id: None,
                        api_key_id: None,
                    },
                    model: None,
                    provider: None,
                    text: &text,
                    segments: &envelope.segments,
                },
                Instant::now() + Duration::from_secs(1),
            ))
            .unwrap();
        let excluded = external_guardrail_evaluation("normalized", result, &envelope);
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

    #[test]
    fn later_block_marks_an_earlier_redaction_as_not_enforced() {
        let base = crate::config::GuardrailRule {
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
        };
        let mut block = base.clone();
        block.id = "block-secret".into();
        block.name = "Block secret".into();
        block.effect = crate::config::GuardrailEffect::Deny;
        block.code = "guardrail_blocked".into();
        let state = AppState::new(Config {
            providers: vec![test_provider()],
            models: vec![test_model()],
            guardrails: vec![base, block],
            ..Config::default()
        });

        let matched = match_guardrail_for_test(
            &state,
            crate::config::GuardrailStage::Response,
            &ferrogate_core::TenantContext::default(),
            Some("fast-chat"),
            Some("openai"),
            "provider returned secret",
        )
        .expect("the blocking policy must win");
        assert_eq!(matched.rule_id, "block-secret");

        let evaluations = state.repositories.list_guardrail_evaluations(None).unwrap();
        let redaction = evaluations
            .iter()
            .find(|evaluation| evaluation.policy_id == "redact-secret")
            .unwrap();
        let block = evaluations
            .iter()
            .find(|evaluation| evaluation.policy_id == "block-secret")
            .unwrap();
        assert_eq!(redaction.action, "redact");
        assert_eq!(redaction.enforcement_status, "not_enforced");
        assert!(!redaction.transformed);
        assert_eq!(block.action, "block");
        assert_eq!(block.enforcement_status, "enforced");
        assert!(!block.transformed);
    }

    /// Spawns a one-shot plain-HTTP mock guardrail provider on `127.0.0.1`
    /// that reads a single `Content-Length`-bounded request, records its
    /// JSON body, and replies with `response_body`.
    fn spawn_guardrail_provider_mock(
        response_body: impl Into<String>,
    ) -> (String, Arc<Mutex<Option<serde_json::Value>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(None));
        let server_captured = Arc::clone(&captured);
        let response_body = response_body.into();

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
        assert_eq!(
            matched.redact_text("my email is john@example.com"),
            "[REDACTED]"
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
        let evidence = state
            .repositories
            .list_guardrail_check_evaluations(None)
            .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].verdict, "error");
        assert_eq!(evidence[0].action, "block");
        assert_eq!(evidence[0].enforcement_status, "enforced");
        assert_eq!(evidence[0].error_kind.as_deref(), Some("unavailable"));
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
        let evaluation = state.repositories.list_guardrail_evaluations(None).unwrap();
        assert_eq!(evaluation[0].verdict, "error");
        assert_eq!(evaluation[0].action, "record");
        assert_eq!(evaluation[0].enforcement_status, "enforced");
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
        assert_eq!(state.audit_events()[0].outcome, "fallback");
    }

    #[test]
    fn custom_http_provider_applies_typed_redaction_patches() {
        let content = "email john@example.com";
        let fingerprint = ferrogate_guardrails::content_fingerprint(content);
        let (endpoint, _) = spawn_guardrail_provider_mock(
            serde_json::json!({
                "verdict": "fail",
                "findings": [{
                    "category": "pii",
                    "severity": "high",
                    "segment_id": "chat:0",
                    "byte_start": 6,
                    "byte_end": 22
                }],
                "patches": [{
                    "segment_id": "chat:0",
                    "expected_fingerprint": fingerprint,
                    "protocol_location": "choices[0].message.content",
                    "byte_start": 6,
                    "byte_end": 22,
                    "replacement": "[EMAIL]"
                }],
                "detector_version": "test-1"
            })
            .to_string(),
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
            content,
        )
        .expect("typed patch detector should match");
        let response = serde_json::json!({
            "model": "must-not-change",
            "choices": [{"message": {"role": "assistant", "content": content}}]
        })
        .to_string();
        let redacted: serde_json::Value =
            serde_json::from_str(&matched.redact_text(&response)).unwrap();
        assert_eq!(
            redacted["choices"][0]["message"]["content"],
            "email [EMAIL]"
        );
        assert_eq!(redacted["model"], "must-not-change");
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
        let response = serde_json::json!({
            "model": "must-not-change",
            "choices": [{"message": {
                "role": "assistant",
                "content": "provider returned token-123 and token-456"
            }}]
        })
        .to_string();
        let redacted: serde_json::Value =
            serde_json::from_str(&matched.redact_text(&response)).unwrap();
        assert_eq!(
            redacted["choices"][0]["message"]["content"],
            "provider returned [REDACTED] and [REDACTED]"
        );
        assert_eq!(redacted["model"], "must-not-change");
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
