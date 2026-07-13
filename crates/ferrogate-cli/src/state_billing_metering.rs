// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for billing-event recording, the durable
// billing-report outbox, metering/usage admin views, request-log
// recording+redaction, and the Prometheus metrics snapshot.

use super::*;

impl AppState {
    #[cfg(test)]
    pub(crate) fn record_billing_event(
        &self,
        draft: BillingEventDraft<'_>,
        usage: &ProviderUsage,
    ) -> Result<(), ferrogate_billing::BillingError> {
        let provider_attempt = ProviderAttempt::for_request(&draft.request.request_id, 0);
        self.record_provider_attempt_billing_event(draft, &provider_attempt, usage)
    }

    pub(crate) fn record_provider_attempt_billing_event(
        &self,
        draft: BillingEventDraft<'_>,
        provider_attempt: &ProviderAttempt,
        usage: &ProviderUsage,
    ) -> Result<(), ferrogate_billing::BillingError> {
        let usage = BillingTokenUsage::new(
            usage.prompt_tokens.unwrap_or_default(),
            usage.completion_tokens.unwrap_or_default(),
            usage.total_tokens.unwrap_or_default(),
        )
        .estimate_missing_total();
        self.record_billing_token_usage(
            BillingTokenUsageDraft {
                request: draft.request,
                logical_model: draft.logical_model,
                provider: draft.provider,
                provider_model: draft.provider_model,
                usage: &usage,
                usage_source: BillingUsageSource::ProviderUsage,
                status_code: draft.status_code,
                latency_ms: draft.latency_ms,
                metadata: draft.metadata,
            },
            provider_attempt,
        )
    }

    #[cfg(test)]
    pub(crate) fn record_estimated_billing_event(
        &self,
        draft: BillingEventDraft<'_>,
        usage: &BillingTokenUsage,
    ) -> Result<(), ferrogate_billing::BillingError> {
        let provider_attempt = ProviderAttempt::for_request(&draft.request.request_id, 0);
        self.record_estimated_provider_attempt_billing_event(draft, &provider_attempt, usage)
    }

    pub(crate) fn record_estimated_provider_attempt_billing_event(
        &self,
        draft: BillingEventDraft<'_>,
        provider_attempt: &ProviderAttempt,
        usage: &BillingTokenUsage,
    ) -> Result<(), ferrogate_billing::BillingError> {
        self.record_billing_token_usage(
            BillingTokenUsageDraft {
                request: draft.request,
                logical_model: draft.logical_model,
                provider: draft.provider,
                provider_model: draft.provider_model,
                usage,
                usage_source: BillingUsageSource::GatewayEstimate,
                status_code: draft.status_code,
                latency_ms: draft.latency_ms,
                metadata: draft.metadata,
            },
            provider_attempt,
        )
    }

    fn record_billing_token_usage(
        &self,
        draft: BillingTokenUsageDraft<'_>,
        provider_attempt: &ProviderAttempt,
    ) -> Result<(), ferrogate_billing::BillingError> {
        // Reconcile a missing prompt/completion split against total_tokens
        // before pricing (issue #145): some providers report only a total, and
        // pricing prompt/completion directly without this would settle
        // cost_usd = Some(0.0) for real usage, which the ledger then honors
        // verbatim as authoritative (issue #135). reconcile_split() is a
        // superset of estimate_missing_total() (it also fills a missing total
        // from the split), so a single call covers both directions.
        let usage = draft.usage.clone().reconcile_split();
        let cost_usd = settled_cost_usd(
            &self.model_registry,
            draft.logical_model,
            draft.provider,
            draft.provider_model,
            &usage,
        );
        // Prepaid-credit wallet debit (issue #169): a no-op for tenants
        // without a wallet row (opt-in), so this never affects a request
        // outside the prepaid-billing path. Computed *before* building
        // `event` (rather than after recording it, as this used to do) so
        // the outcome can be attached to the event itself and carried
        // through to the standalone billing service's ledger
        // (`GET /v1/billing/ledger` showing wallet debits alongside cost/
        // credit fields is one of #169's acceptance criteria) -- the debit
        // still happens exactly once, here, before anything is recorded;
        // the billing service only ever mirrors this outcome, never
        // computes or applies its own (see `BillingEvent::wallet_delta_credits`'s
        // doc comment in `ferrogate-billing`).
        let mut event = BillingEvent {
            request_id: draft.request.request_id.clone(),
            trace_id: draft.request.trace_id.clone(),
            provider_attempt: provider_attempt.clone(),
            agent_run_id: draft.request.agent_run_id.clone(),
            workflow_id: draft.request.workflow_id.clone(),
            workflow_version: draft.request.workflow_version,
            workflow_node_id: draft.request.workflow_node_id.clone(),
            cluster_id: Some(self.cluster_identity.cluster_id.clone()),
            node_id: Some(self.cluster_identity.node_id.clone()),
            tenant: draft.request.tenant.clone(),
            logical_model: draft.logical_model.into(),
            provider: draft.provider.into(),
            provider_model: draft.provider_model.into(),
            usage: usage.clone(),
            usage_source: draft.usage_source,
            status_code: draft.status_code,
            // Stamp the actual settlement time (issue #153): leaving this None
            // meant every billing_ledger row had a NULL occurred_at_unix,
            // making idx_billing_ledger_tenant_time unusable for time-scoped
            // tenant queries/reporting.
            occurred_at_unix: now_unix_seconds(),
            cost_usd,
            latency_ms: draft.latency_ms,
            metadata: draft.metadata.cloned().unwrap_or_default(),
            wallet_delta_credits: None,
            wallet_balance_after_credits: None,
        };
        let settlement_id = ferrogate_billing::ledger::ledger_entry_id(&event);
        let wallet_debit = cost_usd.and_then(|cost_usd| {
            self.debit_wallet_for_settled_cost(&draft.request.tenant, cost_usd, &settlement_id)
        });
        event.wallet_delta_credits = wallet_debit.as_ref().map(|outcome| outcome.delta_credits);
        event.wallet_balance_after_credits = wallet_debit
            .as_ref()
            .map(|outcome| outcome.balance_after_credits);
        // Durably enqueue the settled usage for delivery to the standalone
        // billing service (issues #131/#137) in the SAME call as the metering
        // write rather than a second sequential synchronous round-trip (issue
        // #150): `append_billing_event_with_outbox_enqueue` commits both in one
        // Postgres transaction. Rather than a fire-and-forget POST that would
        // be lost if billing is unavailable, the event is written to a
        // persistent outbox and a background sweeper delivers it (idempotent
        // on the ledger entry id), so a charge survives a billing outage or a
        // gateway restart.
        let recorded = if self.billing_reporter.is_some() {
            let entry_id = ferrogate_billing::ledger::ledger_entry_id(&event);
            let now = now_unix_seconds().unwrap_or_default() as i64;
            let outcome = self
                .repositories
                .append_billing_event_with_outbox_enqueue(event.clone(), &entry_id, now)
                .map_err(|error| {
                    ferrogate_billing::BillingError::new(
                        "billing_persistence_failed",
                        format!("failed to persist billing event: {error}"),
                    )
                })?;
            if let Some(error) = outcome.enqueue_error {
                // Distinguishable from a successful enqueue (issue #151): this
                // is the narrow window where the charge is lost despite the
                // durable-outbox design, since nothing retries the enqueue
                // write itself. Surface it as a counter (not just a log line)
                // so operators can alert on it.
                if let Ok(mut metrics) = self.metrics.lock() {
                    metrics.record_billing_report_enqueue_failure();
                }
                warn!(
                    request_id = %event.request_id,
                    error = %error,
                    "failed to enqueue billing report for durable delivery"
                );
            }
            outcome.recorded
        } else {
            self.repositories
                .append_billing_event(event.clone())
                .map_err(|error| {
                    ferrogate_billing::BillingError::new(
                        "billing_persistence_failed",
                        format!("failed to persist billing event: {error}"),
                    )
                })?
        };
        if !recorded {
            return Ok(());
        }
        self.metering_events.record(event.clone())?;
        self.record_billing_metrics(&event);
        if let Some(exporter) = &self.metering_exporter {
            exporter.export_event(event.clone());
        }
        if let Some(api_key_id) = &draft.request.tenant.api_key_id {
            if let Err(error) = self
                .cluster_counters
                .record_used_tokens(api_key_id, usage.total_tokens)
            {
                warn!(
                    api_key_id = %api_key_id,
                    total_tokens = usage.total_tokens,
                    error = %error,
                    "failed to record shared token counter usage"
                );
            }
        }
        // Runs after the rollup update this settled request just committed
        // (both `append_billing_event` paths increment
        // `usage_monthly_rollups` synchronously), so spend read here
        // reflects this request (issue #170).
        self.dispatch_budget_threshold_alerts(&draft.request.tenant);
        Ok(())
    }

    /// Deliver one batch of pending billing reports from the durable outbox to
    /// the billing service (issue #137): delete rows that deliver successfully
    /// and reschedule failures with capped exponential backoff. After
    /// [`MAX_BILLING_OUTBOX_ATTEMPTS`] failures, a report is dead-lettered
    /// instead of retried forever (issue #143) — it stops consuming sweeper
    /// batch capacity but is kept for operator inspection. Idempotent on the
    /// billing side, so replay never double-bills. A no-op when billing
    /// reporting is disabled.
    pub(crate) fn sweep_billing_outbox_once(&self) {
        let Some(reporter) = self.billing_reporter.clone() else {
            return;
        };
        let now = now_unix_seconds().unwrap_or_default() as i64;
        let due = match self
            .repositories
            .list_due_billing_reports(now, BILLING_OUTBOX_BATCH)
        {
            Ok(entries) => entries,
            Err(error) => {
                warn!(error = %error, "failed to list due billing reports");
                return;
            }
        };
        for entry in due {
            match reporter.deliver_once(&entry.event) {
                Ok(()) => {
                    if let Err(error) = self.repositories.delete_billing_report(&entry.id) {
                        warn!(id = %entry.id, error = %error, "failed to delete delivered billing report");
                    }
                }
                Err(error) => {
                    let attempts_after = entry.attempts.saturating_add(1);
                    if attempts_after >= MAX_BILLING_OUTBOX_ATTEMPTS {
                        if let Err(dead_letter_error) =
                            self.repositories.dead_letter_billing_report(&entry.id, now)
                        {
                            warn!(id = %entry.id, error = %dead_letter_error, "failed to dead-letter billing report");
                        }
                        warn!(
                            id = %entry.id,
                            attempts = attempts_after,
                            error = %error,
                            "billing report delivery failed permanently; dead-lettering after max attempts"
                        );
                        continue;
                    }
                    let next = now.saturating_add(billing_outbox_backoff_secs(entry.attempts));
                    if let Err(reschedule_error) =
                        self.repositories.reschedule_billing_report(&entry.id, next)
                    {
                        warn!(id = %entry.id, error = %reschedule_error, "failed to reschedule billing report");
                    }
                    warn!(
                        id = %entry.id,
                        attempts = entry.attempts,
                        error = %error,
                        "billing report delivery failed; will retry"
                    );
                }
            }
        }
    }

    /// List dead-lettered billing outbox entries for operator inspection
    /// (issue #143).
    pub(crate) fn billing_outbox_dead_letters(
        &self,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        self.repositories.list_dead_lettered_billing_reports(500)
    }

    #[cfg(test)]
    pub(crate) fn billing_events(&self) -> Vec<BillingEvent> {
        let persisted = self.repositories.billing_events();
        if persisted.is_empty() {
            self.metering_events.list()
        } else {
            persisted
        }
    }

    /// See [`AppState::request_logs_page`]'s `tenant_scope` doc (issue
    /// #185); same rationale applies to metering/billing events.
    pub(crate) fn metering_events_page(
        &self,
        pagination: AdminPagination,
        tenant_scope: Option<&str>,
    ) -> AdminPage<BillingEvent> {
        if let Some(tenant_id) = tenant_scope {
            let filtered: Vec<BillingEvent> = self
                .repositories
                .billing_events()
                .into_iter()
                .filter(|event| event.tenant.organization_id.as_deref() == Some(tenant_id))
                .collect();
            let filtered = if filtered.is_empty() {
                self.metering_events
                    .list()
                    .into_iter()
                    .filter(|event| event.tenant.organization_id.as_deref() == Some(tenant_id))
                    .collect()
            } else {
                filtered
            };
            let total = filtered.len();
            let data = filtered
                .into_iter()
                .skip(pagination.offset)
                .take(pagination.limit)
                .collect();
            return AdminPage {
                data,
                total,
                offset: pagination.offset,
                limit: pagination.limit,
            };
        }

        let page = self
            .repositories
            .billing_events_page(pagination.offset, pagination.limit);
        if page.total > 0 || !page.data.is_empty() {
            return AdminPage {
                data: page.data,
                total: page.total,
                offset: page.offset,
                limit: page.limit,
            };
        }

        AdminPage {
            data: self
                .metering_events
                .list_paginated(pagination.offset, pagination.limit),
            total: self.metering_events.len(),
            offset: pagination.offset,
            limit: pagination.limit,
        }
    }

    /// `tenant_scope`: export-status rows only carry a bare `request_id`, no
    /// tenant field directly, so a tenant-scoped caller (issue #185) is
    /// narrowed by cross-referencing each row's `request_id` against the
    /// owning metering event's tenant; a `request_id` that can't be
    /// resolved is dropped (fail closed) rather than shown.
    pub(crate) fn metering_export_status(
        &self,
        tenant_scope: Option<&str>,
    ) -> Vec<MeteringExportStatus> {
        let statuses = self
            .metering_exporter
            .as_ref()
            .map(|exporter| exporter.statuses())
            .unwrap_or_default();
        let Some(tenant_id) = tenant_scope else {
            return statuses;
        };
        let tenant_by_request_id: HashMap<String, Option<String>> = self
            .metering_events
            .list()
            .into_iter()
            .map(|event| (event.request_id, event.tenant.organization_id))
            .collect();
        statuses
            .into_iter()
            .filter(|status| {
                tenant_by_request_id
                    .get(&status.request_id)
                    .and_then(|organization_id| organization_id.as_deref())
                    == Some(tenant_id)
            })
            .collect()
    }

    /// `tenant_scope`: narrows to a single tenant's usage aggregates (issue
    /// #185); `None` (platform operator) is unfiltered, same as before.
    pub(crate) fn usage_aggregates(&self, tenant_scope: Option<&str>) -> Vec<StoredUsageAggregate> {
        let aggregates = self.repositories.usage_aggregates();
        let Some(tenant_id) = tenant_scope else {
            return aggregates;
        };
        aggregates
            .into_iter()
            .filter(|aggregate| aggregate.organization_id.as_deref() == Some(tenant_id))
            .collect()
    }

    pub(crate) fn record_request_log(&self, mut log: StoredRequestLog) {
        log.cluster_id = Some(self.cluster_identity.cluster_id.clone());
        log.node_id = Some(self.cluster_identity.node_id.clone());
        self.sanitize_request_log_bodies(&mut log);
        self.record_request_metrics(&log);
        if let Ok(mut metrics) = self.provider_routing_metrics.lock() {
            metrics.record_request_log(&log);
        }
        self.repositories.append_request_log(log);
    }

    fn sanitize_request_log_bodies(&self, log: &mut StoredRequestLog) {
        if let Some(body) = &mut log.prompt_body {
            *body = self.redact_configured_secrets(body);
        }
        if let Some(body) = &mut log.response_body {
            *body = self.redact_configured_secrets(body);
        }
    }

    fn redact_configured_secrets(&self, text: &str) -> String {
        let mut redacted = text.to_string();
        for secret in self.configured_secret_values() {
            redacted = redacted.replace(&secret, "[REDACTED]");
        }
        redacted
    }

    fn configured_secret_values(&self) -> Vec<String> {
        let mut secrets = Vec::new();
        for key in &self.config.api_keys {
            if let Some(value) = key.key.as_ref().filter(|value| !value.is_empty()) {
                secrets.push(value.clone());
            }
            if let Some(env_name) = key.key_env.as_ref() {
                if let Ok(value) = env::var(env_name) {
                    if !value.is_empty() {
                        secrets.push(value);
                    }
                }
            }
        }
        for provider in &self.config.providers {
            if let Some(env_name) = provider.api_key_env.as_ref() {
                if let Ok(value) = env::var(env_name) {
                    if !value.is_empty() {
                        secrets.push(value);
                    }
                }
            }
        }
        secrets.sort();
        secrets.dedup();
        secrets
    }

    fn record_request_metrics(&self, log: &StoredRequestLog) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_request_log(log);
        }
    }

    fn record_billing_metrics(&self, event: &BillingEvent) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_billing_event(event);
        }
    }

    pub(crate) fn record_admin_audit_event(&self, event: AdminAuditEventDraft) {
        self.repositories
            .append_audit_event(self.prepare_admin_audit_event(event));
    }

    pub(super) fn prepare_admin_audit_event(
        &self,
        event: AdminAuditEventDraft,
    ) -> StoredAuditEvent {
        StoredAuditEvent {
            id: self.repositories.next_audit_event_id(),
            request_id: event.request_id,
            trace_id: event.trace_id,
            agent_run_id: event.agent_run_id,
            workflow_id: event.workflow_id,
            workflow_version: event.workflow_version,
            workflow_node_id: event.workflow_node_id,
            cluster_id: Some(self.cluster_identity.cluster_id.clone()),
            node_id: Some(self.cluster_identity.node_id.clone()),
            actor_api_key_id: event.actor_api_key_id,
            tenant: event.tenant,
            action: event.action,
            target: event.target,
            outcome: event.outcome,
            message: event.message,
            occurred_at_unix: now_unix_seconds(),
        }
    }

    pub(crate) fn record_tool_billing_event(
        &self,
        request_id: &str,
        tenant: &ferrogate_core::TenantContext,
        tool_name: &str,
        latency_ms: u64,
        status_code: u16,
    ) {
        let event = BillingEvent {
            request_id: request_id.into(),
            trace_id: None,
            provider_attempt: ProviderAttempt::for_request(request_id, 0),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: Some(self.cluster_identity.cluster_id.clone()),
            node_id: Some(self.cluster_identity.node_id.clone()),
            tenant: tenant.clone(),
            logical_model: format!("mcp_tool:{tool_name}"),
            provider: "mcp".into(),
            provider_model: tool_name.into(),
            usage: BillingTokenUsage::new(0, 0, 0),
            usage_source: BillingUsageSource::GatewayEstimate,
            status_code,
            occurred_at_unix: now_unix_seconds(),
            cost_usd: None,
            latency_ms: Some(latency_ms),
            metadata: std::collections::BTreeMap::new(),
            wallet_delta_credits: None,
            wallet_balance_after_credits: None,
        };
        let _ = self.metering_events.record(event.clone());
        self.record_billing_metrics(&event);
        if let Some(exporter) = &self.metering_exporter {
            exporter.export_event(event);
        }
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_tool_call(tool_name, latency_ms);
        }
    }

    pub(crate) fn prometheus_metrics_snapshot(&self) -> GatewayMetricsSnapshot {
        self.metrics
            .lock()
            .map(|metrics| metrics.snapshot(self.state_service_name()))
            .unwrap_or_else(|_| GatewayMetricsSnapshot {
                service_name: self.state_service_name(),
                request_log_total: 0,
                request_error_total: 0,
                request_status_totals: Vec::new(),
                cache_hits_total: 0,
                cache_misses_total: 0,
                guardrail_match_total: 0,
                guardrail_denial_total: 0,
                guardrail_redaction_total: 0,
                guardrail_detector_error_total: 0,
                guardrail_evaluation_total: 0,
                guardrail_evaluation_fail_total: 0,
                guardrail_evaluation_error_total: 0,
                guardrail_evaluation_shadow_total: 0,
                guardrail_evidence_persistence_failure_total: 0,
                billing_event_total: 0,
                billing_report_enqueue_failure_total: 0,
                tool_call_total: 0,
                tool_latency_ms_total: 0,
                mcp_identity_resolution_total: 0,
                mcp_identity_failure_total: 0,
                mcp_identity_refresh_total: 0,
                mcp_identity_revocation_total: 0,
                mcp_refresh_response_deadline_total: 0,
                mcp_refresh_storage_cancellation_total: 0,
                mcp_refresh_storage_outcome_unknown_total: 0,
                mcp_refresh_late_reconciliation_total: 0,
                mcp_identity_error_audit_deadline_total: 0,
                token_totals: TokenMetricTotals::default(),
                model_provider_totals: Vec::new(),
                network_access_denied_total: 0,
                network_access_rate_limited_total: 0,
            })
    }
}

#[cfg(test)]
#[path = "state_billing_metering_metrics_test.rs"]
mod metrics_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_token_metering_event_with_settled_gateway_cost() {
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
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(2.0),
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        };
        let state = AppState::new(config);
        let request = RequestContext {
            request_id: "fg-test".into(),
            trace_id: Some("trace-test".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: ferrogate_core::TenantContext {
                organization_id: Some("org".into()),
                team_id: None,
                project_id: Some("project".into()),
                workspace_id: None,
                user_id: None,
                api_key_id: Some("key_dev".into()),
            },
        };

        state
            .record_billing_event(
                BillingEventDraft {
                    request: &request,
                    logical_model: "fast-chat",
                    provider: "openai",
                    provider_model: "gpt-4o-mini",
                    status_code: 200,
                    latency_ms: Some(120),
                    metadata: None,
                },
                &ProviderUsage {
                    prompt_tokens: Some(3),
                    completion_tokens: Some(5),
                    total_tokens: Some(8),
                },
            )
            .unwrap();

        let events = state.billing_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant.organization_id.as_deref(), Some("org"));
        assert_eq!(events[0].usage.total_tokens, 8);
        assert_eq!(events[0].usage_source, BillingUsageSource::ProviderUsage);
        // 3 prompt tokens @ $1.00/1M + 5 completion tokens @ $2.00/1M.
        assert!((events[0].cost_usd.unwrap() - 0.000_013).abs() < 1e-9);
        assert_eq!(events[0].latency_ms, Some(120));

        let aggregates = state.usage_aggregates(None);
        assert_eq!(aggregates.len(), 1);
        assert_eq!(aggregates[0].organization_id.as_deref(), Some("org"));
        assert_eq!(aggregates[0].project_id.as_deref(), Some("project"));
        assert_eq!(aggregates[0].api_key_id.as_deref(), Some("key_dev"));
        assert_eq!(aggregates[0].logical_model, "fast-chat");
        assert_eq!(aggregates[0].provider, "openai");
        assert_eq!(aggregates[0].usage.total_tokens, 8);

        let rollup = state
            .get_usage_monthly_rollup(
                ferrogate_storage::QuotaScopeKind::Key,
                "key_dev",
                &state.current_period_month(),
            )
            .unwrap()
            .expect("monthly rollup for the api key must exist");
        assert_eq!(rollup.total_tokens, 8);
        assert_eq!(rollup.request_count, 1);
        assert_eq!(rollup.error_count, 0);
        assert!((rollup.cost_usd - 0.000_013).abs() < 1e-9);
    }

    #[test]
    fn billing_event_carries_the_wallet_debit_outcome_when_a_wallet_exists() {
        // Issue #169's GET /v1/billing/ledger acceptance criterion: the
        // BillingEvent posted to the standalone billing service (and thus
        // the LedgerEntry it produces) must show the wallet debit
        // alongside cost/credit fields, not just update the wallet
        // silently on the side.
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
                // $1/1M input tokens, chosen so 500_000 prompt tokens
                // settles to exactly $0.50 = 500_000 credits.
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(0.0),
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        };
        let state = AppState::new(config);
        state
            .upsert_wallet(ferrogate_storage::StoredWallet {
                id: "org".into(),
                tenant_id: "org".into(),
                balance_credits: 1_000_000,
                auto_recharge_threshold_credits: None,
                auto_recharge_amount_credits: None,
                dunning: false,
                created_at_unix: 0,
                updated_at_unix: 0,
            })
            .unwrap();
        let request = RequestContext {
            request_id: "fg-wallet-test".into(),
            trace_id: Some("trace-wallet-test".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: ferrogate_core::TenantContext {
                workspace_id: None,
                organization_id: Some("org".into()),
                team_id: None,
                project_id: None,
                user_id: None,
                api_key_id: None,
            },
        };

        state
            .record_billing_event(
                BillingEventDraft {
                    request: &request,
                    logical_model: "fast-chat",
                    provider: "openai",
                    provider_model: "gpt-4o-mini",
                    status_code: 200,
                    latency_ms: None,
                    metadata: None,
                },
                &ProviderUsage {
                    prompt_tokens: Some(500_000),
                    completion_tokens: Some(0),
                    total_tokens: Some(500_000),
                },
            )
            .unwrap();

        let events = state.billing_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].wallet_delta_credits,
            Some(-500_000),
            "500_000 prompt tokens @ $1/1M = $0.50 = 500_000 credits debited"
        );
        assert_eq!(
            events[0].wallet_balance_after_credits,
            Some(500_000),
            "1_000_000 starting balance - 500_000 debited = 500_000 remaining"
        );

        let wallet = state.get_wallet("org").unwrap().unwrap();
        assert_eq!(
            wallet.balance_credits, 500_000,
            "the event's reported balance must match the real, persisted wallet balance"
        );
    }

    #[test]
    fn records_no_cost_when_model_has_no_configured_pricing() {
        let state = AppState::new(Config::default());
        let request = RequestContext {
            request_id: "fg-no-price".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: None,
            upstream: None,
            tenant: ferrogate_core::TenantContext::default(),
        };

        state
            .record_billing_event(
                BillingEventDraft {
                    request: &request,
                    logical_model: "unknown-model",
                    provider: "openai",
                    provider_model: "gpt-4o-mini",
                    status_code: 200,
                    latency_ms: None,
                    metadata: None,
                },
                &ProviderUsage {
                    prompt_tokens: Some(3),
                    completion_tokens: Some(5),
                    total_tokens: Some(8),
                },
            )
            .unwrap();

        let events = state.billing_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].cost_usd, None,
            "an unregistered model must not produce a fabricated cost"
        );
    }

    #[test]
    fn records_estimated_billing_event_when_provider_usage_is_missing() {
        let state = AppState::new(Config::default());
        let request = RequestContext {
            request_id: "fg-estimated".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: ferrogate_core::TenantContext {
                workspace_id: None,
                organization_id: None,
                team_id: None,
                project_id: None,
                user_id: None,
                api_key_id: Some("key_dev".into()),
            },
        };

        state
            .record_estimated_billing_event(
                BillingEventDraft {
                    request: &request,
                    logical_model: "fast-chat",
                    provider: "openai",
                    provider_model: "gpt-4o-mini",
                    status_code: 200,
                    latency_ms: Some(95),
                    metadata: None,
                },
                &BillingTokenUsage::new(2, 6, 8),
            )
            .unwrap();

        let events = state.billing_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].usage_source, BillingUsageSource::GatewayEstimate);
        assert_eq!(events[0].usage.total_tokens, 8);
        assert_eq!(state.api_key_total_tokens_used("key_dev"), 8);
    }

    #[test]
    fn records_structured_request_logs_without_body_flags_by_default() {
        let state = AppState::new(Config::default());
        state.record_request_log(StoredRequestLog {
            request_id: "fg-test".into(),
            trace_id: Some("trace-test".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: ferrogate_core::TenantContext::default(),
            route: Some("openai.chat.completions".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: None,
            completed_at_unix: None,
        });

        let logs = state.request_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].request_id, "fg-test");
        assert!(!logs[0].prompt_recorded);
        assert!(!logs[0].response_recorded);
        assert!(logs[0].prompt_body.is_none());
        assert!(logs[0].response_body.is_none());
    }

    #[test]
    fn request_log_export_filters_records_and_redacts_configured_secrets() {
        let state = AppState::new(Config {
            api_keys: vec![crate::config::ApiKey {
                region_allowlist: Vec::new(),
                id: "key_dev".into(),
                name: "Development key".into(),
                key_env: None,
                key: Some("client-secret".into()),
                key_hash: None,
                enabled: true,
                scopes: vec!["chat.completions".into()],
                allowed_models: vec![],
                denied_models: vec![],
                allowed_providers: vec![],
                denied_providers: vec![],
                organization_id: Some("org".into()),
                team_id: None,
                project_id: Some("project".into()),
                workspace_id: None,
                user_id: None,
                monthly_token_budget: None,
                request_limit_per_minute: None,
                expires_at_unix: None,
                log_bodies: Some(true),
                cache_enabled: None,
            }],
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
            ..Config::default()
        });
        state.record_request_log(StoredRequestLog {
            request_id: "fg-export-1".into(),
            trace_id: Some("trace-export".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: ferrogate_core::TenantContext {
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key_dev".into()),
                ..ferrogate_core::TenantContext::default()
            },
            route: Some("openai.chat.completions".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: true,
            response_recorded: true,
            prompt_body: Some(r#"{"input":"client-secret prompt"}"#.into()),
            response_body: Some(r#"{"output":"ok"}"#.into()),
            cache_status: None,
            started_at_unix: Some(10),
            completed_at_unix: Some(11),
        });
        state.record_request_log(StoredRequestLog {
            request_id: "fg-export-2".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: ferrogate_core::TenantContext {
                organization_id: Some("other".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key_dev".into()),
                ..ferrogate_core::TenantContext::default()
            },
            route: Some("openai.responses".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 500,
            error_code: Some("provider_error".into()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: Some("must not export".into()),
            response_body: Some("must not export".into()),
            cache_status: None,
            started_at_unix: Some(12),
            completed_at_unix: Some(13),
        });

        let records = state.request_log_export_records(RequestLogExportFilter::from_query(Some(
            "organization_id=org&project_id=project&model=fast-chat&provider=openai&status=200&since=10&until=11&limit=10",
        )));

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].request_id, "fg-export-1");
        assert_eq!(records[0].provider.as_deref(), Some("openai"));
        assert_eq!(records[0].logical_model.as_deref(), Some("fast-chat"));
        let encoded = serde_json::to_string(&records[0]).unwrap();
        assert!(encoded.contains("[REDACTED] prompt"));
        assert!(!encoded.contains("client-secret"));
        assert!(!encoded.contains("must not export"));
    }

    #[test]
    fn in_memory_analytics_retains_configured_window_with_paginated_admin_views() {
        let state = AppState::new(Config {
            analytics: crate::config::AnalyticsConfig {
                request_log_retention_records: 2,
                audit_event_retention_records: 2,
                billing_event_retention_records: 2,
                ..crate::config::AnalyticsConfig::default()
            },
            storage: crate::config::StorageConfig {
                admin_list_default_limit: 1,
                admin_list_max_limit: 2,
                ..crate::config::StorageConfig::default()
            },
            ..Config::default()
        });

        for (index, status_code) in [(1, 200), (2, 500), (3, 200)] {
            state.record_request_log(StoredRequestLog {
                request_id: format!("fg-{index}"),
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
                status_code,
                error_code: None,
                prompt_recorded: false,
                response_recorded: false,
                prompt_body: None,
                response_body: None,
                cache_status: None,
                started_at_unix: None,
                completed_at_unix: None,
            });
            state.record_admin_audit_event(AdminAuditEventDraft {
                request_id: format!("fg-{index}"),
                trace_id: None,
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                actor_api_key_id: None,
                tenant: ferrogate_core::TenantContext::default(),
                action: "config.validate".into(),
                target: "config".into(),
                outcome: "accepted".into(),
                message: format!("audit {index}"),
            });
            state
                .record_estimated_billing_event(
                    BillingEventDraft {
                        request: &RequestContext {
                            request_id: format!("fg-{index}"),
                            trace_id: None,
                            agent_run_id: None,
                            workflow_id: None,
                            workflow_version: None,
                            workflow_node_id: None,
                            route: None,
                            upstream: None,
                            tenant: ferrogate_core::TenantContext::default(),
                        },
                        logical_model: "fast-chat",
                        provider: "openai",
                        provider_model: "gpt-4o-mini",
                        status_code,
                        latency_ms: None,
                        metadata: None,
                    },
                    &BillingTokenUsage::new(index, index, index * 2),
                )
                .unwrap();
        }

        let first_page = state.request_logs_page(state.admin_pagination(None), None);
        assert_eq!(first_page.total, 2);
        assert_eq!(first_page.limit, 1);
        assert_eq!(first_page.data[0].request_id, "fg-2");

        let second_page =
            state.request_logs_page(state.admin_pagination(Some("offset=1&limit=9")), None);
        assert_eq!(second_page.limit, 2);
        assert_eq!(second_page.data.len(), 1);
        assert_eq!(second_page.data[0].request_id, "fg-3");

        let audit_page = state.audit_events_page(state.admin_pagination(None), None);
        assert_eq!(audit_page.total, 2);
        assert_eq!(audit_page.data[0].request_id, "fg-2");

        let metering_page = state.metering_events_page(state.admin_pagination(None), None);
        assert_eq!(metering_page.total, 2);
        assert_eq!(metering_page.data[0].request_id, "fg-2");

        let snapshot = state.prometheus_metrics_snapshot();
        assert_eq!(snapshot.request_log_total, 3);
        assert_eq!(snapshot.request_error_total, 1);
        assert_eq!(snapshot.billing_event_total, 3);
        assert_eq!(snapshot.token_totals.total_tokens, 12);
    }

    #[test]
    fn access_log_modes_filter_success_and_error_requests() {
        let mut config = Config::default();
        config.telemetry.access_log = AccessLogMode::Error;
        let state = AppState::new(config.clone());
        assert!(!state.should_log_access("fg-0000000000000001", 200, false));
        assert!(state.should_log_access("fg-0000000000000001", 500, false));
        assert!(state.should_log_access("fg-0000000000000001", 200, true));

        config.telemetry.access_log = AccessLogMode::Sampled;
        config.telemetry.access_log_sample_rate = 10;
        let state = AppState::new(config.clone());
        assert!(state.should_log_access("fg-000000000000000a", 200, false));
        assert!(!state.should_log_access("fg-000000000000000b", 200, false));
        assert!(state.should_log_access("fg-000000000000000b", 404, false));

        config.telemetry.access_log = AccessLogMode::All;
        let state = AppState::new(config.clone());
        assert!(state.should_log_access("fg-0000000000000001", 200, false));

        config.telemetry.access_log = AccessLogMode::Off;
        let state = AppState::new(config);
        assert!(!state.should_log_access("fg-0000000000000001", 500, true));
    }

    #[test]
    fn access_log_rate_limits_error_storms_per_second() {
        let mut config = Config::default();
        config.telemetry.access_log = AccessLogMode::Error;
        config.telemetry.access_log_error_rate_limit_per_sec = 2;
        let state = AppState::new(config.clone());

        assert!(state.should_log_access_at("fg-0000000000000001", 500, false, 1_000));
        assert!(state.should_log_access_at("fg-0000000000000002", 502, false, 1_000));
        assert!(!state.should_log_access_at("fg-0000000000000003", 503, false, 1_000));
        assert!(state.should_log_access_at("fg-0000000000000004", 500, false, 1_001));

        config.telemetry.access_log = AccessLogMode::All;
        let state = AppState::new(config);
        assert!(state.should_log_access_at("fg-0000000000000001", 200, false, 1_000));
        assert!(state.should_log_access_at("fg-0000000000000002", 500, false, 1_000));
        assert!(state.should_log_access_at("fg-0000000000000003", 500, false, 1_000));
        assert!(!state.should_log_access_at("fg-0000000000000004", 500, false, 1_000));
    }
}
