// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the P1-3/P1-4 quota/policy
// enforcement engine -- usage reports, effective-quota resolution,
// api-key token accounting, guardrail policy evaluation and matching.

use super::*;

impl AppState {
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

    pub(crate) fn match_guardrail(
        &self,
        stage: GuardrailStage,
        tenant: &ferrogate_core::TenantContext,
        model: Option<&str>,
        provider: Option<&str>,
        body_text: &str,
    ) -> Option<GuardrailMatch> {
        self.guardrail_rules.iter().find_map(|rule| {
            if !rule.enabled {
                return None;
            }
            if rule.stage != stage {
                return None;
            }
            if !allows_optional_scope(&rule.organization_ids, tenant.organization_id.as_deref()) {
                return None;
            }
            if !allows_optional_scope(&rule.project_ids, tenant.project_id.as_deref()) {
                return None;
            }
            if !allows_optional_scope(&rule.api_key_ids, tenant.api_key_id.as_deref()) {
                return None;
            }
            if !allows_optional_scope(&rule.models, model) {
                return None;
            }
            if !allows_optional_scope(&rule.providers, provider) {
                return None;
            }
            if rule.provider == GuardrailProviderKind::CustomHttp {
                let endpoint = rule.provider_endpoint.as_deref()?;
                return match call_guardrail_provider(
                    endpoint,
                    rule.provider_timeout_ms,
                    stage,
                    tenant,
                    model,
                    provider,
                    body_text,
                ) {
                    Ok(Some(matched_text)) => Some(GuardrailMatch {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        effect: rule.effect,
                        matched_text,
                        redaction_regex: None,
                        code: rule.code.clone(),
                        message: rule.message.clone(),
                    }),
                    Ok(None) => None,
                    Err(reason) => Some(GuardrailMatch {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        // Fail closed: a security control we can't reach is
                        // treated as a deny regardless of the rule's
                        // configured effect, since there is nothing to
                        // redact when the provider never responded.
                        effect: GuardrailEffect::Deny,
                        matched_text: String::new(),
                        redaction_regex: None,
                        code: "guardrail_provider_unavailable".to_string(),
                        message: format!(
                            "guardrail provider for rule '{}' is unavailable: {reason}",
                            rule.name
                        ),
                    }),
                };
            }
            let matched = if let Some(max_input_bytes) = rule.max_input_bytes {
                if body_text.len() > max_input_bytes {
                    Some(("length".to_string(), None))
                } else {
                    None
                }
            } else {
                None
            }
            .or_else(|| {
                rule.keywords
                    .iter()
                    .find(|keyword| body_text.contains(keyword.as_str()))
                    .map(|keyword| (keyword.clone(), None))
            })
            .or_else(|| {
                rule.regex.iter().find_map(|regex| {
                    regex
                        .find(body_text)
                        .map(|matched| (matched.as_str().to_string(), Some(regex.clone())))
                })
            })?;
            Some(GuardrailMatch {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                effect: rule.effect,
                matched_text: matched.0,
                redaction_regex: matched.1,
                code: rule.code.clone(),
                message: rule.message.clone(),
            })
        })
    }

    pub(crate) fn has_guardrail_candidate(
        &self,
        stage: GuardrailStage,
        tenant: &ferrogate_core::TenantContext,
        model: Option<&str>,
        provider: Option<&str>,
    ) -> bool {
        self.guardrail_rules.iter().any(|rule| {
            rule.enabled
                && rule.stage == stage
                && allows_optional_scope(&rule.organization_ids, tenant.organization_id.as_deref())
                && allows_optional_scope(&rule.project_ids, tenant.project_id.as_deref())
                && allows_optional_scope(&rule.api_key_ids, tenant.api_key_id.as_deref())
                && allows_optional_scope(&rule.models, model)
                && allows_optional_scope(&rule.providers, provider)
        })
    }

    pub(crate) fn record_guardrail_match(&self, guardrail: &GuardrailMatch) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_guardrail_match(guardrail.effect);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let matched = state
            .match_guardrail(
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
                effect: crate::config::GuardrailEffect::Deny,
                code: "guardrail_blocked".into(),
                message: "blocked by guardrail".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        assert!(state
            .match_guardrail(
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
                effect: crate::config::GuardrailEffect::Redact,
                code: "guardrail_redacted".into(),
                message: "redacted by guardrail".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        let matched = state
            .match_guardrail(
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
    /// JSON body, and replies with `response_body`. `http_post` always sends
    /// `Connection: close`, so a single accepted connection is enough.
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
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.trim().parse().ok())
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

        let matched = state
            .match_guardrail(
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

        assert!(state
            .match_guardrail(
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

        let matched = state
            .match_guardrail(
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
                effect: crate::config::GuardrailEffect::Redact,
                code: "guardrail_redacted".into(),
                message: "redacted by guardrail".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        let matched = state
            .match_guardrail(
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
                effect: crate::config::GuardrailEffect::Deny,
                code: "guardrail_input_too_large".into(),
                message: "input is too large".into(),
            }],
            ..Config::default()
        };
        let state = AppState::new(config);

        let matched = state
            .match_guardrail(
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
