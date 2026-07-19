// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for AI request dispatch preparation,
// model/provider routing (candidate selection, latency/cost/balanced
// ordering, region filtering), provider circuit breakers and health,
// AI response caching, and reverse-proxy runtime route/upstream
// selection.

use super::*;

impl AppState {
    pub(crate) fn prepare_chat_completions(
        &self,
        provider: &Provider,
        model_route: &ModelRoute,
        tool_context: ToolInjectionContext<'_>,
        logical_model: String,
        stream: bool,
        body: serde_json::Value,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        let tools = self
            .tools_for(
                tool_context.tenant,
                tool_context.api_key_id,
                tool_context.route,
            )
            .into_iter()
            .map(|tool| ferrogate_core::ToolDef {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
            })
            .collect::<Vec<_>>();
        let body = self
            .provider_adapters
            .inject_tools(&provider.kind, body, &tools)?;
        self.provider_adapters.prepare_chat_completions(
            self.provider_config(provider),
            ChatCompletionPlan {
                logical_model,
                provider_model: model_route.provider_model.clone(),
                stream,
                body,
            },
        )
    }

    pub(crate) fn prepare_responses(
        &self,
        provider: &Provider,
        model_route: &ModelRoute,
        logical_model: String,
        stream: bool,
        body: serde_json::Value,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        self.provider_adapters.prepare_responses(
            self.provider_config(provider),
            ResponsesPlan {
                logical_model,
                provider_model: model_route.provider_model.clone(),
                stream,
                body,
            },
        )
    }

    pub(crate) fn prepare_embeddings(
        &self,
        provider: &Provider,
        model_route: &ModelRoute,
        logical_model: String,
        body: serde_json::Value,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        self.provider_adapters.prepare_embeddings(
            self.provider_config(provider),
            EmbeddingsPlan {
                logical_model,
                provider_model: model_route.provider_model.clone(),
                body,
            },
        )
    }

    /// Normalize a successful provider embeddings response into the
    /// canonical OpenAI-shaped body, or `None` when the upstream body
    /// already is OpenAI-shaped and should pass through unchanged (issue
    /// #274). Selects the adapter family by the resolved route's provider
    /// kind, mirroring how chat dispatch picks its adapter.
    pub(crate) fn translate_embeddings_response(
        &self,
        provider_kind: &str,
        body: &[u8],
        logical_model: &str,
    ) -> Result<Option<serde_json::Value>, AdapterError> {
        self.provider_adapters
            .translate_embeddings_response(provider_kind, body, logical_model)
    }

    pub(crate) fn provider_config(&self, provider: &Provider) -> ProviderConfig {
        let api_key = self
            .resolved_provider_secrets
            .get(&provider.name)
            .cloned()
            .or_else(|| provider.api_key_value());
        ProviderConfig {
            name: provider.name.clone(),
            kind: provider.kind.clone(),
            base_url: provider.base_url.clone(),
            api_key,
            openrouter_http_referer: provider.openrouter_http_referer.clone(),
            openrouter_x_title: provider.openrouter_x_title.clone(),
            aws_credentials: aws_provider_credentials(provider),
            gcp_credentials: gcp_provider_credentials(provider),
        }
    }

    pub(crate) fn prepare_model_catalog(
        &self,
        provider: &Provider,
    ) -> Result<ferrogate_providers::ProviderCatalogRequest, AdapterError> {
        self.provider_adapters
            .prepare_model_catalog(self.provider_config(provider))
    }

    pub(crate) fn parse_model_catalog(
        &self,
        provider_kind: &str,
        body: &[u8],
    ) -> Result<Vec<ferrogate_providers::ProviderCatalogModel>, AdapterError> {
        self.provider_adapters
            .parse_model_catalog(provider_kind, body)
    }

    pub(crate) fn ai_cache_enabled(
        &self,
        api_key_id: Option<&str>,
        logical_model: &str,
        provider_name: &str,
        gateway_config: Option<&GatewayConfigUse>,
    ) -> bool {
        if !self.config.cache.enabled {
            return false;
        }
        if gateway_config.and_then(|profile| profile.cache_enabled) == Some(false) {
            return false;
        }
        let _ = provider_name;
        if self
            .config
            .models
            .iter()
            .find(|model| model.name == logical_model)
            .and_then(|model| model.cache_enabled)
            == Some(false)
        {
            return false;
        }
        if let Some(api_key_id) = api_key_id {
            if self
                .config
                .api_keys
                .iter()
                .find(|key| key.id == api_key_id)
                .and_then(|key| key.cache_enabled)
                == Some(false)
            {
                return false;
            }
        }
        true
    }

    pub(crate) fn resolve_gateway_config_profile(
        &self,
        profile_id: Option<&str>,
        api_key_id: Option<&str>,
    ) -> Result<Option<GatewayConfigUse>, GatewayConfigResolveError> {
        let Some(profile_id) = profile_id.map(str::trim).filter(|id| !id.is_empty()) else {
            return Ok(None);
        };
        let Some(profile) = self
            .config
            .gateway_configs
            .iter()
            .find(|profile| profile.id == profile_id)
        else {
            return Err(GatewayConfigResolveError::NotFound(profile_id.to_string()));
        };
        gateway_config_use(profile, api_key_id).map(Some)
    }

    pub(crate) fn ai_response_cache_key(
        &self,
        route: &str,
        tenant: &ferrogate_core::TenantContext,
        logical_model: &str,
        provider: &str,
        provider_model: &str,
        body: &serde_json::Value,
    ) -> AiResponseCacheKey {
        #[derive(Serialize)]
        struct CacheKeyInput<'a> {
            route: &'a str,
            organization_id: &'a Option<String>,
            team_id: &'a Option<String>,
            project_id: &'a Option<String>,
            user_id: &'a Option<String>,
            api_key_id: &'a Option<String>,
            logical_model: &'a str,
            provider: &'a str,
            provider_model: &'a str,
            stream: bool,
            request_body: &'a serde_json::Value,
            /// #233: any guardrail-policy change (e.g. a tightened
            /// Response-stage redaction rule) rotates this fingerprint, so
            /// entries cached under the old policy can no longer be served.
            guardrail_policy_fingerprint: u64,
        }

        let bytes = serde_json::to_vec(&CacheKeyInput {
            route,
            organization_id: &tenant.organization_id,
            team_id: &tenant.team_id,
            project_id: &tenant.project_id,
            user_id: &tenant.user_id,
            api_key_id: &tenant.api_key_id,
            logical_model,
            provider,
            provider_model,
            stream: false,
            request_body: body,
            guardrail_policy_fingerprint: self.guardrail_policy_fingerprint,
        })
        .expect("AI cache key serialization should not fail");
        AiResponseCacheKey::new(format!("ai-cache:{:016x}", fnv1a64(&bytes)))
    }

    pub(crate) fn lookup_ai_response_cache(
        &self,
        key: &AiResponseCacheKey,
    ) -> Option<AiCachedResponse> {
        let now = now_unix_seconds().unwrap_or_default();
        self.response_cache
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(key, now))
    }

    pub(crate) fn store_ai_response_cache(
        &self,
        key: AiResponseCacheKey,
        response: AiCachedResponse,
    ) {
        let now = now_unix_seconds().unwrap_or_default();
        if let Ok(mut cache) = self.response_cache.lock() {
            cache.insert(
                key,
                response,
                self.config.cache.ttl_secs,
                self.config.cache.max_records,
                now,
            );
        }
    }

    pub(crate) fn record_ai_cache_hit(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_cache_hit();
        }
    }

    pub(crate) fn record_ai_cache_miss(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_cache_miss();
        }
    }

    pub(crate) fn resolve_model(
        &self,
        logical_model: &str,
    ) -> Result<ResolvedModelRoute, ModelRegistryError> {
        self.model_registry.resolve(logical_model)
    }

    pub(crate) fn candidate_model_routes(
        &self,
        model: &ResolvedModelRoute,
        estimated_usage: Option<&BillingTokenUsage>,
        region_allowlist: &HashSet<String>,
    ) -> Vec<ModelRoute> {
        let mut routes = match model.routing_strategy {
            RoutingStrategy::Priority => {
                let mut routes = vec![model.primary.clone()];
                let mut cursor = self.model_route_counter.fetch_add(1, Ordering::Relaxed);
                let mut fallbacks = model.fallbacks.as_slice();
                while let Some((priority, group_end)) = fallback_priority_group(fallbacks) {
                    let group = &fallbacks[..group_end];
                    let start = weighted_start_index(group, cursor);
                    routes.extend(group[start..].iter().cloned());
                    routes.extend(group[..start].iter().cloned());
                    cursor /= total_weight(group);
                    fallbacks = &fallbacks[group_end..];
                    debug_assert!(group.iter().all(|route| route.priority == priority));
                }
                routes
            }
            RoutingStrategy::LowestCost => {
                let mut routes = vec![model.primary.clone()];
                routes.extend(model.fallbacks.iter().cloned());
                routes.sort_by(|left, right| {
                    route_estimated_cost(left, estimated_usage)
                        .partial_cmp(&route_estimated_cost(right, estimated_usage))
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| left.priority.cmp(&right.priority))
                        .then_with(|| right.weight.cmp(&left.weight))
                        .then_with(|| left.provider.cmp(&right.provider))
                        .then_with(|| left.provider_model.cmp(&right.provider_model))
                });
                routes
            }
            RoutingStrategy::LowestLatency => {
                let mut routes = vec![model.primary.clone()];
                routes.extend(model.fallbacks.iter().cloned());
                self.sort_routes_by_latency(&mut routes);
                routes
            }
            RoutingStrategy::Balanced => {
                let mut routes = vec![model.primary.clone()];
                routes.extend(model.fallbacks.iter().cloned());
                self.sort_routes_by_balanced_score(&mut routes);
                routes
            }
        };
        // Region enforcement (issue #173), applied uniformly after
        // strategy-specific ordering rather than duplicated per arm:
        // sort order is independent of region eligibility. Empty
        // allowlist means unrestricted; non-empty fails closed on routes
        // with no declared region, not just a mismatched one.
        if !region_allowlist.is_empty() {
            routes.retain(|route| {
                route
                    .region
                    .as_deref()
                    .is_some_and(|region| region_allowlist.contains(region))
            });
        }
        routes
    }

    fn sort_routes_by_latency(&self, routes: &mut [ModelRoute]) {
        let metrics = self.provider_routing_metrics.lock().ok();
        routes.sort_by(|left, right| {
            let left_score = metrics
                .as_ref()
                .map(|metrics| metrics.score(&left.provider))
                .unwrap_or_default();
            let right_score = metrics
                .as_ref()
                .map(|metrics| metrics.score(&right.provider))
                .unwrap_or_default();
            provider_health_rank(self, left, left_score)
                .cmp(&provider_health_rank(self, right, right_score))
                .then_with(|| latency_rank(left_score).cmp(&latency_rank(right_score)))
                .then_with(|| left.priority.cmp(&right.priority))
                .then_with(|| right.weight.cmp(&left.weight))
                .then_with(|| left.provider.cmp(&right.provider))
                .then_with(|| left.provider_model.cmp(&right.provider_model))
        });
    }

    fn sort_routes_by_balanced_score(&self, routes: &mut [ModelRoute]) {
        let metrics = self.provider_routing_metrics.lock().ok();
        routes.sort_by(|left, right| {
            let left_score = metrics
                .as_ref()
                .map(|metrics| metrics.score(&left.provider))
                .unwrap_or_default();
            let right_score = metrics
                .as_ref()
                .map(|metrics| metrics.score(&right.provider))
                .unwrap_or_default();
            provider_health_rank(self, left, left_score)
                .cmp(&provider_health_rank(self, right, right_score))
                .then_with(|| {
                    balanced_route_score(left, left_score)
                        .partial_cmp(&balanced_route_score(right, right_score))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| left.priority.cmp(&right.priority))
                .then_with(|| right.weight.cmp(&left.weight))
                .then_with(|| left.provider.cmp(&right.provider))
                .then_with(|| left.provider_model.cmp(&right.provider_model))
        });
    }

    pub(crate) fn can_tenant_use_model(
        &self,
        logical_model: &str,
        organization_id: Option<&str>,
        project_id: Option<&str>,
    ) -> bool {
        self.model_visibility
            .get(logical_model)
            .is_none_or(|visibility| visibility.allows(organization_id, project_id))
    }

    pub(crate) fn normalize_provider_error(
        &self,
        provider_kind: &str,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> Result<ProviderErrorResponse, AdapterError> {
        self.provider_adapters.normalize_error_response(
            provider_kind,
            status,
            content_type,
            body,
            request_id,
        )
    }

    pub(crate) fn extract_provider_usage(
        &self,
        provider_kind: &str,
        body: &[u8],
    ) -> Result<Option<ProviderUsage>, AdapterError> {
        self.provider_adapters.extract_usage(provider_kind, body)
    }

    pub(crate) fn is_provider_status_retryable(
        &self,
        provider_kind: &str,
        status: u16,
    ) -> Result<bool, AdapterError> {
        self.provider_adapters
            .is_retryable_status(provider_kind, status)
    }

    pub(crate) fn provider_dispatch_timeout(&self) -> Duration {
        Duration::from_secs(
            self.config
                .reliability
                .provider_dispatch_timeout_secs
                .unwrap_or(10),
        )
    }

    pub(crate) fn mcp_dispatch_timeout(&self) -> Duration {
        Duration::from_secs(self.config.reliability.mcp_dispatch_timeout_secs)
    }

    pub(crate) fn provider_dispatch_max_retries(&self) -> u32 {
        self.config
            .reliability
            .provider_dispatch_max_retries
            .unwrap_or_default()
    }

    pub(crate) fn provider_response_body_max_bytes(&self) -> usize {
        self.config
            .reliability
            .provider_response_body_max_bytes
            .unwrap_or(16 * 1024 * 1024)
    }

    pub(crate) fn provider_health_checks(&self) -> Vec<ProviderHealthCheck> {
        self.config
            .providers
            .iter()
            .map(|provider| self.provider_health_check(provider))
            .collect()
    }

    pub(crate) fn provider_circuit_allows(&self, provider_name: &str) -> bool {
        let Some(config) = self.provider_circuit_config else {
            return true;
        };
        self.provider_circuits
            .get(provider_name)
            .is_none_or(|circuit| circuit.allows_request(config.cooldown, SystemTime::now()))
    }

    pub(crate) fn record_provider_success(&self, provider_name: &str) {
        if self.provider_circuit_config.is_none() {
            return;
        }
        if let Some(circuit) = self.provider_circuits.get(provider_name) {
            circuit.record_success();
        }
    }

    pub(crate) fn record_provider_failure(&self, provider_name: &str) {
        let Some(config) = self.provider_circuit_config else {
            return;
        };
        if let Some(circuit) = self.provider_circuits.get(provider_name) {
            circuit.record_failure(config.failure_threshold, SystemTime::now());
        }
    }

    fn provider_circuit_snapshot(&self, provider_name: &str) -> ProviderCircuitSnapshot {
        self.provider_circuits
            .get(provider_name)
            .map(|circuit| circuit.snapshot())
            .unwrap_or_default()
    }

    fn provider_health_check(&self, provider: &Provider) -> ProviderHealthCheck {
        let checked_at_unix = now_unix_seconds();
        let circuit = self.provider_circuit_snapshot(&provider.name);
        let local_observations = self.provider_routing_health(provider, circuit.open);
        if !provider.enabled {
            return ProviderHealthCheck {
                name: provider.name.clone(),
                kind: provider.kind.clone(),
                base_url: provider.base_url.clone(),
                enabled: false,
                status: "disabled",
                reachable: false,
                circuit_open: circuit.open,
                consecutive_failures: circuit.consecutive_failures,
                checked_at_unix,
                error: None,
                routing: local_observations,
                local_observations,
                cluster_observations: None,
            };
        }

        let probe = probe_provider_endpoint(&provider.base_url, Duration::from_millis(500));
        let reachable = probe.is_ok();
        let status = if circuit.open {
            "circuit_open"
        } else if reachable {
            "healthy"
        } else {
            "unreachable"
        };

        ProviderHealthCheck {
            name: provider.name.clone(),
            kind: provider.kind.clone(),
            base_url: provider.base_url.clone(),
            enabled: true,
            status,
            reachable,
            circuit_open: circuit.open,
            consecutive_failures: circuit.consecutive_failures,
            checked_at_unix,
            error: probe.err(),
            routing: local_observations,
            local_observations,
            cluster_observations: None,
        }
    }

    fn provider_routing_health(
        &self,
        provider: &Provider,
        circuit_open: bool,
    ) -> ProviderRoutingHealth {
        let metric = self
            .provider_routing_metrics
            .lock()
            .ok()
            .and_then(|metrics| metrics.providers.get(&provider.name).copied())
            .unwrap_or_default();
        if !provider.enabled {
            return metric.health(3, "disabled");
        }
        let score = metric.score();
        metric.health(
            provider_health_rank_from_signals(!circuit_open, score),
            provider_health_reason(circuit_open, score),
        )
    }

    pub(crate) fn try_consume_api_key_request(
        &self,
        api_key_id: &str,
        limit: u64,
    ) -> anyhow::Result<bool> {
        self.cluster_counters.try_consume_request(api_key_id, limit)
    }

    /// P1-3 tokens-per-minute (TPM) quota check, consulted at dispatch time
    /// once the request's estimated token usage is known (unlike RPM, this
    /// cannot be checked at header-parse time in `auth::authenticate`).
    pub(crate) fn try_consume_api_key_tokens_per_minute(
        &self,
        api_key_id: &str,
        limit: u64,
        estimated_tokens: u64,
    ) -> anyhow::Result<bool> {
        self.cluster_counters
            .try_consume_tokens_per_minute(api_key_id, limit, estimated_tokens)
    }

    pub(crate) fn durable_api_key_authenticator(
        &self,
    ) -> &Arc<ferrogate_auth::StorageApiKeyAuthenticator> {
        &self.durable_api_key_authenticator
    }
    pub(crate) fn match_runtime_route(
        &self,
        host: Option<&str>,
        path: &str,
        headers: &HeaderMap,
    ) -> Option<RuntimeRoute> {
        self.runtime_routes
            .iter()
            .filter(|route| route.config.enabled)
            .find(|route| route.matches_request(host, path, headers))
            .cloned()
    }

    pub(crate) fn select_runtime_upstream_endpoint(
        &self,
        upstream_name: &str,
    ) -> Option<RuntimeUpstreamEndpoint> {
        let upstream = self.runtime_upstreams.get(upstream_name)?;
        if upstream.endpoints.is_empty() {
            return None;
        }
        let next = self
            .upstream_counters
            .get(upstream_name)
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed))
            .unwrap_or(0);
        upstream
            .endpoints
            .get(next as usize % upstream.endpoints.len())
            .cloned()
    }

    #[cfg(test)]
    pub(crate) fn select_upstream_url(&self, upstream: &Upstream) -> Option<String> {
        let endpoints = upstream.endpoint_urls();
        if endpoints.is_empty() {
            return None;
        }
        let next = self
            .upstream_counters
            .get(&upstream.name)
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed))
            .unwrap_or(0);
        endpoints
            .get(next as usize % endpoints.len())
            .map(|url| (*url).to_string())
    }
}

#[cfg(test)]
#[path = "state_routing_test.rs"]
mod state_routing_test;
