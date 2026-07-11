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

    #[test]
    fn selects_upstream_endpoints_round_robin() {
        let upstream = Upstream {
            name: "pool".to_string(),
            url: Some("http://127.0.0.1:10001".to_string()),
            urls: vec!["http://127.0.0.1:10002".to_string()],
            enabled: true,
        };
        let config = Config {
            upstreams: vec![upstream.clone()],
            ..Config::default()
        };
        let state = AppState::new(config);

        assert_eq!(
            state.select_upstream_url(&upstream).as_deref(),
            Some("http://127.0.0.1:10001")
        );
        assert_eq!(
            state.select_upstream_url(&upstream).as_deref(),
            Some("http://127.0.0.1:10002")
        );
        assert_eq!(
            state.select_upstream_url(&upstream).as_deref(),
            Some("http://127.0.0.1:10001")
        );
    }

    #[test]
    fn selects_runtime_upstream_endpoints_round_robin() {
        let upstream = Upstream {
            name: "pool".to_string(),
            url: Some("http://127.0.0.1:10001/base".to_string()),
            urls: vec!["https://example.com:9443/api".to_string()],
            enabled: true,
        };
        let config = Config {
            upstreams: vec![upstream],
            ..Config::default()
        };
        let state = AppState::new(config);

        let first = state
            .select_runtime_upstream_endpoint("pool")
            .expect("first endpoint");
        assert_eq!(first.endpoint.scheme, "http");
        assert_eq!(first.endpoint.authority, "127.0.0.1:10001");
        assert_eq!(first.endpoint.base_path, "/base");

        let second = state
            .select_runtime_upstream_endpoint("pool")
            .expect("second endpoint");
        assert_eq!(second.endpoint.scheme, "https");
        assert_eq!(second.endpoint.authority, "example.com:9443");
        assert_eq!(second.endpoint.base_path, "/api");
    }

    #[test]
    fn matches_runtime_route_with_precompiled_headers() {
        let config = Config {
            routes: vec![RouteRule {
                name: "api".into(),
                upstream: "pool".into(),
                hosts: vec!["api.example.com".into()],
                path_prefixes: vec!["/v1".into()],
                match_headers: vec![crate::config::HeaderMatcher {
                    name: "x-tier".into(),
                    value: "gold".into(),
                }],
                strip_prefix: Some("/v1".into()),
                add_prefix: Some("/proxy".into()),
                request_headers: vec![HeaderMutation {
                    name: "x-added".into(),
                    value: "enabled".into(),
                }],
                response_headers: vec![HeaderMutation {
                    name: "x-response-added".into(),
                    value: "done".into(),
                }],
                enabled: true,
            }],
            ..Config::default()
        };
        let state = AppState::new(config);
        let mut headers = HeaderMap::new();
        headers.insert("x-tier", HeaderValue::from_static("gold"));

        let route = state
            .match_runtime_route(Some("api.example.com"), "/v1/chat", &headers)
            .expect("runtime route must match");

        assert_eq!(route.config.name, "api");
        assert_eq!(route.rewrite_path("/v1/chat"), "/proxy/chat");
        assert_eq!(route.request_headers[0].name.as_str(), "x-added");
        assert_eq!(
            route.request_headers[0].value,
            HeaderValue::from_static("enabled")
        );
        assert!(state
            .match_runtime_route(Some("api.example.com"), "/v1/chat", &HeaderMap::new())
            .is_none());
    }

    #[test]
    fn orders_model_fallbacks_with_weighted_rotation_within_priority() {
        let config = Config {
            providers: vec![
                Provider {
                    region: None,
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "primary".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10001/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    region: None,
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "backup-a".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10002/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    region: None,
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "backup-b".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10003/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
            ],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "primary".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![
                    crate::config::ModelFallback {
                        provider: "backup-a".into(),
                        provider_model: "gpt-4.1-mini".into(),
                        input_price_per_1m: Some(2.0),
                        output_price_per_1m: Some(2.0),
                        priority: Some(10),
                        weight: Some(1),
                        enabled: true,
                    },
                    crate::config::ModelFallback {
                        provider: "backup-b".into(),
                        provider_model: "gpt-4.1".into(),
                        input_price_per_1m: Some(1.0),
                        output_price_per_1m: Some(1.0),
                        priority: Some(10),
                        weight: Some(2),
                        enabled: true,
                    },
                ],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: None,
                output_price_per_1m: None,
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        };
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let first = state
            .candidate_model_routes(&resolved, None, &HashSet::new())
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();
        let second = state
            .candidate_model_routes(&resolved, None, &HashSet::new())
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();
        let third = state
            .candidate_model_routes(&resolved, None, &HashSet::new())
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(first, ["primary", "backup-b", "backup-a"]);
        assert_eq!(second, ["primary", "backup-b", "backup-a"]);
        assert_eq!(third, ["primary", "backup-a", "backup-b"]);
    }

    fn region_test_config(routing_strategy: RoutingStrategy) -> Config {
        Config {
            providers: vec![
                Provider {
                    region: Some("eu-west-1".into()),
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "eu-primary".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10001/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    region: Some("us-east-1".into()),
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "us-fallback".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10002/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    region: None,
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "no-region-fallback".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10003/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
            ],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "eu-primary".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy,
                fallbacks: vec![
                    crate::config::ModelFallback {
                        provider: "us-fallback".into(),
                        provider_model: "gpt-4.1-mini".into(),
                        input_price_per_1m: Some(1.0),
                        output_price_per_1m: Some(1.0),
                        priority: Some(10),
                        weight: Some(1),
                        enabled: true,
                    },
                    crate::config::ModelFallback {
                        provider: "no-region-fallback".into(),
                        provider_model: "gpt-4.1".into(),
                        input_price_per_1m: Some(0.5),
                        output_price_per_1m: Some(0.5),
                        priority: Some(20),
                        weight: Some(1),
                        enabled: true,
                    },
                ],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(2.0),
                output_price_per_1m: Some(2.0),
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        }
    }

    #[test]
    fn candidate_model_routes_is_unrestricted_with_an_empty_region_allowlist() {
        let config = region_test_config(RoutingStrategy::Priority);
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let routes = state.candidate_model_routes(&resolved, None, &HashSet::new());
        assert_eq!(routes.len(), 3, "no region_allowlist means no filtering");
    }

    #[test]
    fn candidate_model_routes_filters_by_region_for_priority_strategy() {
        let config = region_test_config(RoutingStrategy::Priority);
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let region_allowlist = HashSet::from(["eu-west-1".to_string()]);
        let routes = state.candidate_model_routes(&resolved, None, &region_allowlist);
        let providers: Vec<_> = routes.iter().map(|route| route.provider.as_str()).collect();
        assert_eq!(
            providers,
            ["eu-primary"],
            "us-fallback (wrong region) and no-region-fallback (undeclared region) must both \
             be excluded once a region_allowlist is set"
        );
    }

    #[test]
    fn candidate_model_routes_region_filter_applies_to_lowest_cost_strategy_too() {
        let config = region_test_config(RoutingStrategy::LowestCost);
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();

        // no-region-fallback is the cheapest route and would normally sort
        // first under LowestCost -- it must still be excluded by the
        // region filter, proving the filter isn't strategy-specific.
        let region_allowlist = HashSet::from(["eu-west-1".to_string()]);
        let routes = state.candidate_model_routes(&resolved, None, &region_allowlist);
        let providers: Vec<_> = routes.iter().map(|route| route.provider.as_str()).collect();
        assert_eq!(providers, ["eu-primary"]);
    }

    #[test]
    fn candidate_model_routes_fails_closed_when_no_route_satisfies_the_region_allowlist() {
        let config = region_test_config(RoutingStrategy::Priority);
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let region_allowlist = HashSet::from(["ap-southeast-1".to_string()]);
        let routes = state.candidate_model_routes(&resolved, None, &region_allowlist);
        assert!(
            routes.is_empty(),
            "no configured provider is in ap-southeast-1, so the candidate list must be empty, \
             not silently fall back to an out-of-region provider"
        );
    }

    #[test]
    fn orders_lowest_cost_routes_by_estimated_price() {
        let config = Config {
            providers: vec![
                Provider {
                    region: None,
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "primary".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10001/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    region: None,
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "backup-a".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10002/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
                Provider {
                    region: None,
                    aws_access_key_id: None,
                    aws_secret_access_key_env: None,
                    aws_session_token_env: None,
                    gcp_project_id: None,
                    gcp_access_token_env: None,
                    name: "backup-b".into(),
                    kind: "openai".into(),
                    base_url: "http://127.0.0.1:10003/v1".into(),
                    api_key_env: None,
                    secret_ref: None,
                    openrouter_http_referer: None,
                    openrouter_x_title: None,
                    enabled: true,
                },
            ],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "primary".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::LowestCost,
                fallbacks: vec![
                    crate::config::ModelFallback {
                        provider: "backup-a".into(),
                        provider_model: "gpt-4.1-mini".into(),
                        input_price_per_1m: Some(2.0),
                        output_price_per_1m: Some(2.0),
                        priority: Some(10),
                        weight: Some(1),
                        enabled: true,
                    },
                    crate::config::ModelFallback {
                        provider: "backup-b".into(),
                        provider_model: "gpt-4.1".into(),
                        input_price_per_1m: Some(1.0),
                        output_price_per_1m: Some(1.0),
                        priority: Some(10),
                        weight: Some(2),
                        enabled: true,
                    },
                ],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(5.0),
                output_price_per_1m: Some(5.0),
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        };
        config.validate().unwrap();
        let state = AppState::new(config);
        let resolved = state.resolve_model("fast-chat").unwrap();
        let usage = BillingTokenUsage::new(1_000, 2_000, 3_000);

        let providers = state
            .candidate_model_routes(&resolved, Some(&usage), &HashSet::new())
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(providers, ["backup-b", "backup-a", "primary"]);
    }

    #[test]
    fn orders_lowest_latency_routes_by_observed_provider_latency() {
        let state = AppState::new(routing_strategy_test_config(
            RoutingStrategy::LowestLatency,
            Some(5.0),
            Some(5.0),
        ));
        record_provider_latency(&state, "primary", 200, 0, 1);
        record_provider_latency(&state, "backup-a", 200, 0, 3);
        record_provider_latency(&state, "backup-b", 200, 0, 2);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let providers = state
            .candidate_model_routes(&resolved, None, &HashSet::new())
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(providers, ["primary", "backup-b", "backup-a"]);
    }

    #[test]
    fn latency_routing_avoids_unhealthy_observed_provider() {
        let state = AppState::new(routing_strategy_test_config(
            RoutingStrategy::LowestLatency,
            Some(5.0),
            Some(5.0),
        ));
        record_provider_latency(&state, "primary", 500, 0, 1);
        record_provider_latency(&state, "primary", 500, 0, 1);
        record_provider_latency(&state, "primary", 200, 0, 1);
        record_provider_latency(&state, "backup-a", 200, 0, 5);
        record_provider_latency(&state, "backup-b", 200, 0, 10);
        let resolved = state.resolve_model("fast-chat").unwrap();

        let providers = state
            .candidate_model_routes(&resolved, None, &HashSet::new())
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(providers, ["backup-a", "backup-b", "primary"]);
    }

    #[test]
    fn provider_health_exposes_routing_observations_and_rank_reason() {
        let state = AppState::new(routing_strategy_test_config(
            RoutingStrategy::LowestLatency,
            Some(5.0),
            Some(5.0),
        ));
        record_provider_latency(&state, "primary", 500, 0, 1);
        record_provider_latency(&state, "primary", 500, 0, 1);
        record_provider_latency(&state, "primary", 200, 0, 1);

        let primary = state
            .provider_health_checks()
            .into_iter()
            .find(|check| check.name == "primary")
            .unwrap();

        assert_eq!(primary.routing.observed_requests, 3);
        assert_eq!(primary.routing.successful_requests, 1);
        assert_eq!(primary.routing.failed_requests, 2);
        assert_eq!(primary.routing.average_latency_ms, Some(1_000));
        assert!((primary.routing.failure_rate - 0.666).abs() < 0.001);
        assert_eq!(primary.routing.health_rank, 1);
        assert_eq!(primary.routing.health_reason, "observed_failure_rate");
    }

    #[test]
    fn balanced_routing_combines_cost_latency_and_failures() {
        let state = AppState::new(routing_strategy_test_config(
            RoutingStrategy::Balanced,
            Some(5.0),
            Some(5.0),
        ));
        record_provider_latency(&state, "primary", 200, 0, 1);
        record_provider_latency(&state, "backup-a", 200, 0, 4);
        record_provider_latency(&state, "backup-b", 500, 0, 1);
        record_provider_latency(&state, "backup-b", 500, 0, 1);
        record_provider_latency(&state, "backup-b", 200, 0, 1);
        let resolved = state.resolve_model("fast-chat").unwrap();
        let usage = BillingTokenUsage::new(1_000, 1_000, 2_000);

        let providers = state
            .candidate_model_routes(&resolved, Some(&usage), &HashSet::new())
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();

        assert_eq!(providers, ["backup-a", "primary", "backup-b"]);
    }

    #[test]
    fn provider_circuit_opens_after_configured_failures_and_resets_on_success() {
        let config = Config {
            reliability: crate::config::ReliabilityConfig {
                provider_circuit_breaker_failure_threshold: Some(2),
                provider_circuit_breaker_cooldown_secs: Some(60),
                ..crate::config::ReliabilityConfig::default()
            },
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
        };
        let state = AppState::new(config);

        assert!(state.provider_circuit_allows("openai"));
        state.record_provider_failure("openai");
        assert!(state.provider_circuit_allows("openai"));
        state.record_provider_failure("openai");
        assert!(!state.provider_circuit_allows("openai"));
        state.record_provider_success("openai");
        assert!(state.provider_circuit_allows("openai"));
    }

    #[test]
    fn provider_circuit_is_disabled_without_reliability_config() {
        let state = AppState::new(Config {
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

        state.record_provider_failure("openai");
        state.record_provider_failure("openai");

        assert!(state.provider_circuit_allows("openai"));
    }

    #[test]
    fn provider_config_prefers_resolved_secret_ref_over_api_key_env() {
        std::env::set_var("FERROGATE_STATE_TEST_SECRET_REF_KEY", "from-secret-ref");
        std::env::set_var("FERROGATE_STATE_TEST_API_KEY_ENV_KEY", "from-api-key-env");
        let mut provider = test_provider();
        provider.api_key_env = Some("FERROGATE_STATE_TEST_API_KEY_ENV_KEY".into());
        provider.secret_ref = Some("env://FERROGATE_STATE_TEST_SECRET_REF_KEY".into());
        let state = AppState::new(Config {
            providers: vec![provider.clone()],
            ..Config::default()
        });

        let config = state.provider_config(&provider);

        assert_eq!(config.api_key.as_deref(), Some("from-secret-ref"));
    }

    #[test]
    fn provider_config_falls_back_to_api_key_env_when_secret_ref_unresolvable() {
        std::env::remove_var("FERROGATE_STATE_TEST_UNSET_SECRET_REF_KEY");
        std::env::set_var(
            "FERROGATE_STATE_TEST_FALLBACK_API_KEY_ENV",
            "fallback-value",
        );
        let mut provider = test_provider();
        provider.api_key_env = Some("FERROGATE_STATE_TEST_FALLBACK_API_KEY_ENV".into());
        provider.secret_ref = Some("env://FERROGATE_STATE_TEST_UNSET_SECRET_REF_KEY".into());
        let state = AppState::new(Config {
            providers: vec![provider.clone()],
            ..Config::default()
        });

        let config = state.provider_config(&provider);

        assert_eq!(config.api_key.as_deref(), Some("fallback-value"));
    }

    #[test]
    fn provider_config_uses_api_key_env_when_no_secret_ref_configured() {
        std::env::set_var("FERROGATE_STATE_TEST_PLAIN_API_KEY_ENV", "plain-value");
        let mut provider = test_provider();
        provider.api_key_env = Some("FERROGATE_STATE_TEST_PLAIN_API_KEY_ENV".into());
        let state = AppState::new(Config {
            providers: vec![provider.clone()],
            ..Config::default()
        });

        let config = state.provider_config(&provider);

        assert_eq!(config.api_key.as_deref(), Some("plain-value"));
    }

    #[test]
    fn provider_health_reports_disabled_provider_without_probe() {
        let state = AppState::new(Config {
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "disabled".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:1/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: false,
            }],
            ..Config::default()
        });

        let checks = state.provider_health_checks();

        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, "disabled");
        assert!(!checks[0].reachable);
    }

    #[test]
    fn api_key_request_window_rejects_after_configured_limit() {
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
                organization_id: None,
                team_id: None,
                project_id: None,
                workspace_id: None,
                user_id: None,
                monthly_token_budget: None,
                request_limit_per_minute: Some(1),
                expires_at_unix: None,
                log_bodies: None,
                cache_enabled: None,
            }],
            ..Config::default()
        });

        assert!(state.try_consume_api_key_request("key_dev", 1).unwrap());
        assert!(!state.try_consume_api_key_request("key_dev", 1).unwrap());
    }

    #[test]
    fn api_key_token_reservation_counts_against_budget_until_released() {
        let state = AppState::new(Config::default());

        let reservation = state
            .try_reserve_api_key_tokens("key_dev", 10, 7)
            .unwrap()
            .expect("first reservation should fit");

        assert_eq!(
            state
                .api_key_tokens_committed_or_reserved("key_dev")
                .unwrap(),
            7
        );
        assert!(state
            .try_reserve_api_key_tokens("key_dev", 10, 4)
            .unwrap()
            .is_none());

        drop(reservation);

        assert_eq!(
            state
                .api_key_tokens_committed_or_reserved("key_dev")
                .unwrap(),
            0
        );
        assert!(state
            .try_reserve_api_key_tokens("key_dev", 10, 4)
            .unwrap()
            .is_some());
    }

    fn routing_strategy_test_config(
        routing_strategy: RoutingStrategy,
        primary_input_price: Option<f64>,
        primary_output_price: Option<f64>,
    ) -> Config {
        let config = Config {
            providers: vec![
                provider_config("primary", "http://127.0.0.1:10001/v1"),
                provider_config("backup-a", "http://127.0.0.1:10002/v1"),
                provider_config("backup-b", "http://127.0.0.1:10003/v1"),
            ],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "primary".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy,
                fallbacks: vec![
                    crate::config::ModelFallback {
                        provider: "backup-a".into(),
                        provider_model: "gpt-4.1-mini".into(),
                        input_price_per_1m: Some(2.0),
                        output_price_per_1m: Some(2.0),
                        priority: Some(10),
                        weight: Some(1),
                        enabled: true,
                    },
                    crate::config::ModelFallback {
                        provider: "backup-b".into(),
                        provider_model: "gpt-4.1".into(),
                        input_price_per_1m: Some(1.0),
                        output_price_per_1m: Some(1.0),
                        priority: Some(10),
                        weight: Some(2),
                        enabled: true,
                    },
                ],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: primary_input_price,
                output_price_per_1m: primary_output_price,
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        };
        config.validate().unwrap();
        config
    }

    fn provider_config(name: &str, base_url: &str) -> Provider {
        Provider {
            region: None,
            aws_access_key_id: None,
            aws_secret_access_key_env: None,
            aws_session_token_env: None,
            gcp_project_id: None,
            gcp_access_token_env: None,
            name: name.into(),
            kind: "openai".into(),
            base_url: base_url.into(),
            api_key_env: None,
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }
    }

    fn record_provider_latency(
        state: &AppState,
        provider: &str,
        status_code: u16,
        started_at_unix: u64,
        completed_at_unix: u64,
    ) {
        state.record_request_log(StoredRequestLog {
            request_id: format!("fg-{provider}-{status_code}-{completed_at_unix}"),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: ferrogate_core::TenantContext::default(),
            route: Some("openai.chat.completions".into()),
            provider: Some(provider.into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code,
            error_code: (status_code >= 400).then(|| "provider_error".into()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: Some(started_at_unix),
            completed_at_unix: Some(completed_at_unix),
        });
    }
}
