use anyhow::{bail, Context, Result as AnyResult};
use http::{HeaderName, HeaderValue};
use pingora::tls::load_certs_and_key_files;
use std::collections::HashSet;

use crate::routing::parse_upstream_endpoint;
use ferrogate_providers::RoutingStrategy;

use super::Config;

impl Config {
    pub(crate) fn validate(&self) -> AnyResult<()> {
        self.listen
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("field listen: invalid listen address {}", self.listen))?;
        if let Some(admin_listen) = &self.admin.listen {
            normalize_listen_addr(admin_listen).with_context(|| {
                format!("field admin.listen: invalid admin listen address {admin_listen}")
            })?;
        }

        let provider_names = self.validate_providers()?;
        let model_names = self.validate_models(&provider_names)?;
        let api_key_ids = self.validate_api_keys(&model_names, &provider_names)?;
        self.validate_policies(&api_key_ids, &model_names, &provider_names)?;
        self.validate_extensions()?;
        self.validate_tls()?;
        self.validate_telemetry()?;
        self.validate_metering()?;
        self.validate_storage()?;
        self.validate_reliability()?;
        self.validate_cluster()?;
        let upstream_names = self.validate_upstreams()?;
        self.validate_routes(&upstream_names)?;
        Ok(())
    }

    fn validate_tls(&self) -> AnyResult<()> {
        if !self.tls.is_enabled() {
            return Ok(());
        }

        let has_cert = self
            .tls
            .cert_path
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let has_key = self
            .tls
            .key_path
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());

        if self.tls.acme.enabled && (has_cert || has_key) {
            bail!("field tls.acme.enabled: cannot be combined with tls.cert_path/tls.key_path");
        }

        if self.tls.acme.enabled {
            self.validate_acme_tls()?;
            return Ok(());
        }

        if !has_cert {
            bail!("field tls.cert_path: required when TLS is enabled");
        }
        if !has_key {
            bail!("field tls.key_path: required when TLS is enabled");
        }

        let cert_path = self.tls.cert_path.as_deref().unwrap();
        let key_path = self.tls.key_path.as_deref().unwrap();
        validate_manual_tls_files(cert_path, key_path)?;

        Ok(())
    }

    fn validate_acme_tls(&self) -> AnyResult<()> {
        let acme = &self.tls.acme;
        if acme.domains.is_empty() {
            bail!("field tls.acme.domains: at least one domain is required");
        }
        for (index, domain) in acme.domains.iter().enumerate() {
            let domain = domain.trim();
            if domain.is_empty() {
                bail!("field tls.acme.domains[{index}]: cannot be empty");
            }
            if domain.contains('/') || domain.contains(':') {
                bail!(
                    "field tls.acme.domains[{index}]: must be a DNS name, not a URL or host:port"
                );
            }
        }
        let email = acme
            .email
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("field tls.acme.email: required when ACME is enabled")
            })?;
        if !email.contains('@') {
            bail!("field tls.acme.email: must be an email address");
        }
        if acme.directory_url.trim().is_empty() {
            bail!("field tls.acme.directory_url: cannot be empty");
        }
        if !acme.directory_url.starts_with("https://") {
            bail!("field tls.acme.directory_url: must start with https://");
        }
        if !acme.terms_agreed {
            bail!("field tls.acme.terms_agreed: must be true to use ACME");
        }
        match acme.challenge.as_str() {
            "dns-01" => self.validate_acme_dns01_tls()?,
            "http-01" => self.validate_acme_http01_tls()?,
            _ => bail!("field tls.acme.challenge: must be dns-01 or http-01"),
        }
        if acme.storage_dir.trim().is_empty() {
            bail!("field tls.acme.storage_dir: cannot be empty");
        }
        if acme.dns_propagation_delay_secs == 0 {
            bail!("field tls.acme.dns_propagation_delay_secs: must be greater than zero");
        }
        if acme.renewal_window_secs == 0 {
            bail!("field tls.acme.renewal_window_secs: must be greater than zero");
        }
        if acme.renewal_check_interval_secs == 0 {
            bail!("field tls.acme.renewal_check_interval_secs: must be greater than zero");
        }
        if acme.renewal_retry_interval_secs == 0 {
            bail!("field tls.acme.renewal_retry_interval_secs: must be greater than zero");
        }

        Ok(())
    }

    fn validate_acme_dns01_tls(&self) -> AnyResult<()> {
        let acme = &self.tls.acme;
        if acme
            .dns_provider
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            bail!("field tls.acme.dns_provider: cannot be empty");
        }
        for (key, value) in &acme.dns_config {
            if key.trim().is_empty() {
                bail!("field tls.acme.dns_config: keys cannot be empty");
            }
            if value.trim().is_empty() {
                bail!("field tls.acme.dns_config.{key}: cannot be empty");
            }
        }
        let has_set_hook = acme
            .dns_hook_set
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let has_cleanup_hook = acme
            .dns_hook_cleanup
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let uses_builtin_cloudflare = acme
            .dns_provider
            .as_deref()
            .is_some_and(|provider| provider.trim().eq_ignore_ascii_case("cloudflare"));
        if has_set_hook != has_cleanup_hook {
            bail!("fields tls.acme.dns_hook_set and tls.acme.dns_hook_cleanup: configure both hooks or neither");
        }
        if !has_set_hook && !uses_builtin_cloudflare {
            bail!("field tls.acme.dns_provider: dns-01 requires built-in provider cloudflare or dns hooks");
        }
        if uses_builtin_cloudflare && !has_set_hook {
            if !acme.dns_config.contains_key("api_token") {
                bail!("field tls.acme.dns_config.api_token: required for cloudflare dns-01");
            }
            if !acme.dns_config.contains_key("zone_id")
                && !acme.dns_config.contains_key("zone_name")
            {
                bail!("field tls.acme.dns_config.zone_id: required for cloudflare dns-01 unless zone_name is configured");
            }
        }
        Ok(())
    }

    fn validate_acme_http01_tls(&self) -> AnyResult<()> {
        let acme = &self.tls.acme;
        for (index, domain) in acme.domains.iter().enumerate() {
            if domain.trim().starts_with("*.") {
                bail!("field tls.acme.domains[{index}]: wildcard domains require dns-01");
            }
        }
        normalize_listen_addr(&acme.http_challenge_listen).with_context(|| {
            format!(
                "field tls.acme.http_challenge_listen: invalid listen address {}",
                acme.http_challenge_listen
            )
        })?;

        Ok(())
    }

    fn validate_telemetry(&self) -> AnyResult<()> {
        if self.telemetry.service_name.trim().is_empty() {
            bail!("field telemetry.service_name: cannot be empty");
        }
        if self.telemetry.access_log_sample_rate == 0 {
            bail!("field telemetry.access_log_sample_rate: must be greater than zero");
        }
        if self.telemetry.access_log_error_rate_limit_per_sec == 0 {
            bail!("field telemetry.access_log_error_rate_limit_per_sec: must be greater than zero");
        }
        if let Some(endpoint) = &self.telemetry.otlp_endpoint {
            if endpoint.trim().is_empty() {
                bail!("field telemetry.otlp_endpoint: cannot be empty");
            }
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                bail!("field telemetry.otlp_endpoint: must start with http:// or https://");
            }
        }
        Ok(())
    }

    fn validate_metering(&self) -> AnyResult<()> {
        if self.metering.export_endpoint.trim().is_empty() {
            bail!("field metering.export_endpoint: cannot be empty");
        }
        if !self.metering.export_endpoint.starts_with("http://")
            && !self.metering.export_endpoint.starts_with("https://")
        {
            bail!("field metering.export_endpoint: must start with http:// or https://");
        }
        if self.metering.export_timeout_secs == 0 {
            bail!("field metering.export_timeout_secs: must be greater than zero");
        }
        let has_token_env = self
            .metering
            .export_token_env
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let has_inline_token = self
            .metering
            .export_token
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if self.metering.export_enabled && !has_token_env && !has_inline_token {
            bail!(
                "field metering.export_token_env: required when metering export is enabled unless metering.export_token is set"
            );
        }
        Ok(())
    }

    fn validate_storage(&self) -> AnyResult<()> {
        if self.storage.request_log_retention_records == 0 {
            bail!("field storage.request_log_retention_records: must be greater than zero");
        }
        if self.storage.audit_event_retention_records == 0 {
            bail!("field storage.audit_event_retention_records: must be greater than zero");
        }
        if self.storage.billing_event_retention_records == 0 {
            bail!("field storage.billing_event_retention_records: must be greater than zero");
        }
        if self.storage.admin_list_default_limit == 0 {
            bail!("field storage.admin_list_default_limit: must be greater than zero");
        }
        if self.storage.admin_list_max_limit == 0 {
            bail!("field storage.admin_list_max_limit: must be greater than zero");
        }
        if self.storage.admin_list_default_limit > self.storage.admin_list_max_limit {
            bail!(
                "field storage.admin_list_default_limit: must be less than or equal to storage.admin_list_max_limit"
            );
        }
        Ok(())
    }

    fn validate_reliability(&self) -> AnyResult<()> {
        let threshold = self.reliability.provider_circuit_breaker_failure_threshold;
        let cooldown = self.reliability.provider_circuit_breaker_cooldown_secs;
        let dispatch_timeout = self.reliability.provider_dispatch_timeout_secs;
        let provider_body_max_bytes = self.reliability.provider_response_body_max_bytes;
        let shutdown_grace_period = self.reliability.graceful_shutdown_grace_period_secs;
        let shutdown_timeout = self.reliability.graceful_shutdown_timeout_secs;
        let graceful_upgrade_pid_file = self.reliability.graceful_upgrade_pid_file.as_deref();
        let graceful_upgrade_sock = self.reliability.graceful_upgrade_sock.as_deref();

        match (threshold, cooldown) {
            (Some(0), _) => bail!(
                "field reliability.provider_circuit_breaker_failure_threshold: must be greater than zero"
            ),
            (_, Some(0)) => bail!(
                "field reliability.provider_circuit_breaker_cooldown_secs: must be greater than zero"
            ),
            (Some(_), None) => bail!(
                "field reliability.provider_circuit_breaker_cooldown_secs: required when provider circuit breaker threshold is set"
            ),
            (None, Some(_)) => bail!(
                "field reliability.provider_circuit_breaker_failure_threshold: required when provider circuit breaker cooldown is set"
            ),
            _ => {}
        }

        if dispatch_timeout == Some(0) {
            bail!("field reliability.provider_dispatch_timeout_secs: must be greater than zero");
        }
        if provider_body_max_bytes == Some(0) {
            bail!("field reliability.provider_response_body_max_bytes: must be greater than zero");
        }
        if shutdown_grace_period == Some(0) {
            bail!(
                "field reliability.graceful_shutdown_grace_period_secs: must be greater than zero"
            );
        }
        if shutdown_timeout == Some(0) {
            bail!("field reliability.graceful_shutdown_timeout_secs: must be greater than zero");
        }
        if graceful_upgrade_pid_file.is_some_and(|path| path.trim().is_empty()) {
            bail!("field reliability.graceful_upgrade_pid_file: cannot be empty");
        }
        if graceful_upgrade_sock.is_some_and(|path| path.trim().is_empty()) {
            bail!("field reliability.graceful_upgrade_sock: cannot be empty");
        }
        if self.reliability.graceful_upgrade_sock_retries == Some(0) {
            bail!("field reliability.graceful_upgrade_sock_retries: must be greater than zero");
        }

        Ok(())
    }

    fn validate_cluster(&self) -> AnyResult<()> {
        if !self.cluster.enabled {
            return Ok(());
        }
        if self.cluster.cluster_id.trim().is_empty() {
            bail!("field cluster.cluster_id: cannot be empty when cluster mode is enabled");
        }
        if self.cluster.node_id.trim().is_empty() {
            bail!("field cluster.node_id: cannot be empty when cluster mode is enabled");
        }
        if self
            .cluster
            .node_region
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            bail!("field cluster.node_region: cannot be empty");
        }
        if self
            .cluster
            .node_zone
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            bail!("field cluster.node_zone: cannot be empty");
        }
        if self.cluster.state_backend.trim().is_empty() {
            bail!("field cluster.state_backend: cannot be empty");
        }
        if self.cluster.counter_backend.trim().is_empty() {
            bail!("field cluster.counter_backend: cannot be empty");
        }
        if self.cluster.counter_timeout_millis == 0 {
            bail!("field cluster.counter_timeout_millis: must be greater than zero");
        }
        if self.cluster.heartbeat_interval_secs == 0 {
            bail!("field cluster.heartbeat_interval_secs: must be greater than zero");
        }
        if self.cluster.config_poll_interval_secs == 0 {
            bail!("field cluster.config_poll_interval_secs: must be greater than zero");
        }
        match self.cluster.state_backend.as_str() {
            "local" => {}
            "file" => {
                if self
                    .cluster
                    .file_state_path
                    .as_deref()
                    .is_none_or(|path| path.trim().is_empty())
                {
                    bail!("field cluster.file_state_path: required when cluster.state_backend is file");
                }
            }
            _ => {
                bail!(
                    "field cluster.state_backend: only local and file are supported until database shared state lands"
                );
            }
        }
        if self.cluster.counter_backend != "local" {
            match self.cluster.counter_backend.as_str() {
                "redis" => {
                    let redis_url = self
                        .cluster
                        .redis_url
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "field cluster.redis_url: required when cluster.counter_backend is redis"
                            )
                        })?;
                    if !redis_url.starts_with("redis://") && !redis_url.starts_with("rediss://") {
                        bail!("field cluster.redis_url: must start with redis:// or rediss://");
                    }
                }
                _ => {
                    bail!("field cluster.counter_backend: only local and redis are supported");
                }
            }
        }
        Ok(())
    }

    fn validate_providers(&self) -> AnyResult<HashSet<&str>> {
        let mut names = HashSet::new();
        for (index, provider) in self.providers.iter().enumerate() {
            if provider.name.trim().is_empty() {
                bail!("field providers[{index}].name: cannot be empty");
            }
            if !names.insert(provider.name.as_str()) {
                bail!(
                    "field providers[{index}].name: duplicate provider name {}",
                    provider.name
                );
            }
            if provider.base_url.trim().is_empty() {
                bail!("field providers[{index}].base_url: cannot be empty");
            }
            if provider.api_key_env.as_deref().is_some_and(str::is_empty) {
                bail!("field providers[{index}].api_key_env: cannot be empty");
            }
            if provider
                .openrouter_http_referer
                .as_deref()
                .is_some_and(str::is_empty)
            {
                bail!("field providers[{index}].openrouter_http_referer: cannot be empty");
            }
            if provider
                .openrouter_x_title
                .as_deref()
                .is_some_and(str::is_empty)
            {
                bail!("field providers[{index}].openrouter_x_title: cannot be empty");
            }
        }
        Ok(names)
    }

    fn validate_models<'a>(
        &'a self,
        provider_names: &HashSet<&str>,
    ) -> AnyResult<HashSet<&'a str>> {
        let mut names = HashSet::new();
        for (index, model) in self.models.iter().enumerate() {
            if model.name.trim().is_empty() {
                bail!("field models[{index}].name: cannot be empty");
            }
            if !names.insert(model.name.as_str()) {
                bail!(
                    "field models[{index}].name: duplicate model name {}",
                    model.name
                );
            }
            if !provider_names.contains(model.provider.as_str()) {
                bail!(
                    "field models[{index}].provider: model {} references unknown provider {}",
                    model.name,
                    model.provider
                );
            }
            if model.provider_model.trim().is_empty() {
                bail!("field models[{index}].provider_model: cannot be empty");
            }
            if matches!(model.routing_strategy, RoutingStrategy::LowestCost)
                && (model.input_price_per_1m.is_none() || model.output_price_per_1m.is_none())
            {
                bail!(
                    "field models[{index}].routing_strategy: lowest_cost requires input_price_per_1m and output_price_per_1m on the primary model"
                );
            }
            for (fallback_index, fallback) in model.fallbacks.iter().enumerate() {
                if !fallback.enabled {
                    continue;
                }
                if !provider_names.contains(fallback.provider.as_str()) {
                    bail!(
                        "field models[{index}].fallbacks[{fallback_index}].provider: model {} references unknown fallback provider {}",
                        model.name,
                        fallback.provider
                    );
                }
                if fallback.provider_model.trim().is_empty() {
                    bail!(
                        "field models[{index}].fallbacks[{fallback_index}].provider_model: cannot be empty"
                    );
                }
                if matches!(model.routing_strategy, RoutingStrategy::LowestCost)
                    && (fallback.input_price_per_1m.is_none()
                        || fallback.output_price_per_1m.is_none())
                {
                    bail!(
                        "field models[{index}].fallbacks[{fallback_index}]: lowest_cost requires input_price_per_1m and output_price_per_1m"
                    );
                }
                if fallback.weight == Some(0) {
                    bail!(
                        "field models[{index}].fallbacks[{fallback_index}].weight: must be greater than zero"
                    );
                }
            }
        }
        Ok(names)
    }

    fn validate_api_keys<'a>(
        &'a self,
        model_names: &HashSet<&str>,
        provider_names: &HashSet<&str>,
    ) -> AnyResult<HashSet<&'a str>> {
        let mut ids = HashSet::new();
        for (index, key) in self.api_keys.iter().enumerate() {
            if key.id.trim().is_empty() {
                bail!("field api_keys[{index}].id: cannot be empty");
            }
            if !ids.insert(key.id.as_str()) {
                bail!(
                    "field api_keys[{index}].id: duplicate api key id {}",
                    key.id
                );
            }
            if key.key_env.as_deref().is_some_and(str::is_empty) {
                bail!("field api_keys[{index}].key_env: cannot be empty");
            }
            if key.key.as_deref().is_some_and(str::is_empty) {
                bail!("field api_keys[{index}].key: cannot be empty");
            }
            if key.key_hash.as_deref().is_some_and(str::is_empty) {
                bail!("field api_keys[{index}].key_hash: cannot be empty");
            }
            if let Some(key_hash) = &key.key_hash {
                if !key_hash.starts_with("blake2b:") {
                    bail!("field api_keys[{index}].key_hash: unsupported key hash format");
                }
            }
            if key.key_env.is_none() && key.key.is_none() && key.key_hash.is_none() {
                bail!("field api_keys[{index}].key_env: key_env, key, or key_hash is required");
            }
            for allowed_model in &key.allowed_models {
                if !model_names.contains(allowed_model.as_str()) {
                    bail!(
                        "field api_keys[{index}].allowed_models: api key {} allows unknown model {}",
                        key.id,
                        allowed_model
                    );
                }
            }
            for denied_model in &key.denied_models {
                if !model_names.contains(denied_model.as_str()) {
                    bail!(
                        "field api_keys[{index}].denied_models: api key {} denies unknown model {}",
                        key.id,
                        denied_model
                    );
                }
            }
            for allowed_provider in &key.allowed_providers {
                if !provider_names.contains(allowed_provider.as_str()) {
                    bail!(
                        "field api_keys[{index}].allowed_providers: api key {} allows unknown provider {}",
                        key.id,
                        allowed_provider
                    );
                }
            }
            for denied_provider in &key.denied_providers {
                if !provider_names.contains(denied_provider.as_str()) {
                    bail!(
                        "field api_keys[{index}].denied_providers: api key {} denies unknown provider {}",
                        key.id,
                        denied_provider
                    );
                }
            }
        }
        Ok(ids)
    }

    fn validate_policies(
        &self,
        api_key_ids: &HashSet<&str>,
        model_names: &HashSet<&str>,
        provider_names: &HashSet<&str>,
    ) -> AnyResult<()> {
        let mut names = HashSet::new();
        for (index, policy) in self.policies.iter().enumerate() {
            if policy.name.trim().is_empty() {
                bail!("field policies[{index}].name: cannot be empty");
            }
            if !names.insert(policy.name.as_str()) {
                bail!(
                    "field policies[{index}].name: duplicate policy name {}",
                    policy.name
                );
            }
            if !policy.effect.eq_ignore_ascii_case("deny") {
                bail!("field policies[{index}].effect: only deny is supported in the MVP");
            }
            for api_key_id in &policy.api_key_ids {
                if !api_key_ids.contains(api_key_id.as_str()) {
                    bail!(
                        "field policies[{index}].api_key_ids: policy {} references unknown api key {}",
                        policy.name,
                        api_key_id
                    );
                }
            }
            for model in &policy.models {
                if !model_names.contains(model.as_str()) {
                    bail!(
                        "field policies[{index}].models: policy {} references unknown model {}",
                        policy.name,
                        model
                    );
                }
            }
            for provider in &policy.providers {
                if !provider_names.contains(provider.as_str()) {
                    bail!(
                        "field policies[{index}].providers: policy {} references unknown provider {}",
                        policy.name,
                        provider
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_extensions(&self) -> AnyResult<()> {
        let mut ids = HashSet::new();
        let mut enabled_orders = HashSet::new();

        for (index, extension) in self.extensions.iter().enumerate() {
            if extension.id.trim().is_empty() {
                bail!("field extensions[{index}].id: cannot be empty");
            }
            if !ids.insert(extension.id.as_str()) {
                bail!(
                    "field extensions[{index}].id: duplicate extension id {}",
                    extension.id
                );
            }
            if extension.source.trim().is_empty() {
                bail!("field extensions[{index}].source: cannot be empty");
            }
            if extension.source != "builtin" {
                bail!(
                    "field extensions[{index}].source: only builtin extensions are supported in this phase"
                );
            }
            if extension.enabled
                && !enabled_orders.insert((extension.kind.clone(), extension.order))
            {
                bail!(
                    "field extensions[{index}].order: duplicate enabled extension order {} for kind {:?}",
                    extension.order,
                    extension.kind
                );
            }

            validate_extension_permission_names(
                index,
                "permissions.tools",
                &extension.permissions.tools,
            )?;
            validate_extension_permission_names(
                index,
                "permissions.network",
                &extension.permissions.network,
            )?;
        }

        Ok(())
    }

    fn validate_upstreams(&self) -> AnyResult<HashSet<&str>> {
        let mut names = HashSet::new();
        for (index, upstream) in self.upstreams.iter().enumerate() {
            if upstream.name.trim().is_empty() {
                bail!("field upstreams[{index}].name: cannot be empty");
            }
            if !names.insert(upstream.name.as_str()) {
                bail!(
                    "field upstreams[{index}].name: duplicate upstream name {}",
                    upstream.name
                );
            }
            let endpoints = upstream.endpoint_urls();
            if endpoints.is_empty() {
                bail!("field upstreams[{index}].url: upstream must define url or urls");
            }
            for (endpoint_index, endpoint) in endpoints.into_iter().enumerate() {
                parse_upstream_endpoint(endpoint).with_context(|| {
                    format!(
                        "field upstreams[{index}].urls[{endpoint_index}]: upstream {} has invalid endpoint {}",
                        upstream.name, endpoint
                    )
                })?;
            }
        }
        Ok(names)
    }

    fn validate_routes(&self, upstream_names: &HashSet<&str>) -> AnyResult<()> {
        let mut names = HashSet::new();
        for (index, route) in self.routes.iter().enumerate() {
            if route.name.trim().is_empty() {
                bail!("field routes[{index}].name: cannot be empty");
            }
            if !names.insert(route.name.as_str()) {
                bail!(
                    "field routes[{index}].name: duplicate route name {}",
                    route.name
                );
            }
            if !upstream_names.contains(route.upstream.as_str()) {
                bail!(
                    "field routes[{index}].upstream: route {} references unknown upstream {}",
                    route.name,
                    route.upstream
                );
            }
            for prefix in route.path_prefixes.iter().chain(route.strip_prefix.iter()) {
                if !prefix.starts_with('/') {
                    bail!("field routes[{index}].path_prefixes: path prefix must start with /");
                }
            }
            if let Some(add_prefix) = &route.add_prefix {
                if !add_prefix.starts_with('/') {
                    bail!("field routes[{index}].add_prefix: add_prefix must start with /");
                }
            }
            validate_headers(index, "match_headers", &route.match_headers)?;
            validate_headers(index, "request_headers", &route.request_headers)?;
            validate_headers(index, "response_headers", &route.response_headers)?;
        }
        Ok(())
    }
}

fn validate_manual_tls_files(cert_path: &str, key_path: &str) -> AnyResult<()> {
    let certs_and_key = load_certs_and_key_files(cert_path, key_path).with_context(|| {
        "field tls.cert_path/tls.key_path: failed to load certificate or private key files"
    })?;
    if certs_and_key.is_none() {
        bail!(
            "field tls.cert_path/tls.key_path: certificate chain or private key file is empty or invalid"
        );
    }
    Ok(())
}

fn normalize_listen_addr(value: &str) -> AnyResult<std::net::SocketAddr> {
    if let Ok(addr) = value.parse() {
        return Ok(addr);
    }
    if let Some(port) = value.strip_prefix("localhost:") {
        return format!("127.0.0.1:{port}")
            .parse()
            .with_context(|| format!("invalid localhost listen address {value}"));
    }
    value
        .parse()
        .with_context(|| format!("invalid listen address {value}"))
}

fn validate_headers<T>(route_index: usize, field: &str, headers: &[T]) -> AnyResult<()>
where
    T: HeaderLike,
{
    for (index, header) in headers.iter().enumerate() {
        HeaderName::from_bytes(header.name().as_bytes()).with_context(|| {
            format!("field routes[{route_index}].{field}[{index}].name: invalid header name")
        })?;
        HeaderValue::from_str(header.value()).with_context(|| {
            format!("field routes[{route_index}].{field}[{index}].value: invalid header value")
        })?;
    }
    Ok(())
}

fn validate_extension_permission_names(
    extension_index: usize,
    field: &str,
    names: &[String],
) -> AnyResult<()> {
    let mut seen = HashSet::new();
    for (index, name) in names.iter().enumerate() {
        if name.trim().is_empty() {
            bail!("field extensions[{extension_index}].{field}[{index}]: cannot be empty");
        }
        if !seen.insert(name.as_str()) {
            bail!(
                "field extensions[{extension_index}].{field}[{index}]: duplicate permission value {}",
                name
            );
        }
    }
    Ok(())
}

trait HeaderLike {
    fn name(&self) -> &str;
    fn value(&self) -> &str;
}

impl HeaderLike for super::HeaderMatcher {
    fn name(&self) -> &str {
        &self.name
    }

    fn value(&self) -> &str {
        &self.value
    }
}

impl HeaderLike for super::HeaderMutation {
    fn name(&self) -> &str {
        &self.name
    }

    fn value(&self) -> &str {
        &self.value
    }
}
