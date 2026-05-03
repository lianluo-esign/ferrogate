use anyhow::{bail, Context, Result as AnyResult};
use http::{HeaderName, HeaderValue};
use std::collections::HashSet;

use crate::routing::parse_upstream_endpoint;

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
        let upstream_names = self.validate_upstreams()?;
        self.validate_routes(&upstream_names)?;
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
            if key.key_env.is_none() && key.key.is_none() {
                bail!("field api_keys[{index}].key_env: key_env or key is required");
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
            for allowed_provider in &key.allowed_providers {
                if !provider_names.contains(allowed_provider.as_str()) {
                    bail!(
                        "field api_keys[{index}].allowed_providers: api key {} allows unknown provider {}",
                        key.id,
                        allowed_provider
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
