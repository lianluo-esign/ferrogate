/**
 * Entity-list validators of `Config::validate()` (inventory §5.4): providers,
 * models, MCP servers, API keys, policies, gateway-config profiles, agent
 * upstreams, upstreams and routes — ported 1:1 from `config/validate.rs`.
 *
 * Each returns the name/id set the later validators cross-reference against,
 * exactly as the Rust functions do, so a reference to an entity that failed its
 * own check can never be silently accepted downstream.
 */
import { endpointUrls } from "../schema/entities.js";
import type { Config } from "../schema/index.js";
import { parseUpstreamEndpoint } from "../routing.js";
import {
  fail,
  isBlank,
  isSetAndEmpty,
  validateHeaders,
  validateSecretRef,
} from "./helpers.js";

/** `validate_providers` → the set of declared provider names. */
export function validateProviders(config: Config): Set<string> {
  const names = new Set<string>();
  for (let index = 0; index < config.providers.length; index += 1) {
    const provider = config.providers[index]!;
    const at = (field: string) => `providers[${index}].${field}`;
    if (isBlank(provider.name)) fail(at("name"), "cannot be empty");
    if (names.has(provider.name)) fail(at("name"), `duplicate provider name ${provider.name}`);
    names.add(provider.name);
    if (isBlank(provider.base_url)) fail(at("base_url"), "cannot be empty");
    if (isSetAndEmpty(provider.api_key_env)) fail(at("api_key_env"), "cannot be empty");
    if (provider.secret_ref !== null) validateSecretRef(at("secret_ref"), provider.secret_ref);
    if (isSetAndEmpty(provider.openrouter_http_referer)) {
      fail(at("openrouter_http_referer"), "cannot be empty");
    }
    if (isSetAndEmpty(provider.openrouter_x_title)) fail(at("openrouter_x_title"), "cannot be empty");
    if (isSetAndEmpty(provider.region)) fail(at("region"), "cannot be empty");
    if (isSetAndEmpty(provider.aws_access_key_id)) fail(at("aws_access_key_id"), "cannot be empty");
    if (isSetAndEmpty(provider.aws_secret_access_key_env)) {
      fail(at("aws_secret_access_key_env"), "cannot be empty");
    }
    if (isSetAndEmpty(provider.aws_session_token_env)) {
      fail(at("aws_session_token_env"), "cannot be empty");
    }
    // Bedrock has no bearer-token auth mode -- fail at config-load time (not
    // silently at first-request time) when any piece of the SigV4 credential
    // shape is missing.
    if (provider.kind === "bedrock" || provider.kind === "aws-bedrock") {
      if (provider.aws_access_key_id === null) {
        fail(at("aws_access_key_id"), "required when kind = bedrock");
      }
      if (provider.aws_secret_access_key_env === null) {
        fail(at("aws_secret_access_key_env"), "required when kind = bedrock");
      }
      if (provider.region === null) {
        fail(at("region"), "required when kind = bedrock (this is the AWS region, e.g. us-east-1)");
      }
    }
    if (isSetAndEmpty(provider.gcp_project_id)) fail(at("gcp_project_id"), "cannot be empty");
    if (isSetAndEmpty(provider.gcp_access_token_env)) {
      fail(at("gcp_access_token_env"), "cannot be empty");
    }
    // Vertex has no bearer-API-key auth mode -- same fail-closed shape as Bedrock.
    if (provider.kind === "vertex" || provider.kind === "vertex-ai") {
      if (provider.gcp_project_id === null) fail(at("gcp_project_id"), "required when kind = vertex");
      if (provider.gcp_access_token_env === null) {
        fail(at("gcp_access_token_env"), "required when kind = vertex");
      }
      if (provider.region === null) {
        fail(at("region"), "required when kind = vertex (this is the GCP location, e.g. us-central1)");
      }
    }
  }
  return names;
}

/** `validate_models` → the set of declared model names. */
export function validateModels(config: Config, providerNames: Set<string>): Set<string> {
  const names = new Set<string>();
  for (let index = 0; index < config.models.length; index += 1) {
    const model = config.models[index]!;
    const at = (field: string) => `models[${index}].${field}`;
    if (isBlank(model.name)) fail(at("name"), "cannot be empty");
    if (names.has(model.name)) fail(at("name"), `duplicate model name ${model.name}`);
    names.add(model.name);
    if (!providerNames.has(model.provider)) {
      fail(at("provider"), `model ${model.name} references unknown provider ${model.provider}`);
    }
    if (isBlank(model.provider_model)) fail(at("provider_model"), "cannot be empty");
    if (
      model.routing_strategy === "lowest_cost" &&
      (model.input_price_per_1m === null || model.output_price_per_1m === null)
    ) {
      fail(
        at("routing_strategy"),
        "lowest_cost requires input_price_per_1m and output_price_per_1m on the primary model",
      );
    }
    // Issue #146: with the standalone billing service enabled, the gateway's own
    // route price is what feeds monthly budget enforcement. A model with no
    // gateway-side price settles cost_usd = None, so its real spend never counts
    // against the budget. Fail closed rather than let the two systems diverge.
    if (
      config.billing_service.enabled &&
      (model.input_price_per_1m === null || model.output_price_per_1m === null)
    ) {
      throw new Error(
        `field models[${index}]: billing_service.enabled requires input_price_per_1m and ` +
          `output_price_per_1m on every model, so monthly budget enforcement never diverges from ` +
          `the billing service's ledger (model ${model.name})`,
      );
    }
    for (let fallbackIndex = 0; fallbackIndex < model.fallbacks.length; fallbackIndex += 1) {
      const fallback = model.fallbacks[fallbackIndex]!;
      if (!fallback.enabled) continue;
      const atFallback = (field: string) => `${at("fallbacks")}[${fallbackIndex}].${field}`;
      if (!providerNames.has(fallback.provider)) {
        fail(
          atFallback("provider"),
          `model ${model.name} references unknown fallback provider ${fallback.provider}`,
        );
      }
      if (isBlank(fallback.provider_model)) fail(atFallback("provider_model"), "cannot be empty");
      if (
        model.routing_strategy === "lowest_cost" &&
        (fallback.input_price_per_1m === null || fallback.output_price_per_1m === null)
      ) {
        throw new Error(
          `field models[${index}].fallbacks[${fallbackIndex}]: lowest_cost requires ` +
            `input_price_per_1m and output_price_per_1m`,
        );
      }
      // Issue #146: a fallback route can be selected at request time, so it needs
      // a gateway-side price too whenever billing reporting is enabled.
      if (
        config.billing_service.enabled &&
        (fallback.input_price_per_1m === null || fallback.output_price_per_1m === null)
      ) {
        throw new Error(
          `field models[${index}].fallbacks[${fallbackIndex}]: billing_service.enabled requires ` +
            `input_price_per_1m and output_price_per_1m on every fallback route`,
        );
      }
      if (fallback.weight === 0) fail(atFallback("weight"), "must be greater than zero");
    }
    // Canary rollout target (issue #276): validated like the primary route so a
    // misconfigured canary fails closed at load time.
    const canary = model.canary;
    if (canary !== null && canary.enabled) {
      if (!providerNames.has(canary.provider)) {
        fail(
          at("canary.provider"),
          `model ${model.name} references unknown canary provider ${canary.provider}`,
        );
      }
      if (isBlank(canary.provider_model)) fail(at("canary.provider_model"), "cannot be empty");
      if (canary.percent > 100) {
        fail(at("canary.percent"), `must be between 0 and 100 (got ${canary.percent})`);
      }
    }
    // Shadow/mirror target (issue #276): metered but never billed, so it does not
    // carry the billing-service price requirement.
    const shadow = model.shadow;
    if (shadow !== null && shadow.enabled) {
      if (!providerNames.has(shadow.provider)) {
        fail(
          at("shadow.provider"),
          `model ${model.name} references unknown shadow provider ${shadow.provider}`,
        );
      }
      if (isBlank(shadow.provider_model)) fail(at("shadow.provider_model"), "cannot be empty");
      if (shadow.sample_percent > 100) {
        fail(at("shadow.sample_percent"), `must be between 0 and 100 (got ${shadow.sample_percent})`);
      }
    }
  }
  return names;
}

/**
 * `validate_mcp_servers`. The duplicate-name gate is this crate's; the per-server
 * shape check is `ferrogate_mcp::validate_mcp_server_config`, whose modeled legs
 * (name shape + deny-by-default execution + the network-transport URL
 * requirement) are ported here.
 *
 * PORT-TODO(inventory §5.3): the remaining legs of
 * `ferrogate_mcp::validate_mcp_server_config` (reconnect backoff bounds, static
 * header/auth-mode pairing, OAuth config, per-server TLS, stdio `command`) read
 * `McpServerConfig` fields owned by `@ferrogate/mcp` (wave 2) that this schema
 * still accepts via passthrough; delegate to that crate's validator once ported.
 */
export function validateMcpServers(config: Config): void {
  const names = new Set<string>();
  for (let index = 0; index < config.mcp_servers.length; index += 1) {
    const server = config.mcp_servers[index]!;
    if (names.has(server.name)) {
      fail(`mcp_servers[${index}].name`, `duplicate MCP server name ${server.name}`);
    }
    names.add(server.name);
    const at = `mcp_servers[${index}]`;
    if (isBlank(server.name)) fail(at, "MCP server name cannot be empty");
    if (server.name.includes("-")) {
      fail(at, "MCP server name cannot contain '-' because tool names use serverName-toolName");
    }
    if (server.tools_to_execute.length === 0) {
      fail(at, `MCP server ${server.name} must set tools_to_execute; execution is deny-by-default`);
    }
    if (server.transport === "streamable_http" || server.transport === "sse") {
      if (server.url === null) fail(at, `MCP network server ${server.name} requires url`);
    }
  }
}

/**
 * `add_mcp_policy_targets`: MCP tools/servers are addressable as policy targets
 * (`mcp_tool:<server>-<tool>` as a model, `mcp:<server>` as a provider), so the
 * cross-reference sets are widened BEFORE api keys/policies/guardrails are
 * checked against them. Mutates both sets, like the Rust.
 */
export function addMcpPolicyTargets(
  config: Config,
  modelNames: Set<string>,
  providerNames: Set<string>,
): void {
  for (const server of config.mcp_servers) {
    for (const tool of server.tools_to_execute) {
      if (tool !== "*") modelNames.add(`mcp_tool:${server.name}-${tool}`);
    }
    providerNames.add(`mcp:${server.name}`);
  }
}

/** `validate_api_keys` → the set of declared api-key ids. */
export function validateApiKeys(
  config: Config,
  modelNames: Set<string>,
  providerNames: Set<string>,
): Set<string> {
  const ids = new Set<string>();
  for (let index = 0; index < config.api_keys.length; index += 1) {
    const key = config.api_keys[index]!;
    const at = (field: string) => `api_keys[${index}].${field}`;
    if (isBlank(key.id)) fail(at("id"), "cannot be empty");
    if (ids.has(key.id)) fail(at("id"), `duplicate api key id ${key.id}`);
    ids.add(key.id);
    if (isSetAndEmpty(key.key_env)) fail(at("key_env"), "cannot be empty");
    if (isSetAndEmpty(key.key)) fail(at("key"), "cannot be empty");
    if (isSetAndEmpty(key.key_hash)) fail(at("key_hash"), "cannot be empty");
    if (key.key_hash !== null && !key.key_hash.startsWith("blake2b:")) {
      fail(at("key_hash"), "unsupported key hash format");
    }
    if (key.key_env === null && key.key === null && key.key_hash === null) {
      fail(at("key_env"), "key_env, key, or key_hash is required");
    }
    // #515. `organization_id` is the authorization identity every tenant-isolation
    // check reads, so both ways of writing it wrong are load-time errors: a blank
    // value is neither "no tenant" nor a tenant id that can match a `tenants` row,
    // and claiming a tenant AND platform root at once is a contradiction.
    if (key.organization_id !== null && isBlank(key.organization_id)) {
      fail(
        at("organization_id"),
        "cannot be blank; omit it for a platform-operator key (and set platform_operator = true) " +
          "or name the tenant it belongs to",
      );
    }
    if (key.platform_operator === true && key.organization_id !== null) {
      fail(
        at("platform_operator"),
        `api key ${key.id} sets platform_operator = true and organization_id = ` +
          `${key.organization_id}; a platform-operator key is unscoped by definition, so it must ` +
          `not also claim a tenant`,
      );
    }
    for (const allowedModel of key.allowed_models) {
      if (!modelNames.has(allowedModel)) {
        fail(at("allowed_models"), `api key ${key.id} allows unknown model ${allowedModel}`);
      }
    }
    for (const deniedModel of key.denied_models) {
      if (!modelNames.has(deniedModel)) {
        fail(at("denied_models"), `api key ${key.id} denies unknown model ${deniedModel}`);
      }
    }
    for (const allowedProvider of key.allowed_providers) {
      if (!providerNames.has(allowedProvider)) {
        fail(at("allowed_providers"), `api key ${key.id} allows unknown provider ${allowedProvider}`);
      }
    }
    for (const deniedProvider of key.denied_providers) {
      if (!providerNames.has(deniedProvider)) {
        fail(at("denied_providers"), `api key ${key.id} denies unknown provider ${deniedProvider}`);
      }
    }
    // Issue #173: a region_allowlist entry that matches no configured provider's
    // `region` can never be satisfied, so the tenant would silently get zero
    // usable routes at request time.
    for (const region of key.region_allowlist) {
      if (isBlank(region)) fail(at("region_allowlist"), "cannot contain an empty value");
      if (!config.providers.some((provider) => provider.region === region)) {
        fail(
          at("region_allowlist"),
          `api key ${key.id} requires region ${region} but no configured provider declares it`,
        );
      }
    }
  }
  return ids;
}

/** `validate_policies`. */
export function validatePolicies(
  config: Config,
  apiKeyIds: Set<string>,
  modelNames: Set<string>,
  providerNames: Set<string>,
): void {
  const names = new Set<string>();
  for (let index = 0; index < config.policies.length; index += 1) {
    const policy = config.policies[index]!;
    const at = (field: string) => `policies[${index}].${field}`;
    if (isBlank(policy.name)) fail(at("name"), "cannot be empty");
    if (names.has(policy.name)) fail(at("name"), `duplicate policy name ${policy.name}`);
    names.add(policy.name);
    if (policy.effect.toLowerCase() !== "deny") {
      fail(at("effect"), "only deny is supported in the MVP");
    }
    for (const apiKeyId of policy.api_key_ids) {
      if (!apiKeyIds.has(apiKeyId)) {
        fail(at("api_key_ids"), `policy ${policy.name} references unknown api key ${apiKeyId}`);
      }
    }
    for (const model of policy.models) {
      if (!modelNames.has(model)) {
        fail(at("models"), `policy ${policy.name} references unknown model ${model}`);
      }
    }
    for (const provider of policy.providers) {
      if (!providerNames.has(provider)) {
        fail(at("providers"), `policy ${policy.name} references unknown provider ${provider}`);
      }
    }
  }
}

/** `validate_gateway_configs`. */
export function validateGatewayConfigs(config: Config, apiKeyIds: Set<string>): void {
  const ids = new Set<string>();
  for (let index = 0; index < config.gateway_configs.length; index += 1) {
    const profile = config.gateway_configs[index]!;
    const at = (field: string) => `gateway_configs[${index}].${field}`;
    if (isBlank(profile.id)) fail(at("id"), "cannot be empty");
    if (ids.has(profile.id)) fail(at("id"), `duplicate gateway config id ${profile.id}`);
    ids.add(profile.id);
    if (isBlank(profile.name)) fail(at("name"), "cannot be empty");
    if (profile.revision === 0) fail(at("revision"), "must be greater than zero");
    if (profile.cache_enabled === null) {
      throw new Error(
        `field gateway_configs[${index}]: cache_enabled is required for this profile slice`,
      );
    }
    for (const apiKeyId of profile.api_key_ids) {
      if (!apiKeyIds.has(apiKeyId)) {
        fail(
          at("api_key_ids"),
          `gateway config ${profile.id} references unknown api key ${apiKeyId}`,
        );
      }
    }
  }
}

/** `validate_agent_upstreams` (A2A upstreams). */
export function validateAgentUpstreams(config: Config): void {
  const ids = new Set<string>();
  for (let index = 0; index < config.agent_upstreams.length; index += 1) {
    const upstream = config.agent_upstreams[index]!;
    const at = (field: string) => `agent_upstreams[${index}].${field}`;
    if (isBlank(upstream.id)) fail(at("id"), "cannot be empty");
    if (ids.has(upstream.id)) fail(at("id"), `duplicate agent upstream id ${upstream.id}`);
    ids.add(upstream.id);
    if (isBlank(upstream.name)) fail(at("name"), "cannot be empty");
    if (isBlank(upstream.endpoint)) fail(at("endpoint"), "cannot be empty");
    if (!upstream.endpoint.startsWith("http://") && !upstream.endpoint.startsWith("https://")) {
      fail(at("endpoint"), "must start with http:// or https://");
    }
    if (upstream.tenant_ids.some((tenant) => isBlank(tenant))) {
      fail(at("tenant_ids"), "cannot contain empty tenant ids");
    }
    if (upstream.capabilities.length === 0) {
      fail(at("capabilities"), "at least one capability is required");
    }
    if (upstream.capabilities.includes("stream") && upstream.protocol !== "a2a") {
      fail(at("protocol"), "streaming capability requires A2A protocol");
    }
  }
}

/** `validate_upstreams` → the set of declared upstream names. */
export function validateUpstreams(config: Config): Set<string> {
  const names = new Set<string>();
  for (let index = 0; index < config.upstreams.length; index += 1) {
    const upstream = config.upstreams[index]!;
    if (isBlank(upstream.name)) fail(`upstreams[${index}].name`, "cannot be empty");
    if (names.has(upstream.name)) {
      fail(`upstreams[${index}].name`, `duplicate upstream name ${upstream.name}`);
    }
    names.add(upstream.name);
    const endpoints = endpointUrls(upstream);
    if (endpoints.length === 0) {
      fail(`upstreams[${index}].url`, "upstream must define url or urls");
    }
    for (let endpointIndex = 0; endpointIndex < endpoints.length; endpointIndex += 1) {
      const endpoint = endpoints[endpointIndex]!;
      try {
        parseUpstreamEndpoint(endpoint);
      } catch (error) {
        // Rust renders the `with_context` chain as `<context>: <cause>`.
        fail(
          `upstreams[${index}].urls[${endpointIndex}]`,
          `upstream ${upstream.name} has invalid endpoint ${endpoint}: ` +
            `${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }
  return names;
}

/** `validate_routes`. */
export function validateRoutes(config: Config, upstreamNames: Set<string>): void {
  const names = new Set<string>();
  for (let index = 0; index < config.routes.length; index += 1) {
    const route = config.routes[index]!;
    const at = (field: string) => `routes[${index}].${field}`;
    if (isBlank(route.name)) fail(at("name"), "cannot be empty");
    if (names.has(route.name)) fail(at("name"), `duplicate route name ${route.name}`);
    names.add(route.name);
    if (!upstreamNames.has(route.upstream)) {
      fail(at("upstream"), `route ${route.name} references unknown upstream ${route.upstream}`);
    }
    // `strip_prefix` is checked by the same loop (and so reports the
    // `path_prefixes` field), exactly as the Rust `.chain(strip_prefix.iter())`.
    const prefixes = [...route.path_prefixes];
    if (route.strip_prefix !== null) prefixes.push(route.strip_prefix);
    for (const prefix of prefixes) {
      if (!prefix.startsWith("/")) fail(at("path_prefixes"), "path prefix must start with /");
    }
    if (route.add_prefix !== null && !route.add_prefix.startsWith("/")) {
      fail(at("add_prefix"), "add_prefix must start with /");
    }
    validateHeaders(index, "match_headers", route.match_headers);
    validateHeaders(index, "request_headers", route.request_headers);
    validateHeaders(index, "response_headers", route.response_headers);
  }
}
