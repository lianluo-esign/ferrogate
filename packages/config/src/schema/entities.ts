/**
 * Entity schemas — the list-typed members of `Config` (`Provider`, `Model`,
 * `ApiKey`, `PolicyRule`, `GuardrailRule`, workflows, prompt templates, skill
 * packages, extensions, MCP servers, agent upstreams, upstreams, routes) from
 * `config/types.rs` (inventory §5.3). `#[serde(deny_unknown_fields)]` structs
 * are `.strict()`.
 */
import { z } from "zod";
import { approvalPolicySchema } from "@ferrogate/core";
import {
  agentUpstreamCapabilitySchema,
  agentUpstreamProtocolSchema,
  agentWorkflowNodeKindSchema,
  contentSourceSchema,
  extensionKindSchema,
  guardrailEffectSchema,
  guardrailProviderErrorModeSchema,
  guardrailProviderKindSchema,
  guardrailStageSchema,
  mcpAuthTypeSchema,
  mcpTransportSchema,
  modelCapabilitySchema,
  promptTemplateStatusSchema,
  promptTemplateTargetSchema,
  promptTemplateVersionStatusSchema,
  providerCloudflareAiGatewayModeSchema,
  routingStrategySchema,
  skillPackageCapabilityKindSchema,
  ALL_CONTENT_SOURCES,
} from "./enums.js";
import { sectionDefault } from "./util.js";

const optString = z.string().nullable().default(null);
const optNumber = z.number().int().nullable().default(null);
const optBool = z.boolean().nullable().default(null);
const optFloat = z.number().nullable().default(null);

export const providerCloudflareAiGatewayConfigSchema = z.object({
  gateway_id: z.string(),
  aig_token_secret_ref: optString,
  mode: providerCloudflareAiGatewayModeSchema,
  provider_slug: optString,
});
export type ProviderCloudflareAiGatewayConfig = z.infer<typeof providerCloudflareAiGatewayConfigSchema>;

export const providerSchema = z.object({
  name: z.string(),
  kind: z.string().default("openai"),
  base_url: z.string(),
  api_key_env: optString,
  secret_ref: optString,
  openrouter_http_referer: optString,
  openrouter_x_title: optString,
  enabled: z.boolean().default(true),
  region: optString,
  aws_access_key_id: optString,
  aws_secret_access_key_env: optString,
  aws_session_token_env: optString,
  gcp_project_id: optString,
  gcp_access_token_env: optString,
  cloudflare_ai_gateway: providerCloudflareAiGatewayConfigSchema.nullable().default(null),
});
export type Provider = z.infer<typeof providerSchema>;

export const canaryRouteSchema = z.object({
  provider: z.string(),
  provider_model: z.string(),
  capabilities: z.array(modelCapabilitySchema).default([]),
  context_window: optNumber,
  percent: z.number().int().default(0),
  input_price_per_1m: optFloat,
  output_price_per_1m: optFloat,
  enabled: z.boolean().default(true),
});
export type CanaryRoute = z.infer<typeof canaryRouteSchema>;

export const shadowRouteSchema = z.object({
  provider: z.string(),
  provider_model: z.string(),
  sample_percent: z.number().int().default(0),
  max_requests: z.number().int().default(0),
  enabled: z.boolean().default(true),
});
export type ShadowRoute = z.infer<typeof shadowRouteSchema>;

export const modelFallbackSchema = z.object({
  provider: z.string(),
  provider_model: z.string(),
  capabilities: z.array(modelCapabilitySchema).default([]),
  context_window: optNumber,
  input_price_per_1m: optFloat,
  output_price_per_1m: optFloat,
  priority: optNumber,
  weight: optNumber,
  enabled: z.boolean().default(true),
});
export type ModelFallback = z.infer<typeof modelFallbackSchema>;

export const modelSchema = z.object({
  name: z.string(),
  provider: z.string(),
  provider_model: z.string(),
  routing_strategy: routingStrategySchema,
  fallbacks: z.array(modelFallbackSchema).default([]),
  canary: canaryRouteSchema.nullable().default(null),
  shadow: shadowRouteSchema.nullable().default(null),
  visible_organization_ids: z.array(z.string()).default([]),
  visible_project_ids: z.array(z.string()).default([]),
  capabilities: z.array(modelCapabilitySchema).default([]),
  context_window: optNumber,
  input_price_per_1m: optFloat,
  output_price_per_1m: optFloat,
  enabled: z.boolean().default(true),
  cache_enabled: optBool,
});
export type Model = z.infer<typeof modelSchema>;

export const apiKeySchema = z.object({
  id: z.string(),
  name: z.string(),
  key_env: optString,
  key: optString,
  key_hash: optString,
  enabled: z.boolean().default(true),
  scopes: z.array(z.string()).default([]),
  allowed_models: z.array(z.string()).default([]),
  denied_models: z.array(z.string()).default([]),
  allowed_providers: z.array(z.string()).default([]),
  denied_providers: z.array(z.string()).default([]),
  region_allowlist: z.array(z.string()).default([]),
  organization_id: optString,
  platform_operator: optBool,
  team_id: optString,
  project_id: optString,
  workspace_id: optString,
  user_id: optString,
  monthly_token_budget: optNumber,
  request_limit_per_minute: optNumber,
  expires_at_unix: optNumber,
  log_bodies: optBool,
  cache_enabled: optBool,
});
export type ApiKey = z.infer<typeof apiKeySchema>;

export const policyRuleSchema = z.object({
  name: z.string(),
  effect: z.string().default("deny"),
  organization_ids: z.array(z.string()).default([]),
  project_ids: z.array(z.string()).default([]),
  api_key_ids: z.array(z.string()).default([]),
  models: z.array(z.string()).default([]),
  providers: z.array(z.string()).default([]),
  code: z.string().default("policy_denied"),
  message: z.string().default("request denied by policy"),
  enabled: z.boolean().default(true),
});
export type PolicyRule = z.infer<typeof policyRuleSchema>;

export const gatewayConfigProfileSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    revision: z.number().int().default(1),
    enabled: z.boolean().default(true),
    api_key_ids: z.array(z.string()).default([]),
    cache_enabled: optBool,
  })
  .strict();
export type GatewayConfigProfile = z.infer<typeof gatewayConfigProfileSchema>;

export const agentWorkflowNodeSchema = z
  .object({
    id: z.string(),
    kind: agentWorkflowNodeKindSchema,
    model: optString,
    providers: z.array(z.string()).default([]),
    tool: optString,
    max_iterations: optNumber,
    token_budget: optNumber,
  })
  .strict();
export type AgentWorkflowNode = z.infer<typeof agentWorkflowNodeSchema>;

export const agentWorkflowEdgeSchema = z
  .object({ from: z.string(), to: z.string(), condition: optString })
  .strict();
export type AgentWorkflowEdge = z.infer<typeof agentWorkflowEdgeSchema>;

export const agentWorkflowPolicySchema = z
  .object({
    id: z.string(),
    name: z.string(),
    version: z.number().int().default(1),
    enabled: z.boolean().default(true),
    organization_ids: z.array(z.string()).default([]),
    project_ids: z.array(z.string()).default([]),
    api_key_ids: z.array(z.string()).default([]),
    nodes: z.array(agentWorkflowNodeSchema),
    edges: z.array(agentWorkflowEdgeSchema).default([]),
    max_model_calls: optNumber,
    max_tool_calls: optNumber,
    max_parallelism: optNumber,
    max_iterations: optNumber,
    timeout_millis: optNumber,
    token_budget: optNumber,
  })
  .strict();
export type AgentWorkflowPolicy = z.infer<typeof agentWorkflowPolicySchema>;

export const promptTemplateVariableSchema = z
  .object({
    name: z.string(),
    required: z.boolean().default(true),
    default: optString,
    description: optString,
  })
  .strict();
export type PromptTemplateVariable = z.infer<typeof promptTemplateVariableSchema>;

export const promptTemplateMessageSchema = z
  .object({ role: z.string(), content: z.string() })
  .strict();
export type PromptTemplateMessage = z.infer<typeof promptTemplateMessageSchema>;

export const promptTemplateVersionSchema = z
  .object({
    revision: z.number().int().default(1),
    status: promptTemplateVersionStatusSchema,
    messages: z.array(promptTemplateMessageSchema),
    temperature: optFloat,
    top_p: optFloat,
    max_tokens: optNumber,
  })
  .strict();
export type PromptTemplateVersion = z.infer<typeof promptTemplateVersionSchema>;

export const promptTemplateSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    status: promptTemplateStatusSchema,
    target: promptTemplateTargetSchema,
    model: z.string(),
    variables: z.array(promptTemplateVariableSchema).default([]),
    versions: z.array(promptTemplateVersionSchema),
  })
  .strict();
export type PromptTemplate = z.infer<typeof promptTemplateSchema>;

export const guardrailProviderRuntimeConfigSchema = z.object({
  provider_on_error: guardrailProviderErrorModeSchema,
  provider_max_concurrency: z.number().int().default(16),
  provider_circuit_failure_threshold: z.number().int().default(3),
  provider_circuit_cooldown_ms: z.number().int().default(30000),
  provider_max_retries: z.number().int().default(0),
  provider_max_payload_bytes: z.number().int().default(1024 * 1024),
  provider_max_response_bytes: z.number().int().default(256 * 1024),
  provider_allow_private_network: z.boolean().default(false),
  provider_secret_ref: optString,
});
export type GuardrailProviderRuntimeConfig = z.infer<typeof guardrailProviderRuntimeConfigSchema>;

/**
 * The CONFIG mirror translated into the guardrails crate's
 * `DetectorDefinition`/`PolicyRevision`. `provider_runtime` is `#[serde(flatten)]`
 * in Rust — its fields sit at the top level of the rule — so the schema merges
 * the two field sets rather than nesting.
 */
export const guardrailRuleSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    enabled: z.boolean().default(true),
    stage: guardrailStageSchema,
    sources: z.array(contentSourceSchema).default(ALL_CONTENT_SOURCES),
    organization_ids: z.array(z.string()).default([]),
    project_ids: z.array(z.string()).default([]),
    api_key_ids: z.array(z.string()).default([]),
    models: z.array(z.string()).default([]),
    providers: z.array(z.string()).default([]),
    keywords: z.array(z.string()).default([]),
    regex: z.array(z.string()).default([]),
    max_input_bytes: optNumber,
    provider: guardrailProviderKindSchema,
    provider_endpoint: optString,
    provider_language: optString,
    provider_score_threshold_percent: optNumber,
    provider_entities: z.array(z.string()).nullable().default(null),
    provider_fingerprint_secret_ref: optString,
    provider_timeout_ms: z.number().int().default(2000),
    effect: guardrailEffectSchema,
    code: z.string().default("guardrail_denied"),
    message: z.string().default("request blocked by guardrail"),
  })
  .merge(guardrailProviderRuntimeConfigSchema)
  .strict();
export type GuardrailRule = z.infer<typeof guardrailRuleSchema>;

export const extensionPermissionsSchema = z.object({
  tools: z.array(z.string()).default([]),
  network: z.array(z.string()).default([]),
  filesystem: z.boolean().default(false),
  shell: z.boolean().default(false),
  tenant_scope: z.boolean().default(false),
  secrets: z.boolean().default(false),
  admin_mutation: z.boolean().default(false),
});
export type ExtensionPermissions = z.infer<typeof extensionPermissionsSchema>;

export const pluginManifestSchema = z.object({
  name: optString,
  description: optString,
  capabilities: z.array(z.string()).default([]),
  required_permissions: sectionDefault(extensionPermissionsSchema),
  hooks: z.array(z.string()).default([]),
  config_schema: z.unknown().nullable().default(null),
});
export type PluginManifest = z.infer<typeof pluginManifestSchema>;

export const pluginCompatibilitySchema = z.object({
  min_gateway_version: optString,
  max_gateway_version: optString,
});
export type PluginCompatibility = z.infer<typeof pluginCompatibilitySchema>;

export const extensionConfigSchema = z.object({
  id: z.string(),
  kind: extensionKindSchema,
  version: z.string().default("0.1.0"),
  manifest: sectionDefault(pluginManifestSchema),
  compatibility: sectionDefault(pluginCompatibilitySchema),
  enabled: z.boolean().default(true),
  source: z.string().default("builtin"),
  order: z.number().int().default(100),
  approval_policy: approvalPolicySchema,
  permissions: sectionDefault(extensionPermissionsSchema),
  config: z.record(z.string(), z.unknown()).default({}),
});
export type ExtensionConfig = z.infer<typeof extensionConfigSchema>;
/** `PluginConfig` is a type alias of `ExtensionConfig` in Rust. */
export type PluginConfig = ExtensionConfig;

export const skillPackageCompatibilitySchema = z.object({
  min_gateway_version: optString,
  agent_runtimes: z.array(z.string()).default([]),
});
export type SkillPackageCompatibility = z.infer<typeof skillPackageCompatibilitySchema>;

export const skillPackageCapabilitySchema = z.object({
  kind: skillPackageCapabilityKindSchema,
  id: z.string(),
  description: optString,
});
export type SkillPackageCapability = z.infer<typeof skillPackageCapabilitySchema>;

// PORT-TODO(inventory §5.3): McpServerConfig is owned by `@ferrogate/mcp` (wave 2);
// the load-time guards only read name/url/transport/auth_type, so the rest is
// accepted via passthrough until that crate is ported.
export const mcpServerConfigSchema = z
  .object({
    name: z.string(),
    url: optString,
    transport: mcpTransportSchema,
    auth_type: mcpAuthTypeSchema,
  })
  .passthrough();
export type McpServerConfig = z.infer<typeof mcpServerConfigSchema>;

export const skillPackageResourcesSchema = z.object({
  plugins: z.array(extensionConfigSchema).default([]),
  mcp_servers: z.array(mcpServerConfigSchema).default([]),
  prompt_templates: z.array(promptTemplateSchema).default([]),
  agent_workflows: z.array(agentWorkflowPolicySchema).default([]),
});
export type SkillPackageResources = z.infer<typeof skillPackageResourcesSchema>;

export const skillPackageSchema = z.object({
  id: z.string(),
  name: z.string(),
  version: z.string().default("0.1.0"),
  description: optString,
  enabled: z.boolean().default(true),
  compatibility: sectionDefault(skillPackageCompatibilitySchema),
  permissions: sectionDefault(extensionPermissionsSchema),
  capabilities: z.array(skillPackageCapabilitySchema).default([]),
  resources: sectionDefault(skillPackageResourcesSchema),
  api_key_ids: z.array(z.string()).default([]),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
export type SkillPackage = z.infer<typeof skillPackageSchema>;

// AgentUpstreamAuth: an internally-tagged Rust enum (None | Bearer | Header).
export const agentUpstreamAuthSchema = z
  .union([
    z.object({ none: z.object({}).default({}) }),
    z.object({ bearer: z.object({ token: optString }) }),
    z.object({ header: z.object({ name: z.string(), value: optString }) }),
  ])
  .default({ none: {} });
export type AgentUpstreamAuth = z.infer<typeof agentUpstreamAuthSchema>;

export const agentUpstreamConfigSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: optString,
  enabled: z.boolean().default(true),
  protocol: agentUpstreamProtocolSchema,
  endpoint: z.string(),
  auth: agentUpstreamAuthSchema,
  tenant_ids: z.array(z.string()).default([]),
  capabilities: z.array(agentUpstreamCapabilitySchema).default([]),
});
export type AgentUpstreamConfig = z.infer<typeof agentUpstreamConfigSchema>;

export const upstreamSchema = z.object({
  name: z.string(),
  url: optString,
  urls: z.array(z.string()).default([]),
  enabled: z.boolean().default(true),
});
export type Upstream = z.infer<typeof upstreamSchema>;

/** `Upstream::endpoint_urls()`: primary url then pool, dropping blanks. */
export function endpointUrls(upstream: Upstream): string[] {
  const out: string[] = [];
  if (upstream.url !== null && upstream.url.trim().length > 0) out.push(upstream.url);
  for (const url of upstream.urls) if (url.trim().length > 0) out.push(url);
  return out;
}

export const headerMutationSchema = z.object({ name: z.string(), value: z.string() });
export type HeaderMutation = z.infer<typeof headerMutationSchema>;

export const headerMatcherSchema = z.object({ name: z.string(), value: z.string() });
export type HeaderMatcher = z.infer<typeof headerMatcherSchema>;

export const routeRuleSchema = z.object({
  name: z.string(),
  upstream: z.string(),
  hosts: z.array(z.string()).default([]),
  path_prefixes: z.array(z.string()).default([]),
  match_headers: z.array(headerMatcherSchema).default([]),
  strip_prefix: optString,
  add_prefix: optString,
  request_headers: z.array(headerMutationSchema).default([]),
  response_headers: z.array(headerMutationSchema).default([]),
  enabled: z.boolean().default(true),
});
export type RouteRule = z.infer<typeof routeRuleSchema>;

// PORT-TODO(inventory §5.3): CloudflareConfig is owned by `@ferrogate/cloudflare`
// (wave 2); the fields the load-time guards read (account_id/api_token/base URLs/
// tenant_tokens/r2_s3_endpoint) are modeled, the rest passes through.
export const cloudflareConfigSchema = z
  .object({
    account_id: z.string().default(""),
    api_token: z.string().default(""),
    tenant_tokens: z.record(z.string(), z.string()).default({}),
    api_base_url: z.string().default("https://api.cloudflare.com/client/v4"),
    ai_gateway_base_url: z.string().default("https://gateway.ai.cloudflare.com"),
    r2_s3_endpoint: optString,
  })
  .passthrough();
export type CloudflareConfig = z.infer<typeof cloudflareConfigSchema>;
