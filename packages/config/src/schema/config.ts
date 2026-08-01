/**
 * The root `Config` schema — port of `Config` in `ferrogate-config`'s
 * `config/types.rs` (inventory §5.3). Assembles every section + entity list.
 *
 * Config is NOT `deny_unknown_fields` in Rust (serde ignores unknown keys), so
 * this object is non-strict and strips unknown top-level keys.
 *
 * Control-plane alias handling (inventory §5.5): the canonical `[control_api]`
 * and deprecated `[admin_api]` alias are resolved into the effective
 * `admin_api` by `migrateControlPlaneAliases` in `../loader.ts` BEFORE this
 * schema runs, so the schema exposes only the effective `admin_api` section.
 */
import { z } from "zod";
import {
  adminApiConfigSchema,
  adminConfigSchema,
  agentRuntimeConfigSchema,
  analyticsConfigSchema,
  assetBucketConfigSchema,
  assetLifecycleConfigSchema,
  authConfigSchema,
  authServiceConfigSchema,
  billingAlertsConfigSchema,
  billingServiceConfigSchema,
  cacheConfigSchema,
  clusterConfigSchema,
  limitsConfigSchema,
  meteringConfigSchema,
  networkAccessConfigSchema,
  observabilityConfigSchema,
  reliabilityConfigSchema,
  schedulerConfigSchema,
  storageConfigSchema,
  telemetryConfigSchema,
  tenancyConfigSchema,
  tlsConfigSchema,
  x402ReconcilerConfigSchema,
  x402SweeperConfigSchema,
} from "./sections.js";
import {
  agentUpstreamConfigSchema,
  agentWorkflowPolicySchema,
  apiKeySchema,
  cloudflareConfigSchema,
  extensionConfigSchema,
  gatewayConfigProfileSchema,
  guardrailRuleSchema,
  mcpServerConfigSchema,
  modelSchema,
  policyRuleSchema,
  promptTemplateSchema,
  providerSchema,
  routeRuleSchema,
  skillPackageSchema,
  upstreamSchema,
} from "./entities.js";
import { sectionDefault } from "./util.js";

export const configSchema = z.object({
  listen: z.string().default("127.0.0.1:8080"),
  admin: sectionDefault(adminConfigSchema),
  tls: sectionDefault(tlsConfigSchema),
  auth_service: sectionDefault(authServiceConfigSchema),
  billing_service: sectionDefault(billingServiceConfigSchema),
  /** Effective control-plane API config (resolved from `[control_api]`/`[admin_api]`). */
  admin_api: sectionDefault(adminApiConfigSchema),
  providers: z.array(providerSchema).default([]),
  models: z.array(modelSchema).default([]),
  api_keys: z.array(apiKeySchema).default([]),
  policies: z.array(policyRuleSchema).default([]),
  gateway_configs: z.array(gatewayConfigProfileSchema).default([]),
  agent_workflows: z.array(agentWorkflowPolicySchema).default([]),
  skill_packages: z.array(skillPackageSchema).default([]),
  prompt_templates: z.array(promptTemplateSchema).default([]),
  guardrails: z.array(guardrailRuleSchema).default([]),
  plugins: z.array(extensionConfigSchema).default([]),
  extensions: z.array(extensionConfigSchema).default([]),
  mcp_servers: z.array(mcpServerConfigSchema).default([]),
  agent_upstreams: z.array(agentUpstreamConfigSchema).default([]),
  telemetry: sectionDefault(telemetryConfigSchema),
  billing_alerts: sectionDefault(billingAlertsConfigSchema),
  observability: sectionDefault(observabilityConfigSchema),
  analytics: sectionDefault(analyticsConfigSchema),
  metering: sectionDefault(meteringConfigSchema),
  cache: sectionDefault(cacheConfigSchema),
  storage: sectionDefault(storageConfigSchema),
  reliability: sectionDefault(reliabilityConfigSchema),
  limits: sectionDefault(limitsConfigSchema),
  agent_runtime: sectionDefault(agentRuntimeConfigSchema),
  cluster: sectionDefault(clusterConfigSchema),
  upstreams: z.array(upstreamSchema).default([]),
  routes: z.array(routeRuleSchema).default([]),
  network_access: sectionDefault(networkAccessConfigSchema),
  asset_bucket: sectionDefault(assetBucketConfigSchema),
  scheduler: sectionDefault(schedulerConfigSchema),
  asset_lifecycle: sectionDefault(assetLifecycleConfigSchema),
  x402_sweeper: sectionDefault(x402SweeperConfigSchema),
  x402_reconciler: sectionDefault(x402ReconcilerConfigSchema),
  // PORT-TODO(D: inventory §5.3) — DELIBERATE PRODUCT DECISION (x402 is
  // deprioritized), not a platform gap. `X402ScopedSpendPolicy` is owned by the
  // (deprioritized) x402 policy surface in `@ferrogate/policy`; accepted as
  // opaque entries until that crate is ported. See `../x402-scope.ts`.
  x402_spend_policies: z.array(z.unknown()).default([]),
  asset_egress_price_per_gb: z.number().nullable().default(null),
  cloudflare: cloudflareConfigSchema.nullable().default(null),
  tenancy: sectionDefault(tenancyConfigSchema),
  auth: sectionDefault(authConfigSchema),
});

export type Config = z.infer<typeof configSchema>;

/** Parse an already-alias-resolved config object into a validated `Config` shape (no cross-field validation). */
export function parseConfig(raw: unknown): Config {
  return configSchema.parse(raw);
}

/** A fully-defaulted `Config` (Rust `Config::default()`). */
export function defaultConfig(): Config {
  return configSchema.parse({});
}

/**
 * `Config::auth_required()` (issue #542): the one deployment-wide answer to
 * "must a request present a credential?". Deliberately does NOT count keys.
 */
export function authRequired(config: Config): boolean {
  return !config.auth.disabled;
}

/**
 * `Config::durable_api_key_store()` (issue #542): the storage provider iff it
 * can hold durable virtual API keys, else `null`.
 */
export function durableApiKeyStore(config: Config): Config["storage"]["provider"] | null {
  switch (config.storage.provider) {
    case "postgres":
    case "supabase":
    case "cloudflare_d1":
      return config.storage.provider;
    case "memory":
    case "turso_libsql":
    case "mysql":
      return null;
  }
}

/**
 * `Config::has_credential_source()` (issue #542): whether this config can
 * resolve a presented credential to anything.
 */
export function hasCredentialSource(config: Config): boolean {
  return (
    config.api_keys.length > 0 ||
    config.auth_service.enabled ||
    durableApiKeyStore(config) !== null
  );
}
