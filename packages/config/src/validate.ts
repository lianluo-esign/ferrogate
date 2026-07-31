/**
 * Port of `ferrogate-config`'s `Config::validate()` (inventory §5.4,
 * `config/validate.rs`) — the load-time gate. The Rust gate is ~4000 lines /
 * ~98 helper fns; every one of them is now either ported (here and in
 * `./validate/*`) or explicitly REMOVED as N/A on Cloudflare with the reason
 * written down next to where it used to run.
 *
 * Shape note: the Rust gate `bail!`s the FIRST `field <path>: <reason>` it
 * meets, and the order of the checks is itself observable (it is what an
 * operator sees when several things are wrong). This port therefore keeps the
 * imperative first-failure form and the exact Rust call order rather than
 * collecting Zod issues — the Zod schema already owns the structural/type
 * errors, this owns the cross-field/semantic ones.
 *
 * REMOVED AS N/A ON CLOUDFLARE (see `./validate/sections.ts` for the full
 * rationale): `validate_tls`, `validate_acme_tls`, `validate_acme_dns01_tls`,
 * `validate_acme_http01_tls` and `validate_manual_tls_files` — Cloudflare
 * terminates TLS in front of the Worker, there is no cert/key file to load
 * (the Rust pre-flight is pingora's `load_certs_and_key_files`), no `:80`
 * HTTP-01 challenge listener a Worker can own, and no ACME storage directory.
 */
import { R2_REGION, endpointTargetsR2, parseEndpoint, parseR2Endpoint } from "./asset-endpoint.js";
import type { ApiKey, Config } from "./schema/index.js";
import { buildsS3Client } from "./schema/sections.js";
import { buildSnapshotCrypto } from "./signed-snapshot.js";
import {
  addMcpPolicyTargets,
  validateAgentUpstreams,
  validateApiKeys,
  validateGatewayConfigs,
  validateMcpServers,
  validateModels,
  validatePolicies,
  validateProviders,
  validateRoutes,
  validateUpstreams,
} from "./validate/entities.js";
import { isValidSocketAddr } from "./validate/helpers.js";
import { validatePlugins } from "./validate/plugins.js";
import {
  validateAgentWorkflows,
  validateGuardrails,
  validatePromptTemplates,
  validateSkillPackages,
  workflowToolNames,
} from "./validate/policies.js";
import {
  validateAdminApi,
  validateAgentRuntime,
  validateAnalytics,
  validateAuthService,
  validateBillingAlerts,
  validateCache,
  validateCloudflareAiGatewayProviders,
  validateCluster,
  validateLimits,
  validateMetering,
  validateNetworkAccess,
  validateObservability,
  validateReliability,
  validateStorage,
  validateTelemetry,
  validateX402SpendPolicies,
} from "./validate/sections.js";
import { x402ConfirmationWindowSecs, x402HoldTtlFloorSecs } from "./x402-hold.js";

// Re-exported so `@ferrogate/config` keeps ONE validation surface (the Rust
// `Config::validate` + its `pub` helpers), whichever module implements it.
// `./validate/helpers.js` is deliberately NOT re-exported: those mirror the
// PRIVATE free functions at the bottom of `validate.rs` (`fail`, `is_blank`,
// `version_parts`, ...) and their names are too generic for a package surface.
export * from "./validate/entities.js";
export * from "./validate/sections.js";
export * from "./validate/plugins.js";
export * from "./validate/policies.js";

/** Options controlling the tenant-identity gate (mirrors the `#[serde(skip)]` flag). */
export interface ValidateOptions {
  /**
   * `Config::api_keys_are_control_plane_documents`. `false` (default) = the keys
   * came from a config *document*, so an undeclared key STOPS validation;
   * `true` = durable control-plane rows, so it is reported (warned) not refused.
   */
  apiKeysAreControlPlaneDocuments?: boolean;
}

/** Result of a warn-only posture check. */
export interface TenancyWarnings {
  warnings: string[];
}

// --- tenant identity (security invariant #7) --------------------------------

/** Keys that declare neither `organization_id` nor `platform_operator`. */
export function apiKeysWithoutTenantIdentity(config: Config): string[] {
  return config.api_keys
    .filter((key) => key.platform_operator === null && key.organization_id === null)
    .map((key) => key.id);
}

/** Keys that declare `platform_operator = false` with no `organization_id` (authorize nothing). */
export function apiKeysThatAuthorizeNothing(config: Config): string[] {
  return config.api_keys
    .filter((key) => key.platform_operator === false && key.organization_id === null)
    .map((key) => key.id);
}

/** The legacy opt-in's running commentary; returns the ids it would warn about. */
export function warnImplicitPlatformOperators(config: Config): string[] {
  if (!config.tenancy.implicit_platform_operator) return [];
  return apiKeysWithoutTenantIdentity(config);
}

/** The load-time posture report for `[tenancy]` (warn-only). */
export function tenancyPostureWarnings(config: Config): string[] {
  const warnings: string[] = [];
  const implicit = warnImplicitPlatformOperators(config);
  if (implicit.length > 0) {
    warnings.push(
      `[tenancy] implicit_platform_operator = true grants UNRESTRICTED cross-tenant (platform-operator) access to every API key that declares neither organization_id nor platform_operator: ${implicit.join(", ")}. Declare each key and then remove the switch.`,
    );
  }
  const authorizesNothing = apiKeysThatAuthorizeNothing(config);
  if (authorizesNothing.length > 0) {
    warnings.push(
      `these API keys declare platform_operator = false and name no organization_id, so they have no tenant identity to authorize against: every request presenting one is refused with tenant_identity_required: ${authorizesNothing.join(", ")}.`,
    );
  }
  return warnings;
}

function undeclaredTenantIdentityRefusal(undeclared: string[]): string {
  return `refusing to start: these API keys declare neither organization_id nor platform_operator, so they have no tenant identity to authorize against and would be refused at authentication (tenant_identity_required): ${undeclared.join(", ")}. Say what each one is: platform_operator = true (administers every tenant) or organization_id = "<tenants.id>" (belongs to one tenant). In TOML/YAML only you may keep the pre-#515 behaviour with [tenancy] implicit_platform_operator = true while you annotate them.`;
}

/**
 * `#540`, the flip: refuse (at load) a config whose static keys would only be
 * authorized by the pre-#515 "no tenant means root" rule. Durable control-plane
 * keys are reported, not refused (stopping there would lock the operator out of
 * the API that repairs them). Throws on refusal.
 */
export function ensureEveryKeyDeclaresTenantIdentity(
  config: Config,
  options: ValidateOptions = {},
): void {
  if (config.tenancy.implicit_platform_operator) return;
  const undeclared = apiKeysWithoutTenantIdentity(config);
  if (undeclared.length === 0) return;
  if (options.apiKeysAreControlPlaneDocuments) {
    warnUndeclaredControlPlaneApiKeys(config, options); // reported (warn), not refused
    return;
  }
  throw new Error(undeclaredTenantIdentityRefusal(undeclared));
}

/**
 * `Config::warn_undeclared_control_plane_api_keys` (#540 rework 2): the durable
 * branch's ENTIRE compensating control, as a function that returns what it warned
 * about — so relaxing the refusal for control-plane rows is itself assertable
 * rather than a bare log line. Empty unless these keys really are durable rows: a
 * config *document* in this state is refused outright, and the legacy opt-in
 * short-circuits both.
 */
export function warnUndeclaredControlPlaneApiKeys(
  config: Config,
  options: ValidateOptions = {},
): string[] {
  if (config.tenancy.implicit_platform_operator || !options.apiKeysAreControlPlaneDocuments) {
    return [];
  }
  return apiKeysWithoutTenantIdentity(config);
}

/** The same refusal aimed at one key, for the runtime mint path (`POST/PUT /admin/v1/api-keys`). */
export function ensureApiKeyDeclaresTenantIdentity(config: Config, key: ApiKey): void {
  if (config.tenancy.implicit_platform_operator) return;
  if (key.platform_operator !== null || key.organization_id !== null) return;
  throw new Error(undeclaredTenantIdentityRefusal([key.id]));
}

// --- x402 reconciler money-safety (issues #400/#401) ------------------------

/** Reject a config whose x402 hold TTL cannot outlive the settlement window. */
export function validateX402Reconciler(config: Config): void {
  const reconciler = config.x402_reconciler;
  if (!reconciler.enabled) return;
  const floor = x402HoldTtlFloorSecs(reconciler);
  if (BigInt(reconciler.hold_ttl_secs) < floor) {
    const window = x402ConfirmationWindowSecs(reconciler);
    throw new Error(
      `field x402_reconciler.hold_ttl_secs: the wallet hold TTL (${reconciler.hold_ttl_secs}s) must strictly outlive the settlement confirmation window (confirmation_deadline_secs ${reconciler.confirmation_deadline_secs}s + reconcile_check_delay_secs ${reconciler.reconcile_check_delay_secs}s + one reconciler tick of slack tick_interval_secs ${reconciler.tick_interval_secs}s = ${window}s); otherwise a payment confirmed on-chain can no longer capture the wallet hold (it has already auto-released past its TTL), delivering the stablecoin without ever charging the wallet -- raise hold_ttl_secs above ${window}s or shrink the confirmation window`,
    );
  }
}

// --- asset bucket (issues #176/#410/#411/#485) ------------------------------

/** Credential-presence checks for `[asset_bucket]` (a no-op unless enabled/S3). */
export function validateAssetBucket(config: Config): void {
  const bucket = config.asset_bucket;
  const emptyString = (v: string | null) => v !== null && v.length === 0;
  if (emptyString(bucket.endpoint)) throw new Error("field asset_bucket.endpoint: cannot be empty");
  if (emptyString(bucket.bucket)) throw new Error("field asset_bucket.bucket: cannot be empty");
  if (emptyString(bucket.region)) throw new Error("field asset_bucket.region: cannot be empty");
  if (emptyString(bucket.access_key_id))
    throw new Error("field asset_bucket.access_key_id: cannot be empty");
  if (emptyString(bucket.secret_access_key_env))
    throw new Error("field asset_bucket.secret_access_key_env: cannot be empty");
  if (!buildsS3Client(bucket)) return;
  const required: [keyof typeof bucket, string][] = [
    ["endpoint", "endpoint"],
    ["bucket", "bucket"],
    ["region", "region"],
    ["access_key_id", "access_key_id"],
    ["secret_access_key_env", "secret_access_key_env"],
  ];
  for (const [field, name] of required) {
    if (bucket[field] === null) {
      throw new Error(`field asset_bucket.${name}: required when asset_bucket.enabled = true`);
    }
  }
}

/** Cloudflare-R2-specific checks for `[asset_bucket]` (issue #410/#485). */
export function validateAssetBucketR2(config: Config): void {
  const bucket = config.asset_bucket;
  if (!buildsS3Client(bucket)) return;
  const endpoint = bucket.endpoint;
  if (endpoint === null) return;
  if (!endpointTargetsR2(endpoint)) return;
  if (parseR2Endpoint(endpoint) === null) {
    let display = endpoint;
    let signedHost = endpoint;
    try {
      const parts = parseEndpoint(endpoint);
      const at = parts.authority.lastIndexOf("@");
      if (at !== -1) {
        display = `${parts.scheme}://<redacted-userinfo>@${parts.authority.slice(at + 1)}${parts.pathPrefix}`;
      }
      signedHost = parts.signingHost();
    } catch {
      /* keep raw endpoint */
    }
    throw new Error(
      `field asset_bucket.endpoint: ${display} looks like a Cloudflare R2 endpoint but is not of the form https://<account_id>.r2.cloudflarestorage.com (optionally with an .eu./.fedramp. jurisdiction label); the account id must be a single DNS label and the endpoint must use https:// and carry no userinfo, port, path, query, or fragment. The runtime would send \`host: ${signedHost}\`, which R2 rejects for this endpoint shape`,
    );
  }
  if (bucket.region !== R2_REGION) {
    throw new Error(
      `field asset_bucket.region: FerroGate requires region "${R2_REGION}" for Cloudflare R2 endpoints (got ${JSON.stringify(bucket.region)}); R2 ignores geographic regions and documents a blank region and "us-east-1" as aliases for "${R2_REGION}", but the signer folds this string straight into the credential scope, so FerroGate pins the canonical value`,
    );
  }
}

/** Cloudflare-native `[asset_bucket]` backend checks (issue #411). */
export function validateAssetBucketBackend(config: Config): void {
  const bucket = config.asset_bucket;
  if (!bucket.enabled || bucket.backend !== "workers-static-assets") return;
  const requireCf = (v: string | null, name: string) => {
    if (v === null || v.trim().length === 0) {
      throw new Error(
        `field asset_bucket.${name}: required when asset_bucket.backend = "workers-static-assets"`,
      );
    }
  };
  requireCf(bucket.cf_account_id, "cf_account_id");
  requireCf(bucket.cf_api_token, "cf_api_token");
  requireCf(bucket.cf_script_name, "cf_script_name");
}

// --- cloudflare (issues #405/#406/#408) -------------------------------------

/** Static invariants for the optional `[cloudflare]` block. */
export function validateCloudflare(config: Config): void {
  const cf = config.cloudflare;
  if (cf === null) return;
  if (cf.account_id.trim().length === 0)
    throw new Error("field cloudflare.account_id: cannot be empty");
  if (cf.api_token.trim().length === 0)
    throw new Error("field cloudflare.api_token: cannot be empty (an env:// reference or token)");
  for (const [tenant, ref] of Object.entries(cf.tenant_tokens)) {
    if (ref.trim().length === 0)
      throw new Error(`field cloudflare.tenant_tokens.${tenant}: token reference cannot be empty`);
  }
  for (const [field, url] of [
    ["api_base_url", cf.api_base_url],
    ["ai_gateway_base_url", cf.ai_gateway_base_url],
  ] as const) {
    if (url.trim().length === 0) throw new Error(`field cloudflare.${field}: cannot be empty`);
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      throw new Error(`field cloudflare.${field}: must start with http:// or https://`);
    }
  }
  if (cf.r2_s3_endpoint !== null) {
    if (!cf.r2_s3_endpoint.startsWith("http://") && !cf.r2_s3_endpoint.startsWith("https://")) {
      throw new Error("field cloudflare.r2_s3_endpoint: must start with http:// or https://");
    }
  }
}

/** Cloudflare managed MCP upstream guardrails (issue #408). */
export function validateCloudflareMcpServers(config: Config): void {
  for (let index = 0; index < config.mcp_servers.length; index += 1) {
    const server = config.mcp_servers[index]!;
    if (server.transport !== "streamable_http" && server.transport !== "sse") continue;
    const url = server.url;
    if (url === null) continue;
    if (!isCloudflareManagedMcpUrl(url)) continue;
    if (!url.toLowerCase().startsWith("https://")) {
      throw new Error(
        `field mcp_servers[${index}].url: Cloudflare managed MCP server ${server.name} must use an https url`,
      );
    }
    if (server.auth_type === "none") {
      throw new Error(
        `field mcp_servers[${index}].auth_type: Cloudflare managed MCP server ${server.name} requires authentication (shared_headers with a Cloudflare API bearer token, per_user_oauth, or original_bearer); Cloudflare rejects unauthenticated requests`,
      );
    }
  }
}

/**
 * `ferrogate_mcp::is_cloudflare_managed_mcp_url` (issue #408), ported 1:1:
 * anything on `*.mcp.cloudflare.com`, plus a tenant Worker whose path is the
 * conventional `/mcp` (Streamable HTTP) or `/sse` on `*.workers.dev` — so an
 * ordinary Worker on `workers.dev` is NOT flagged as an MCP upstream.
 *
 * PORT-TODO(inventory §5.3) — PACKAGE RELOCATION, NO OWNING LIBRARY EXISTS.
 * BEHAVIOR IS CLOSED. The function belongs to `ferrogate-mcp`, whose TS port
 * lives in the `apps/mcp` WORKER — there is no `@ferrogate/mcp` library
 * package, and `packages/config` must not depend on an app (that edge points
 * the wrong way and would drag a Worker entry module into every consumer of the
 * config schema). So the matcher is inlined here, read verbatim from
 * `crates/ferrogate-mcp`, and pinned by `validate-entities.test.ts` +
 * `validate-asset-bucket-cloudflare.test.ts`. Unlike the
 * `@ferrogate/{providers,storage,guardrails}` enum edges — which HAVE landed
 * and are now real imports (`schema/enums.ts`) — this one cannot be closed by
 * this package alone: it needs an `@ferrogate/mcp` library to exist first. Do
 * not re-derive the matcher when it does.
 */
function isCloudflareManagedMcpUrl(url: string): boolean {
  let host: string;
  let path: string;
  try {
    const u = new URL(url);
    host = u.hostname.toLowerCase();
    path = u.pathname;
  } catch {
    return false;
  }
  if (host === "mcp.cloudflare.com" || host.endsWith(".mcp.cloudflare.com")) return true;
  if (host !== "workers.dev" && !host.endsWith(".workers.dev")) return false;
  const trimmed = path.replace(/\/+$/, "");
  return trimmed.endsWith("/mcp") || trimmed.endsWith("/sse");
}

// --- entry point ------------------------------------------------------------

/**
 * `Config::validate()` — the load-time gate, in the Rust call order (which is
 * observable: it decides WHICH of several problems an operator is told about
 * first). Throws the first `field ...: ...` error, mirroring the Rust `anyhow`
 * chain.
 */
export function validateConfig(config: Config, options: ValidateOptions = {}): void {
  if (!isValidSocketAddr(config.listen)) {
    throw new Error(`field listen: invalid listen address ${config.listen}`);
  }
  if (config.admin.listen !== null && !isValidSocketAddr(config.admin.listen)) {
    throw new Error(`field admin.listen: invalid admin listen address ${config.admin.listen}`);
  }

  const providerNames = validateProviders(config);
  const modelNames = validateModels(config, providerNames);
  validateMcpServers(config);
  validateAuthService(config);
  validateAdminApi(config);
  // MCP tools/servers become addressable policy targets BEFORE the api-key,
  // policy and guardrail cross-reference checks run against those sets.
  addMcpPolicyTargets(config, modelNames, providerNames);
  const apiKeyIds = validateApiKeys(config, modelNames, providerNames);
  ensureEveryKeyDeclaresTenantIdentity(config, options);
  // Rust warns here via `tracing::warn!`. A library on Workers has no logger and
  // this function returns `void`, so a call whose `string[]` is discarded would
  // be INERT — it would look wired and warn nobody. The warning is surfaced
  // instead by {@link tenancyPostureWarnings}, which the two consumers that can
  // actually show it to an operator do call: `apps/control-plane`'s
  // `admin_config_ops` validate response and `apps/cli`'s config gate. Pinned by
  // `schema-validate.test.ts` > "tenancy posture warnings".
  validatePolicies(config, apiKeyIds, modelNames, providerNames);
  validateGatewayConfigs(config, apiKeyIds);
  validatePlugins(config);
  const toolNames = workflowToolNames(config);
  validateAgentWorkflows(config, apiKeyIds, modelNames, providerNames, toolNames);
  validatePromptTemplates(config, modelNames);
  validateSkillPackages(config, apiKeyIds, toolNames);
  validateAgentUpstreams(config);
  validateGuardrails(config, apiKeyIds, modelNames, providerNames);
  // `self.validate_tls()` ran here in Rust — REMOVED as N/A on Cloudflare (CF
  // terminates TLS; see the module header).
  validateTelemetry(config);
  validateBillingAlerts(config);
  validateObservability(config);
  validateAnalytics(config);
  validateMetering(config);
  validateCache(config);
  validateStorage(config);
  validateReliability(config);
  validateLimits(config);
  validateAgentRuntime(config);
  validateCluster(config);
  validateNetworkAccess(config);
  const upstreamNames = validateUpstreams(config);
  validateRoutes(config, upstreamNames);
  validateAssetBucket(config);
  validateX402Reconciler(config);
  validateX402SpendPolicies(config);
  validateCloudflare(config);
  validateAssetBucketR2(config);
  validateCloudflareAiGatewayProviders(config);
  validateCloudflareMcpServers(config);
  validateAssetBucketBackend(config);
}

/**
 * `validateConfig` plus the one leg that cannot be synchronous on Workers: the
 * signed-snapshot key material (#206). Rust runs the SAME builder the runtime
 * uses (`build_snapshot_crypto`) inside `validate_cluster`, so a config that
 * validates is one that constructs; WebCrypto's `importKey` is async, so the
 * structural half runs in `validateCluster` and the key parse runs here.
 *
 * Callers that can await SHOULD prefer this over `validateConfig`.
 */
export async function validateConfigAsync(
  config: Config,
  options: ValidateOptions = {},
): Promise<void> {
  validateConfig(config, options);
  if (config.cluster.enabled) await buildSnapshotCrypto(config.cluster);
}
