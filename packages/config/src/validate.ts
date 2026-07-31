/**
 * Port of the load-bearing invariants of `ferrogate-config`'s `validate.rs`
 * (inventory §5.4, `Config::validate`). The Rust gate is ~1800 lines / 98
 * helper fns; the security- and money-critical invariants the inventory and
 * the security appendix call out are ported here with fidelity, and the long
 * tail of per-field cross-reference checks is flagged.
 *
 * PORT-TODO(inventory §5.4): the remaining ~90 helper validators (provider/model
 * name uniqueness + cross-references, header name/value validity via `http`
 * types, plugin/skill-package manifest + permission checks, prompt-template
 * placeholder checks, managed-worker action lists, storage DSN/identifier
 * checks, TLS file presence, MCP server config) are mechanical Zod
 * `superRefine` ports and are staged incrementally; the Zod schema already
 * rejects the structural/type errors. What is ported below is every invariant
 * whose omission would change a security or money outcome.
 */
import { parseEndpoint, endpointTargetsR2, parseR2Endpoint, R2_REGION } from "./asset-endpoint.js";
import { x402ConfirmationWindowSecs, x402HoldTtlFloorSecs } from "./x402-hold.js";
import { buildsS3Client } from "./schema/sections.js";
import type { ApiKey, Config } from "./schema/index.js";

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
      `[tenancy] implicit_platform_operator = true grants UNRESTRICTED cross-tenant ` +
        `(platform-operator) access to every API key that declares neither organization_id nor ` +
        `platform_operator: ${implicit.join(", ")}. Declare each key and then remove the switch.`,
    );
  }
  const authorizesNothing = apiKeysThatAuthorizeNothing(config);
  if (authorizesNothing.length > 0) {
    warnings.push(
      `these API keys declare platform_operator = false and name no organization_id, so they ` +
        `have no tenant identity to authorize against: every request presenting one is refused ` +
        `with tenant_identity_required: ${authorizesNothing.join(", ")}.`,
    );
  }
  return warnings;
}

function undeclaredTenantIdentityRefusal(undeclared: string[]): string {
  return (
    `refusing to start: these API keys declare neither organization_id nor platform_operator, ` +
    `so they have no tenant identity to authorize against and would be refused at authentication ` +
    `(tenant_identity_required): ${undeclared.join(", ")}. Say what each one is: ` +
    `platform_operator = true (administers every tenant) or organization_id = "<tenants.id>" ` +
    `(belongs to one tenant). In TOML/YAML only you may keep the pre-#515 behaviour with ` +
    `[tenancy] implicit_platform_operator = true while you annotate them.`
  );
}

/**
 * `#540`, the flip: refuse (at load) a config whose static keys would only be
 * authorized by the pre-#515 "no tenant means root" rule. Durable control-plane
 * keys are reported, not refused (stopping there would lock the operator out of
 * the API that repairs them). Throws on refusal.
 */
export function ensureEveryKeyDeclaresTenantIdentity(config: Config, options: ValidateOptions = {}): void {
  if (config.tenancy.implicit_platform_operator) return;
  const undeclared = apiKeysWithoutTenantIdentity(config);
  if (undeclared.length === 0) return;
  if (options.apiKeysAreControlPlaneDocuments) return; // reported (warn), not refused
  throw new Error(undeclaredTenantIdentityRefusal(undeclared));
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
      `field x402_reconciler.hold_ttl_secs: the wallet hold TTL (${reconciler.hold_ttl_secs}s) ` +
        `must strictly outlive the settlement confirmation window (confirmation_deadline_secs ` +
        `${reconciler.confirmation_deadline_secs}s + reconcile_check_delay_secs ` +
        `${reconciler.reconcile_check_delay_secs}s + one reconciler tick of slack ` +
        `tick_interval_secs ${reconciler.tick_interval_secs}s = ${window}s); otherwise a payment ` +
        `confirmed on-chain can no longer capture the wallet hold, delivering the stablecoin ` +
        `without ever charging the wallet -- raise hold_ttl_secs above ${window}s or shrink the ` +
        `confirmation window`,
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
  if (emptyString(bucket.access_key_id)) throw new Error("field asset_bucket.access_key_id: cannot be empty");
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
      `field asset_bucket.endpoint: ${display} looks like a Cloudflare R2 endpoint but is not of ` +
        `the form https://<account_id>.r2.cloudflarestorage.com (optionally with an .eu./.fedramp. ` +
        `jurisdiction label); the account id must be a single DNS label and the endpoint must use ` +
        `https:// and carry no userinfo, port, path, query, or fragment. The runtime would send ` +
        `\`host: ${signedHost}\`, which R2 rejects for this endpoint shape`,
    );
  }
  if (bucket.region !== R2_REGION) {
    throw new Error(
      `field asset_bucket.region: FerroGate requires region "${R2_REGION}" for Cloudflare R2 ` +
        `endpoints (got ${JSON.stringify(bucket.region)}); R2 ignores geographic regions but the ` +
        `signer folds this string straight into the credential scope, so FerroGate pins the ` +
        `canonical value`,
    );
  }
}

/** Cloudflare-native `[asset_bucket]` backend checks (issue #411). */
export function validateAssetBucketBackend(config: Config): void {
  const bucket = config.asset_bucket;
  if (!bucket.enabled || bucket.backend !== "workers-static-assets") return;
  const requireCf = (v: string | null, name: string) => {
    if (v === null || v.trim().length === 0) {
      throw new Error(`field asset_bucket.${name}: required when asset_bucket.backend = "workers-static-assets"`);
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
  if (cf.account_id.trim().length === 0) throw new Error("field cloudflare.account_id: cannot be empty");
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
        `field mcp_servers[${index}].auth_type: Cloudflare managed MCP server ${server.name} requires authentication`,
      );
    }
  }
}

/**
 * PORT-TODO(inventory §5.3): mirror of `ferrogate_mcp::is_cloudflare_managed_mcp_url`
 * (wave 2). Matches `*.mcp.cloudflare.com` and tenant `*.workers.dev/mcp`.
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
  if ((host === "workers.dev" || host.endsWith(".workers.dev")) && path.replace(/\/+$/, "").endsWith("/mcp")) {
    return true;
  }
  return false;
}

// --- listen address ---------------------------------------------------------

function isValidSocketAddr(value: string): boolean {
  let v = value;
  if (v.startsWith("localhost:")) v = `127.0.0.1:${v.slice("localhost:".length)}`;
  const lastColon = v.lastIndexOf(":");
  if (lastColon === -1) return false;
  const host = v.slice(0, lastColon);
  const portStr = v.slice(lastColon + 1);
  if (!/^\d+$/.test(portStr)) return false;
  const port = Number.parseInt(portStr, 10);
  if (port > 65535) return false;
  return host.length > 0;
}

// --- entry point ------------------------------------------------------------

/**
 * `Config::validate()` — the load-time gate. Runs the invariants that change a
 * security/money/binding outcome (the structural/type invariants are enforced
 * by the Zod schema). Throws the first `field ...: ...` error, mirroring the
 * Rust `anyhow` chain.
 */
export function validateConfig(config: Config, options: ValidateOptions = {}): void {
  if (!isValidSocketAddr(config.listen)) {
    throw new Error(`field listen: invalid listen address ${config.listen}`);
  }
  if (config.admin.listen !== null && !isValidSocketAddr(config.admin.listen)) {
    throw new Error(`field admin.listen: invalid admin listen address ${config.admin.listen}`);
  }
  ensureEveryKeyDeclaresTenantIdentity(config, options);
  warnImplicitPlatformOperators(config);
  validateAssetBucket(config);
  validateX402Reconciler(config);
  validateCloudflare(config);
  validateAssetBucketR2(config);
  validateCloudflareMcpServers(config);
  validateAssetBucketBackend(config);
}
