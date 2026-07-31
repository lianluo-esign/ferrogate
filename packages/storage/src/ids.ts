/**
 * Deterministic id helpers, the `YYYY-MM` period key, sha256, and the saturating
 * integer helpers shared across the storage domain modules.
 *
 * The ids are deterministic on purpose (ports the Rust helpers): an `upsert`
 * keyed on the composed id is naturally idempotent per its owning tuple, with no
 * separate lookup-then-insert step.
 */
import type { QuotaScopeKind } from "./quota.js";

/** `{tenant}:{asset_type}:{name}:{version}` — idempotent per that tuple. */
export function storedAssetId(
  tenantId: string,
  assetType: string,
  name: string,
  version: string,
): string {
  return `${tenantId}:${assetType}:${name}:${version}`;
}

/**
 * Variant-aware asset id (issue #260). Falls back to {@link storedAssetId} for the
 * default (empty) variant so pre-#260 ids are preserved, else appends `:v:{variant}`.
 */
export function storedAssetVariantId(
  tenantId: string,
  assetType: string,
  name: string,
  version: string,
  variant: string,
): string {
  if (variant === "") return storedAssetId(tenantId, assetType, name, version);
  return `${tenantId}:${assetType}:${name}:${version}:v:${variant}`;
}

/** `{tenant}:{asset_type}:{name}:{channel}` channel-pointer id. */
export function assetChannelId(
  tenantId: string,
  assetType: string,
  name: string,
  channel: string,
): string {
  return `${tenantId}:${assetType}:${name}:${channel}`;
}

/** `{scope_type}:{scope_id}` quota-policy id. */
export function quotaPolicyId(scopeType: QuotaScopeKind, scopeId: string): string {
  return `${scopeType}:${scopeId}`;
}

/** `{period_month}:{scope_type}:{scope_id}` usage-monthly-rollup id. */
export function usageMonthlyRollupId(
  periodMonth: string,
  scopeType: QuotaScopeKind,
  scopeId: string,
): string {
  return `${periodMonth}:${scopeType}:${scopeId}`;
}

/** `{period}:{org}:{key}:{value}` metadata-rollup id (org included per #226). */
export function usageMetadataRollupId(
  periodMonth: string,
  organizationId: string,
  metadataKey: string,
  metadataValue: string,
): string {
  return `${periodMonth}:${organizationId}:${metadataKey}:${metadataValue}`;
}

/** `{scope_type}:{scope_id}:{period}:{threshold}` budget-alert id (#170). */
export function budgetAlertNotificationId(
  scopeType: QuotaScopeKind,
  scopeId: string,
  periodMonth: string,
  thresholdPct: number,
): string {
  return `${scopeType}:${scopeId}:${periodMonth}:${thresholdPct}`;
}

/** `{workflow}:{version}:{run}` workflow-run-budget id (#279). */
export function workflowRunBudgetId(
  workflowId: string,
  workflowVersion: number,
  runId: string,
): string {
  return `${workflowId}:${workflowVersion}:${runId}`;
}

/** `{tenant}:{provider}:{provider_pm_id}` payment-method id (#169). */
export function paymentMethodId(
  tenantId: string,
  provider: string,
  providerPaymentMethodId: string,
): string {
  return `${tenantId}:${provider}:${providerPaymentMethodId}`;
}

/** `{tenant}:{resource_type}:{scope}` retention-policy id (#263). */
export function retentionPolicyId(
  tenantId: string,
  resourceType: string,
  scope: string,
): string {
  return `${tenantId}:${resourceType}:${scope}`;
}

/** `{policy_id}@{revision}` guardrail-policy-revision id. */
export function guardrailPolicyRevisionId(policyId: string, revision: number): string {
  return `${policyId}@${revision}`;
}

/**
 * Length-prefixed composite key `{len(tenant)}:{tenant}:{len(agent)}:{agent}:{len(period)}:{period}`
 * for the agent-cost-burn row (#428). Length prefixes make aliasing impossible.
 */
export function agentCostBurnKey(tenantId: string, agentKey: string, period: string): string {
  return `${tenantId.length}:${tenantId}:${agentKey.length}:${agentKey}:${period.length}:${period}`;
}

/** Length-prefixed `{len(tenant)}:{tenant}:{api_key_id}` presence key (#357). */
export function observedAgentPresenceKey(tenantId: string, apiKeyId: string): string {
  return `${tenantId.length}:${tenantId}:${apiKeyId}`;
}

/** Length-prefixed `{len(tenant)}:{tenant}:{hostname}` site-domain-verification key (#576). */
export function siteDomainVerificationKey(tenantId: string, hostname: string): string {
  return `${tenantId.length}:${tenantId}:${hostname}`;
}

/**
 * `YYYY-MM` (UTC) calendar month for a unix-seconds timestamp. Dependency-free
 * port of Howard Hinnant's `civil_from_days`, matching the Rust helper exactly
 * (so a row's period key is identical across the port).
 */
export function periodMonthFromUnix(unixSeconds: number): string {
  const days = Math.floor(unixSeconds / 86_400);
  const [year, month] = civilFromDays(days);
  return `${pad(year, 4)}-${pad(month, 2)}`;
}

function civilFromDays(daysSinceEpoch: number): [number, number, number] {
  const z = daysSinceEpoch + 719_468;
  const era = Math.floor(z / 146_097);
  const doe = z - era * 146_097; // [0, 146096]
  const yoe = Math.floor((doe - Math.floor(doe / 1_460) + Math.floor(doe / 36_524) - Math.floor(doe / 146_096)) / 365); // [0, 399]
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100)); // [0, 365]
  const mp = Math.floor((5 * doy + 2) / 153); // [0, 11]
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1; // [1, 31]
  const m = mp < 10 ? mp + 3 : mp - 9; // [1, 12]
  const year = m <= 2 ? y + 1 : y;
  return [year, m, d];
}

function pad(value: number, width: number): string {
  return String(value).padStart(width, "0");
}

/**
 * SHA-256, hex-encoded (ports `sha256_hex`). Async because WebCrypto's
 * `subtle.digest` is async — the Rust `sha2` call is sync, but content hashing
 * only ever runs off the parse hot path (asset push / object-key derivation).
 */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  const view = new Uint8Array(digest);
  let out = "";
  for (const byte of view) out += byte.toString(16).padStart(2, "0");
  return out;
}

/** Saturating i64 add, clamped to the JS safe-integer range. Ports Rust `saturating_add`. */
export function saturatingAdd(a: number, b: number): number {
  const sum = a + b;
  if (sum > Number.MAX_SAFE_INTEGER) return Number.MAX_SAFE_INTEGER;
  if (sum < Number.MIN_SAFE_INTEGER) return Number.MIN_SAFE_INTEGER;
  return sum;
}
