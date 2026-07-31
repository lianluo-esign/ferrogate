/**
 * Where the multi-level quota for a request comes from.
 *
 * The MERGE ITSELF IS NOT IMPLEMENTED HERE. `@ferrogate/policy`'s
 * `resolveEffectiveQuota` already ports `ferrogate-policy/quota.rs` (62 tests):
 * min-across tenant → project → workspace → key, model-allowlist intersection,
 * `enabled = false` anywhere is a hard deny, and a plan supplies the FLOOR (a
 * field takes the plan default only when no policy set it). This module only
 * decides *which policies to feed it* and turns the result into the RPM/TPM
 * windows in `keys.ts`.
 *
 * `resolveEffectiveQuota` takes its policy lookup as a closure precisely so the
 * source is swappable, so the port is a `QuotaPolicySource`:
 *
 *  - production → D1, via `@ferrogate/storage` (PORT-TODO below);
 *  - today      → the `GATEWAY_QUOTA_POLICIES` / `GATEWAY_PLANS` Worker vars,
 *    mirroring how `src/adapters.ts` backs the auth ports from vars until
 *    storage lands. Fail-closed on malformed JSON exactly as `parseJsonVar`
 *    does: an unreadable table configures NO policies, which cannot widen a
 *    limit that a policy would have imposed.
 */
import {
  type EffectiveQuota,
  type QuotaScopeChain,
  type QuotaScopeKind,
  type StoredPlan,
  type StoredQuotaPolicy,
  resolveEffectiveQuota,
} from "@ferrogate/policy";
import { type CounterWindow, requestWindows, tpmWindow } from "./keys.js";

/**
 * Everything the limiter needs about one caller, projected out of the resolved
 * `AuthContext` by the composition root.
 */
export interface QuotaSubject {
  /** The presented credential's id. `key`-scope windows are namespaced with it. */
  readonly apiKeyId: string;
  /** Tenant / project / workspace / key ids to merge policies across. */
  readonly chain: QuotaScopeChain;
  /**
   * The TOK-12 per-key `request_limit_per_minute` carried on the credential
   * itself, independent of the quota chain. Rust `AuthContext.request_limit_per_minute`.
   */
  readonly requestLimitPerMinute?: number | undefined;
}

/**
 * Supplies the policies + plan for a subject.
 *
 * PORT-TODO(inventory-request-path §1.6 "Quota policies"): back this with
 * `@ferrogate/storage` (`quota_policies` + `plans` tables in D1), replacing
 * {@link quotaPolicySourceFromEnv}. `AppState::resolve_effective_quota` reads
 * both from Supabase in Rust and returns
 * `503 quota_resolution_unavailable` on a lookup error — which is why
 * {@link QuotaResolution} has an `unavailable` variant rather than defaulting
 * to "no quota".
 */
export interface QuotaPolicySource {
  policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot>;
}

export type QuotaPolicySnapshot =
  | {
      readonly ok: true;
      /** Rust's `lookup` closure. `undefined` = that scope does not restrict. */
      readonly lookup: (kind: QuotaScopeKind, id: string) => StoredQuotaPolicy | undefined;
      /** The tenant's plan, if any — the merge FLOOR (issue #168). */
      readonly plan?: StoredPlan | undefined;
    }
  | { readonly ok: false; readonly detail: string };

/** The merged quota plus the windows it implies. */
export type QuotaResolution =
  | {
      readonly ok: true;
      readonly quota: EffectiveQuota;
      readonly rpm: CounterWindow[];
      readonly tpm: CounterWindow | null;
    }
  | { readonly ok: false; readonly detail: string };

/**
 * Merge the chain and derive the windows.
 *
 * A `deniedBy` result is returned as-is on `quota` — it is a **403
 * `quota_scope_disabled`**, not a rate-limit denial, and the caller must check
 * for it before enforcing any window (Rust `finalize_auth` does exactly that,
 * ahead of the budget and RPM checks).
 */
export async function resolveQuotaWindows(
  source: QuotaPolicySource,
  subject: QuotaSubject,
): Promise<QuotaResolution> {
  const snapshot = await source.policiesFor(subject);
  if (!snapshot.ok) return { ok: false, detail: snapshot.detail };

  const quota = resolveEffectiveQuota(subject.chain, snapshot.lookup, snapshot.plan);
  if (quota.deniedBy !== undefined) {
    // No windows: the request never reaches admission counting.
    return { ok: true, quota, rpm: [], tpm: null };
  }
  return {
    ok: true,
    quota,
    rpm: requestWindows(subject.apiKeyId, quota, subject.requestLimitPerMinute),
    tpm: tpmWindow(subject.apiKeyId, quota),
  };
}

// ---------------------------------------------------------------------------
// Config-var adapter
// ---------------------------------------------------------------------------

/** Worker bindings this module reads. */
export interface QuotaBindings {
  /**
   * JSON array of `StoredQuotaPolicy` rows (snake_case on the wire, matching
   * the storage column names). Absent/malformed ⇒ no policy restricts.
   */
  readonly GATEWAY_QUOTA_POLICIES?: string | undefined;
  /** JSON map of tenant id → `StoredPlan` (the merge floor). */
  readonly GATEWAY_PLANS?: string | undefined;
  /** JSON map of tenant id → plan slug/id, selecting which plan applies. */
  readonly GATEWAY_TENANT_PLANS?: string | undefined;
}

function parseJsonVar<T>(raw: string | undefined, fallback: T): T {
  if (raw === undefined || raw.trim() === "") return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    // Fail closed: an unreadable table configures nothing, and "nothing
    // configured" can only leave a limit unset, never raise one.
    return fallback;
  }
}

interface WirePolicy {
  id?: string;
  scope_type: QuotaScopeKind;
  scope_id: string;
  model_allowlist?: string[];
  rpm_limit?: number;
  tpm_limit?: number;
  monthly_budget_usd?: number;
  agent_cost_budget_usd?: number;
  asset_storage_quota_bytes?: number;
  asset_max_object_bytes?: number;
  monthly_egress_bytes_budget?: number;
  download_rpm_limit?: number;
  alert_threshold_pcts?: number[];
  enabled?: boolean;
}

interface WirePlan {
  id?: string;
  name?: string;
  slug?: string;
  default_model_allowlist?: string[];
  default_rpm_limit?: number;
  default_tpm_limit?: number;
  default_monthly_budget_usd?: number;
  default_agent_cost_budget_usd?: number;
  default_monthly_egress_bytes_budget?: number;
  default_download_rpm_limit?: number;
  default_asset_storage_quota_bytes?: number;
  default_asset_max_object_bytes?: number;
}

function toStoredPolicy(wire: WirePolicy): StoredQuotaPolicy {
  return {
    id: wire.id ?? `${wire.scope_type}:${wire.scope_id}`,
    scopeType: wire.scope_type,
    scopeId: wire.scope_id,
    modelAllowlist: wire.model_allowlist ?? [],
    rpmLimit: wire.rpm_limit,
    tpmLimit: wire.tpm_limit,
    monthlyBudgetUsd: wire.monthly_budget_usd,
    agentCostBudgetUsd: wire.agent_cost_budget_usd,
    assetStorageQuotaBytes: wire.asset_storage_quota_bytes,
    assetMaxObjectBytes: wire.asset_max_object_bytes,
    monthlyEgressBytesBudget: wire.monthly_egress_bytes_budget,
    downloadRpmLimit: wire.download_rpm_limit,
    alertThresholdPcts: wire.alert_threshold_pcts ?? [],
    // Rust default for a persisted policy row is enabled; only an explicit
    // `false` denies, so an omitted column cannot lock a tenant out by accident.
    enabled: wire.enabled ?? true,
    createdAtUnix: 0,
    updatedAtUnix: 0,
  };
}

function toStoredPlan(wire: WirePlan): StoredPlan {
  return {
    id: wire.id ?? wire.slug ?? "plan",
    name: wire.name ?? wire.slug ?? "plan",
    slug: wire.slug ?? wire.id ?? "plan",
    mcpEnabled: false,
    selfHostedWorkersEnabled: false,
    defaultModelAllowlist: wire.default_model_allowlist ?? [],
    defaultRpmLimit: wire.default_rpm_limit,
    defaultTpmLimit: wire.default_tpm_limit,
    defaultMonthlyBudgetUsd: wire.default_monthly_budget_usd,
    defaultAgentCostBudgetUsd: wire.default_agent_cost_budget_usd,
    defaultMonthlyEgressBytesBudget: wire.default_monthly_egress_bytes_budget,
    defaultDownloadRpmLimit: wire.default_download_rpm_limit,
    defaultAssetStorageQuotaBytes: wire.default_asset_storage_quota_bytes,
    defaultAssetMaxObjectBytes: wire.default_asset_max_object_bytes,
    createdAtUnix: 0,
    updatedAtUnix: 0,
    assetHostingEnabled: false,
    extensionToolsEnabled: false,
  };
}

/**
 * Build a {@link QuotaPolicySource} from Worker vars. Policies are indexed by
 * `"{scope_type}:{scope_id}"` — the same shape as `quotaPolicyId` in
 * `@ferrogate/policy`, and NOT the counter key (a policy row's identity and a
 * counter window's identity are different things; conflating them is how the
 * `key`-scope namespacing gets lost).
 */
export function quotaPolicySourceFromEnv(env: QuotaBindings): QuotaPolicySource {
  const rows = parseJsonVar<WirePolicy[]>(env.GATEWAY_QUOTA_POLICIES, []);
  const index = new Map<string, StoredQuotaPolicy>();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (typeof row?.scope_type !== "string" || typeof row?.scope_id !== "string") continue;
    index.set(`${row.scope_type}:${row.scope_id}`, toStoredPolicy(row));
  }

  const planRows = parseJsonVar<Record<string, WirePlan>>(env.GATEWAY_PLANS, {});
  const tenantPlans = parseJsonVar<Record<string, string>>(env.GATEWAY_TENANT_PLANS, {});

  const lookup = (kind: QuotaScopeKind, id: string): StoredQuotaPolicy | undefined =>
    index.get(`${kind}:${id}`);

  return {
    async policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot> {
      const tenantId = subject.chain.tenantId;
      const planKey = tenantId === undefined ? undefined : tenantPlans[tenantId];
      const wirePlan = planKey === undefined ? undefined : planRows[planKey];
      return {
        ok: true,
        lookup,
        plan: wirePlan === undefined ? undefined : toStoredPlan(wirePlan),
      };
    },
  };
}

/** A source that configures nothing — the fail-open-to-no-limits default. */
export const NO_QUOTA_POLICIES: QuotaPolicySource = {
  async policiesFor(): Promise<QuotaPolicySnapshot> {
    return { ok: true, lookup: () => undefined };
  },
};
