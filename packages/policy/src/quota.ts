/**
 * Multi-level quota/rate-limit resolution (port of `ferrogate-policy` `quota.rs`,
 * P1-3 / #168 / #259 / #262 / #428).
 *
 * Merges tenant/project/workspace/key scope policies into one effective quota:
 * numeric limits are `min`-across-the-chain (a nearer scope may tighten but can
 * never exceed an ancestor cap), `model_allowlist` is the intersection of every
 * scope that defines a non-empty list, and a disabled policy anywhere is a hard
 * deny. A plan supplies the FLOOR (a field takes the plan default only when no
 * policy set it).
 */
import type {
  QuotaScopeKind,
  StoredPlan,
  StoredQuotaPolicy,
} from "./stored-types.js";

/**
 * The scope chain a request resolves to. Any level may be absent (e.g. a key
 * that predates the workspace hierarchy).
 */
export interface QuotaScopeChain {
  tenantId?: string;
  projectId?: string;
  workspaceId?: string;
  keyId?: string;
}

/**
 * The single scope whose configured limit is binding (tightest) for a dimension.
 * Rate-limit/budget windows are keyed on this so a tenant/project/workspace cap
 * is enforced as ONE aggregate counter shared by every key under it.
 */
export class QuotaScopeSelector {
  constructor(
    readonly kind: QuotaScopeKind,
    readonly id: string,
  ) {}

  /**
   * The rate-limit/budget counter-window key for this binding scope.
   *
   * SECURITY-CRITICAL: EVERY scope (including `key`) is `"{kind}:{id}"`-namespaced.
   * A `key` winner is `"key:{api_key_id}"` — never the raw, tenant-controllable
   * `api_key_id`. The `"key:"` prefix makes a per-key counter structurally unable
   * to equal any broader-scope key, so a tenant cannot mint a virtual key whose
   * id is `"tenant:<victim>"` and collide another tenant's aggregate window
   * (cross-tenant DoS).
   */
  counterKey(apiKeyId: string): string {
    return this.kind === "key" ? `key:${apiKeyId}` : `${this.kind}:${this.id}`;
  }

  equals(other: QuotaScopeSelector | undefined): boolean {
    return other !== undefined && other.kind === this.kind && other.id === this.id;
  }
}

/** The result of merging every defined policy across a scope chain. */
export interface EffectiveQuota {
  /** `undefined` ⇒ no scope restricts models; otherwise the intersection. */
  modelAllowlist?: string[];
  rpmLimit?: number;
  rpmLimitScope?: QuotaScopeSelector;
  tpmLimit?: number;
  tpmLimitScope?: QuotaScopeSelector;
  monthlyBudgetUsd?: number;
  monthlyBudgetScope?: QuotaScopeSelector;
  /** #428 tightest per-tenant monthly agent-runtime-cost ceiling. */
  agentCostBudgetUsd?: number;
  agentCostBudgetScope?: QuotaScopeSelector;
  /** #259 cumulative asset storage byte quota (tenant-scoped only). */
  assetStorageQuotaBytes?: number;
  /** #259 dedicated per-object asset byte ceiling (tenant-scoped only). */
  assetMaxObjectBytes?: number;
  /** #262 tightest monthly egress/download byte budget. */
  monthlyEgressBytesBudget?: number;
  monthlyEgressBytesScope?: QuotaScopeSelector;
  /** #262 tightest per-minute asset-download request cap. */
  downloadRpmLimit?: number;
  downloadRpmLimitScope?: QuotaScopeSelector;
  /** Set ⇒ a scope in the chain is disabled; the caller MUST fail closed. */
  deniedBy?: QuotaScopeKind;
}

/** `denied_by.is_some()`. */
export function isDenied(quota: EffectiveQuota): boolean {
  return quota.deniedBy !== undefined;
}

/** Allowlist is unset (unrestricted) OR contains `model`. */
export function allowsModel(quota: EffectiveQuota, model: string): boolean {
  return quota.modelAllowlist === undefined || quota.modelAllowlist.includes(model);
}

/**
 * Fold one policy's numeric limit into the running `min`, recording the scope
 * whose value now holds that min. Overrides on `<=` so that, given the
 * Tenant→Project→Workspace→Key iteration order, a tie is awarded to the most
 * specific scope (preserving per-key counting). Shared by u64 and f64 dims — TS
 * has one number type, and the comparison is identical.
 */
function updateMinScope(
  current: { value?: number; scope?: QuotaScopeSelector },
  candidate: number | undefined,
  scopeType: QuotaScopeKind,
  scopeId: string,
): void {
  if (candidate === undefined) return;
  if (current.value === undefined || candidate <= current.value) {
    current.value = candidate;
    current.scope = new QuotaScopeSelector(scopeType, scopeId);
  }
}

/**
 * Resolve the effective quota for one request's scope chain. `lookup` is injected
 * so callers can source policies from any backend (D1 in production, a map in
 * tests) without this module doing I/O. `plan` (issue #168) supplies the merge
 * floor and can never tighten or loosen an explicit policy value.
 */
export function resolveEffectiveQuota(
  chain: QuotaScopeChain,
  lookup: (kind: QuotaScopeKind, id: string) => StoredQuotaPolicy | undefined,
  plan?: StoredPlan,
): EffectiveQuota {
  const scopes: [QuotaScopeKind, string | undefined][] = [
    ["tenant", chain.tenantId],
    ["project", chain.projectId],
    ["workspace", chain.workspaceId],
    ["key", chain.keyId],
  ];
  const policies: StoredQuotaPolicy[] = [];
  for (const [kind, id] of scopes) {
    if (id === undefined) continue;
    const policy = lookup(kind, id);
    if (policy !== undefined) policies.push(policy);
  }

  const disabled = policies.find((p) => !p.enabled);
  if (disabled !== undefined) {
    return { deniedBy: disabled.scopeType };
  }

  const effective: EffectiveQuota = {};
  const rpm = { value: undefined as number | undefined, scope: undefined as QuotaScopeSelector | undefined };
  const tpm = { value: undefined as number | undefined, scope: undefined as QuotaScopeSelector | undefined };
  const budget = { value: undefined as number | undefined, scope: undefined as QuotaScopeSelector | undefined };
  const agent = { value: undefined as number | undefined, scope: undefined as QuotaScopeSelector | undefined };
  const egress = { value: undefined as number | undefined, scope: undefined as QuotaScopeSelector | undefined };
  const dlRpm = { value: undefined as number | undefined, scope: undefined as QuotaScopeSelector | undefined };

  for (const policy of policies) {
    if (policy.modelAllowlist.length > 0) {
      effective.modelAllowlist =
        effective.modelAllowlist === undefined
          ? [...policy.modelAllowlist]
          : effective.modelAllowlist.filter((m) => policy.modelAllowlist.includes(m));
    }
    updateMinScope(rpm, policy.rpmLimit, policy.scopeType, policy.scopeId);
    updateMinScope(tpm, policy.tpmLimit, policy.scopeType, policy.scopeId);
    updateMinScope(budget, policy.monthlyBudgetUsd, policy.scopeType, policy.scopeId);
    updateMinScope(agent, policy.agentCostBudgetUsd, policy.scopeType, policy.scopeId);
    updateMinScope(egress, policy.monthlyEgressBytesBudget, policy.scopeType, policy.scopeId);
    updateMinScope(dlRpm, policy.downloadRpmLimit, policy.scopeType, policy.scopeId);
    if (policy.scopeType === "tenant") {
      effective.assetStorageQuotaBytes = policy.assetStorageQuotaBytes;
      effective.assetMaxObjectBytes = policy.assetMaxObjectBytes;
    }
  }

  if (plan !== undefined) {
    const planScope =
      chain.tenantId !== undefined ? new QuotaScopeSelector("tenant", chain.tenantId) : undefined;
    if (effective.modelAllowlist === undefined && plan.defaultModelAllowlist.length > 0) {
      effective.modelAllowlist = [...plan.defaultModelAllowlist];
    }
    if (rpm.value === undefined && plan.defaultRpmLimit !== undefined) {
      rpm.value = plan.defaultRpmLimit;
      rpm.scope = planScope;
    }
    if (tpm.value === undefined && plan.defaultTpmLimit !== undefined) {
      tpm.value = plan.defaultTpmLimit;
      tpm.scope = planScope;
    }
    if (budget.value === undefined && plan.defaultMonthlyBudgetUsd !== undefined) {
      budget.value = plan.defaultMonthlyBudgetUsd;
      budget.scope = planScope;
    }
    if (agent.value === undefined && plan.defaultAgentCostBudgetUsd !== undefined) {
      agent.value = plan.defaultAgentCostBudgetUsd;
      agent.scope = planScope;
    }
    if (egress.value === undefined && plan.defaultMonthlyEgressBytesBudget !== undefined) {
      egress.value = plan.defaultMonthlyEgressBytesBudget;
      egress.scope = planScope;
    }
    if (dlRpm.value === undefined && plan.defaultDownloadRpmLimit !== undefined) {
      dlRpm.value = plan.defaultDownloadRpmLimit;
      dlRpm.scope = planScope;
    }
    effective.assetStorageQuotaBytes =
      effective.assetStorageQuotaBytes ?? plan.defaultAssetStorageQuotaBytes;
    effective.assetMaxObjectBytes = effective.assetMaxObjectBytes ?? plan.defaultAssetMaxObjectBytes;
  }

  effective.rpmLimit = rpm.value;
  effective.rpmLimitScope = rpm.scope;
  effective.tpmLimit = tpm.value;
  effective.tpmLimitScope = tpm.scope;
  effective.monthlyBudgetUsd = budget.value;
  effective.monthlyBudgetScope = budget.scope;
  effective.agentCostBudgetUsd = agent.value;
  effective.agentCostBudgetScope = agent.scope;
  effective.monthlyEgressBytesBudget = egress.value;
  effective.monthlyEgressBytesScope = egress.scope;
  effective.downloadRpmLimit = dlRpm.value;
  effective.downloadRpmLimitScope = dlRpm.scope;
  return effective;
}
