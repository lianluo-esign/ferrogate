/**
 * Quota policies + usage-monthly rollups (ports `QuotaScopeKind`,
 * `StoredQuotaPolicy`, `validate_quota_policy`, `StoredUsageMonthlyRollup`,
 * `OverviewUsageTotals` from `ferrogate-storage::lib`).
 *
 * NOTE: the effective-quota MERGE (`resolve_effective_quota`,
 * key→workspace→project→plan, clamp-to-ancestor, allowlist-intersection,
 * cost-min-across-chain) lives in `ferrogate-policy` in the Rust tree, so it is
 * ported in `@ferrogate/policy`, NOT here. This module owns the persisted policy
 * row, its validation invariant, and its deterministic id.
 */
import { z } from "zod";
import { StorageError } from "./errors.js";

/** The four scope levels a quota policy can attach to. */
export type QuotaScopeKind = "tenant" | "project" | "workspace" | "key";

export const QUOTA_SCOPE_KINDS: readonly QuotaScopeKind[] = [
  "tenant",
  "project",
  "workspace",
  "key",
];

/** Parse a raw `scope_type` column value; `undefined` for an unknown token. */
export function quotaScopeKindFromString(value: string): QuotaScopeKind | undefined {
  return (QUOTA_SCOPE_KINDS as readonly string[]).includes(value)
    ? (value as QuotaScopeKind)
    : undefined;
}

/**
 * A quota/rate-limit policy attached to one scope. Zod validates the wire/DB row
 * shape that serde + the Rust type system gave for free.
 */
export const storedQuotaPolicySchema = z.object({
  id: z.string(),
  scopeType: z.enum(["tenant", "project", "workspace", "key"]),
  scopeId: z.string(),
  modelAllowlist: z.array(z.string()).default([]),
  rpmLimit: z.number().int().nonnegative().optional(),
  tpmLimit: z.number().int().nonnegative().optional(),
  monthlyBudgetUsd: z.number().optional(),
  /** Tenant-only cumulative asset-storage byte ceiling. */
  assetStorageQuotaBytes: z.number().int().nonnegative().optional(),
  /** Tenant-only per-object asset byte ceiling (#259). */
  assetMaxObjectBytes: z.number().int().nonnegative().optional(),
  /** CF-hosted-agent monthly USD ceiling, min-merged at any scope (#428). */
  agentCostBudgetUsd: z.number().optional(),
  /** Percent-of-budget alert tiers, e.g. [75, 90, 95] (#170). */
  alertThresholdPcts: z.array(z.number().int()).default([]),
  enabled: z.boolean().default(true),
  createdAtUnix: z.number().int().default(0),
  updatedAtUnix: z.number().int().default(0),
  /** Monthly egress byte budget, min-merged across the chain (#262). */
  monthlyEgressBytesBudget: z.number().int().nonnegative().optional(),
  /** Per-minute asset-download request cap (#262). */
  downloadRpmLimit: z.number().int().nonnegative().optional(),
});

export type StoredQuotaPolicy = z.infer<typeof storedQuotaPolicySchema>;

/**
 * Enforce the tenant-only invariant on the two asset byte ceilings
 * (ports `validate_quota_policy`): stored assets and their usage are
 * tenant-owned, so a narrower scope may not carry these overrides.
 * Throws {@link StorageError} `runtime` on violation.
 */
export function validateQuotaPolicy(policy: StoredQuotaPolicy): void {
  if (policy.scopeType !== "tenant" && policy.assetStorageQuotaBytes !== undefined) {
    throw StorageError.runtime(
      "asset_storage_quota_bytes is tenant-only because stored assets and usage are tenant-owned",
    );
  }
  if (policy.scopeType !== "tenant" && policy.assetMaxObjectBytes !== undefined) {
    throw StorageError.runtime(
      "asset_max_object_bytes is tenant-only because stored assets and usage are tenant-owned",
    );
  }
}

/** Per-scope, per-calendar-month usage/cost rollup row. */
export interface StoredUsageMonthlyRollup {
  id: string;
  /** `YYYY-MM`, UTC. */
  periodMonth: string;
  scopeType: QuotaScopeKind;
  scopeId: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
  requestCount: number;
  errorCount: number;
  updatedAtUnix: number;
}

/**
 * Aggregated token/cost/request/error totals for one window in the control-plane
 * overview (#339). `accumulate` folds a rollup row in; summed only over
 * `scope_type = tenant` rows by the caller so the per-scope fan-out can never
 * double-count a request.
 */
export interface OverviewUsageTotals {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
  requestCount: number;
  errorCount: number;
}

export function emptyOverviewUsageTotals(): OverviewUsageTotals {
  return {
    promptTokens: 0,
    completionTokens: 0,
    totalTokens: 0,
    costUsd: 0,
    requestCount: 0,
    errorCount: 0,
  };
}

export function accumulateOverviewUsage(
  totals: OverviewUsageTotals,
  rollup: StoredUsageMonthlyRollup,
): void {
  totals.promptTokens += rollup.promptTokens;
  totals.completionTokens += rollup.completionTokens;
  totals.totalTokens += rollup.totalTokens;
  totals.costUsd += rollup.costUsd;
  totals.requestCount += rollup.requestCount;
  totals.errorCount += rollup.errorCount;
}
