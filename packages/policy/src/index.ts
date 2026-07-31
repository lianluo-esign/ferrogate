/**
 * `@ferrogate/policy` — quota merge and budget preflight.
 *
 * Replaces the Rust crate `ferrogate-policy`. Pure decision logic; no I/O.
 */
import type { Identity, Scope } from "@ferrogate/core";

/** Rate/budget limits resolved from plan + tenant + key overrides. */
export interface QuotaLimits {
  rpm?: number;
  tpm?: number;
  monthlyBudgetUsd?: number;
}

/**
 * Merge two quota layers; the override wins per-field when present. Mirrors the
 * plan → tenant → key precedence of the Rust policy merge.
 */
export function mergeQuota(base: QuotaLimits, override: QuotaLimits): QuotaLimits {
  return {
    rpm: override.rpm ?? base.rpm,
    tpm: override.tpm ?? base.tpm,
    monthlyBudgetUsd: override.monthlyBudgetUsd ?? base.monthlyBudgetUsd,
  };
}

/** Outcome of a pre-request budget check. */
export interface BudgetPreflight {
  allowed: boolean;
  remainingUsd: number;
  reason?: string;
}

/** Evaluates whether an identity may proceed under its resolved quota. */
export interface PolicyEngine {
  preflight(identity: Identity, scope: Scope, estimateUsd: number): BudgetPreflight;
}
