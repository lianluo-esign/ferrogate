/**
 * The Cron leg of batch execution (#698, slice 2) — the recovery floor.
 *
 * `[triggers] crons = ["* * * * *"]` already fires every minute for the
 * billing-outbox sweep, so this needs no new trigger. It exists because the
 * queue is a best-effort accelerator and three things it cannot cover are all
 * routine:
 *
 *  - a batch created in a deployment with no `BATCH_JOBS` binding (the enqueue
 *    is a no-op by design, not an error);
 *  - a job whose consumer invocation died mid-tick — the lease expires and
 *    nothing re-sends the message;
 *  - a NATIVE job, which must be polled until the provider finishes and would
 *    otherwise need the consumer to re-enqueue itself once a minute forever.
 *
 * ## The fan-out shape is `assets/retention.ts`'s, deliberately
 *
 * Per-tenant `try`/`catch`, `console.warn` on failure, never throws. One
 * tenant's unreachable database must not stop the fleet's sweep, and a batch
 * sweep must never be able to fail the same Cron tick the billing-outbox
 * recovery runs on.
 */
import type { BatchExecutorDeps, BatchTickResult } from "./executor.js";
import { runTenantBatchTicks } from "./executor.js";

/** Jobs one tenant may have advanced per tick. */
export const DEFAULT_BATCH_SWEEP_PER_TENANT = 5;

export interface BatchSweepBindings {
  /**
   * `GATEWAY_BATCH_SWEEP_LIMIT` — jobs per tenant per Cron tick. Absent or not
   * a positive integer ⇒ {@link DEFAULT_BATCH_SWEEP_PER_TENANT}; a bad value is
   * IGNORED rather than applied, because a `0` would silently disable the
   * recovery path for every tenant.
   */
  readonly GATEWAY_BATCH_SWEEP_LIMIT?: string | undefined;
}

/** {@link BatchSweepBindings.GATEWAY_BATCH_SWEEP_LIMIT}, validated. */
export function batchSweepLimitFromEnv(env: unknown): number {
  const raw = (env as BatchSweepBindings | null)?.GATEWAY_BATCH_SWEEP_LIMIT;
  if (typeof raw !== "string" || raw.trim() === "") return DEFAULT_BATCH_SWEEP_PER_TENANT;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) return DEFAULT_BATCH_SWEEP_PER_TENANT;
  return parsed;
}

/**
 * Advance every tenant's claimable batches. NEVER throws.
 *
 * `tenantIds` comes from the same `provisionedTenants()` the other sweeps on
 * this tick use, so a deployment with no tenant registry sweeps nothing rather
 * than guessing at a shared database.
 */
export async function sweepBatchExecution(
  env: unknown,
  tenantIds: readonly string[],
  deps: BatchExecutorDeps = {},
): Promise<readonly BatchTickResult[]> {
  const limit = batchSweepLimitFromEnv(env);
  const out: BatchTickResult[] = [];
  for (const tenantId of tenantIds) {
    if (tenantId.trim() === "") continue;
    try {
      out.push(...(await runTenantBatchTicks(env, tenantId, limit, deps)));
    } catch (error) {
      console.warn(
        `[ferrogate] batch sweep skipped tenant ${tenantId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  return out;
}
