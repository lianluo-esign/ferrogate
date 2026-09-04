/**
 * The REAL `CONTROL_DB` binding for the online-evaluation suite.
 *
 * The schema — `0009_online_eval.sql` included — is the DEPLOYED directory,
 * applied whole by `test/setup-d1.ts` via `applyD1Migrations` before every
 * test file. This harness only locates the binding and resets rows.
 */
import { env } from "cloudflare:test";
import { ONLINE_EVAL_REGRESSION_TABLE, ONLINE_EVAL_SCORE_TABLE } from "../../src/evals/index.js";
import { applyControlMigrations } from "../requestlog/harness.js";
import { tenantObjectDb } from "../tenant-object.js";

/** The live `env.CONTROL_DB` binding. */
export function controlDb(): D1Database {
  const binding = (env as unknown as { CONTROL_DB?: D1Database }).CONTROL_DB;
  if (binding === undefined) {
    // Loud, never a silent skip: the binding is declared in `wrangler.toml`, so
    // an absent one means the declaration was removed and this suite is about
    // to prove something other than what it claims.
    throw new Error(
      "online-eval tests expect the `CONTROL_DB` D1 binding (apps/gateway/wrangler.toml).",
    );
  }
  return binding;
}

/**
 * The full control schema — `0009_online_eval.sql` included — is applied by
 * `test/setup-d1.ts` (`applyD1Migrations` over the whole directory) before
 * every test file. Kept as an exported no-op so callers need no edit; the
 * subset-applier it used to be is exactly the shape that rotted (see
 * `../requestlog/harness.ts`).
 */
export async function applyOnlineEvalMigrations(): Promise<void> {
  await applyControlMigrations();
}

/**
 * Apply the control schema; each test resets its OWN tenant objects.
 *
 * There is nothing to reset on the control side any more: the
 * `online_eval_scores` projection was DROPPED by control migration 0043 (a score
 * is tenant data and lives only in its owning object; production runs the queue
 * consumer with `projectToControl: false`), and the `online_eval_regressions`
 * mirror was DROPPED earlier by 0036. Deleting from either now would hit
 * `no such table`. Kept as an exported async no-op-over-migrations so callers
 * need no edit.
 */
export async function resetOnlineEvalTables(): Promise<void> {
  await applyOnlineEvalMigrations();
}

/**
 * Stored score rows read from the TENANT object that owns them — the
 * authoritative destination the deployed consumer writes to now that the
 * control projection is no longer mirrored (`projectToControl: false`).
 */
export async function storedTenantScores(
  tenantId: string,
): Promise<Record<string, unknown>[]> {
  const result = await tenantObjectDb(tenantId)
    .prepare(`SELECT * FROM ${ONLINE_EVAL_SCORE_TABLE} ORDER BY criterion_id`)
    .all();
  return result.results as Record<string, unknown>[];
}

/**
 * One stored regression row, read from the TENANT object that owns it — the
 * only place a regression claim is ever written (no control mirror exists).
 */
export async function storedRegressions(tenantId = "tenant_a"): Promise<Record<string, unknown>[]> {
  const result = await tenantObjectDb(tenantId)
    .prepare(`SELECT * FROM ${ONLINE_EVAL_REGRESSION_TABLE} ORDER BY claim_key`)
    .all();
  return result.results as Record<string, unknown>[];
}
