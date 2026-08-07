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

/** Empty both tables, so each test starts from zero rows. */
export async function resetOnlineEvalTables(): Promise<void> {
  await applyOnlineEvalMigrations();
  await controlDb().prepare(`DELETE FROM ${ONLINE_EVAL_SCORE_TABLE}`).run();
  await controlDb().prepare(`DELETE FROM ${ONLINE_EVAL_REGRESSION_TABLE}`).run();
}

/** One stored score row, read straight out of the table. */
export async function storedScores(): Promise<Record<string, unknown>[]> {
  const result = await controlDb()
    .prepare(`SELECT * FROM ${ONLINE_EVAL_SCORE_TABLE} ORDER BY criterion_id`)
    .all();
  return result.results as Record<string, unknown>[];
}

/** One stored regression row. */
export async function storedRegressions(): Promise<Record<string, unknown>[]> {
  const result = await controlDb()
    .prepare(`SELECT * FROM ${ONLINE_EVAL_REGRESSION_TABLE} ORDER BY claim_key`)
    .all();
  return result.results as Record<string, unknown>[];
}
