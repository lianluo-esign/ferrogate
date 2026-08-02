/**
 * The REAL `CONTROL_DB` binding with the REAL `0009_online_eval.sql` applied,
 * for the online-evaluation suite.
 *
 * Same posture as `test/requestlog/harness.ts`: the schema is the DEPLOYED
 * migration read with Vite's `?raw`, never a fixture copy, so a column rename in
 * the migration breaks these tests instead of letting them pass against a
 * private schema no account has.
 *
 * `0009` is MIXED — seven non-idempotent `ALTER TABLE … ADD COLUMN`s on
 * `quota_policies` plus idempotent `CREATE TABLE IF NOT EXISTS`es — and the pool
 * PERSISTS this database under `.wrangler/state` between runs, so the alters get
 * a column-presence guard for exactly the reason `0003` needs one there: a blind
 * re-apply fails the second `vitest run` with "duplicate column name" and every
 * assertion after it reads as a code bug.
 */
import { env } from "cloudflare:test";
import onlineEvalSql from "../../../../sql/d1-ts/control/0009_online_eval.sql?raw";
import { ONLINE_EVAL_REGRESSION_TABLE, ONLINE_EVAL_SCORE_TABLE } from "../../src/evals/index.js";
import { applyControlMigrations } from "../requestlog/harness.js";

function sqlStatements(migration: string): string[] {
  return migration
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

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

let applied = false;

export async function applyOnlineEvalMigrations(): Promise<void> {
  if (applied) return;
  // The EARLIER control migrations come from the request-log harness rather
  // than being re-listed here. `test/evals/mount.test.ts` drives `gatewayQueue`,
  // which routes request-log messages too, so this suite needs `request_logs`
  // to have its `0003` decision columns — and two harnesses applying two
  // different subsets of the same migration set is how one suite comes to pass
  // against a schema the other cannot produce.
  await applyControlMigrations();
  const db = controlDb();
  const columns = await db.prepare("PRAGMA table_info(quota_policies)").all();
  const names = new Set(
    (columns.results as { name?: unknown }[]).map((row) => String(row.name ?? "")),
  );
  const statements = sqlStatements(onlineEvalSql).filter(
    (statement) =>
      !(names.has("online_eval_enabled") && statement.startsWith("ALTER TABLE quota_policies")),
  );
  for (const statement of statements) {
    await db.prepare(statement).run();
  }
  applied = true;
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
