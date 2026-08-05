/**
 * The REAL `CONTROL_DB` binding, with the REAL control migration applied, for
 * the request-log suite.
 *
 * `apps/gateway/wrangler.toml` declares `[[d1_databases]] binding =
 * "CONTROL_DB"`, so `@cloudflare/vitest-pool-workers` provisions a real local
 * SQLite for it and every statement `writeRequestLogs` issues is executed by
 * the same engine production runs. Nothing here doubles the database.
 *
 * The schema applied is the DEPLOYED migration set, read with Vite's `?raw` —
 * never a fixture copy — for the reason `test/metering/d1-harness.ts` gives:
 * a column rename in the migration must break this suite rather than let it
 * pass against a private schema the account does not have. `0003` is where the
 * decision columns live, so it is applied here too and applying it is what
 * makes this suite and `apps/control-plane/test/request-logs-read.test.ts`
 * agree about the row.
 */
import { env } from "cloudflare:test";
import controlInitSql from "../../../../sql/d1-ts/control/0001_init_control.sql?raw";
import ssoNonceSql from "../../../../sql/d1-ts/control/0002_sso_flow_nonce.sql?raw";
import requestLogColumnsSql from "../../../../sql/d1-ts/control/0003_request_log_columns.sql?raw";
import guardrailEvidenceSql from "../../../../sql/d1-ts/control/0004_guardrail_evaluations.sql?raw";
import delegationChainSql from "../../../../sql/d1-ts/control/0008_delegation_chain.sql?raw";
import onlineEvalSql from "../../../../sql/d1-ts/control/0009_online_eval.sql?raw";
import experimentOutcomesSql from "../../../../sql/d1-ts/control/0011_experiment_outcomes.sql?raw";
import evidenceProjectionKeysSql from "../../../../sql/d1-ts/control/0014_tenant_evidence_projection_keys.sql?raw";
import guardrailProjectionKeysSql from "../../../../sql/d1-ts/control/0015_guardrail_evidence_projection_keys.sql?raw";
import { GUARDRAIL_CHECK_TABLE, GUARDRAIL_EVALUATION_TABLE } from "../../src/guardrails/index.js";
import { REQUEST_LOG_TABLE } from "../../src/requestlog/index.js";

/** Split a `.sql` migration into executable statements (comments stripped). */
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
      "request-log tests expect the `CONTROL_DB` D1 binding (apps/gateway/wrangler.toml).",
    );
  }
  return binding;
}

let applied = false;

/**
 * Apply the deployed control migrations once per isolate.
 *
 * `0003` is `ALTER TABLE … ADD COLUMN`, which is NOT idempotent, and the pool
 * PERSISTS the database under `.wrangler/state` between runs — so a blind
 * re-apply fails with "duplicate column name" on the second `vitest run` and
 * every assertion after it reads as a code bug. The presence of one of the new
 * columns is therefore checked first, which is the same question the migration
 * bookkeeping would answer if `applyD1Migrations` were usable for a
 * hand-applied set.
 */
export async function applyControlMigrations(): Promise<void> {
  if (applied) return;
  const db = controlDb();
  for (const statement of [...sqlStatements(controlInitSql), ...sqlStatements(ssoNonceSql)]) {
    await db.prepare(statement).run();
  }

  const columns = await db.prepare(`PRAGMA table_info(${REQUEST_LOG_TABLE})`).all();
  const names = new Set(
    (columns.results as { name?: unknown }[]).map((row) => String(row.name ?? "")),
  );
  if (!names.has("latency_ms")) {
    for (const statement of sqlStatements(requestLogColumnsSql)) {
      await db.prepare(statement).run();
    }
  }

  // `0004` is `CREATE TABLE IF NOT EXISTS` throughout, so unlike `0003` it is
  // idempotent and needs no guard (#665).
  for (const statement of sqlStatements(guardrailEvidenceSql)) {
    await db.prepare(statement).run();
  }

  // `0008` (#691) is MIXED: `CREATE TABLE IF NOT EXISTS` is idempotent but its
  // two `ALTER TABLE … ADD COLUMN`s are not, so it gets the same
  // column-presence guard `0003` gets, for the same reason — the pool persists
  // this database under `.wrangler/state`, and a blind re-apply fails the
  // second `vitest run` with "duplicate column name".
  if (!names.has("delegation_chain")) {
    for (const statement of sqlStatements(delegationChainSql)) {
      await db.prepare(statement).run();
    }
  }

  // `0009` (#692) and `0010` (#693) are applied here even though neither is a
  // request-log migration, and the reason is `0010`: it adds
  // `request_logs.experiment_id` / `.experiment_arm`, which `REQUEST_LOG_UPSERT_SQL`
  // now writes on EVERY row. A harness that stopped at `0008` would fail every
  // insert with "no such column" — so the request-log suite's schema is the
  // whole committed set from here on, not a prefix of it.
  //
  // Order is load-bearing: `0010` alters `online_eval_scores`, which `0009`
  // creates. Both get the same column-presence guard the alters above get,
  // because the pool PERSISTS this database under `.wrangler/state` and a blind
  // re-apply fails the second `vitest run` with "duplicate column name".
  const quotaColumns = await db.prepare("PRAGMA table_info(quota_policies)").all();
  const quotaNames = new Set(
    (quotaColumns.results as { name?: unknown }[]).map((row) => String(row.name ?? "")),
  );
  for (const statement of sqlStatements(onlineEvalSql)) {
    if (quotaNames.has("online_eval_enabled") && statement.startsWith("ALTER TABLE")) continue;
    await db.prepare(statement).run();
  }
  if (!names.has("experiment_arm")) {
    for (const statement of sqlStatements(experimentOutcomesSql)) {
      await db.prepare(statement).run();
    }
  }
  if (!names.has("projection_key")) {
    for (const statement of sqlStatements(evidenceProjectionKeysSql)) {
      await db.prepare(statement).run();
    }
  }
  const guardrailColumns = await db
    .prepare(`PRAGMA table_info(${GUARDRAIL_EVALUATION_TABLE})`)
    .all();
  const guardrailNames = new Set(
    (guardrailColumns.results as { name?: unknown }[]).map((row) => String(row.name ?? "")),
  );
  if (!guardrailNames.has("projection_key")) {
    for (const statement of sqlStatements(guardrailProjectionKeysSql)) {
      await db.prepare(statement).run();
    }
  }
  applied = true;
}

/** Empty `request_logs`, so each test starts from zero rows. */
export async function resetRequestLogs(): Promise<void> {
  await applyControlMigrations();
  await controlDb().prepare(`DELETE FROM ${REQUEST_LOG_TABLE}`).run();
}

/**
 * Empty the guardrail evidence tables (#665).
 *
 * Children first: `guardrail_check_evaluations.evaluation_id` is a foreign key,
 * so deleting parents first fails on a database with enforcement on.
 */
export async function resetGuardrailEvidence(): Promise<void> {
  await applyControlMigrations();
  await controlDb().prepare(`DELETE FROM ${GUARDRAIL_CHECK_TABLE}`).run();
  await controlDb().prepare(`DELETE FROM ${GUARDRAIL_EVALUATION_TABLE}`).run();
}

/** One stored `guardrail_evaluations` row, read straight out of the table. */
export interface StoredGuardrailEvaluation {
  readonly id: string;
  readonly request_id: string;
  readonly trace_id: string | null;
  readonly agent_run_id: string | null;
  readonly subject_id: string | null;
  readonly tenant: string | null;
  readonly scope_type: string;
  readonly scope_id: string | null;
  readonly target: string;
  readonly protocol: string;
  readonly stage: string;
  readonly mode: string;
  readonly policy_id: string;
  readonly policy_revision: number;
  readonly verdict: string;
  readonly action: string;
  readonly enforcement_status: string;
  readonly latency_ms: number;
  readonly finding_count: number;
  readonly input_fingerprint: string;
  readonly action_fingerprint: string | null;
  readonly occurred_at_unix: number;
  readonly evaluation_json: string;
}

/** One stored `guardrail_check_evaluations` row. */
export interface StoredGuardrailCheck {
  readonly id: string;
  readonly evaluation_id: string;
  readonly check_id: string;
  readonly detector_id: string;
  readonly detector_version: string;
  readonly config_digest: string;
  readonly verdict: string;
  readonly action: string;
  readonly enforcement_status: string;
  readonly error_kind: string | null;
  readonly check_json: string;
}

/** Every stored evaluation, oldest first. */
export async function storedGuardrailEvaluations(): Promise<StoredGuardrailEvaluation[]> {
  const result = await controlDb()
    .prepare(`SELECT * FROM ${GUARDRAIL_EVALUATION_TABLE} ORDER BY occurred_at_unix ASC, id ASC`)
    .all<StoredGuardrailEvaluation>();
  return result.results;
}

/** Every stored check row, by evaluation then check. */
export async function storedGuardrailChecks(): Promise<StoredGuardrailCheck[]> {
  const result = await controlDb()
    .prepare(`SELECT * FROM ${GUARDRAIL_CHECK_TABLE} ORDER BY evaluation_id ASC, check_id ASC`)
    .all<StoredGuardrailCheck>();
  return result.results;
}

/** One stored row, read straight out of the table. */
export interface StoredRequestLog {
  readonly request_id: string;
  readonly tenant: string | null;
  readonly project: string | null;
  readonly api_key_id: string | null;
  readonly route: string | null;
  readonly provider: string | null;
  readonly logical_model: string | null;
  readonly provider_model: string | null;
  readonly status_code: number | null;
  readonly error_code: string | null;
  readonly latency_ms: number | null;
  readonly prompt_tokens: number | null;
  readonly completion_tokens: number | null;
  readonly total_tokens: number | null;
  readonly guardrail_verdict: string | null;
  readonly guardrail_policy_id: string | null;
  readonly streamed: number;
  readonly started_at_unix: number;
  readonly completed_at_unix: number | null;
  readonly request_json: string;
}

/** Every stored row, oldest first. */
export async function storedRequestLogs(): Promise<StoredRequestLog[]> {
  const result = await controlDb()
    .prepare(`SELECT * FROM ${REQUEST_LOG_TABLE} ORDER BY started_at_unix ASC, request_id ASC`)
    .all<StoredRequestLog>();
  return result.results;
}

/** A Queue producer double that records what was sent, and can be told to fail. */
export class RecordingQueue {
  readonly sent: unknown[] = [];
  #failure: Error | undefined;

  async send(body: unknown): Promise<void> {
    if (this.#failure !== undefined) throw this.#failure;
    this.sent.push(body);
  }

  async sendBatch(messages: Iterable<{ body: unknown }>): Promise<void> {
    if (this.#failure !== undefined) throw this.#failure;
    for (const message of messages) this.sent.push(message.body);
  }

  /** Simulate an unavailable queue: every `send` rejects. */
  fail(reason = "queue unavailable"): void {
    this.#failure = new Error(reason);
  }
}
