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
import { GUARDRAIL_CHECK_TABLE, GUARDRAIL_EVALUATION_TABLE } from "../../src/guardrails/index.js";
import { REQUEST_LOG_TABLE, requestLogPlatformDatabaseFrom } from "../../src/requestlog/index.js";

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

/**
 * The control schema is applied by `test/setup-d1.ts`, which runs before
 * every test file and hands the ENTIRE `sql/d1-ts/control/` directory to
 * `applyD1Migrations` — the same name-bookkept application `wrangler d1
 * migrations apply` performs in production.
 *
 * This function used to hand-apply a curated subset with per-column guards,
 * and that shape rotted twice over: the global setup's own subset missed
 * `0012` (the `storage_backend` column the tenancy resolver reads on every
 * authenticated request), and once the global setup went full-directory this
 * harness's blind re-apply of `0002`'s ALTER failed every caller with
 * `duplicate column name: nonce`. Kept as an exported no-op so the many
 * suites that call it before their resets need no edit; there is exactly one
 * schema applier now, and it is not here.
 */
export async function applyControlMigrations(): Promise<void> {}

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

/**
 * The PLATFORM_DATA singleton's `request_logs` rows (Zero-D1 Plan B), read
 * through the SAME facade the production write path uses
 * (`requestLogPlatformDatabaseFrom`). The whole table IS the platform domain, so
 * there is no tenant fence — every row here is unattributed by construction and
 * its `tenant` column is NULL.
 */
export async function storedPlatformRequestLogs(): Promise<StoredRequestLog[]> {
  const db = requestLogPlatformDatabaseFrom(env);
  if (db === undefined) {
    // Loud, never a silent skip: PLATFORM_DATA is declared in `wrangler.toml`, so
    // an absent one means the platform-object leg cannot be under test at all.
    throw new Error(
      "request-log platform tests expect the `PLATFORM_DATA` binding (apps/gateway/wrangler.toml).",
    );
  }
  const result = (await db
    .prepare(`SELECT * FROM ${REQUEST_LOG_TABLE} ORDER BY started_at_unix ASC, request_id ASC`)
    .bind()
    .all()) as { results: StoredRequestLog[] };
  return result.results;
}

/** Empty the platform object's `request_logs`, so each test starts from zero. */
export async function resetPlatformRequestLogs(): Promise<void> {
  const db = requestLogPlatformDatabaseFrom(env);
  if (db === undefined) return;
  await db.prepare(`DELETE FROM ${REQUEST_LOG_TABLE}`).bind().run();
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
