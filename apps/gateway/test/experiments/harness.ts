/**
 * The REAL `CONTROL_DB` binding with the REAL migration set, for the experiment
 * suite (#693).
 *
 * The migrations themselves are applied by `test/requestlog/harness.ts`, which
 * now runs the whole committed control set: `0010` adds `experiment_id` /
 * `experiment_arm` to `request_logs`, so a request-log harness that stopped
 * short of it would fail every insert. Delegating rather than copying is what
 * keeps this suite and the request-log suite reading the SAME schema — two
 * harnesses applying overlapping migration prefixes is how two suites end up
 * agreeing about a row that neither production nor the other one has.
 */
import { EXPERIMENT_SHADOW_LEG_TABLE } from "../../src/experiments/index.js";
import { REQUEST_LOG_TABLE } from "../../src/requestlog/index.js";
import { applyControlMigrations, controlDb } from "../requestlog/harness.js";
import { tenantObjectDb } from "../tenant-object.js";

export { applyControlMigrations, controlDb };

/** One stored `request_logs` row, narrowed to the experiment columns. */
export interface StoredExperimentRequestLog {
  readonly request_id: string;
  readonly tenant: string | null;
  readonly logical_model: string | null;
  readonly provider: string | null;
  readonly provider_model: string | null;
  readonly status_code: number | null;
  readonly latency_ms: number | null;
  readonly experiment_id: string | null;
  readonly experiment_arm: string | null;
}

/** One stored `experiment_shadow_legs` row. */
export interface StoredShadowLeg {
  readonly leg_id: string;
  readonly client_request_id: string;
  readonly experiment_id: string;
  readonly tenant: string;
  readonly project: string | null;
  readonly logical_model: string;
  readonly provider: string;
  readonly provider_model: string;
  readonly status_code: number | null;
  readonly error_code: string | null;
  readonly latency_ms: number | null;
  readonly prompt_tokens: number | null;
  readonly completion_tokens: number | null;
  readonly total_tokens: number | null;
  readonly cost_usd: number | null;
  readonly observed_at_unix: number;
}

/**
 * The tenant objects the experiment suites write shadow legs to now that the
 * control projection is no longer mirrored (`projectToControl: false`). Cleared
 * on reset so each test starts from zero rows in the AUTHORITATIVE store — the
 * control mirror alone no longer bounds a suite's visible legs.
 */
const SHADOW_LEG_TEST_TENANTS = ["tenant_a", "tenant_optin"] as const;

export async function resetExperimentTables(): Promise<void> {
  await applyControlMigrations();
  await controlDb().prepare(`DELETE FROM ${REQUEST_LOG_TABLE}`).run();
  await controlDb().prepare(`DELETE FROM ${EXPERIMENT_SHADOW_LEG_TABLE}`).run();
  for (const tenantId of SHADOW_LEG_TEST_TENANTS) {
    await tenantObjectDb(tenantId).prepare(`DELETE FROM ${EXPERIMENT_SHADOW_LEG_TABLE}`).run();
  }
}

export async function storedRequestLogs(): Promise<StoredExperimentRequestLog[]> {
  const result = await controlDb()
    .prepare(`SELECT * FROM ${REQUEST_LOG_TABLE} ORDER BY started_at_unix ASC, request_id ASC`)
    .all<StoredExperimentRequestLog>();
  return result.results;
}

export async function storedShadowLegs(): Promise<StoredShadowLeg[]> {
  const result = await controlDb()
    .prepare(
      `SELECT * FROM ${EXPERIMENT_SHADOW_LEG_TABLE} ORDER BY observed_at_unix ASC, leg_id ASC`,
    )
    .all<StoredShadowLeg>();
  return result.results;
}

/**
 * Shadow legs read from the TENANT object that owns them — the authoritative
 * destination the deployed producer writes to now that the control projection is
 * no longer mirrored (`projectToControl: false`).
 */
export async function storedTenantShadowLegs(tenantId: string): Promise<StoredShadowLeg[]> {
  const result = await tenantObjectDb(tenantId)
    .prepare(
      `SELECT * FROM ${EXPERIMENT_SHADOW_LEG_TABLE} ORDER BY observed_at_unix ASC, leg_id ASC`,
    )
    .all<StoredShadowLeg>();
  return result.results;
}
