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

/**
 * The tenant objects the experiment-family suites attribute request logs to now
 * that the control `request_logs` mirror was DROPPED by control migration 0045
 * (Track A): `attribution.test.ts` runs as `tenant_a`, `routing-decision-log.
 * test.ts` as `tenant_cq`. Every request these suites make is authenticated, so
 * every row is tenant-attributed and lands in its OWNER's object — never the
 * platform singleton — via the same by-name routing the production sink uses
 * (`requestLogTenantDatabaseFrom`, which does not consult the roster). Cleared
 * on reset and fanned over on read so a suite sees exactly its own rows.
 */
const REQUEST_LOG_TEST_TENANTS = ["tenant_a", "tenant_optin", "tenant_cq"] as const;

export async function resetExperimentTables(): Promise<void> {
  await applyControlMigrations();
  // The control `request_logs` mirror was DROPPED by control migration 0045
  // (Track A) and the control `experiment_shadow_legs` projection by 0043 — both
  // are tenant-object authoritative now, so only the owning tenant objects are
  // cleared here.
  for (const tenantId of SHADOW_LEG_TEST_TENANTS) {
    await tenantObjectDb(tenantId).prepare(`DELETE FROM ${EXPERIMENT_SHADOW_LEG_TABLE}`).run();
  }
  for (const tenantId of REQUEST_LOG_TEST_TENANTS) {
    await tenantObjectDb(tenantId).prepare(`DELETE FROM ${REQUEST_LOG_TABLE}`).run();
  }
}

/**
 * Every stored `request_logs` row across the experiment-family tenant objects,
 * oldest first. The control mirror is gone (0045); a row served for a tenant is
 * authoritative in that tenant's object, so this fans out over the suites'
 * tenants and merges. Callers still key on the request id they alone control, so
 * a foreign tenant's row can neither be counted nor read in place of it.
 */
export async function storedRequestLogs(): Promise<StoredExperimentRequestLog[]> {
  const perTenant = await Promise.all(
    REQUEST_LOG_TEST_TENANTS.map((tenantId) =>
      tenantObjectDb(tenantId)
        .prepare(`SELECT * FROM ${REQUEST_LOG_TABLE} ORDER BY started_at_unix ASC, request_id ASC`)
        .all<StoredExperimentRequestLog & { readonly started_at_unix: number }>()
        .then((result) => result.results),
    ),
  );
  return perTenant
    .flat()
    .sort(
      (a, b) =>
        (a as { started_at_unix: number }).started_at_unix -
          (b as { started_at_unix: number }).started_at_unix ||
        a.request_id.localeCompare(b.request_id),
    );
}

/**
 * Shadow legs read from the TENANT object that owns them — the authoritative
 * (and only) destination now that the control projection was DROPPED by control
 * migration 0043.
 */
export async function storedTenantShadowLegs(tenantId: string): Promise<StoredShadowLeg[]> {
  const result = await tenantObjectDb(tenantId)
    .prepare(
      `SELECT * FROM ${EXPERIMENT_SHADOW_LEG_TABLE} ORDER BY observed_at_unix ASC, leg_id ASC`,
    )
    .all<StoredShadowLeg>();
  return result.results;
}
