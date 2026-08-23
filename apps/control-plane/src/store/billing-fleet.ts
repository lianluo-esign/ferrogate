/**
 * The cross-tenant billing fleet view (#956 read side).
 *
 * Per-transaction cost is authoritative in each tenant's own Durable Object and
 * read one tenant at a time; a CROSS-tenant question ("top spenders this month",
 * "fleet billed by model") has no fan-out shortcut and tenant billing is never
 * projected into the control database. The gateway therefore DUAL-WRITES one
 * Analytics Engine data point per priced event (`apps/gateway/src/metering/
 * billing-analytics.ts`), and this module answers a fleet question with ONE
 * cross-tenant SQL aggregate over that dataset.
 *
 * The AE **write** side is a Worker binding; the **read** side is the
 * account-scoped `/analytics_engine/sql` REST endpoint (`adapters.ts` holds the
 * production adapter and the account token). It has NO offline emulation —
 * `wrangler dev --local` / vitest-pool-workers accept `writeDataPoint` and
 * discard it, and there is nothing to query back — so everything HTTP lives
 * behind {@link BillingFleetQueryPort} and the two pure pieces here
 * ({@link buildFleetSql}, {@link mapFleetRows}) carry the logic that can be
 * proven offline. The real round-trip is exercised live.
 *
 * AE samples, so every aggregate is corrected by `_sample_interval`
 * (`SUM(value * _sample_interval)`), and the report is flagged `sampled: true`.
 */

/** The dimension a fleet report groups by → the AE blob column it lives in. */
export const FLEET_GROUP_BY_COLUMN = {
  tenant: "blob1",
  project: "blob2",
  logical_model: "blob3",
  provider: "blob4",
  billing_group: "blob5",
  provider_model: "blob6",
} as const;

export type FleetGroupBy = keyof typeof FLEET_GROUP_BY_COLUMN;

export const FLEET_GROUP_BY_VALUES = Object.keys(FLEET_GROUP_BY_COLUMN) as readonly FleetGroupBy[];

export const DEFAULT_FLEET_LIMIT = 20;
export const MAX_FLEET_LIMIT = 100;

/** A validated fleet query. All fields are already range-checked by the route. */
export interface FleetQuery {
  readonly groupBy: FleetGroupBy;
  /** Inclusive lower bound, unix seconds. */
  readonly sinceUnix: number;
  /** Exclusive upper bound, unix seconds. */
  readonly untilUnix: number;
  readonly limit: number;
}

/** One aggregated row of the fleet report. */
export interface FleetReportRow {
  readonly key: string;
  readonly offer_usd: number;
  readonly final_usd: number;
  readonly provider_cost_usd: number;
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly events: number;
}

export interface FleetReport {
  readonly object: "billing_fleet_report";
  readonly group_by: FleetGroupBy;
  readonly since_unix: number;
  readonly until_unix: number;
  /** AE aggregates are sample-corrected estimates, never exact invoices. */
  readonly sampled: true;
  readonly rows: readonly FleetReportRow[];
}

/**
 * The HTTP seam. `runSql` returns the raw `data` array from the AE SQL REST
 * response, or throws {@link BillingFleetUnavailableError} when the account
 * query surface cannot be reached — the route maps that to a 503, never a 500.
 */
export interface BillingFleetQueryPort {
  runSql(sql: string): Promise<readonly Record<string, unknown>[]>;
}

export class BillingFleetUnavailableError extends Error {}

/**
 * What the route depends on: a dataset-bound query service. `null` in the deps
 * when the account query surface is unconfigured (no account id / token), which
 * the route reports as a 503 rather than an empty report that reads as "no
 * spend".
 */
export interface BillingFleetService {
  report(query: FleetQuery): Promise<FleetReport>;
}

/** An AE dataset name is a bare identifier and cannot be parameterized. */
const DATASET_NAME = /^[A-Za-z0-9_]+$/;

/**
 * Build the cross-tenant aggregate SQL.
 *
 * Every interpolated value is trusted: `dataset` is deploy config (validated as
 * an identifier), the grouped column is a whitelisted constant (never user
 * text), and the bounds + limit are integers the route already validated — so
 * there is no injection surface even though the AE SQL REST API takes raw text
 * rather than bound parameters.
 */
export function buildFleetSql(dataset: string, query: FleetQuery): string {
  if (!DATASET_NAME.test(dataset)) {
    throw new Error(`invalid Analytics Engine dataset name: ${dataset}`);
  }
  const column = FLEET_GROUP_BY_COLUMN[query.groupBy];
  const since = Math.trunc(query.sinceUnix);
  const until = Math.trunc(query.untilUnix);
  const limit = Math.trunc(query.limit);
  return [
    `SELECT ${column} AS key,`,
    "       SUM(double1 * _sample_interval) AS offer_usd,",
    "       SUM(double2 * _sample_interval) AS final_usd,",
    "       SUM(double6 * _sample_interval) AS provider_cost_usd,",
    "       SUM(double4 * _sample_interval) AS prompt_tokens,",
    "       SUM(double5 * _sample_interval) AS completion_tokens,",
    "       SUM(_sample_interval) AS events",
    `  FROM ${dataset}`,
    ` WHERE timestamp >= toDateTime(${since}) AND timestamp < toDateTime(${until})`,
    " GROUP BY key",
    " ORDER BY final_usd DESC",
    ` LIMIT ${limit}`,
  ].join("\n");
}

function numberField(row: Record<string, unknown>, key: string): number {
  const value = row[key];
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

/** Map the raw AE `data` rows onto the report shape, dropping nothing. */
export function mapFleetRows(rows: readonly Record<string, unknown>[]): FleetReportRow[] {
  return rows.map((row) => ({
    key: typeof row.key === "string" ? row.key : String(row.key ?? ""),
    offer_usd: numberField(row, "offer_usd"),
    final_usd: numberField(row, "final_usd"),
    provider_cost_usd: numberField(row, "provider_cost_usd"),
    prompt_tokens: numberField(row, "prompt_tokens"),
    completion_tokens: numberField(row, "completion_tokens"),
    events: numberField(row, "events"),
  }));
}

/** Run one fleet report through the injected query port. */
export async function runFleetReport(
  port: BillingFleetQueryPort,
  dataset: string,
  query: FleetQuery,
): Promise<FleetReport> {
  const rows = await port.runSql(buildFleetSql(dataset, query));
  return {
    object: "billing_fleet_report",
    group_by: query.groupBy,
    since_unix: query.sinceUnix,
    until_unix: query.untilUnix,
    sampled: true,
    rows: mapFleetRows(rows),
  };
}
