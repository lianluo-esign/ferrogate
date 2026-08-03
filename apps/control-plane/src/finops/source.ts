/**
 * The spend substrate the detector reads (#697) — #677's join, bucketed.
 *
 * ## Why the join and not a new counter
 *
 * `admin_cost_record.ts` states the rule this file obeys: a THIRD durable
 * figure for the same money is a figure that can DISAGREE with `billing_ledger`,
 * and the day it does, an operator has two numbers and no way to tell which one
 * billed the customer. So there is no `spend_rate` table and no new writer. The
 * cost of every window here is
 * `SUM(billing_events.event_json -> cost_usd)` — the same documents
 * `D1LedgerStore.record` wrote in the same batch as the `billing_ledger` row,
 * grouped by hour instead of by request.
 *
 * A detector that alerted on a number the invoice does not agree with would be
 * the worst possible version of this feature.
 *
 * ## The fence direction, which is the same one #677 argues
 *
 * `billing_events` has NO tenant column — its rows are keyed by `request_id`,
 * because the metering path identifies a charge by its provider attempt. So the
 * query is DRIVEN by `request_logs`, whose `tenant` carries the authenticated
 * tenant, and `billing_events` is reached only through the join. A tenant is
 * attributed spend only for requests its own authenticated calls produced.
 *
 * The cost of driving from that side is the same one #677 accepts and states:
 * a `billing_events` row whose `request_logs` row has aged past the retention
 * horizon contributes nothing. The detector therefore UNDER-observes an old
 * window rather than attributing a charge to nobody — which for a rate detector
 * means the baseline can only be too low (making it more sensitive) or the
 * observed window too low (making it quieter). Both are visible; neither
 * fabricates spend.
 *
 * ## Two queries for the whole fleet, not two per tenant
 *
 * Both statements below are `GROUP BY tenant`, so a pass costs a fixed two
 * round trips no matter how many tenants exist. That is what makes it
 * affordable to watch every tenant by default rather than making the feature
 * opt-in — see the migration's note on `spend_anomaly_enabled`.
 *
 * `idx_request_logs_tenant_started` (`0003_request_log_columns.sql`) is the
 * index both of them drive from.
 */
import { BILLING_EVENT_TABLE, REQUEST_LOG_TABLE } from "../store/d1.js";

/**
 * The priced cost of one request, guarded exactly as #677's aggregate is.
 *
 * `json_extract` RAISES on malformed JSON, so one corrupt `event_json` row
 * would take the whole detection pass down — which would silently stop the
 * fleet's spend monitoring on account of a single bad row. Guarded, a corrupt
 * row contributes nothing, and the pass keeps watching everyone else.
 *
 * A row with no `cost_usd` (#663: metered, nothing could price it) also
 * contributes nothing. `SUM` over an all-NULL group is NULL, which the reader
 * below turns into `0` for a WINDOW — and that is the one place the two
 * surfaces differ on purpose: #677 keeps NULL because a chargeback line must
 * not claim a request was free, while a rate detector needs a number and the
 * only honest number for "unpriced" is "no observed spend". It makes the
 * detector quieter, never louder.
 */
const COST_EXPRESSION = `SUM(CASE WHEN json_valid(be.event_json)
                                  THEN COALESCE(json_extract(be.event_json, '$.cost_usd'), 0)
                                  ELSE 0 END)`;

/** One (tenant, window) bucket of priced spend. */
export interface SpendBucketRow {
  readonly tenant: string;
  readonly bucket: number;
  readonly cost_usd: number | null;
  readonly requests: number;
}

/**
 * Priced spend per tenant per window over `[fromUnix, toUnix)`.
 *
 * The bucket is `started_at_unix / windowSecs` floored, so buckets are anchored
 * on the EPOCH rather than on `now` — two consecutive passes therefore agree
 * about which hour a request belongs to, which a `now`-relative bucketing would
 * not.
 *
 * The `CAST(... AS INTEGER)` is load-bearing and was a live bug before it was
 * there: D1 binds a JS `number` as SQLite REAL, so `started_at_unix / ?` is
 * FLOATING-POINT division and every request lands in a bucket of its own. The
 * detector then sees a baseline of thousands of near-zero windows and never
 * fires — a detector that is silent for the exact reason it was bought. Casting
 * truncates toward zero, which for a positive unix second is the floor.
 *
 * Attribution is by the request's START, not by `billing_events.occurred_at_unix`.
 * A long-running streamed request is one decision by one caller, and splitting
 * its cost across the windows it happened to straddle would make the RATE
 * depend on how long the provider took to answer.
 */
export async function readSpendBuckets(
  db: D1Database,
  fromUnix: number,
  toUnix: number,
  windowSecs: number,
): Promise<SpendBucketRow[]> {
  const rows = await db
    .prepare(
      `SELECT rl.tenant AS tenant,
              CAST(rl.started_at_unix / ? AS INTEGER) AS bucket,
              ${COST_EXPRESSION} AS cost_usd,
              COUNT(DISTINCT rl.request_id) AS requests
         FROM ${REQUEST_LOG_TABLE} rl
         JOIN ${BILLING_EVENT_TABLE} be ON be.request_id = rl.request_id
        WHERE rl.tenant IS NOT NULL
          AND rl.started_at_unix >= ?
          AND rl.started_at_unix < ?
        GROUP BY rl.tenant, bucket`,
    )
    .bind(windowSecs, fromUnix, toUnix)
    .all<SpendBucketRow>();
  return [...rows.results];
}

/** Month-to-date priced spend per tenant. */
export interface PeriodSpendRow {
  readonly tenant: string;
  readonly cost_usd: number | null;
}

/**
 * Priced spend per tenant over `[periodStartUnix, toUnix)` — the forecast leg's
 * month-to-date figure.
 *
 * Read from the SAME join as the windows rather than from
 * `usage_monthly_rollups`, even though the rollup already holds a monthly
 * total. Two reasons, and the second is the important one:
 *
 *  - the rollup lives in the TENANT database (`store/tenancy.ts`), so using it
 *    would turn a two-query fleet pass into a fan-out of one round trip per
 *    provisioned tenant;
 *  - the projection is `periodSpend + observed * remainingWindows`, and if
 *    those two terms came from different sources they could disagree about
 *    whether a given request is counted — which would make the forecast wrong
 *    by exactly the amount of the disagreement, invisibly.
 */
export async function readPeriodSpend(
  db: D1Database,
  periodStartUnix: number,
  toUnix: number,
): Promise<PeriodSpendRow[]> {
  const rows = await db
    .prepare(
      `SELECT rl.tenant AS tenant, ${COST_EXPRESSION} AS cost_usd
         FROM ${REQUEST_LOG_TABLE} rl
         JOIN ${BILLING_EVENT_TABLE} be ON be.request_id = rl.request_id
        WHERE rl.tenant IS NOT NULL
          AND rl.started_at_unix >= ?
          AND rl.started_at_unix < ?
        GROUP BY rl.tenant`,
    )
    .bind(periodStartUnix, toUnix)
    .all<PeriodSpendRow>();
  return [...rows.results];
}
