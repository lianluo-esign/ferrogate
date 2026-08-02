/**
 * Contract group `admin_spend_anomaly` (1 operation) —
 * `GET /admin/v1/spend-anomalies`, the burn-rate episode ledger (#697).
 *
 * `admin.read`, tenant-scoped, read-only.
 *
 * ## Why this operation exists at all when there is a webhook
 *
 * Three questions the webhook cannot answer, each of which an operator asks
 * within a day of the first page:
 *
 *  1. **"What is firing right now?"** A channel is a log of things that HAPPENED;
 *     `?status=open` is the current state, which is what an incident starts from.
 *  2. **"Why did this fire?"** Every episode carries `baseline_usd`,
 *     `threshold_usd` and `bound_by`, so the decision is reconstructable from
 *     the row. A detector whose reasoning cannot be inspected is one nobody can
 *     tune, and an untunable detector gets muted.
 *  3. **"What did my receiver drop?"** `notified_count = 0` on an episode is
 *     exactly the set of alerts that were detected and never delivered. There
 *     is no retry (`finops/notify.ts` says why), so without this surface those
 *     are simply gone.
 *
 * ## The fence
 *
 * `scope_id` on a `tenant`-scoped episode IS the tenant id, so the fence is a
 * strict equality on it — the same shape `admin_cost_record.ts` uses and for
 * the same reason. An episode names a customer and how much they are spending
 * per hour, which is a competitive-intelligence leak, not merely a privacy one.
 *
 * The fence is applied BEFORE pagination. Window first and filter after, and a
 * tenant's page can come back empty while its rows exist, with `total` counting
 * rows the caller may not see.
 */
import type { CallerScope, StoreRecord } from "../ports.js";
import { adminListPaginated, parseListQuery } from "../responses.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

const SPEND_ANOMALY_OBJECT = "spend_anomaly";
const EPISODE_TABLE = "spend_anomaly_episodes";

interface EpisodeRow {
  readonly id: string;
  readonly scope_type: string;
  readonly scope_id: string;
  readonly signal: string;
  readonly severity: string;
  readonly peak_severity: string;
  readonly window_start_unix: number;
  readonly window_secs: number;
  readonly opened_at_unix: number;
  readonly last_seen_unix: number;
  readonly resolved_at_unix: number | null;
  readonly windows_seen: number;
  readonly notified_count: number;
  readonly last_notified_unix: number | null;
  readonly observed_usd: number;
  readonly baseline_usd: number | null;
  readonly threshold_usd: number | null;
  readonly bound_by: string | null;
  readonly baseline_windows: number | null;
  readonly active_windows: number | null;
  readonly projected_usd: number | null;
  readonly budget_usd: number | null;
  readonly period_month: string | null;
  readonly detail_json: string | null;
  readonly total?: number;
}

/** The stored detail map, or `{}` when there is none or it does not parse. */
function detailOf(raw: string | null): Record<string, unknown> {
  if (raw === null) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

/**
 * Project one episode onto the wire.
 *
 * `status` is derived rather than stored, because "open" is exactly
 * `resolved_at_unix IS NULL` and a second column asserting the same fact is a
 * column that can disagree with it.
 */
function episodeDocument(row: EpisodeRow): StoreRecord {
  return {
    object: SPEND_ANOMALY_OBJECT,
    id: row.id,
    status: row.resolved_at_unix === null ? "open" : "resolved",
    scope_type: row.scope_type,
    scope_id: row.scope_id,
    signal: row.signal,
    severity: row.severity,
    peak_severity: row.peak_severity,
    window_start_unix: row.window_start_unix,
    window_secs: row.window_secs,
    opened_at_unix: row.opened_at_unix,
    last_seen_unix: row.last_seen_unix,
    resolved_at_unix: row.resolved_at_unix,
    windows_seen: row.windows_seen,
    // The gap between `windows_seen` and `notified_count` is the whole point of
    // the episode model: an incident that ran for seven windows and paged twice
    // is working as designed, and the two numbers say so side by side.
    notified_count: row.notified_count,
    last_notified_unix: row.last_notified_unix,
    observed_usd: row.observed_usd,
    baseline_usd: row.baseline_usd,
    threshold_usd: row.threshold_usd,
    bound_by: row.bound_by,
    baseline_windows: row.baseline_windows,
    active_windows: row.active_windows,
    projected_usd: row.projected_usd,
    budget_usd: row.budget_usd,
    period_month: row.period_month,
    detail: detailOf(row.detail_json),
  };
}

/** A trimmed, non-empty query parameter, or `undefined`. */
function param(url: URL, name: string): string | undefined {
  const value = url.searchParams.get(name)?.trim() ?? "";
  return value === "" ? undefined : value;
}

/**
 * `GET /admin/v1/spend-anomalies`.
 *
 * Ordered `last_seen_unix DESC, id ASC`. Newest first because an incident
 * question is asked from the present backwards; `id` as the tiebreaker is
 * load-bearing rather than tidy — `last_seen_unix` is whole seconds and one
 * pass stamps every episode it touched with the SAME second, so an unstable
 * sort inside that second lets a page boundary re-serve one episode and skip
 * another.
 */
function listSpendAnomaliesHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope: CallerScope = scopeOf(c);
    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    const db = deps.controlDatabase;

    if (db === null) {
      // No control database means the detector never ran and the table does not
      // exist. An empty page is the truthful answer, and it is the answer every
      // sibling evidence reader gives.
      return json(c, 200, adminListPaginated([], 0, query.offset, query.limit));
    }

    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (scope.kind !== "platform_operator") {
      clauses.push("scope_id = ?");
      params.push(scope.tenantId);
    }

    // `?status=open` is the incident view; `resolved` is the history. Anything
    // else is IGNORED rather than a 400 — the same judgement
    // `admin_agent_cost_burn.ts` makes about a malformed period: a report that
    // errors on a typo is a report an operator stops using.
    const status = param(url, "status");
    if (status === "open") clauses.push("resolved_at_unix IS NULL");
    else if (status === "resolved") clauses.push("resolved_at_unix IS NOT NULL");

    // `?scope_id=` is a NARROWING, never a replacement for the fence. For a
    // platform operator it selects one tenant; for a tenant caller it is
    // AND-ed with a fence that already pins `scope_id`, so asking for someone
    // else's tenant yields the empty set. A filter that REPLACED the fence
    // would be a one-parameter cross-tenant read of the most sensitive report
    // in the product — `admin_cost_record.ts::costFilters` states the same rule
    // for the same reason.
    const scopeId = param(url, "scope_id");
    if (scopeId !== undefined) {
      clauses.push("scope_id = ?");
      params.push(scopeId);
    }

    const signal = param(url, "signal");
    if (signal !== undefined) {
      clauses.push("signal = ?");
      params.push(signal);
    }

    const severity = param(url, "severity");
    if (severity !== undefined) {
      clauses.push("severity = ?");
      params.push(severity);
    }

    // `since` INCLUSIVE, on `last_seen_unix`, so two adjacent queries partition
    // the history instead of both claiming the boundary second.
    const since = param(url, "since");
    const sinceUnix = since === undefined ? undefined : Number.parseInt(since, 10);
    if (sinceUnix !== undefined && Number.isSafeInteger(sinceUnix) && sinceUnix >= 0) {
      clauses.push("last_seen_unix >= ?");
      params.push(sinceUnix);
    }

    const where = clauses.length === 0 ? "" : ` WHERE ${clauses.join(" AND ")}`;
    const result = await db
      .prepare(
        `SELECT *, count(*) OVER() AS total
           FROM ${EPISODE_TABLE}${where}
          ORDER BY last_seen_unix DESC, id ASC
          LIMIT ? OFFSET ?`,
      )
      .bind(...params, query.limit, query.offset)
      .all<EpisodeRow>();

    // `count(*) OVER()` computes the total in the SAME statement as the page, so
    // the two cannot disagree under a concurrent detector pass — and it is the
    // count of what the caller MAY see, because it is computed after the fence.
    const total = result.results[0]?.total ?? 0;
    return json(
      c,
      200,
      adminListPaginated(
        result.results.map(episodeDocument),
        total,
        query.offset,
        query.limit,
      ),
    );
  };
}

export const adminSpendAnomalyRoutes: GroupModule = crudGroup(
  "admin_spend_anomaly",
  [readOnlyCollection("spend-anomalies", SPEND_ANOMALY_OBJECT)],
  { listAdminSpendAnomalies: listSpendAnomaliesHandler() },
);
