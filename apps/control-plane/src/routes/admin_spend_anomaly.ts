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
 *
 * ## Where the episodes live, and the fence that follows from it
 *
 * The authoritative episode row is written ONLY to its tenant's own object
 * (#859/#881) — the finops pass is object-connected and the shared control
 * `spend_anomaly_episodes` copy is a retired projection that holds nothing a
 * tenant owns. So a tenant read routes to that tenant's object and an operator
 * read fans out across the object roster (bounded, `tenant_page`-paged); there
 * is no shared table to read a whole fleet from in one query. The fan-out is
 * per-object DISJOINT — see {@link fleetEpisodePage} — so it needs no dedup, and
 * the physical isolation of one object per tenant IS the fence for a whole-fleet
 * read: an operator only ever sees an episode by reading the object that owns it.
 */
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import type { CallerScope, StoreRecord } from "../ports.js";
import { adminListPaginated, parseListQuery } from "../responses.js";
import { provisionedTenantPage, tenantFanoutOffset } from "../store/tenant-fanout.js";
import { tenantEvidenceDatabaseFor } from "../store/tenancy.js";
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
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
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
 * The content filters an episode read shares on every path — status, signal,
 * severity, since — WITHOUT the tenant fence, which each path applies itself.
 *
 * `?status=open` is the incident view; `resolved` is the history. Anything else
 * is IGNORED rather than a 400 — the same judgement `admin_agent_cost_burn.ts`
 * makes about a malformed period: a report that errors on a typo is a report an
 * operator stops using. `since` is INCLUSIVE on `last_seen_unix`, so two
 * adjacent queries partition the history instead of both claiming the boundary
 * second.
 */
function episodeFilters(url: URL): { clauses: string[]; params: (string | number)[] } {
  const clauses: string[] = [];
  const params: (string | number)[] = [];

  const status = param(url, "status");
  if (status === "open") clauses.push("resolved_at_unix IS NULL");
  else if (status === "resolved") clauses.push("resolved_at_unix IS NOT NULL");

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

  const since = param(url, "since");
  const sinceUnix = since === undefined ? undefined : Number.parseInt(since, 10);
  if (sinceUnix !== undefined && Number.isSafeInteger(sinceUnix) && sinceUnix >= 0) {
    clauses.push("last_seen_unix >= ?");
    params.push(sinceUnix);
  }

  return { clauses, params };
}

/**
 * Ordered `last_seen_unix DESC, id ASC`. Newest first because an incident
 * question is asked from the present backwards; `id` as the tiebreaker is
 * load-bearing rather than tidy — `last_seen_unix` is whole seconds and one
 * pass stamps every episode it touched with the SAME second, so an unstable
 * sort inside that second lets a page boundary re-serve one episode and skip
 * another. The fleet fan-out re-sorts by this SAME key so a merged page orders
 * identically to a single-object one.
 */
const EPISODE_ORDER = "ORDER BY last_seen_unix DESC, id ASC";

/** One fenced, ordered page of episodes from a single database. */
async function readEpisodePage(
  db: D1Database,
  clauses: readonly string[],
  params: readonly (string | number)[],
  limit: number,
  offset: number,
): Promise<{ rows: EpisodeRow[]; total: number }> {
  const where = clauses.length === 0 ? "" : ` WHERE ${clauses.join(" AND ")}`;
  const result = await db
    .prepare(
      `SELECT *, count(*) OVER() AS total
         FROM ${EPISODE_TABLE}${where}
        ${EPISODE_ORDER}
        LIMIT ? OFFSET ?`,
    )
    .bind(...params, limit, offset)
    .all<EpisodeRow>();
  // `count(*) OVER()` computes the total in the SAME statement as the page, so
  // the two cannot disagree under a concurrent detector pass — and it is the
  // count of what the caller MAY see, because it is computed after the fence.
  return { rows: [...result.results], total: result.results[0]?.total ?? 0 };
}

/**
 * The fleet (platform-operator) episode page, assembled by a bounded live
 * fan-out over each provisioned tenant object — NEVER a shared control
 * `spend_anomaly_episodes` projection, which under the object cutover
 * (#859/#881) holds nothing a tenant owns.
 *
 * An episode's authoritative row lives ONLY in its tenant's object — the same
 * object the tenant-scoped read routes to — so the fleet answer is the
 * per-object pages concatenated. The objects are DISJOINT: an episode id is
 * `tenant:{scope}:{signal}:{window}` (`finops/pass.ts`), so two tenants can
 * never name the same episode, and the rows are appended rather than folded
 * through a Map — a fold would risk dropping a real episode on an id collision
 * that cannot happen but must not be assumed away.
 *
 * Bounded exactly as `billing.ts::fleetUsageAggregatePage` is: at most
 * `FLEET_FANOUT_MAX_TENANTS` objects per request, `?tenant_offset=` pages the
 * roster and `tenant_page` reports whether more remain. A fleet read on the
 * request path cannot fan out to an unbounded number of objects — that bound is
 * the whole reason a background sweep uses `provisionedTenants()` directly and
 * an operator read does not.
 */
async function fleetEpisodePage(
  router: TenantDatabaseRouter,
  filter: { readonly clauses: readonly string[]; readonly params: readonly (string | number)[] },
  query: { readonly offset: number; readonly limit: number },
  tenantOffset: number,
): Promise<{
  records: StoreRecord[];
  total: number;
  tenantPage: Awaited<ReturnType<typeof provisionedTenantPage>>;
}> {
  // Each object is paged from 0 to `offset+limit`: the merge re-slices, so a
  // per-object offset would drop rows the merged window still needs.
  const fetchLimit = Math.max(1, query.offset + query.limit);
  const tenantPage = await provisionedTenantPage(router, tenantOffset);

  const rows: EpisodeRow[] = [];
  let sourceTotal = 0;
  for (const tenantId of tenantPage.tenantIds) {
    let db: D1Database;
    try {
      db = await tenantEvidenceDatabaseFor(router, tenantId);
    } catch {
      // A tenant with no reachable object contributes nothing rather than
      // failing the whole fleet read: the detector simply never wrote it an
      // episode. Isolated exactly as the finops sweep isolates a bad object.
      continue;
    }
    const page = await readEpisodePage(db, filter.clauses, filter.params, fetchLimit, 0);
    rows.push(...page.rows);
    sourceTotal += page.total;
  }

  rows.sort((a, b) => b.last_seen_unix - a.last_seen_unix || a.id.localeCompare(b.id));
  return {
    records: rows.slice(query.offset, query.offset + query.limit).map(episodeDocument),
    // The objects are disjoint so `rows.length` and `sourceTotal` agree, but
    // `max` keeps the count honest if the per-object `fetchLimit` ever clips a
    // very active tenant's page.
    total: Math.max(rows.length, sourceTotal),
    tenantPage,
  };
}

/**
 * `GET /admin/v1/spend-anomalies`.
 *
 * Three routes to the SAME per-object query, differing only in which object(s)
 * hold the answer:
 *  - a `tenant` caller reads its OWN object, fenced to its `scope_id`;
 *  - a platform operator naming one tenant (`?scope_id=`) reads THAT object
 *    directly, so the answer does not depend on where the tenant falls in the
 *    bounded roster page;
 *  - a platform operator naming none fans out across the roster page.
 *
 * `?scope_id=` is a NARROWING, never a replacement for the fence: for a tenant
 * caller it is AND-ed with a fence that already pins `scope_id`, so asking for
 * someone else's tenant yields the empty set. A filter that REPLACED the fence
 * would be a one-parameter cross-tenant read of the most sensitive report in
 * the product — `admin_cost_record.ts` states the same rule for the same reason.
 */
function listSpendAnomaliesHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope: CallerScope = scopeOf(c);
    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    // The same router the tenant-scoped read routes through, so an operator's
    // per-tenant drill-in and a tenant's own read hit the same object.
    const router = deps.tenantStorage ?? deps.tenantDatabases;

    const filter = episodeFilters(url);
    const scopeId = param(url, "scope_id");
    if (scopeId !== undefined) {
      filter.clauses.push("scope_id = ?");
      filter.params.push(scopeId);
    }

    if (scope.kind === "tenant") {
      // Tenant scope is an authority read of the tenant's OWN object; the
      // control projection is being retired and is never a fallback here.
      const db = await tenantEvidenceDatabaseFor(router, scope.tenantId);
      const clauses = ["scope_id = ?", ...filter.clauses];
      const params = [scope.tenantId, ...filter.params];
      const page = await readEpisodePage(db, clauses, params, query.limit, query.offset);
      return json(
        c,
        200,
        adminListPaginated(page.rows.map(episodeDocument), page.total, query.offset, query.limit),
      );
    }

    if (scopeId !== undefined) {
      // Platform operator, one named tenant: read that object directly.
      let db: D1Database;
      try {
        db = await tenantEvidenceDatabaseFor(router, scopeId);
      } catch {
        // The named tenant has no reachable object — the honest answer for a
        // customer the detector never watched is an empty page, not a 503.
        return json(c, 200, adminListPaginated([], 0, query.offset, query.limit));
      }
      const page = await readEpisodePage(db, filter.clauses, filter.params, query.limit, query.offset);
      return json(
        c,
        200,
        adminListPaginated(page.rows.map(episodeDocument), page.total, query.offset, query.limit),
      );
    }

    // Platform operator, whole fleet: a bounded live fan-out over the objects.
    const fleet = await fleetEpisodePage(router, filter, query, tenantFanoutOffset(url));
    return json(c, 200, {
      ...adminListPaginated(fleet.records, fleet.total, query.offset, query.limit),
      tenant_page: {
        offset: fleet.tenantPage.offset,
        limit: fleet.tenantPage.limit,
        total: fleet.tenantPage.total,
        has_more: fleet.tenantPage.hasMore,
      },
    });
  };
}

export const adminSpendAnomalyRoutes: GroupModule = crudGroup(
  "admin_spend_anomaly",
  [readOnlyCollection("spend-anomalies", SPEND_ANOMALY_OBJECT)],
  { listAdminSpendAnomalies: listSpendAnomaliesHandler() },
);
