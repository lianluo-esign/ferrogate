/**
 * Contract group `admin_agent_cost_burn` (1 operation) —
 * `GET /admin/v1/agent-cost-burn`, the durable accumulated cost burn per agent.
 *
 * `admin.read`, tenant-scoped, read-only. Clean-room port of
 * `crates/ferrogate-gateway/src/server/agent_cost_burn.rs`.
 */
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { periodMonthFromUnix } from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope, ControlPlaneDeps, StoreRecord } from "../ports.js";
import { adminListPaginated, parseListQuery } from "../responses.js";
import { fanOutProvisionedTenants } from "../store/tenant-fanout.js";
import { tenantDatabaseFor } from "../store/tenancy.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

/**
 * Rust `is_period_month`: four digits, a dash, and a month in `01..=12`.
 *
 * The Rust enumerates the twelve literals rather than range-checking, so
 * `2001-13` and `2001-00` are NOT periods — and a caller passing one gets the
 * current month rather than an empty list that would read as "this agent spent
 * nothing in month thirteen".
 */
function isPeriodMonth(value: string): boolean {
  if (!/^\d{4}-\d{2}$/.test(value)) return false;
  const month = Number.parseInt(value.slice(5), 10);
  return month >= 1 && month <= 12;
}

/**
 * Rust `resolve_agent_cost_burn_period`: an explicit, well-formed
 * `?period=YYYY-MM` wins; anything else — absent, blank, or garbage — falls back
 * to the current UTC billing month, derived by the SAME helper the usage
 * rollups use (`@ferrogate/storage`'s `periodMonthFromUnix`) so the report and
 * the accumulator cannot disagree about which month a row belongs to.
 *
 * Deliberately NOT a 400: Rust keeps the surface usable without a param, and a
 * report that errors on a typo is a report an operator stops using.
 */
export function resolveBurnPeriod(raw: string | null, nowUnixSeconds: number): string {
  const trimmed = raw?.trim() ?? "";
  return isPeriodMonth(trimmed) ? trimmed : periodMonthFromUnix(nowUnixSeconds);
}

interface BurnRow {
  readonly tenant_id: string;
  readonly agent_key: string;
  readonly period: string;
  readonly accumulated_usd: number;
  readonly updated_at_unix: number;
}

/**
 * Rust `AgentCostBurnRow::from_stored` — five fields.
 *
 * `first_seen_unix` is internal bookkeeping and is deliberately NOT surfaced;
 * putting a second, differently-meaning timestamp on a money report is how a
 * dashboard ends up plotting the wrong one.
 */
function burnDocument(row: BurnRow): StoreRecord {
  return {
    id: `${row.tenant_id}:${row.agent_key}:${row.period}`,
    tenant_id: row.tenant_id,
    agent_key: row.agent_key,
    period: row.period,
    accumulated_usd: row.accumulated_usd,
    updated_at_unix: row.updated_at_unix,
  };
}

/**
 * The raw per-agent SELECT out of one object's `agent_cost_burn` table.
 *
 * Shared by the tenant-fenced read (which wraps a failure as `503`) and the
 * platform fan-out (whose per-object isolation turns a single failing object
 * into `[]` rather than failing the whole fleet). `WHERE tenant_id = ?` is kept
 * even though a tenant object holds only its own rows: it is the same predicate
 * the accumulator writes under, and it makes a mis-routed read return nothing
 * instead of another tenant's burn.
 */
async function selectBurnRows(
  db: D1Database,
  tenantId: string,
  period: string,
): Promise<BurnRow[]> {
  const rows = await db
    .prepare(
      `SELECT tenant_id, agent_key, period, accumulated_usd, updated_at_unix
         FROM agent_cost_burn
        WHERE tenant_id = ? AND period = ?`,
    )
    .bind(tenantId, period)
    .all<BurnRow>();
  return [...rows.results];
}

/**
 * Read one tenant database's burn rows for `period`.
 *
 * A D1 failure is re-raised as `503 service_unavailable`, never swallowed into
 * an empty array. `agent_cost_burn.rs`'s header states the rule and the reason:
 * *"A durable-store failure degrades to an explicit `service_unavailable`, never
 * a fabricated empty list (which would read as 'no burn')."*
 */
async function burnRowsFor(
  deps: ControlPlaneDeps,
  tenantId: string,
  period: string,
): Promise<BurnRow[]> {
  // Throws `503 tenant_database_unavailable` when the tenant HAS a provisioned
  // database this deployment cannot reach, and answers `null` when it has none
  // at all — see `store/tenancy.ts` for why collapsing those two is wrong.
  const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantId);
  if (handle === null) return [];

  try {
    return await selectBurnRows(handle.db, tenantId, period);
  } catch (error) {
    throw new HttpError(
      503,
      "service_unavailable",
      `agent cost-burn surface unavailable: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/**
 * `GET /admin/v1/agent-cost-burn`.
 *
 * ## Why this is not the generic list handler
 *
 * It used to be, and that was the defect the wave-15 certification recorded:
 * the generic handler paged an `agent-cost-burn` DOCUMENT collection that has
 * no writer, while the real accumulator is the TENANT database's typed
 * `agent_cost_burn` table (`packages/storage/src/d1/monotonic.ts`'s
 * `accumulateAgentCostBurn`). The operation answered an empty list on every
 * deployment while the burn it reports on was being recorded elsewhere.
 *
 * That is a MONEY surface, not a cosmetic one: `accumulated_usd` is what
 * `quota_policies.agent_cost_budget_usd` is compared against, so an operator
 * reading zero burn concludes an agent is not spending.
 *
 * ## Isolation happens BEFORE pagination
 *
 * Rust says so explicitly and the reason is that the alternative leaks: window
 * first and filter after, and a tenant's page can come back empty while its
 * rows exist, with `total` counting rows the caller may not see.
 */
function listAgentCostBurnHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope: CallerScope = scopeOf(c);
    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    const period = resolveBurnPeriod(url.searchParams.get("period"), Math.floor(Date.now() / 1000));

    const rows: BurnRow[] = [];
    let metadata: { readonly source: string; readonly as_of_unix: number } | undefined;
    if (scope.kind === "tenant") {
      rows.push(...(await burnRowsFor(deps, scope.tenantId, period)));
    } else {
      // The platform view is the LIVE fold of every tenant object's own
      // `agent_cost_burn` — no longer a control-D1 projection. The burn is
      // tenant-private authority; mirroring it into the shared control object
      // was the red-line this slice removes. `fanOutProvisionedTenants` reads
      // each provisioned object concurrently and, per-object isolation, an
      // unreachable one contributes `[]` rather than failing the fleet read.
      const router: TenantDatabaseRouter = deps.tenantStorage ?? deps.tenantDatabases;
      rows.push(
        ...(await fanOutProvisionedTenants(
          router,
          (db, tenantId) => selectBurnRows(db, tenantId, period),
          "agent-cost-burn",
        )),
      );
    }
    metadata = {
      source: "tenant_authority",
      as_of_unix: Math.floor(Date.now() / 1000),
    };

    // Rust's storage layer returns "biggest accumulated total first"; the
    // fan-out has to re-establish that across databases, and `agent_key` is the
    // tiebreaker so two agents with identical spend do not swap places between
    // two reads of the same page.
    rows.sort(
      (a, b) => b.accumulated_usd - a.accumulated_usd || a.agent_key.localeCompare(b.agent_key),
    );

    const windowed = rows.slice(query.offset, query.offset + query.limit);
    const list = adminListPaginated(
      windowed.map(burnDocument),
      rows.length,
      query.offset,
      query.limit,
    );
    return json(c, 200, metadata === undefined ? list : { ...list, ...metadata });
  };
}

export const adminAgentCostBurnRoutes: GroupModule = crudGroup(
  "admin_agent_cost_burn",
  [readOnlyCollection("agent-cost-burn", "agent_cost_burn")],
  { listAdminAgentCostBurn: listAgentCostBurnHandler() },
);
