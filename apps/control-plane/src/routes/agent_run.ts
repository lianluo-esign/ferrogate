/**
 * Contract group `agent_run` — this app's 3 read-only slices of it.
 *
 * ```
 *   GET /admin/v1/agent-runs
 *   GET /admin/v1/agent-runs/{run_id}         run timeline
 *   GET /admin/v1/self-hosted-runs/{run_id}   self-hosted run timeline
 * ```
 *
 * The rest of the `agent_run` group (`/v1/agent-jobs/**`, `/v1/agents/**`,
 * `/.well-known/agent.json`) belongs to `apps/agent-runtime`; `contract.ts`
 * filters it out, and `crudGroup` is handed only the operations this Worker
 * owns, so there is no way to accidentally register a data-plane route here.
 *
 * Both `{run_id}` operations are TIMELINES — an ordered event list for one
 * run — not a row read, which is why they are sub-lists rather than the derived
 * `readHandler`. The distinction matters for `agent_run_id` correlation: the
 * timeline is the join key's evidence trail.
 */
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
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
  pathParam,
  readOnlyCollection,
  scopeOf,
  subListHandler,
} from "./resource.js";

/**
 * PORT-TODO(P: inventory-edge-control §agent-worker) — the run authority is the
 * `apps/agent-runtime` `AgentRunState` Durable Object keyed
 * `${tenant_id}:${run_id}`, projected into each tenant's OWN evidence database.
 * The control schema's `agent_runs` / `agent_run_events` tables were derived
 * cross-tenant compatibility projections; mirroring tenant data into the shared
 * control store is the red line #859/#881 closed, so NEITHER the LIST nor the
 * `{run_id}` TIMELINE reads them: a tenant-scoped read hits the exact object, a
 * platform operator's LIST is a bounded roster fan-out (`fleetAgentRunPage`,
 * mirroring `admin_spend_anomaly.ts`), and the TIMELINE for an operator naming no
 * tenant is a whole-roster fan-out (`findRunOwners`) that preserves the 409
 * `ambiguous_agent_run_id` collision contract by reporting when more than one
 * object owns the id.
 *
 * The `self-hosted-runs` timeline still routes through the generic sub-list
 * reader (`subListHandler`) against the control store — a separate follow-up.
 */

const AGENT_RUN_COLUMNS = "id, request_id, tenant, started_at_unix, completed_at_unix, run_json";
const AGENT_RUN_EVENT_COLUMNS = "id, run_id, request_id, tenant, occurred_at_unix, event_json";

function documentOf(raw: unknown): Record<string, unknown> {
  if (typeof raw !== "string") return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function runDocument(row: Record<string, unknown>): StoreRecord {
  const { run_json: raw, ...columns } = row;
  // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
  delete columns.total;
  return {
    ...documentOf(raw),
    ...columns,
    object: "agent_run",
    id: String(columns.id ?? ""),
  };
}

function eventDocument(row: Record<string, unknown>): StoreRecord {
  const { event_json: raw, ...columns } = row;
  // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
  delete columns.total;
  return {
    ...documentOf(raw),
    ...columns,
    object: "agent_run_event",
    id: String(columns.id ?? ""),
  };
}

function notFound(object: string, id: string): HttpError {
  return new HttpError(404, "not_found", `${object} ${id} not found`);
}

async function agentRunPage(
  db: D1Database,
  scope: CallerScope,
  limit: number,
  offset: number,
): Promise<{ rows: Record<string, unknown>[]; total: number }> {
  const tenant = scope.kind === "tenant" ? " WHERE tenant = ?" : "";
  const params = scope.kind === "tenant" ? [scope.tenantId] : [];
  const result = await db
    .prepare(
      `SELECT ${AGENT_RUN_COLUMNS}, count(*) OVER() AS total
         FROM agent_runs${tenant}
        ORDER BY started_at_unix ASC, id ASC
        LIMIT ? OFFSET ?`,
    )
    .bind(...params, limit, offset)
    .all<Record<string, unknown> & { total?: number }>();
  return { rows: result.results, total: result.results[0]?.total ?? 0 };
}

async function tenantAgentRunPage(
  router: TenantDatabaseRouter,
  tenantId: string,
  limit: number,
  offset: number,
): Promise<{ rows: Record<string, unknown>[]; total: number }> {
  return agentRunPage(
    await tenantEvidenceDatabaseFor(router, tenantId),
    { kind: "tenant", tenantId },
    limit,
    offset,
  );
}

/**
 * A platform operator's fleet page: a bounded live fan-out over the tenant
 * objects that OWN the runs, mirroring `admin_spend_anomaly.ts::fleetEpisodePage`
 * exactly. The authoritative run row lives ONLY in its tenant's object (its
 * `AgentRunState` DO, projected into that tenant's evidence database); the
 * control `agent_runs` projection (#859/#881) held nothing a tenant owns and is
 * retired here. The objects are DISJOINT — a run id is scoped per tenant — so
 * the per-object pages are appended and re-sorted rather than folded.
 *
 * Bounded exactly as the spend-anomaly fleet read: at most
 * `FLEET_FANOUT_MAX_TENANTS` objects per request, `?tenant_offset=` pages the
 * roster and the returned `tenantPage` reports whether more remain.
 */
async function fleetAgentRunPage(
  router: TenantDatabaseRouter,
  query: { readonly offset: number; readonly limit: number },
  tenantOffset: number,
): Promise<{
  rows: Record<string, unknown>[];
  total: number;
  tenantPage: Awaited<ReturnType<typeof provisionedTenantPage>>;
}> {
  // Each object is paged from 0 to `offset+limit`: the merge re-slices, so a
  // per-object offset would drop rows the merged window still needs.
  const fetchLimit = Math.max(1, query.offset + query.limit);
  const tenantPage = await provisionedTenantPage(router, tenantOffset);

  const rows: Record<string, unknown>[] = [];
  let sourceTotal = 0;
  for (const tenantId of tenantPage.tenantIds) {
    let db: D1Database;
    try {
      db = await tenantEvidenceDatabaseFor(router, tenantId);
    } catch {
      // A tenant with no reachable object contributes nothing rather than
      // failing the whole fleet read — isolated exactly as the finops sweep
      // isolates a bad object.
      continue;
    }
    const page = await agentRunPage(db, { kind: "tenant", tenantId }, fetchLimit, 0);
    rows.push(...page.rows);
    sourceTotal += page.total;
  }

  // Re-sort on the same key the per-object page uses (`started_at_unix ASC,
  // id ASC`) so the merged window is stable across `tenant_offset` pages.
  rows.sort(
    (a, b) =>
      Number(a.started_at_unix ?? 0) - Number(b.started_at_unix ?? 0) ||
      String(a.id ?? "").localeCompare(String(b.id ?? "")),
  );
  return {
    rows: rows.slice(query.offset, query.offset + query.limit),
    // Disjoint objects mean `rows.length` and `sourceTotal` agree, but `max`
    // keeps the count honest if a very active tenant's per-object page clips.
    total: Math.max(rows.length, sourceTotal),
    tenantPage,
  };
}

function listAgentRunsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    // The same router the tenant-scoped read routes through, so an operator's
    // fleet page and a tenant's own read hit the same objects.
    const router = deps.tenantStorage ?? deps.tenantDatabases;

    if (scope.kind === "tenant") {
      // A tenant's own object is the authority; the control projection is
      // retired and never a fallback here.
      const page = await tenantAgentRunPage(router, scope.tenantId, query.limit, query.offset);
      return json(
        c,
        200,
        adminListPaginated(page.rows.map(runDocument), page.total, query.offset, query.limit),
      );
    }

    // Platform operator: a bounded live fan-out over the tenant objects that own
    // the runs. The control `agent_runs` projection (#859/#881) is retired and
    // is never read here — the fleet answer is the per-object pages merged.
    const fleet = await fleetAgentRunPage(router, query, tenantFanoutOffset(url));
    return json(c, 200, {
      ...adminListPaginated(fleet.rows.map(runDocument), fleet.total, query.offset, query.limit),
      tenant_page: {
        offset: fleet.tenantPage.offset,
        limit: fleet.tenantPage.limit,
        total: fleet.tenantPage.total,
        has_more: fleet.tenantPage.hasMore,
      },
    });
  };
}

/**
 * The tenant objects that own a run id, found by a whole-roster live fan-out.
 *
 * A run id is unique only WITHIN a tenant (its `AgentRunState` object is keyed
 * `${tenant_id}:${run_id}`), so a platform operator naming no tenant cannot know
 * which object holds it — or whether more than one does — without asking every
 * object. Each check is a single indexed point lookup on the `agent_runs` primary
 * key, and the scan STOPS as soon as a second owner appears, so the ambiguous
 * case never fans out past the collision it reports. An unreachable object
 * contributes nothing rather than failing the read, exactly as `fleetAgentRunPage`
 * and the finops sweep isolate a bad object. This is the last reader of the
 * retired cross-tenant control `agent_runs` projection (#859/#881) in this file.
 */
async function findRunOwners(
  router: TenantDatabaseRouter,
  runId: string,
): Promise<{ tenantId: string; db: D1Database }[]> {
  const owners: { tenantId: string; db: D1Database }[] = [];
  for (const tenantId of [...(await router.provisionedTenants())].sort()) {
    let db: D1Database;
    try {
      db = await tenantEvidenceDatabaseFor(router, tenantId);
    } catch {
      continue;
    }
    const run = await db
      .prepare("SELECT id FROM agent_runs WHERE id = ? AND tenant = ?")
      .bind(runId, tenantId)
      .first<Record<string, unknown>>();
    if (run !== null) {
      owners.push({ tenantId, db });
      if (owners.length > 1) break; // already ambiguous — stop scanning the roster
    }
  }
  return owners;
}

function agentRunTimelineHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const runId = pathParam(c, "run_id");
    const url = new URL(c.req.url);
    const requestedTenantId =
      scope.kind === "platform_operator"
        ? url.searchParams.get("tenant_id")?.trim() || null
        : null;
    const selectedTenantId = scope.kind === "tenant" ? scope.tenantId : requestedTenantId;
    // The same router the tenant-scoped read and the operator LIST route through,
    // so every timeline path reads the exact objects the list paged over.
    const router = deps.tenantStorage ?? deps.tenantDatabases;

    let db: D1Database;
    let eventTenant: string;
    if (selectedTenantId !== null) {
      // A tenant, or an operator naming one: the run lives in that exact object.
      db = await tenantEvidenceDatabaseFor(router, selectedTenantId);
      const run = await db
        .prepare("SELECT id FROM agent_runs WHERE id = ? AND tenant = ?")
        .bind(runId, selectedTenantId)
        .first<Record<string, unknown>>();
      if (run === null) throw notFound("agent_run", runId);
      eventTenant = selectedTenantId;
    } else {
      // A platform operator naming NO tenant: a whole-roster live fan-out. More
      // than one owning object is the documented 409 collision; the caller
      // resolves it by naming a `tenant_id` (the branch above).
      const owners = await findRunOwners(router, runId);
      if (owners.length > 1) {
        throw new HttpError(
          409,
          "ambiguous_agent_run_id",
          `agent_run ${runId} belongs to multiple tenants; tenant_id is required`,
        );
      }
      const owner = owners[0];
      if (owner === undefined) throw notFound("agent_run", runId);
      db = owner.db;
      eventTenant = owner.tenantId;
    }

    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    // Agent runs are always tenant-owned (the `AgentRunState` DO is keyed
    // `${tenant_id}:${run_id}`), so events are fenced to the owning tenant — there
    // is no NULL-tenant control-projection branch any more.
    const events = await db
      .prepare(
        `SELECT ${AGENT_RUN_EVENT_COLUMNS}, count(*) OVER() AS total
           FROM agent_run_events
          WHERE run_id = ? AND tenant = ?
          ORDER BY occurred_at_unix ASC, id ASC
          LIMIT ? OFFSET ?`,
      )
      .bind(runId, eventTenant, query.limit, query.offset)
      .all<Record<string, unknown> & { total?: number }>();
    return json(
      c,
      200,
      adminListPaginated(
        events.results.map(eventDocument),
        events.results[0]?.total ?? 0,
        query.offset,
        query.limit,
      ),
    );
  };
}

export const agentRunRoutes: GroupModule = crudGroup(
  "agent_run",
  [readOnlyCollection("agent-runs", "agent_run")],
  {
    listAdminAgentRuns: listAgentRunsHandler(),
    getAdminAgentRunTimeline: agentRunTimelineHandler(),

    getAdminSelfHostedRunTimeline: subListHandler({
      parent: { segment: "self-hosted-runs", object: "self_hosted_run" },
      parentParam: "run_id",
      collection: "self-hosted-run-events",
      parentField: "run_id",
    }),
  },
);
