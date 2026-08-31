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
import {
  adminListPaginated,
  adminListPaginatedWithMetadata,
  derivedControlProjectionMetadata,
  parseListQuery,
} from "../responses.js";
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
 * PORT-TODO(P: inventory-edge-control §agent-worker) — these three read document
 * collections (`agent-runs`, `agent-run-events`, `self-hosted-runs`,
 * `self-hosted-run-events`) that nothing writes, so the operator-facing run
 * evidence is empty on every deployment.
 *
 * The runs are real, and their authority is the `apps/agent-runtime`
 * `AgentRunState` Durable Object keyed `${tenant_id}:${run_id}`, projected into
 * each tenant's OWN evidence database. The control schema's `agent_runs` /
 * `agent_run_events` tables were derived cross-tenant compatibility projections;
 * mirroring tenant data into the shared control store is the red line #859/#881
 * closed, so the LIST no longer reads them: a tenant-scoped list reads the exact
 * object, and a platform operator's list is a bounded live fan-out over the
 * roster page (`fleetAgentRunPage`, mirroring `admin_spend_anomaly.ts`). The
 * `{run_id}` TIMELINE still reads the control projection for a platform operator
 * naming no tenant — its cross-object collision contract (409
 * `ambiguous_agent_run_id`) needs a fan-out design of its own and is a follow-up.
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

function agentRunTimelineHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const runId = pathParam(c, "run_id");
    const requestedTenantId =
      scope.kind === "platform_operator"
        ? new URL(c.req.url).searchParams.get("tenant_id")?.trim() || null
        : null;
    const selectedTenantId = scope.kind === "tenant" ? scope.tenantId : requestedTenantId;
    const projectionBacked = scope.kind === "platform_operator" && selectedTenantId === null;
    const db =
      selectedTenantId !== null
        ? await tenantEvidenceDatabaseFor(deps.tenantDatabases, selectedTenantId)
        : deps.controlDatabase;
    if (db === null) throw notFound("agent_run", runId);

    let run: Record<string, unknown> | null;
    if (projectionBacked) {
      const matches = await db
        .prepare(
          `SELECT ${AGENT_RUN_COLUMNS}
             FROM agent_runs
            WHERE id = ?
            ORDER BY tenant ASC`,
        )
        .bind(runId)
        .all<Record<string, unknown>>();
      if (matches.results.length > 1) {
        throw new HttpError(
          409,
          "ambiguous_agent_run_id",
          `agent_run ${runId} belongs to multiple tenants; tenant_id is required`,
        );
      }
      run = matches.results[0] ?? null;
    } else {
      run = await db
        .prepare(
          `SELECT ${AGENT_RUN_COLUMNS}
             FROM agent_runs
            WHERE id = ? AND tenant = ?`,
        )
        .bind(runId, selectedTenantId)
        .first<Record<string, unknown>>();
    }
    if (run === null) throw notFound("agent_run", runId);

    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    const eventTenant = selectedTenantId ?? (typeof run.tenant === "string" ? run.tenant : null);
    const eventFence = eventTenant === null ? " AND tenant IS NULL" : " AND tenant = ?";
    const eventParams = eventTenant === null ? [runId] : [runId, eventTenant];
    const events = await db
      .prepare(
        `SELECT ${AGENT_RUN_EVENT_COLUMNS}, count(*) OVER() AS total
           FROM agent_run_events
          WHERE run_id = ?${eventFence}
          ORDER BY occurred_at_unix ASC, id ASC
          LIMIT ? OFFSET ?`,
      )
      .bind(...eventParams, query.limit, query.offset)
      .all<Record<string, unknown> & { total?: number }>();
    const body = projectionBacked
      ? adminListPaginatedWithMetadata(
          events.results.map(eventDocument),
          events.results[0]?.total ?? 0,
          query.offset,
          query.limit,
          derivedControlProjectionMetadata(),
        )
      : adminListPaginated(
          events.results.map(eventDocument),
          events.results[0]?.total ?? 0,
          query.offset,
          query.limit,
        );
    return json(c, 200, body);
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
