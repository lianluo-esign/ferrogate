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
 * `AgentRunState` Durable Object keyed `${tenant_id}:${run_id}`. The control
 * schema's `agent_runs` / `agent_run_events` tables are derived compatibility
 * projections written after the object. Tenant-scoped reads route to the exact
 * object; platform pages use a bounded/as-of control projection until #825
 * defines the general fleet fan-out and freshness contract.
 */

const AGENT_RUN_COLUMNS =
  "id, request_id, tenant, started_at_unix, completed_at_unix, run_json";
const AGENT_RUN_EVENT_COLUMNS =
  "id, run_id, request_id, tenant, occurred_at_unix, event_json";

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

function listAgentRunsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    if (deps.controlDatabase === null && scope.kind === "platform_operator") {
      const page = await deps.store.list("agent-runs", scope, query);
      return json(c, 200, adminListPaginated(page.items, page.total, query.offset, query.limit));
    }

    const page =
      scope.kind === "tenant"
        ? await tenantAgentRunPage(
            deps.tenantDatabases,
            scope.tenantId,
            query.limit,
            query.offset,
          )
        : await agentRunPage(
            deps.controlDatabase as D1Database,
            scope,
            query.limit,
            query.offset,
          );
    return json(
      c,
      200,
      adminListPaginated(page.rows.map(runDocument), page.total, query.offset, query.limit),
    );
  };
}

function agentRunTimelineHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const runId = pathParam(c, "run_id");
    const db =
      scope.kind === "tenant"
        ? await tenantEvidenceDatabaseFor(deps.tenantDatabases, scope.tenantId)
        : deps.controlDatabase;
    if (db === null) throw notFound("agent_run", runId);

    const run = await db
      .prepare(
        `SELECT ${AGENT_RUN_COLUMNS}
           FROM agent_runs
          WHERE id = ?${scope.kind === "tenant" ? " AND tenant = ?" : ""}`,
      )
      .bind(...(scope.kind === "tenant" ? [runId, scope.tenantId] : [runId]))
      .first<Record<string, unknown>>();
    if (run === null) throw notFound("agent_run", runId);

    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    const eventFence = scope.kind === "tenant" ? " AND tenant = ?" : "";
    const eventParams = scope.kind === "tenant" ? [runId, scope.tenantId] : [runId];
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
