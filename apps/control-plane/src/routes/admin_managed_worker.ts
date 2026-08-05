/**
 * Contract group `admin_managed_worker` (4 operations) — read-only views of the
 * managed (gateway-hosted) agent worker plane: the workers themselves, their
 * live sessions, the framework adapters they expose, and the observed activity
 * feed.
 *
 * Distinct from `self_hosted_worker`, which is the operator-run worker family
 * with registration, heartbeat and identity rotation.
 */
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { periodMonthFromUnix } from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope, ControlPlaneDeps, StoreRecord } from "../ports.js";
import { adminListPaginated, listResponse, parseListQuery } from "../responses.js";
import { tenantEvidenceDatabaseFor } from "../store/tenancy.js";
import {
  listTenantManagedWorkerSessions,
  listTenantManagedWorkers,
} from "../store/tenant-worker.js";
import { pageOf } from "../store/query.js";
import {
  json,
  scopeOf,
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  readOnlyCollection,
} from "./resource.js";

async function listManagedObjects(
  c: Parameters<Handler>[0],
  read: (
    router: ControlPlaneDeps["tenantDatabases"],
    tenantId: string,
    limit: number,
  ) => Promise<readonly StoreRecord[] | null>,
): Promise<Response> {
  const deps = depsOf(c);
  const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
  const scope = scopeOf(c);
  const tenantIds =
    scope.kind === "tenant" ? [scope.tenantId] : await deps.tenantDatabases.provisionedTenants();
  const records: StoreRecord[] = [];
  const unreadableTenants: string[] = [];
  const fanoutLimit = Math.max(1, Math.min(deps.listMaxLimit, query.offset + query.limit));
  for (const tenantId of tenantIds) {
    try {
      const rows = await read(deps.tenantDatabases, tenantId, fanoutLimit);
      if (rows !== null) records.push(...rows);
    } catch {
      if (scope.kind === "tenant") throw new Error(`tenant ${tenantId} managed worker state is unreadable`);
      unreadableTenants.push(tenantId);
    }
  }
  const body = listResponse(pageOf(records, query), query);
  return unreadableTenants.length === 0
    ? json(c, 200, body)
    : json(c, 200, { ...body, unreadable_tenants: unreadableTenants });
}

const listManagedWorkers: Handler = (c) =>
  listManagedObjects(c, listTenantManagedWorkers);

const listManagedWorkerSessions: Handler = (c) =>
  listManagedObjects(c, listTenantManagedWorkerSessions);

const OBSERVED_AGENT_RUNNING_TTL_SECONDS = 300;

interface PresenceRow {
  readonly tenant_id: string;
  readonly api_key_id: string;
  readonly first_seen_at_unix: number;
  readonly last_seen_at_unix: number;
  readonly request_count: number;
}

interface RequestActivityRow {
  readonly api_key_id: string;
  readonly project_id: string | null;
  readonly workspace_id: string | null;
  readonly credential_name: string | null;
  readonly first_seen_at_unix: number;
  readonly last_seen_at_unix: number;
  readonly request_count: number;
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
}

interface UsageActivityRow {
  readonly api_key_id: string;
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
  readonly cost_usd: number;
}

interface ActivityRow {
  readonly document: StoreRecord;
  readonly lastSeenAtUnix: number;
}

async function observedActivityRowsFor(
  router: TenantDatabaseRouter,
  tenantId: string,
  nowUnix: number,
): Promise<{ rows: ActivityRow[]; presenceFeedAvailable: boolean; presenceReason: string | null }> {
  const db = await tenantEvidenceDatabaseFor(router, tenantId);
  const requestRows = await db
    .prepare(
      "SELECT r.api_key_id, k.project_id, k.workspace_id, k.name AS credential_name, " +
        "MIN(r.started_at_unix) AS first_seen_at_unix, " +
        "MAX(COALESCE(r.completed_at_unix, r.started_at_unix)) AS last_seen_at_unix, " +
        "COUNT(*) AS request_count, " +
        "COALESCE(SUM(r.prompt_tokens), 0) AS prompt_tokens, " +
        "COALESCE(SUM(r.completion_tokens), 0) AS completion_tokens, " +
        "COALESCE(SUM(r.total_tokens), 0) AS total_tokens " +
        "FROM request_logs r LEFT JOIN api_keys k ON k.id = r.api_key_id " +
        "WHERE r.tenant = ? AND r.api_key_id IS NOT NULL AND r.api_key_id <> '' " +
        "AND (r.agent_run_id IS NULL OR r.agent_run_id = '') " +
        "GROUP BY r.api_key_id, k.project_id, k.workspace_id, k.name",
    )
    .bind(tenantId)
    .all<RequestActivityRow>();

  const usage = await db
    .prepare(
      "SELECT scope_id AS api_key_id, prompt_tokens, completion_tokens, total_tokens, cost_usd " +
        "FROM usage_monthly_rollups WHERE period_month = ? AND scope_type = 'key'",
    )
    .bind(periodMonthFromUnix(nowUnix))
    .all<UsageActivityRow>();
  const usageByKey = new Map(usage.results.map((row) => [row.api_key_id, row]));

  let presenceByKey = new Map<string, PresenceRow>();
  let presenceFeedAvailable = true;
  let presenceReason: string | null = null;
  try {
    const presence = await db
      .prepare(
        "SELECT tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count " +
          "FROM observed_agent_presence WHERE tenant_id = ?",
      )
      .bind(tenantId)
      .all<PresenceRow>();
    presenceByKey = new Map(presence.results.map((row) => [row.api_key_id, row]));
  } catch (error) {
    presenceFeedAvailable = false;
    presenceReason = `tenant_presence_feed_unavailable: ${
      error instanceof Error ? error.message : String(error)
    }`;
  }

  const candidates = new Map<string, RequestActivityRow>();
  for (const row of requestRows.results) candidates.set(row.api_key_id, row);
  for (const presence of presenceByKey.values()) {
    if (candidates.has(presence.api_key_id)) continue;
    candidates.set(presence.api_key_id, {
      api_key_id: presence.api_key_id,
      project_id: null,
      workspace_id: null,
      credential_name: null,
      first_seen_at_unix: presence.first_seen_at_unix,
      last_seen_at_unix: presence.last_seen_at_unix,
      request_count: presence.request_count,
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    });
  }

  const rows: ActivityRow[] = [];
  for (const activity of candidates.values()) {
    const presence = presenceByKey.get(activity.api_key_id);
    const usageRow = usageByKey.get(activity.api_key_id);
    const firstSeenAtUnix = Math.min(
      activity.first_seen_at_unix,
      presence?.first_seen_at_unix ?? activity.first_seen_at_unix,
    );
    const requestLastSeenAtUnix = activity.last_seen_at_unix;
    const lastSeenAtUnix = Math.max(requestLastSeenAtUnix, presence?.last_seen_at_unix ?? 0);
    const secondsSinceLastSeen = Math.max(0, nowUnix - lastSeenAtUnix);
    const withinRunningWindow = secondsSinceLastSeen <= OBSERVED_AGENT_RUNNING_TTL_SECONDS;
    const evidenceAvailable =
      activity.request_count > 0 || activity.total_tokens > 0 || presence !== undefined;
    const status = presenceFeedAvailable
      ? withinRunningWindow
        ? "running"
        : "inactive"
      : "unknown";
    const statusBasis = presenceFeedAvailable
      ? "recent_api_key_activity"
      : "presence_feed_unavailable";
    const reason = presenceFeedAvailable
      ? withinRunningWindow
        ? "recent unattributed virtual API-key activity"
        : "no unattributed virtual API-key activity inside the running window"
      : "durable presence feed unavailable; status is intentionally unknown";
    const evidence = {
      evidence_source: "request_logs",
      request_count: activity.request_count,
      seconds_since_last_seen: secondsSinceLastSeen,
      running_ttl_seconds: OBSERVED_AGENT_RUNNING_TTL_SECONDS,
      within_running_window: presenceFeedAvailable ? withinRunningWindow : null,
      durable_presence_backed: presenceFeedAvailable ? presence !== undefined : null,
      presence_feed_status: presenceFeedAvailable ? "available" : "unavailable",
      presence_unavailable_reason: presenceReason,
      ...(usageRow === undefined
        ? {}
        : {
            prompt_tokens: usageRow.prompt_tokens,
            completion_tokens: usageRow.completion_tokens,
            total_tokens: usageRow.total_tokens,
            cost_usd: usageRow.cost_usd,
          }),
      usage_evidence_available: usageRow !== undefined || evidenceAvailable,
      reason,
    };
    rows.push({
      lastSeenAtUnix,
      document: {
        id: `observed:${tenantId}:${activity.api_key_id}`,
        source: "virtual_api_key",
        identity_status: "unattributed",
        display_name: "Unknown",
        status,
        status_basis: statusBasis,
        tenant_id: tenantId,
        api_key_id: activity.api_key_id,
        ...(activity.project_id === null ? {} : { project_id: activity.project_id }),
        ...(activity.workspace_id === null ? {} : { workspace_id: activity.workspace_id }),
        ...(activity.credential_name === null ? {} : { credential_name: activity.credential_name }),
        first_seen_at_unix: firstSeenAtUnix,
        last_seen_at_unix: lastSeenAtUnix,
        running_ttl_seconds: OBSERVED_AGENT_RUNNING_TTL_SECONDS,
        evidence,
      },
    });
  }
  rows.sort(
    (left, right) =>
      right.lastSeenAtUnix - left.lastSeenAtUnix ||
      String(left.document.id).localeCompare(String(right.document.id)),
  );
  return { rows, presenceFeedAvailable, presenceReason };
}

async function listObservedAgentActivity(c: Parameters<Handler>[0]): Promise<Response> {
  const deps = depsOf(c);
  const scope: CallerScope = scopeOf(c);
  const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
  const nowUnix = Math.floor(Date.now() / 1000);
  const router = deps.tenantStorage ?? deps.tenantDatabases;
  const tenantIds =
    scope.kind === "tenant" ? [scope.tenantId] : await router.provisionedTenants();
  const rows: ActivityRow[] = [];
  const unavailableTenants: string[] = [];
  let presenceFeedAvailable = true;
  const presenceReasons: string[] = [];
  for (const tenantId of tenantIds) {
    try {
      const result = await observedActivityRowsFor(router, tenantId, nowUnix);
      rows.push(...result.rows);
      if (!result.presenceFeedAvailable) {
        presenceFeedAvailable = false;
        if (result.presenceReason !== null) presenceReasons.push(`${tenantId}: ${result.presenceReason}`);
      }
    } catch (error) {
      if (scope.kind === "tenant") {
        throw new HttpError(
          503,
          "tenant_evidence_unavailable",
          `observed agent activity is unavailable for ${tenantId}: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      unavailableTenants.push(tenantId);
      presenceFeedAvailable = false;
      presenceReasons.push(`${tenantId}: tenant evidence unavailable`);
    }
  }
  rows.sort(
    (left, right) =>
      right.lastSeenAtUnix - left.lastSeenAtUnix ||
      String(left.document.id).localeCompare(String(right.document.id)),
  );
  const windowed = rows.slice(query.offset, query.offset + query.limit);
  return json(c, 200, {
    ...adminListPaginated(windowed.map((row) => row.document), rows.length, query.offset, query.limit),
    presence_feed: {
      status: presenceFeedAvailable ? "available" : "unavailable",
      unavailable_reason:
        presenceReasons.length === 0 ? null : presenceReasons.join("; "),
      rows_may_be_incomplete: unavailableTenants.length > 0 || !presenceFeedAvailable,
    },
  });
}

/**
 * PORT-TODO(P: inventory-edge-control §agent-worker §8.2) — all four answer an empty
 * `AdminList`; Rust answers a NON-empty fixed descriptor for the first one.
 *
 * `handle_admin_managed_workers` (`local.rs:5187`) returns a single
 * `AdminManagedWorkerRuntime` naming the process boundary, the gateway/worker
 * role split, the eight lifecycle actions and the ranked isolation backends
 * (firecracker / kata / gvisor / rootless-docker) — a CONTRACT descriptor, not a
 * storage listing, so it is answerable here without any new binding and is
 * currently the clearest divergence: an operator asking "what isolation backends
 * does this deployment offer?" is told "none configured" rather than "these,
 * with this preference order".
 *
 * The tenant object now owns the managed-worker rows. The adapter provides the
 * lifecycle upserts for the runtime integration, and the two admin lists below
 * fan out only over the provisioned tenant roster. Framework adapters and
 * observed activity remain derived platform views until their producers exist;
 * this keeps the ADMIN VIEWS honest rather than manufacturing rows.
 */
export const adminManagedWorkerRoutes: GroupModule = crudGroup("admin_managed_worker", [
  readOnlyCollection("managed-workers", "managed_worker"),
  readOnlyCollection("managed-worker-sessions", "managed_worker_session"),
  readOnlyCollection("framework-adapters", "framework_adapter"),
  readOnlyCollection("observed-agent-activity", "observed_agent_activity"),
], {
  listAdminManagedWorkers: listManagedWorkers,
  listAdminManagedWorkerSessions: listManagedWorkerSessions,
  listAdminObservedAgentActivity: listObservedAgentActivity,
});
