/**
 * Contract group `admin_managed_worker` (4 operations) — read-only views of the
 * managed (gateway-hosted) agent worker plane: the workers themselves, their
 * live sessions, the framework adapters they expose, and the observed activity
 * feed.
 *
 * Distinct from `self_hosted_worker`, which is the operator-run worker family
 * with registration, heartbeat and identity rotation.
 */
import type { ControlPlaneDeps, StoreRecord } from "../ports.js";
import { listResponse, parseListQuery } from "../responses.js";
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
});
