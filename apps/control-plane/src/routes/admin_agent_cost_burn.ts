/**
 * Contract group `admin_agent_cost_burn` (1 operation) —
 * `GET /admin/v1/agent-cost-burn`, the durable accumulated cost burn per agent.
 *
 * `admin.read`, tenant-scoped by the store like every other admin listing.
 */
import { type GroupModule, crudGroup, readOnlyCollection } from "./resource.js";

/**
 * PORT-TODO(P: inventory-data-billing agent cost burn) — this pages an
 * `agent-cost-burn` document collection with no writer; the real accumulator is
 * the TENANT database's typed `agent_cost_burn` table, upserted monotonically by
 * `packages/storage/src/d1/monotonic.ts` (`INSERT … ON CONFLICT … updated_at_unix
 * = max(...)`). So the one operation in this group answers an empty list while
 * the burn it reports on is being recorded, per tenant, elsewhere.
 *
 * Closing it: read through `deps.tenantDatabases` for the caller's tenant (and,
 * for a platform operator, fan out over the routed tenants) rather than through
 * the account-global document store — the same shape `store/tenancy.ts` already
 * uses for the hierarchy projections.
 */
export const adminAgentCostBurnRoutes: GroupModule = crudGroup("admin_agent_cost_burn", [
  readOnlyCollection("agent-cost-burn", "agent_cost_burn"),
]);
