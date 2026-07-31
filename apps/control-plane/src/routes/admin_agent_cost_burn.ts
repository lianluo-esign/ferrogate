/**
 * Contract group `admin_agent_cost_burn` (1 operation) —
 * `GET /admin/v1/agent-cost-burn`, the durable accumulated cost burn per agent.
 *
 * `admin.read`, tenant-scoped by the store like every other admin listing.
 */
import { crudGroup, readOnlyCollection, type GroupModule } from "./resource.js";

export const adminAgentCostBurnRoutes: GroupModule = crudGroup("admin_agent_cost_burn", [
  readOnlyCollection("agent-cost-burn", "agent_cost_burn"),
]);
