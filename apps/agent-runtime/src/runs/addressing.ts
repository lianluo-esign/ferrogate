/**
 * How a run and a worker plane are ADDRESSED.
 *
 * This is where tenant isolation is actually obtained, so it lives in one file
 * with one exported function each and nothing else. Every read and write of run
 * state goes through {@link runStateStub}; every queue operation goes through
 * {@link workerPlaneStub}.
 */
import type { AgentRuntimeBindings } from "../ports.js";
import type { WorkerPlane } from "../workers/plane.js";
import type { AgentRunState } from "./do.js";

/**
 * Escape the separator so `(tenant "a:b", run "c")` and `(tenant "a", run
 * "b:c")` cannot address the same Durable Object. Without this the isolation
 * boundary is a string-concatenation bug away from being crossed.
 */
function joinName(...parts: readonly string[]): string {
  return parts.map((part) => part.replace(/\\/g, "\\\\").replace(/:/g, "\\c")).join(":");
}

/**
 * The DO instance for `(tenant, run)`.
 *
 * Because the tenant is part of the name, another tenant's `run_id` resolves to
 * a DIFFERENT, empty instance — which the routes report as 404, so the surface
 * is not an existence oracle (Rust `agent_jobs.rs`: "a cross-tenant `run_id`
 * resolves to `None` and is reported as 404 (not 403)").
 */
export function runStateStub(
  env: AgentRuntimeBindings,
  tenantId: string,
  runId: string,
): DurableObjectStub<AgentRunState> {
  const id = env.AGENT_RUN_STATE.idFromName(joinName(tenantId, runId));
  return env.AGENT_RUN_STATE.get(id) as DurableObjectStub<AgentRunState>;
}

/**
 * The DO instance for `(tenant, workspace)` — the exact scope Rust's
 * `can_lease_to` filters dispatches on, so a worker can only ever be handed
 * work from its own tenant AND workspace.
 */
export function workerPlaneStub(
  env: AgentRuntimeBindings,
  tenantId: string,
  workspaceId: string,
): DurableObjectStub<WorkerPlane> {
  const id = env.WORKER_PLANE.idFromName(joinName(tenantId, workspaceId));
  return env.WORKER_PLANE.get(id) as DurableObjectStub<WorkerPlane>;
}
