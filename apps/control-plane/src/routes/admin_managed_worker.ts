/**
 * Contract group `admin_managed_worker` (4 operations) — read-only views of the
 * managed (gateway-hosted) agent worker plane: the workers themselves, their
 * live sessions, the framework adapters they expose, and the observed activity
 * feed.
 *
 * Distinct from `self_hosted_worker`, which is the operator-run worker family
 * with registration, heartbeat and identity rotation.
 */
import { type GroupModule, crudGroup, readOnlyCollection } from "./resource.js";

export const adminManagedWorkerRoutes: GroupModule = crudGroup("admin_managed_worker", [
  readOnlyCollection("managed-workers", "managed_worker"),
  readOnlyCollection("managed-worker-sessions", "managed_worker_session"),
  readOnlyCollection("framework-adapters", "framework_adapter"),
  readOnlyCollection("observed-agent-activity", "observed_agent_activity"),
]);
