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
 * `managed-worker-sessions` / `framework-adapters` / `observed-agent-activity`
 * are the storage half. The control schema declares `managed_worker_templates`,
 * `agent_worker_instances`, `managed_worker_sessions`,
 * and the three `managed_worker_isolation_` tables — none has a writer or a
 * reader in `apps/<app>/src`,
 * which is consistent with the platform limit recorded on
 * `apps/agent-runtime/src/runs/do.ts` (workerd cannot host the microVM backends),
 * but the ADMIN VIEWS should still report that honestly rather than as absence.
 */
export const adminManagedWorkerRoutes: GroupModule = crudGroup("admin_managed_worker", [
  readOnlyCollection("managed-workers", "managed_worker"),
  readOnlyCollection("managed-worker-sessions", "managed_worker_session"),
  readOnlyCollection("framework-adapters", "framework_adapter"),
  readOnlyCollection("observed-agent-activity", "observed_agent_activity"),
]);
