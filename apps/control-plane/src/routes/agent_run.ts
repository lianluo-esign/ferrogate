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
import { type GroupModule, crudGroup, readOnlyCollection, subListHandler } from "./resource.js";

/**
 * PORT-TODO(P: inventory-edge-control §agent-worker) — these three read document
 * collections (`agent-runs`, `agent-run-events`, `self-hosted-runs`,
 * `self-hosted-run-events`) that nothing writes, so the operator-facing run
 * evidence is empty on every deployment.
 *
 * The runs are real, they just live somewhere this Worker cannot page: run state
 * and its event log are held by `apps/agent-runtime`'s `AgentRunState` Durable
 * Object, keyed `${tenant_id}:${run_id}` (`apps/agent-runtime/src/runs/do.ts`) —
 * the CF-native replacement for Rust's `agent_runs` + `agent_run_events`
 * Postgres tables. The control schema still declares both tables
 * (`sql/d1-ts/control/0001_init_control.sql`) and neither has a writer or a
 * reader in `apps/<app>/src`.
 *
 * A Durable Object is addressable but NOT queryable across instances, so
 * "list every run for this tenant" cannot be served from the DO alone. The
 * closing move is a projection: `AgentRunState` writes a summary row into
 * `agent_runs` (and an append-only `agent_run_events` row per event) on each
 * transition, and this group pages that table with the tenant fence. That is a
 * cross-app change — `apps/agent-runtime` owns the write side.
 */
export const agentRunRoutes: GroupModule = crudGroup(
  "agent_run",
  [readOnlyCollection("agent-runs", "agent_run")],
  {
    getAdminAgentRunTimeline: subListHandler({
      parent: { segment: "agent-runs", object: "agent_run" },
      parentParam: "run_id",
      collection: "agent-run-events",
      parentField: "agent_run_id",
    }),

    getAdminSelfHostedRunTimeline: subListHandler({
      parent: { segment: "self-hosted-runs", object: "self_hosted_run" },
      parentParam: "run_id",
      collection: "self-hosted-run-events",
      parentField: "run_id",
    }),
  },
);
