/**
 * Contract group `admin_agent_workflow` (6 operations) — plain CRUD over
 * `/admin/v1/agent-workflows`.
 *
 * A workflow row carries the graph the agent runtime executes; `version` is
 * part of the run attribution chain (`RequestContext.workflow_version` in
 * `@ferrogate/core`), so it is typed rather than left free-form.
 */
import { z } from "zod";
import { type GroupModule, adminRecordSchema, crudGroup } from "./resource.js";

/**
 * NO LONGER DURABLE-BUT-UNREAD — this group has a reader, as of the D2
 * workflow-gate slice.
 *
 * The wave-15 certification listed `admin_agent_workflow`'s 6 operations among
 * the 87 that "write to a store nothing reads". That is now false and the
 * reader is nameable: `apps/gateway/src/inference/workflow.ts` loads
 * `control_plane_resources` rows of kind `agent-workflows`
 * (`AGENT_WORKFLOW_COLLECTION`, `workflow.ts:326`) out of its `CONTROL_DB`
 * binding — the same table these six operations write — and enforces node
 * pinning, edge transitions, iteration/model-call limits and the workflow
 * timeout from them.
 *
 * Two consequences for anyone editing this file:
 *
 *  1. **The schema below is now load-bearing on a request path.** `nodes` and
 *     `version` are read by the gate on every workflow-tagged inference call;
 *     widening them here widens what the data plane will execute.
 *  2. **A `DELETE` here now actually stops enforcing a workflow**, rather than
 *     answering 200 into a void. That is the intended behaviour, and it is why
 *     the gate defaults to "no workflows declared ⇒ gate nothing" rather than
 *     failing closed on an empty read: an empty table is the state of a
 *     deployment that has declared no workflows, not an outage.
 */

export const agentWorkflowSchema = adminRecordSchema.extend({
  version: z.number().int().min(0).max(4_294_967_295).optional(),
  nodes: z.array(z.record(z.unknown())).optional(),
});

export const adminAgentWorkflowRoutes: GroupModule = crudGroup("admin_agent_workflow", [
  { segment: "agent-workflows", object: "agent_workflow", body: agentWorkflowSchema },
]);
