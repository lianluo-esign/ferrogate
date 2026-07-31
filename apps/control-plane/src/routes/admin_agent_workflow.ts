/**
 * Contract group `admin_agent_workflow` (6 operations) — plain CRUD over
 * `/admin/v1/agent-workflows`.
 *
 * A workflow row carries the graph the agent runtime executes; `version` is
 * part of the run attribution chain (`RequestContext.workflow_version` in
 * `@ferrogate/core`), so it is typed rather than left free-form.
 */
import { z } from "zod";
import { adminRecordSchema, crudGroup, type GroupModule } from "./resource.js";

export const agentWorkflowSchema = adminRecordSchema.extend({
  version: z.number().int().min(0).max(4_294_967_295).optional(),
  nodes: z.array(z.record(z.unknown())).optional(),
});

export const adminAgentWorkflowRoutes: GroupModule = crudGroup("admin_agent_workflow", [
  { segment: "agent-workflows", object: "agent_workflow", body: agentWorkflowSchema },
]);
