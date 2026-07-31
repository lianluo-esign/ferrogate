/**
 * Contract group `admin_agent_upstream` (6 operations) — plain CRUD over
 * `/admin/v1/agent-upstreams`, the registry of upstream agent endpoints the
 * runtime may dispatch to.
 *
 * Rust: `crates/ferrogate-gateway/src/server/local.rs` (agent-upstream family).
 */
import { z } from "zod";
import { adminRecordSchema, crudGroup, type GroupModule } from "./resource.js";

/**
 * PORT-TODO(inventory-request-path §agent upstreams): tighten to the Rust
 * `AdminAgentUpstreamMutation` once `@ferrogate/schemas` exposes it. `url` and
 * `enabled` are asserted now because a malformed upstream URL is the failure
 * that only shows up at dispatch time.
 */
export const agentUpstreamSchema = adminRecordSchema.extend({
  url: z.string().url().optional(),
  enabled: z.boolean().optional(),
});

export const adminAgentUpstreamRoutes: GroupModule = crudGroup("admin_agent_upstream", [
  { segment: "agent-upstreams", object: "agent_upstream", body: agentUpstreamSchema },
]);
