/**
 * Contract group `admin_agent_upstream` (6 operations) — plain CRUD over
 * `/admin/v1/agent-upstreams`, the registry of upstream agent endpoints the
 * runtime may dispatch to.
 *
 * Rust: `crates/ferrogate-gateway/src/server/local.rs` (agent-upstream family),
 * body `AdminAgentUpstreamMutation` in `crates/ferrogate-gateway/src/responses.rs`.
 */
import {
  agentUpstreamAuthSchema,
  agentUpstreamCapabilitySchema,
  agentUpstreamProtocolSchema,
} from "@ferrogate/config";
import { z } from "zod";
import { type GroupModule, adminRecordSchema, crudGroup } from "./resource.js";

/**
 * `AdminAgentUpstreamMutation`, field for field:
 *
 * ```rust
 * struct AdminAgentUpstreamMutation {
 *     id: Option<String>,          name: Option<String>,
 *     description: Option<String>, enabled: Option<bool>,
 *     protocol: Option<AgentUpstreamProtocol>,
 *     endpoint: Option<String>,    auth: Option<AgentUpstreamAuth>,
 *     tenant_ids: Option<Vec<String>>,
 *     capabilities: Option<Vec<AgentUpstreamCapability>>,
 * }
 * ```
 *
 * Every enum-valued field reuses the schema `@ferrogate/config` already derives
 * from the Rust type (`AgentUpstreamProtocol`, `AgentUpstreamAuth`,
 * `AgentUpstreamCapability`) rather than a list of strings restated here — a
 * second spelling of an enum is a second thing to forget when it grows a
 * variant, and the runtime resolves the SAME values off the config document.
 *
 * `endpoint` is the Rust field name. The app's earlier `url` spelling is kept as
 * an accepted alias because stored rows carry it, and both are validated as
 * absolute URLs: a malformed upstream endpoint is the failure that otherwise
 * only surfaces at dispatch time, inside a request nobody is watching.
 */
export const agentUpstreamSchema = adminRecordSchema.extend({
  description: z.string().optional(),
  enabled: z.boolean().optional(),
  protocol: agentUpstreamProtocolSchema.optional(),
  endpoint: z.string().url().optional(),
  /** Legacy spelling of `endpoint`, still carried by existing rows. */
  url: z.string().url().optional(),
  auth: agentUpstreamAuthSchema.optional(),
  tenant_ids: z.array(z.string().trim().min(1)).optional(),
  capabilities: z.array(agentUpstreamCapabilitySchema).optional(),
});

export const adminAgentUpstreamRoutes: GroupModule = crudGroup("admin_agent_upstream", [
  { segment: "agent-upstreams", object: "agent_upstream", body: agentUpstreamSchema },
]);
