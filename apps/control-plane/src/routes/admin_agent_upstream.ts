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

/**
 * PORT-TODO(P: inventory-edge-control §4 config-backed collections) — the CRUD here
 * and the registry the data plane serves from are two disjoint systems.
 *
 * `apps/gateway/src/routes/agent-discovery.ts` builds `/.well-known/agent.json`
 * (and the tenant-visibility filter over it) from the DEPLOY-TIME Worker var
 * `GATEWAY_AGENT_UPSTREAMS` (`AGENT_UPSTREAMS_VAR`), never from this app's
 * documents. So `POST /admin/v1/agent-upstreams` records an upstream that no
 * agent discovery response will ever list, and removing one does not withdraw
 * it — that needs a `wrangler.toml` edit and a redeploy. In Rust both were the
 * one `[[agent_upstreams]]` table in the live config snapshot.
 *
 * The same split applies to `routes/prompt.ts` (`GATEWAY_PROMPT_TEMPLATES`),
 * `routes/skill.ts` (`GATEWAY_SKILL_PACKAGES`, read by
 * `apps/gateway/src/routes/skills.ts:152,168`), `routes/admin_policy.ts` and
 * `routes/admin_plugin.ts`: durable, audited, tenant-fenced CRUD whose documents
 * have no reader outside this Worker.
 *
 * ## The decision is no longer open — it has been made twice, the same way
 *
 * This used to end "choosing is a cross-app decision". It has since been chosen,
 * in two different Workers, and both picked the SAME shape: **the data plane
 * reads `control_plane_resources` directly, so the admin write IS the
 * data-plane source.**
 *
 *  1. `apps/mcp/src/catalog.ts` reads the `mcp-servers` documents
 *     (`routes/admin_mcp_server.ts`).
 *  2. `apps/gateway/src/inference/workflow.ts:89` + `:326` read
 *     `control_plane_resources` of kind `agent-workflows`
 *     (`routes/admin_agent_workflow.ts`) when `CONTROL_DB` is bound, falling
 *     back to the var when it is not — landed by the D2 workflow-gate slice, and
 *     the reason `admin_agent_workflow` has come OFF this list.
 *
 * So the remaining four are no longer a design question, only unstarted work,
 * and each is the same three-line change in the gateway: a `CONTROL_DB` source
 * ahead of the var, defaulting to the var when the binding is absent. The wiring
 * is `apps/gateway`'s to land and its composition root is owned by the integrate
 * step, so it cannot be done from here — but nothing is being decided any more.
 *
 * **Blast radius, unchanged and worth restating:** the operator is told `201` /
 * `200` and nothing takes effect until someone edits `wrangler.toml` and
 * redeploys. For `agent-upstreams` specifically that includes DELETE: removing a
 * compromised upstream through the admin API does not withdraw it.
 */
export const adminAgentUpstreamRoutes: GroupModule = crudGroup("admin_agent_upstream", [
  { segment: "agent-upstreams", object: "agent_upstream", body: agentUpstreamSchema },
]);
