/**
 * Contract group `admin_tool` (7 operations) — tool approvals, tool sessions,
 * and the tool catalogue.
 *
 * ```
 *   GET   /admin/v1/tools
 *   GET   /admin/v1/tool-approvals
 *   GET   /admin/v1/tool-approvals/{approval_id}
 *   POST  /admin/v1/tool-approvals/{approval_id}/approve
 *   POST  /admin/v1/tool-approvals/{approval_id}/deny
 *   POST  /admin/v1/tool-approvals/{approval_id}/expire
 *   GET   /admin/v1/tool-sessions/{session_id}
 * ```
 *
 * An approval is **never created or deleted through this API** — the contract
 * declares no POST on the collection and no DELETE on the item. Approvals are
 * *raised by the runtime* when a governed tool call needs a human decision;
 * the admin surface only records that decision. Allowing an operator to mint an
 * approval out of band would let a tool call be pre-approved before it exists,
 * which defeats the whole approval gate (`@ferrogate/core`'s `ApprovalPolicy`).
 *
 * The three decisions are terminal and mutually exclusive, so each records the
 * decision, who made it, and when — `expire` is the timeout path and is
 * deliberately an explicit operation rather than an implicit sweep, so the
 * transition is auditable.
 */
import {
  type CollectionSpec,
  type GroupModule,
  actionHandler,
  crudGroup,
  readOnlyCollection,
  subListHandler,
} from "./resource.js";

/**
 * PORT-TODO(P: cert2-controlplane §CLASS-A admin_tool tools catalogue) — the
 * approvals half is EQUIVALENT (`apps/mcp/src/approvals.ts` reads the very
 * documents the three decisions write, `TOOL_APPROVAL_COLLECTION`), but
 * `GET /admin/v1/tools` and `GET /admin/v1/tool-sessions/{id}` are CLASS A.
 *
 * Rust `local.rs::handle_admin_tools` (7901) answers from `state.all_tools()`
 * (`state_tools.rs:71` → the live extension/tool registry), i.e. the tools the
 * deployment can actually dispatch. Here `tools`, `tool-sessions` and
 * `tool-session-events` are read-only `control_plane_resources` collections with
 * NO writer anywhere in `apps/*\/src` or `packages/*\/src`, so an operator asking
 * "what tools does this deployment expose?" is told "none", and
 * `adapters.ts::StoreRuntimeStatus.status()` reports `tools: 0` off the same
 * empty collection.
 *
 * `tools` closes with the same cross-app decision as `admin_plugin` (the plugin
 * registry is where tools come from). `tool-sessions` needs a writer on the MCP
 * side first — `apps/mcp` holds session state in its Durable Object, which is
 * addressable but not queryable across instances, so it needs a projection row
 * exactly as `agent_run` does.
 */
const TOOL_APPROVAL_SPEC: CollectionSpec = {
  segment: "tool-approvals",
  object: "tool_approval",
};

/** Terminal decision recorded on an approval. */
function decide(status: "approved" | "denied" | "expired") {
  return actionHandler({
    spec: TOOL_APPROVAL_SPEC,
    param: "approval_id",
    apply: (_record, body, now) => ({
      status,
      decided_at: now,
      decided_by: typeof body.decided_by === "string" ? body.decided_by : null,
      decision_reason: typeof body.reason === "string" ? body.reason : null,
    }),
  });
}

export const adminToolRoutes: GroupModule = crudGroup(
  "admin_tool",
  [TOOL_APPROVAL_SPEC, readOnlyCollection("tools", "tool")],
  {
    approveAdminToolApproval: decide("approved"),
    denyAdminToolApproval: decide("denied"),
    expireAdminToolApproval: decide("expired"),

    /**
     * `GET /admin/v1/tool-sessions/{session_id}` lists that session's EVENTS
     * (`listAdminToolSessionEvents`), not the session row — the operation id
     * says so and the response is a list envelope.
     */
    listAdminToolSessionEvents: subListHandler({
      parent: { segment: "tool-sessions", object: "tool_session" },
      parentParam: "session_id",
      collection: "tool-session-events",
      parentField: "session_id",
    }),
  },
);
