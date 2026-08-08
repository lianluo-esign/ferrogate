/**
 * THE MCP MANAGED-ACTION POLICY, READ FROM THE DURABLE ACTIVATED REVISION.
 *
 * `docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-3**. Before this module the
 * MCP tool chokepoint screened arguments and results from
 * `FG_DEV_MCP_GUARDRAILS`, committed in `wrangler.toml` as `""` — which parses
 * to `{}`, which matches nothing, which allows everything — while
 * `apps/gateway` merged the durable `guardrail_policy_revisions` +
 * `guardrail_policy_bindings` rows into its detector source. `src/ports.ts`
 * said so itself: *"the real enforcement policy is tenant-scoped control-plane
 * state and this var is DEV/TEST ONLY."* The honesty was never the problem; the
 * gap was. An operator activated a policy, saw it bound, and it covered ONE of
 * the three doors that screen content.
 *
 * That is the shape of both bypasses this project has already shipped: **a
 * control that is DURABLE on one Worker and VAR-ONLY on another.**
 *
 * ## Scope class: this Worker screens MANAGED ACTIONS
 *
 * `scopeMatches` requires a policy's `managed_action` selector and the
 * request's managed-action context to be BOTH present or BOTH absent, and that
 * is Rust, not an artefact of the port: `evaluate_managed_action_guardrail_async`
 * passes `managed_action: Some(ManagedActionContext { class: Mcp, target })`
 * with `provider: None` and `model: None`
 * (`crates/ferrogate-gateway/src/server/managed_action_guardrail.rs:115-155`),
 * while the A2A ingress passes `managed_action: None`. So a model-content
 * policy correctly does not police an MCP tool call, and a managed-action
 * policy correctly does not police a chat completion. The FC-3 defect was never
 * that the scopes were wrong — it was that a correctly-scoped activated
 * revision reached NO screening Worker but one.
 *
 * ## Precedence
 *
 * `env.DB` bound (the CONTROL database, `wrangler.toml`
 * `database_name = "ferrogate-control"`) ⇒ the durable activated revisions
 * apply FIRST, and the operator var still applies after them. Durable rows are
 * ADDITIVE, exactly as `apps/gateway/src/guardrails/d1.ts::loadGuardrailPolicyStore`
 * makes them additive to `GATEWAY_GUARDRAIL_POLICIES`, so a deployment that
 * configured only the var behaves exactly as it did. No `env.DB` ⇒ the var
 * alone.
 *
 * ## FAIL CLOSED
 *
 * A control database that cannot be read produces a REFUSAL
 * (`guardrail_policy_unavailable`), never an allow — `apps/gateway/src/ratelimit/quota.ts`
 * argues this posture and the MCP admission ladder already takes it. A detector
 * that cannot run lands on the revision's `on_error` actions, whose Rust
 * `provider_on_error` default is `Block`, inside
 * `@ferrogate/guardrails`' `screenGuardrailPolicies`.
 *
 * ## The snapshot is REVALIDATED, not merely memoized
 *
 * `activatedGuardrailPolicies` re-reads the binding POINTERS on every call and
 * recompiles only when `(policy_id, active_revision, generation)` moved, so an
 * activation takes effect on the very NEXT tool call rather than whenever this
 * isolate happens to recycle. A failed read is not cached, so one D1 blip
 * cannot wedge an isolate into refusing every call.
 *
 * ## Streaming and incrementality
 *
 * MCP `tools/call` returns its result as one JSON-RPC response, so there is no
 * stream to screen incrementally on this surface — the result is fully in hand
 * at the response stage and a match therefore BLOCKS, which is what
 * `src/tools.ts` already does with the verdict. The incremental case is A2A
 * `message:stream`, handled in `apps/agent-runtime/src/agents/ingress.ts`.
 */
import {
  type CompiledGuardrailPolicy,
  type GuardrailPolicyDatabase,
  type GuardrailPolicySql,
  type GuardrailScreeningDecision,
  activatedGuardrailPolicies,
  envelopeManagedAction,
  flattenedText,
  forgetActivatedGuardrailPolicies,
  guardrailSecretsFromEnv,
  screenGuardrailPolicies,
} from "@ferrogate/guardrails";

import type { DispatchContext, GuardrailVerdict, GuardrailsPort, McpTool } from "./ports.js";

/** The CONTROL database binding this Worker reads guardrail policy from. */
export const MCP_GUARDRAIL_DATABASE_BINDING = "DB";

/**
 * The statements this Worker's screening ISSUES, restated here rather than
 * imported.
 *
 * This is the repo's standing convention for cross-Worker SQL — written out at
 * length in `apps/control-plane/src/store/guardrail_registry.ts` — and it is
 * load-bearing twice over. An operator or reviewer grepping "who reads
 * `guardrail_policy_bindings`" must find this Worker; before FC-3 they would not
 * have, and the answer was correct because nothing here read it. And
 * `apps/gateway/test/fleet-control-matrix.test.ts` derives each control's
 * source-of-truth class by extracting table names from the SQL LITERALS in each
 * Worker's own `src/`, so a Worker that reached the rows only through a helper
 * would still be scored VAR-ONLY: the exact shape of every fleet control defect
 * shipped so far.
 *
 * They cannot drift. `apps/mcp/test/fleet-guardrail-activation.test.ts` asserts
 * each of these equals `@ferrogate/guardrails`' own constant AND the gateway's,
 * character for character.
 */
export const MCP_GUARDRAIL_REVISION_SQL =
  "SELECT revision_json FROM guardrail_policy_revisions ORDER BY policy_id ASC, revision ASC";

// Written as ONE literal, not a concatenation: the fleet matrix extracts table
// names from a literal that also carries the verb, so a `"SELECT …" + "FROM x"`
// split hides the table from the scan — and a Worker whose reads are invisible
// to that scan is scored VAR-ONLY, which is the finding this closed.
export const MCP_GUARDRAIL_BINDING_SQL =
  "SELECT policy_id, active_revision, generation, binding_json FROM guardrail_policy_bindings ORDER BY policy_id ASC";

/** The cheap per-request freshness probe: which revision is live, at what generation. */
export const MCP_GUARDRAIL_POINTER_SQL =
  "SELECT policy_id, active_revision, generation FROM guardrail_policy_bindings ORDER BY policy_id ASC";

/** Handed to `activatedGuardrailPolicies`, so these strings are what really runs. */
const GUARDRAIL_SQL: GuardrailPolicySql = {
  revisionSql: MCP_GUARDRAIL_REVISION_SQL,
  bindingSql: MCP_GUARDRAIL_BINDING_SQL,
  pointerSql: MCP_GUARDRAIL_POINTER_SQL,
};

/** Rust `ManagedActionClass::Mcp` — the class every action this Worker raises carries. */
export const MCP_MANAGED_ACTION_SCOPE_CLASS = "mcp" as const;

export interface McpGuardrailBindings {
  readonly CONTROL_DATA?: unknown;
}

/** Drop the memoized snapshot. Test affordance; an isolate recycle does the same. */
export function forgetMcpGuardrailPolicies(env: object): void {
  forgetActivatedGuardrailPolicies(env);
}

function controlDatabase(env: McpGuardrailBindings): GuardrailPolicyDatabase | undefined {
  const binding = controlDatabaseFrom(env);
  return typeof binding === "object" &&
    binding !== null &&
    typeof (binding as GuardrailPolicyDatabase).prepare === "function"
    ? (binding as GuardrailPolicyDatabase)
    : undefined;
}

/** Rust `ManagedExternalAction::target()` for the `McpTool` arm. */
function targetOf(tool: McpTool): string {
  return `mcp:${tool.serverName}:${tool.remoteName}`;
}

/**
 * Screen one managed action against the DURABLE activated revisions.
 *
 * `renderText` is a THUNK for the reason the var-driven port already documents:
 * `JSON.stringify` runs caller-controlled `toJSON`/getters, so rendering the
 * payload can throw, and a failure THERE has cleared exactly as little as a
 * failure inside the detector. It must refuse, not escape as a 500 some outer
 * handler could mistake for a clean pass.
 */
export async function screenManagedActionAgainstDurablePolicies(
  env: McpGuardrailBindings,
  context: DispatchContext,
  tool: McpTool,
  stage: "request" | "response",
  renderText: () => string,
): Promise<GuardrailScreeningDecision> {
  const db = controlDatabase(env);
  if (db === undefined) return { outcome: "allow" };

  let policies: readonly CompiledGuardrailPolicy[];
  try {
    policies = await activatedGuardrailPolicies(
      env,
      db,
      { secrets: guardrailSecretsFromEnv(env as unknown as Record<string, unknown>) },
      GUARDRAIL_SQL,
    );
  } catch (error) {
    return unavailable(
      `guardrail policy store is unavailable: ${
        error instanceof Error ? error.message : "read error"
      }`,
    );
  }
  if (policies.length === 0) return { outcome: "allow" };

  const target = targetOf(tool);
  let envelope: ReturnType<typeof envelopeManagedAction>;
  try {
    envelope = envelopeManagedAction(stage, `managed_action:${target}`, renderText());
  } catch (error) {
    return unavailable(
      `guardrail payload could not be rendered for ${tool.name}: ${
        error instanceof Error ? error.message : "render error"
      }`,
    );
  }

  return screenGuardrailPolicies({
    policies,
    // Rust's context, verbatim: no `provider`, no `model`, and the
    // managed-action `(class, target)` pair that selects the scope class.
    selection: {
      ...(context.auth.organizationId !== undefined
        ? { organization_id: context.auth.organizationId }
        : {}),
      ...(context.auth.workspaceId !== undefined ? { workspace_id: context.auth.workspaceId } : {}),
      ...(context.auth.apiKeyId !== undefined ? { api_key_id: context.auth.apiKeyId } : {}),
      managed_action: { class: MCP_MANAGED_ACTION_SCOPE_CLASS, target },
    },
    stage,
    // Rust passes `streaming: false` for every managed action.
    streaming: false,
    input: {
      protocol: "managed_action",
      stage,
      tenant: {
        ...(context.auth.organizationId !== undefined
          ? { organization_id: context.auth.organizationId }
          : {}),
        ...(context.auth.apiKeyId !== undefined ? { api_key_id: context.auth.apiKeyId } : {}),
      },
      text: flattenedText(envelope),
      segments: [...envelope.segments],
    },
  });
}

function unavailable(message: string): GuardrailScreeningDecision {
  return {
    outcome: "deny",
    code: "guardrail_policy_unavailable",
    message,
    policyId: "",
    policyRevision: 0,
    actionKind: "block",
    findingCount: 0,
  };
}

/**
 * The MCP tool chokepoint's guardrail seam, bound to the durable activated
 * revisions, with the var-driven detector as the second authority.
 *
 * ORDER IS LOAD-BEARING: the durable policy runs FIRST, so a tenant-scoped
 * activated revision cannot be reached around by a deployment whose own var
 * happens to allow the content; the `fallback` still runs whenever the durable
 * half allowed, so a var-only deployment is unchanged.
 *
 * The refusal `reason` CARRIES THE OPERATOR'S CODE. `src/tools.ts` renders the
 * verdict's reason into the JSON-RPC error message, and carrying the code there
 * is what makes "the gateway blocks it and MCP blocks it with the SAME code"
 * observable to the caller — the fleet property FC-3 is about. The matched text
 * is never carried: the crate's standing invariant.
 */
export function durableManagedActionGuardrails(
  env: McpGuardrailBindings,
  fallback: GuardrailsPort,
): GuardrailsPort {
  const verdict = (
    decision: GuardrailScreeningDecision,
    refusal: "block" | "withhold",
  ): GuardrailVerdict | undefined =>
    decision.outcome === "deny"
      ? { action: refusal, reason: `${decision.code}: ${decision.message}` }
      : undefined;

  return {
    async inspectInput(context, tool, args) {
      const decision = await screenManagedActionAgainstDurablePolicies(
        env,
        context,
        tool,
        "request",
        // Rust `managed_action_input_text`: the canonical target, a newline,
        // then the payload — so a policy can match on the addressing
        // (`mcp:github:create_issue`) as well as on the body.
        () => `${targetOf(tool)}\n${payloadText(args)}`,
      );
      return verdict(decision, "block") ?? fallback.inspectInput(context, tool, args);
    },
    async inspectOutput(context, tool, content) {
      const decision = await screenManagedActionAgainstDurablePolicies(
        env,
        context,
        tool,
        "response",
        () => payloadText(content),
      );
      return verdict(decision, "withhold") ?? fallback.inspectOutput(context, tool, content);
    },
  };
}

/**
 * Rust `managed_action_guardrail::payload_text`: a bare JSON string is scanned
 * as-is (no enclosing quotes, which would fence a keyword off from its
 * neighbours), anything else by its compact JSON encoding.
 *
 * Restated here rather than imported from `./ports.js` so this module stays a
 * LEAF — `apps/mcp/test/fleet-guardrail-activation.test.ts` and the
 * agent-runtime fleet spec reach it from another Worker's test bundle, and
 * `ports.ts` drags the whole in-memory port bundle behind it.
 */
function payloadText(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value ?? null);
}
import { controlDatabaseFrom } from "./control-data";
