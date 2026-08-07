/**
 * THE A2A SCREENING POLICY, READ FROM THE DURABLE ACTIVATED REVISION.
 *
 * `docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-3**. Before this module the
 * A2A ingress screened from `FG_DEV_A2A_GUARDRAILS` — a deploy-time var that
 * `wrangler.toml` does not even commit — while `apps/gateway` merged the
 * durable `guardrail_policy_revisions` + `guardrail_policy_bindings` rows into
 * its detector source. An operator who authored a policy revision and called
 * `POST /admin/v1/guardrail-policies/{id}/activate` saw it bound and it covered
 * ONE of the three doors that screen content. Move the payload into an A2A
 * `message:send` body and the activated revision never saw it.
 *
 * That is the shape of both bypasses this project has already shipped: **a
 * control that is DURABLE on one Worker and VAR-ONLY on another.**
 *
 * ## Precedence, and why it is the same one the registry uses
 *
 * `CONTROL_DB` bound ⇒ the durable activated revisions apply, and the operator
 * var applies too — durable rows are ADDITIVE, exactly as
 * `apps/gateway/src/guardrails/d1.ts::loadGuardrailPolicyStore` makes them
 * additive to `GATEWAY_GUARDRAIL_POLICIES`. A deployment that configured only
 * the var behaves exactly as it did, which is what makes wiring this safe.
 * No `CONTROL_DB` ⇒ the var alone, which is the offline harness's posture and a
 * legitimate var-only deployment's.
 *
 * Unlike the agent-upstream registry, the durable half does NOT replace the var
 * half, and the asymmetry is deliberate: a withdrawn UPSTREAM must stop being
 * reachable (a union would keep dispatching to it), whereas a guardrail is a
 * RESTRICTION and dropping the operator's own configured detectors on the day a
 * control database is bound would be the fail-OPEN direction.
 *
 * ## FAIL CLOSED, in both of the two ways this can go wrong
 *
 *  1. **The control database cannot be read.** The screen answers `deny`
 *     `guardrail_policy_unavailable`, never `allow`. A control that admits when
 *     its backend is unavailable recreates the bypass in a new form — the
 *     posture `apps/gateway/src/ratelimit/quota.ts` argues explicitly, and the
 *     posture `agents/ingress.ts` already takes for the upstream registry.
 *  2. **A detector cannot run.** Handled inside
 *     `@ferrogate/guardrails`' `screenGuardrailPolicies`, which routes a
 *     detector error onto the revision's `on_error` actions — whose Rust
 *     `provider_on_error` default is `Block`.
 *
 * ## The snapshot is REVALIDATED, not merely memoized
 *
 * `activatedGuardrailPolicies` re-reads the binding POINTERS on every call and
 * recompiles only when `(policy_id, active_revision, generation)` moved, so an
 * activation takes effect on the very NEXT request rather than whenever this
 * isolate happens to recycle. That promise is the whole point of FC-3; a
 * process-lifetime memo would satisfy every unit test and quietly break it. A
 * failed read is not cached either, so one D1 blip cannot wedge an isolate into
 * refusing.
 *
 * ## This module is a LEAF, on purpose
 *
 * It imports `@ferrogate/guardrails` and TYPES from `./ports.js`, and nothing
 * else — no Hono, no route, no Worker entry. That is what lets the fleet gate
 * in `apps/mcp/test/fleet-guardrail-activation.test.ts` reach agent-runtime's
 * REAL screening path from another Worker's test without pulling this Worker's
 * module graph into that Worker's bundle. The property is asserted off this
 * file's own source text there rather than trusted to this paragraph.
 */
import {
  type CompiledGuardrailPolicy,
  type GuardrailPolicyDatabase,
  type GuardrailPolicySql,
  type GuardrailScreeningDecision,
  activatedGuardrailPolicies,
  envelopeFromText,
  flattenedText,
  forgetActivatedGuardrailPolicies,
  guardrailSecretsFromEnv,
  screenGuardrailPolicies,
} from "@ferrogate/guardrails";

import type { D1Database } from "@cloudflare/workers-types";
import { controlDatabaseFrom } from "./control-data.js";
import type { GuardrailDecision, GuardrailEvaluation, GuardrailPort } from "./ports.js";

/** The CONTROL database binding this Worker reads guardrail policy from. */
export const A2A_GUARDRAIL_DATABASE_BINDING = "CONTROL_DB";

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
export const A2A_GUARDRAIL_REVISION_SQL =
  "SELECT revision_json FROM guardrail_policy_revisions ORDER BY policy_id ASC, revision ASC";

// Written as ONE literal, not a concatenation: the fleet matrix extracts table
// names from a literal that also carries the verb, so a `"SELECT …" + "FROM x"`
// split hides the table from the scan — and a Worker whose reads are invisible
// to that scan is scored VAR-ONLY, which is the finding this closed.
export const A2A_GUARDRAIL_BINDING_SQL =
  "SELECT policy_id, active_revision, generation, binding_json FROM guardrail_policy_bindings ORDER BY policy_id ASC";

/** The cheap per-request freshness probe: which revision is live, at what generation. */
export const A2A_GUARDRAIL_POINTER_SQL =
  "SELECT policy_id, active_revision, generation FROM guardrail_policy_bindings ORDER BY policy_id ASC";

/** Handed to `activatedGuardrailPolicies`, so these strings are what really runs. */
const GUARDRAIL_SQL: GuardrailPolicySql = {
  revisionSql: A2A_GUARDRAIL_REVISION_SQL,
  bindingSql: A2A_GUARDRAIL_BINDING_SQL,
  pointerSql: A2A_GUARDRAIL_POINTER_SQL,
};

/**
 * The detector id recorded on a durable-policy denial.
 *
 * Distinct from `a2a.deterministic` (the var-driven port) so an investigator
 * reading the run timeline can tell which authority refused — the operator's
 * activated revision or this deployment's own configuration.
 */
export const A2A_DURABLE_DETECTOR_ID = "a2a.durable_policy";

export interface A2aGuardrailBindings {
  readonly CONTROL_DB?: unknown;
}

/** Drop the memoized snapshot. Test affordance; an isolate recycle does the same. */
export function forgetA2aGuardrailPolicies(env: object): void {
  forgetActivatedGuardrailPolicies(env);
}

function controlDatabase(env: A2aGuardrailBindings): GuardrailPolicyDatabase | undefined {
  const binding = controlDatabaseFrom(env, { legacy: [env.CONTROL_DB as D1Database | undefined] });
  return typeof binding === "object" &&
    binding !== null &&
    typeof (binding as GuardrailPolicyDatabase).prepare === "function"
    ? (binding as GuardrailPolicyDatabase)
    : undefined;
}

/**
 * Screen one A2A evaluation against the DURABLE activated revisions.
 *
 * The envelope is built exactly as Rust `a2a_input_envelope` /
 * `a2a_output_envelope` build it — protocol `a2a`, source `user` on the request
 * leg and `assistant` on the response leg, protocol location
 * `a2a:{agent}/message` or `a2a:{agent}/response` — so a policy whose check
 * declares those sources sees the same segments the gateway's chat path
 * presents for the same content.
 *
 * The SELECTION context is Rust's, verbatim (`server/local.rs:9989-9994`):
 * organization from the tenant, `provider` = the agent id, no `model`, and
 * **no `managed_action`** — A2A is model content, not a managed action, so a
 * managed-action-scoped policy correctly does not police it and vice versa.
 */
export async function screenA2aAgainstDurablePolicies(
  env: A2aGuardrailBindings,
  input: GuardrailEvaluation,
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
    // FAIL CLOSED. A policy set that could not be read has cleared nothing.
    return {
      outcome: "deny",
      code: "guardrail_policy_unavailable",
      message: `guardrail policy store is unavailable: ${
        error instanceof Error ? error.message : "read error"
      }`,
      policyId: "",
      policyRevision: 0,
      actionKind: "block",
      findingCount: 0,
    };
  }
  if (policies.length === 0) return { outcome: "allow" };

  const source = input.stage === "request" ? "user" : "assistant";
  const location =
    input.stage === "request" ? `a2a:${input.agentId}/message` : `a2a:${input.agentId}/response`;
  const envelope = envelopeFromText("a2a", input.stage, source, location, input.text);

  return screenGuardrailPolicies({
    policies,
    selection: { organization_id: input.tenantId, provider: input.agentId },
    stage: input.stage,
    streaming: input.streaming,
    input: {
      protocol: "a2a",
      stage: input.stage,
      // `DetectorTenant` has no tenant field of its own — Rust attributes a
      // guardrail evaluation by ORGANIZATION.
      tenant: { organization_id: input.tenantId },
      provider: input.agentId,
      text: flattenedText(envelope),
      segments: [...envelope.segments],
    },
  });
}

/**
 * The A2A {@link GuardrailPort} bound to the durable activated revisions, with
 * the var-driven detector as the second authority.
 *
 * ORDER IS LOAD-BEARING: the durable policy runs FIRST. A tenant-scoped
 * activated revision must not be reachable-around by a deployment whose own var
 * happens to allow the content, and a var-only deployment keeps behaving
 * exactly as it did because `fallback` still runs whenever the durable half
 * allowed.
 */
export function durableA2aGuardrailPort(
  env: A2aGuardrailBindings,
  fallback: GuardrailPort,
): GuardrailPort {
  return {
    async evaluate(input: GuardrailEvaluation): Promise<GuardrailDecision> {
      const decision = await screenA2aAgainstDurablePolicies(env, input);
      if (decision.outcome === "deny") {
        return {
          outcome: "deny",
          denial: {
            detector: A2A_DURABLE_DETECTOR_ID,
            stage: input.stage,
            // The OPERATOR's code, which is what makes "the gateway blocks it
            // and A2A blocks it with the same code" expressible at all.
            code: decision.code,
            // The operator's message. Never the matched text: a refusal that
            // quoted the secret it caught would defeat the detector.
            message: decision.message,
          },
        };
      }
      return fallback.evaluate(input);
    },
  };
}
