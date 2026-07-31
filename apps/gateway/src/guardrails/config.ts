/**
 * Worker-var → guardrail deps.
 *
 * The Rust read `[[guardrails]]` out of the config file and the durable
 * `guardrail_policy_revisions` + `guardrail_policy_bindings` rows out of
 * Supabase, and rebuilt the whole `AppState.guardrail_policies` snapshot on
 * reload. On Workers the config file is a JSON var and the durable half is D1;
 * this module covers the var half so the middleware is runnable and testable
 * with zero bindings.
 *
 * PORT-TODO(inventory-data-billing §guardrail_policy_bindings): the durable
 * revision/binding tables move to the D1 control database, read through
 * `@ferrogate/storage`. `binding.ts` already holds the generation-guarded CAS
 * algorithm those writes need; only the row I/O is missing.
 */
import { type PolicyRevision, policyRevisionSchema } from "@ferrogate/guardrails";
import type { WorkersAiBinding } from "@ferrogate/guardrails";
import {
  InMemoryGuardrailPolicyStore,
  emptyPolicySource,
  policySourceFromStore,
} from "./binding.js";
import { secretsFromEnv } from "./detectors.js";
import type { DetectorBuildContext } from "./detectors.js";
import { InMemoryGuardrailEvidenceSink } from "./evidence.js";
import type { GuardrailMiddlewareOptions } from "./middleware.js";

/** JSON array of `PolicyRevision` documents. */
export const GUARDRAIL_POLICY_VAR = "GATEWAY_GUARDRAIL_POLICIES";
/** JSON array of `{ policy_id, active_revision }` binding rows. */
export const GUARDRAIL_BINDING_VAR = "GATEWAY_GUARDRAIL_BINDINGS";
/** Worker SECRET holding the evidence HMAC key. Never a plain var. */
export const GUARDRAIL_EVIDENCE_KEY_VAR = "GUARDRAIL_EVIDENCE_HMAC_KEY";

interface BindingVarRow {
  readonly policy_id: string;
  readonly active_revision: number;
}

function parseArray(value: unknown, name: string): unknown[] {
  if (typeof value !== "string" || value.trim().length === 0) {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new Error(`${name} is not valid JSON: ${String(error)}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`${name} must be a JSON array`);
  }
  return parsed;
}

/**
 * Build the policy source from the two vars.
 *
 * A malformed policy document is a HARD failure, not a skip: silently dropping
 * an unparsable guardrail policy is the exact "silent pass" the appendix
 * forbids. The Rust `compile_static_guardrail` behaved the same way — a policy
 * that fails `revision.validate()` aborts the config load.
 */
export function guardrailPolicySourceFromEnv(
  env: Record<string, unknown>,
  detectorContext: DetectorBuildContext = {},
): ReturnType<typeof policySourceFromStore> {
  const revisions = parseArray(env[GUARDRAIL_POLICY_VAR], GUARDRAIL_POLICY_VAR);
  if (revisions.length === 0) {
    return emptyPolicySource;
  }
  const store = new InMemoryGuardrailPolicyStore();
  const parsed: PolicyRevision[] = revisions.map(
    (document) => policyRevisionSchema.parse(document) as PolicyRevision,
  );
  for (const revision of parsed) {
    store.putRevision(revision);
  }

  const bindingRows = parseArray(env[GUARDRAIL_BINDING_VAR], GUARDRAIL_BINDING_VAR) as
    | BindingVarRow[]
    | [];
  // With no explicit binding var every declared revision is treated as active
  // (that is what a static `[[guardrails]]` table meant: config IS the binding).
  const bindings: BindingVarRow[] =
    bindingRows.length > 0
      ? bindingRows
      : parsed.map((revision) => ({
          policy_id: revision.policy_id,
          active_revision: revision.revision,
        }));

  for (const row of bindings) {
    const result = store.activate(row.policy_id, row.active_revision, 0, "worker_var");
    if (!result.ok) {
      throw new Error(
        `guardrail policy binding ${row.policy_id}@${row.active_revision} could not be activated: ${result.detail}`,
      );
    }
  }

  return policySourceFromStore(store, {
    secrets: secretsFromEnv(env),
    ...detectorContext,
  });
}

/** Default {@link GuardrailMiddlewareOptions} for a Worker `env`. */
export function guardrailDepsFromEnv(env: Record<string, unknown>): GuardrailMiddlewareOptions {
  const ai = env.AI as WorkersAiBinding | undefined;
  const policies = guardrailPolicySourceFromEnv(env, ai !== undefined ? { workersAi: ai } : {});
  const key = env[GUARDRAIL_EVIDENCE_KEY_VAR];
  return {
    policies,
    evidence: new InMemoryGuardrailEvidenceSink(),
    ...(typeof key === "string" && key.length > 0
      ? { evidenceHmacKey: new TextEncoder().encode(key) }
      : {}),
  };
}
