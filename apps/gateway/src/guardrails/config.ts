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
 * Both halves are live. The var half is below; the DURABLE half is
 * `D1GuardrailPolicyStore` (`./d1.ts`) over the CONTROL D1 —
 * `guardrail_policy_revisions` + `guardrail_policy_bindings`, with the
 * generation-guarded CAS `binding.ts` defines — and the two are merged by
 * {@link guardrailPolicySourceFromEnv}: durable rows are ADDITIVE to the config
 * table, so a config-only deployment behaves exactly as it did.
 */
import { type PolicyRevision, policyRevisionSchema } from "@ferrogate/guardrails";
import type { WorkersAiBinding } from "@ferrogate/guardrails";
import {
  InMemoryGuardrailPolicyStore,
  emptyPolicySource,
  policySourceFromStore,
} from "./binding.js";
import { D1GuardrailPolicyStore, loadGuardrailPolicyStore } from "./d1.js";
import { secretsFromEnv } from "./detectors.js";
import type { DetectorBuildContext } from "./detectors.js";
import {
  DurableGuardrailEvidenceSink,
  guardrailEvidenceDatabaseFrom,
  guardrailEvidenceQueueFrom,
} from "./evidence-sink.js";
import { InMemoryGuardrailEvidenceSink } from "./evidence.js";
import type { GuardrailDepsResolver, GuardrailMiddlewareOptions } from "./middleware.js";
import type { GuardrailEvidenceSink, GuardrailPolicySource } from "./ports.js";

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
): GuardrailPolicySource {
  const store = guardrailPolicyStoreFromEnv(env);
  if (store === undefined) {
    return emptyPolicySource;
  }
  return policySourceFromStore(store, {
    secrets: secretsFromEnv(env),
    ...detectorContext,
  });
}

/**
 * The var half as a STORE rather than a compiled source, so the durable half
 * can be layered on top of the same object before anything is compiled.
 *
 * `undefined` — not an empty store — when no policy var is set, which is what
 * lets {@link guardrailPolicySourceFromEnv} keep returning the shared
 * {@link emptyPolicySource} singleton for the unconfigured case.
 */
export function guardrailPolicyStoreFromEnv(
  env: Record<string, unknown>,
): InMemoryGuardrailPolicyStore | undefined {
  const revisions = parseArray(env[GUARDRAIL_POLICY_VAR], GUARDRAIL_POLICY_VAR);
  if (revisions.length === 0) {
    return undefined;
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

  return store;
}

/**
 * Default {@link GuardrailMiddlewareOptions} for a Worker `env`.
 *
 * Returns a PROMISE when — and only when — the CONTROL D1 is bound and the
 * durable revision/binding tables have to be read. With no `CONTROL_DB` the
 * value is returned synchronously and the behaviour is exactly what it was
 * before the durable half landed, which is what keeps every var-driven caller
 * and test unchanged. `guardrails()` accepts either (see
 * {@link GuardrailDepsResolver}).
 *
 * A durable read FAILURE is not caught here. The rejection reaches the
 * middleware, which lets it become a 5xx: an engine built from a policy set
 * that half-loaded would screen with rules silently missing, and passing
 * unscreened content to a provider is the one outcome the guardrail exists to
 * prevent.
 */
export function guardrailDepsFromEnv(
  env: Record<string, unknown>,
): GuardrailMiddlewareOptions | Promise<GuardrailMiddlewareOptions> {
  const ai = env.AI as WorkersAiBinding | undefined;
  const detectorContext: DetectorBuildContext = ai !== undefined ? { workersAi: ai } : {};
  const durable = D1GuardrailPolicyStore.fromEnv(env);

  if (durable === null) {
    return guardrailOptions(env, guardrailPolicySourceFromEnv(env, detectorContext));
  }

  // Which policies came out of the DURABLE control tables, as opposed to this
  // deployment's own `GATEWAY_GUARDRAIL_POLICIES` var. Only the durable ones may
  // fail closed instead of failing the boot: they are another Worker's runtime
  // input, while a mistyped secret ref in the operator's own deploy config must
  // still be a startup error rather than a policy that refuses every request.
  const durablePolicyIds = new Set<string>();
  return loadGuardrailPolicyStore(durable, guardrailPolicyStoreFromEnv(env), {
    onDurablePolicy: (policyId) => durablePolicyIds.add(policyId),
  }).then((store) =>
    guardrailOptions(
      env,
      policySourceFromStore(
        store,
        { secrets: secretsFromEnv(env), ...detectorContext },
        { failClosedPolicyIds: durablePolicyIds },
      ),
    ),
  );
}

/**
 * The evidence sink for a Worker `env` (#665).
 *
 * DURABLE whenever a destination is bound — the `REQUEST_LOG` queue,
 * `TENANT_DATA`, or the `CONTROL_DB` projection — and in-memory otherwise.
 *
 * The fork is on the BINDING rather than on a feature flag, deliberately. A
 * deployment with no evidence destination is `wrangler dev --local`, a unit
 * test, or a self-hosted install that has not provisioned D1; installing a
 * durable sink there would count a `dropped` for every screened request and say
 * nothing more useful than the in-memory sink already does. A deployment that
 * HAS the binding has one because an operator provisioned it, and silently not
 * writing to it would reproduce exactly the defect this issue closes.
 */
function guardrailEvidenceSinkFor(env: Record<string, unknown>): GuardrailEvidenceSink {
  const durable =
    guardrailEvidenceQueueFrom(env) !== undefined ||
    guardrailEvidenceDatabaseFrom(env) !== undefined ||
    env.TENANT_DATA !== undefined;
  // Track A / G2: retire the direct-fallback control guardrail mirror write
  // (red line no-tenant-data-mirror-in-control-d1), symmetric with the queue
  // consumer's `projectGuardrailToControl: false` (`src/index.ts`). Tenant
  // objects + PLATFORM_DATA are the sole homes; the control projection now has
  // zero writers and no steady-state reader (only the drain-on-read backfill
  // bridges remain). Reversible by flipping this literal.
  return durable
    ? new DurableGuardrailEvidenceSink({ projectToControl: false })
    : new InMemoryGuardrailEvidenceSink();
}

function guardrailOptions(
  env: Record<string, unknown>,
  policies: GuardrailPolicySource,
): GuardrailMiddlewareOptions {
  const key = env[GUARDRAIL_EVIDENCE_KEY_VAR];
  return {
    policies,
    evidence: guardrailEvidenceSinkFor(env),
    ...(typeof key === "string" && key.length > 0
      ? { evidenceHmacKey: new TextEncoder().encode(key) }
      : {}),
  };
}
