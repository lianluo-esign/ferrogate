/**
 * The two fingerprints that INVALIDATE cached bodies when the rules that
 * produced them change.
 *
 * ## 1. `guardrail_policy_fingerprint` — issue #233, and the reason a response
 * cache is a guardrail concern at all
 *
 * Rust mixes a fingerprint of the ACTIVE GUARDRAIL POLICY SET into every cache
 * key (`state.rs:1520`, `state_routing.rs:281`). Without it the cache is a
 * policy-bypass primitive: an operator tightens a Response-stage redaction rule,
 * and the gateway keeps serving the pre-tightening body — unredacted — for the
 * whole TTL, because a cache HIT returns before response screening runs. (It
 * does in this port too: `middleware/response-cache.ts` is mounted after the
 * guardrail middleware and short-circuits the route, exactly as Rust's
 * `return write_raw_response(...)` short-circuits `chat.rs`.) Rotating the key
 * on every policy change is what makes that safe, so the fingerprint is not
 * optional bookkeeping — it is the control.
 *
 * Policies reach the gateway from two places, and BOTH are folded in:
 *
 *   - the `GATEWAY_GUARDRAIL_POLICIES` / `GATEWAY_GUARDRAIL_BINDINGS` vars,
 *     hashed verbatim (a var edit is a redeploy, so this half is exact); and
 *   - the DURABLE `guardrail_policy_bindings` rows in `CONTROL_DB`, read
 *     through the same `D1GuardrailPolicyStore.listBindings()` the guardrail
 *     middleware's own store uses. Each row contributes
 *     `policy_id@active_revision#generation`, so an activation, a CAS bump, an
 *     archive or a restore all rotate the fingerprint.
 *
 * The durable read is memoized **per `env` object**, i.e. once per isolate,
 * which is the same staleness the guardrail ENGINE itself has (`guardrails()`
 * memoizes its resolved deps on `env` for the same reason: D1 has no
 * synchronous read and paying a query per request is not viable). The cache can
 * therefore never be staler than the screening it is standing in for — the
 * property that matters — and both refresh together when the isolate recycles.
 *
 * A durable read FAILURE returns `null`, and the middleware treats `null` as
 * "do not read and do not write the cache" — fail closed. A gateway that cannot
 * tell which policies are active must not serve a body screened under unknown
 * ones.
 *
 * ## 2. `registryFingerprint` — the stand-in for Rust's `provider` /
 * `provider_model` key fields
 *
 * See the header of `./key.ts`. A digest of the `GATEWAY_PROVIDERS` +
 * `GATEWAY_MODELS` vars the model registry is built from, so re-pointing a
 * logical model at a different provider or a different physical model rotates
 * every key that names it.
 */
import { D1GuardrailPolicyStore } from "../guardrails/d1.js";
import { sha256Hex } from "./key.js";

/** Vars whose CONTENT decides which physical route a logical model resolves to. */
export const MODEL_REGISTRY_VARS = ["GATEWAY_PROVIDERS", "GATEWAY_MODELS"] as const;
/** Vars carrying statically-declared guardrail policies + bindings. */
export const GUARDRAIL_POLICY_VARS = [
  "GATEWAY_GUARDRAIL_POLICIES",
  "GATEWAY_GUARDRAIL_BINDINGS",
] as const;

function varMaterial(env: Record<string, unknown>, names: readonly string[]): string {
  return JSON.stringify(names.map((name) => [name, String(env[name] ?? "")]));
}

/**
 * A per-`env` memo table.
 *
 * Keyed by the env OBJECT (a `WeakMap`, so an isolate that serves many
 * deployments does not leak) because that is the unit `guardrails()` and the
 * asset/metering sinks already memoize on: one `env` is one deployment's
 * bindings, and a Worker gets a fresh one per request but with stable identity
 * within an isolate for a given deployment.
 */
const FINGERPRINT_MEMO = new WeakMap<object, Promise<string | null>>();

/**
 * `guardrail_policy_fingerprint` for this deployment, or `null` when the
 * durable policy table could not be read.
 */
export function guardrailPolicyFingerprint(env: Record<string, unknown>): Promise<string | null> {
  const memoKey = env as object;
  const memo = FINGERPRINT_MEMO.get(memoKey);
  if (memo !== undefined) return memo;
  const computed = computeGuardrailPolicyFingerprint(env);
  FINGERPRINT_MEMO.set(memoKey, computed);
  return computed;
}

async function computeGuardrailPolicyFingerprint(
  env: Record<string, unknown>,
): Promise<string | null> {
  const staticMaterial = varMaterial(env, GUARDRAIL_POLICY_VARS);

  const durable = D1GuardrailPolicyStore.fromEnv(env);
  if (durable === null) {
    return await sha256Hex(JSON.stringify(["vars-only", staticMaterial]));
  }

  let durableMaterial: string;
  try {
    const bindings = await durable.listBindings();
    durableMaterial = JSON.stringify(
      [...bindings]
        .map((binding) => `${binding.policyId}@${binding.activeRevision}#${binding.generation}`)
        .sort(),
    );
  } catch {
    // Fail CLOSED. Returning a fingerprint computed from the var half alone
    // would let a durable policy change go unnoticed, which is the exact
    // bypass #233 exists to prevent.
    return null;
  }

  return await sha256Hex(JSON.stringify(["vars+d1", staticMaterial, durableMaterial]));
}

/** Digest of the model-registry vars. See the header. */
export function modelRegistryFingerprint(env: Record<string, unknown>): Promise<string> {
  return sha256Hex(varMaterial(env, MODEL_REGISTRY_VARS));
}

/** Drop the memo — for tests that change `CONTROL_DB` state within one isolate. */
export function resetGuardrailPolicyFingerprintMemo(env: Record<string, unknown>): void {
  FINGERPRINT_MEMO.delete(env as object);
}
