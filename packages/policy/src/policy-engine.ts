/**
 * Basic rule-based policy engine (port of `ferrogate-policy` `lib.rs`).
 *
 * First matching rule wins; default Allow. A `PolicyRule` matches when its
 * `PolicySubject` matches the tenant (each of organization/project/api-key id is
 * either absent = wildcard or must equal the tenant's value), AND the model is in
 * `models` (empty = any) AND the provider is in `providers` (empty = any).
 */
import type { RequestContext, TenantContext } from "@ferrogate/core";

/** The two-valued policy outcome (Rust `PolicyDecision`). */
export type PolicyDecision =
  | { kind: "allow" }
  | { kind: "deny"; code: string; message: string };

/** The Allow singleton. */
export const ALLOW: PolicyDecision = { kind: "allow" };

/** Construct a Deny decision. */
export function deny(code: string, message: string): PolicyDecision {
  return { kind: "deny", code, message };
}

/** Which tenant a rule applies to. Each field absent ⇒ wildcard. */
export interface PolicySubject {
  organizationId?: string;
  projectId?: string;
  apiKeyId?: string;
}

/** One deny rule: subject × model allowlist × provider allowlist ⇒ code/message. */
export interface PolicyRule {
  subject: PolicySubject;
  /** Empty ⇒ any model. */
  models: string[];
  /** Empty ⇒ any provider. */
  providers: string[];
  code: string;
  message: string;
}

/** Build a deny rule (mirrors `PolicyRule::deny`). */
export function denyRule(
  subject: PolicySubject,
  models: string[],
  providers: string[],
  code: string,
  message: string,
): PolicyRule {
  return { subject, models, providers, code, message };
}

/** An `expected` constraint matches when it is absent, or equals `actual`. */
function matchesOptionalValue(expected: string | undefined, actual: string | undefined): boolean {
  return expected === undefined || expected === actual;
}

/** An allowlist matches when empty, or `actual` is present and in the list. */
function matchesOptionalList(expected: string[], actual: string | undefined): boolean {
  return expected.length === 0 || (actual !== undefined && expected.includes(actual));
}

function subjectMatches(subject: PolicySubject, tenant: TenantContext): boolean {
  return (
    matchesOptionalValue(subject.organizationId, tenant.organization_id) &&
    matchesOptionalValue(subject.projectId, tenant.project_id) &&
    matchesOptionalValue(subject.apiKeyId, tenant.api_key_id)
  );
}

function ruleEvaluate(
  rule: PolicyRule,
  tenant: TenantContext,
  model: string | undefined,
  provider: string | undefined,
): PolicyDecision | undefined {
  if (!subjectMatches(rule.subject, tenant)) return undefined;
  if (!matchesOptionalList(rule.models, model)) return undefined;
  if (!matchesOptionalList(rule.providers, provider)) return undefined;
  return deny(rule.code, rule.message);
}

/** A policy engine evaluates a request into an Allow/Deny decision. */
export interface PolicyEngine {
  evaluate(
    request: RequestContext,
    model: string | undefined,
    provider: string | undefined,
  ): PolicyDecision;
}

/**
 * First-match-wins rule engine over an ordered rule list (Rust `BasicPolicyEngine`).
 *
 * PORT-TODO(inventory-policy-core §2.4a) — IMPLEMENTED BUT NEVER MOUNTED.
 * REAL GAP: operator `[[policies]]` are VALIDATED at load and NEVER ENFORCED.
 *
 * The algorithm below is a 1:1 port and is covered by `test/policy-engine.test.ts`,
 * but nothing constructs it. In Rust the composition root is
 * `crates/ferrogate-gateway/src/state.rs::build_policy_engine(&config.policies)`
 * (state.rs:7079), stored as `policy_engine: Arc<BasicPolicyEngine>` (state.rs:1516)
 * and evaluated per request in `state_quota_and_policy.rs`. On the TS side
 * `grep -rn "BasicPolicyEngine\|PolicyDecision\|PolicySubject" apps/` returns
 * ZERO hits, while `packages/config` fully validates the `[[policies]]` section
 * (`validatePolicies` cross-checks every rule's api-key / model / provider id).
 *
 * Consequence, stated plainly: an operator writes a deny rule, the config loads
 * clean, the admin surface shows it, and every request it names is ALLOWED. This
 * is the repo's recurring "fully implemented, fully tested, never mounted" defect
 * — the config-driven deny path is not the same thing as the per-key
 * `allowedModels`/`deniedModels` check in `apps/gateway/src/inference/ports.ts`,
 * which is sourced from the D1 `api_keys` row and cannot express a
 * `(subject × models × providers)` rule.
 *
 * TO CLOSE (gateway-owned, outside this package):
 *   1. build the engine from `config.policies` in the gateway composition root;
 *   2. evaluate it after auth + before dispatch, mapping `deny` → the rule's
 *      `{code, message}`;
 *   3. add a wiring assertion that FAILS when the engine is unmounted (a config
 *      with one deny rule must produce a denied response), and prove it RED by
 *      deleting the call — per the composition-root rule, a green suite with an
 *      unmounted engine is the exact failure this marker exists to prevent.
 */
export class BasicPolicyEngine implements PolicyEngine {
  readonly rules: PolicyRule[];

  constructor(rules: PolicyRule[] = []) {
    this.rules = rules;
  }

  evaluate(
    request: RequestContext,
    model: string | undefined,
    provider: string | undefined,
  ): PolicyDecision {
    for (const rule of this.rules) {
      const decision = ruleEvaluate(rule, request.tenant, model, provider);
      if (decision !== undefined) return decision;
    }
    return ALLOW;
  }
}
