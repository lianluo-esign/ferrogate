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
export type PolicyDecision = { kind: "allow" } | { kind: "deny"; code: string; message: string };

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
 * ## THE "IMPLEMENTED BUT NEVER MOUNTED" MARKER IS CLOSED — do not re-add it
 *
 * It read: "operator `[[policies]]` are VALIDATED at load and NEVER ENFORCED …
 * `grep -rn "BasicPolicyEngine\|PolicyDecision\|PolicySubject" apps/` returns
 * ZERO hits", with the consequence "an operator writes a deny rule, the config
 * loads clean, the admin surface shows it, and every request it names is
 * ALLOWED."
 *
 * That grep is no longer zero. `apps/gateway/src/ratelimit/policy.ts`
 * value-imports `BasicPolicyEngine`, `PolicyDecision`, `PolicyRule` and
 * `denyRule` from this package, compiles the validated `[[policies]]` section
 * into rules, and evaluates the engine inside `rateLimit()` — the admission
 * middleware every deployed operation passes through — rendering a
 * `PolicyDecision` deny as **403** carrying the rule's own `code` and
 * `message`, exactly as Rust's five AI handlers do.
 *
 * Two deliberate, documented deltas from Rust, both recorded at the mount site
 * rather than here: the evaluation sits in the admission middleware instead of
 * being repeated in each handler (so a sixth handler cannot forget it), which
 * means a request tripping BOTH a guardrail and a deny rule reports the deny
 * rule where Rust reports the guardrail. Both are a 403 naming the cause and
 * neither admits an upstream call, so no request is admitted that Rust would
 * have refused.
 *
 * The engine still cannot express what a per-key `allowedModels`/`deniedModels`
 * check expresses and vice versa — they are different mechanisms with different
 * sources (config section vs. the D1 `api_keys` row), and both are now live.
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
