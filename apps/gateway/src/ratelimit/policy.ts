/**
 * Operator deny rules — `@ferrogate/policy`'s `BasicPolicyEngine`, mounted.
 *
 * ## What was wrong before this file existed
 *
 * `packages/policy/src/policy-engine.ts` carries a 1:1 port of the Rust
 * `BasicPolicyEngine` with its own passing tests, and `packages/config`
 * fully validates the `[[policies]]` section — `validatePolicies` cross-checks
 * every rule's api-key / model / provider id against the rest of the config, so
 * a typo is a load-time failure. Between those two there was NOTHING:
 * `grep -rn "BasicPolicyEngine" apps/` returned zero hits.
 *
 * The consequence, quoted from the marker this file closes: "an operator writes
 * a deny rule, the config loads clean, the admin surface shows it, and every
 * request it names is ALLOWED."
 *
 * ## Where the evaluation sits, and why here
 *
 * Rust evaluates in each AI handler, right after guardrail screening and right
 * before dispatch (`server/chat.rs:421`, and the identical block in
 * `messages.rs` / `embeddings.rs` / `images.rs` / `state_tools.rs`), rendering a
 * `PolicyDecision::Deny` as **403** with the rule's own `code` and `message`.
 *
 * This port evaluates in `rateLimit()`, i.e. in the admission middleware, for
 * two reasons that are both about coverage rather than convenience:
 *
 *  1. Rust repeats the block in five handlers; a middleware states it once and
 *     cannot be forgotten by the sixth.
 *  2. `apps/gateway/src/inference/handlers.ts` is not this slice's file. A seam
 *     that had to be called from there would be exactly the un-mounted shape
 *     this whole wave exists to remove.
 *
 * The observable difference from Rust is ORDER: a request that both trips a
 * guardrail and a deny rule answers the deny rule here and the guardrail in
 * Rust. Both are 403 with a code naming the cause, and no upstream is called in
 * either case, so no request is admitted that Rust would have refused and none
 * is refused that Rust would have admitted. The reverse order is not available:
 * `GATEWAY_MIDDLEWARE` mounts `rateLimit` ahead of `guardrails` because the
 * Rust ingress charges the quota windows before it screens content, and moving
 * the whole limiter behind screening to reorder one check would spend detector
 * work — including paid provider calls — on unadmitted requests.
 *
 * ## Reading the model without disturbing the body
 *
 * A rule may name `models` and `providers`, which are not known until the
 * request document is parsed — and the middleware runs before the handler
 * parses it. The body is therefore read from a `Request.clone()` with a byte
 * cap, exactly as `src/guardrails/middleware.ts` does, so Hono's body cache and
 * the downstream `payload_too_large` / `invalid_json` behaviour are untouched.
 *
 * That read is SKIPPED entirely unless at least one enabled rule actually
 * constrains a model or a provider ({@link PolicyRuleSet.needsRequestDocument}).
 * A deployment whose rules are subject-only — or which has no rules at all,
 * which is every deployment today — pays nothing.
 */
import { type PolicyRule as ConfigPolicyRule, policyRuleSchema } from "@ferrogate/config";
import type { RequestContext, TenantContext } from "@ferrogate/core";
import { BasicPolicyEngine, type PolicyDecision, type PolicyRule, denyRule } from "@ferrogate/policy";
import type { Context } from "hono";
import { modelsFromEnv } from "../inference/catalog.js";
import type { AuthContext, GatewayEnv } from "../ports.js";

/** Bindings this module reads. */
export interface PolicyBindings {
  /**
   * JSON array of `[[policies]]` rules, in the SAME wire shape
   * `packages/config` parses and `ferrogate check` validates — this module
   * parses it with that package's own `policyRuleSchema` rather than restating
   * the field list, so the two cannot drift.
   *
   * Absent/empty ⇒ no rule denies. MALFORMED ⇒ every request is refused with
   * 503 `policy_rules_unavailable`; see {@link policyRulesFromEnv}.
   */
  readonly GATEWAY_POLICY_RULES?: string | undefined;
}

/** The compiled rules, plus what evaluating them costs. */
export interface PolicyRuleSet {
  readonly engine: BasicPolicyEngine;
  /**
   * True when some rule constrains `models` or `providers`, i.e. when the
   * request document has to be read to decide. False ⇒ subject-only rules,
   * decidable from the credential alone.
   */
  readonly needsRequestDocument: boolean;
}

/** A rule set that denies nothing and reads nothing. */
export const NO_POLICY_RULES: PolicyRuleSet = {
  engine: new BasicPolicyEngine([]),
  needsRequestDocument: false,
};

/** Failure to READ the rules — deliberately not the same thing as "no rules". */
export interface PolicyRulesUnavailable {
  readonly ok: false;
  readonly detail: string;
}

export type PolicyRulesResolution = { readonly ok: true; readonly rules: PolicyRuleSet } | PolicyRulesUnavailable;

/**
 * Expand one config rule into the cross-product of its subject lists — the port
 * of Rust `build_policy_engine` + `expand_optional_subjects` (`state.rs:7079`).
 *
 * An EMPTY list is one `undefined` subject facet, i.e. a wildcard, not "matches
 * nothing". Getting that backwards turns a tenant-wide deny into a no-op, which
 * is the failure direction that costs the operator their policy.
 */
export function expandPolicyRule(rule: ConfigPolicyRule): PolicyRule[] {
  const optional = (values: readonly string[]): (string | undefined)[] =>
    values.length === 0 ? [undefined] : [...values];

  const expanded: PolicyRule[] = [];
  for (const organizationId of optional(rule.organization_ids)) {
    for (const projectId of optional(rule.project_ids)) {
      for (const apiKeyId of optional(rule.api_key_ids)) {
        expanded.push(
          denyRule(
            {
              ...(organizationId === undefined ? {} : { organizationId }),
              ...(projectId === undefined ? {} : { projectId }),
              ...(apiKeyId === undefined ? {} : { apiKeyId }),
            },
            [...rule.models],
            [...rule.providers],
            rule.code,
            rule.message,
          ),
        );
      }
    }
  }
  return expanded;
}

/**
 * Compile config rules into an engine.
 *
 * `enabled = false` and any `effect` other than `deny` are dropped here exactly
 * as Rust's filter drops them. `validatePolicies` already refuses a non-`deny`
 * effect at load, so this is the second of two gates, not the only one.
 */
export function compilePolicyRules(rules: readonly ConfigPolicyRule[]): PolicyRuleSet {
  const enabled = rules.filter(
    (rule) => rule.enabled && rule.effect.toLowerCase() === "deny",
  );
  const compiled = enabled.flatMap(expandPolicyRule);
  return {
    engine: new BasicPolicyEngine(compiled),
    needsRequestDocument: enabled.some(
      (rule) => rule.models.length > 0 || rule.providers.length > 0,
    ),
  };
}

/**
 * Parse `GATEWAY_POLICY_RULES`.
 *
 * ## Malformed input FAILS CLOSED, and this is the one place in the limiter
 * where "fail closed" means something different
 *
 * `quota.ts::parseJsonVar` treats an unreadable var as "nothing configured",
 * and that is correct THERE: a quota policy only ever imposes a limit, so
 * losing one can leave a limit unset but can never raise one. A DENY rule is
 * the opposite — losing it grants access. So an unparseable rule table cannot
 * degrade to an empty engine; it answers `503 policy_rules_unavailable` and
 * refuses everything until an operator fixes it.
 *
 * An ABSENT or empty var is not malformed: it means the operator configured no
 * rules, which is a valid, allow-everything posture (and the shipped default).
 */
export function policyRulesFromEnv(env: PolicyBindings): PolicyRulesResolution {
  const raw = env.GATEWAY_POLICY_RULES;
  if (raw === undefined || raw.trim() === "") return { ok: true, rules: NO_POLICY_RULES };

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { ok: false, detail: `GATEWAY_POLICY_RULES is not valid JSON: ${detail}` };
  }
  if (!Array.isArray(parsed)) {
    return { ok: false, detail: "GATEWAY_POLICY_RULES must be a JSON array of policy rules" };
  }

  const rules: ConfigPolicyRule[] = [];
  for (let index = 0; index < parsed.length; index += 1) {
    const result = policyRuleSchema.safeParse(parsed[index]);
    if (!result.success) {
      const issue = result.error.issues[0];
      const at = issue === undefined ? "" : ` at ${issue.path.join(".")}`;
      return {
        ok: false,
        detail: `GATEWAY_POLICY_RULES[${index}] is not a policy rule${at}: ${
          issue?.message ?? "invalid"
        }`,
      };
    }
    rules.push(result.data);
  }
  return { ok: true, rules: compilePolicyRules(rules) };
}

/** How the middleware gets its rules. Resolved once per `env`, then memoized. */
export type PolicyRulesResolver = (env: PolicyBindings) => PolicyRulesResolution;

/**
 * `TenantContext` for the policy subject, from the authenticated credential.
 *
 * `organization_id` IS the tenant id (`packages/core/src/context.ts`), and
 * `api_key_id` is the credential's own subject — which is what makes a
 * per-key deny rule a per-key deny rule.
 */
export function policyTenantFrom(auth: AuthContext): TenantContext {
  const tenantId = auth.tenancy.tenantId;
  const projectId = auth.tenancy.projectId;
  const workspaceId = auth.tenancy.workspaceId;
  return {
    ...(tenantId === null || tenantId === undefined ? {} : { organization_id: tenantId }),
    ...(projectId === null || projectId === undefined ? {} : { project_id: projectId }),
    ...(workspaceId === null || workspaceId === undefined ? {} : { workspace_id: workspaceId }),
    ...(auth.subject === null ? {} : { api_key_id: auth.subject }),
  };
}

/** The `RequestContext` Rust builds for `evaluate_policy`. */
export function policyRequestFrom(requestId: string, auth: AuthContext): RequestContext {
  return { request_id: requestId, tenant: policyTenantFrom(auth) };
}

/**
 * Read `{ model }` off a bounded clone of the request body.
 *
 * Returns `undefined` for a body that is not JSON, is over the cap, or has no
 * string `model` — in every one of those cases a model-scoped rule simply does
 * not match, which is the same answer Rust gives when it evaluates with
 * `model: None`. Never throws, and never touches the original request.
 */
export async function requestModel(
  request: Request,
  maxBytes: number,
): Promise<string | undefined> {
  if (request.body === null) return undefined;
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("json")) return undefined;

  const declared = Number(request.headers.get("content-length") ?? Number.NaN);
  if (Number.isFinite(declared) && declared > maxBytes) return undefined;

  try {
    const text = await request.clone().text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) return undefined;
    const document: unknown = JSON.parse(text);
    if (typeof document !== "object" || document === null) return undefined;
    const model = (document as { model?: unknown }).model;
    return typeof model === "string" ? model : undefined;
  } catch {
    return undefined;
  }
}

/** Default cap for {@link requestModel} — the Rust `limits.inference_body_max_bytes`. */
export const POLICY_MAX_REQUEST_BYTES = 1024 * 1024;

/**
 * Evaluate the rule set for one request.
 *
 * `model`/`provider` are resolved only when {@link PolicyRuleSet.needsRequestDocument}
 * says a rule cares, so a subject-only rule table costs one array walk and no
 * I/O at all.
 */
export async function evaluatePolicyRules(
  c: Context<GatewayEnv>,
  auth: AuthContext,
  rules: PolicyRuleSet,
  options: EvaluatePolicyOptions = {},
): Promise<PolicyDecision> {
  const request = policyRequestFrom(c.get("requestId") ?? "", auth);
  if (!rules.needsRequestDocument) {
    return rules.engine.evaluate(request, undefined, undefined);
  }

  const model = await requestModel(c.req.raw, options.maxRequestBytes ?? POLICY_MAX_REQUEST_BYTES);
  // The provider comes from the SAME registry the dispatcher resolves against,
  // so a provider-scoped rule names the provider the request would really have
  // reached. An unresolvable model yields no provider, and a provider-scoped
  // rule then does not match — the Rust reading of `provider: None`.
  const resolveProvider = options.providerForModel ?? defaultProviderForModel;
  const provider = model === undefined ? undefined : resolveProvider(model, c.env);
  return rules.engine.evaluate(request, model, provider);
}

/** Tunables for {@link evaluatePolicyRules}. */
export interface EvaluatePolicyOptions {
  readonly providerForModel?: ((model: string, env: unknown) => string | undefined) | undefined;
  readonly maxRequestBytes?: number | undefined;
}

/** The config-var model registry — the same one `src/index.ts` gives the dispatcher. */
export function defaultProviderForModel(model: string, env: unknown): string | undefined {
  return modelsFromEnv(env as never).resolve(model)?.provider ?? undefined;
}
