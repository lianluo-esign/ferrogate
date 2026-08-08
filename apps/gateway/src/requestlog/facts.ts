/**
 * How facts that only ONE slice knows reach the one middleware that writes the
 * request log.
 *
 * ## The problem
 *
 * A request log needs facts from three different places in the request path:
 *
 *  - the OUTER middleware chain knows the credential, the operation, the
 *    status, the latency and the cache header — {@link requestLogging} reads
 *    those straight off the Hono context and needs nothing from here;
 *  - the GUARDRAIL middleware is the only thing that knows whether screening
 *    ran and what it decided;
 *  - the INFERENCE router is the only thing that knows which physical route was
 *    chosen, which provider model was called, and how many tokens the provider
 *    reported — and it runs inside a SEPARATE Hono app (`route-module.ts`
 *    delegates with `inner.fetch(c.req.raw, …)`), so `c.set(...)` there is
 *    invisible to the outer chain.
 *
 * ## The carrier, and why it is a `WeakMap` keyed by the `Request`
 *
 * This is the same device `src/inference/identity.ts` already uses to push the
 * authenticated caller INTO the inner app, for the same reasons it gives:
 *
 *  - a module-scoped "current request" slot is a cross-request data leak the
 *    moment two requests interleave on an `await`, and every handler on this
 *    path does. For evidence that is not a glitch, it is one tenant's decision
 *    recorded under another tenant's id;
 *  - a wrapper `env` object would defeat the `WeakMap`-by-env memoization the
 *    model registry and the guardrail engine both rely on.
 *
 * The `Request` object is per-request by construction, is the exact value
 * handed to `inner.fetch`, and is collected with the request — so a `WeakMap`
 * keyed by it is isolated and leak-free.
 *
 * ## Contributions MERGE, and later ones win per field
 *
 * Contributors run at different times (guardrail input screening before
 * dispatch, the usage report at or after the response) and none of them knows
 * the whole record. {@link contributeRequestLogFacts} therefore merges rather
 * than replaces, and it ignores `undefined` values — so a contributor that
 * knows nothing about a field cannot erase what another one already
 * established. That is what makes this an extension point: a later slice adds
 * a field and a contributor, and nothing else in the path changes.
 */
import type { GuardrailVerdict } from "./record.js";

/** The subset of a request log that only an inner slice can know. */
export interface RequestLogFacts {
  readonly route?: string | undefined;
  readonly provider?: string | undefined;
  readonly logicalModel?: string | undefined;
  readonly providerModel?: string | undefined;
  readonly promptTokens?: number | undefined;
  readonly completionTokens?: number | undefined;
  readonly totalTokens?: number | undefined;
  readonly streamed?: boolean | undefined;
  readonly providerAttemptIndex?: number | undefined;
  readonly guardrailVerdict?: GuardrailVerdict | undefined;
  readonly guardrailPolicyId?: string | undefined;
  readonly agentRunId?: string | undefined;
  /**
   * #691 — the VERIFIED delegation chain, rendered
   * (`user:u_1>agent:planner>agent:writer`), and its root principal.
   *
   * Contributed by `src/delegation/middleware.ts` and only ever for a chain
   * that verified: a chain that failed any check refuses the request, so there
   * is no path by which an unverified claim reaches the audit row. That is the
   * property that makes the column evidence rather than an echo of a header.
   */
  readonly delegationChain?: string | undefined;
  readonly delegationRoot?: string | undefined;
  /**
   * #693 — the traffic-split experiment this request belonged to, and the arm
   * that served it (`control` / `canary`).
   *
   * Contributed by the inference router, which is the only thing that knows the
   * model's candidate list AND which candidate answered. Absent for every
   * request whose model declares no canary and no shadow, which is almost all
   * of them: a model with no variant is not an experiment.
   *
   * Never `shadow`. A mirror is stripped from the servable ladder before
   * eligibility runs, so no served response can come from one; the shadow arm's
   * evidence is its own table (`experiment_shadow_legs`), because a leg no
   * client received must not become a row in the record of client requests.
   */
  readonly experimentId?: string | undefined;
  readonly experimentArm?: string | undefined;
  /**
   * #699 — the cost/quality dial's rendered, explainable routing decision.
   *
   * Contributed by the inference router, the only thing that runs the task
   * classifier and knows which candidates cleared the quality floor. Absent for
   * every request whose tenant did not opt the dial in, which keeps the log
   * byte-identical for everyone who did not.
   */
  readonly routingDecision?: string | undefined;
}

const FACTS = new WeakMap<Request, RequestLogFacts>();

/**
 * Merge what this slice learned into the request's fact set.
 *
 * Never throws and never fails a request: it is called from the request path
 * and a logging failure must not become a client-visible one. A `request` that
 * is not an object (a unit test calling a handler directly) is a silent no-op
 * rather than a `TypeError` thrown from inside the guardrail middleware.
 */
export function contributeRequestLogFacts(request: Request, facts: RequestLogFacts): void {
  try {
    const previous = FACTS.get(request) ?? {};
    const merged: Record<string, unknown> = { ...previous };
    for (const [key, value] of Object.entries(facts)) {
      // `undefined` means "I do not know", which must not overwrite a fact
      // another contributor already established.
      if (value !== undefined) merged[key] = value;
    }
    FACTS.set(request, merged as RequestLogFacts);
  } catch {
    // A `WeakMap` rejects a non-object key. Evidence is best-effort at this
    // seam; the row is still written, just without this slice's contribution.
  }
}

/** Everything contributed for this request, or an empty set. */
export function requestLogFactsFor(request: Request): RequestLogFacts {
  try {
    return FACTS.get(request) ?? {};
  } catch {
    return {};
  }
}
