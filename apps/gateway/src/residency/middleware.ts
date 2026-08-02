/**
 * The enforcement seam for #681: resolve the calling tenant's residency policy,
 * refuse what cannot be served inside it, and publish it to the routing layer.
 *
 * ============================================================================
 * WHERE THIS SITS ON THE LADDER
 * ============================================================================
 *
 * `src/index.ts` mounts it between `attributionTags()` and `guardrails()`:
 *
 *   contractAuth → meteringDrain → requestTelemetry → requestLogging
 *                → rateLimit → attributionTags → **residency**
 *                → guardrails → tenantDatabase → responseCache → dispatch
 *
 *  - **AFTER `contractAuth`** — the policy is per-TENANT and the tenant only
 *    exists once the credential resolves. A residency policy keyed on anything
 *    the client asserts would be a policy the client can switch off.
 *  - **AFTER `rateLimit()`** — so a request refused on residency still burns the
 *    caller's admission window. The same argument `attributionTags` makes: a
 *    refusal path ahead of admission is an unmetered flood.
 *  - **BEFORE `guardrails()`** — and this edge is a residency argument, not an
 *    economic one. Guardrail screening can call OUT: an LLM-judge or a hosted
 *    detector receives the prompt itself. Screening a governed prompt before
 *    deciding whether it may leave the region would send the prompt to the
 *    detector's region first and ask afterwards.
 *
 * The refusal is still RECORDED — `requestLogging()` is mounted three layers
 * out and wraps everything below it, so a 403 from here lands in the #664 trail
 * exactly like `rateLimit()`'s 429.
 *
 * ============================================================================
 * WHAT THE DURABLE LOG AND THE METERING ROWS STORE UNDER A POLICY
 * ============================================================================
 *
 * The issue asks this explicitly, so it is answered here rather than left
 * implicit in whichever file happens to write a row.
 *
 *  1. **Neither surface stores prompt or completion CONTENT, today, at all.**
 *     `requestlog/record.ts::RequestLogRecord` is ids, status, latency, model
 *     names and token COUNTS; `metering/event.ts` writes a `billing_events` row
 *     of counts, prices and `metadata` tags. So what a residency policy governs
 *     on these surfaces is request METADATA, not the regulated content. Saying
 *     that plainly matters: a reader who assumed the log held prompts would
 *     draw the wrong conclusion from everything below.
 *  2. **Metadata still has a residence, and a tenant may govern it.**
 *     `logResidency: "in_region"` requires the operator to ASSERT, via
 *     `GATEWAY_LOG_REGION`, which region the durable stores sit in, and the
 *     assertion is verified against the tenant's own region list. The same
 *     modelling as ZDR (`policy.ts`): an unasserted store cannot satisfy an
 *     in-region policy by default, because "nobody said" is not "yes".
 *  3. **A deployment that cannot satisfy it REFUSES, per request.** Not
 *     "writes the row anyway", not "drops the row and serves". #674's rule,
 *     applied again in #690: what cannot be expressed is refused. A dropped row
 *     would ALSO breach the tenant's Art. 12 record-keeping expectation, so
 *     "degrade the log" is not a safe middle — it trades one compliance failure
 *     for another and hides both.
 *  4. **The refusal itself is logged, and that is deliberate.** The row it
 *     produces carries no model, no tokens and no tenant CONTENT — it records
 *     that this gateway refused. An operator who cannot satisfy log residency
 *     needs to see the refusals; a control whose failures are invisible is the
 *     defect this repository keeps finding.
 */
import type { Context, MiddlewareHandler, Next } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";
import { recordResidencyPolicy } from "./carrier.js";
import type { ResidencyPolicy } from "./policy.js";
import {
  type ResidencyBindings,
  type ResidencyPolicySource,
  residencyPolicySourceFromEnv,
} from "./source.js";

/**
 * The operations a residency policy governs: the six that put tenant CONTENT on
 * a provider socket.
 *
 * The five `attribution/middleware.ts::ATTRIBUTED_OPERATION_IDS` names plus
 * `createRerank`, which #676 added and which ships the caller's documents to a
 * reranker — the same egress, and the reason this list is written out rather
 * than imported: the two answer different questions ("is this work
 * attributable" vs "may this content leave the region") and rerank is exactly
 * where they differ.
 *
 * `listModels`, `getModel` and `countMessageTokens` are absent: none dispatches
 * to a provider and none carries a prompt off the isolate. Refusing a catalogue
 * read because the operator has not annotated their model rows would break the
 * pre-flight a client runs while trying to configure residency in the first
 * place.
 */
export const RESIDENCY_GOVERNED_OPERATION_IDS: readonly string[] = [
  "createChatCompletion",
  "createResponse",
  "createMessage",
  "createEmbedding",
  "createImage",
  "createRerank",
];

export interface ResidencyMiddlewareOptions {
  /** Override the policy source. Production reads it from `env`. */
  readonly policies?:
    | ResidencyPolicySource
    | ((env: ResidencyBindings) => ResidencyPolicySource);
  /** Override the governed operation set (tests narrow it). */
  readonly operationIds?: readonly string[];
}

/**
 * Does the deployment's declared log region satisfy this policy?
 *
 * `GATEWAY_LOG_REGION` is an ASSERTION by the operator about where `CONTROL_DB`
 * / the `REQUEST_LOG` queue physically live. Cloudflare exposes no runtime
 * property that would let the Worker verify it — a D1 binding does not report
 * its `location_hint` — so the honest modelling is the ZDR one: the operator
 * asserts, the policy verifies the assertion, and an ABSENT assertion fails.
 * Reading "no assertion" as "wherever the tenant wants" would make this leg
 * satisfied by default on every deployment that has never heard of it.
 */
export function logPlacementSatisfied(
  policy: ResidencyPolicy,
  declaredLogRegion: string | undefined,
): boolean {
  if (policy.logResidency !== "in_region") return true;
  const region = declaredLogRegion?.trim() ?? "";
  if (region === "") return false;
  return policy.allowedRegions.includes(region);
}

/** The message for a log-placement refusal — actionable, and names both sides. */
export function logPlacementMessage(
  policy: ResidencyPolicy,
  declaredLogRegion: string | undefined,
): string {
  const declared = declaredLogRegion?.trim();
  const stated =
    declared === undefined || declared === ""
      ? "this deployment declares no log region (GATEWAY_LOG_REGION is unset)"
      : `this deployment declares its request log in region ${declared}`;
  return (
    `tenant residency policy requires the durable request log to stay within ` +
    `[${[...policy.allowedRegions].join(", ")}], but ${stated}`
  );
}

/**
 * Enforce the calling tenant's residency policy.
 *
 * Inert — one cached lookup and `next()` — for every deployment that has
 * configured no policy, which is every deployment until an operator opts in.
 */
export function residency(
  options: ResidencyMiddlewareOptions = {},
): MiddlewareHandler<GatewayEnv> {
  const governed = new Set(options.operationIds ?? RESIDENCY_GOVERNED_OPERATION_IDS);

  return async function residencyMiddleware(c, next: Next): Promise<void> {
    const operation = (c as Context<GatewayEnv>).get("operation");
    if (operation === null || operation === undefined || !governed.has(operation.operationId)) {
      await next();
      return;
    }

    const auth = c.get("auth");
    if (auth === null || auth === undefined) {
      await next();
      return;
    }

    // The AUTHENTICATED tenant — never a header, never a body field.
    const tenantId = auth.tenancy.tenantId;
    if (tenantId === null || tenantId === undefined || tenantId === "") {
      // A platform-operator or unclassified credential belongs to no tenant, so
      // no per-tenant policy can name it.
      await next();
      return;
    }

    const env = c.env as unknown as ResidencyBindings;
    const source =
      typeof options.policies === "function"
        ? options.policies(env)
        : (options.policies ?? residencyPolicySourceFromEnv(env));

    const resolved = await source.policyFor(tenantId);
    if (!resolved.ok) {
      // An outage OR an unreadable policy row, and both refuse. Admitting here
      // would serve a governed tenant under NO policy — which is precisely the
      // out-of-region request this control exists to prevent, arriving through
      // the back door and succeeding silently. See `./source.ts` on why this
      // fail direction is the opposite of #678's.
      throw new HttpError(
        503,
        "residency_policy_unavailable",
        `residency policy lookup failed: ${resolved.detail}`,
      );
    }
    if (resolved.policy === null) {
      await next();
      return;
    }

    if (!logPlacementSatisfied(resolved.policy, env.GATEWAY_LOG_REGION)) {
      throw new HttpError(
        403,
        "log_residency_unsatisfiable",
        logPlacementMessage(resolved.policy, env.GATEWAY_LOG_REGION),
      );
    }

    // Keyed by the inbound `Request` — the same object `route-module.ts` hands
    // to `inner.fetch` and reads the scope back from. Route eligibility and the
    // shadow mirror both read it there; this middleware deliberately makes NO
    // routing decision itself, because the candidate list does not exist yet.
    recordResidencyPolicy(c.req.raw, resolved.policy);
    await next();
  };
}
