/**
 * The delegation gate — where a presented chain is VERIFIED (#691).
 *
 * ============================================================================
 * WHERE THIS SITS ON THE LADDER, AND WHY
 * ============================================================================
 *
 * `src/index.ts` mounts it between `rateLimit()` and `attributionTags()`:
 *
 *   contractAuth → meteringDrain → requestTelemetry → requestLogging
 *                → rateLimit → **delegationChain** → attributionTags
 *                → residency → guardrails → tenantDatabase → … → dispatch
 *
 * Each edge is a decision.
 *
 *  - **AFTER `contractAuth`** — structurally forced. The chain is verified
 *    AGAINST the credential: its tenant claim must match the authenticated
 *    tenant, its leaf must be bound to the authenticated api-key id, and its
 *    scope set may not exceed what that credential holds. None of those three
 *    exists before the credential resolves, and a chain verified without them
 *    would be a signature check masquerading as an authorization one.
 *
 *  - **AFTER `rateLimit()`** — so a request with a bad chain still BURNS the
 *    caller's admission window. The same argument `attributionTags` makes for
 *    its own position: refusing ahead of admission creates an unmetered refusal
 *    path, and an attacker probing chain forgeries would pay nothing and never
 *    be throttled while doing it.
 *
 *  - **BEFORE `attributionTags()`** — identity precedes attribution. The chain
 *    contributes the `agent_run_id` that the #677 cost query groups by, and
 *    attributing spend to a chain that has not been verified is exactly the
 *    approximate-audit-answer this issue exists to end.
 *
 *  - **BEFORE `guardrails()` and every route** — screening and dispatch both
 *    spend real money (a detector can make paid provider calls), and a request
 *    this gate refuses reaches no model at all.
 *
 * The refusal is still RECORDED: `requestLogging()` is mounted three layers
 * further out and wraps everything below it, so a 403 from here lands in the
 * #664 trail exactly like `rateLimit()`'s 429.
 *
 * ============================================================================
 * INERT UNTIL A CALLER PRESENTS A CHAIN
 * ============================================================================
 *
 * No header → one `headers.get` and `next()`. Not a policy lookup, not a key
 * import, not a database read. Every existing deployment pays exactly that.
 *
 * A header WITH no verifier configured is a **503**, never a 200 with the
 * header ignored. That asymmetry is the whole point: if an unconfigured
 * verifier silently admitted delegated requests, "delete the binding" would be
 * a one-step bypass of every rule in `verifyDelegationChain`.
 *
 * ============================================================================
 * WHAT THIS GATE DOES NOT PROVE
 * ============================================================================
 *
 * That the agent behaved. A verified chain establishes that each delegation was
 * AUTHORISED and that nobody widened their authority along the way. It says
 * nothing about whether the agent did what it was asked, and it must not be
 * read — or sold — as behavioural assurance.
 */
import {
  DELEGATION_HEADER,
  type DelegationFailureCode,
  type VerifiedDelegationChain,
  verifyDelegationChain,
} from "@ferrogate/identity";
import type { Context, MiddlewareHandler, Next } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";
import { contributeRequestLogFacts } from "../requestlog/facts.js";
import { type DelegationBindings, type DelegationVerifier, delegationVerifierFromEnv } from "./source.js";

/**
 * The HTTP status each refusal is rendered with.
 *
 * Only ONE code is a 400: `delegation_malformed`, i.e. the bytes are not a
 * chain at all. Everything else is a 403, because the chain parsed and what
 * refused it was a RULE — the same 400-vs-403 line the rest of this path draws
 * (`invalid_request_metadata` is a malformed map; `model_not_allowed`,
 * `attribution_tags_required` and `guardrail_blocked` are all policy refusals
 * of a well-formed request).
 *
 * `delegation_too_deep` is deliberately on the 403 side of that line even
 * though it looks structural: the chain is perfectly well formed, and what
 * refuses it is this verifier's bound on how much delegation it will honour.
 *
 * The one 503 is the revocation lookup — see the fail-closed note below.
 */
const STATUS_BY_CODE: Readonly<Record<DelegationFailureCode, number>> = {
  delegation_malformed: 400,
  delegation_too_deep: 403,
  delegation_signature_invalid: 403,
  delegation_tenant_mismatch: 403,
  delegation_chain_broken: 403,
  delegation_expired: 403,
  delegation_not_yet_valid: 403,
  delegation_lifetime_excessive: 403,
  delegation_outlives_delegator: 403,
  delegation_scope_widened: 403,
  delegation_scope_exceeds_credential: 403,
  delegation_scope_denied: 403,
  delegation_subject_mismatch: 403,
  delegation_revoked: 403,
  // Fail CLOSED. A revocation list that cannot be read is UNKNOWN state, and
  // admitting on unknown state would make "flap the control plane" a revocation
  // bypass — the same reasoning `LifecycleGateError::Unavailable` (403-vs-503)
  // and `attribution/source.ts` both apply to their own outages.
  delegation_revocation_unavailable: 503,
};

/** `503` — this Worker cannot verify, so it will not pretend to. */
export const DELEGATION_UNAVAILABLE = "delegation_verification_unavailable";
/** `403` — a chain was presented on a request that authenticated no credential. */
export const DELEGATION_REQUIRES_CREDENTIAL = "delegation_requires_credential";

export interface DelegationMiddlewareOptions {
  /** Override the verifier. Production resolves it from `env`. */
  readonly verifier?: (env: DelegationBindings) => Promise<DelegationVerifier>;
  /** Override the clock (tests pin a second). */
  readonly now?: () => number;
}

/**
 * Verify the presented delegation chain, or refuse the request.
 *
 * On success the chain is published two ways, and both are needed:
 *
 *  - `c.set("delegation", chain)` for anything downstream that wants the
 *    attenuated authority in the same Hono context;
 *  - `contributeRequestLogFacts(...)` for the audit row, because the request
 *    log is written by a middleware mounted THREE layers further out and the
 *    inference router runs in a separate Hono app entirely — `c.set` is
 *    invisible to both. See `requestlog/facts.ts` on why the carrier is a
 *    `WeakMap` keyed by the `Request`.
 */
export function delegationChain(
  options: DelegationMiddlewareOptions = {},
): MiddlewareHandler<GatewayEnv> {
  const resolveVerifier = options.verifier ?? delegationVerifierFromEnv;
  const now = options.now ?? ((): number => Math.floor(Date.now() / 1000));

  return async function delegationChainMiddleware(c, next: Next): Promise<void> {
    const header = c.req.header(DELEGATION_HEADER);
    // The inert path, and it is the only one most requests take.
    if (header === undefined || header.trim() === "") {
      await next();
      return;
    }

    const verifier = await resolveVerifier(c.env as unknown as DelegationBindings);
    if (verifier.state !== "ready") {
      throw new HttpError(
        503,
        DELEGATION_UNAVAILABLE,
        verifier.state === "misconfigured"
          ? `this deployment cannot verify delegation chains: ${verifier.detail}`
          : "this deployment cannot verify delegation chains (DELEGATION_SIGNING_KEY is not bound), " +
            "so a request presenting one is refused rather than served with the chain ignored",
      );
    }

    const auth = (c as Context<GatewayEnv>).get("auth");
    const tenantId = auth?.tenancy.tenantId;
    const subject = auth?.subject;
    if (auth === null || auth === undefined || !tenantId || !subject) {
      // A chain names a DELEGATE and binds to the credential that presents it.
      // With no credential — an anonymous operation, or a platform-operator key
      // that names no tenant — there is nothing to bind to and nothing to fence
      // the revocation lookup with, so the only honest answer is a refusal.
      // Admitting it would record a chain nothing checked.
      throw new HttpError(
        403,
        DELEGATION_REQUIRES_CREDENTIAL,
        `${DELEGATION_HEADER} requires a credential that names a tenant and a subject`,
      );
    }

    const verified = await verifyDelegationChain(verifier.key, {
      header,
      tenantId,
      presenterKeyId: subject,
      presenterScopes: auth.scopes,
      // The scope the matched operation requires, so attenuation is ENFORCED
      // and not merely recorded. `contractAuth` publishes it for every bearer
      // and `method_dependent` operation; `undefined` here means the surface
      // has no contract scope at all, in which case there is nothing to narrow.
      ...(() => {
        const required = (c as Context<GatewayEnv>).get("requiredScope");
        return required === null || required === undefined ? {} : { requiredScope: required };
      })(),
      nowUnix: now(),
      revocations: verifier.revocations,
    });

    if (!verified.ok) {
      throw new HttpError(STATUS_BY_CODE[verified.code], verified.code, verified.detail);
    }

    publish(c as Context<GatewayEnv>, verified.chain);
    await next();
  };
}

function publish(c: Context<GatewayEnv>, chain: VerifiedDelegationChain): void {
  c.set("delegation", chain);
  contributeRequestLogFacts(c.req.raw, {
    delegationChain: chain.path,
    delegationRoot: chain.rootPrincipal,
    // The chain feeds the attribution shape #677/#678 already built rather than
    // a second one beside it: `agent_run_id` is a column the per-request cost
    // query already groups by, so a delegated run is queryable by finance on
    // day one without a new report.
    //
    // Contributed only when the chain NAMES a run. `contributeRequestLogFacts`
    // ignores `undefined`, so a chain with no run cannot erase a run id the
    // inference path already established.
    ...(chain.agentRunId === undefined ? {} : { agentRunId: chain.agentRunId }),
  });
}
