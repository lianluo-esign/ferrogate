/**
 * The carrier for the residency policy the OUTER gate resolved for one request
 * (#681).
 *
 * A `WeakMap` keyed by the inbound `Request`, for the same three reasons
 * `attribution/defaults.ts`, `requestlog/facts.ts` and `inference/identity.ts`
 * give for theirs: the policy is resolved on the OUTER app (it needs `c.env`
 * and an async D1 read) while route eligibility runs inside `inner.fetch`'s
 * fresh Hono context, so a context variable cannot cross; a module-level
 * "current request" slot is a cross-request leak the first time two requests
 * interleave on an `await`, and here that leak would apply one tenant's
 * residency policy to another tenant's prompt — refusing legal traffic in one
 * direction and, worse, routing a governed prompt out of region in the other;
 * and the `Request` object is per-request by construction.
 */

import type { ResidencyPolicy } from "./policy.js";

const POLICIES = new WeakMap<Request, ResidencyPolicy>();

/**
 * Publish the policy governing `request`.
 *
 * Never throws — a `WeakMap` rejects a non-object key and a bookkeeping failure
 * must not become a client-visible one. `null` is not stored, which keeps
 * {@link residencyPolicyFor} allocation-free on the unpoliced path.
 *
 * NOTE the failure mode this `catch` leaves: a store that fails means the inner
 * app sees NO policy and the request is served unconstrained. That is only
 * reachable for a non-object `request`, which cannot occur on the deployed
 * path (`c.req.raw` is always a `Request`), and the alternative — throwing —
 * would turn it into a 500 on a request that is otherwise fine. It is called
 * out here rather than hidden because it is the one soft edge in this slice.
 */
export function recordResidencyPolicy(request: Request, policy: ResidencyPolicy | null): void {
  if (policy === null) return;
  try {
    POLICIES.set(request, policy);
  } catch {
    /* see above */
  }
}

/** The policy governing `request`, or `null` when the tenant is not governed. */
export function residencyPolicyFor(request: Request): ResidencyPolicy | null {
  try {
    return POLICIES.get(request) ?? null;
  } catch {
    return null;
  }
}
