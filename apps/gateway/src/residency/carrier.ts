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
import type { TenantObjectAddress } from "@ferrogate/storage";

const POLICIES = new WeakMap<Request, ResidencyPolicy>();
const ADDRESSES = new WeakMap<Request, TenantObjectAddress>();
const ENV_ADDRESSES = new WeakMap<object, Map<string, TenantObjectAddress>>();

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

/** Publish the immutable namespace address selected for this request's tenant. */
export function recordTenantObjectAddress(
  request: Request,
  address: TenantObjectAddress | undefined,
): void {
  if (address === undefined) return;
  try {
    ADDRESSES.set(request, address);
  } catch {
    /* Request is always an object on the deployed path. */
  }
}

/** Publish the same address for request-scoped sinks that only receive env. */
export function recordTenantObjectAddressForEnv(
  env: unknown,
  tenantId: string,
  address: TenantObjectAddress | undefined,
): void {
  if (address === undefined || tenantId.trim() === "") return;
  if (typeof env !== "object" || env === null) return;
  try {
    let addresses = ENV_ADDRESSES.get(env);
    if (addresses === undefined) {
      addresses = new Map();
      ENV_ADDRESSES.set(env, addresses);
    }
    addresses.set(tenantId, address);
  } catch {
    /* Bindings are objects on the deployed path. */
  }
}

/** Read the namespace address selected by the outer residency resolver. */
export function tenantObjectAddressFor(request: Request): TenantObjectAddress | undefined {
  try {
    return ADDRESSES.get(request);
  } catch {
    return undefined;
  }
}

/** Read a request's address from a helper that only received its env. */
export function tenantObjectAddressForEnv(
  env: unknown,
  tenantId: string,
): TenantObjectAddress | undefined {
  if (typeof env !== "object" || env === null || tenantId.trim() === "") return undefined;
  try {
    return ENV_ADDRESSES.get(env)?.get(tenantId);
  } catch {
    return undefined;
  }
}
