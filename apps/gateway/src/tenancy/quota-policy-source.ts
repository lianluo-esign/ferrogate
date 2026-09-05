/**
 * The `quota_policies` READ RESOLUTION for the gateway's policy sources
 * (Track A red line: no tenant data mirrored in the shared CONTROL object).
 *
 * ============================================================================
 * WHAT THIS IS AND WHY IT IS SHARED
 * ============================================================================
 *
 * Three admission-adjacent readers — attribution (#678), online-eval (#692) and
 * residency (#681) — each seek ONE row out of `quota_policies` by
 * `scope_type = 'tenant' AND scope_id = ?`. That table's authoritative home is
 * the per-tenant object; the shared CONTROL copy has been removed (Track A).
 * This helper is the single point that points those three seeks at the tenant's
 * OWN object, and it is shared precisely so the resolution is decided ONCE, the
 * same way, for all three — a per-module copy would be three chances to diverge
 * on the one thing that must not: which object a tenant's governance is read
 * from.
 *
 * It mirrors `ratelimit/middleware.ts`'s `quotaTenantPolicyDb` (the admission
 * quota/throttle reader's version of the same resolution), and the two exist as
 * siblings rather than one because that reader has a request `Context` and reads
 * the already-resolved accessor, whereas these three sources are built from
 * `env` alone and must resolve the tenant themselves.
 *
 * ============================================================================
 * THE RESOLUTION IS THE FENCE
 * ============================================================================
 *
 * `resolverForEnv(env).forTenant(tenantId)` is the SAME authoritative resolver
 * the whole request path routes through — not a best-effort address cache. It
 * resolves exactly the tenant the seek is for, so there is no cross-tenant
 * lookup to guard against here: the object it returns is that tenant's and no
 * other's. A resolver refusal (unbound namespace, blank tenant id) throws, and
 * every caller seeks `quota_policies` INSIDE its own try/catch, so the throw
 * becomes that source's outage answer — `503` for attribution/residency,
 * "sample nothing" for online-eval — never a silent read of the wrong or empty
 * row.
 */

import { type TenancyBindings } from "./ports.js";
import { resolverForEnv } from "./resolver.js";

/**
 * Base bindings for the three policy sources. The Track A hard-cut removed the
 * `GATEWAY_QUOTA_POLICY_SOURCE` gate — the tenant object is now the sole
 * authority — so this carries no fields of its own and exists only as the shared
 * super-interface the attribution/residency/online-eval bindings extend.
 */
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface QuotaPolicySourceBindings {}

/**
 * A per-request resolver for the tenant's OWN `quota_policies` database.
 *
 * Track A hard-cut: the tenant object is the SOLE authority, so this always
 * returns the resolver (never `undefined`). The returned function resolves the
 * named tenant's object through the authoritative request-path resolver; the
 * caller awaits it inside its own try so a resolver refusal fails in that
 * source's own direction (503 / sample-nothing), never a silent control read.
 */
export function tenantQuotaPolicyDbFrom(
  env: QuotaPolicySourceBindings,
): (tenantId: string) => Promise<D1Database> {
  return async (tenantId: string): Promise<D1Database> => {
    const handle = await resolverForEnv(env as unknown as TenancyBindings).forTenant(tenantId);
    return handle.db;
  };
}
