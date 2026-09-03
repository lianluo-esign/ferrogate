/**
 * The `quota_policies` READ RELOCATION for the gateway's policy sources
 * (Track A red line: no tenant data mirrored in the shared CONTROL object).
 *
 * ============================================================================
 * WHAT THIS IS AND WHY IT IS SHARED
 * ============================================================================
 *
 * Three admission-adjacent readers — attribution (#678), online-eval (#692) and
 * residency (#681) — each seek ONE row out of `quota_policies` by
 * `scope_type = 'tenant' AND scope_id = ?`. That table's authoritative home is
 * now the per-tenant object, not the shared CONTROL database; the control copy
 * is a mirror on its way out. This helper is the single switch that points those
 * three seeks at the tenant's OWN object instead, and it is shared precisely so
 * the switch is decided ONCE, the same way, for all three — a per-module copy
 * would be three chances to diverge on the one thing that must not: which object
 * a tenant's governance is read from.
 *
 * It mirrors `ratelimit/middleware.ts`'s `quotaTenantPolicyDb` (the admission
 * quota/throttle reader's version of the same switch), and the two exist as
 * siblings rather than one because that reader has a request `Context` and reads
 * the already-resolved accessor, whereas these three sources are built from
 * `env` alone and must resolve the tenant themselves.
 *
 * ============================================================================
 * THE FLAG IS DEFAULT-OFF, AND OFF IS BYTE-IDENTICAL
 * ============================================================================
 *
 * `GATEWAY_QUOTA_POLICY_SOURCE` defaults to `"control"`. Anything other than the
 * exact string `"tenant_object"` returns `undefined`, and a source handed
 * `undefined` keeps reading the control database it was already reading — the
 * pre-relocation behaviour, unchanged to the byte. The flip to `"tenant_object"`
 * is GATED behind the backfill that makes every tenant object hold its own
 * policy row; reading an un-backfilled object would answer "no policy", which
 * for residency is a silent out-of-region breach. That is why this cannot be
 * always-on and why the closure is not even BUILT until the flag is set.
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

/** The one var this switch reads. */
export interface QuotaPolicySourceBindings {
  /**
   * `"tenant_object"` relocates the `quota_policies` seek to the tenant's own
   * object; anything else (the default `"control"`, absent, blank) keeps the
   * control read. See the module docs on why the flip is GATED.
   */
  readonly GATEWAY_QUOTA_POLICY_SOURCE?: string | undefined;
}

/**
 * A per-request resolver for the tenant's OWN `quota_policies` database, or
 * `undefined` to leave the caller reading the control database.
 *
 * `undefined` unless `GATEWAY_QUOTA_POLICY_SOURCE === "tenant_object"`, so the
 * default deployment is untouched. When set, the returned function resolves the
 * named tenant's object through the authoritative request-path resolver; the
 * caller awaits it inside its own try so a resolver refusal fails in that
 * source's own direction.
 */
export function tenantQuotaPolicyDbFrom(
  env: QuotaPolicySourceBindings,
): ((tenantId: string) => Promise<D1Database>) | undefined {
  if ((env.GATEWAY_QUOTA_POLICY_SOURCE ?? "").trim() !== "tenant_object") return undefined;
  return async (tenantId: string): Promise<D1Database> => {
    const handle = await resolverForEnv(env as unknown as TenancyBindings).forTenant(tenantId);
    return handle.db;
  };
}
