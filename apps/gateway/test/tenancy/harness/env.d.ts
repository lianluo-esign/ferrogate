/**
 * Types the `env` that `cloudflare:test` hands the tenancy specs, so a spec can
 * reach the REAL per-tenant D1 bindings without casting.
 *
 * `cloudflare:test` exports `env` as `Cloudflare.Env`, the global ambient
 * binding namespace, so the harness bindings are declared there.
 *
 * Scoped to this harness: `apps/gateway/src/ports.ts` (`GatewayBindings`) is the
 * composition root's file, and the integrate step adds the per-tenant stanzas
 * plus `GATEWAY_TENANT_DB_ROUTING` there — see the WIRING block in
 * `src/tenancy/index.ts`.
 */
import type { D1Migration } from "cloudflare:test";

declare global {
  namespace Cloudflare {
    interface Env {
      /** Account-global; holds `tenant_databases`. */
      CONTROL_DB: D1Database;
      /** Tenant `tenant_acme`'s own database. */
      TENANT_DB_ACME: D1Database;
      /** Tenant `tenant_globex`'s own database. */
      TENANT_DB_GLOBEX: D1Database;
      GATEWAY_TENANT_DB_ROUTING: string;
      CONTROL_MIGRATIONS: D1Migration[];
      TENANT_MIGRATIONS: D1Migration[];
    }
  }
}
