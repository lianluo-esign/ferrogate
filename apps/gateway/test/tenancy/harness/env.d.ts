import type { D1Migration } from "cloudflare:test";
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
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";

declare global {
  namespace Cloudflare {
    interface Env {
      /** Account-global; holds `tenant_databases`. */
      CONTROL_DB: D1Database;
      /**
       * The per-tenant Durable Object namespace — the DEFAULT topology. One
       * binding for every tenant that will ever exist, which is why there is no
       * `TENANT_DATA_ACME` / `TENANT_DATA_GLOBEX` pair beside it.
       */
      TENANT_DATA: TenantDataNamespace;
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
