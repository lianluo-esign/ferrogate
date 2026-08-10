/**
 * Boot guard for the SDK-conformance suite under the post-Zero-D1 topology.
 *
 * ## There is no `applyD1Migrations` step any more
 *
 * `apps/gateway/wrangler.toml` (the config this suite boots via `configPath`)
 * declares NO `[[d1_databases]]` at all since Zero-D1 #821/#881: the shared
 * `ferrogate-tenant` D1 (`env.DB`) and the `CONTROL_DB` / `BILLING_DB` control
 * D1s were all retired. Production now reads tenant-schema tables through the
 * per-tenant `TenantDataObject` (`env.TENANT_DATA`) and control-schema tables
 * through the singleton `ControlDataObject` (`env.CONTROL_DATA`), because
 * `GATEWAY_TENANT_DB_ROUTING` and `GATEWAY_CONTROL_STORAGE` are both
 * `"durable_object"` in that toml. Each Durable Object applies its own deployed
 * schema on first wake (see `packages/storage/src/{control,tenant}-data-object.ts`
 * — the constructor migrates under `blockConcurrencyWhile`), so there is nothing
 * for the harness to migrate. The single DB seed in the whole suite — the
 * `quota_policies` row the 429 leg needs — is written through the CONTROL_DATA
 * facade in `test/errors.test.ts::beforeAll`, which wakes and migrates the
 * object on its first query.
 *
 * ## What this file does instead: fail LOUD if the objects are unbound
 *
 * A missing `CONTROL_DATA` / `TENANT_DATA` binding would make every
 * authenticated request answer `503` (control/quota/rbac resolution
 * unavailable) and the conformance findings would be about a broken harness
 * rather than about the gateway. Rather than let that pass as a silent skip, the
 * guard throws at collection — same shape and rationale as
 * `apps/gateway/test/setup-d1.ts:50-59`.
 */
import { env } from "cloudflare:test";

interface DurableObjectBindings {
  readonly CONTROL_DATA?: unknown;
  readonly TENANT_DATA?: unknown;
}

const bindings = env as unknown as DurableObjectBindings;

if (bindings.CONTROL_DATA === undefined || bindings.TENANT_DATA === undefined) {
  // Loud, never a silent skip: `apps/gateway/wrangler.toml` declares the
  // [[durable_objects.bindings]] CONTROL_DATA + TENANT_DATA stanzas and every
  // rbac/quota/tenant-data read resolves them (Zero-D1 S5/S6, #881/#882). An
  // absent one means the deploy config changed and the suite is about to prove
  // something other than what it claims.
  throw new Error(
    "sdk-conformance setup: expected the [[durable_objects.bindings]] `CONTROL_DATA` and " +
      "`TENANT_DATA` stanzas (apps/gateway/wrangler.toml). The retired `env.DB` tenant D1 is " +
      "gone (Zero-D1 #821); tenant reads route through TENANT_DATA and control through CONTROL_DATA.",
  );
}
