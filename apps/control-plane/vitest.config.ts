/**
 * `apps/control-plane` test pool.
 *
 * ## `TEST_D1_SCHEMA` / `TEST_TENANT_D1_SCHEMA`
 *
 * The D1-backed `D1ControlPlaneStore` is only worth testing against a REAL D1
 * binding, and a real binding is only useful once the schema exists in it. The
 * DDL is read here, in Node, from `sql/d1-ts/{control,tenant}/` — the SAME
 * directories `wrangler d1 migrations apply` is pointed at (`wrangler.toml`
 * names the control one as `migrations_dir`) — and handed to the tests as
 * bindings so `test/d1.ts` can apply them with `applyD1Migrations`.
 *
 * Running the deployed migrations rather than a fixture copy of the DDL is the
 * point: a column rename in the migration then breaks these tests, instead of
 * the tests passing happily against a private schema production does not have.
 *
 * ## The per-tenant databases
 *
 * `TENANT_DB_A` / `TENANT_DB_B` are declared HERE and not in `wrangler.toml`,
 * and that asymmetry is not an oversight — it is what the topology actually
 * looks like. A tenant's `[[d1_databases]]` stanza is written by the
 * PROVISIONING flow when that tenant is onboarded (see
 * `EnvBindingTenantDatabaseRouter` in `@ferrogate/storage`: bindings resolve at
 * deploy time, and the registry maps `tenant_id -> binding_name`), so the
 * committed config cannot enumerate tenants that do not exist yet. What the
 * committed config DOES carry is the control database, which is the only one
 * this Worker needs in order to *resolve* a tenant.
 *
 * Two databases, not one, because the router's whole job is to hand back
 * DIFFERENT databases: a cross-tenant assertion against a single shared
 * database would pass against a router that ignored its argument.
 *
 * A third tenant is registered in `test/tenant-db.ts` naming a binding that is
 * deliberately NOT declared here, so the "provisioned but not yet redeployed"
 * refusal has something real to refuse.
 */
import { readFileSync } from "node:fs";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { gatewayTenantDataAuxWorker } from "../gateway/test/support/rate-limit-aux-worker.js";

/**
 * The committed deploy config, read here because workerd has no filesystem.
 *
 * It is bound so `test/cron-trigger.test.ts` can assert on `[triggers] crons` —
 * the half of the schedule wiring no binding surfaces and no behavioural test
 * can see, because the pool never dispatches a scheduled event of its own.
 */
const WRANGLER_TOML = readFileSync(new URL("./wrangler.toml", import.meta.url), "utf8");

const controlMigrations = await readD1Migrations("../../sql/d1-ts/control");
const tenantMigrations = await readD1Migrations("../../sql/d1-ts/tenant");

if (controlMigrations.length === 0 || tenantMigrations.length === 0) {
  // A silently-empty migration set makes every D1 test fail with "no such
  // table" and look like a code bug. Fail here, where the cause is.
  throw new Error("control-plane tests: no D1 migrations found under sql/d1-ts/{control,tenant}");
}

export default defineConfig({
  /**
   * Vitest's 5s default is too tight for THIS suite specifically.
   *
   * `test/wiring.test.ts` proves its invariants by sweeping the WHOLE contract
   * surface — several tests issue ~209 real `fetch`es through `export default`
   * in workerd, one per contract operation, because a sampled subset would let
   * exactly the un-swept operation be the one that drifted. That is inherently
   * O(operations), and on a 2-core GitHub runner three of those sweeps hit the
   * 5s wall while passing comfortably on a developer machine — a green local
   * suite and a red CI, which is the worst signal a gate can give.
   *
   * Raised rather than sampled, and raised per-suite rather than globally: the
   * other workspaces keep the tight default, so a genuine hang there still
   * surfaces fast. 60s is far above the observed CI cost of a sweep (~5-8s) and
   * far below "hung", so a real deadlock still fails rather than stalling the
   * job to its 45-minute limit.
   */
  test: {
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        d1Databases: ["TENANT_DB_A", "TENANT_DB_B"],
        // The `ferrogate-gateway` script this Worker's committed
        // `[[durable_objects.bindings]] TENANT_DATA` points at with
        // `script_name` (#820). Without it workerd refuses to START the session
        // ("binding TENANT_DATA refers to a service core:user:ferrogate-gateway,
        // but no such service is defined"), and the alternative — leaving the
        // stanza out of the committed config — is the defect #666 fixed for
        // RATE_LIMIT: a committed configuration that only works after a human
        // edits it at deploy time.
        //
        // It carries the gateway's REAL `TenantDataObject`, so
        // `test/tenant-onboarding.test.ts` provisions a tenant through the same
        // namespace the data plane would read, rather than through a stub that
        // would agree with whatever the provisioner did.
        workers: [gatewayTenantDataAuxWorker(new URL("../gateway/", import.meta.url))],
        bindings: {
          TEST_D1_SCHEMA: controlMigrations,
          TEST_TENANT_D1_SCHEMA: tenantMigrations,
          TEST_WRANGLER_TOML: WRANGLER_TOML,
        },
      },
    }),
  ],
});
