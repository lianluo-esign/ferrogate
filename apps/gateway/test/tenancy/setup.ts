/**
 * Shared setup for the tenancy suite.
 *
 * Applies the DEPLOYED tenant migrations (`sql/d1-ts/tenant`, read by
 * `harness/vitest.config.ts` with `readD1Migrations`) to the REAL per-tenant D1
 * databases `workerd` bound from `harness/wrangler.toml`, applies the control
 * migrations to the raw `CONTROL_DB` handle the schema-split introspection specs
 * read, and seeds the `tenant_databases` registry the router actually reads.
 *
 * Since Zero-D1 S5 (#914) that registry lives in the singleton `CONTROL_DATA`
 * object, NOT the native `CONTROL_DB` D1 — the router resolves its control store
 * through `controlDatabaseFrom(env)`, which wraps `env.CONTROL_DATA` in the
 * D1-shaped facade. So the seeding goes through that same facade (the object
 * self-migrates its schema on the first query), exactly as `test/setup-d1.ts`
 * seeds the main suite's roster. Seeding the native `CONTROL_DB` here would land
 * the rows in a store the router never reads and every tenant would fail closed.
 *
 * Nothing here fakes a database, a binding, or a router.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { ControlDatabaseTenantRegistry, controlDataObjectDatabase } from "@ferrogate/storage";

/** Registered, `TENANT_DB_ACME` is declared in `harness/wrangler.toml`. */
export const TENANT_ACME = "tenant_acme";
/** Registered, `TENANT_DB_GLOBEX` is declared. The isolation counterpart. */
export const TENANT_GLOBEX = "tenant_globex";
/**
 * Registered and names `TENANT_DB_INITECH`, which `harness/wrangler.toml`
 * deliberately does NOT declare — the control registry and the deployed config
 * disagree. Must fail closed.
 */
export const TENANT_INITECH = "tenant_initech";
/**
 * Registered with `binding_name = NULL`: the database exists in the account but
 * the Worker has not been redeployed with its stanza. "Provisioned but not yet
 * routable" must fail closed, not fall back.
 */
export const TENANT_UNBOUND = "tenant_unbound";
/**
 * Registered naming `GATEWAY_TENANT_DB_ROUTING` — a real binding, but a plain
 * string var, not a D1 database. Must fail closed rather than duck-type it.
 */
export const TENANT_NON_D1 = "tenant_non_d1";
/** Never registered at all. Must fail closed. */
export const TENANT_GHOST = "tenant_ghost";

const NOW = 1_700_000_000;

/**
 * Apply both migration sets and seed the registry. Idempotent: `applyD1Migrations`
 * is bookkept in `d1_migrations` and `upsert` is idempotent by tenant id.
 */
export async function setupTenancy(): Promise<void> {
  // Migrate the RAW `CONTROL_DB` handle so the schema-split introspection specs
  // can read its `sqlite_master`; migrate the per-tenant D1s for the isolation
  // proofs. The `CONTROL_DATA` object needs no step here — it self-migrates on
  // the first facade query below.
  await applyD1Migrations(env.CONTROL_DB, env.CONTROL_MIGRATIONS);
  await applyD1Migrations(env.TENANT_DB_ACME, env.TENANT_MIGRATIONS);
  await applyD1Migrations(env.TENANT_DB_GLOBEX, env.TENANT_MIGRATIONS);

  // Seed through the CONTROL_DATA facade — the store the router reads via
  // `controlDatabaseFrom(env)`. The first upsert wakes the object and applies
  // its schema.
  const registry = new ControlDatabaseTenantRegistry(controlDataObjectDatabase(env.CONTROL_DATA));
  await registry.upsert(
    {
      tenantId: TENANT_ACME,
      bindingName: "TENANT_DB_ACME",
      schemaVersion: 1,
    },
    NOW,
  );
  await registry.upsert(
    {
      tenantId: TENANT_GLOBEX,
      bindingName: "TENANT_DB_GLOBEX",
      schemaVersion: 1,
    },
    NOW,
  );
  await registry.upsert(
    {
      tenantId: TENANT_INITECH,
      bindingName: "TENANT_DB_INITECH",
      schemaVersion: 1,
    },
    NOW,
  );
  await registry.upsert(
    {
      tenantId: TENANT_UNBOUND,
      schemaVersion: 1,
    },
    NOW,
  );
  await registry.upsert(
    {
      tenantId: TENANT_NON_D1,
      bindingName: "GATEWAY_TENANT_DB_ROUTING",
      schemaVersion: 1,
    },
    NOW,
  );
}

/** A wallet row for `tenantId`, so the isolation proof runs on the money table. */
export function walletFor(tenantId: string, balanceCredits: number) {
  return {
    id: tenantId,
    tenantId,
    balanceCredits,
    dunning: false,
    createdAtUnix: NOW,
    updatedAtUnix: NOW,
  };
}
