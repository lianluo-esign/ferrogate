/**
 * Shared setup for the tenancy suite.
 *
 * Applies the DEPLOYED migrations (`sql/d1-ts/control` + `sql/d1-ts/tenant`,
 * read by `harness/vitest.config.ts` with `readD1Migrations`) to the REAL D1
 * databases `workerd` bound from `harness/wrangler.toml`, and seeds the CONTROL
 * database's `tenant_databases` registry with the six cases the specs assert on.
 *
 * Nothing here fakes a database, a binding, or a router.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { ControlDatabaseTenantRegistry } from "@ferrogate/storage";

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
  await applyD1Migrations(env.CONTROL_DB, env.CONTROL_MIGRATIONS);
  await applyD1Migrations(env.TENANT_DB_ACME, env.TENANT_MIGRATIONS);
  await applyD1Migrations(env.TENANT_DB_GLOBEX, env.TENANT_MIGRATIONS);

  const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
  await registry.upsert(
    {
      tenantId: TENANT_ACME,
      databaseUuid: "11111111-1111-4111-8111-111111111111",
      databaseName: "ferrogate-tenant-acme",
      bindingName: "TENANT_DB_ACME",
      schemaVersion: 1,
    },
    NOW,
  );
  await registry.upsert(
    {
      tenantId: TENANT_GLOBEX,
      databaseUuid: "22222222-2222-4222-8222-222222222222",
      databaseName: "ferrogate-tenant-globex",
      bindingName: "TENANT_DB_GLOBEX",
      schemaVersion: 1,
    },
    NOW,
  );
  await registry.upsert(
    {
      tenantId: TENANT_INITECH,
      databaseUuid: "33333333-3333-4333-8333-333333333333",
      databaseName: "ferrogate-tenant-initech",
      bindingName: "TENANT_DB_INITECH",
      schemaVersion: 1,
    },
    NOW,
  );
  await registry.upsert(
    {
      tenantId: TENANT_UNBOUND,
      databaseUuid: "44444444-4444-4444-8444-444444444444",
      databaseName: "ferrogate-tenant-unbound",
      schemaVersion: 1,
    },
    NOW,
  );
  await registry.upsert(
    {
      tenantId: TENANT_NON_D1,
      databaseUuid: "55555555-5555-4555-8555-555555555555",
      databaseName: "ferrogate-tenant-non-d1",
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
