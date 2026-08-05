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
