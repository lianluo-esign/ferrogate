/**
 * The per-tenant D1 topology, against REAL D1 databases in `workerd`.
 *
 * Three properties, each one the reason the feature exists:
 *
 *  1. **The mount is the real library.** The resolver IS
 *     `@ferrogate/storage`'s `EnvBindingTenantDatabaseRouter` — the class that
 *     had zero importers under any app before this slice. Replacing it with a
 *     hand-rolled equivalent (this repo's recurring defect) turns §1 red.
 *  2. **Physical isolation.** A wallet written through tenant A's handle is
 *     INVISIBLE through tenant B's, because they are two different SQLite
 *     files, not two values of a `tenant_id` column. Routing both tenants to
 *     one database turns §2 red.
 *  3. **Fail closed.** Five distinct unresolvable shapes each ERROR. None of
 *     them returns the shared or the control database. Adding a single
 *     `?? env.CONTROL_DB` anywhere in `src/tenancy/` turns §3 red.
 */
import { env } from "cloudflare:test";
import {
  ControlDatabaseTenantRegistry,
  D1WalletStore,
  EnvBindingTenantDatabaseRouter,
  requireAtomicBatch,
} from "@ferrogate/storage";
import { beforeAll, describe, expect, test } from "vitest";
import { controlDatabaseFrom } from "../../src/control-data.js";
import { HttpError } from "../../src/middleware/errors.js";
import {
  TENANT_DATABASE_ROUTING_MISCONFIGURED,
  TENANT_DATABASE_UNAVAILABLE,
  type TenancyBindings,
  createTenantDatabaseResolver,
  parseTenantDatabaseRoutingMode,
} from "../../src/tenancy/index.js";
import {
  TENANT_ACME,
  TENANT_GHOST,
  TENANT_GLOBEX,
  TENANT_INITECH,
  TENANT_NON_D1,
  TENANT_UNBOUND,
  setupTenancy,
  walletFor,
} from "./setup.js";

beforeAll(setupTenancy);

/** The production bindings, exactly as `harness/wrangler.toml` supplies them. */
function bindings(): TenancyBindings {
  return env as unknown as TenancyBindings;
}

/** Assert a promise rejects with a gateway `HttpError` carrying `code`. */
async function refusal(work: Promise<unknown>, code: string, status = 503): Promise<HttpError> {
  const error = await work.then(
    () => undefined,
    (thrown: unknown) => thrown,
  );
  expect(error, "expected a refusal, got a resolved value").toBeInstanceOf(HttpError);
  const httpError = error as HttpError;
  expect(httpError.code).toBe(code);
  expect(httpError.status).toBe(status);
  return httpError;
}

// ---------------------------------------------------------------------------
// 1. The mount
// ---------------------------------------------------------------------------

describe("the resolver is @ferrogate/storage's router, not a second implementation", () => {
  test('"binding" mode mounts EnvBindingTenantDatabaseRouter over the CONTROL_DATA facade', async () => {
    const resolver = createTenantDatabaseResolver({
      ...bindings(),
      GATEWAY_TENANT_DB_ROUTING: "binding",
    });
    // THE UNMOUNT GATE. If someone re-implements tenantId -> D1 lookup inside
    // apps/gateway instead of importing the tested library, this fails.
    expect(resolver.router).toBeInstanceOf(EnvBindingTenantDatabaseRouter);
    expect(resolver.mode).toBe("binding");
    expect(resolver.eager).toBe(false);
    // The CONTROL database is the account-global one, and it is NOT any tenant's
    // database. Since Zero-D1 S5 (#914) retired `d1_compat`, it is the
    // `CONTROL_DATA` object facade rather than `env.CONTROL_DB` — a fresh handle
    // per resolve, so identity is proved by WHAT IT IS NOT (either tenant's own
    // database) and by WHAT IT READS (the account-global `tenant_databases`
    // registry), never by `===`.
    const control = resolver.control();
    expect(control).not.toBe(env.TENANT_DB_ACME);
    expect(control).not.toBe(env.TENANT_DB_GLOBEX);
    const registry = new ControlDatabaseTenantRegistry(control);
    expect((await registry.get(TENANT_ACME))?.bindingName).toBe("TENANT_DB_ACME");
  });

  test('"binding_strict" is the same router, resolved eagerly', () => {
    const resolver = createTenantDatabaseResolver(bindings());
    expect(resolver.router).toBeInstanceOf(EnvBindingTenantDatabaseRouter);
    expect(resolver.mode).toBe("binding_strict");
    expect(resolver.eager).toBe(true);
  });

  test("the registry the router reads is the control database's tenant_databases", async () => {
    // The router reads its control store through `controlDatabaseFrom(env)` — the
    // `CONTROL_DATA` object facade since Zero-D1 S5 — so the registry is seeded
    // and read there, NOT in the native `CONTROL_DB` D1.
    const registry = new ControlDatabaseTenantRegistry(
      controlDatabaseFrom(bindings()) as D1Database,
    );
    const acme = await registry.get(TENANT_ACME);
    expect(acme?.bindingName).toBe("TENANT_DB_ACME");
    // `tenant_unbound` is provisioned but has no binding: the column is NULL,
    // not a guessed name.
    expect((await registry.get(TENANT_UNBOUND))?.bindingName).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 2. Physical isolation
// ---------------------------------------------------------------------------

describe("one D1 database per tenant — physical isolation", () => {
  test("two tenants resolve to two PHYSICALLY different databases", async () => {
    const resolver = createTenantDatabaseResolver(bindings());
    const acme = await resolver.forTenant(TENANT_ACME);
    const globex = await resolver.forTenant(TENANT_GLOBEX);

    expect(acme.db).toBe(env.TENANT_DB_ACME);
    expect(globex.db).toBe(env.TENANT_DB_GLOBEX);
    expect(acme.db).not.toBe(globex.db);
    // Neither is the account-global database — a router that returned the
    // control database for everyone would satisfy "not undefined" but not this.
    expect(acme.db).not.toBe(env.CONTROL_DB);
    expect(globex.db).not.toBe(env.CONTROL_DB);
  });

  test("a native binding keeps the atomic primitives the money paths require", async () => {
    const resolver = createTenantDatabaseResolver(bindings());
    const acme = await resolver.forTenant(TENANT_ACME);
    expect(acme.source).toBe("native_binding");
    expect(acme.supportsAtomicBatch).toBe(true);
    // `requireAtomicBatch` is what every guarded write in `@ferrogate/storage`
    // calls first; it must ADMIT a routed native handle.
    expect(requireAtomicBatch(acme, "reserve_wallet_credits")).toBe(acme);
  });

  test("a wallet written through tenant A's handle is INVISIBLE from tenant B's", async () => {
    const resolver = createTenantDatabaseResolver(bindings());
    // The REAL money store from `@ferrogate/storage`, over the ROUTED handles.
    const acme = new D1WalletStore(await resolver.forTenant(TENANT_ACME));
    const globex = new D1WalletStore(await resolver.forTenant(TENANT_GLOBEX));

    await acme.upsertWallet(walletFor(TENANT_ACME, 5_000));
    await globex.upsertWallet(walletFor(TENANT_GLOBEX, 11));

    expect((await acme.getWallet(TENANT_ACME))?.balanceCredits).toBe(5_000);
    expect((await globex.getWallet(TENANT_GLOBEX))?.balanceCredits).toBe(11);

    // The load-bearing half: ACME's row does not exist in GLOBEX's database at
    // all. This is not a `WHERE tenant_id = ?` filter — the row is in a
    // different SQLite file, so no query in GLOBEX's database can reach it,
    // including one that forgot the filter.
    const leaked = await env.TENANT_DB_GLOBEX.prepare(
      "SELECT tenant_id, balance_credits FROM wallets WHERE tenant_id = ?",
    )
      .bind(TENANT_ACME)
      .first();
    expect(leaked).toBeNull();

    const rowsInGlobex = await env.TENANT_DB_GLOBEX.prepare("SELECT tenant_id FROM wallets").all<{
      tenant_id: string;
    }>();
    expect(rowsInGlobex.results.map((r) => r.tenant_id)).toEqual([TENANT_GLOBEX]);

    // And the CONTROL database holds no wallets at all — the split is real.
    const controlWallets = await env.CONTROL_DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'wallets'",
    ).first();
    expect(controlWallets).toBeNull();
  });

  test("the control database holds the account-global tables, the tenant ones do not", async () => {
    const tableIn = async (db: D1Database, name: string) =>
      (await db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
        .bind(name)
        .first()) !== null;

    // CONTROL: the tenant registry, the credential directory, plans.
    expect(await tableIn(env.CONTROL_DB, "tenant_databases")).toBe(true);
    expect(await tableIn(env.CONTROL_DB, "api_key_directory")).toBe(true);
    // `billing_report_outbox` was DROPPED from control by migration 0045 (Track
    // A) and now lives only on the tenant/platform object, so the control mirror
    // no longer carries it — this pin is retired rather than inverted.
    // TENANT: the tenant's own money/usage/asset state.
    expect(await tableIn(env.TENANT_DB_ACME, "wallets")).toBe(true);
    expect(await tableIn(env.TENANT_DB_ACME, "usage_monthly_rollups")).toBe(true);
    // The split is enforced by the migrations, so a mis-routed write fails
    // loudly with "no such table" instead of silently landing in the wrong DB.
    expect(await tableIn(env.TENANT_DB_ACME, "tenant_databases")).toBe(false);
    expect(await tableIn(env.CONTROL_DB, "wallets")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 3. Fail closed
// ---------------------------------------------------------------------------

describe("fail closed — an unresolvable tenant NEVER falls back", () => {
  const resolver = () => createTenantDatabaseResolver(bindings());

  test("an unregistered tenant errors instead of returning the control database", async () => {
    const error = await refusal(resolver().forTenant(TENANT_GHOST), TENANT_DATABASE_UNAVAILABLE);
    expect(error.message).toContain(TENANT_GHOST);
    expect(error.message).toContain("control registry");
  });

  test("a tenant registered WITHOUT a binding name is refused, not fallen back", async () => {
    const error = await refusal(resolver().forTenant(TENANT_UNBOUND), TENANT_DATABASE_UNAVAILABLE);
    // The operator gets the actionable cause: the Worker needs a redeploy.
    expect(error.message).toContain("binding_name");
  });

  test("a registration naming a binding this Worker does not have is refused", async () => {
    const error = await refusal(resolver().forTenant(TENANT_INITECH), TENANT_DATABASE_UNAVAILABLE);
    expect(error.message).toContain("TENANT_DB_INITECH");
  });

  test("a registration naming a NON-D1 binding is refused rather than duck-typed", async () => {
    // `GATEWAY_TENANT_DB_ROUTING` is a real binding — a plain string var.
    await refusal(resolver().forTenant(TENANT_NON_D1), TENANT_DATABASE_UNAVAILABLE);
  });

  test("an empty tenant id is refused rather than routed anywhere", async () => {
    await refusal(resolver().forTenant(""), TENANT_DATABASE_UNAVAILABLE);
  });

  test('the retired "off" mode no longer parses, so no shared-DB fallback exists', async () => {
    // #821 PR2-delete: `"off"` and `"shared_development"` — the only modes that
    // read the shared `env.DB` — are gone. Naming `"off"` is now an unknown
    // mode, so the resolver refuses to build at all rather than handing back a
    // shared database. There is nowhere left for a `catch → env.DB` to reach.
    expect(parseTenantDatabaseRoutingMode("off")).toBeUndefined();
    expect(() =>
      createTenantDatabaseResolver({
        ...bindings(),
        GATEWAY_TENANT_DB_ROUTING: "off",
        DB: env.TENANT_DB_ACME,
      }),
    ).toThrow(
      expect.objectContaining({ code: TENANT_DATABASE_ROUTING_MISCONFIGURED, status: 503 }),
    );
  });

  test("EVERY refusal above is an error — none of them is a database", async () => {
    // The single assertion that a `catch → env.DB` anywhere in `src/tenancy/`
    // would break, stated over all six shapes at once.
    const r = resolver();
    const shapes = [TENANT_GHOST, TENANT_UNBOUND, TENANT_INITECH, TENANT_NON_D1, ""];
    const outcomes = await Promise.all(
      shapes.map((tenantId) =>
        r.forTenant(tenantId).then(
          (handle) => `RESOLVED:${handle.tenantId}`,
          () => "refused",
        ),
      ),
    );
    expect(outcomes).toEqual(["refused", "refused", "refused", "refused", "refused"]);
  });
});

// ---------------------------------------------------------------------------
// 4. Misconfiguration is loud, not permissive
// ---------------------------------------------------------------------------

describe("GATEWAY_TENANT_DB_ROUTING parsing", () => {
  test("absent or empty is durable_object; every legal mode round-trips", () => {
    // #819 reversed this: the default used to be `"off"`, i.e. per-tenant
    // storage was opt-in and every deployment that forgot the var had none.
    // `durable_object` costs nothing to turn on — no deploy, no provisioning —
    // so the safe posture is no longer the opt-in one. `durable-object.spec.ts`
    // owns the rest of that claim; this case pins the parse.
    expect(parseTenantDatabaseRoutingMode(undefined)).toBe("durable_object");
    expect(parseTenantDatabaseRoutingMode("   ")).toBe("durable_object");
    // Since #821 PR2-delete only the routed modes survive; every one round-trips.
    for (const mode of ["durable_object", "binding", "binding_strict"]) {
      expect(parseTenantDatabaseRoutingMode(mode)).toBe(mode);
    }
    // The retired shared-`env.DB` modes now parse to `undefined` (an unknown
    // mode) rather than a posture, so a config still naming one is a loud 503.
    expect(parseTenantDatabaseRoutingMode("off")).toBeUndefined();
    expect(parseTenantDatabaseRoutingMode("shared_development")).toBeUndefined();
  });

  test("a typo does NOT silently degrade to a mode", () => {
    expect(parseTenantDatabaseRoutingMode("bindng")).toBeUndefined();
    expect(() =>
      createTenantDatabaseResolver({ ...bindings(), GATEWAY_TENANT_DB_ROUTING: "bindng" }),
    ).toThrow(
      expect.objectContaining({ code: TENANT_DATABASE_ROUTING_MISCONFIGURED, status: 503 }),
    );
  });

  test("a mode whose required binding is absent is misconfigured, not degraded", () => {
    // The control binding a `binding`-mode router requires is now `CONTROL_DATA`
    // (the store `controlDatabaseFrom` resolves), not the native `CONTROL_DB`.
    // Removing it must be a loud misconfiguration, never a silent degrade.
    const { CONTROL_DATA: _control, ...withoutControl } = bindings() as Record<string, unknown>;
    expect(() =>
      createTenantDatabaseResolver({
        ...withoutControl,
        GATEWAY_TENANT_DB_ROUTING: "binding",
      } as TenancyBindings),
    ).toThrow(expect.objectContaining({ code: TENANT_DATABASE_ROUTING_MISCONFIGURED }));

    // The retired "shared_development" mode is now an unknown value, so it too
    // is misconfigured rather than a reachable escape hatch to a shared `DB`.
    expect(() =>
      createTenantDatabaseResolver({
        ...bindings(),
        GATEWAY_TENANT_DB_ROUTING: "shared_development",
      } as TenancyBindings),
    ).toThrow(expect.objectContaining({ code: TENANT_DATABASE_ROUTING_MISCONFIGURED }));
  });
});
