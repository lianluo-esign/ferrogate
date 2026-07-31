/**
 * `TenantDatabaseRouter` against REAL bindings (JOB 3).
 *
 * The property under test is that routing is **physical**: two tenants get two
 * genuinely different databases, and every unresolvable tenant is an error and
 * never a fallback. A router that silently returned the control database on a
 * miss would put one tenant's money in the account-global ledger, which is the
 * exact failure the DB-per-tenant topology exists to prevent — so most of this
 * file is about the refusals.
 */
import { env } from "cloudflare:test";
import { beforeAll, describe, expect, test } from "vitest";
import {
  ControlDatabaseTenantRegistry,
  D1_BINDING_STRATEGIES,
  D1RestTenantDatabaseRouter,
  type EnvBindingTenantDatabaseRouter,
  SharedDatabaseTenantRouter,
  type TenantDatabaseHandle,
  requireAtomicBatch,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, TENANT_C, setupDatabases } from "./harness.js";

let router: EnvBindingTenantDatabaseRouter;

beforeAll(async () => {
  router = await setupDatabases();
});

describe("EnvBindingTenantDatabaseRouter — resolution", () => {
  test("resolves a registered tenant to its own native binding", async () => {
    const handle = await router.forTenant(TENANT_A);
    expect(handle.tenantId).toBe(TENANT_A);
    expect(handle.source).toBe("native_binding");
    expect(handle.supportsAtomicBatch).toBe(true);
    expect(handle.databaseUuid).toBe("uuid-a");
    expect(handle.schemaVersion).toBe(1);
  });

  test("two tenants get two PHYSICALLY different databases", async () => {
    const a = await router.forTenant(TENANT_A);
    const b = await router.forTenant(TENANT_B);
    expect(a.db).not.toBe(b.db);

    // Prove it with data, not identity: a row written through A is absent in B.
    await a.db
      .prepare(
        "INSERT INTO projects (id, tenant_id, name, slug, created_at_unix, updated_at_unix) " +
          "VALUES ('p_route', ?, 'n', 'route-probe', 1, 1) ON CONFLICT (id) DO NOTHING",
      )
      .bind(TENANT_A)
      .run();
    const inA = await a.db.prepare("SELECT id FROM projects WHERE id = 'p_route'").first();
    const inB = await b.db.prepare("SELECT id FROM projects WHERE id = 'p_route'").first();
    expect(inA).not.toBeNull();
    expect(inB).toBeNull();
  });

  test("the control database is NOT any tenant's database", async () => {
    const a = await router.forTenant(TENANT_A);
    expect(router.control()).not.toBe(a.db);
    // The control schema has no `wallets` table; the tenant schema has no
    // `plans` table. Each miss proves the split is physical, not conventional.
    await expect(router.control().prepare("SELECT * FROM wallets").all()).rejects.toThrow();
    await expect(a.db.prepare("SELECT * FROM plans").all()).rejects.toThrow();
  });

  test("provisionedTenants lists every registration, ascending", async () => {
    expect(await router.provisionedTenants()).toEqual([TENANT_A, TENANT_B, TENANT_C]);
  });
});

describe("EnvBindingTenantDatabaseRouter — fail-closed refusals", () => {
  test("an UNREGISTERED tenant is not_found, not the control database", async () => {
    await expect(router.forTenant("tenant_unknown")).rejects.toMatchObject({
      kind: "not_found",
    });
  });

  test("a tenant registered WITHOUT a binding name is refused, not fallen back", async () => {
    // tenant_c is provisioned (it has a uuid) but its Worker binding has not
    // been deployed. This is the state a half-finished onboarding leaves.
    await expect(router.forTenant(TENANT_C)).rejects.toThrow(/has no binding_name/);
  });

  test("a registration naming a binding this Worker does not have is refused", async () => {
    const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
    await registry.upsert(
      {
        tenantId: "tenant_ghost",
        databaseUuid: "uuid-ghost",
        databaseName: "ferrogate-tenant-ghost",
        bindingName: "TENANT_DB_UNBOUND",
        schemaVersion: 1,
      },
      1,
    );
    await expect(router.forTenant("tenant_ghost")).rejects.toThrow(
      /not a D1 database on this Worker's env/,
    );
  });

  test("a registration naming a NON-D1 binding is refused", async () => {
    const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
    await registry.upsert(
      {
        tenantId: "tenant_wrongkind",
        databaseUuid: "uuid-wrongkind",
        databaseName: "x",
        // A real binding on env, but it is a plain JSON var, not a database.
        bindingName: "TENANT_MIGRATIONS",
        schemaVersion: 1,
      },
      1,
    );
    await expect(router.forTenant("tenant_wrongkind")).rejects.toThrow(
      /not a D1 database on this Worker's env/,
    );
  });

  test("an empty tenant id is refused rather than routed anywhere", async () => {
    await expect(router.forTenant("")).rejects.toThrow(/non-empty tenant id/);
  });
});

describe("Registry", () => {
  test("upsert is idempotent by tenant id and can later attach a binding name", async () => {
    const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
    await registry.upsert(
      {
        tenantId: "tenant_late",
        databaseUuid: "uuid-late",
        databaseName: "ferrogate-tenant-late",
        schemaVersion: 1,
      },
      100,
    );
    expect((await registry.get("tenant_late"))?.bindingName).toBeUndefined();

    await registry.upsert(
      {
        tenantId: "tenant_late",
        databaseUuid: "uuid-late",
        databaseName: "ferrogate-tenant-late",
        bindingName: "TENANT_DB_C",
        schemaVersion: 1,
      },
      200,
    );
    const after = await registry.get("tenant_late");
    expect(after?.bindingName).toBe("TENANT_DB_C");
    // Still ONE row — the second call updated rather than duplicated.
    expect((await registry.list()).filter((r) => r.tenantId === "tenant_late")).toHaveLength(1);
  });

  test("an unknown tenant reads back as undefined", async () => {
    const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
    expect(await registry.get("nobody")).toBeUndefined();
  });
});

describe("requireAtomicBatch", () => {
  test("admits a native handle and refuses a REST-shaped one", async () => {
    const native = await router.forTenant(TENANT_A);
    expect(requireAtomicBatch(native, "op")).toBe(native);

    const rest: TenantDatabaseHandle = { ...native, source: "rest", supportsAtomicBatch: false };
    expect(() => requireAtomicBatch(rest, "reserve_wallet_credits")).toThrow(
      /refusing to run the guard non-atomically/,
    );
  });
});

describe("SharedDatabaseTenantRouter", () => {
  test("hands every tenant the same database and labels itself as such", async () => {
    const shared = new SharedDatabaseTenantRouter(env.TENANT_DB_A, ["t1", "t2"]);
    const one = await shared.forTenant("t1");
    const two = await shared.forTenant("t2");
    expect(one.db).toBe(two.db);
    // The label is the point: a downstream reader can tell that this handle
    // carries no physical isolation, even though its atomic primitives are real.
    expect(one.source).toBe("shared_development");
    expect(one.supportsAtomicBatch).toBe(true);
    expect(await shared.provisionedTenants()).toEqual(["t1", "t2"]);
  });

  test("still refuses an empty tenant id", async () => {
    const shared = new SharedDatabaseTenantRouter(env.TENANT_DB_A);
    await expect(shared.forTenant("")).rejects.toThrow(/non-empty tenant id/);
  });
});

describe("D1RestTenantDatabaseRouter", () => {
  test("refuses to hand out a handle, naming the exact missing primitives", async () => {
    const rest = new D1RestTenantDatabaseRouter(env.CONTROL_DB, {
      accountId: "acct",
      apiTokenRef: "secret://d1",
    });
    await expect(rest.forTenant(TENANT_A)).rejects.toThrow(
      /neither atomic batch\(\) nor RETURNING/,
    );
  });

  test("can still enumerate the registry, since that is a control-database read", async () => {
    const rest = new D1RestTenantDatabaseRouter(env.CONTROL_DB, {
      accountId: "acct",
      apiTokenRef: "secret://d1",
    });
    expect(await rest.provisionedTenants()).toContain(TENANT_A);
  });
});

describe("D1_BINDING_STRATEGIES", () => {
  test("records that only native/proxy support the primitives the money paths need", () => {
    expect(D1_BINDING_STRATEGIES.native_binding.atomicBatch).toBe(true);
    expect(D1_BINDING_STRATEGIES.native_binding.returning).toBe(true);
    expect(D1_BINDING_STRATEGIES.proxy_service.atomicBatch).toBe(true);
    // The honest half: REST is the only deploy-free strategy and the only one
    // that cannot host a guard. If this ever flips, the README claim and
    // `D1RestTenantDatabaseRouter`'s refusal both need revisiting.
    expect(D1_BINDING_STRATEGIES.rest.atomicBatch).toBe(false);
    expect(D1_BINDING_STRATEGIES.rest.returning).toBe(false);
    expect(D1_BINDING_STRATEGIES.rest.requiresDeployPerTenant).toBe(false);
  });
});
