/**
 * TENANT ONBOARDING, end to end through the real HTTP surfaces (#820).
 *
 * ## What this proves that `packages/storage` cannot
 *
 * The storage package proves the PROVISIONER: refuse an unregistered tenant,
 * record resumable state, seed once, never clobber. It cannot prove that
 * anything CALLS it. That is the defect this slice was written for — nothing in
 * production wrote `tenant_databases` at all, and every `registry.upsert(` in
 * the tree was a test — so "the code is correct and unreachable" is precisely
 * the failure shape to guard against.
 *
 * So this file drives the two creation entry points over HTTP and asserts on the
 * storage that results:
 *
 *  * `POST /admin/v1/tenant-accounts` — the generic CRUD leg, through the
 *    `provision` hook on the collection spec;
 *  * `POST /v1/admin/register` — console self-service, which bypasses
 *    `crudGroup` entirely and therefore runs NO spec hook of any kind. It is the
 *    entry point that gets forgotten, and before this slice it wrote neither the
 *    typed `tenants` row nor any storage.
 *
 * ## The object is the REAL one
 *
 * `TENANT_DATA` here is the gateway's `TenantDataObject`, bound cross-script
 * exactly as `wrangler.toml` binds it, published into the session by
 * `gatewayTenantDataAuxWorker` (`vitest.config.ts`). So `idFromName(tenantId)`
 * names the same object the data plane would read, the schema is applied by the
 * object itself on its first wake, and a stub that agreed with the provisioner
 * would not have been able to do either.
 */
import { SELF, env } from "cloudflare:test";
import {
  ControlDatabaseTenantRegistry,
  DEFAULT_TENANT_MODEL_CATALOG,
  listTenantModelCatalog,
  resolveTenantModel,
} from "@ferrogate/storage";
import { Hono } from "hono";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveDeps, resolveTenantStorage } from "../src/adapters.js";
import { contractAuth } from "../src/middleware/auth.js";
import { adminCorsPreflight, corsResponseHeaders } from "../src/middleware/cors.js";
import {
  controlPlaneErrorHandler,
  controlPlaneNotFoundHandler,
  requestId,
} from "../src/middleware/errors.js";
import type { ControlPlaneBindings, ControlPlaneEnv } from "../src/ports.js";
import { mountAdminConsoleSession } from "../src/session/index.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm } from "./harness.js";
import { applyTenantSchema, resetTenantD1 } from "./tenant-db.js";

const OPERATOR = "onboarding-operator-key";
const FLEET_OPERATOR = "onboarding-fleet-operator-key";
const JWT_SECRET = "onboarding-signing-secret-for-tests";

/**
 * The console-session app, composed the way `src/index.ts` composes it — the
 * same shape `console-session.test.ts` uses, because `POST /v1/admin/register`
 * is mounted by the integrate step rather than by the contract router.
 */
function buildConsoleApp(): Hono<ControlPlaneEnv> {
  const app = new Hono<ControlPlaneEnv>();
  app.onError(controlPlaneErrorHandler);
  app.notFound(controlPlaneNotFoundHandler);
  app.use("*", requestId);
  app.use("*", async (c, next) => {
    c.set("deps", resolveDeps(c.env, { requestId: c.get("requestId") }));
    await next();
  });
  app.use("*", corsResponseHeaders);
  app.use("*", adminCorsPreflight);
  app.use("*", contractAuth());
  mountAdminConsoleSession(app);
  return app;
}

const consoleApp = buildConsoleApp();

/**
 * The PROVISIONING router the Worker builds, so a test reads what production
 * reads. Deliberately `resolveTenantStorage` and not `resolveTenantDatabases`:
 * those are two different routers on this Worker today, and the reason is
 * documented on `resolveTenantStorage`.
 */
function router() {
  return resolveTenantStorage(env as unknown as ControlPlaneBindings);
}

function registry(): ControlDatabaseTenantRegistry {
  return new ControlDatabaseTenantRegistry(db());
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  await resetD1();
  await resetTenantD1();
  // The D1 store, not the in-memory one: `runProjection` and the provisioning
  // hook are both gated on `controlDatabase`, which is `null` under
  // `CONTROL_PLANE_STORE = "memory"`. A memory-store run would pass every
  // assertion below vacuously by never reaching the code under test.
  arm({
    store: "d1",
    staticKeys: [
      { secret: OPERATOR, platform_operator: true },
      // `admin.assets.fleet` must be held EXACTLY — `hasScope`'s wildcard does
      // not reach it (see `ASSET_FLEET_SCOPE`), so the platform-operator key
      // above cannot open the fleet view and a second key is not redundant.
      {
        secret: FLEET_OPERATOR,
        platform_operator: true,
        scopes: ["admin.read", "admin.write", "admin.assets.fleet"],
      },
    ],
  });
  (env as unknown as Record<string, string | undefined>).ADMIN_CONSOLE_JWT_SECRET = JWT_SECRET;
});

/** A fresh tenant id per test, so a persisted Durable Object cannot be reused. */
function freshTenantId(label: string): string {
  return `tenant_onboard_${label}_${crypto.randomUUID().slice(0, 8)}`;
}

describe("the provisioning router", () => {
  it("resolves tenants through TENANT_DATA — the gateway's namespace, cross-script", async () => {
    // Not a tautology: this Worker had NO object namespace at all before #820,
    // so onboarding could only ever have provisioned a D1 database that
    // `apps/gateway` (on `durable_object` since #819) would never read. The
    // binding is what makes `idFromName(tenantId)` the same object on both sides.
    const handle = await router().forTenant("tenant_probe");
    expect(handle.source).toBe("durable_object");
    expect(handle.supportsAtomicBatch).toBe(true);
  });
});

describe("POST /admin/v1/tenant-accounts", () => {
  it("provisions storage: a tenants row, a state row, a schema, and a catalog", async () => {
    const tenantId = freshTenantId("crud");

    const created = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ id: tenantId, name: "Acme", slug: `acme-${tenantId}` }),
    });
    expect(created.status).toBe(201);

    // (1) the typed `tenants` row — what the gateway's lifecycle read and its
    // plan join both traverse, and what the provisioner admits on.
    const tenantRow = await db()
      .prepare("SELECT id, status FROM tenants WHERE id = ?")
      .bind(tenantId)
      .first<{ id: string; status: string }>();
    expect(tenantRow?.status).toBe("active");

    // (2) the state row, at `ready`.
    const state = await registry().get(tenantId);
    expect(state?.status).toBe("ready");
    expect(state?.storageBackend).toBe("durable_object");
    expect(state?.lastError).toBeUndefined();

    // (3) the object at the CURRENT schema version. The object migrated itself
    // on first wake; nothing here applied a migration.
    expect(state?.schemaVersion).toBeGreaterThanOrEqual(8);

    // (4) a non-empty catalog, read back through the same router the data plane
    // would use. No manual step and no deploy happened between (1) and here.
    const handle = await router().forTenant(tenantId);
    expect(await listTenantModelCatalog(handle.db, tenantId)).toHaveLength(
      DEFAULT_TENANT_MODEL_CATALOG.length,
    );
    const model = await resolveTenantModel(handle.db, tenantId, "gpt-4o");
    expect(model?.providerModel).toBe("gpt-4o");
    expect(model?.inputPricePer1m).toBe(2.5);
  });

  it("puts the tenant on the fleet roster, which is the only enumeration there is", async () => {
    const tenantId = freshTenantId("roster");
    await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ id: tenantId, name: "Roster", slug: `roster-${tenantId}` }),
    });
    // A Durable Object namespace cannot be listed in production, so a tenant
    // missing from here is invisible to `store/asset_fleet.ts` and every other
    // fleet view.
    expect(await router().provisionedTenants()).toContain(tenantId);
  });

  it("a PATCH re-runs provisioning as a no-op that does not clobber a catalog edit", async () => {
    const tenantId = freshTenantId("patch");
    await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ id: tenantId, name: "Patchy", slug: `patchy-${tenantId}` }),
    });

    const handle = await router().forTenant(tenantId);
    await handle.db
      .prepare("DELETE FROM model_catalog WHERE tenant_id = ? AND model = ?")
      .bind(tenantId, "gpt-5")
      .run();

    const patched = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/${tenantId}`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ name: "Patchy Renamed" }),
    });
    expect(patched.status).toBe(200);

    // PUT/PATCH are repair points for a tenant whose provisioning failed, which
    // means they re-run it — so a tenant that removed a model must not find it
    // reinstated by renaming its account.
    expect(await resolveTenantModel(handle.db, tenantId, "gpt-5")).toBeUndefined();
    expect(await listTenantModelCatalog(handle.db, tenantId)).toHaveLength(
      DEFAULT_TENANT_MODEL_CATALOG.length - 1,
    );
  });

  it("two tenants created in sequence get two DISTINCT objects with independent data", async () => {
    const first = freshTenantId("iso1");
    const second = freshTenantId("iso2");
    for (const tenantId of [first, second]) {
      await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
        method: "POST",
        headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
        body: JSON.stringify({ id: tenantId, name: tenantId, slug: tenantId }),
      });
    }

    const a = await router().forTenant(first);
    const b = await router().forTenant(second);
    await a.db
      .prepare(
        "UPDATE model_catalog SET input_price_per_1m = 42.0 WHERE tenant_id = ? AND model = ?",
      )
      .bind(first, "gpt-4o")
      .run();

    expect((await resolveTenantModel(a.db, first, "gpt-4o"))?.inputPricePer1m).toBe(42.0);
    expect((await resolveTenantModel(b.db, second, "gpt-4o"))?.inputPricePer1m).toBe(2.5);

    // And the inverse: the second object holds ONLY the second tenant's rows.
    // Without this, a router that ignored its argument and handed both tenants
    // one object would pass the assertion above by writing 42.0 into the shared
    // row and then reading a row it had not touched.
    const rows = await b.db
      .prepare("SELECT DISTINCT tenant_id FROM model_catalog")
      .all<{ tenant_id: string }>();
    expect(rows.results.map((row) => row.tenant_id)).toEqual([second]);
  });
});

describe("POST /v1/admin/register (console self-service)", () => {
  it("writes the typed tenants row AND provisions storage, with no spec hook in play", async () => {
    // This handler bypasses `crudGroup` and writes the documents directly, so
    // NEITHER the projection nor the provisioning hook runs for it — both had to
    // be called explicitly, and before #820 neither was. The visible consequence
    // was a self-registered tenant with no `tenants` row at all, so the
    // gateway's lifecycle read and its plan join both missed.
    const response = await consoleApp.request(
      `${BASE}/v1/admin/register`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "founder@example.test",
          password: "correct horse battery",
          organization_name: "Self Service Co",
        }),
      },
      env,
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as { tenant: { id: string } };
    const tenantId = body.tenant.id;

    const tenantRow = await db()
      .prepare("SELECT id, plan_id, status FROM tenants WHERE id = ?")
      .bind(tenantId)
      .first<{ id: string; plan_id: string; status: string }>();
    expect(tenantRow).not.toBeNull();
    expect(tenantRow?.plan_id).toBe("free");
    expect(tenantRow?.status).toBe("active");

    const state = await registry().get(tenantId);
    expect(state?.status).toBe("ready");
    expect(state?.storageBackend).toBe("durable_object");

    const handle = await router().forTenant(tenantId);
    expect(await listTenantModelCatalog(handle.db, tenantId)).toHaveLength(
      DEFAULT_TENANT_MODEL_CATALOG.length,
    );
  });
});

describe("junk objects", () => {
  it("an id with no tenants row gets NO state row — nothing addresses its object", async () => {
    // First touch is the provisioning event, so a typo or a probe would create a
    // real, billable, unenumerable object. The roster row is the observable half
    // of the ordering: the provisioner writes `pending` BEFORE touching storage,
    // so no row here means nothing was touched.
    const { provisionTenantStorage } = await import("@ferrogate/storage");
    await expect(provisionTenantStorage(router(), "tenant_never_registered")).rejects.toThrow(
      /has no row in the control database's tenants table/,
    );
    expect(await registry().get("tenant_never_registered")).toBeUndefined();
    expect(await router().provisionedTenants()).not.toContain("tenant_never_registered");
  });
});

/**
 * The follow-up defect #820 left behind: a tenant was PROVISIONED onto a Durable
 * Object and every tenant-DATA path on this Worker still resolved through
 * `EnvBindingTenantDatabaseRouter`, which serves `[[d1_databases]]` bindings and
 * answers `not_found` for a `durable_object` roster row. Every caller reads
 * `not_found` as "no tenant database, act on the document only", so the two
 * halves failed silently and in opposite directions:
 *
 *  - an admin wallet credit answered 200 having written no `wallets` row
 *    anywhere, so the gateway's no-oversell reserve found no wallet and the
 *    tenant was never denied on a prepaid balance;
 *  - the fleet asset view enumerated the roster, dropped every tenant on it, and
 *    answered an empty page with an EMPTY `unreadable_tenants` — the "green, and
 *    wrong" outcome `tenant-do.ts` says the roster survives to prevent.
 *
 * `BackendDispatchingTenantDatabaseRouter` reads `storage_backend` and sends
 * each tenant to the backend its own row names. These tests assert the money and
 * the inventory land in the object the DATA PLANE reads, addressed through the
 * provisioning router so a wrong address cannot pass.
 */
describe("the control plane writes into the object the data plane reads", () => {
  async function createTenant(tenantId: string): Promise<void> {
    const created = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ id: tenantId, name: "Routed", slug: `routed-${tenantId}` }),
    });
    expect(created.status).toBe(201);
  }

  it("an admin wallet credit lands in the tenant's DURABLE OBJECT, not only the document", async () => {
    const tenantId = freshTenantId("wallet");
    await createTenant(tenantId);

    const wallet = await SELF.fetch(`${BASE}/admin/v1/wallets`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ tenant_id: tenantId, balance_cents: 0 }),
    });
    expect(wallet.status).toBe(201);

    const credited = await SELF.fetch(`${BASE}/admin/v1/wallets/${tenantId}/adjust`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ amount_cents: 50_000, reason: "prepaid top-up" }),
    });
    expect(credited.status).toBe(200);

    // THE ASSERTION. `wallets.balance_credits` inside the tenant's own object is
    // the row `D1WalletStore.reserveWalletCredits` guards on the inference path.
    // Before the dispatcher this read `null` — the operator saw $500 credited
    // and the gateway had nothing to enforce.
    const handle = await router().forTenant(tenantId);
    const row = await handle.db
      .prepare("SELECT balance_credits FROM wallets WHERE tenant_id = ?")
      .bind(tenantId)
      .first<{ balance_credits: string | number }>();
    // 50,000 cents at 10,000 credits per cent. Compared as a string because the
    // column crosses the RPC boundary as one — credits can exceed 2^53.
    expect(String(row?.balance_credits)).toBe("500000000");

    // And a charge is now decided against THAT balance rather than the document's
    // running total: 6,000 cents is affordable, so this is 200 and not a 409.
    const charged = await SELF.fetch(`${BASE}/admin/v1/wallets/${tenantId}/charge`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ amount_cents: 6_000, reason: "usage" }),
    });
    expect(charged.status).toBe(200);
    const after = await handle.db
      .prepare("SELECT balance_credits FROM wallets WHERE tenant_id = ?")
      .bind(tenantId)
      .first<{ balance_credits: string | number }>();
    expect(String(after?.balance_credits)).toBe("440000000");
  });

  it("the fleet asset view reaches a durable_object tenant instead of skipping it", async () => {
    const tenantId = freshTenantId("fleet");
    await createTenant(tenantId);

    // Seeded straight into the tenant's object, because the point is that the
    // FLEET READ finds rows the admin surface did not put there. `stored_assets`
    // is part of the tenant schema the object applies to itself.
    const handle = await router().forTenant(tenantId);
    await handle.db
      .prepare(
        "INSERT INTO stored_assets (id, tenant_id, asset_type, name, version, variant, " +
          "content_type, content_hash, size_bytes, created_at_unix, updated_at_unix) " +
          "VALUES (?, ?, 'binary', 'agentctl', '1.0.0', 'linux-amd64', " +
          "'application/octet-stream', 'sha256:seed', 12, 1, 1)",
      )
      .bind(`asset_${tenantId}`, tenantId)
      .run();

    const page = await SELF.fetch(`${BASE}/admin/v1/assets`, {
      headers: { authorization: `Bearer ${FLEET_OPERATOR}` },
    });
    expect(page.status).toBe(200);
    const body = (await page.json()) as {
      data: { id: string; tenant_id: string }[];
      unreadable_tenants?: string[];
    };
    // Before the dispatcher this was `{data: [], unreadable_tenants: []}` — an
    // answer indistinguishable from "the fleet has no assets", which is the one
    // failure mode a fleet inventory must never have.
    expect(body.data.map((row) => row.id)).toContain(`asset_${tenantId}`);
    expect(body.unreadable_tenants ?? []).toEqual([]);
  });

  it("deleting a tenant does NOT provision it — no object is manufactured", async () => {
    // The only teardown the contract has is `PATCH {"status":"deleted"}`, and
    // `mergeHandler` runs the `provision` hook unconditionally. So a tenant that
    // has no storage yet used to have its object CREATED, seeded and marked
    // `ready` by the request that deleted it — permanently billable, never
    // usable. `assertTenantRegistered` refuses `deleted`, and the delete still
    // succeeds because the refusal is recorded rather than raised.
    const tenantId = freshTenantId("deleted");
    await createTenant(tenantId);
    // Drop the roster row so this asserts about PROVISIONING rather than about
    // idempotence: a tenant created a moment ago is already `ready`, and a
    // no-op resume would pass whatever the guard did.
    await db().prepare("DELETE FROM tenant_databases WHERE tenant_id = ?").bind(tenantId).run();

    const deleted = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/${tenantId}`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ status: "deleted" }),
    });
    expect(deleted.status).toBe(200);

    // No roster row means nothing was provisioned: the provisioner writes
    // `pending` BEFORE it touches storage, so its absence is the evidence.
    expect(await registry().get(tenantId)).toBeUndefined();
    expect(await router().provisionedTenants()).not.toContain(tenantId);
  });
});
