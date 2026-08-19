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
import { provisionTenantStorageFor } from "../src/store/tenant_storage.js";
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

  it("populates the control document mirror so the operator LIST serves it without a DO fan-out", async () => {
    const tenantId = freshTenantId("mirror");
    await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ id: tenantId, name: "Mirror", slug: `mirror-${tenantId}` }),
    });

    // The write-through hook filled `tenants.document_json` with the full admin
    // document as part of the create — no backfill, no deploy, no second write.
    const mirrorRow = await db()
      .prepare("SELECT document_json FROM tenants WHERE id = ?")
      .bind(tenantId)
      .first<{ document_json: string | null }>();
    expect(mirrorRow?.document_json).not.toBeNull();
    expect(JSON.parse(mirrorRow?.document_json ?? "null")).toMatchObject({
      id: tenantId,
      name: "Mirror",
    });

    // The operator LIST is now served from that single control-DO query. The
    // onboarded tenant appears in it, end to end through the real route stack.
    const listed = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      headers: { authorization: `Bearer ${OPERATOR}` },
    });
    expect(listed.status).toBe(200);
    const body = (await listed.json()) as { data: { id: string }[] };
    expect(body.data.map((row) => row.id)).toContain(tenantId);
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
      .prepare("DELETE FROM catalog_models WHERE tenant_id = ? AND name = ?")
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
        "UPDATE catalog_model_offerings SET input_price_per_1m = 42.0 " +
          "WHERE tenant_id = ? AND model_id = ?",
      )
      .bind(first, `${first}:model:gpt-4o`)
      .run();

    expect((await resolveTenantModel(a.db, first, "gpt-4o"))?.inputPricePer1m).toBe(42.0);
    expect((await resolveTenantModel(b.db, second, "gpt-4o"))?.inputPricePer1m).toBe(2.5);

    // And the inverse: the second object holds ONLY the second tenant's rows.
    // Without this, a router that ignored its argument and handed both tenants
    // one object would pass the assertion above by writing 42.0 into the shared
    // row and then reading a row it had not touched.
    const rows = await b.db
      .prepare("SELECT DISTINCT tenant_id FROM catalog_models")
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

/**
 * #891: with the managed platform catalog adopted, a new tenant is seeded from
 * the platform graph rather than the compiled-in card.
 *
 * The platform rows are written with RAW SQL into `env.DB` — the same handle the
 * `d1_compat` CONTROL_DATA facade the Worker resolves reads — because a fixture
 * built with `PlatformModelCatalogStore` (the code under test) could not show
 * that provisioning reads what is actually in the table. The assertions below
 * are platform-SPECIFIC on purpose: a real `openai` channel, `source =
 * platform_seed`, and a mark detail carrying the revision — none of which the
 * DEFAULT card produces, so a silent fallback fails rather than passes.
 */
async function seedPlatformCatalog(revision: number): Promise<void> {
  await db().batch([
    db().prepare(
      "INSERT INTO platform_provider_channels " +
        "(id, name, kind, base_url, api_key_var, enabled, created_at_unix, updated_at_unix) " +
        "VALUES ('p-openai', 'OpenAI', 'openai', 'https://api.openai.com/v1', 'OPENAI_API_KEY', 1, 1, 1)",
    ),
    db().prepare(
      "INSERT INTO platform_catalog_models " +
        "(id, name, capabilities_json, routing_strategy, enabled, created_at_unix, updated_at_unix) " +
        "VALUES ('m-4o', 'gpt-4o', '[]', 'priority', 1, 1, 1)",
    ),
    // `source = 'admin'` here proves the seed FORCES 'platform_seed' on the copy
    // rather than carrying the platform label across.
    db().prepare(
      "INSERT INTO platform_catalog_offerings " +
        "(id, model_id, provider_id, upstream_model_id, role, priority, weight, " +
        "input_price_per_1m, output_price_per_1m, currency, source, enabled, " +
        "created_at_unix, updated_at_unix) " +
        "VALUES ('o-4o', 'm-4o', 'p-openai', 'gpt-4o', 'primary', 0, 1, 2.5, 10.0, 'USD', 'admin', 1, 1, 1)",
    ),
    db()
      .prepare(
        "INSERT INTO platform_catalog_revisions (id, revision, updated_at_unix) VALUES (1, ?, 1)",
      )
      .bind(revision),
  ]);
}

async function assertSeededFromPlatform(tenantId: string, revision: number): Promise<void> {
  const handle = await router().forTenant(tenantId);

  // A real `openai` channel with its base_url carried across — not the card's
  // `platform`-kind indirection channel.
  const channel = await handle.db
    .prepare("SELECT kind, base_url FROM provider_channels WHERE tenant_id = ? AND kind = 'openai'")
    .bind(tenantId)
    .first<{ kind: string; base_url: string }>();
  expect(channel?.base_url).toBe("https://api.openai.com/v1");

  // The copied graph, not the 16-entry card.
  const catalog = await listTenantModelCatalog(handle.db, tenantId);
  expect(catalog).toHaveLength(1);
  expect(catalog.length).not.toBe(DEFAULT_TENANT_MODEL_CATALOG.length);

  const model = await resolveTenantModel(handle.db, tenantId, "gpt-4o");
  expect(model?.inputPricePer1m).toBe(2.5);
  expect(model?.provider).toBe("OpenAI");
  expect(model?.source).toBe("platform_seed");

  // The mark records WHICH platform catalog seeded the tenant.
  const mark = await handle.db
    .prepare(
      "SELECT detail FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = 'model_catalog_seed'",
    )
    .bind(tenantId)
    .first<{ detail: string }>();
  expect(mark?.detail).toBe(`revision=${revision};providers=1;models=1;offerings=1`);
}

describe("seeding from the platform catalog (#891)", () => {
  it("POST /admin/v1/tenant-accounts seeds the platform graph, not the card", async () => {
    await seedPlatformCatalog(5);
    const tenantId = freshTenantId("platformcrud");

    const created = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ id: tenantId, name: "Platformy", slug: `platformy-${tenantId}` }),
    });
    expect(created.status).toBe(201);

    await assertSeededFromPlatform(tenantId, 5);
  });

  it("the self-service register path also seeds the platform graph", async () => {
    await seedPlatformCatalog(9);

    const response = await consoleApp.request(
      `${BASE}/v1/admin/register`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "platform-founder@example.test",
          password: "correct horse battery",
          organization_name: "Platform Self Service Co",
        }),
      },
      env,
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as { tenant: { id: string } };

    await assertSeededFromPlatform(body.tenant.id, 9);
  });

  it("a NON-missing-table platform read fault falls back to the card, it does not fail onboarding", async () => {
    // The regression this guards: `exportForSeed` tolerates a missing platform
    // TABLE (the d1_compat migration window), but the SAME window can raise
    // `no such column` when a new Worker's PROVIDER_SELECT references a column a
    // pending migration has not added yet. Before the fix that throw was caught
    // by `provisionTenantStorageFor`'s outer catch, which returned `false`
    // BEFORE `provisionTenantStorage` ran — so the tenant got NO storage, NO
    // roster row, and NOT the documented card fallback. Onboarding must not
    // depend on platform-catalog read health.
    await seedPlatformCatalog(7); // adopted, so a healthy read WOULD seed the graph
    const tenantId = freshTenantId("readfault");
    // A `tenants` row with no object seed yet, so the lazy loader is actually
    // invoked (an already-seeded tenant would short-circuit before it).
    await db()
      .prepare(
        "INSERT INTO tenants (id, name, slug, status, plan_id) VALUES (?, ?, ?, 'active', 'free')",
      )
      .bind(tenantId, "Read Fault", `readfault-${tenantId}`)
      .run();

    const deps = resolveDeps(env as unknown as ControlPlaneBindings, { requestId: "readfault" });
    const realControl = deps.controlDatabase;
    if (realControl === null) throw new Error("expected a control database under store=d1");
    // A statement whose reads reject with a non-missing-table D1 error, returned
    // ONLY for the platform_* catalog SELECTs; everything else delegates to the
    // real control handle unchanged.
    const faultMessage = "D1_ERROR: no such column: platform_provider_channels.some_pending_column";
    const faultStatement = {
      bind: () => faultStatement,
      all: async () => {
        throw new Error(faultMessage);
      },
      first: async () => {
        throw new Error(faultMessage);
      },
      run: async () => {
        throw new Error(faultMessage);
      },
    } as unknown as D1PreparedStatement;
    const faultyControl = new Proxy(realControl, {
      get(target, prop) {
        if (prop === "prepare") {
          return (sql: string): D1PreparedStatement =>
            /\bplatform_/i.test(sql) ? faultStatement : target.prepare(sql);
        }
        const value = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    const provisioned = await provisionTenantStorageFor(
      { ...deps, controlDatabase: faultyControl },
      tenantId,
    );
    // It did NOT fail: storage is ready, from the card.
    expect(provisioned).toBe(true);
    const state = await registry().get(tenantId);
    expect(state?.status).toBe("ready");

    const handle = await router().forTenant(tenantId);
    // The CARD, not the platform graph — the fault degraded to the fallback.
    expect(await listTenantModelCatalog(handle.db, tenantId)).toHaveLength(
      DEFAULT_TENANT_MODEL_CATALOG.length,
    );
    // The card's `platform`-kind indirection channel is present; the graph's real
    // `openai` channel (which a healthy read of the seeded catalog would have
    // copied) is absent — proof the graph read was skipped, not merely empty.
    const platformChannel = await handle.db
      .prepare("SELECT kind FROM provider_channels WHERE tenant_id = ? AND kind = 'platform'")
      .bind(tenantId)
      .first<{ kind: string }>();
    expect(platformChannel?.kind).toBe("platform");
    const openaiChannel = await handle.db
      .prepare("SELECT kind FROM provider_channels WHERE tenant_id = ? AND kind = 'openai'")
      .bind(tenantId)
      .first<{ kind: string }>();
    expect(openaiChannel).toBeNull();
  });

  it("with ZERO platform rows the legacy card seed still runs (pinned)", async () => {
    // No `seedPlatformCatalog` — `resetD1` left the platform tables empty, so
    // this is the bootstrap fallback and it must be the 16-entry card.
    const tenantId = freshTenantId("nocatalog");
    const created = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
      body: JSON.stringify({ id: tenantId, name: "Cardy", slug: `cardy-${tenantId}` }),
    });
    expect(created.status).toBe(201);

    const handle = await router().forTenant(tenantId);
    expect(await listTenantModelCatalog(handle.db, tenantId)).toHaveLength(
      DEFAULT_TENANT_MODEL_CATALOG.length,
    );
    // The card's `platform`-kind indirection channel, never a real `openai` one.
    const platformChannel = await handle.db
      .prepare("SELECT kind FROM provider_channels WHERE tenant_id = ? AND kind = 'platform'")
      .bind(tenantId)
      .first<{ kind: string }>();
    expect(platformChannel?.kind).toBe("platform");
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
