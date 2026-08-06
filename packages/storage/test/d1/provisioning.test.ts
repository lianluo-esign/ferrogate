/**
 * TENANT ONBOARDING (#820), against a REAL backend — both of them.
 *
 * This file is in `test/d1/` rather than `test/do/` on purpose: the suite runs
 * TWICE (`vitest.d1.config.ts` → `native_binding`, `vitest.d1do.config.ts` →
 * `durable_object`), so every claim below is proved against per-tenant D1
 * bindings AND against per-tenant Durable Objects, through the same code. A
 * provisioner that only worked over one of them would be a provisioner that
 * silently stopped working the day a deployment changed
 * `GATEWAY_TENANT_DB_ROUTING`.
 *
 * Two things differ between the legs and both are asserted rather than avoided:
 *
 *  * the reported `storageBackend` (that is the point of the two legs), and
 *  * the reported `schemaVersion`. Inside an object `storage_schema_migrations`
 *    is authoritative — `TenantDataObject` writes one row per migration file, so
 *    it reads `TENANT_SCHEMA_VERSION`. In D1 that ledger is vestigial: only
 *    `0001_init_tenant` ever inserts and `wrangler d1 migrations apply` does the
 *    real bookkeeping elsewhere, so a D1 tenant honestly reports `1`. Asserting
 *    the same number on both legs would mean asserting a lie on one of them.
 */
import { env, listDurableObjectIds } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { StorageError } from "../../src/errors.js";
import {
  ControlDatabaseTenantRegistry,
  DEFAULT_TENANT_MODEL_CATALOG,
  MODEL_CATALOG_SEED_MARK,
  type TenantDatabaseRouter,
  describeTenantStorage,
  listTenantModelCatalog,
  provisionTenantStorage,
  resolveTenantModel,
  retireTenantStorage,
} from "../../src/index.js";
import { TENANT_SCHEMA_VERSION } from "../../src/tenant-schema-sql.js";
import {
  IS_DURABLE_OBJECT_BACKEND,
  TENANT_A,
  TENANT_B,
  TENANT_C,
  setupTenantRouter,
  tenantDb,
} from "./harness.js";

const NOW = 1_700_000_500;

/** An id no `tenants` row will ever carry — the junk-object case. */
const UNREGISTERED = "tenant_typo_or_probe";

let router: TenantDatabaseRouter;

/**
 * A `tenants` row is what {@link provisionTenantStorage} admits on, so the
 * fixture writes one directly rather than through `projectTenantAccount` (which
 * lives in `apps/control-plane` and is not importable here). Raw SQL for the
 * usual reason: a fixture built with the code under test cannot show that the
 * code under test reads what is actually in the table.
 */
async function registerTenant(tenantId: string, status = "active"): Promise<void> {
  await env.CONTROL_DB.prepare(
    "INSERT INTO tenants (id, name, slug, status, plan_id, created_at_unix, updated_at_unix) " +
      "VALUES (?, ?, ?, ?, 'free', ?, ?) ON CONFLICT (id) DO UPDATE SET status = excluded.status",
  )
    .bind(tenantId, tenantId, tenantId, status, NOW, NOW)
    .run();
}

beforeEach(async () => {
  router = await setupTenantRouter();
  await env.CONTROL_DB.prepare("DELETE FROM tenants").run();
  // The roster rows are cleared on the DO leg ONLY, and the asymmetry is not a
  // convenience: under `native_binding` the `tenant_databases` row carries
  // `binding_name`, which IS the route, so deleting it would leave the harness's
  // tenants unroutable and this file would be testing the refusal path in every
  // test. Under `durable_object` the row carries no part of the address, so
  // clearing it is free and buys a real assertion — that provisioning CREATES
  // the roster row rather than only updating one the harness left behind.
  if (IS_DURABLE_OBJECT_BACKEND) {
    await env.CONTROL_DB.prepare("DELETE FROM tenant_databases").run();
  }
  // The tenant side too: under `durable_object` the objects persist across
  // files in `.wrangler/state`, so a leftover seed mark from a previous run
  // would make "seeding a fresh tenant" pass by having already happened.
  for (const tenantId of [TENANT_A, TENANT_B, TENANT_C]) {
    const db = tenantDb(tenantId);
    await db.batch([
      db.prepare("DELETE FROM catalog_model_offerings"),
      db.prepare("DELETE FROM catalog_models"),
      db.prepare("DELETE FROM provider_channels"),
      db.prepare("DELETE FROM catalog_audit_outbox"),
      db.prepare("DELETE FROM catalog_revisions"),
      db.prepare("DELETE FROM tenant_database_identity"),
      db.prepare("DELETE FROM tenant_provisioning_marks"),
    ]);
  }
});

describe("refusing before the object is addressed", () => {
  test.runIf(IS_DURABLE_OBJECT_BACKEND)(
    "an unknown tenant does not materialize its Durable Object",
    async () => {
      const targetId = env.TENANT_DATA.idFromName(UNREGISTERED).toString();
      const before = await listDurableObjectIds(env.TENANT_DATA);
      expect(before.some((id) => id.toString() === targetId)).toBe(false);

      await expect(provisionTenantStorage(router, UNREGISTERED)).rejects.toThrow(
        /has no row in the control database's tenants table/,
      );

      const after = await listDurableObjectIds(env.TENANT_DATA);
      expect(after.some((id) => id.toString() === targetId)).toBe(false);
    },
  );

  test("a tenant with no `tenants` row is refused, and leaves NO roster row", async () => {
    await expect(provisionTenantStorage(router, UNREGISTERED)).rejects.toThrow(
      /has no row in the control database's tenants table/,
    );

    // The refusal has to happen BEFORE anything is written or addressed,
    // otherwise the guard creates the very object it exists to prevent. The
    // roster row is the observable half of that ordering: if the `pending` write
    // had run first, a row would be here.
    const registration = await new ControlDatabaseTenantRegistry(env.CONTROL_DB).get(UNREGISTERED);
    expect(registration).toBeUndefined();
  });

  test("the refusal is `not_found`, not a generic runtime error", async () => {
    // The kind is load-bearing for the control plane: `store/tenancy.ts` maps
    // `not_found` to a document-only outcome and everything else to a 503.
    const error = await provisionTenantStorage(router, UNREGISTERED).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StorageError);
    expect((error as StorageError).kind).toBe("not_found");
  });

  test("a blank tenant id is refused before anything else", async () => {
    // `idFromName("")` is a perfectly valid Durable Object id, so a blank id
    // would provision ONE shared object for every unclassified caller.
    await expect(provisionTenantStorage(router, "  ")).rejects.toThrow(/non-empty tenant id/);
  });

  test("a SUSPENDED tenant is still provisioned", async () => {
    // Suspension is reversible and the tenant's data must survive it. Refusing
    // here would mean a tenant suspended between creation and its first
    // provisioning attempt could never be resumed — a billing control turned
    // into data loss. Whether a REQUEST may be served is the lifecycle gate's
    // question, asked per request, strictly later.
    await registerTenant(TENANT_A, "suspended");
    const outcome = await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });
    expect(outcome.status).toBe("ready");
  });
});

describe("provisioning a tenant end to end", () => {
  test("records the immutable placement decision and its registration signal", async () => {
    await registerTenant(TENANT_A);

    await provisionTenantStorage(router, TENANT_A, {
      nowUnix: NOW,
      locationHint: "weur",
      locationHintSource: "cf.continent=EU;cf.colo=FRA",
      locationHintRecordedAtUnix: NOW,
    });

    const registration = await new ControlDatabaseTenantRegistry(env.CONTROL_DB).get(TENANT_A);
    expect(registration).toMatchObject({
      locationHint: "weur",
      locationHintSource: "cf.continent=EU;cf.colo=FRA",
      locationHintRecordedAtUnix: NOW,
    });
  });

  test("yields a state row, an object at the current schema version, and a catalog", async () => {
    await registerTenant(TENANT_A);

    const outcome = await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });

    expect(outcome.status).toBe("ready");
    // `resumed` reports whether a non-`ready` roster row already existed. On the
    // DO leg there is none, so this is a first onboarding; on the native leg the
    // harness pre-registers every tenant's binding, so it genuinely IS a resume
    // and reporting `false` there would be the lie.
    expect(outcome.resumed).toBe(!IS_DURABLE_OBJECT_BACKEND);
    expect(outcome.catalogSeeded).toBe(true);
    expect(outcome.catalogEntries).toBe(DEFAULT_TENANT_MODEL_CATALOG.length);
    // A guard on the fixture: an empty default card would make "non-empty
    // catalog" pass vacuously everywhere below.
    expect(DEFAULT_TENANT_MODEL_CATALOG.length).toBe(16);
    expect(outcome.storageBackend).toBe(
      IS_DURABLE_OBJECT_BACKEND ? "durable_object" : "native_binding",
    );
    expect(outcome.schemaVersion).toBe(IS_DURABLE_OBJECT_BACKEND ? TENANT_SCHEMA_VERSION : 1);

    const registration = await new ControlDatabaseTenantRegistry(env.CONTROL_DB).get(TENANT_A);
    expect(registration?.status).toBe("ready");
    expect(registration?.schemaVersion).toBe(outcome.schemaVersion);
    expect(registration?.storageBackend).toBe(outcome.storageBackend);
    expect(registration?.catalogSeededAtUnix).toBe(NOW);
    expect(registration?.lastError).toBeUndefined();
  });

  test("the tenant appears in provisionedTenants(), which is the only roster there is", async () => {
    // A Durable Object namespace cannot be enumerated in production, so a tenant
    // absent from this list is invisible to every fleet view
    // (`apps/control-plane/src/store/asset_fleet.ts` fans out over it). Before
    // this slice NOTHING in production wrote the table it reads.
    await registerTenant(TENANT_A);
    const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
    // Stated as "not ready" rather than "absent" so it holds on both legs: the
    // native harness leaves a row behind because that row is the route.
    expect((await registry.get(TENANT_A))?.status).not.toBe("ready");

    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });

    expect(await router.provisionedTenants()).toContain(TENANT_A);
    expect((await registry.get(TENANT_A))?.status).toBe("ready");
  });

  test("the first inference-shaped model resolution succeeds with NO manual step", async () => {
    // The acceptance claim, at the storage layer: nobody wrote a model row, no
    // deploy happened between registration and this read, and a model the tenant
    // never configured resolves — priced.
    await registerTenant(TENANT_A);
    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });

    const handle = await router.forTenant(TENANT_A);
    const resolved = await resolveTenantModel(handle.db, TENANT_A, "gpt-4o");
    expect(resolved?.providerModel).toBe("gpt-4o");
    expect(resolved?.inputPricePer1m).toBe(2.5);
    expect(resolved?.enabled).toBe(true);
    expect(resolved?.source).toBe("platform_seed");
  });

  test("an unknown model resolves to nothing — the catalog is not a wildcard", async () => {
    await registerTenant(TENANT_A);
    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });
    const handle = await router.forTenant(TENANT_A);
    expect(await resolveTenantModel(handle.db, TENANT_A, "no-such-model")).toBeUndefined();
  });
});

describe("catalog seeding is best effort", () => {
  test("a failed seed is recoverable and does not throw from provisioning", async () => {
    await registerTenant(TENANT_A);

    const incomplete = await provisionTenantStorage(router, TENANT_A, {
      nowUnix: NOW,
      catalog: [],
    });

    expect(incomplete.status).toBe("incomplete");
    expect(incomplete.catalogSeeded).toBe(false);
    expect(incomplete.catalogEntries).toBe(0);

    const handle = await router.forTenant(TENANT_A);
    const mark = await handle.db
      .prepare("SELECT mark FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
      .bind(TENANT_A, MODEL_CATALOG_SEED_MARK)
      .first();
    expect(mark).toBeNull();

    const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
    const registration = await registry.get(TENANT_A);
    expect(registration?.status).toBe("incomplete");
    expect(registration?.lastError).toMatch(/catalog seed requires at least one entry/);
    expect((await registry.listUnfinished()).map((row) => row.tenantId)).toContain(TENANT_A);

    const recovered = await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW + 60 });
    expect(recovered.status).toBe("ready");
    expect(recovered.catalogSeeded).toBe(true);
    expect(recovered.catalogEntries).toBe(DEFAULT_TENANT_MODEL_CATALOG.length);
    expect((await registry.get(TENANT_A))?.lastError).toBeUndefined();
  });

  test("repairs a stale seed mark before retrying the catalog", async () => {
    await registerTenant(TENANT_A);
    const handle = await router.forTenant(TENANT_A);
    await handle.db
      .prepare(
        "INSERT INTO tenant_provisioning_marks (tenant_id, mark, detail, applied_at_unix) " +
          "VALUES (?, ?, 'entries=0', ?)",
      )
      .bind(TENANT_A, MODEL_CATALOG_SEED_MARK, NOW)
      .run();

    const recovered = await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW + 60 });

    expect(recovered.status).toBe("ready");
    expect(recovered.catalogSeeded).toBe(true);
    expect(recovered.catalogEntries).toBe(DEFAULT_TENANT_MODEL_CATALOG.length);
    expect(
      await handle.db
        .prepare("SELECT COUNT(*) AS count FROM catalog_models WHERE tenant_id = ?")
        .bind(TENANT_A)
        .first<{ count: number }>(),
    ).toEqual({ count: DEFAULT_TENANT_MODEL_CATALOG.length });
  });

  test("does not resurrect a tenant that intentionally deletes every model", async () => {
    await registerTenant(TENANT_A);
    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });

    const handle = await router.forTenant(TENANT_A);
    await handle.db.prepare("DELETE FROM catalog_models WHERE tenant_id = ?").bind(TENANT_A).run();

    const rerun = await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW + 60 });

    expect(rerun.status).toBe("incomplete");
    expect(rerun.catalogSeeded).toBe(false);
    expect(rerun.catalogEntries).toBe(0);
    expect(await listTenantModelCatalog(handle.db, TENANT_A)).toHaveLength(0);
    expect(
      await handle.db
        .prepare("SELECT mark FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
        .bind(TENANT_A, MODEL_CATALOG_SEED_MARK)
        .first(),
    ).not.toBeNull();

    const registration = await new ControlDatabaseTenantRegistry(env.CONTROL_DB).get(TENANT_A);
    expect(registration?.status).toBe("incomplete");
    expect(registration?.catalogSeededAtUnix).toBeUndefined();
  });
});

describe("two tenants, two independent stores", () => {
  test("provisioned in sequence, they do not share a catalog", async () => {
    await registerTenant(TENANT_A);
    await registerTenant(TENANT_B);
    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });
    await provisionTenantStorage(router, TENANT_B, { nowUnix: NOW });

    const a = await router.forTenant(TENANT_A);
    const b = await router.forTenant(TENANT_B);

    // A's edit must be invisible to B. Under `durable_object` that is physical
    // (two objects); under `native_binding` it is physical too (two databases);
    // and under a shared database it would be the `tenant_id` predicate. The
    // assertion is the same in all three, which is why it is worth making.
    await a.db
      .prepare(
        "UPDATE catalog_model_offerings SET input_price_per_1m = 999.0 " +
          "WHERE tenant_id = ? AND model_id = ?",
      )
      .bind(TENANT_A, `${TENANT_A}:model:gpt-4o`)
      .run();

    expect((await resolveTenantModel(a.db, TENANT_A, "gpt-4o"))?.inputPricePer1m).toBe(999.0);
    expect((await resolveTenantModel(b.db, TENANT_B, "gpt-4o"))?.inputPricePer1m).toBe(2.5);

    // And the inverse direction of the same claim: B's catalog holds ONLY B's
    // rows. Without this, a store that ignored its tenant argument and wrote
    // everything into one place would pass the assertion above by luck.
    const bRows = await b.db
      .prepare("SELECT DISTINCT tenant_id FROM catalog_models")
      .all<{ tenant_id: string }>();
    expect(bRows.results.map((row) => row.tenant_id)).toEqual([TENANT_B]);
  });
});

describe("re-running provisioning", () => {
  test("is a no-op that does not clobber the tenant's own catalog edits", async () => {
    await registerTenant(TENANT_A);
    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });

    const handle = await router.forTenant(TENANT_A);
    // Three different KINDS of edit, because they fail differently: a re-price
    // is protected by `INSERT OR IGNORE` alone, a DELETE is not (that is what
    // the seed mark is for), and a disable must not be reverted either.
    await handle.db
      .prepare(
        "UPDATE catalog_model_offerings SET input_price_per_1m = 1.0 " +
          "WHERE tenant_id = ? AND model_id = ?",
      )
      .bind(TENANT_A, `${TENANT_A}:model:gpt-4o`)
      .run();
    await handle.db
      .prepare("DELETE FROM catalog_models WHERE tenant_id = ? AND name = ?")
      .bind(TENANT_A, "claude-opus-4")
      .run();
    await handle.db
      .prepare("UPDATE catalog_models SET enabled = 0 WHERE tenant_id = ? AND name = ?")
      .bind(TENANT_A, "gpt-5")
      .run();

    const second = await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW + 60 });

    expect(second.catalogSeeded).toBe(false);
    expect(second.status).toBe("ready");
    expect((await resolveTenantModel(handle.db, TENANT_A, "gpt-4o"))?.inputPricePer1m).toBe(1.0);
    // The one `INSERT OR IGNORE` cannot protect, and the reason the seed is
    // gated on a mark instead: a deleted model must STAY deleted.
    expect(await resolveTenantModel(handle.db, TENANT_A, "claude-opus-4")).toBeUndefined();
    expect(await resolveTenantModel(handle.db, TENANT_A, "gpt-5")).toBeUndefined();
    expect(await listTenantModelCatalog(handle.db, TENANT_A)).toHaveLength(
      DEFAULT_TENANT_MODEL_CATALOG.length - 1,
    );
  });

  test("does not re-stamp the tenant's original provisioning time", async () => {
    await registerTenant(TENANT_A);
    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });
    const first = await env.CONTROL_DB.prepare(
      "SELECT provisioned_at_unix, updated_at_unix FROM tenant_databases WHERE tenant_id = ?",
    )
      .bind(TENANT_A)
      .first<{ provisioned_at_unix: number; updated_at_unix: number }>();

    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW + 3600 });
    const second = await env.CONTROL_DB.prepare(
      "SELECT provisioned_at_unix, updated_at_unix FROM tenant_databases WHERE tenant_id = ?",
    )
      .bind(TENANT_A)
      .first<{ provisioned_at_unix: number; updated_at_unix: number }>();

    expect(second?.provisioned_at_unix).toBe(first?.provisioned_at_unix);
    expect(second?.updated_at_unix).toBe(NOW + 3600);
  });
});

describe("a half-provisioned tenant is detectable and resumable", () => {
  test("an interrupted run leaves `pending`, which listUnfinished() finds", async () => {
    await registerTenant(TENANT_A);
    const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
    // The exact state a crash between the two stores leaves: the roster row was
    // written, the tenant's own storage never was. It is written here directly
    // because the alternative — crashing the provisioner for real — proves less:
    // what has to be true is that THIS STATE is recoverable, however it arose.
    // The prior row is carried across so the native leg keeps its binding name;
    // the state under test is `pending`, not "unroutable".
    await registry.upsert(
      {
        ...(await registry.get(TENANT_A)),
        tenantId: TENANT_A,
        schemaVersion: 0,
        status: "pending",
      },
      NOW,
    );

    expect((await registry.listUnfinished()).map((row) => row.tenantId)).toContain(TENANT_A);

    const report = await describeTenantStorage(router, TENANT_A);
    expect(report.healthy).toBe(false);
    expect(report.catalogEntries).toBe(0);
    expect(report.problems.join(" ")).toMatch(/provisioning_status is pending/);
    expect(report.problems.join(" ")).toMatch(/model catalog is EMPTY/);

    const resumed = await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW + 10 });
    expect(resumed.resumed).toBe(true);
    expect(resumed.catalogSeeded).toBe(true);
    expect((await registry.listUnfinished()).map((row) => row.tenantId)).not.toContain(TENANT_A);
    expect((await describeTenantStorage(router, TENANT_A)).healthy).toBe(true);
  });

  test("describeTenantStorage does NOT address the object of an unprovisioned tenant", async () => {
    // The read path has the same junk-object rule as the write path, and it is
    // easier to violate by accident: a diagnostic that touches every id it is
    // asked about would manufacture an object per typo.
    const report = await describeTenantStorage(router, UNREGISTERED);
    expect(report.healthy).toBe(false);
    expect(report.registration).toBeUndefined();
    expect(report.catalogEntries).toBeUndefined();
    expect(report.problems.join(" ")).toMatch(/deliberately NOT addressed/);
  });

  test("a failure is RECORDED on the roster row, not merely thrown", async () => {
    // `TENANT_C` is registered with no `binding_name`, so the binding router
    // refuses it — the "provisioned but not yet redeployed" state. The DO router
    // has no such state (one namespace binding serves every tenant), so this
    // asserts the failure-recording path on the leg where a real failure exists
    // and asserts the absence of the state on the other.
    await registerTenant(TENANT_C);
    if (IS_DURABLE_OBJECT_BACKEND) {
      const outcome = await provisionTenantStorage(router, TENANT_C, { nowUnix: NOW });
      expect(outcome.status).toBe("ready");
      return;
    }
    await expect(provisionTenantStorage(router, TENANT_C, { nowUnix: NOW })).rejects.toThrow(
      /no native D1 binding_name/,
    );
    const registration = await new ControlDatabaseTenantRegistry(env.CONTROL_DB).get(TENANT_C);
    expect(registration?.status).toBe("failed");
    expect(registration?.lastError).toMatch(/no native D1 binding_name/);
    // And the report says the same thing, so an operator sweeping the fleet sees
    // the cause rather than a bare "not ready".
    const report = await describeTenantStorage(router, TENANT_C);
    expect(report.healthy).toBe(false);
    expect(report.problems.join(" ")).toMatch(/no native D1 binding_name/);
  });
});

describe("retiring a tenant", () => {
  test("removes the roster row and RETAINS the data", async () => {
    // The data-retention decision, asserted as behaviour so it cannot be changed
    // silently: deletion is not `deleteAll()`. See the docblock on
    // `TenantDeprovisioningReceipt` for the three options and why this one.
    await registerTenant(TENANT_A);
    await provisionTenantStorage(router, TENANT_A, { nowUnix: NOW });

    const receipt = await retireTenantStorage(router, TENANT_A);

    expect(receipt.rosterRowRemoved).toBe(true);
    expect(receipt.tenantDataRetained).toBe(true);
    // The receipt carries the registration BECAUSE the roster row is now gone:
    // after this call, nothing else can tell an erasure job what to erase.
    expect(receipt.retained?.status).toBe("ready");
    expect(await router.provisionedTenants()).not.toContain(TENANT_A);

    // Read through the harness's DIRECT accessor, not through the router: the
    // roster row is gone, so under `native_binding` the router can no longer
    // resolve this tenant at all. That is the retirement working — and it is
    // also why the receipt has to carry the registration, because after this
    // point nothing else can tell an erasure job where the retained data is.
    expect(await listTenantModelCatalog(tenantDb(TENANT_A), TENANT_A)).toHaveLength(
      DEFAULT_TENANT_MODEL_CATALOG.length,
    );
  });

  test("removes pushed aggregate rows while retaining tenant data", async () => {
    await registerTenant(TENANT_A);
    await env.CONTROL_DB.batch([
      env.CONTROL_DB.prepare(
        `INSERT INTO tenant_agent_cost_rollups
             (tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix, as_of_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(TENANT_A, "agent", "2026-08", 1, 1, 2, 3),
      env.CONTROL_DB.prepare(
        `INSERT INTO tenant_spend_rollups
             (tenant_id, period, accumulated_usd, as_of_unix)
           VALUES (?, ?, ?, ?)`,
      ).bind(TENANT_A, "2026-08", 1, 3),
      env.CONTROL_DB.prepare(
        `INSERT INTO tenant_asset_rollups
             (tenant_id, asset_count, asset_bytes, channel_count, as_of_unix)
           VALUES (?, ?, ?, ?, ?)`,
      ).bind(TENANT_A, 1, 10, 1, 3),
    ]);

    await retireTenantStorage(router, TENANT_A);

    expect(
      await env.CONTROL_DB.prepare(
        `SELECT count(*) AS count FROM (
             SELECT tenant_id FROM tenant_agent_cost_rollups WHERE tenant_id = ?
             UNION ALL SELECT tenant_id FROM tenant_spend_rollups WHERE tenant_id = ?
             UNION ALL SELECT tenant_id FROM tenant_asset_rollups WHERE tenant_id = ?
           )`,
      )
        .bind(TENANT_A, TENANT_A, TENANT_A)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
  });

  test("retiring a tenant that was never provisioned is not an error", async () => {
    const receipt = await retireTenantStorage(router, UNREGISTERED);
    expect(receipt.rosterRowRemoved).toBe(false);
    expect(receipt.retained).toBeUndefined();
  });
});
