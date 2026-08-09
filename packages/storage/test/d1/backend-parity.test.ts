/**
 * THE ANTI-VACUITY GATE for the two-backend run.
 *
 * `test/d1/**` executes twice — `vitest.d1.config.ts` (`native_binding`) and
 * `vitest.d1do.config.ts` (`durable_object`, #823) — and every other file in
 * the directory is written to be indifferent to which. That indifference is the
 * point, and it is also the danger: if the `TENANT_BACKEND` binding were
 * misspelled, if `readD1Migrations` moved, if `setupTenantRouter()` fell back to
 * the binding router, the second leg would run the whole suite against D1 again
 * and report 309 green tests that proved nothing about the facade. There is no
 * "0 tests matched" signal for that failure; the output would be indistinguish-
 * able from a real pass.
 *
 * So this file asserts what the OTHER files deliberately do not know:
 *
 *  * which backend is actually mounted, cross-checked against the binding;
 *  * that the durable leg's writes land in the Durable Object and NOT in the D1
 *    tenant database the same harness still migrates — the strongest available
 *    statement of "the suite is looking at the right place";
 *  * that `requireAtomicBatch()` admits the handle on all 13 money paths;
 *  * the one place the two topologies legitimately DISAGREE, so the difference
 *    is recorded rather than discovered.
 */
import { env } from "cloudflare:test";
import { beforeAll, describe, expect, test } from "vitest";
import {
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
  requireAtomicBatch,
} from "../../src/index.js";
import {
  IS_DURABLE_OBJECT_BACKEND,
  TENANT_A,
  TENANT_BACKEND,
  TENANT_C,
  setupTenantRouter,
  tenantDb,
} from "./harness.js";

const NOW = 1_700_000_000;

let router: TenantDatabaseRouter;
let handleA: TenantDatabaseHandle;

beforeAll(async () => {
  router = await setupTenantRouter();
  handleA = await router.forTenant(TENANT_A);
});

describe("which backend this run is actually exercising", () => {
  test("the handle's source matches the backend the config asked for", () => {
    // Read from the HANDLE, not from the harness constant: the constant says
    // what was requested and the handle says what was delivered. A
    // `setupTenantRouter()` that silently fell back to the binding router would
    // satisfy the first and fail the second.
    expect(handleA.source).toBe(IS_DURABLE_OBJECT_BACKEND ? "durable_object" : "native_binding");
    expect(TENANT_BACKEND).toBe(handleA.source);
  });

  test("requireAtomicBatch ADMITS this handle on every money path", () => {
    // All 13 call sites read exactly this. The object-backed topology makes
    // those transaction-backed paths available.
    expect(handleA.supportsAtomicBatch).toBe(true);
    for (const operation of [
      "reserve_wallet_credits",
      "settle_wallet_reservation",
      "debit_workflow_run_budget",
      "create_asset_within_quota",
      "delete_agent_schedule",
      "persist_usage_aggregate",
    ]) {
      expect(requireAtomicBatch(handleA, operation)).toBe(handleA);
    }
  });
});

describe("the routed handle and the harness's direct database are the same place", () => {
  test("a write through the handle is visible through tenantDb(), and vice versa", async () => {
    // If these two ever diverged, every assertion in the directory that seeds
    // through one and reads through the other would be checking an empty
    // database against an empty expectation.
    await handleA.db
      .prepare("INSERT OR REPLACE INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind("parity_handle", TENANT_A, "H", "parity-h")
      .run();
    const seenDirectly = await tenantDb(TENANT_A)
      .prepare("SELECT id FROM projects WHERE id = ?")
      .bind("parity_handle")
      .first<{ id: string }>();
    expect(seenDirectly?.id).toBe("parity_handle");

    await tenantDb(TENANT_A)
      .prepare("INSERT OR REPLACE INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind("parity_direct", TENANT_A, "D", "parity-d")
      .run();
    const seenThroughHandle = await handleA.db
      .prepare("SELECT id FROM projects WHERE id = ?")
      .bind("parity_direct")
      .first<{ id: string }>();
    expect(seenThroughHandle?.id).toBe("parity_direct");
  });

  test.runIf(IS_DURABLE_OBJECT_BACKEND)(
    "the durable leg writes into the OBJECT, and the D1 tenant database stays empty",
    async () => {
      // THE assertion that makes the second leg non-vacuous. The harness still
      // applies the tenant migrations to `TENANT_DB_A` in both legs, so the
      // table exists and a query against it succeeds — it is simply not where
      // the row went. A durable leg that had quietly fallen back to the binding
      // router would find the row here and fail.
      await handleA.db
        .prepare("INSERT OR REPLACE INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
        .bind("only_in_the_object", TENANT_A, "O", "only-object")
        .run();

      const inD1 = await env.TENANT_DB_A.prepare("SELECT id FROM projects WHERE id = ?")
        .bind("only_in_the_object")
        .first();
      expect(inD1).toBeNull();

      const inObject = await handleA.db
        .prepare("SELECT id FROM projects WHERE id = ?")
        .bind("only_in_the_object")
        .first<{ id: string }>();
      expect(inObject?.id).toBe("only_in_the_object");
    },
  );

  test.runIf(!IS_DURABLE_OBJECT_BACKEND)(
    "the native leg routes to the D1 binding the registry names",
    async () => {
      // The mirror image, so the assertion above cannot be satisfied by a leg
      // that writes nowhere at all.
      await handleA.db
        .prepare("INSERT OR REPLACE INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
        .bind("in_the_binding", TENANT_A, "B", "in-binding")
        .run();
      const inD1 = await env.TENANT_DB_A.prepare("SELECT id FROM projects WHERE id = ?")
        .bind("in_the_binding")
        .first<{ id: string }>();
      expect(inD1?.id).toBe("in_the_binding");
    },
  );
});

describe("where the two topologies legitimately disagree", () => {
  test("a registration with no binding_name: refused on D1, routable on a Durable Object", async () => {
    // `TENANT_C` is registered with `binding_name = null` — the "provisioned but
    // not yet redeployed" state, which the binding router must refuse rather
    // than serve from the control database.
    //
    // That state cannot exist under `durable_object`, and saying so is the
    // architectural claim of #822 rather than a relaxation: ONE
    // `[[durable_objects.bindings]]` entry serves every tenant that will ever
    // exist, so there is no stanza to be missing and no deploy to be waiting
    // for. Pinning both halves here keeps the difference recorded in one place
    // instead of being rediscovered as a bug.
    if (IS_DURABLE_OBJECT_BACKEND) {
      const handleC = await router.forTenant(TENANT_C);
      expect(handleC.source).toBe("durable_object");
      expect(handleC.supportsAtomicBatch).toBe(true);
      await handleC.db
        .prepare("INSERT OR REPLACE INTO projects (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)")
        .bind("c_ok", TENANT_C, "C", "c-ok")
        .run();
    } else {
      await expect(router.forTenant(TENANT_C)).rejects.toThrow(/no native D1 binding_name/);
    }
  });

  test("an UNREGISTERED tenant: refused on D1, resolved on a Durable Object", async () => {
    // An earlier revision of this case asserted `not_found` on BOTH backends,
    // because the durable router kept the `tenant_databases` row as an
    // existence gate. #819 DELETED that read, and this is the honest record of
    // what changed rather than a relaxed assertion.
    //
    // Why it was removed: under `native_binding` the row carries the ANSWER
    // (`binding_name`), so no row meant no route. Here it carries no part of
    // the answer — the address is `idFromName(tenantId)` — so reading it would
    // only be a POLICY check, "is this a tenant we serve?", asked once per
    // request on the inference hot path. That question is already answered
    // strictly earlier and strictly better by the credential: a tenant id
    // reaches a router only because `apps/gateway/src/keys/` resolved an
    // authenticated credential to it through the CONTROL `api_key_directory`.
    //
    // What it costs, stated plainly: a resolver bug that computed a wrong id
    // gets an empty object instead of an error. What it does NOT cost is
    // isolation — the worst case is one empty object holding nothing, never a
    // write into another tenant's ledger, which is what the same mistake does
    // under `shared_development`. The wrong-object case is caught by the
    // object's own admission guard (see `tenant-do-facade.test.ts`).
    if (IS_DURABLE_OBJECT_BACKEND) {
      const handle = await router.forTenant("tenant_never_provisioned");
      expect(handle.source).toBe("durable_object");
      const rows = await handle.db.prepare("SELECT id FROM projects").all();
      expect(rows.results).toEqual([]);
    } else {
      await expect(router.forTenant("tenant_never_provisioned")).rejects.toMatchObject({
        kind: "not_found",
      });
    }
    // The one gate that survives on BOTH backends, and the one that matters
    // most: `idFromName("")` is a perfectly valid id, so a blank tenant id
    // would name ONE object that every unclassified caller lands in — a
    // fallback database by accident. There is still no default database in
    // either topology.
    await expect(router.forTenant("")).rejects.toThrow(/non-empty tenant id/);
  });

  test("provisionedTenants() is answered from the control registry on both", async () => {
    // A Durable Object namespace CANNOT be enumerated in production —
    // `listDurableObjectIds` is a `cloudflare:test` helper — and
    // `apps/control-plane/src/store/asset_fleet.ts:330` fans out over this list
    // to serve the fleet asset views. Returning `[]` would report an empty
    // fleet: green, and wrong.
    const tenants = await router.provisionedTenants();
    expect(tenants).toContain(TENANT_A);
    expect(tenants).toContain(TENANT_C);
  });

  test("the control database is D1 on both backends, and is NOT the tenant's", async () => {
    // `tenant_databases` lives in the control schema and nowhere else. If
    // `control()` ever started answering with a tenant object, this read would
    // fail `no such table` — which is the correct outcome and the reason the
    // classification doc exists.
    const row = await router
      .control()
      .prepare("SELECT tenant_id FROM tenant_databases WHERE tenant_id = ?")
      .bind(TENANT_A)
      .first<{ tenant_id: string }>();
    expect(row?.tenant_id).toBe(TENANT_A);

    const wallets = await handleA.db
      .prepare("SELECT count(*) AS n FROM wallets WHERE created_at_unix <= ?")
      .bind(NOW + 1_000_000)
      .first<{ n: number }>();
    // `wallets` exists in the tenant schema and not in the control one; the
    // read simply has to succeed, which is the half that proves the handle is
    // not the control database wearing a tenant id.
    expect(typeof wallets?.n).toBe("number");
  });
});
