/**
 * The `durable_object` topology, against a REAL `TenantDataObject` in workerd —
 * the four claims #819 makes, each stated as an assertion that a plausible
 * wrong implementation fails.
 *
 *  1. **It is the DEFAULT.** An absent `GATEWAY_TENANT_DB_ROUTING` resolves to
 *     `durable_object`, and the mount is `@ferrogate/storage`'s
 *     `DurableObjectTenantDatabaseRouter` — not a second `idFromName` call
 *     written inside this app.
 *  2. **Resolution reads NOTHING.** Counted, not eyeballed: the control
 *     database is wrapped in a proxy that tallies `prepare()`, and a request-path
 *     resolution must leave that tally at ZERO. Re-adding a `tenant_databases`
 *     lookup to `forTenant()` turns §2 red — a comment claiming the read is gone
 *     would not.
 *  3. **The money paths RUN.** A wallet reserve — `requireAtomicBatch()` call
 *     site #1 of 13, and a three-statement `RETURNING` batch — completes end to
 *     end through a resolved handle, and N concurrent reserves against a
 *     balance affording K admit exactly K. Under `rest` this could not run at
 *     all; under a facade whose `batch()` was not one transaction it would
 *     oversell.
 *  4. **Fail closed, in the shape the topology actually has.** A misconfigured
 *     binding is no longer possible — one stanza serves every tenant — so the
 *     "provisioned but unreachable" case is carried by the OBJECT: a stub that
 *     has adopted a different tenant refuses, and that refusal must surface as
 *     an error, never as a retry and never as another database.
 *
 * Read `resolver.spec.ts` beside this file: it pins the same fail-closed
 * property for the D1 modes, which still ship for self-hosted single-tenant
 * deploys. Neither file's refusals are portable to the other topology, which is
 * why they are two files rather than a `describe.each`.
 */
import { env } from "cloudflare:test";
import {
  D1WalletStore,
  DurableObjectTenantDatabaseRouter,
  requireAtomicBatch,
} from "@ferrogate/storage";
import { Hono } from "hono";
import { beforeAll, describe, expect, test } from "vitest";
import { HttpError } from "../../src/middleware/errors.js";
import type { GatewayEnv } from "../../src/ports.js";
import {
  TENANT_DATABASE_ROUTING_MISCONFIGURED,
  TENANT_DATABASE_UNAVAILABLE,
  type TenancyBindings,
  createTenantDatabaseResolver,
  parseTenantDatabaseRoutingMode,
  tenantDatabase,
  tenantDatabaseOf,
} from "../../src/tenancy/index.js";
import { TENANT_ACME, TENANT_GHOST, TENANT_GLOBEX, setupTenancy, walletFor } from "./setup.js";

beforeAll(setupTenancy);

/**
 * The harness bindings with the routing var REMOVED, so every resolver built
 * here exercises the default rather than a value this file chose. `env` pins
 * `"binding_strict"` for the D1 specs; deleting the key is what makes "the
 * default is `durable_object`" a real assertion instead of a restatement.
 */
function defaultBindings(): TenancyBindings {
  const { GATEWAY_TENANT_DB_ROUTING: _pinned, ...rest } = env as unknown as Record<string, unknown>;
  return rest as TenancyBindings;
}

/** A control database that counts every statement prepared against it. */
function countingControlDb(): { db: D1Database; prepared: string[] } {
  const prepared: string[] = [];
  const db = new Proxy(env.CONTROL_DB, {
    get(target, property, receiver) {
      if (property === "prepare") {
        return (query: string) => {
          prepared.push(query);
          return target.prepare(query);
        };
      }
      const value = Reflect.get(target, property, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  }) as D1Database;
  return { db, prepared };
}

// ---------------------------------------------------------------------------
// 1. The default, and the mount
// ---------------------------------------------------------------------------

describe("durable_object is the default topology, and it is the library's router", () => {
  test("an absent GATEWAY_TENANT_DB_ROUTING resolves to durable_object", () => {
    expect(parseTenantDatabaseRoutingMode(undefined)).toBe("durable_object");
    expect(parseTenantDatabaseRoutingMode("   ")).toBe("durable_object");
    // `"off"` is still reachable, but only by NAME. That is the half that keeps
    // a self-hosted deploy with no TENANT_DATA binding able to say so.
    expect(parseTenantDatabaseRoutingMode("off")).toBe("off");
  });

  test("the resolver mounts DurableObjectTenantDatabaseRouter, lazily", () => {
    const resolver = createTenantDatabaseResolver(defaultBindings());
    expect(resolver.mode).toBe("durable_object");
    // THE UNMOUNT GATE, same shape as `resolver.spec.ts` §1: re-implementing
    // `idFromName` inside `apps/gateway` instead of importing the tested
    // library fails here.
    expect(resolver.router).toBeInstanceOf(DurableObjectTenantDatabaseRouter);
    // NOT eager. There is nothing an eager pass could learn: `idFromName`
    // cannot fail, so proving reachability would mean issuing a real RPC per
    // request. `binding_strict` exists because a D1 binding genuinely might not
    // have been deployed.
    expect(resolver.eager).toBe(false);
    // The CONTROL database is still account-global, and is NOT any tenant's.
    expect(resolver.control()).toBe(env.CONTROL_DB);
  });

  test("a handle reports source durable_object and supportsAtomicBatch", async () => {
    const handle = await createTenantDatabaseResolver(defaultBindings()).forTenant(TENANT_ACME);
    expect(handle.tenantId).toBe(TENANT_ACME);
    expect(handle.source).toBe("durable_object");
    expect(handle.supportsAtomicBatch).toBe(true);
    // The gate every guarded write in `@ferrogate/storage` calls first. Under
    // `rest` this THREW for all 13 money paths; admitting the handle is the
    // whole reason the topology changed.
    expect(requireAtomicBatch(handle, "reserve_wallet_credits")).toBe(handle);
  });

  test("two tenants get two physically different objects", async () => {
    const resolver = createTenantDatabaseResolver(defaultBindings());
    const acme = new D1WalletStore(await resolver.forTenant(TENANT_ACME));
    const globex = new D1WalletStore(await resolver.forTenant(TENANT_GLOBEX));

    await acme.upsertWallet(walletFor(TENANT_ACME, 5_000));
    await globex.upsertWallet(walletFor(TENANT_GLOBEX, 11));

    expect((await acme.getWallet(TENANT_ACME))?.balanceCredits).toBe(5_000);
    expect((await globex.getWallet(TENANT_GLOBEX))?.balanceCredits).toBe(11);

    // The load-bearing half, and the DO analogue of `resolver.spec.ts`'s
    // cross-database read: ACME's row is not merely filtered out of GLOBEX's
    // view, it is in a different SQLite file inside a different object. A query
    // in GLOBEX's object that FORGOT the `tenant_id` predicate still cannot
    // reach it.
    const globexRows = await (await resolver.forTenant(TENANT_GLOBEX)).db
      .prepare("SELECT tenant_id FROM wallets")
      .all<{ tenant_id: string }>();
    expect(globexRows.results.map((row) => row.tenant_id)).toEqual([TENANT_GLOBEX]);

    // And the CONTROL database holds no wallets at all — the split is real.
    const controlWallets = await env.CONTROL_DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'wallets'",
    ).first();
    expect(controlWallets).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. Resolution reads nothing — COUNTED
// ---------------------------------------------------------------------------

describe("a request-path resolution performs NO control-database read", () => {
  test("resolving ten tenants prepares zero statements on CONTROL_DB", async () => {
    const { db, prepared } = countingControlDb();
    const resolver = createTenantDatabaseResolver({
      ...defaultBindings(),
      CONTROL_DB: db,
    } as TenancyBindings);

    const tenants = Array.from({ length: 10 }, (_, index) => `tenant_counted_${index}`);
    const handles = await Promise.all(tenants.map((tenantId) => resolver.forTenant(tenantId)));

    expect(handles.map((handle) => handle.tenantId)).toEqual(tenants);
    // THE ASSERTION. Not "it looks like there is no await" — the tally. The old
    // binding router charged one `tenant_databases` SELECT per uncached tenant
    // on the inference hot path, and the 30 s cache that softened it was deleted
    // rather than left guarding a read that no longer happens.
    expect(prepared).toEqual([]);
  });

  test("a resolution the tenancy MIDDLEWARE performs reads nothing either", async () => {
    // The same claim through the seam the request path actually takes.
    //
    // This test used to call `createTenantDatabaseResolver(...).forTenant(...)`
    // — the identical seam as the case above — and assert `handle.db` is
    // defined, which `forTenant` sets as an eager plain property and so could
    // never fail. It therefore could not catch the ONE thing its own comment
    // claimed: an accessor that pre-warms a registry row. So it now mounts the
    // REAL `tenantDatabase()` middleware and reaches the handle through
    // `tenantDatabaseOf(c)`, which is the only path that constructs
    // `RequestTenantDatabaseAccessor`. Adding
    // `void this.resolver().control().prepare("SELECT 1")` to that constructor
    // turns this red; it left the old version green.
    const { db, prepared } = countingControlDb();
    const app = new Hono<GatewayEnv>();
    app.use("*", async (c, next) => {
      c.set("auth", {
        subject: "key_probe",
        tenancy: { tenantId: TENANT_ACME },
        scopes: ["*"],
        platformOperator: false,
        source: "durable_native",
      });
      await next();
    });
    app.use("*", tenantDatabase());
    app.get("/probe", async (c) => {
      const handle = await tenantDatabaseOf(c).handle();
      // Reading the handle's own database must not touch the control plane
      // either; the object is addressed, not looked up. A real statement, so
      // the tally covers the first RPC into the object and not just resolution.
      await handle.db
        .prepare("SELECT tenant_id FROM wallets WHERE tenant_id = ?")
        .bind(handle.tenantId)
        .all();
      return c.json({ tenantId: handle.tenantId, source: handle.source });
    });

    const response = await app.request("https://probe.test/probe", {}, {
      ...defaultBindings(),
      CONTROL_DB: db,
    } as unknown as Record<string, unknown>);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      tenantId: TENANT_ACME,
      source: "durable_object",
    });
    expect(prepared).toEqual([]);
  });

  test("provisionedTenants DOES read it — the registry survives, off the request path", async () => {
    const { db, prepared } = countingControlDb();
    const resolver = createTenantDatabaseResolver({
      ...defaultBindings(),
      CONTROL_DB: db,
    } as TenancyBindings);

    const tenants = await resolver.router.provisionedTenants();
    // The inverse assertion, and it is not decoration: if `provisionedTenants`
    // had ALSO stopped reading, §2 above would pass vacuously against a router
    // that had lost the control database entirely — and every fleet view would
    // report an empty fleet. A DO namespace cannot be enumerated in production,
    // so `tenant_databases` is the only possible answer here.
    expect(prepared.length).toBeGreaterThan(0);
    expect(tenants).toContain(TENANT_ACME);
    expect(tenants).toContain(TENANT_GLOBEX);
  });

  test("an UNREGISTERED tenant still resolves — and that is the change", async () => {
    // Under `binding` this tenant was `503`: no registry row meant no
    // `binding_name` meant no route. Here the address is a pure function of the
    // id, so it resolves, and the honest worst case is one EMPTY object rather
    // than a write into somebody else's database.
    //
    // The check that used to live here has not been dropped, it has moved
    // EARLIER: a tenant id reaches the router only because an authenticated
    // credential resolved to it through the CONTROL `api_key_directory`. A
    // second existence check would re-ask that question, per request, on the
    // inference path.
    const handle = await createTenantDatabaseResolver(defaultBindings()).forTenant(TENANT_GHOST);
    expect(handle.source).toBe("durable_object");
    const rows = await handle.db.prepare("SELECT tenant_id FROM wallets").all();
    expect(rows.results).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 3. The 13 requireAtomicBatch() call sites RUN
// ---------------------------------------------------------------------------

describe("the money paths run end to end through a resolved handle", () => {
  const NOW = 1_700_000_000;

  test("a wallet reserve completes through the routed Durable Object", async () => {
    const tenant = "tenant_reserve_ok";
    const handle = await createTenantDatabaseResolver(defaultBindings()).forTenant(tenant);
    const store = new D1WalletStore(handle);
    await store.upsertWallet(walletFor(tenant, 100));

    const reserved = await store.reserveWalletCredits("hold_1", tenant, 40, NOW + 60, NOW);
    // `reserveWalletCredits` asserts `requireAtomicBatch` first and then runs a
    // THREE-statement batch whose no-oversell predicate lives inside the
    // INSERT, reading its outcome from a `RETURNING` clause. Every one of those
    // — the guard, the transaction, the returned rows — is a thing the `rest`
    // strategy could not provide, so this single assertion is the clearest
    // evidence that the topology landed.
    expect(reserved.kind).toBe("reserved");
    if (reserved.kind !== "reserved") return;
    expect(reserved.reservation.amountCredits).toBe(40);
    expect(reserved.reservation.tenantId).toBe(tenant);

    // And the hold is visible to the balance arithmetic, i.e. it really wrote.
    const second = await store.reserveWalletCredits("hold_2", tenant, 40, NOW + 60, NOW);
    expect(second.kind).toBe("reserved");
    const third = await store.reserveWalletCredits("hold_3", tenant, 40, NOW + 60, NOW);
    expect(third.kind).toBe("insufficient");
    if (third.kind !== "insufficient") return;
    expect(third.availableCredits).toBe(20);
  });

  test("N concurrent reserves against a balance affording K admit exactly K", async () => {
    const tenant = "tenant_reserve_race";
    const handle = await createTenantDatabaseResolver(defaultBindings()).forTenant(tenant);
    const store = new D1WalletStore(handle);
    await store.upsertWallet(walletFor(tenant, 7));

    // Twenty reserves of 1 credit against a balance of 7. A naive
    // read-then-write admits all twenty; the in-statement guard admits seven.
    // This is the assertion that would fail if the facade's `batch()` were N
    // sequential statements instead of one `transactionSync`.
    const outcomes = await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        store.reserveWalletCredits(`race_${index}`, tenant, 1, NOW + 60, NOW),
      ),
    );
    expect(outcomes.filter((outcome) => outcome.kind === "reserved")).toHaveLength(7);
    expect(outcomes.filter((outcome) => outcome.kind === "insufficient")).toHaveLength(13);
  });

  test("a released hold returns its credits, so the ledger is not one-way", async () => {
    const tenant = "tenant_reserve_release";
    const handle = await createTenantDatabaseResolver(defaultBindings()).forTenant(tenant);
    const store = new D1WalletStore(handle);
    await store.upsertWallet(walletFor(tenant, 10));

    expect((await store.reserveWalletCredits("rel_1", tenant, 10, NOW + 60, NOW)).kind).toBe(
      "reserved",
    );
    expect((await store.reserveWalletCredits("rel_2", tenant, 1, NOW + 60, NOW)).kind).toBe(
      "insufficient",
    );
    await store.releaseWalletReservation("rel_1", NOW + 1);
    expect((await store.reserveWalletCredits("rel_3", tenant, 10, NOW + 60, NOW)).kind).toBe(
      "reserved",
    );
  });
});

// ---------------------------------------------------------------------------
// 4. Fail closed — the refusals this topology actually has
// ---------------------------------------------------------------------------

describe("fail closed — an unreachable tenant NEVER falls back", () => {
  test("a blank tenant id is refused rather than given the empty-name object", async () => {
    // `idFromName("")` is a perfectly valid id. `routableTenantId` hands an
    // UNCLASSIFIED credential the empty string precisely because it matches
    // nothing, so accepting it here would turn the unforgeable sentinel into
    // ONE shared object every such caller writes into — a fallback database by
    // accident, which is the single outcome this directory exists to prevent.
    const resolver = createTenantDatabaseResolver(defaultBindings());
    const error = await resolver.forTenant("").then(
      () => undefined,
      (thrown: unknown) => thrown,
    );
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).code).toBe(TENANT_DATABASE_UNAVAILABLE);
    expect((error as HttpError).status).toBe(503);
  });

  test("PROVISIONED BUT UNREACHABLE: an object holding another tenant refuses", async () => {
    // The DO analogue of `TENANT_DB_INITECH` — the registry and the deployment
    // disagreeing — and the reason that case is KEPT rather than deleted with
    // the D1 topology. The property it proves is not specific to D1: a tenant
    // whose storage cannot serve it must ERROR, never be quietly served from
    // somewhere else.
    //
    // The mechanism is what changed. There is no stanza to omit, so the way an
    // object becomes unreachable is that it has ADOPTED A DIFFERENT TENANT:
    // `idFromName` is one-way, so an object cannot check its own name, and
    // `TenantDataObject` therefore adopts the first tenant id it is addressed
    // with and refuses every later one. Squatting the object here is exactly
    // what a resolver bug computing the wrong name would do in production.
    const tenant = "tenant_squatted";
    const squatter = new DurableObjectTenantDatabaseRouter(
      env.TENANT_DATA,
      env.CONTROL_DB,
    ).databaseFor(tenant);
    // Address `tenant_squatted`'s object as somebody else, first.
    await env.TENANT_DATA.get(env.TENANT_DATA.idFromName(tenant)).query({
      tenantId: "tenant_the_impostor",
      sql: "SELECT 1 AS one",
    });
    expect(squatter).toBeDefined();

    // Resolution still succeeds — it reads nothing and cannot know. The refusal
    // arrives at the first STATEMENT, which is the honest place for it.
    const handle = await createTenantDatabaseResolver(defaultBindings()).forTenant(tenant);
    const failure = await handle.db
      .prepare("SELECT tenant_id FROM wallets")
      .all()
      .then(
        () => undefined,
        (thrown: unknown) => thrown,
      );
    expect(failure, "the object must refuse, not serve the impostor's rows").toBeInstanceOf(Error);
    expect((failure as Error).message).toContain("REFUSED");
    expect((failure as Error).message).toContain("tenant_the_impostor");
  });

  test("a wallet reserve against a squatted object is UNAVAILABLE, never insufficient", async () => {
    // The consequence at the money path, and the direction matters: an
    // unreachable object has NOT proven the caller is overdrawn. Reporting
    // `insufficient` would 429 a solvent tenant on a routing bug; the reserve
    // must surface the refusal instead.
    const tenant = "tenant_squatted_wallet";
    await env.TENANT_DATA.get(env.TENANT_DATA.idFromName(tenant)).query({
      tenantId: "tenant_the_impostor",
      sql: "SELECT 1 AS one",
    });
    const handle = await createTenantDatabaseResolver(defaultBindings()).forTenant(tenant);
    const store = new D1WalletStore(handle);
    await expect(
      store.reserveWalletCredits("squat_hold", tenant, 1, 1_700_000_060, 1_700_000_000),
    ).rejects.toThrow(/REFUSED/);
  });

  test("no TENANT_DATA binding is a NAMED refusal, not a fallback to DB", () => {
    // The one configuration mistake this topology still admits. It must be a
    // 503 that names the missing stanza — never `env.DB`, which is bound in
    // this very harness and would have made the whole suite pass while every
    // tenant shared one database.
    const { TENANT_DATA: _absent, ...withoutNamespace } = defaultBindings() as Record<
      string,
      unknown
    >;
    expect(() => createTenantDatabaseResolver(withoutNamespace as TenancyBindings)).toThrow(
      expect.objectContaining({ code: TENANT_DATABASE_ROUTING_MISCONFIGURED, status: 503 }),
    );
  });

  test("no CONTROL_DB is a refusal too, even though routing would not need it", () => {
    // `durable_object` resolution reads nothing, so this could have been made
    // optional. It is not: without the control database `control()` and
    // `provisionedTenants()` cannot answer, and a gateway that cannot enumerate
    // its fleet should say so at configuration time rather than at the first
    // admin fan-out.
    const { CONTROL_DB: _absent, ...withoutControl } = defaultBindings() as Record<string, unknown>;
    expect(() => createTenantDatabaseResolver(withoutControl as TenancyBindings)).toThrow(
      expect.objectContaining({ code: TENANT_DATABASE_ROUTING_MISCONFIGURED }),
    );
  });
});
