/**
 * ONE contract, TWO implementations.
 *
 * The in-memory store is the reference the 131 routing/auth/envelope tests are
 * written against; the D1 store is what production runs. If the suite that pins
 * the behaviour only ever drives the in-memory one, every difference between
 * them is a production-only bug — and "the tests are green against a store
 * nobody deploys" is the same defect class as a router nobody mounts.
 *
 * So this file states the {@link ControlPlaneStore} contract ONCE and runs it
 * against both. Adding a third backend later means adding a factory here, not
 * writing a third suite.
 *
 * The D1 case runs against a REAL `env.DB` with the real control migration
 * applied (`./d1.ts`), not a fake.
 */
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type CallerScope,
  type ControlPlaneStore,
  type ListQuery,
  StoreConflictError,
  type StoreRecord,
} from "../src/ports.js";
import { D1ControlPlaneStore } from "../src/store/d1.js";
import { MemoryControlPlaneStore } from "../src/store/memory.js";
import { applySchema, db, resetD1 } from "./d1.js";

const OPERATOR: CallerScope = { kind: "platform_operator" };
const TENANT_A: CallerScope = { kind: "tenant", tenantId: "tenant_a" };
const TENANT_B: CallerScope = { kind: "tenant", tenantId: "tenant_b" };

/** A bare list request: no query string, so no pagination envelope. */
function bareQuery(overrides: Partial<ListQuery> = {}): ListQuery {
  return { offset: 0, limit: 100, paginate: false, search: null, filters: {}, ...overrides };
}

/** A list request that carried a query string. */
function pagedQuery(overrides: Partial<ListQuery> = {}): ListQuery {
  return { ...bareQuery(), paginate: true, ...overrides };
}

interface Backend {
  readonly name: string;
  readonly prepare: () => Promise<void>;
  readonly build: () => ControlPlaneStore;
}

const BACKENDS: readonly Backend[] = [
  {
    name: "MemoryControlPlaneStore",
    prepare: () => Promise.resolve(),
    build: () => new MemoryControlPlaneStore(),
  },
  {
    name: "D1ControlPlaneStore",
    prepare: resetD1,
    build: () => new D1ControlPlaneStore(db(), { requestId: "req_conformance" }),
  },
];

beforeAll(async () => {
  await applySchema();
});

describe.each(BACKENDS)("ControlPlaneStore contract: $name", (backend) => {
  let store: ControlPlaneStore;

  beforeEach(async () => {
    await backend.prepare();
    store = backend.build();
  });

  const seed = async (collection: string, records: readonly StoreRecord[]): Promise<void> => {
    for (const record of records) await store.create(collection, OPERATOR, record);
  };

  // -------------------------------------------------------------------------
  // create
  // -------------------------------------------------------------------------

  it("returns the stored record and reads it back", async () => {
    const created = await store.create("plans", OPERATOR, { id: "p1", name: "Pro" });
    expect(created).toMatchObject({ id: "p1", name: "Pro" });
    expect(await store.get("plans", OPERATOR, "p1")).toMatchObject({ id: "p1", name: "Pro" });
  });

  it("stamps a platform operator's declared tenant, or null when it declares none", async () => {
    await store.create("plans", OPERATOR, { id: "global" });
    await store.create("plans", OPERATOR, { id: "owned", tenant_id: "tenant_a" });
    expect((await store.get("plans", OPERATOR, "global"))?.tenant_id).toBeNull();
    expect((await store.get("plans", OPERATOR, "owned"))?.tenant_id).toBe("tenant_a");
  });

  it("overrides a tenant caller's declared tenant with its own", async () => {
    const created = await store.create("plans", TENANT_B, { id: "p1", tenant_id: "tenant_a" });
    expect(created.tenant_id).toBe("tenant_b");
  });

  it("REJECTS (not throws synchronously) on a duplicate id", async () => {
    await store.create("plans", OPERATOR, { id: "p1" });
    // The `.rejects` form is the point: a synchronous `throw` from one
    // implementation and a rejected promise from the other is a real
    // difference for any caller that does not `await` inside a `try`.
    await expect(store.create("plans", OPERATOR, { id: "p1" })).rejects.toBeInstanceOf(
      StoreConflictError,
    );
  });

  it("conflicts on an id another tenant already took", async () => {
    await store.create("plans", TENANT_A, { id: "shared_id" });
    await expect(store.create("plans", TENANT_B, { id: "shared_id" })).rejects.toBeInstanceOf(
      StoreConflictError,
    );
  });

  it("keeps collections separate", async () => {
    await store.create("plans", OPERATOR, { id: "x", name: "plan" });
    await store.create("projects", OPERATOR, { id: "x", name: "project" });
    expect((await store.get("plans", OPERATOR, "x"))?.name).toBe("plan");
    expect((await store.get("projects", OPERATOR, "x"))?.name).toBe("project");
  });

  // -------------------------------------------------------------------------
  // Tenant visibility
  // -------------------------------------------------------------------------

  it("hides another tenant's row from get", async () => {
    await store.create("plans", TENANT_A, { id: "p1" });
    expect(await store.get("plans", TENANT_B, "p1")).toBeNull();
    expect(await store.get("plans", TENANT_A, "p1")).not.toBeNull();
    expect(await store.get("plans", OPERATOR, "p1")).not.toBeNull();
  });

  it("shows an un-attributed platform row to every tenant", async () => {
    await store.create("plans", OPERATOR, { id: "global" });
    expect(await store.get("plans", TENANT_A, "global")).not.toBeNull();
    expect(await store.get("plans", TENANT_B, "global")).not.toBeNull();
  });

  it("reports a missing row and an invisible row identically", async () => {
    await store.create("plans", TENANT_A, { id: "p1" });
    expect(await store.get("plans", TENANT_B, "p1")).toBeNull();
    expect(await store.get("plans", TENANT_B, "never_existed")).toBeNull();
  });

  // -------------------------------------------------------------------------
  // replace / merge
  // -------------------------------------------------------------------------

  it("replaces the whole document but keeps id and tenant structural", async () => {
    await store.create("plans", TENANT_A, { id: "p1", name: "old", extra: 1 });
    const replaced = await store.replace("plans", TENANT_A, "p1", {
      name: "new",
      tenant_id: "tenant_b",
    });
    expect(replaced).toMatchObject({ id: "p1", name: "new", tenant_id: "tenant_a" });
    expect(replaced?.extra).toBeUndefined();
  });

  it("merges shallowly and ignores id/tenant_id in the patch", async () => {
    await store.create("plans", TENANT_A, { id: "p1", name: "old", keep: true });
    const merged = await store.merge("plans", TENANT_A, "p1", {
      name: "new",
      id: "hijack",
      tenant_id: "tenant_b",
    });
    expect(merged).toMatchObject({ id: "p1", name: "new", keep: true, tenant_id: "tenant_a" });
  });

  it("answers null for a replace/merge of an invisible row, and writes nothing", async () => {
    await store.create("plans", TENANT_A, { id: "p1", name: "original" });
    expect(await store.replace("plans", TENANT_B, "p1", { name: "hijacked" })).toBeNull();
    expect(await store.merge("plans", TENANT_B, "p1", { name: "hijacked" })).toBeNull();
    expect((await store.get("plans", TENANT_A, "p1"))?.name).toBe("original");
  });

  it("answers null for a replace/merge of a row that does not exist", async () => {
    expect(await store.replace("plans", OPERATOR, "ghost", { name: "x" })).toBeNull();
    expect(await store.merge("plans", OPERATOR, "ghost", { name: "x" })).toBeNull();
  });

  // -------------------------------------------------------------------------
  // mergeIf — the compare-and-set
  // -------------------------------------------------------------------------
  //
  // Held to ONE contract across both backends for the usual reason, but with an
  // extra edge here: the memory store gets its atomicity from the isolate being
  // single-threaded, while D1 has to reconstruct it with a revision guard and a
  // retry. Those are entirely different mechanisms, so "they agree" is not a
  // given — it is the thing under test.

  it("applies the patch when the precondition holds", async () => {
    await store.create("site-domain-verifications", TENANT_A, { id: "v1", attempts: 0 });
    const outcome = await store.mergeIf(
      "site-domain-verifications",
      TENANT_A,
      "v1",
      { attempts: 1 },
      (current) => current.attempts === 0,
    );
    expect(outcome.kind).toBe("merged");
    expect(await store.get("site-domain-verifications", TENANT_A, "v1")).toMatchObject({
      attempts: 1,
    });
  });

  it("refuses and WRITES NOTHING when the precondition fails", async () => {
    await store.create("site-domain-verifications", TENANT_A, { id: "v1", attempts: 7 });
    const outcome = await store.mergeIf(
      "site-domain-verifications",
      TENANT_A,
      "v1",
      { attempts: 8 },
      (current) => current.attempts === 0,
    );
    expect(outcome.kind).toBe("precondition_failed");
    // The refusal carries the row it was decided against, so a caller can label
    // it (how long is left on a cooldown) instead of re-reading and racing again.
    if (outcome.kind === "precondition_failed") {
      expect(outcome.current).toMatchObject({ attempts: 7 });
    }
    expect(await store.get("site-domain-verifications", TENANT_A, "v1")).toMatchObject({
      attempts: 7,
    });
  });

  it("reports `not_found` — not `precondition_failed` — for a row that does not exist", async () => {
    // The two are different facts: one is a 404, the other a 429/409. A store
    // that collapsed them would make a rate limit report itself as a missing
    // resource, and the precondition must not even be consulted.
    let consulted = false;
    const outcome = await store.mergeIf("plans", OPERATOR, "ghost", { x: 1 }, () => {
      consulted = true;
      return true;
    });
    expect(outcome.kind).toBe("not_found");
    expect(consulted).toBe(false);
  });

  it("reports `not_found` for another tenant's row, without consulting the predicate", async () => {
    await store.create("plans", TENANT_A, { id: "p1", secret: "a" });
    let consulted = false;
    const outcome = await store.mergeIf("plans", TENANT_B, "p1", { secret: "b" }, (current) => {
      consulted = true;
      return current.secret === "a";
    });
    expect(outcome.kind).toBe("not_found");
    // Handing another tenant's row to the caller's own predicate would leak its
    // contents even though the write is refused.
    expect(consulted).toBe(false);
    expect(await store.get("plans", TENANT_A, "p1")).toMatchObject({ secret: "a" });
  });

  it("keeps `id` and `tenant_id` structural, exactly as `merge` does", async () => {
    await store.create("plans", TENANT_A, { id: "p1" });
    await store.mergeIf(
      "plans",
      TENANT_A,
      "p1",
      { id: "forged", tenant_id: "tenant_b", label: "ok" },
      () => true,
    );
    expect(await store.get("plans", OPERATOR, "p1")).toMatchObject({
      id: "p1",
      tenant_id: "tenant_a",
      label: "ok",
    });
    expect(await store.get("plans", OPERATOR, "forged")).toBeNull();
  });

  it("admits exactly ONE of two concurrent claims on the same row", async () => {
    // The whole reason the method exists. `get` + `merge` passes every test
    // above and FAILS this one: both readers see `claimed: false`, both are
    // told yes, and both write.
    await store.create("plans", OPERATOR, { id: "slot", claimed: false });
    const claim = () =>
      store.mergeIf(
        "plans",
        OPERATOR,
        "slot",
        { claimed: true },
        (current) => current.claimed !== true,
      );
    const outcomes = await Promise.all([claim(), claim(), claim(), claim(), claim()]);
    expect(outcomes.filter((outcome) => outcome.kind === "merged")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.kind === "precondition_failed")).toHaveLength(4);
  });

  // -------------------------------------------------------------------------
  // remove
  // -------------------------------------------------------------------------

  it("removes a visible row and reports it", async () => {
    await store.create("plans", TENANT_A, { id: "p1" });
    expect(await store.remove("plans", TENANT_A, "p1")).toBe(true);
    expect(await store.get("plans", OPERATOR, "p1")).toBeNull();
  });

  it("refuses to remove an invisible row and leaves it in place", async () => {
    await store.create("plans", TENANT_A, { id: "p1" });
    expect(await store.remove("plans", TENANT_B, "p1")).toBe(false);
    expect(await store.get("plans", TENANT_A, "p1")).not.toBeNull();
  });

  it("reports false for a row that never existed", async () => {
    expect(await store.remove("plans", OPERATOR, "ghost")).toBe(false);
  });

  // -------------------------------------------------------------------------
  // The tenant fence is ASYMMETRIC: readable ≠ writable
  // -------------------------------------------------------------------------
  //
  // A row with no `tenant_id` is PLATFORM data — a global `role`, a shared
  // `policy`, a `plan` other tenants are billed against. Every tenant may READ
  // it ("shows an un-attributed platform row to every tenant", above), because
  // it is the deployment's own configuration and hiding it would break
  // `resolved-defaults`.
  //
  // It must NOT be WRITABLE by a tenant. The wave-15 certification found the
  // same predicate (`tenant_id IS NULL OR tenant_id = ?`) on `#update`,
  // `remove` and the `atomic` batch as on the SELECT, and no test pinning the
  // write side — so a tenant administrator holding `admin.write` (an intended
  // configuration) could PATCH or DELETE any platform row. Rust's
  // `filter_by_tenant_scope` (`auth.rs:428`) is strict equality and makes that
  // unreachable.
  //
  // The refusal is `null`/`false` — a 404, indistinguishable from absent —
  // rather than a 403, for the same reason the cross-tenant case is: a distinct
  // status would confirm the row exists.

  it("refuses a tenant's REPLACE of an un-attributed platform row", async () => {
    await store.create("plans", OPERATOR, { id: "global", name: "platform" });

    expect(await store.replace("plans", TENANT_A, "global", { name: "hijacked" })).toBeNull();
    expect((await store.get("plans", OPERATOR, "global"))?.name).toBe("platform");
  });

  it("refuses a tenant's MERGE of an un-attributed platform row", async () => {
    await store.create("plans", OPERATOR, { id: "global", name: "platform" });

    expect(await store.merge("plans", TENANT_A, "global", { name: "hijacked" })).toBeNull();
    expect((await store.get("plans", OPERATOR, "global"))?.name).toBe("platform");
  });

  it("refuses a tenant's MERGE-IF of an un-attributed platform row", async () => {
    await store.create("plans", OPERATOR, { id: "global", name: "platform" });

    const outcome = await store.mergeIf(
      "plans",
      TENANT_A,
      "global",
      { name: "hijacked" },
      () => true,
    );
    expect(outcome.kind).toBe("not_found");
    expect((await store.get("plans", OPERATOR, "global"))?.name).toBe("platform");
  });

  it("refuses a tenant's DELETE of an un-attributed platform row", async () => {
    await store.create("plans", OPERATOR, { id: "global", name: "platform" });

    expect(await store.remove("plans", TENANT_A, "global")).toBe(false);
    expect(await store.get("plans", OPERATOR, "global")).not.toBeNull();
  });

  it("refuses an ATOMIC unit that merges an un-attributed platform row", async () => {
    await store.create("plans", OPERATOR, { id: "global", name: "platform" });

    const applied = await store.atomic(TENANT_A, [
      { kind: "merge", collection: "plans", id: "global", patch: { name: "hijacked" } },
    ]);
    expect(applied).toBeNull();
    expect((await store.get("plans", OPERATOR, "global"))?.name).toBe("platform");
  });

  it("still lets a tenant write ITS OWN rows, and the operator write the platform's", async () => {
    // The narrowing must not be a blanket denial — that would pass the four
    // cases above while breaking every tenant-scoped write in the product.
    await store.create("plans", TENANT_A, { id: "mine", name: "old" });
    await store.create("plans", OPERATOR, { id: "global", name: "platform" });

    expect(await store.merge("plans", TENANT_A, "mine", { name: "new" })).toMatchObject({
      name: "new",
    });
    expect(await store.remove("plans", TENANT_A, "mine")).toBe(true);
    expect(await store.merge("plans", OPERATOR, "global", { name: "renamed" })).toMatchObject({
      name: "renamed",
    });
    expect(await store.remove("plans", OPERATOR, "global")).toBe(true);
  });

  it("keeps the platform row READABLE by the tenant that may not write it", async () => {
    // The asymmetry itself, in one case: the same row, same caller, read yes /
    // write no. A "fix" that hid the row instead would break
    // `resolved-defaults` and is caught here.
    await store.create("plans", OPERATOR, { id: "global", name: "platform" });

    expect(await store.get("plans", TENANT_A, "global")).not.toBeNull();
    expect(await store.remove("plans", TENANT_A, "global")).toBe(false);
  });

  // -------------------------------------------------------------------------
  // list
  // -------------------------------------------------------------------------

  it("lists in insertion order", async () => {
    await seed("plans", [{ id: "c" }, { id: "a" }, { id: "b" }]);
    const page = await store.list("plans", OPERATOR, bareQuery());
    expect(page.items.map((record) => record.id)).toEqual(["c", "a", "b"]);
    expect(page.total).toBe(3);
  });

  it("lists only the caller's rows plus un-attributed ones", async () => {
    await store.create("plans", OPERATOR, { id: "global" });
    await store.create("plans", TENANT_A, { id: "a1" });
    await store.create("plans", TENANT_B, { id: "b1" });
    const page = await store.list("plans", TENANT_A, bareQuery());
    expect(page.items.map((record) => record.id)).toEqual(["global", "a1"]);
    expect(page.total).toBe(2);
  });

  it("returns an empty page for a collection with no rows", async () => {
    const page = await store.list("nothing-here", OPERATOR, bareQuery());
    expect(page).toEqual({ items: [], total: 0 });
  });

  it("windows a paginated list and reports the PRE-pagination total", async () => {
    await seed(
      "plans",
      Array.from({ length: 5 }, (_, index) => ({ id: `p${index}` })),
    );
    const page = await store.list("plans", OPERATOR, pagedQuery({ offset: 1, limit: 2 }));
    expect(page.items.map((record) => record.id)).toEqual(["p1", "p2"]);
    expect(page.total).toBe(5);
  });

  it("ignores offset/limit when the request carried no query string", async () => {
    await seed(
      "plans",
      Array.from({ length: 5 }, (_, index) => ({ id: `p${index}` })),
    );
    const page = await store.list("plans", OPERATOR, bareQuery({ offset: 3, limit: 1 }));
    expect(page.items.length).toBe(5);
  });

  it("counts the tenant-visible set, not the whole collection", async () => {
    await store.create("plans", TENANT_A, { id: "a1" });
    await store.create("plans", TENANT_B, { id: "b1" });
    await store.create("plans", TENANT_B, { id: "b2" });
    const page = await store.list("plans", TENANT_A, pagedQuery({ limit: 10 }));
    expect(page.items.map((record) => record.id)).toEqual(["a1"]);
    expect(page.total).toBe(1);
  });

  it("matches `search` case-insensitively across the searchable fields", async () => {
    await seed("plans", [
      { id: "p1", name: "Nightly Sync" },
      { id: "p2", name: "Hourly" },
      { id: "p3", description: "runs nightly" },
      { id: "p4", untracked_field: "nightly" },
    ]);
    const page = await store.list("plans", OPERATOR, bareQuery({ search: "NIGHTLY" }));
    // `name` and `description` are searched; an arbitrary field is not.
    expect(page.items.map((record) => record.id)).toEqual(["p1", "p3"]);
  });

  it("matches `?k=v` filters by string equality and skips absent fields", async () => {
    await seed("plans", [
      { id: "p1", status: "active", weight: 5 },
      { id: "p2", status: "retired", weight: 5 },
      { id: "p3", weight: 5 },
    ]);
    expect(
      (await store.list("plans", OPERATOR, bareQuery({ filters: { status: "active" } }))).items.map(
        (record) => record.id,
      ),
    ).toEqual(["p1"]);
    // Numbers compare by their string form.
    expect(
      (await store.list("plans", OPERATOR, bareQuery({ filters: { weight: "5" } }))).items.length,
    ).toBe(3);
    // A row that does not carry the field never matches.
    expect(
      (await store.list("plans", OPERATOR, bareQuery({ filters: { status: "" } }))).items.length,
    ).toBe(0);
  });

  /**
   * The two semantics that BLOCK pushing `search`/`filters` into SQL, pinned so
   * a later "just add a LIKE / json_extract predicate" optimization cannot
   * change list results silently. See the kept PORT-TODO in `src/store/d1.ts`.
   */
  it("folds case with UNICODE rules, which SQLite's ASCII-only LIKE does not", async () => {
    await seed("plans", [
      { id: "u1", name: "ÄRZTE" },
      { id: "u2", name: "STRASSE" },
    ]);
    // JS `toLowerCase()` folds `Ä`→`ä`; SQLite `LIKE` folds ASCII only, so a
    // `document_json LIKE '%ärzte%'` pre-filter would DROP this row.
    const page = await store.list("plans", OPERATOR, bareQuery({ search: "ärzte" }));
    expect(page.items.map((record) => record.id)).toEqual(["u1"]);
  });

  it('compares a BOOLEAN field against its JS string form (`"true"`), not SQL 1/0', async () => {
    await seed("plans", [
      { id: "b1", enabled: true },
      { id: "b2", enabled: false },
    ]);
    // `String(true) === "true"`. `json_extract(document_json, '$.enabled')`
    // yields the integer `1` for the same row, so a SQL predicate comparing
    // against `'true'` would match nothing.
    expect(
      (await store.list("plans", OPERATOR, bareQuery({ filters: { enabled: "true" } }))).items.map(
        (record) => record.id,
      ),
    ).toEqual(["b1"]);
    expect(
      (await store.list("plans", OPERATOR, bareQuery({ filters: { enabled: "1" } }))).items.length,
    ).toBe(0);
  });

  // -------------------------------------------------------------------------
  // atomic
  // -------------------------------------------------------------------------
  //
  // `atomic` is the ONE method a route uses to move money: `routes/wallets.ts`
  // applies `[create(ledger entry), merge(wallet balance)]` as a unit, so a
  // half-applied unit is a balance that moved with no ledger row explaining it.
  // It was the only port method the contract below did not state, and the two
  // stores had drifted apart underneath that hole in exactly that direction.

  it("applies a create + merge pair and returns the records in mutation order", async () => {
    await store.create("wallets", OPERATOR, { id: "w1", balance_cents: 100 });
    const applied = await store.atomic(OPERATOR, [
      { kind: "create", collection: "ledger", record: { id: "e1", amount_cents: 50 } },
      { kind: "merge", collection: "wallets", id: "w1", patch: { balance_cents: 150 } },
    ]);
    expect(applied?.map((record) => record.id)).toEqual(["e1", "w1"]);
    expect(await store.get("ledger", OPERATOR, "e1")).toMatchObject({ amount_cents: 50 });
    expect(await store.get("wallets", OPERATOR, "w1")).toMatchObject({ balance_cents: 150 });
  });

  it("returns an empty result for an empty unit and writes nothing", async () => {
    expect(await store.atomic(OPERATOR, [])).toEqual([]);
  });

  it("stamps a tenant caller's own tenant on every created row in the unit", async () => {
    await store.create("wallets", TENANT_A, { id: "w1", balance_cents: 10 });
    const applied = await store.atomic(TENANT_A, [
      { kind: "create", collection: "ledger", record: { id: "e1", tenant_id: "tenant_b" } },
      { kind: "merge", collection: "wallets", id: "w1", patch: { balance_cents: 20 } },
    ]);
    expect(applied?.[0]?.tenant_id).toBe("tenant_a");
    expect(await store.get("ledger", TENANT_B, "e1")).toBeNull();
  });

  it("keeps id and tenant_id structural in a unit's merge patch", async () => {
    await store.create("wallets", TENANT_A, { id: "w1", keep: true });
    const applied = await store.atomic(TENANT_A, [
      {
        kind: "merge",
        collection: "wallets",
        id: "w1",
        patch: { balance_cents: 5, id: "hijack", tenant_id: "tenant_b" },
      },
    ]);
    expect(applied?.[0]).toMatchObject({ id: "w1", tenant_id: "tenant_a", keep: true });
  });

  /**
   * THE half-apply. `ON CONFLICT … DO NOTHING` makes a colliding insert match
   * zero rows without erroring, so before the batch guard covered `create` ids
   * the D1 store COMMITTED the sibling merge (balance 999, no ledger entry) and
   * reported a bare `Error`, while the in-memory reference rejected with
   * `StoreConflictError` and wrote nothing. Both halves are asserted: the error
   * IDENTITY and that the wallet is untouched.
   */
  it("rejects a taken create id with StoreConflictError and applies NOTHING", async () => {
    await store.create("ledger", OPERATOR, { id: "e1", amount_cents: 1 });
    await store.create("wallets", OPERATOR, { id: "w1", balance_cents: 100 });
    await expect(
      store.atomic(OPERATOR, [
        { kind: "create", collection: "ledger", record: { id: "e1", amount_cents: 42 } },
        { kind: "merge", collection: "wallets", id: "w1", patch: { balance_cents: 999 } },
      ]),
    ).rejects.toBeInstanceOf(StoreConflictError);
    expect(await store.get("wallets", OPERATOR, "w1")).toMatchObject({ balance_cents: 100 });
    expect(await store.get("ledger", OPERATOR, "e1")).toMatchObject({ amount_cents: 1 });
  });

  it("rejects the same create id twice in ONE unit and applies NOTHING", async () => {
    await expect(
      store.atomic(OPERATOR, [
        { kind: "create", collection: "ledger", record: { id: "dup", amount_cents: 1 } },
        { kind: "create", collection: "ledger", record: { id: "dup", amount_cents: 2 } },
      ]),
    ).rejects.toBeInstanceOf(StoreConflictError);
    expect(await store.get("ledger", OPERATOR, "dup")).toBeNull();
  });

  it("answers null for a missing merge target and applies NOTHING", async () => {
    const applied = await store.atomic(OPERATOR, [
      { kind: "create", collection: "ledger", record: { id: "e1" } },
      { kind: "merge", collection: "wallets", id: "ghost", patch: { balance_cents: 1 } },
    ]);
    expect(applied).toBeNull();
    expect(await store.get("ledger", OPERATOR, "e1")).toBeNull();
  });

  it("answers null for another tenant's merge target and applies NOTHING", async () => {
    await store.create("wallets", TENANT_A, { id: "w1", balance_cents: 100 });
    const applied = await store.atomic(TENANT_B, [
      { kind: "create", collection: "ledger", record: { id: "e1" } },
      { kind: "merge", collection: "wallets", id: "w1", patch: { balance_cents: 0 } },
    ]);
    expect(applied).toBeNull();
    expect(await store.get("ledger", OPERATOR, "e1")).toBeNull();
    expect(await store.get("wallets", TENANT_A, "w1")).toMatchObject({ balance_cents: 100 });
  });

  /**
   * Precedence, pinned so it cannot depend on which store is bound: an
   * unresolvable merge target is `null` (→ 404) even when the SAME unit also
   * carries a taken `create` id. The in-memory store used to decide this by
   * mutation position and answered 409 here; D1 resolves every merge target
   * before it can build a statement, so it answered 404.
   */
  it("prefers the missing-merge-target answer over a taken create id", async () => {
    await store.create("ledger", OPERATOR, { id: "e1" });
    const applied = await store.atomic(OPERATOR, [
      { kind: "create", collection: "ledger", record: { id: "e1" } },
      { kind: "merge", collection: "wallets", id: "ghost", patch: { balance_cents: 1 } },
    ]);
    expect(applied).toBeNull();
  });

  it("combines search, filters, tenant scope and pagination", async () => {
    await store.create("plans", TENANT_A, { id: "a1", name: "nightly one", status: "active" });
    await store.create("plans", TENANT_A, { id: "a2", name: "nightly two", status: "active" });
    await store.create("plans", TENANT_A, { id: "a3", name: "nightly three", status: "retired" });
    await store.create("plans", TENANT_B, { id: "b1", name: "nightly hidden", status: "active" });

    const page = await store.list(
      "plans",
      TENANT_A,
      pagedQuery({ search: "nightly", filters: { status: "active" }, offset: 1, limit: 5 }),
    );
    expect(page.items.map((record) => record.id)).toEqual(["a2"]);
    expect(page.total).toBe(2);
  });
});
