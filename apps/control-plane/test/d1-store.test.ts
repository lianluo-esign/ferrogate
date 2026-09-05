/**
 * The admin surface driven through the EXPORTED Worker with the D1 store live.
 *
 * Every request here goes through `SELF`, i.e. through
 * `withAliasCanonicalization(app)` — the object `src/worker.ts` re-exports as
 * the default handler — with `CONTROL_PLANE_STORE` unset, which is the
 * production default: `DB` is bound in `wrangler.toml`, so `resolveStore`
 * chooses D1. A suite that built its own Hono app and its own store would prove
 * nothing about the Worker anyone deploys; that is exactly how `apps/gateway`
 * once shipped 24 unreachable operations behind a green suite.
 *
 * Assertions are made on BOTH sides of the boundary: the HTTP response the
 * operator sees, and the row `control_plane_resources` actually holds. A test
 * that only checks the response cannot tell a durable write from a value the
 * handler echoed back.
 *
 * Coverage follows the main path's dependency order: tenant_hierarchy →
 * admin_api_key / admin_virtual_key → admin_model / admin_provider →
 * quota_policy → wallets → billing, plus the cross-tenant isolation guard and
 * the audit trail every mutation owes.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { D1ControlPlaneStore } from "../src/store/d1.js";
import { applySchema, auditRows, db, rawDocument, rawRevision, resetD1, seedD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import {
  rawTenantDocument,
  rawTenantRevision,
  registerObjectTenants,
  tenantObjectDb,
} from "./tenant-object.js";

const KEY = operatorKey.secret;
const TENANT_A_KEY = "tenant-a-secret";
const TENANT_B_KEY = "tenant-b-secret";

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_A_KEY, "tenant_a"), tenantKey(TENANT_B_KEY, "tenant_b")],
  });
});

// ---------------------------------------------------------------------------
// It actually reaches the database
// ---------------------------------------------------------------------------

describe("the exported Worker writes to D1", () => {
  it("persists a created record into control_plane_resources", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/api-keys`,
      jsonRequest(KEY, "POST", { id: "key_1", name: "ci", scopes: ["admin.read"] }),
    );
    expect(created.status).toBe(201);

    // The row, read straight out of the table — not out of the response.
    expect(await rawDocument("api-keys", "key_1")).toMatchObject({
      id: "key_1",
      name: "ci",
      scopes: ["admin.read"],
    });
    expect(await rawRevision("api-keys", "key_1")).toBe(1);
  });

  it("serves rows written to the table by something other than itself", async () => {
    // Seeded with raw SQL: if the handler were reading an in-memory map it
    // would answer with an empty list here.
    await seedD1("models", [
      { id: "gpt-4o", name: "gpt-4o", tenant_id: null, provider: "openai" },
      { id: "private", name: "private", tenant_id: "tenant_b" },
    ]);

    const response = await SELF.fetch(`${BASE}/admin/v1/models`, { headers: bearer(KEY) });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { id: string }[] };
    expect(body.data.map((model) => model.id).sort()).toEqual(["gpt-4o", "private"]);
  });

  it("keeps a provider list tenant-scoped for a tenant credential", async () => {
    await seedD1("providers", [
      { id: "shared", name: "shared", tenant_id: null },
      { id: "a-only", name: "a-only", tenant_id: "tenant_a" },
      { id: "b-only", name: "b-only", tenant_id: "tenant_b" },
    ]);

    const response = await SELF.fetch(`${BASE}/admin/v1/providers`, {
      headers: bearer(TENANT_A_KEY),
    });
    const body = (await response.json()) as { data: { id: string }[] };
    // The un-attributed platform row is visible; `tenant_b`'s is not.
    expect(body.data.map((provider) => provider.id).sort()).toEqual(["a-only", "shared"]);
  });
});

// ---------------------------------------------------------------------------
// Round-trips for the prioritized groups
// ---------------------------------------------------------------------------

describe("tenant_hierarchy round-trips on D1", () => {
  // The operator fan-out over tenant-attributed rows reads the roster;
  // production writes these rows at onboarding.
  beforeEach(() => registerObjectTenants(["tenant_a", "tenant_b"]));

  it("creates, reads, patches and replaces a tenant account", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts`,
      jsonRequest(KEY, "POST", { id: "tenant_a", name: "Acme", status: "active" }),
    );
    expect(created.status).toBe(201);

    const read = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/tenant_a`, {
      headers: bearer(KEY),
    });
    expect(read.status).toBe(200);
    expect(await read.json()).toMatchObject({ tenant_account: { id: "tenant_a", name: "Acme" } });

    const patched = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/tenant_a`,
      jsonRequest(KEY, "PATCH", { status: "suspended" }),
    );
    expect(patched.status).toBe(200);
    // A PATCH merges: `name` survives, and the row on disk agrees.
    expect(await rawTenantDocument("tenant_a", "tenant-accounts", "tenant_a")).toMatchObject({
      name: "Acme",
      status: "suspended",
    });

    const replaced = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/tenant_a`,
      jsonRequest(KEY, "PUT", { status: "active" }),
    );
    expect(replaced.status).toBe(200);
    // A PUT replaces: `name` is gone from the STORED document, not merely from
    // the response body.
    const afterPut = await rawTenantDocument("tenant_a", "tenant-accounts", "tenant_a");
    expect(afterPut).toMatchObject({ id: "tenant_a", status: "active" });
    expect(afterPut?.name).toBeUndefined();

    // Three mutations, three revisions.
    expect(await rawTenantRevision("tenant_a", "tenant-accounts", "tenant_a")).toBe(3);
  });

  it("creates and deletes a project, and the row is really gone", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(KEY, "POST", { id: "proj_1", name: "web", tenant_id: "tenant_a" }),
    );
    expect(await rawTenantDocument("tenant_a", "projects", "proj_1")).not.toBeNull();

    const deleted = await SELF.fetch(`${BASE}/admin/v1/projects/proj_1`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ object: "project", id: "proj_1", deleted: true });
    expect(await rawTenantDocument("tenant_a", "projects", "proj_1")).toBeNull();

    const gone = await SELF.fetch(`${BASE}/admin/v1/projects/proj_1`, { headers: bearer(KEY) });
    expect(gone.status).toBe(404);
  });

  it("refuses a duplicate id with 409 and leaves the stored document intact", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/workspaces`,
      jsonRequest(KEY, "POST", { id: "ws_1", name: "first" }),
    );
    const conflict = await SELF.fetch(
      `${BASE}/admin/v1/workspaces`,
      jsonRequest(KEY, "POST", { id: "ws_1", name: "second" }),
    );
    expect(conflict.status).toBe(409);
    // `INSERT ... ON CONFLICT DO NOTHING` must not have overwritten the row.
    expect(await rawDocument("workspaces", "ws_1")).toMatchObject({ name: "first" });
    expect(await rawRevision("workspaces", "ws_1")).toBe(1);
  });
});

describe("admin_virtual_key lifecycle on D1", () => {
  it("mints, rotates, disables and revokes without ever persisting the secret", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/virtual-keys`,
      jsonRequest(KEY, "POST", { id: "vk_1", name: "ci-key" }),
    );
    expect(created.status).toBe(201);
    const mint = (await created.json()) as { secret: string; virtual_key: { key_hash: string } };
    expect(mint.secret.startsWith("fg_")).toBe(true);

    const stored = await rawDocument("virtual-keys", "vk_1");
    expect(stored).toMatchObject({ id: "vk_1", enabled: true, revoked: false });
    // The plaintext is shown once and never written down.
    expect(JSON.stringify(stored)).not.toContain(mint.secret);
    expect(stored?.key_hash).toBe(mint.virtual_key.key_hash);

    const rotated = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/vk_1/rotate`, {
      method: "POST",
      headers: bearer(KEY),
    });
    expect(rotated.status).toBe(200);
    const rotation = (await rotated.json()) as { secret: string };
    expect(rotation.secret).not.toBe(mint.secret);
    expect((await rawDocument("virtual-keys", "vk_1"))?.key_hash).not.toBe(
      mint.virtual_key.key_hash,
    );

    await SELF.fetch(`${BASE}/admin/v1/virtual-keys/vk_1/disable`, {
      method: "POST",
      headers: bearer(KEY),
    });
    expect(await rawDocument("virtual-keys", "vk_1")).toMatchObject({ enabled: false });

    // DELETE is a REVOCATION here: the row survives so audit/billing rows that
    // reference the key id are not orphaned.
    const revoked = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/vk_1`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(revoked.status).toBe(200);
    expect(await rawDocument("virtual-keys", "vk_1")).toMatchObject({
      enabled: false,
      revoked: true,
    });
  });
});

describe("quota_policy round-trips on D1", () => {
  // The operator fan-out over tenant-attributed rows reads the roster;
  // production writes these rows at onboarding.
  beforeEach(() => registerObjectTenants(["tenant_a", "tenant_b"]));

  // The TYPED enforcement row (`quota_policies`), read straight out of a given
  // database handle — control's facade or a tenant object's — so a dual-write
  // assertion compares both sides of the boundary, not a value the handler
  // echoed back. `rpm_limit` is the assertion target because it maps to a real
  // typed column (unlike the `max_tokens_per_month` document-only field above).
  async function typedQuotaRow(
    handle: D1Database,
    scopeType: string,
    scopeId: string,
  ): Promise<{ id: string; rpm_limit: number | null } | null> {
    return handle
      .prepare("SELECT id, rpm_limit FROM quota_policies WHERE scope_type = ? AND scope_id = ?")
      .bind(scopeType, scopeId)
      .first<{ id: string; rpm_limit: number | null }>();
  }

  /**
   * After Track A migration 0045 the control facade has no `quota_policies`
   * table at all — a strictly stronger red line than the row-absence the case
   * asserted while the table still existed. `sqlite_master` is the honest probe:
   * a `SELECT` from the table itself would throw `no such table`.
   */
  async function controlLacksQuotaPoliciesTable(): Promise<boolean> {
    const row = await db()
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'quota_policies'")
      .first<{ name: string }>();
    return row === null;
  }

  it("writes the typed row ONLY into the owning tenant object, never the control facade", async () => {
    // Track A hard-cut: the typed enforcement projection is written ONLY to the
    // owning tenant's `quota_policies` (migration 0033) — the shared control
    // mirror leg was removed entirely, and the gateway's admission gate now reads
    // the row from that object. The control facade holds NO typed row at any
    // point. (Track A migration 0045 DROPS the control `quota_policies` table
    // outright, so these assert the facade has NO SUCH TABLE — stronger than the
    // row-absence they asserted while it still existed.)
    const created = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies`,
      jsonRequest(KEY, "POST", { scope_type: "tenant", scope_id: "tenant_a", rpm_limit: 60 }),
    );
    expect(created.status).toBe(201);
    // THE RED LINE: nothing on the control facade.
    expect(await controlLacksQuotaPoliciesTable()).toBe(true);
    // …and the owning tenant object is the sole authority.
    expect(await typedQuotaRow(tenantObjectDb("tenant_a"), "tenant", "tenant_a")).toMatchObject({
      id: "tenant:tenant_a",
      rpm_limit: 60,
    });

    const patched = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies/tenant/tenant_a`,
      jsonRequest(KEY, "PATCH", { rpm_limit: 120 }),
    );
    expect(patched.status).toBe(200);
    // The edit reaches the tenant object (the enforcement authority), and still
    // nothing lands on the control facade.
    expect(await typedQuotaRow(tenantObjectDb("tenant_a"), "tenant", "tenant_a")).toMatchObject({
      rpm_limit: 120,
    });
    expect(await controlLacksQuotaPoliciesTable()).toBe(true);

    const deleted = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/tenant_a`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(deleted.status).toBe(200);
    // The typed row must not outlive the document in the tenant object, or a
    // deleted limit would keep biting once admission reads the object.
    expect(await typedQuotaRow(tenantObjectDb("tenant_a"), "tenant", "tenant_a")).toBeNull();
    expect(await controlLacksQuotaPoliciesTable()).toBe(true);
  });

  it("round-trips the composite-keyed policy", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies`,
      jsonRequest(KEY, "POST", {
        scope_type: "tenant",
        scope_id: "tenant_a",
        max_tokens_per_month: 1000,
      }),
    );
    expect(created.status).toBe(201);
    // The composite key is what the row is stored under.
    expect(await rawTenantDocument("tenant_a", "quota-policies", "tenant:tenant_a")).toMatchObject({
      scope_type: "tenant",
      scope_id: "tenant_a",
      max_tokens_per_month: 1000,
    });

    const patched = await SELF.fetch(
      `${BASE}/admin/v1/quota-policies/tenant/tenant_a`,
      jsonRequest(KEY, "PATCH", { max_tokens_per_month: 2000 }),
    );
    expect(patched.status).toBe(200);
    expect(await rawTenantDocument("tenant_a", "quota-policies", "tenant:tenant_a")).toMatchObject({
      max_tokens_per_month: 2000,
    });

    const deleted = await SELF.fetch(`${BASE}/admin/v1/quota-policies/tenant/tenant_a`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(deleted.status).toBe(200);
    expect(await rawTenantDocument("tenant_a", "quota-policies", "tenant:tenant_a")).toBeNull();
  });
});

describe("wallets on D1", () => {
  // The operator fan-out over tenant-attributed rows reads the roster;
  // production writes these rows at onboarding.
  beforeEach(() => registerObjectTenants(["tenant_a", "tenant_b"]));

  it("moves a balance and writes the ledger entry that explains it", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/wallets`,
      jsonRequest(KEY, "POST", { tenant_id: "tenant_a", balance_cents: 500, currency: "usd" }),
    );
    expect(created.status).toBe(201);

    const credited = await SELF.fetch(
      `${BASE}/admin/v1/wallets/tenant_a/adjust`,
      jsonRequest(KEY, "POST", { amount_cents: 250, reason: "promo" }),
    );
    expect(credited.status).toBe(200);
    expect(await rawTenantDocument("tenant_a", "wallets", "tenant_a")).toMatchObject({
      balance_cents: 750,
    });

    const charged = await SELF.fetch(
      `${BASE}/admin/v1/wallets/tenant_a/charge`,
      jsonRequest(KEY, "POST", { amount_cents: 100 }),
    );
    expect(charged.status).toBe(200);
    expect(await rawTenantDocument("tenant_a", "wallets", "tenant_a")).toMatchObject({
      balance_cents: 650,
    });

    const ledger = await SELF.fetch(`${BASE}/admin/v1/wallets/tenant_a/ledger?limit=10`, {
      headers: bearer(KEY),
    });
    expect(ledger.status).toBe(200);
    const entries = (await ledger.json()) as { data: { kind: string; amount_cents: number }[] };
    expect(entries.data.map((entry) => [entry.kind, entry.amount_cents])).toEqual([
      ["adjustment", 250],
      ["charge", -100],
    ]);
  });

  /**
   * The reachable half-apply: two concurrent charges on one wallet.
   *
   * Both read the wallet at revision `r` and both submit
   * `[create(ledger entry), merge(balance)]`. The loser's ledger id is a fresh
   * uuid, so its INSERT always succeeds; only its balance UPDATE is guarded on
   * `r`. Before `atomic` guarded every statement on the revisions it expects AT
   * ITS OWN POSITION in the batch, the loser therefore COMMITTED a ledger entry
   * (with a `balance_after_cents` that never happened) while moving no balance,
   * and reported a bare `Error` — a ledger permanently disagreeing with the
   * balance it exists to explain.
   *
   * The race is staged rather than hoped for: `atomic` reads through the
   * `D1Database` it was constructed with, so the store is handed a decorator
   * that moves the wallet on ONCE, after the revisions were read and before the
   * batch runs. That is exactly the window a second request occupies.
   */
  it("writes no ledger entry when the balance update loses its revision race", async () => {
    await seedD1("wallets", [{ id: "tenant_a", tenant_id: null, balance_cents: 500 }]);

    const real = db();
    let interfered = false;
    const racing = {
      prepare: (sql: string) => real.prepare(sql),
      batch: async <T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> => {
        if (!interfered) {
          interfered = true;
          // The other request commits first: the wallet moves to revision 2.
          await real
            .prepare(
              "UPDATE control_plane_resources SET revision = revision + 1 WHERE resource_kind = ? AND resource_id = ?",
            )
            .bind("wallets", "tenant_a")
            .run();
        }
        return real.batch<T>(statements);
      },
    } as unknown as D1Database;

    const store = new D1ControlPlaneStore(racing, { requestId: "req_race" });
    const applied = await store.atomic({ kind: "platform_operator" }, [
      {
        kind: "create",
        collection: "wallet-ledger",
        record: { id: "entry_1", wallet_id: "tenant_a", amount_cents: -100 },
      },
      { kind: "merge", collection: "wallets", id: "tenant_a", patch: { balance_cents: 400 } },
    ]);

    // The unit retried against the state the winner left and then applied.
    expect(applied).not.toBeNull();
    expect(interfered).toBe(true);
    expect(await rawDocument("wallets", "tenant_a")).toMatchObject({ balance_cents: 400 });

    // THE assertion: exactly ONE ledger entry. The losing attempt wrote none.
    const ledger = await db()
      .prepare(
        "SELECT COUNT(*) AS total FROM control_plane_resources WHERE resource_kind = 'wallet-ledger'",
      )
      .first<{ total: number }>();
    expect(ledger?.total).toBe(1);
  });

  /**
   * The OTHER mid-flight change: a merge target DELETED between the load and
   * the batch, rather than moved.
   *
   * This is the one case an UPDATE cannot turn into an error — there is no row
   * left to violate a constraint on, so it matches zero rows silently. Two
   * independent things then keep the unit whole, and mutating EITHER alone
   * leaves this test green (mutating both together turns it red):
   *
   *  - the ledger INSERT's guard requires the wallet to EXIST, and it is a
   *    `CASE … ELSE NULL` over a NOT NULL column, so it ABORTS the transaction
   *    rather than inserting nothing;
   *  - failing that, every statement matched zero rows, and the all-zero branch
   *    re-reads instead of reporting success.
   *
   * Both routes end at the same answer a target that was already missing at
   * load time gets: `null` (→ 404).
   *
   * Staged like the race above: a decorator deletes the wallet once, after
   * `atomic` has read its revision and before the batch runs.
   */
  it("writes no ledger entry when the wallet is deleted mid-flight", async () => {
    await seedD1("wallets", [{ id: "tenant_a", tenant_id: null, balance_cents: 500 }]);

    const real = db();
    let interfered = false;
    const racing = {
      prepare: (sql: string) => real.prepare(sql),
      batch: async <T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> => {
        if (!interfered) {
          interfered = true;
          await real
            .prepare(
              "DELETE FROM control_plane_resources WHERE resource_kind = ? AND resource_id = ?",
            )
            .bind("wallets", "tenant_a")
            .run();
        }
        return real.batch<T>(statements);
      },
    } as unknown as D1Database;

    const store = new D1ControlPlaneStore(racing, { requestId: "req_vanish" });
    const applied = await store.atomic({ kind: "platform_operator" }, [
      {
        kind: "create",
        collection: "wallet-ledger",
        record: { id: "entry_1", wallet_id: "tenant_a", amount_cents: -100 },
      },
      { kind: "merge", collection: "wallets", id: "tenant_a", patch: { balance_cents: 400 } },
    ]);

    // The target is gone, so the unit resolves the way a missing merge target
    // always does — `null`, which the route turns into a 404.
    expect(interfered).toBe(true);
    expect(applied).toBeNull();

    // THE assertion: no orphan ledger entry for a balance that never moved.
    const ledger = await db()
      .prepare(
        "SELECT COUNT(*) AS total FROM control_plane_resources WHERE resource_kind = 'wallet-ledger'",
      )
      .first<{ total: number }>();
    expect(ledger?.total).toBe(0);
  });

  /**
   * What the CROSS-guard is for: a unit that moves TWO wallets, one of which is
   * deleted mid-flight.
   *
   * The surviving wallet's own `revision = ?` guard is perfectly satisfied, so
   * nothing about ITS statement objects — and the deleted one's UPDATE matches
   * zero rows in silence. Without the clause that requires every OTHER merge
   * target to still EXIST at the revision it should hold, the batch therefore
   * commits half the unit: one balance moves, the other does not, and the
   * caller is told only that "1 of 2 statements" applied, after the fact.
   *
   * With it, the surviving wallet's own statement fails its guard, which is a
   * NOT NULL violation, which rolls the transaction back. The unit then
   * resolves the deleted target the way every unresolvable target resolves —
   * `null`.
   */
  it("moves NEITHER wallet when one of two merge targets is deleted mid-flight", async () => {
    await seedD1("wallets", [
      { id: "tenant_a", tenant_id: null, balance_cents: 500 },
      { id: "tenant_b", tenant_id: null, balance_cents: 900 },
    ]);

    const real = db();
    let interfered = false;
    const racing = {
      prepare: (sql: string) => real.prepare(sql),
      batch: async <T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> => {
        if (!interfered) {
          interfered = true;
          await real
            .prepare(
              "DELETE FROM control_plane_resources WHERE resource_kind = ? AND resource_id = ?",
            )
            .bind("wallets", "tenant_b")
            .run();
        }
        return real.batch<T>(statements);
      },
    } as unknown as D1Database;

    const store = new D1ControlPlaneStore(racing, { requestId: "req_sibling" });
    const applied = await store.atomic({ kind: "platform_operator" }, [
      { kind: "merge", collection: "wallets", id: "tenant_a", patch: { balance_cents: 400 } },
      { kind: "merge", collection: "wallets", id: "tenant_b", patch: { balance_cents: 800 } },
    ]);

    expect(interfered).toBe(true);
    expect(applied).toBeNull();

    // THE assertion: the wallet that COULD have been written was not. A unit
    // that half-applied would leave 400 here.
    expect(await rawDocument("wallets", "tenant_a")).toMatchObject({ balance_cents: 500 });
    expect(await rawDocument("wallets", "tenant_b")).toBeNull();
  });

  it("refuses an overdraft and leaves the stored balance untouched", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/wallets`,
      jsonRequest(KEY, "POST", { tenant_id: "tenant_a", balance_cents: 50 }),
    );
    const overdraft = await SELF.fetch(
      `${BASE}/admin/v1/wallets/tenant_a/charge`,
      jsonRequest(KEY, "POST", { amount_cents: 500 }),
    );
    expect(overdraft.status).toBe(409);
    expect(await rawTenantDocument("tenant_a", "wallets", "tenant_a")).toMatchObject({
      balance_cents: 50,
    });
    // The refusal must not have left a ledger entry behind either.
    const ledger = await SELF.fetch(`${BASE}/admin/v1/wallets/tenant_a/ledger`, {
      headers: bearer(KEY),
    });
    expect((await ledger.json()) as { data: unknown[] }).toMatchObject({ data: [] });
  });
});

describe("billing on D1", () => {
  it("replays a dead letter at most once", async () => {
    await seedD1("billing-outbox-dead-letters", [
      { id: "report_1", tenant_id: null, status: "dead_lettered" },
    ]);

    const replayed = await SELF.fetch(
      `${BASE}/admin/v1/billing-outbox-dead-letters/report_1/replay`,
      { method: "POST", headers: bearer(KEY) },
    );
    expect(replayed.status).toBe(200);
    expect(await rawDocument("billing-outbox-dead-letters", "report_1")).toMatchObject({
      replayed: true,
      status: "replayed",
    });

    const again = await SELF.fetch(`${BASE}/admin/v1/billing-outbox-dead-letters/report_1/replay`, {
      method: "POST",
      headers: bearer(KEY),
    });
    // Durable idempotence: the guard reads the row back out of D1.
    expect(again.status).toBe(409);
  });

  it("serves the metering-events compat alias from the same rows", async () => {
    await seedD1("metering-events", [
      { id: "evt_1", tenant_id: null, status: "settled" },
      { id: "evt_2", tenant_id: null, status: "pending" },
    ]);
    const compat = await SELF.fetch(`${BASE}/admin/v1/billing-events`, { headers: bearer(KEY) });
    const canonical = await SELF.fetch(`${BASE}/admin/v1/metering-events`, {
      headers: bearer(KEY),
    });
    expect(await compat.json()).toEqual(await canonical.json());
  });
});

// ---------------------------------------------------------------------------
// Cross-tenant isolation — the guard the whole store exists for
// ---------------------------------------------------------------------------

describe("cross-tenant isolation on D1", () => {
  beforeEach(async () => {
    // The operator fan-out over tenant-attributed rows reads the roster;
    // production writes these rows at onboarding.
    registerObjectTenants(["tenant_a", "tenant_b"]);
    // Written by tenant A, through the Worker, so the row's `tenant_id` is the
    // one the store stamped rather than one a fixture asserted.
    const created = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(TENANT_A_KEY, "POST", { id: "proj_a", name: "a-secret" }),
    );
    expect(created.status).toBe(201);
    expect(await rawTenantDocument("tenant_a", "projects", "proj_a")).toMatchObject({
      tenant_id: "tenant_a",
    });
  });

  it("hides another tenant's row from GET as a 404, not a 403", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, {
      headers: bearer(TENANT_B_KEY),
    });
    // 403 would confirm the resource exists across the tenant boundary.
    expect(response.status).toBe(404);
  });

  it("omits another tenant's row from a list", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(TENANT_B_KEY, "POST", { id: "proj_b", name: "b-thing" }),
    );
    const response = await SELF.fetch(`${BASE}/admin/v1/projects`, {
      headers: bearer(TENANT_B_KEY),
    });
    const body = (await response.json()) as { data: { id: string }[] };
    expect(body.data.map((project) => project.id)).toEqual(["proj_b"]);
  });

  it("omits another tenant's row from a PAGINATED list (the SQL fast path)", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(TENANT_B_KEY, "POST", { id: "proj_b", name: "b-thing" }),
    );
    // A query string switches the store onto the LIMIT/OFFSET + COUNT(*) path,
    // which is a different pair of statements and needs its own proof.
    const response = await SELF.fetch(`${BASE}/admin/v1/projects?limit=50`, {
      headers: bearer(TENANT_B_KEY),
    });
    const body = (await response.json()) as { data: { id: string }[]; total: number };
    expect(body.data.map((project) => project.id)).toEqual(["proj_b"]);
    // `total` is computed by the COUNT, and must be fenced too — otherwise the
    // page is empty of A's row but announces that it exists.
    expect(body.total).toBe(1);
  });

  it("omits another tenant's row from a SEARCHED list (the in-isolate path)", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/projects?search=secret`, {
      headers: bearer(TENANT_B_KEY),
    });
    const body = (await response.json()) as { data: unknown[]; total: number };
    expect(body.data).toEqual([]);
    expect(body.total).toBe(0);
  });

  it("refuses to let another tenant PATCH the row", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/projects/proj_a`,
      jsonRequest(TENANT_B_KEY, "PATCH", { name: "hijacked" }),
    );
    expect(response.status).toBe(404);
    // And the row on disk is untouched — a 404 that still wrote would be worse
    // than a 200 that did.
    expect(await rawTenantDocument("tenant_a", "projects", "proj_a")).toMatchObject({
      name: "a-secret",
    });
    expect(await rawTenantRevision("tenant_a", "projects", "proj_a")).toBe(1);
  });

  it("refuses to let another tenant PUT the row", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/projects/proj_a`,
      jsonRequest(TENANT_B_KEY, "PUT", { name: "hijacked" }),
    );
    expect(response.status).toBe(404);
    expect(await rawTenantDocument("tenant_a", "projects", "proj_a")).toMatchObject({
      name: "a-secret",
    });
  });

  it("refuses to let another tenant DELETE the row", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, {
      method: "DELETE",
      headers: bearer(TENANT_B_KEY),
    });
    expect(response.status).toBe(404);
    expect(await rawTenantDocument("tenant_a", "projects", "proj_a")).not.toBeNull();
  });

  it("stamps the caller's tenant on create, ignoring a declared foreign tenant", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(TENANT_B_KEY, "POST", { id: "proj_forged", tenant_id: "tenant_a" }),
    );
    // B cannot mint a row into A by declaring A's id in the body.
    expect(await rawTenantDocument("tenant_b", "projects", "proj_forged")).toMatchObject({
      tenant_id: "tenant_b",
    });
  });

  it("keeps `tenant_id` structural: a PATCH cannot move a row between tenants", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/projects/proj_a`,
      jsonRequest(TENANT_A_KEY, "PATCH", { tenant_id: "tenant_b" }),
    );
    expect(response.status).toBe(200);
    expect(await rawTenantDocument("tenant_a", "projects", "proj_a")).toMatchObject({
      tenant_id: "tenant_a",
    });
  });

  it("still lets the platform operator see every tenant's rows", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/projects/proj_a`, { headers: bearer(KEY) });
    expect(response.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

describe("audit evidence for admin mutations", () => {
  it("appends one audit_events row per applied mutation, correlated to the request", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(TENANT_A_KEY, "POST", { id: "proj_audit", name: "audited" }),
    );
    const createRequestId = created.headers.get("x-request-id");
    expect(createRequestId).not.toBeNull();

    await SELF.fetch(
      `${BASE}/admin/v1/projects/proj_audit`,
      jsonRequest(TENANT_A_KEY, "PATCH", { name: "renamed" }),
    );
    await SELF.fetch(`${BASE}/admin/v1/projects/proj_audit`, {
      method: "DELETE",
      headers: bearer(TENANT_A_KEY),
    });

    const rows = await auditRows();
    expect(rows.map((row) => row.audit.action)).toEqual(["create", "merge", "remove"]);
    for (const row of rows) {
      expect(row.audit).toMatchObject({
        object: "control_plane_mutation",
        collection: "projects",
        resource_id: "proj_audit",
        actor_scope: "tenant",
        actor_tenant_id: "tenant_a",
      });
      expect(row.tenant).toBe("tenant_a");
      expect(row.request_id).not.toBe("");
    }
    // The create row is correlated to the request that made it, which is what
    // makes the evidence joinable to the CLI's mutation receipt.
    expect(rows[0]?.request_id).toBe(createRequestId);
    // Revisions advance with the mutations they record.
    expect(rows.map((row) => row.audit.revision)).toEqual([1, 2, 2]);
  });

  it("writes NO audit row for a refused mutation", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(TENANT_A_KEY, "POST", { id: "proj_x", name: "a" }),
    );
    const before = (await auditRows()).length;

    // A cross-tenant PATCH (404) and a duplicate create (409) both change
    // nothing, so neither may leave evidence claiming they did.
    await SELF.fetch(
      `${BASE}/admin/v1/projects/proj_x`,
      jsonRequest(TENANT_B_KEY, "PATCH", { name: "hijacked" }),
    );
    await SELF.fetch(
      `${BASE}/admin/v1/projects`,
      jsonRequest(TENANT_A_KEY, "POST", { id: "proj_x", name: "again" }),
    );
    expect((await auditRows()).length).toBe(before);
  });

  it("records the platform operator as the actor when it is one", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/plans`,
      jsonRequest(KEY, "POST", { id: "plan_pro", name: "Pro" }),
    );
    const rows = await auditRows();
    expect(rows.at(-1)?.audit).toMatchObject({
      action: "create",
      collection: "plans",
      actor_scope: "platform_operator",
      actor_tenant_id: null,
    });
  });
});

// ---------------------------------------------------------------------------
// List semantics on the SQL paths
// ---------------------------------------------------------------------------

describe("list semantics against D1", () => {
  beforeEach(async () => {
    await seedD1(
      "plans",
      Array.from({ length: 7 }, (_, index) => ({
        id: `plan_${index}`,
        name: `plan ${index}`,
        tenant_id: null,
        status: index % 2 === 0 ? "active" : "retired",
      })),
    );
  });

  it("answers the un-paginated envelope when there is no query string", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer(KEY) });
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.object).toBe("list");
    expect((body.data as unknown[]).length).toBe(7);
    // Rust omits the three pagination keys entirely rather than sending nulls.
    expect("total" in body).toBe(false);
  });

  it("windows with LIMIT/OFFSET and counts the whole collection", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans?limit=3&offset=2`, {
      headers: bearer(KEY),
    });
    const body = (await response.json()) as { data: { id: string }[]; total: number };
    expect(body.data.map((plan) => plan.id)).toEqual(["plan_2", "plan_3", "plan_4"]);
    expect(body.total).toBe(7);
  });

  it("filters on a record field, and `total` counts the FILTERED set", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans?status=retired`, {
      headers: bearer(KEY),
    });
    const body = (await response.json()) as { data: { id: string }[]; total: number };
    expect(body.data.map((plan) => plan.id)).toEqual(["plan_1", "plan_3", "plan_5"]);
    expect(body.total).toBe(3);
  });

  it("searches case-insensitively across the searchable fields", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans?search=PLAN_6`, {
      headers: bearer(KEY),
    });
    const body = (await response.json()) as { data: { id: string }[] };
    expect(body.data.map((plan) => plan.id)).toEqual(["plan_6"]);
  });

  it("lists in insertion order, deterministically", async () => {
    // Everything above was written in the same second, so the ordering here is
    // carried by the rowid tiebreak rather than by `created_at_unix`.
    const ids = async (response: Response): Promise<string[]> =>
      ((await response.json()) as { data: { id: string }[] }).data.map((plan) => plan.id);
    const first = await ids(
      await SELF.fetch(`${BASE}/admin/v1/plans?limit=7`, { headers: bearer(KEY) }),
    );
    const second = await ids(
      await SELF.fetch(`${BASE}/admin/v1/plans?limit=7`, { headers: bearer(KEY) }),
    );
    expect(first).toEqual(["plan_0", "plan_1", "plan_2", "plan_3", "plan_4", "plan_5", "plan_6"]);
    expect(second).toEqual(first);
  });
});

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

describe("concurrent writers", () => {
  it("does not lose an update when two merges race the same row", async () => {
    const store = new D1ControlPlaneStore(db(), { requestId: "req_race" });
    await store.create("plans", { kind: "platform_operator" }, { id: "p1", name: "base" });

    // Both merges load revision 1 before either writes. D1 has no interactive
    // transaction, so the ONLY thing keeping the second from clobbering the
    // first is the `AND revision = ?` guard on the UPDATE: the loser matches
    // zero rows, re-reads, and re-applies on top of the winner.
    await Promise.all([
      store.merge("plans", { kind: "platform_operator" }, "p1", { alpha: 1 }),
      store.merge("plans", { kind: "platform_operator" }, "p1", { beta: 2 }),
    ]);

    expect(await rawDocument("plans", "p1")).toMatchObject({
      name: "base",
      alpha: 1,
      beta: 2,
    });
    // Two applied mutations, two revisions past the create.
    expect(await rawRevision("plans", "p1")).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// The composition root actually chose D1
// ---------------------------------------------------------------------------

describe("store selection", () => {
  it("uses D1 by default when DB is bound", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/plans`,
      jsonRequest(KEY, "POST", { id: "plan_default", name: "default" }),
    );
    const row = await db()
      .prepare(
        "SELECT COUNT(*) AS n FROM control_plane_resources WHERE resource_kind = 'plans' AND resource_id = 'plan_default'",
      )
      .first<{ n: number }>();
    expect(row?.n).toBe(1);
  });

  it("writes nothing to D1 when CONTROL_PLANE_STORE pins the memory store", async () => {
    arm({ staticKeys: [operatorKey] });
    const created = await SELF.fetch(
      `${BASE}/admin/v1/plans`,
      jsonRequest(KEY, "POST", { id: "plan_memory", name: "memory" }),
    );
    expect(created.status).toBe(201);
    expect(await rawDocument("plans", "plan_memory")).toBeNull();
  });
});
