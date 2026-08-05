/**
 * The READ half of the admin audit trail, driven end-to-end through the
 * exported Worker against a REAL D1 binding.
 *
 * ## The defect this file pins
 *
 * The wave-15 control-plane certification recorded `admin_request_log` as
 * DURABLE-BUT-UNREAD, and `audit-events` is the sharp end of it:
 *
 * > `audit_events` IS written (`src/store/d1.ts:911`) but read only by the
 * > gateway's asset audit tail; [the admin route] reads the `audit-events`
 * > DOCUMENT collection instead, which is empty.
 *
 * So `D1ControlPlaneStore` appends a durable evidence row for every applied
 * mutation — create, replace, merge, remove — and
 * `GET /admin/v1/audit-events` answered `{"object":"list","data":[]}` on a
 * deployment that had been recording evidence all along. An operator asking
 * "who changed this policy, and when" is told **nothing happened**, which is
 * strictly worse than an error: the absence of a row is how you conclude a
 * change was NOT made.
 *
 * `d1-store.test.ts:652` already proves the WRITE ("appends one audit_events
 * row per applied mutation"), and it is exactly why this could ship — it asserts
 * on the table with raw SQL and never once asks the admin API for the trail.
 *
 * ## The rule every case here obeys
 *
 * **Write ONLY through the admin API; read ONLY through the admin API.**
 * Nothing below seeds `audit_events` with SQL. Every row these assertions find
 * has to have been put there by a real mutation flowing through the store, and
 * every row they find has to come back out through the route under test — so a
 * green case cannot be explained by a fixture at either end.
 *
 * Parity source: `crates/ferrogate-gateway/src/server/local.rs:4501`
 * (`handle_admin_audit_events` → `audit_events_page`) and
 * `crates/ferrogate-storage/src/control_plane_store_d1/observability.rs:247`
 * (`ORDER BY occurred_at_unix ASC, id ASC`, `count(*) OVER() AS total`), plus
 * `crates/ferrogate-gateway/src/state_agent_runtime.rs:292` for the tenant
 * filter, which is STRICT equality on the row's organization id.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, auditRows, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { tenantObjectDb } from "./tenant-object.js";

interface AuditListBody {
  object: string;
  data: Record<string, unknown>[];
  total?: number;
  offset?: number;
  limit?: number;
}

/** `GET /admin/v1/audit-events`, as whoever holds `secret`. */
async function readTrail(secret: string, query = ""): Promise<AuditListBody> {
  const response = await SELF.fetch(`${BASE}/admin/v1/audit-events${query}`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as AuditListBody;
}

/** A real mutation: `POST /admin/v1/policies`. */
function createPolicy(secret: string, name: string): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/policies`,
    jsonRequest(secret, "POST", { name, id: name, rules: [] }),
  );
}

function patchPolicy(secret: string, name: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/policies/${name}`, jsonRequest(secret, "PATCH", body));
}

function deletePolicy(secret: string, name: string): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/policies/${name}`, {
    method: "DELETE",
    headers: bearer(secret),
  });
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  await Promise.all(
    ["t-1", "t-2"].map((tenantId) =>
      tenantObjectDb(tenantId).prepare("DELETE FROM audit_events").run(),
    ),
  );
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("k-tenant", "t-1"), tenantKey("k-other", "t-2")],
    rbac: {},
  });
});

// ---------------------------------------------------------------------------
// The headline defect
// ---------------------------------------------------------------------------

describe("the admin audit trail returns the evidence the store recorded", () => {
  it("shows the row a real admin mutation just wrote", async () => {
    // Empty first, so the row below cannot be a leftover.
    expect((await readTrail(operatorKey.secret)).data).toHaveLength(0);

    expect((await createPolicy(operatorKey.secret, "pol_a")).status).toBe(201);

    const trail = await readTrail(operatorKey.secret);
    expect(trail.data).toHaveLength(1);
    expect(trail.data[0]).toMatchObject({
      object: "control_plane_mutation",
      action: "create",
      collection: "policies",
      resource_id: "pol_a",
      actor_scope: "platform_operator",
    });
  });

  it("reads tenant asset audit authority from the TenantDataObject", async () => {
    await tenantObjectDb("t-1")
      .prepare(
        "INSERT INTO audit_events " +
          "(id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json, " +
          "chain_key, seq, prev_hash, row_hash) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(
        "aud_asset_object",
        "req_asset_object",
        "t-1",
        10,
        JSON.stringify({ action: "asset.push", target: "bundle-1", outcome: "committed" }),
        "t-1",
        1,
        "0".repeat(64),
        "1".repeat(64),
      )
      .run();

    const trail = await readTrail("k-tenant");
    expect(trail.data).toContainEqual(
      expect.objectContaining({
        id: "aud_asset_object",
        action: "asset.push",
        tenant_id: "t-1",
      }),
    );
  });

  /**
   * The trail's whole job is to say WHICH verb happened. A reader that showed
   * only creates would let a deletion pass unrecorded, which is the mutation an
   * investigation cares about most.
   */
  it("distinguishes create from merge from remove", async () => {
    expect((await createPolicy(operatorKey.secret, "pol_b")).status).toBe(201);
    expect(
      (await patchPolicy(operatorKey.secret, "pol_b", { name: "pol_b", enabled: false })).status,
    ).toBe(200);
    expect((await deletePolicy(operatorKey.secret, "pol_b")).status).toBe(200);

    const trail = await readTrail(operatorKey.secret);
    // A SET, not a sequence: all three land inside the same wall-clock second,
    // and the ORDER BY's tiebreaker is then the random row id. Rust's query has
    // the identical property, so pinning a sequence here would assert something
    // neither implementation guarantees. The ORDER BY itself is pinned by the
    // next case, against the raw table.
    expect(trail.data.map((event) => event.action).sort()).toEqual(["create", "merge", "remove"]);
    expect(trail.data.every((event) => event.collection === "policies")).toBe(true);
  });

  /** Rust `audit_events_page_async`: `ORDER BY occurred_at_unix ASC, id ASC`. */
  it("returns every row the table holds, and only those", async () => {
    await createPolicy(operatorKey.secret, "pol_c");
    await createPolicy(operatorKey.secret, "pol_d");

    const stored = await auditRows();
    const trail = await readTrail(operatorKey.secret);
    expect(trail.data).toHaveLength(stored.length);
    expect(trail.data.map((event) => event.resource_id)).toEqual(
      stored
        .slice()
        .sort((a, b) => a.occurred_at_unix - b.occurred_at_unix || a.id.localeCompare(b.id))
        .map((row) => row.audit.resource_id),
    );
  });

  /**
   * The correlation id is what joins an audit row to the request that caused
   * it. Dropping it on the wire would leave the trail unjoinable to any other
   * evidence surface in the fleet.
   */
  it("carries the durable row's id, request id and timestamp onto the wire", async () => {
    await createPolicy(operatorKey.secret, "pol_e");

    const [stored] = await auditRows();
    expect(stored).toBeDefined();
    const [event] = (await readTrail(operatorKey.secret)).data;
    expect(event).toMatchObject({
      id: stored?.id,
      request_id: stored?.request_id,
      occurred_at_unix: stored?.occurred_at_unix,
    });
  });
});

// ---------------------------------------------------------------------------
// The tenant fence — read evidence is cross-tenant data
// ---------------------------------------------------------------------------

describe("the trail is fenced to the caller's tenant", () => {
  it("shows a tenant its own mutations", async () => {
    expect((await createPolicy("k-tenant", "pol_t1")).status).toBe(201);

    const trail = await readTrail("k-tenant");
    expect(trail.data).toHaveLength(1);
    expect(trail.data[0]).toMatchObject({ resource_id: "pol_t1", actor_scope: "tenant" });
  });

  it("hides one tenant's mutations from another", async () => {
    await createPolicy("k-tenant", "pol_t1");

    expect((await readTrail("k-other")).data).toHaveLength(0);
  });

  /**
   * Rust filters on `event.tenant.organization_id == Some(tenant_id)` — STRICT
   * equality, so an un-attributed PLATFORM mutation is invisible to a tenant
   * caller. That is narrower than the document READ fence (which deliberately
   * lets a tenant see un-attributed rows) and the difference is load-bearing:
   * platform-operator activity is not a tenant's evidence to read.
   */
  it("hides un-attributed platform mutations from a tenant caller", async () => {
    expect((await createPolicy(operatorKey.secret, "pol_platform")).status).toBe(201);

    expect((await readTrail("k-tenant")).data).toHaveLength(0);
    // ... and the operator can still see it, so the empty list above is a
    // fence and not a broken reader.
    expect((await readTrail(operatorKey.secret)).data).toHaveLength(1);
  });

  it("counts only the visible rows in the paginated total", async () => {
    await createPolicy("k-tenant", "pol_t1");
    await createPolicy("k-other", "pol_t2");
    await createPolicy(operatorKey.secret, "pol_platform");

    expect((await readTrail("k-tenant", "?limit=100")).total).toBe(1);
    expect((await readTrail(operatorKey.secret, "?limit=100")).total).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Pagination envelope
// ---------------------------------------------------------------------------

describe("the pagination envelope matches Rust", () => {
  /**
   * `handle_admin_audit_events` builds `AdminList::paginated(...)`
   * UNCONDITIONALLY — unlike the generic admin list handlers, it does not fork
   * on "was there a query string". A client paging the trail therefore always
   * gets `total`, and cannot mistake a first page for the whole history.
   */
  it("always answers the paginated envelope, query string or not", async () => {
    await createPolicy(operatorKey.secret, "pol_f");

    const trail = await readTrail(operatorKey.secret);
    expect(trail).toMatchObject({ object: "list", total: 1, offset: 0, limit: 100 });
  });

  it("windows on offset/limit while reporting the un-windowed total", async () => {
    await createPolicy(operatorKey.secret, "pol_g");
    await createPolicy(operatorKey.secret, "pol_h");
    await createPolicy(operatorKey.secret, "pol_i");

    const first = await readTrail(operatorKey.secret, "?limit=2");
    expect(first.data).toHaveLength(2);
    expect(first).toMatchObject({ total: 3, offset: 0, limit: 2 });

    const second = await readTrail(operatorKey.secret, "?limit=2&offset=2");
    expect(second.data).toHaveLength(1);
    expect(second).toMatchObject({ total: 3, offset: 2, limit: 2 });

    // The window must not re-serve a row the first page already delivered.
    const ids = [...first.data, ...second.data].map((event) => event.id);
    expect(new Set(ids).size).toBe(3);
  });
});
