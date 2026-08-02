/**
 * Issue #695 — the admin API for the response cache actually moves the row the
 * GATEWAY reads.
 *
 * The failure this file exists to catch is the one the quota chain shipped and
 * `test/quota-registry.test.ts` closed: an admin surface that stores a DOCUMENT
 * in `control_plane_resources` and stops there, while the data plane reads a
 * typed table nobody writes. Both sides are individually green and the control
 * does nothing. So every assertion below drives the REAL Worker through
 * `SELF.fetch` and then reads `semantic_cache_policies` with the GATEWAY's own
 * statement — {@link GATEWAY_SELECT}, transcribed from
 * `apps/gateway/src/cache/governance.ts::CACHE_GOVERNANCE_SELECT_SQL`. If the
 * projection stops writing a column, the gateway reads NULL where the operator
 * configured a value, and that is what goes red here.
 *
 * The gateway-side effect of these rows — a paraphrase served without an
 * upstream call, a purge making a hitting entry unreachable — is
 * `apps/gateway/test/cache/governance.test.ts`. This file owns the WRITE half
 * and the tenant fence on it.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { SEMANTIC_CACHE_POLICIES_TABLE } from "../src/store/semantic_cache_registry.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

/** A native key confined to `tenant_a`, with both admin scopes. */
const TENANT_A_KEY = tenantKey("fg_tenant_a_admin", "tenant_a");

const KEY = operatorKey.secret;
const COLLECTION = "/admin/v1/semantic-cache-policies";

/**
 * `apps/gateway/src/cache/governance.ts`'s `CACHE_GOVERNANCE_SELECT_SQL`,
 * verbatim. The column list is the contract between the two Workers.
 */
const GATEWAY_COLUMNS =
  "scope_type, scope_id, enabled, mode, similarity_threshold, ttl_seconds, scoped_models, invalidation_epoch, generation";
const GATEWAY_SELECT = `SELECT ${GATEWAY_COLUMNS} FROM ${SEMANTIC_CACHE_POLICIES_TABLE} WHERE scope_type = ?1 AND scope_id = ?2`;

async function gatewayRow(scopeId: string): Promise<Record<string, unknown> | null> {
  return await db()
    .prepare(GATEWAY_SELECT)
    .bind("tenant", scopeId)
    .first<Record<string, unknown>>();
}

async function send(method: string, path: string, body?: unknown): Promise<Response> {
  return await SELF.fetch(`${BASE}${path}`, jsonRequest(KEY, method, body));
}

beforeAll(applySchema);

beforeEach(async () => {
  arm({ store: "d1", staticKeys: [operatorKey], nativeKeys: [TENANT_A_KEY] });
  await resetD1();
  await db().prepare(`DELETE FROM ${SEMANTIC_CACHE_POLICIES_TABLE}`).run();
});

// ---------------------------------------------------------------------------
// 1. MOUNT — the document write reaches the typed row
// ---------------------------------------------------------------------------

describe("MOUNT: a policy written through the admin API is readable by the gateway", () => {
  it("projects every governed column, in the gateway's own vocabulary", async () => {
    const created = await send("POST", COLLECTION, {
      scope_type: "tenant",
      scope_id: "tenant_a",
      mode: "semantic",
      similarity_threshold: 0.82,
      ttl_seconds: 600,
      scoped_models: ["gpt-4o-mini", "claude-logical"],
    });
    expect(created.status).toBe(201);

    const row = await gatewayRow("tenant_a");
    expect(row).not.toBeNull();
    expect(row?.mode).toBe("semantic");
    expect(row?.similarity_threshold).toBeCloseTo(0.82, 6);
    expect(row?.ttl_seconds).toBe(600);
    expect(JSON.parse(String(row?.scoped_models))).toEqual(["gpt-4o-mini", "claude-logical"]);
    // Not asked for, so INHERIT — NULL, not 0. A `0` here would read as "this
    // tenant disabled caching", which is the opposite of what was requested.
    expect(row?.enabled).toBeNull();
    expect(row?.invalidation_epoch).toBe(0);
  });

  it("PUT replaces the whole governed policy — an omitted field returns to inherit", async () => {
    await send("POST", COLLECTION, {
      scope_type: "tenant",
      scope_id: "tenant_a",
      mode: "semantic",
      similarity_threshold: 0.82,
      ttl_seconds: 600,
    });
    const replaced = await send("PUT", `${COLLECTION}/tenant/tenant_a`, {
      mode: "semantic",
      similarity_threshold: 0.95,
    });
    expect(replaced.status).toBe(200);

    const row = await gatewayRow("tenant_a");
    expect(row?.similarity_threshold).toBeCloseTo(0.95, 6);
    // The whole point of PUT-without-PATCH: `ttl_seconds` was dropped from the
    // body, so it is back to inheriting the deployment var. A merge-patch could
    // not express this.
    expect(row?.ttl_seconds).toBeNull();
  });

  it("DELETE removes the enforcement row, not just the document", async () => {
    await send("POST", COLLECTION, {
      scope_type: "tenant",
      scope_id: "tenant_a",
      mode: "semantic",
    });
    expect(await gatewayRow("tenant_a")).not.toBeNull();

    expect((await send("DELETE", `${COLLECTION}/tenant/tenant_a`)).status).toBe(200);
    // Leaving the row behind is the quota defect exactly: a console that shows
    // nothing and a gateway that keeps applying it.
    expect(await gatewayRow("tenant_a")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. INVALIDATION — the epoch is monotonic and never moved by an edit
// ---------------------------------------------------------------------------

describe("explicit invalidation", () => {
  it("bumps the epoch and reports the value now in force", async () => {
    const first = await send("POST", `${COLLECTION}/tenant/tenant_a/invalidate`);
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({
      object: "semantic_cache_invalidation",
      scope_type: "tenant",
      scope_id: "tenant_a",
      invalidation_epoch: 1,
    });

    const second = await send("POST", `${COLLECTION}/tenant/tenant_a/invalidate`);
    expect(await second.json()).toMatchObject({ invalidation_epoch: 2 });
    expect((await gatewayRow("tenant_a"))?.invalidation_epoch).toBe(2);
  });

  it("works with NO policy document — a purge does not require a configuration", async () => {
    // "Throw away what you are holding for me" is a complete request on its
    // own. Requiring a policy first would make the emergency path depend on the
    // non-emergency one.
    expect(await gatewayRow("tenant_a")).toBeNull();
    const purged = await send("POST", `${COLLECTION}/tenant/tenant_a/invalidate`);
    expect(purged.status).toBe(200);
    expect((await gatewayRow("tenant_a"))?.invalidation_epoch).toBe(1);
  });

  it("a later configuration edit does NOT move the epoch — forwards or backwards", async () => {
    await send("POST", `${COLLECTION}/tenant/tenant_a/invalidate`);
    await send("POST", `${COLLECTION}/tenant/tenant_a/invalidate`);
    expect((await gatewayRow("tenant_a"))?.invalidation_epoch).toBe(2);

    // THE assertion. Every cache key is a function of the epoch, so a
    // projection that reset it to 0 here would make every body purged a moment
    // ago addressable again — an un-purge performed by an unrelated edit.
    await send("POST", COLLECTION, {
      scope_type: "tenant",
      scope_id: "tenant_a",
      mode: "semantic",
      similarity_threshold: 0.7,
    });
    expect((await gatewayRow("tenant_a"))?.invalidation_epoch).toBe(2);

    await send("PUT", `${COLLECTION}/tenant/tenant_a`, { mode: "exact_match" });
    expect((await gatewayRow("tenant_a"))?.invalidation_epoch).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// 3. VALIDATION — an unusable value is refused rather than stored
// ---------------------------------------------------------------------------

describe("the threshold range is enforced at the admin surface", () => {
  it("refuses a threshold outside (0.0, 1.0] and writes no row", async () => {
    for (const threshold of [0, 1.5, -0.2]) {
      const res = await send("POST", COLLECTION, {
        scope_type: "tenant",
        scope_id: "tenant_a",
        mode: "semantic",
        similarity_threshold: threshold,
      });
      expect(res.status, `threshold ${threshold}`).toBe(400);
    }
    // Storing an out-of-range value would be worse than refusing it: the
    // gateway treats an unreadable governance row as a reason to BYPASS the
    // cache, so a 201 here would silently switch the tenant's caching off while
    // the console showed a configured policy.
    expect(await gatewayRow("tenant_a")).toBeNull();
  });

  it("accepts 1.0 — the interval is half-open at the bottom only", async () => {
    const res = await send("POST", COLLECTION, {
      scope_type: "tenant",
      scope_id: "tenant_a",
      mode: "semantic",
      similarity_threshold: 1,
    });
    expect(res.status).toBe(201);
    expect((await gatewayRow("tenant_a"))?.similarity_threshold).toBe(1);
  });

  it("404s an unknown scope kind rather than inventing a scope", async () => {
    expect((await send("GET", `${COLLECTION}/project/project_1`)).status).toBe(404);
    expect((await send("POST", `${COLLECTION}/project/project_1/invalidate`)).status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// 4. THE FENCE — a tenant-scoped caller cannot govern another tenant's cache
// ---------------------------------------------------------------------------

describe("tenant scoping", () => {
  it("denies a tenant-scoped caller writing ANOTHER tenant's cache policy", async () => {
    // The caller is confined to `tenant_a` (see `./harness.ts`). Governing
    // `tenant_b`'s cache means being able to disable it, loosen its threshold,
    // or purge it — a denial-of-service and a cost lever over a stranger.
    const res = await SELF.fetch(
      `${BASE}${COLLECTION}/tenant/tenant_b`,
      jsonRequest(TENANT_A_KEY.secret, "PUT", { mode: "semantic" }),
    );
    expect(res.status).toBe(403);
    expect(await gatewayRow("tenant_b")).toBeNull();
  });

  it("denies a tenant-scoped caller PURGING another tenant's cache", async () => {
    const res = await SELF.fetch(
      `${BASE}${COLLECTION}/tenant/tenant_b/invalidate`,
      jsonRequest(TENANT_A_KEY.secret, "POST", {}),
    );
    expect(res.status).toBe(403);
    expect(await gatewayRow("tenant_b")).toBeNull();
  });

  it("CONTROL: the same caller CAN govern its OWN tenant", async () => {
    // Without this the two denials above would also pass for a surface that
    // rejects every tenant-scoped caller, which would be a different bug.
    const res = await SELF.fetch(
      `${BASE}${COLLECTION}`,
      jsonRequest(TENANT_A_KEY.secret, "POST", {
        scope_type: "tenant",
        scope_id: "tenant_a",
        mode: "semantic",
      }),
    );
    expect(res.status).toBe(201);
    expect((await gatewayRow("tenant_a"))?.mode).toBe("semantic");
  });
});

// ---------------------------------------------------------------------------
// 5. AUTH — the operations are behind the contract's own scopes
// ---------------------------------------------------------------------------

describe("the contract auth ladder applies", () => {
  it("401s without a credential and 200s with the operator one", async () => {
    expect((await SELF.fetch(`${BASE}${COLLECTION}`)).status).toBe(401);
    expect((await SELF.fetch(`${BASE}${COLLECTION}`, { headers: bearer(KEY) })).status).toBe(200);
  });
});
