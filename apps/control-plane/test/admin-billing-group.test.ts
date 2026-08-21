/**
 * The platform billing-group admin surface (#943, epic #941).
 *
 * These tests drive the DEPLOYED Worker over `SELF` and then read the platform
 * tables with RAW SQL — never through {@link PlatformBillingGroupStore}, because
 * a store reading back its own write proves only that it agrees with itself,
 * this repo's dominant defect mode. The four things proven:
 *
 *  1. a platform operator round-trips a group (create → read → list → patch →
 *     delete), and each step is confirmed against `platform_billing_groups`;
 *  2. a provider binds and unbinds, confirmed against
 *     `platform_billing_group_providers`;
 *  3. a TENANT-scoped caller is fenced — every verb answers `404`, the same 404
 *     a non-existent group gets, so existence is never disclosed;
 *  4. `billing_group_id` on a virtual key is validated against the platform
 *     store and persisted to the tenant's own `api_keys` row, read back with raw
 *     SQL against the tenant database.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import {
  TENANT_A,
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
  tenantDbA,
} from "./tenant-db.js";

const OPERATOR = operatorKey.secret;
const TENANT_SECRET = "billing-group-tenant";

/** The posture `wrangler.toml` pins for this app today; restored after every test. */
const DEFAULT_CONTROL_STORAGE = "durable_object";

interface JsonBody {
  readonly [key: string]: unknown;
}

interface TestResponse {
  readonly status: number;
  readonly body: JsonBody;
}

async function request(
  secret: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<TestResponse> {
  const response = await SELF.fetch(
    `${BASE}${path}`,
    body === undefined || method === "GET" || method === "HEAD"
      ? { method, headers: bearer(secret) }
      : jsonRequest(secret, method, body),
  );
  return { status: response.status, body: (await response.json()) as JsonBody };
}

function controlStorage(mode: string): void {
  (env as unknown as Record<string, string | undefined>).CONTROL_PLANE_CONTROL_STORAGE = mode;
}

/** Group ids in the CONTROL table, read straight out of SQLite. */
async function rawGroupIds(): Promise<readonly string[]> {
  const rows = await db()
    .prepare("SELECT id FROM platform_billing_groups ORDER BY id ASC")
    .all<{ id: string }>();
  return rows.results.map((row) => row.id);
}

/** One group row as the database holds it — not as the store would project it. */
async function rawGroup(
  id: string,
): Promise<{ name: string; multiplier: number; enabled: number } | null> {
  return await db()
    .prepare("SELECT name, multiplier, enabled FROM platform_billing_groups WHERE id = ?")
    .bind(id)
    .first<{ name: string; multiplier: number; enabled: number }>();
}

/** Provider ids bound to a group, read straight out of the edge table. */
async function rawProviderIds(groupId: string): Promise<readonly string[]> {
  const rows = await db()
    .prepare(
      "SELECT provider_id FROM platform_billing_group_providers WHERE group_id = ? ORDER BY provider_id ASC",
    )
    .bind(groupId)
    .all<{ provider_id: string }>();
  return rows.results.map((row) => row.provider_id);
}

/** The tenant's OWN `api_keys` row (raw), the authority the settlement path reads. */
async function tenantKeyBillingGroup(id: string): Promise<string | null | undefined> {
  const row = await tenantDbA()
    .prepare("SELECT billing_group_id FROM api_keys WHERE id = ?")
    .bind(id)
    .first<{ billing_group_id: string | null }>();
  return row === null ? undefined : row.billing_group_id;
}

/** Remove billing-group state `resetD1` does not know about. */
async function wipeBillingGroups(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM platform_billing_group_providers"),
    db().prepare("DELETE FROM platform_billing_groups"),
    db().prepare("DELETE FROM platform_billing_group_revisions"),
  ]);
}

async function createPlatformProvider(id: string): Promise<TestResponse> {
  return request(OPERATOR, "POST", "/admin/v1/providers", {
    id,
    name: id,
    kind: "openai-compatible",
    base_url: `https://${id}.example.test/v1`,
    enabled: true,
  });
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  controlStorage(DEFAULT_CONTROL_STORAGE);
  await resetD1();
  await wipeBillingGroups();
  await resetTenantD1();
  await registerTenantDatabases();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    // admin.write so the tenant caller CLEARS the contract auth scope check and
    // is refused by the handler fence, not by the middleware — that is what
    // makes the 404 a real leak-proofing test and not an accidental 403.
    nativeKeys: [tenantKey(TENANT_SECRET, TENANT_A, ["admin.read", "admin.write"])],
    rbac: { [TENANT_A]: ["*"] },
  });
});

describe("platform billing-group admin surface", () => {
  it("round-trips a group for a platform operator, confirmed with raw SQL", async () => {
    const created = await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_growth",
      name: "growth",
      multiplier: 1.5,
      description: "growth team discount tier",
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect((created.body.billing_group as JsonBody).scope).toBe("platform");
    expect((created.body.billing_group as JsonBody).multiplier).toBe(1.5);

    // RAW SQL: the only assertion that tells "the handler wrote the table" from
    // "the handler agreed with itself".
    expect(await rawGroupIds()).toEqual(["bg_growth"]);
    expect(await rawGroup("bg_growth")).toEqual({ name: "growth", multiplier: 1.5, enabled: 1 });

    const read = await request(OPERATOR, "GET", "/admin/v1/billing-groups/bg_growth");
    expect(read.status).toBe(200);
    expect((read.body.billing_group as JsonBody).name).toBe("growth");

    const list = await request(OPERATOR, "GET", "/admin/v1/billing-groups");
    expect(list.status).toBe(200);
    expect((list.body.data as JsonBody[]).map((row) => row.id)).toEqual(["bg_growth"]);

    const patched = await request(OPERATOR, "PATCH", "/admin/v1/billing-groups/bg_growth", {
      multiplier: 2,
      enabled: false,
    });
    expect(patched.status).toBe(200);
    expect((patched.body.billing_group as JsonBody).multiplier).toBe(2);
    expect((patched.body.billing_group as JsonBody).enabled).toBe(false);
    expect(await rawGroup("bg_growth")).toEqual({ name: "growth", multiplier: 2, enabled: 0 });

    const deleted = await request(OPERATOR, "DELETE", "/admin/v1/billing-groups/bg_growth");
    expect(deleted.status).toBe(200);
    expect(deleted.body.deleted).toBe(true);
    expect(await rawGroupIds()).toEqual([]);

    const missing = await request(OPERATOR, "GET", "/admin/v1/billing-groups/bg_growth");
    expect(missing.status).toBe(404);
  });

  it("rejects a duplicate group name as a 409", async () => {
    expect(
      (
        await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
          id: "bg_a",
          name: "dup",
          multiplier: 1,
        })
      ).status,
    ).toBe(201);
    const clash = await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_b",
      name: "dup",
      multiplier: 1,
    });
    expect(clash.status, JSON.stringify(clash.body)).toBe(409);
    // The clash must NOT have landed a second row.
    expect(await rawGroupIds()).toEqual(["bg_a"]);
  });

  it("rejects a negative multiplier before it reaches the store", async () => {
    const bad = await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_neg",
      name: "neg",
      multiplier: -1,
    });
    expect(bad.status, JSON.stringify(bad.body)).toBe(400);
    expect(await rawGroupIds()).toEqual([]);
  });

  it("binds and unbinds a provider, confirmed with raw SQL", async () => {
    expect((await createPlatformProvider("bg_channel")).status).toBe(201);
    expect(
      (
        await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
          id: "bg_bind",
          name: "bind",
          multiplier: 1,
        })
      ).status,
    ).toBe(201);

    const bound = await request(
      OPERATOR,
      "PUT",
      "/admin/v1/billing-groups/bg_bind/providers/bg_channel",
    );
    expect(bound.status, JSON.stringify(bound.body)).toBe(200);
    expect((bound.body.billing_group as JsonBody).provider_ids).toEqual(["bg_channel"]);

    const incompatibleProviderUpdate = await request(
      OPERATOR,
      "PATCH",
      "/admin/v1/providers/bg_channel",
      { provider_type_id: "anthropic" },
    );
    expect(incompatibleProviderUpdate.status).toBe(400);
    expect((incompatibleProviderUpdate.body.error as JsonBody).message).toMatch(
      /different provider type/,
    );
    expect(await rawProviderIds("bg_bind")).toEqual(["bg_channel"]);

    // Idempotent: re-binding the same edge is still a 200 and still one row.
    expect(
      (await request(OPERATOR, "PUT", "/admin/v1/billing-groups/bg_bind/providers/bg_channel"))
        .status,
    ).toBe(200);
    expect(await rawProviderIds("bg_bind")).toEqual(["bg_channel"]);

    // Binding an unknown provider is a 404, not a silent no-op.
    expect(
      (await request(OPERATOR, "PUT", "/admin/v1/billing-groups/bg_bind/providers/ghost")).status,
    ).toBe(404);

    const unbound = await request(
      OPERATOR,
      "DELETE",
      "/admin/v1/billing-groups/bg_bind/providers/bg_channel",
    );
    expect(unbound.status).toBe(200);
    expect((unbound.body.billing_group as JsonBody).provider_ids).toEqual([]);
    expect(await rawProviderIds("bg_bind")).toEqual([]);

    // Unbinding an absent edge is a 404.
    expect(
      (await request(OPERATOR, "DELETE", "/admin/v1/billing-groups/bg_bind/providers/bg_channel"))
        .status,
    ).toBe(404);
  });

  it("fences a tenant-scoped caller out of the billing-group surface", async () => {
    expect(
      (
        await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
          id: "bg_fenced",
          name: "fenced",
          multiplier: 1,
        })
      ).status,
    ).toBe(201);

    // Every verb, on both the collection and the item, is a 404 — the SAME 404
    // a non-existent group gets, so a probe cannot learn the group exists.
    for (const [method, path, body] of [
      ["GET", "/admin/v1/billing-groups", undefined],
      ["POST", "/admin/v1/billing-groups", { id: "bg_tenant", name: "t", multiplier: 1 }],
      ["GET", "/admin/v1/billing-groups/bg_fenced", undefined],
      ["PATCH", "/admin/v1/billing-groups/bg_fenced", { multiplier: 9 }],
      ["DELETE", "/admin/v1/billing-groups/bg_fenced", undefined],
      ["PUT", "/admin/v1/billing-groups/bg_fenced/providers/bg_channel", undefined],
      ["DELETE", "/admin/v1/billing-groups/bg_fenced/providers/bg_channel", undefined],
    ] as const) {
      const response = await request(TENANT_SECRET, method, path, body);
      expect(response.status, `${method} ${path} as tenant`).toBe(404);
    }

    // The operator's row is untouched — the fence did not delete it.
    expect(await rawGroupIds()).toEqual(["bg_fenced"]);
  });
});

describe("virtual-key billing_group_id assignment", () => {
  async function mint(id: string, extra: Record<string, unknown>): Promise<number> {
    const res = await SELF.fetch(
      `${BASE}/admin/v1/virtual-keys`,
      jsonRequest(OPERATOR, "POST", {
        id,
        name: `key ${id}`,
        tenant_id: TENANT_A,
        project_id: "proj-1",
        workspace_id: "ws-1",
        scopes: ["admin.read"],
        ...extra,
      }),
    );
    return res.status;
  }

  it("validates the group, persists it to the tenant api_keys row, and clears it on null", async () => {
    expect(
      (
        await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
          id: "bg_key",
          name: "key-tier",
          multiplier: 3,
        })
      ).status,
    ).toBe(201);

    // Assigned: the id lands on the tenant's OWN api_keys row (raw read).
    expect(await mint("vk_assigned", { billing_group_id: "bg_key" })).toBe(201);
    expect(await tenantKeyBillingGroup("vk_assigned")).toBe("bg_key");

    // Cleared: an explicit null writes NULL, meaning "no group / multiplier 1.0".
    expect(await mint("vk_cleared", { billing_group_id: null })).toBe(201);
    expect(await tenantKeyBillingGroup("vk_cleared")).toBeNull();

    // Omitted: same as cleared.
    expect(await mint("vk_omitted", {})).toBe(201);
    expect(await tenantKeyBillingGroup("vk_omitted")).toBeNull();

    // An unknown group is refused BEFORE a key is minted for it.
    expect(await mint("vk_bad", { billing_group_id: "bg_does_not_exist" })).toBe(400);
    expect(await tenantKeyBillingGroup("vk_bad")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// `?search=` — the list handler honored paging but silently dropped the needle (#963)
// ---------------------------------------------------------------------------

describe("GET /admin/v1/billing-groups narrows on ?search=", () => {
  it("keeps only groups matching the needle, and totals the matches", async () => {
    await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_needle",
      name: "anthropic premium",
      multiplier: 2,
    });
    await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_other",
      name: "openai standard",
      multiplier: 1,
    });

    const hit = await request(OPERATOR, "GET", "/admin/v1/billing-groups?search=anthropic");
    expect(hit.status).toBe(200);
    expect(hit.body).toMatchObject({ total: 1 });
    expect((hit.body as { data: { id: string }[] }).data.map((g) => g.id)).toEqual(["bg_needle"]);
  });

  it("accepts ?q=, matches case-insensitively, and pages the narrowed set", async () => {
    await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_p1",
      name: "promo tier",
      multiplier: 0,
    });
    await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_p2",
      name: "promo extra",
      multiplier: 0,
    });
    await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_keep",
      name: "baseline",
      multiplier: 1,
    });

    const page = await request(OPERATOR, "GET", "/admin/v1/billing-groups?q=PROMO&limit=1");
    expect(page.status).toBe(200);
    expect(page.body).toMatchObject({ total: 2 });
    expect((page.body as { data: unknown[] }).data).toHaveLength(1);
  });

  it("answers an empty page — not every group — when nothing matches", async () => {
    await request(OPERATOR, "POST", "/admin/v1/billing-groups", {
      id: "bg_present",
      name: "present",
      multiplier: 1,
    });

    const miss = await request(OPERATOR, "GET", "/admin/v1/billing-groups?search=zzz-nope");
    expect(miss.body).toMatchObject({ total: 0 });
    expect((miss.body as { data: unknown[] }).data).toHaveLength(0);
  });
});
