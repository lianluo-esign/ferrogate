import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

/**
 * `GET /admin/v1/shared-billing-groups` reads the ACCOUNT-GLOBAL, ENABLED
 * billing groups from the authoritative control-DB `platform_billing_groups`
 * (#961) — no longer from a per-tenant `shared_billing_groups` Durable Object
 * mirror. This is the source the vega create-key dialog uses to show real,
 * multiplier-bearing group names.
 *
 * Because the set is account-global, every authenticated caller (any tenant, or
 * a platform operator) sees the SAME enabled groups and always the latest — there
 * is no per-tenant mirror to lag and no `?tenant_id=` selector. Groups are seeded
 * through the operator admin API (`POST /admin/v1/billing-groups`), the same path
 * production writes, and the read is then confirmed to project the control-DB
 * authority.
 */

const TENANT_A = "tenant_a";
const TENANT_A_SECRET = "tenant-a-secret";
const TENANT_B = "tenant_b";
const TENANT_B_SECRET = "tenant-b-secret";

const OPERATOR = operatorKey.secret;

type GroupRecord = {
  id: string;
  name: string;
  name_zh: string | null;
  provider_type_id: string | null;
  multiplier: number;
  description: string | null;
  description_zh: string | null;
  enabled: boolean;
  provider_ids: string[];
};

async function read(secret: string, query = ""): Promise<{ status: number; data: GroupRecord[] }> {
  const response = await SELF.fetch(`${BASE}/admin/v1/shared-billing-groups${query}`, {
    headers: bearer(secret),
  });
  const body = (await response.json()) as { data?: GroupRecord[] };
  return { status: response.status, data: body.data ?? [] };
}

/** Create a platform billing group through the operator admin surface. */
async function createGroup(body: Record<string, unknown>): Promise<number> {
  const response = await SELF.fetch(
    `${BASE}/admin/v1/billing-groups`,
    jsonRequest(OPERATOR, "POST", body),
  );
  return response.status;
}

/** Create a platform provider channel, so a group can bind it. */
async function createProvider(id: string): Promise<number> {
  const response = await SELF.fetch(
    `${BASE}/admin/v1/providers`,
    jsonRequest(OPERATOR, "POST", {
      id,
      name: id,
      kind: "openai-compatible",
      base_url: `https://${id}.example.test/v1`,
      enabled: true,
    }),
  );
  return response.status;
}

async function bindProvider(groupId: string, providerId: string): Promise<number> {
  const response = await SELF.fetch(`${BASE}/admin/v1/billing-groups/${groupId}/providers/${providerId}`, {
    method: "PUT",
    headers: bearer(OPERATOR),
  });
  return response.status;
}

/** Billing-group state `resetD1` does not clear on its own. */
async function wipeBillingGroups(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM platform_billing_group_providers"),
    db().prepare("DELETE FROM platform_billing_groups"),
    db().prepare("DELETE FROM platform_billing_group_revisions"),
  ]);
}

beforeAll(applySchema);

describe("tenant reads the account-global shared billing groups", () => {
  beforeEach(async () => {
    await resetD1();
    await wipeBillingGroups();
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_A_SECRET, TENANT_A), tenantKey(TENANT_B_SECRET, TENANT_B)],
    });
  });

  it("returns the enabled groups, ordered by name, projected from control-DB authority", async () => {
    expect(await createProvider("chan_openai")).toBe(201);
    expect(
      await createGroup({ id: "bg_std", name: "Standard", multiplier: 1.5, description: "std" }),
    ).toBe(201);
    expect(await bindProvider("bg_std", "chan_openai")).toBe(200);
    expect(await createGroup({ id: "bg_eco", name: "Economy", multiplier: 0.8 })).toBe(201);
    // A disabled group must NOT reach the vega selector.
    expect(
      await createGroup({ id: "bg_off", name: "Retired", multiplier: 3, enabled: false }),
    ).toBe(201);

    const { status, data } = await read(TENANT_A_SECRET);
    expect(status).toBe(200);
    // Ordered by name → Economy, Standard. The disabled "Retired" is filtered out.
    expect(data.map((g) => g.id)).toEqual(["bg_eco", "bg_std"]);
    expect(data[1]).toEqual({
      id: "bg_std",
      name: "Standard",
      // No Chinese variant configured → null; the Vega frontend falls back to name.
      name_zh: null,
      provider_type_id: "openai",
      multiplier: 1.5,
      description: "std",
      description_zh: null,
      enabled: true,
      provider_ids: ["chan_openai"],
    });
    expect(typeof data[0]?.multiplier).toBe("number");
    expect(data[0]?.provider_ids).toEqual([]);
  });

  it("projects the Chinese display variants so the Vega frontend can switch language (中英双语)", async () => {
    expect(
      await createGroup({
        id: "bg_bi",
        name: "Enterprise",
        name_zh: "企业版",
        multiplier: 2,
        description: "Marked-up tier",
        description_zh: "面向企业的加价档",
      }),
    ).toBe(201);
    // A group with only the English canonical value: its zh variants stay null so
    // the frontend falls back to `name`/`description`.
    expect(await createGroup({ id: "bg_en", name: "Basic", multiplier: 1 })).toBe(201);

    const { status, data } = await read(TENANT_A_SECRET);
    expect(status).toBe(200);
    const bilingual = data.find((g) => g.id === "bg_bi");
    expect(bilingual?.name).toBe("Enterprise");
    expect(bilingual?.name_zh).toBe("企业版");
    expect(bilingual?.description).toBe("Marked-up tier");
    expect(bilingual?.description_zh).toBe("面向企业的加价档");
    const englishOnly = data.find((g) => g.id === "bg_en");
    expect(englishOnly?.name).toBe("Basic");
    expect(englishOnly?.name_zh).toBeNull();
    expect(englishOnly?.description_zh).toBeNull();
  });

  it("serves the identical account-global set to every tenant", async () => {
    expect(await createGroup({ id: "bg_a", name: "GroupA", multiplier: 1 })).toBe(201);
    expect(await createGroup({ id: "bg_b", name: "GroupB", multiplier: 2 })).toBe(201);

    // Account-global config: there is no per-tenant fence — both tenants see both.
    expect((await read(TENANT_A_SECRET)).data.map((g) => g.id)).toEqual(["bg_a", "bg_b"]);
    expect((await read(TENANT_B_SECRET)).data.map((g) => g.id)).toEqual(["bg_a", "bg_b"]);
  });

  it("also serves a platform operator the same enabled set", async () => {
    expect(await createGroup({ id: "bg_ops", name: "Ops", multiplier: 1 })).toBe(201);
    expect((await read(OPERATOR)).data.map((g) => g.id)).toEqual(["bg_ops"]);
  });

  it("returns an empty list when no groups exist", async () => {
    const { status, data } = await read(TENANT_A_SECRET);
    expect(status).toBe(200);
    expect(data).toEqual([]);
  });

  it("returns the global set — not 503 — for a native tenant with no provisioning", async () => {
    expect(await createGroup({ id: "bg_glob", name: "Global", multiplier: 1 })).toBe(201);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey("tenant-c-secret", "tenant_c")],
    });
    const { status, data } = await read("tenant-c-secret");
    expect(status).toBe(200);
    expect(data.map((g) => g.id)).toEqual(["bg_glob"]);
  });

  it("rejects an unauthenticated caller", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/shared-billing-groups`);
    expect(response.status).toBe(401);
  });
});
