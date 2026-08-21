import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1 } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";
import { privilegedTenantBatch, registerDurableObjectTenant } from "./tenant-object.js";

/**
 * `GET /admin/v1/shared-billing-groups` reads the CALLING tenant's own
 * `shared_billing_groups` Durable Object mirror (`billing.ts`). This is the
 * source the vega create-key dialog uses to show real, multiplier-bearing group
 * names. The mirror is a PRIVILEGED_WRITE table, so the fixture seeds it through
 * the privileged tenant RPC — an ordinary tenant write would be refused.
 */

const TENANT_A = "tenant_a";
const TENANT_A_SECRET = "tenant-a-secret";
const TENANT_B = "tenant_b";
const TENANT_B_SECRET = "tenant-b-secret";

interface SeedGroup {
  id: string;
  name: string;
  multiplier: number;
  description: string | null;
  enabled: number;
  providerTypeId?: string | null;
  providerIds: string[] | string; // string lets a case seed malformed JSON
}

async function seedGroups(tenantId: string, groups: readonly SeedGroup[]): Promise<void> {
  await privilegedTenantBatch(
    tenantId,
    groups.map((group) => ({
      sql: `INSERT INTO shared_billing_groups
              (id, name, provider_type_id, multiplier, description, enabled, provider_ids_json,
               config_revision, synced_at_unix)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1700)`,
      params: [
        group.id,
        group.name,
        group.providerTypeId ??
          (Array.isArray(group.providerIds) ? (group.providerIds[0] ?? null) : null),
        group.multiplier,
        group.description,
        group.enabled,
        typeof group.providerIds === "string"
          ? group.providerIds
          : JSON.stringify(group.providerIds),
      ],
    })),
  );
}

type GroupRecord = {
  id: string;
  name: string;
  provider_type_id: string | null;
  multiplier: number;
  description: string | null;
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

beforeAll(applySchema);

describe("tenant reads its own shared_billing_groups mirror", () => {
  beforeEach(async () => {
    await resetD1();
    await registerDurableObjectTenant(TENANT_A);
    await registerDurableObjectTenant(TENANT_B);
    await privilegedTenantBatch(TENANT_A, [
      { sql: "DELETE FROM shared_billing_groups", params: [] },
    ]);
    await privilegedTenantBatch(TENANT_B, [
      { sql: "DELETE FROM shared_billing_groups", params: [] },
    ]);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_A_SECRET, TENANT_A), tenantKey(TENANT_B_SECRET, TENANT_B)],
    });
  });

  it("returns the tenant's enabled groups, ordered by name, with parsed fields", async () => {
    await seedGroups(TENANT_A, [
      {
        id: "bg_std",
        name: "Standard",
        multiplier: 1.5,
        description: "std",
        enabled: 1,
        providerIds: ["openai", "anthropic"],
      },
      {
        id: "bg_eco",
        name: "Economy",
        multiplier: 0.8,
        description: null,
        enabled: 1,
        providerIds: ["deepseek"],
      },
      {
        id: "bg_off",
        name: "Retired",
        multiplier: 3,
        description: "disabled",
        enabled: 0,
        providerIds: [],
      },
    ]);

    const { status, data } = await read(TENANT_A_SECRET);
    expect(status).toBe(200);
    // Ordered by name → Economy, Standard. The disabled "Retired" is filtered out.
    expect(data.map((g) => g.id)).toEqual(["bg_eco", "bg_std"]);
    expect(data[1]).toEqual({
      id: "bg_std",
      name: "Standard",
      provider_type_id: "openai",
      multiplier: 1.5,
      description: "std",
      enabled: true,
      provider_ids: ["openai", "anthropic"],
    });
    expect(typeof data[0]?.multiplier).toBe("number");
    expect(data[0]?.provider_ids).toEqual(["deepseek"]);
  });

  it("fences each tenant to its own mirror", async () => {
    await seedGroups(TENANT_A, [
      {
        id: "bg_a",
        name: "GroupA",
        multiplier: 1,
        description: null,
        enabled: 1,
        providerIds: ["openai"],
      },
    ]);
    await seedGroups(TENANT_B, [
      {
        id: "bg_b",
        name: "GroupB",
        multiplier: 2,
        description: null,
        enabled: 1,
        providerIds: ["grok"],
      },
    ]);

    expect((await read(TENANT_A_SECRET)).data.map((g) => g.id)).toEqual(["bg_a"]);
    expect((await read(TENANT_B_SECRET)).data.map((g) => g.id)).toEqual(["bg_b"]);
  });

  it("returns an empty list for an un-fanned-out (empty) mirror", async () => {
    const { status, data } = await read(TENANT_A_SECRET);
    expect(status).toBe(200);
    expect(data).toEqual([]);
  });

  it("returns an empty list — not 503 — for an unprovisioned/native tenant", async () => {
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey("tenant-c-secret", "tenant_c")],
    });
    const { status, data } = await read("tenant-c-secret");
    expect(status).toBe(200);
    expect(data).toEqual([]);
  });

  it("degrades malformed provider_ids_json to an empty array", async () => {
    await seedGroups(TENANT_A, [
      {
        id: "bg_bad",
        name: "Bad",
        multiplier: 1,
        description: null,
        enabled: 1,
        providerIds: "not json",
      },
    ]);
    const { status, data } = await read(TENANT_A_SECRET);
    expect(status).toBe(200);
    expect(data).toEqual([
      {
        id: "bg_bad",
        name: "Bad",
        provider_type_id: null,
        multiplier: 1,
        description: null,
        enabled: true,
        provider_ids: [],
      },
    ]);
  });

  it("gives a platform operator [] with no tenant, and one tenant's rows with ?tenant_id=", async () => {
    await seedGroups(TENANT_A, [
      {
        id: "bg_a",
        name: "GroupA",
        multiplier: 1,
        description: null,
        enabled: 1,
        providerIds: ["openai"],
      },
    ]);

    expect((await read(operatorKey.secret)).data).toEqual([]);
    expect(
      (await read(operatorKey.secret, `?tenant_id=${TENANT_A}`)).data.map((g) => g.id),
    ).toEqual(["bg_a"]);
  });

  it("rejects an unauthenticated caller", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/shared-billing-groups`);
    expect(response.status).toBe(401);
  });
});
