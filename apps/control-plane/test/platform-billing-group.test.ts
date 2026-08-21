/**
 * `PlatformBillingGroupStore` over the control database (#942, epic #941).
 *
 * The store is exercised directly (not through an HTTP surface — that is #943)
 * and read back with RAW SQL for the audit/revision assertions, so a test can
 * never pass merely because the store agrees with itself — this repo's dominant
 * defect mode. Every mutation asserts three things move together: the projected
 * record, the monotone `platform_billing_group_revisions` stamp, and an audit
 * row on the platform (null-tenant) chain.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { CallerScope } from "../src/ports.js";
import { PlatformBillingGroupStore } from "../src/store/platform-billing-group.js";
import {
  TenantCatalogConflictError,
  TenantCatalogNotFoundError,
} from "../src/store/tenant-model-catalog.js";
import { applySchema, db, resetD1 } from "./d1.js";

const OPERATOR: CallerScope = { kind: "platform_operator" };

function store(): PlatformBillingGroupStore {
  return new PlatformBillingGroupStore({ db: db(), requestId: "test-req" });
}

/** Raw revision, read straight out of the stamp table. */
async function revision(): Promise<number> {
  const row = await db()
    .prepare("SELECT revision FROM platform_billing_group_revisions WHERE id = 1")
    .first<{ revision: number | string }>();
  return Number(row?.revision ?? 0);
}

/** Billing-group audit rows, oldest first, off the raw chain. */
async function auditActions(): Promise<readonly string[]> {
  const rows = await db()
    .prepare("SELECT audit_json, tenant FROM audit_events ORDER BY seq ASC")
    .all<{ audit_json: string; tenant: string | null }>();
  const actions: string[] = [];
  for (const row of rows.results) {
    const parsed = JSON.parse(row.audit_json) as { collection?: string; action?: string };
    if (parsed.collection === "platform_billing_groups") {
      expect(
        row.tenant,
        "a platform billing-group audit row must not be tenant-attributed",
      ).toBeNull();
      actions.push(String(parsed.action));
    }
  }
  return actions;
}

async function seedProvider(id: string, providerTypeId = "openai"): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO platform_provider_channels
         (id, name, provider_type_id, kind, base_url, enabled, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 'openai-compatible', ?, 1, unixepoch(), unixepoch())`,
    )
    .bind(id, id, providerTypeId, `https://${id}.example.test/v1`)
    .run();
}

describe("PlatformBillingGroupStore", () => {
  beforeAll(async () => {
    await applySchema();
  });

  beforeEach(async () => {
    await resetD1();
    await db().batch([
      db().prepare("DELETE FROM platform_billing_group_providers"),
      db().prepare("DELETE FROM platform_billing_groups"),
      db().prepare("DELETE FROM platform_billing_group_revisions"),
      db().prepare("DELETE FROM platform_provider_channels"),
      db().prepare("DELETE FROM audit_events"),
    ]);
    await seedProvider("prov-anthropic");
    await seedProvider("prov-openai");
    await seedProvider("prov-claude", "anthropic");
  });

  it("round-trips a group, its multiplier and a provider binding, bumping revision + audit each write", async () => {
    const s = store();

    const created = await s.createGroup(OPERATOR, {
      id: "grp-anthropic",
      name: "Anthropic",
      multiplier: 1.5,
      description: "anthropic official models",
      enabled: true,
    });
    expect(created.multiplier).toBe(1.5);
    expect(created.provider_type_id).toBe("openai");
    expect(created.provider_ids).toEqual([]);
    expect(created.scope).toBe("platform");
    expect(await revision()).toBe(1);
    expect(await auditActions()).toEqual(["create"]);

    expect(await s.bindProvider(OPERATOR, "grp-anthropic", "prov-anthropic")).toBe(true);
    expect(await s.bindProvider(OPERATOR, "grp-anthropic", "prov-openai")).toBe(true);
    const bound = await s.getGroup("grp-anthropic");
    expect(bound?.provider_ids).toEqual(["prov-anthropic", "prov-openai"]);
    expect(await revision()).toBe(3);

    // Idempotent re-bind: no row, no revision bump, no audit row.
    expect(await s.bindProvider(OPERATOR, "grp-anthropic", "prov-anthropic")).toBe(false);
    expect(await revision()).toBe(3);
    expect(await auditActions()).toEqual(["create", "merge", "merge"]);
  });

  it("updates the multiplier and reflects it in the snapshot the gateway reads", async () => {
    const s = store();
    await s.createGroup(OPERATOR, { id: "g", name: "G", multiplier: 1.0 });

    const updated = await s.updateGroup(OPERATOR, "g", { multiplier: 2.0 });
    expect(updated.multiplier).toBe(2.0);
    expect(await revision()).toBe(2);

    const snapshot = await s.multiplierSnapshot();
    expect(snapshot).toEqual([{ id: "g", multiplier: 2.0, enabled: true }]);
  });

  it("unbinds a provider, audits it as a remove, and drops the revision-bumping edge", async () => {
    const s = store();
    await s.createGroup(OPERATOR, { id: "g", name: "G", multiplier: 1.0 });
    await s.bindProvider(OPERATOR, "g", "prov-openai");
    await s.bindProvider(OPERATOR, "g", "prov-anthropic");

    expect(await s.unbindProvider(OPERATOR, "g", "prov-openai")).toBe(true);
    expect((await s.getGroup("g"))?.provider_ids).toEqual(["prov-anthropic"]);
    // The unbind is a real mutation: revision advanced and it audits as a
    // `remove`, distinguishable from the two `merge`s the binds wrote.
    expect(await revision()).toBe(4);
    expect(await auditActions()).toEqual(["create", "merge", "merge", "remove"]);

    // Idempotent: unbinding an absent edge is a no-op with no revision bump.
    expect(await s.unbindProvider(OPERATOR, "g", "prov-openai")).toBe(false);
    expect(await revision()).toBe(4);
  });

  it("renames a group and rejects a rename onto a taken name with a conflict", async () => {
    const s = store();
    await s.createGroup(OPERATOR, { id: "a", name: "Alpha", multiplier: 1.0 });
    await s.createGroup(OPERATOR, { id: "b", name: "Beta", multiplier: 1.0 });

    const renamed = await s.updateGroup(OPERATOR, "a", { name: "Alpha2", enabled: false });
    expect(renamed.name).toBe("Alpha2");
    expect(renamed.enabled).toBe(false);

    await expect(s.updateGroup(OPERATOR, "b", { name: "Alpha2" })).rejects.toThrow(
      TenantCatalogConflictError,
    );
    // The rejected rename left Beta untouched.
    expect((await s.getGroup("b"))?.name).toBe("Beta");

    const listed = await s.listGroups();
    expect(listed.map((g) => g.name)).toEqual(["Alpha2", "Beta"]);
  });

  it("404s an unknown group on update, delete-no-op, bind, and unbind", async () => {
    const s = store();
    await expect(s.updateGroup(OPERATOR, "ghost", { multiplier: 2 })).rejects.toThrow(
      TenantCatalogNotFoundError,
    );
    expect(await s.deleteGroup(OPERATOR, "ghost")).toBe(false);
    await expect(s.bindProvider(OPERATOR, "ghost", "prov-openai")).rejects.toThrow(
      /billing group ghost not found/,
    );
    // Unbind on an unknown group is a harmless no-op, not a throw.
    expect(await s.unbindProvider(OPERATOR, "ghost", "prov-openai")).toBe(false);
  });

  it("cascades bindings away when the group is deleted", async () => {
    const s = store();
    await s.createGroup(OPERATOR, { id: "g", name: "G", multiplier: 1.0 });
    await s.bindProvider(OPERATOR, "g", "prov-openai");

    expect(await s.deleteGroup(OPERATOR, "g")).toBe(true);
    expect(await s.getGroup("g")).toBeNull();
    const edges = await db()
      .prepare("SELECT COUNT(*) AS n FROM platform_billing_group_providers WHERE group_id = 'g'")
      .first<{ n: number }>();
    expect(Number(edges?.n ?? -1)).toBe(0);
  });

  it("rejects a negative multiplier and an unknown provider", async () => {
    const s = store();
    await expect(
      s.createGroup(OPERATOR, { id: "bad", name: "Bad", multiplier: -1 }),
    ).rejects.toThrow(/multiplier/);
    // A rejected create leaves nothing behind.
    expect(await revision()).toBe(0);

    await s.createGroup(OPERATOR, { id: "g", name: "G", multiplier: 1.0 });
    await expect(s.bindProvider(OPERATOR, "g", "does-not-exist")).rejects.toThrow(/not found/);
  });

  it("rejects binding a provider from a different global provider type", async () => {
    const s = store();
    await s.createGroup(OPERATOR, {
      id: "openai-group",
      name: "OpenAI",
      provider_type_id: "openai",
      multiplier: 1,
    });

    await expect(s.bindProvider(OPERATOR, "openai-group", "prov-claude")).rejects.toThrow(
      /does not match billing group type openai/,
    );
    expect((await s.getGroup("openai-group"))?.provider_ids).toEqual([]);
  });

  it("enforces a unique group name", async () => {
    const s = store();
    await s.createGroup(OPERATOR, { id: "g1", name: "Same", multiplier: 1.0 });
    await expect(
      s.createGroup(OPERATOR, { id: "g2", name: "Same", multiplier: 1.0 }),
    ).rejects.toThrow(TenantCatalogConflictError);
    // The rejected duplicate did not advance the registry.
    expect(await revision()).toBe(1);
    expect((await s.listGroups()).map((g) => g.id)).toEqual(["g1"]);
  });
});
