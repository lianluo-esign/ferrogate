/**
 * `D1AssetEntitlements` — the durable `tenant_can_host`.
 *
 * Run against the REAL `CONTROL_DB` binding and the REAL `tenants` / `plans` /
 * `permissions` / `roles` / `tenant_role_bindings` DDL from
 * `sql/d1-ts/control/0001_init_control.sql` (applied by `test/setup-d1.ts`).
 * The only substituted thing is a THROWING database, which is what a live
 * binding cannot be asked to be.
 *
 * The Rust rule being held (`assets.rs::tenant_can_host`, issues #176/#177/#182):
 *
 *     plan.asset_hosting_enabled  OR  tenant_has_permission(tenant, "assets.host")
 *
 * Either is sufficient; a failure of either lookup is "no grant", never a 503.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ASSET_HOST_PERMISSION,
  D1AssetEntitlements,
  type EntitlementsDatabase,
  NO_ASSET_HOSTING,
  configuredEntitlementsFromEnv,
  entitlementsFromEnv,
} from "../../src/assets/index.js";

const bindings = env as unknown as Record<string, unknown>;

function controlDb(): D1Database {
  const binding = bindings.CONTROL_DB as D1Database | undefined;
  if (binding === undefined) {
    throw new Error(
      "asset entitlement tests expect the `CONTROL_DB` binding (apps/gateway/wrangler.toml).",
    );
  }
  return binding;
}

function durable(fallbackVar?: string): D1AssetEntitlements {
  return new D1AssetEntitlements(controlDb() as unknown as EntitlementsDatabase, {
    fallback: configuredEntitlementsFromEnv({ ASSET_ENTITLEMENTS: fallbackVar }),
  });
}

async function seedPlan(
  id: string,
  hosting: boolean,
  quota?: number,
  maxObject?: number,
): Promise<void> {
  await controlDb()
    .prepare(
      "INSERT OR REPLACE INTO plans (id, name, slug, asset_hosting_enabled, " +
        "default_asset_storage_quota_bytes, default_asset_max_object_bytes) " +
        "VALUES (?1, ?1, ?1, ?2, ?3, ?4)",
    )
    .bind(id, hosting ? 1 : 0, quota ?? null, maxObject ?? null)
    .run();
}

async function seedTenant(id: string, planId: string): Promise<void> {
  await controlDb()
    .prepare("INSERT OR REPLACE INTO tenants (id, name, slug, plan_id) VALUES (?1, ?1, ?1, ?2)")
    .bind(id, planId)
    .run();
}

async function grantHostRole(tenantId: string): Promise<void> {
  const db = controlDb();
  await db
    .prepare(
      "INSERT OR REPLACE INTO permissions (id, key, name) VALUES ('perm_host', ?1, 'assets.host')",
    )
    .bind(ASSET_HOST_PERMISSION)
    .run();
  await db
    .prepare(
      "INSERT OR REPLACE INTO roles (id, name, slug, permission_keys_json) " +
        "VALUES ('role_host', 'host', 'host', ?1)",
    )
    .bind(JSON.stringify([ASSET_HOST_PERMISSION]))
    .run();
  await db
    .prepare(
      "INSERT OR REPLACE INTO tenant_role_bindings (id, tenant_id, role_id) " +
        "VALUES (?1, ?2, 'role_host')",
    )
    .bind(`${tenantId}:role_host`, tenantId)
    .run();
}

async function reset(): Promise<void> {
  const db = controlDb();
  await db.batch([
    db.prepare("DELETE FROM tenant_role_bindings"),
    db.prepare("DELETE FROM roles"),
    db.prepare("DELETE FROM permissions"),
    db.prepare("DELETE FROM tenants"),
    // `plans` ships a seeded `free` row in the migration; only test rows go.
    db.prepare("DELETE FROM plans WHERE id LIKE 'plan_%'"),
  ]);
}

beforeEach(reset);
afterEach(reset);

describe("tenant_can_host — the plan half", () => {
  it("grants hosting from the tenant's plan, with its quotas", async () => {
    await seedPlan("plan_hosting", true, 1024, 512);
    await seedTenant("tenant_p", "plan_hosting");

    expect(await durable().resolve("tenant_p")).toEqual({
      assetHostingEnabled: true,
      assetStorageQuotaBytes: 1024,
      assetMaxObjectBytes: 512,
    });
  });

  it("a plan with hosting off denies, and the var cannot re-grant it", async () => {
    await seedPlan("plan_none", false);
    await seedTenant("tenant_p", "plan_none");

    // The var says yes. The durable plan says no. The plan wins — otherwise the
    // bootstrap table would be a way around a withdrawn entitlement.
    const port = durable(JSON.stringify({ tenant_p: { asset_hosting_enabled: true } }));
    expect((await port.resolve("tenant_p")).assetHostingEnabled).toBe(false);
  });

  it("reports NULL plan quotas as unbounded, not as zero", async () => {
    // A `0` quota would refuse every object; `undefined` is "no ceiling".
    await seedPlan("plan_unbounded", true);
    await seedTenant("tenant_p", "plan_unbounded");

    const resolved = await durable().resolve("tenant_p");
    expect(resolved.assetStorageQuotaBytes).toBeUndefined();
    expect(resolved.assetMaxObjectBytes).toBeUndefined();
  });
});

describe("tenant_can_host — the role half (#182)", () => {
  it("a bound `assets.host` role grants hosting even when the plan does not", async () => {
    await seedPlan("plan_none", false);
    await seedTenant("tenant_r", "plan_none");
    await grantHostRole("tenant_r");

    expect((await durable().resolve("tenant_r")).assetHostingEnabled).toBe(true);
  });

  it("an UNDECLARED `assets.host` permission grants nothing, however many roles name it", async () => {
    await seedPlan("plan_none", false);
    await seedTenant("tenant_r", "plan_none");
    await grantHostRole("tenant_r");
    await controlDb().prepare("DELETE FROM permissions").run();

    expect((await durable().resolve("tenant_r")).assetHostingEnabled).toBe(false);
  });

  it("another tenant's role is not a grant", async () => {
    await seedPlan("plan_none", false);
    await seedTenant("tenant_r", "plan_none");
    await seedTenant("tenant_other", "plan_none");
    await grantHostRole("tenant_other");

    expect((await durable().resolve("tenant_r")).assetHostingEnabled).toBe(false);
  });
});

describe("the bootstrap var answers only for an unknown tenant", () => {
  it("uses the var when the control plane has no row for the tenant", async () => {
    const port = durable(
      JSON.stringify({ tenant_boot: { asset_hosting_enabled: true, asset_max_object_bytes: 99 } }),
    );
    expect(await port.resolve("tenant_boot")).toMatchObject({
      assetHostingEnabled: true,
      assetMaxObjectBytes: 99,
    });
  });

  it("still lets a ROLE grant hosting for a tenant the var does not name", async () => {
    await grantHostRole("tenant_roleonly");
    expect((await durable("{}").resolve("tenant_roleonly")).assetHostingEnabled).toBe(true);
  });

  it("denies an unknown tenant with no var entry and no role", async () => {
    expect(await durable("{}").resolve("tenant_nobody")).toMatchObject(NO_ASSET_HOSTING);
  });
});

describe("a control-plane outage stops PUBLISHES, not READS", () => {
  const failing: EntitlementsDatabase = {
    prepare(): never {
      throw new Error("D1_ERROR: control database is unreachable");
    },
  };

  it("answers `no hosting` rather than throwing — the Rust `.ok().flatten()`", async () => {
    const port = new D1AssetEntitlements(failing);
    // Not a 503: the read surfaces do not require hosting, so already-published
    // assets stay readable while new publishes stop. Turning this into a 5xx
    // would be a worse outage AND a divergence from the Rust.
    await expect(port.resolve("tenant_x")).resolves.toMatchObject({
      assetHostingEnabled: false,
    });
  });
});

describe("entitlementsFromEnv wires the durable port", () => {
  it("prefers D1 when CONTROL_DB is bound and the var alone otherwise", async () => {
    expect(entitlementsFromEnv(bindings as never)).toBeInstanceOf(D1AssetEntitlements);
    // Deleting `D1AssetEntitlements.fromEnv(...) ??` from `entitlementsFromEnv`
    // turns the first assertion red while every test above stays green.
    expect(entitlementsFromEnv({ ASSET_ENTITLEMENTS: "{}" })).not.toBeInstanceOf(
      D1AssetEntitlements,
    );
  });

  it("the wired port really reads the plans table", async () => {
    await seedPlan("plan_hosting", true, 4096);
    await seedTenant("tenant_wired", "plan_hosting");

    const port = entitlementsFromEnv({
      ...(bindings as Record<string, unknown>),
      // Empty var, so a `true` here can only have come from D1.
      ASSET_ENTITLEMENTS: "{}",
    } as never);
    expect(await port.resolve("tenant_wired")).toMatchObject({
      assetHostingEnabled: true,
      assetStorageQuotaBytes: 4096,
    });
  });
});
