/**
 * M9 Step 5 backfill against the real control and tenant databases.
 *
 * This file runs in both D1 harnesses. The same assertions therefore cover
 * native tenant bindings and the Durable Object facade without allowing a
 * helper to hide a cross-tenant read or a stale control-plane write.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";

import {
  TENANT_CONFIGURATION_BACKFILL_MARK,
  backfillTenantConfigurationPolicy,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, setupTenantRouter, tenantDb } from "./harness.js";

const NOW = 1_750_000_000;

async function count(db: D1Database, table: string): Promise<number> {
  const row = await db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{ count: number }>();
  return row?.count ?? 0;
}

beforeEach(async () => {
  const router = await setupTenantRouter();
  await env.CONTROL_DB.batch([
    env.CONTROL_DB.prepare("DELETE FROM tenant_provider_credentials_legacy"),
    env.CONTROL_DB.prepare("DELETE FROM sso_provider_configs_legacy"),
    env.CONTROL_DB.prepare("DELETE FROM tenant_role_bindings_legacy"),
    env.CONTROL_DB.prepare("DELETE FROM semantic_cache_policies_legacy"),
    env.CONTROL_DB.prepare("DELETE FROM delegation_revocations_legacy"),
    env.CONTROL_DB.prepare("DELETE FROM control_plane_replay_floors_legacy"),
    env.CONTROL_DB.prepare("DELETE FROM budget_alert_notifications_legacy"),
    env.CONTROL_DB.prepare("DELETE FROM roles WHERE id IN ('role-backfill', 'role-missing')"),
  ]);
  for (const tenantId of [TENANT_A, TENANT_B]) {
    const db = tenantDb(tenantId);
    if (router.privilegedBatch !== undefined) {
      await router.privilegedBatch(tenantId, [
        { sql: "DELETE FROM tenant_role_bindings" },
        { sql: "DELETE FROM tenant_role_catalog" },
      ]);
    }
    await db.batch([
      db.prepare("DELETE FROM tenant_provider_credentials"),
      db.prepare("DELETE FROM sso_provider_configs"),
      ...(router.privilegedBatch === undefined
        ? [
            db.prepare("DELETE FROM tenant_role_bindings"),
            db.prepare("DELETE FROM tenant_role_catalog"),
          ]
        : []),
      db.prepare("DELETE FROM semantic_cache_policies"),
      db.prepare("DELETE FROM delegation_revocations"),
      db.prepare("DELETE FROM control_plane_replay_floors"),
      db.prepare("DELETE FROM budget_alert_notifications"),
      db
        .prepare("DELETE FROM tenant_provisioning_marks WHERE mark = ?")
        .bind(TENANT_CONFIGURATION_BACKFILL_MARK),
    ]);
  }
});

describe("tenant configuration policy backfill", () => {
  test("copies only the addressed tenant's seven families and is idempotent", async () => {
    await env.CONTROL_DB.batch([
      env.CONTROL_DB.prepare(
        "INSERT INTO roles (id, name, slug, description, permission_keys_json, created_at_unix, updated_at_unix) " +
          "VALUES ('role-backfill', 'Tenant operator', 'tenant-operator', 'operator', '[\"tenant.read\"]', ?, ?)",
      ).bind(NOW, NOW),
      env.CONTROL_DB.prepare(
        "INSERT INTO tenant_provider_credentials_legacy " +
          "(tenant_id, alias, provider, key_version, iv, ciphertext, last4, created_at_unix, rotated_at_unix) " +
          "VALUES (?, 'primary', 'openai', 1, 'iv', 'cipher', '1234', ?, ?)",
      ).bind(TENANT_A, NOW, NOW),
      env.CONTROL_DB.prepare(
        "INSERT INTO tenant_provider_credentials_legacy " +
          "(tenant_id, alias, provider, key_version, iv, ciphertext, last4, created_at_unix, rotated_at_unix) " +
          "VALUES (?, 'primary', 'openai', 1, 'iv', 'other', '5678', ?, ?)",
      ).bind(TENANT_B, NOW, NOW),
      env.CONTROL_DB.prepare(
        "INSERT INTO sso_provider_configs_legacy (tenant_id, provider_kind, default_role) VALUES (?, 'oidc', 'member')",
      ).bind(TENANT_A),
      env.CONTROL_DB.prepare(
        "INSERT INTO tenant_role_bindings_legacy (id, tenant_id, role_id, created_at_unix) VALUES ('binding-a', ?, 'role-backfill', ?)",
      ).bind(TENANT_A, NOW),
      env.CONTROL_DB.prepare(
        "INSERT INTO semantic_cache_policies_legacy (scope_type, scope_id, enabled, updated_at_unix) VALUES ('tenant', ?, 1, ?)",
      ).bind(TENANT_A, NOW),
      env.CONTROL_DB.prepare(
        "INSERT INTO delegation_revocations_legacy (tenant, subject, reason, revoked_at_unix) VALUES (?, 'jti-a', 'incident', ?)",
      ).bind(TENANT_A, NOW),
      env.CONTROL_DB.prepare(
        "INSERT INTO control_plane_replay_floors_legacy (tenant_id, deployment_id, last_accepted_revision, updated_at_unix) VALUES (?, 'deploy-a', 7, ?)",
      ).bind(TENANT_A, NOW),
      env.CONTROL_DB.prepare(
        "INSERT INTO budget_alert_notifications_legacy (id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix) VALUES ('alert-a', 'tenant', ?, '2026-08', 80, ?)",
      ).bind(TENANT_A, NOW),
    ]);

    const router = await setupTenantRouter();
    await backfillTenantConfigurationPolicy(env.CONTROL_DB, router, TENANT_A, NOW);
    const objectDb = tenantDb(TENANT_A);

    expect(await count(objectDb, "tenant_provider_credentials")).toBe(1);
    expect(await count(objectDb, "sso_provider_configs")).toBe(1);
    expect(await count(objectDb, "tenant_role_catalog")).toBe(1);
    expect(await count(objectDb, "tenant_role_bindings")).toBe(1);
    expect(await count(objectDb, "semantic_cache_policies")).toBe(1);
    expect(await count(objectDb, "delegation_revocations")).toBe(1);
    expect(await count(objectDb, "control_plane_replay_floors")).toBe(1);
    expect(await count(objectDb, "budget_alert_notifications")).toBe(1);
    expect(await count(tenantDb(TENANT_B), "tenant_provider_credentials")).toBe(0);

    const marker = await objectDb
      .prepare("SELECT mark FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
      .bind(TENANT_A, TENANT_CONFIGURATION_BACKFILL_MARK)
      .first<{ mark: string }>();
    expect(marker?.mark).toBe(TENANT_CONFIGURATION_BACKFILL_MARK);

    await env.CONTROL_DB.prepare(
      "INSERT INTO tenant_provider_credentials_legacy " +
        "(tenant_id, alias, provider, key_version, iv, ciphertext, last4, created_at_unix, rotated_at_unix) " +
        "VALUES (?, 'late', 'openai', 1, 'iv', 'late', '9999', ?, ?)",
    )
      .bind(TENANT_A, NOW, NOW)
      .run();
    await backfillTenantConfigurationPolicy(env.CONTROL_DB, router, TENANT_A, NOW + 1);
    expect(await count(objectDb, "tenant_provider_credentials")).toBe(1);
  });

  test("drops a binding whose shared role is missing instead of authorizing it", async () => {
    await env.CONTROL_DB.prepare(
      "INSERT INTO tenant_role_bindings_legacy (id, tenant_id, role_id, created_at_unix) VALUES ('binding-missing', ?, 'role-missing', ?)",
    )
      .bind(TENANT_A, NOW)
      .run();

    const router = await setupTenantRouter();
    await backfillTenantConfigurationPolicy(env.CONTROL_DB, router, TENANT_A, NOW);
    expect(await count(tenantDb(TENANT_A), "tenant_role_catalog")).toBe(0);
    expect(await count(tenantDb(TENANT_A), "tenant_role_bindings")).toBe(0);
  });
});
