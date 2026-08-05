/**
 * Idempotent M9 Step 5 backfill from the pre-object CONTROL tables.
 *
 * This module is migration input only. Production readers must call it before
 * reading the tenant object and then stay on that object; they must never use a
 * legacy table as a second read source when the object is unavailable.
 */
import type { TenantDataStatement, TenantDataValue } from "./tenant-data-object.js";
import type { TenantDatabaseRouter } from "./tenant-router.js";

export const TENANT_CONFIGURATION_BACKFILL_MARK = "tenant_configuration_policy_v1";

type Row = Record<string, unknown>;

interface BackfillSources {
  readonly provider: string | null;
  readonly sso: string | null;
  readonly bindings: string | null;
  readonly cache: string | null;
  readonly revocations: string | null;
  readonly replayFloors: string | null;
  readonly budgetAlerts: string | null;
}

async function tableExists(db: D1Database, table: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?")
    .bind(table)
    .first<{ present: number }>();
  return row !== null;
}

async function sourceTable(
  db: D1Database,
  legacy: string,
  active: string,
): Promise<string | null> {
  if (await tableExists(db, legacy)) return legacy;
  if (await tableExists(db, active)) return active;
  return null;
}

async function sources(db: D1Database): Promise<BackfillSources> {
  const [provider, sso, bindings, cache, revocations, replayFloors, budgetAlerts] = await Promise.all([
    sourceTable(db, "tenant_provider_credentials_legacy", "tenant_provider_credentials"),
    sourceTable(db, "sso_provider_configs_legacy", "sso_provider_configs"),
    sourceTable(db, "tenant_role_bindings_legacy", "tenant_role_bindings"),
    sourceTable(db, "semantic_cache_policies_legacy", "semantic_cache_policies"),
    sourceTable(db, "delegation_revocations_legacy", "delegation_revocations"),
    sourceTable(db, "control_plane_replay_floors_legacy", "control_plane_replay_floors"),
    sourceTable(db, "budget_alert_notifications_legacy", "budget_alert_notifications"),
  ]);
  return { provider, sso, bindings, cache, revocations, replayFloors, budgetAlerts };
}

async function all(db: D1Database, sql: string, ...params: readonly unknown[]): Promise<Row[]> {
  const result = await db.prepare(sql).bind(...params).all<Row>();
  return result.results;
}

function value(row: Row, key: string, fallback: string | number | null = null): string | number | null {
  const candidate = row[key];
  return typeof candidate === "string" || typeof candidate === "number" || candidate === null
    ? candidate
    : fallback;
}

function add(statements: TenantDataStatement[], sql: string, params: readonly TenantDataValue[]): void {
  statements.push({ sql, params });
}

async function runTenantBatch(
  router: TenantDatabaseRouter,
  tenantId: string,
  statements: readonly TenantDataStatement[],
): Promise<void> {
  if (router.privilegedBatch !== undefined) {
    await router.privilegedBatch(tenantId, statements);
    return;
  }
  const handle = await router.forTenant(tenantId);
  await handle.db.batch(
    statements.map((statement) => handle.db.prepare(statement.sql).bind(...(statement.params ?? []))),
  );
}

/** Copy one tenant's legacy rows into its object, exactly once. */
export async function backfillTenantConfigurationPolicy(
  controlDb: D1Database,
  router: TenantDatabaseRouter,
  tenantId: string,
  nowUnix = Math.floor(Date.now() / 1000),
): Promise<void> {
  if (tenantId.trim() === "") throw new Error("tenant configuration backfill requires a tenant id");
  const handle = await router.forTenant(tenantId);
  const marker = await handle.db
    .prepare("SELECT mark FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
    .bind(tenantId, TENANT_CONFIGURATION_BACKFILL_MARK)
    .first<{ mark: string }>();
  if (marker !== null) return;

  const source = await sources(controlDb);
  const statements: TenantDataStatement[] = [];

  if (source.provider !== null) {
    for (const row of await all(
      controlDb,
      `SELECT tenant_id, alias, provider, key_version, iv, ciphertext, last4,
              created_at_unix, rotated_at_unix, revoked_at_unix
         FROM ${source.provider} WHERE tenant_id = ?`,
      tenantId,
    )) {
      add(
        statements,
        "INSERT OR IGNORE INTO tenant_provider_credentials " +
          "(tenant_id, alias, provider, key_version, iv, ciphertext, last4, created_at_unix, rotated_at_unix, revoked_at_unix) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          value(row, "tenant_id", tenantId) ?? tenantId,
          value(row, "alias", "") ?? "",
          value(row, "provider", "") ?? "",
          value(row, "key_version", 0) ?? 0,
          value(row, "iv", "") ?? "",
          value(row, "ciphertext", "") ?? "",
          value(row, "last4", "") ?? "",
          value(row, "created_at_unix", nowUnix) ?? nowUnix,
          value(row, "rotated_at_unix", nowUnix) ?? nowUnix,
          value(row, "revoked_at_unix"),
        ],
      );
    }
  }

  if (source.sso !== null) {
    for (const row of await all(controlDb, `SELECT * FROM ${source.sso} WHERE tenant_id = ?`, tenantId)) {
      add(
        statements,
        "INSERT OR IGNORE INTO sso_provider_configs " +
          "(tenant_id, provider_kind, default_role, group_role_mapping_json, oidc_issuer, oidc_client_id, " +
          "oidc_client_secret_ref, oidc_redirect_uri, oidc_group_claim, saml_idp_entity_id, saml_idp_sso_url, " +
          "saml_idp_certificate, saml_sp_entity_id, saml_acs_url, saml_email_attribute, saml_name_attribute, " +
          "saml_groups_attribute, created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          value(row, "tenant_id", tenantId) ?? tenantId,
          value(row, "provider_kind", "") ?? "",
          value(row, "default_role", "member") ?? "member",
          value(row, "group_role_mapping_json", "{}") ?? "{}",
          value(row, "oidc_issuer"),
          value(row, "oidc_client_id"),
          value(row, "oidc_client_secret_ref"),
          value(row, "oidc_redirect_uri"),
          value(row, "oidc_group_claim"),
          value(row, "saml_idp_entity_id"),
          value(row, "saml_idp_sso_url"),
          value(row, "saml_idp_certificate"),
          value(row, "saml_sp_entity_id"),
          value(row, "saml_acs_url"),
          value(row, "saml_email_attribute"),
          value(row, "saml_name_attribute"),
          value(row, "saml_groups_attribute"),
          value(row, "created_at_unix", nowUnix) ?? nowUnix,
          value(row, "updated_at_unix", nowUnix) ?? nowUnix,
        ],
      );
    }
  }

  if (source.bindings !== null) {
    const rows = await all(
      controlDb,
      `SELECT b.id, b.tenant_id, b.role_id, b.created_at_unix,
              r.name, r.slug, r.description, r.permission_keys_json,
              r.created_at_unix AS role_created_at_unix,
              r.updated_at_unix AS role_updated_at_unix
         FROM ${source.bindings} AS b
         JOIN roles AS r ON r.id = b.role_id
        WHERE b.tenant_id = ?`,
      tenantId,
    );
    for (const row of rows) {
      add(
        statements,
        "INSERT INTO tenant_role_catalog " +
          "(role_id, name, slug, description, permission_keys_json, created_at_unix, updated_at_unix) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(role_id) DO UPDATE SET name = excluded.name, slug = excluded.slug, " +
          "description = excluded.description, permission_keys_json = excluded.permission_keys_json, " +
          "updated_at_unix = excluded.updated_at_unix",
        [
          value(row, "role_id", "") ?? "",
          value(row, "name", "") ?? "",
          value(row, "slug", "") ?? "",
          value(row, "description", "") ?? "",
          value(row, "permission_keys_json", "[]") ?? "[]",
          value(row, "role_created_at_unix", nowUnix) ?? nowUnix,
          value(row, "role_updated_at_unix", nowUnix) ?? nowUnix,
        ],
      );
      add(
        statements,
        "INSERT OR IGNORE INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) VALUES (?, ?, ?, ?)",
        [
          value(row, "id", `${tenantId}:${String(value(row, "role_id", ""))}`) ?? "",
          tenantId,
          value(row, "role_id", "") ?? "",
          value(row, "created_at_unix", nowUnix) ?? nowUnix,
        ],
      );
    }
  }

  if (source.cache !== null) {
    for (const row of await all(controlDb, `SELECT * FROM ${source.cache} WHERE scope_id = ? OR scope_id LIKE ?`, tenantId, `${tenantId}:%`)) {
      add(
        statements,
        "INSERT OR IGNORE INTO semantic_cache_policies " +
          "(scope_type, scope_id, enabled, mode, similarity_threshold, ttl_seconds, scoped_models, " +
          "invalidation_epoch, updated_at_unix, updated_by, generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          value(row, "scope_type", "tenant") ?? "tenant",
          value(row, "scope_id", tenantId) ?? tenantId,
          value(row, "enabled"),
          value(row, "mode"),
          value(row, "similarity_threshold"),
          value(row, "ttl_seconds"),
          value(row, "scoped_models"),
          value(row, "invalidation_epoch", 0) ?? 0,
          value(row, "updated_at_unix", nowUnix) ?? nowUnix,
          value(row, "updated_by"),
          value(row, "generation", 0) ?? 0,
        ],
      );
    }
  }

  if (source.revocations !== null) {
    for (const row of await all(controlDb, `SELECT * FROM ${source.revocations} WHERE tenant = ?`, tenantId)) {
      add(
        statements,
        "INSERT OR IGNORE INTO delegation_revocations " +
          "(tenant, subject, reason, revoked_by, revoked_at_unix, expires_at_unix) VALUES (?, ?, ?, ?, ?, ?)",
        [
          tenantId,
          value(row, "subject", "") ?? "",
          value(row, "reason"),
          value(row, "revoked_by"),
          value(row, "revoked_at_unix", nowUnix) ?? nowUnix,
          value(row, "expires_at_unix"),
        ],
      );
    }
  }

  if (source.replayFloors !== null) {
    for (const row of await all(controlDb, `SELECT * FROM ${source.replayFloors} WHERE tenant_id = ?`, tenantId)) {
      add(
        statements,
        "INSERT OR IGNORE INTO control_plane_replay_floors " +
          "(tenant_id, deployment_id, last_accepted_revision, updated_at_unix) VALUES (?, ?, ?, ?)",
        [
          tenantId,
          value(row, "deployment_id", "") ?? "",
          value(row, "last_accepted_revision", 0) ?? 0,
          value(row, "updated_at_unix", nowUnix) ?? nowUnix,
        ],
      );
    }
  }

  if (source.budgetAlerts !== null) {
    for (const row of await all(controlDb, `SELECT * FROM ${source.budgetAlerts} WHERE scope_id = ? OR scope_id LIKE ?`, tenantId, `${tenantId}:%`)) {
      add(
        statements,
        "INSERT OR IGNORE INTO budget_alert_notifications " +
          "(id, tenant_id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          value(row, "id", "") ?? "",
          tenantId,
          value(row, "scope_type", "tenant") ?? "tenant",
          value(row, "scope_id", tenantId) ?? tenantId,
          value(row, "period_month", "") ?? "",
          value(row, "threshold_pct", 0) ?? 0,
          value(row, "notified_at_unix", nowUnix) ?? nowUnix,
        ],
      );
    }
  }

  add(
    statements,
    "INSERT OR IGNORE INTO tenant_provisioning_marks (tenant_id, mark, detail, applied_at_unix) VALUES (?, ?, ?, ?)",
    [tenantId, TENANT_CONFIGURATION_BACKFILL_MARK, JSON.stringify({ source: "control" }), nowUnix],
  );
  await runTenantBatch(router, tenantId, statements);
}
