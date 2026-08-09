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

/** Keep each trusted projection RPC below the D1/DO statement envelope size. */
export const MAX_BACKFILL_STATEMENTS = 100;
const BACKFILL_PAGE_SIZE = 100;

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

async function sourceTable(db: D1Database, legacy: string, active: string): Promise<string | null> {
  if (await tableExists(db, legacy)) return legacy;
  if (await tableExists(db, active)) return active;
  return null;
}

async function sources(db: D1Database): Promise<BackfillSources> {
  const [provider, sso, bindings, cache, revocations, replayFloors, budgetAlerts] =
    await Promise.all([
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
  const rows: Row[] = [];
  for (let offset = 0; ; offset += BACKFILL_PAGE_SIZE) {
    const result = await db
      .prepare(`${sql} LIMIT ? OFFSET ?`)
      .bind(...params, BACKFILL_PAGE_SIZE, offset)
      .all<Row>();
    rows.push(...result.results);
    if (result.results.length < BACKFILL_PAGE_SIZE) return rows;
  }
}

function requiredString(row: Row, key: string, context: string): string {
  const candidate = row[key];
  if (typeof candidate !== "string" || candidate.trim() === "") {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  return candidate;
}

function text(row: Row, key: string, context: string): string {
  const candidate = row[key];
  if (typeof candidate !== "string") {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  return candidate;
}

function nullableString(row: Row, key: string, context: string): string | null {
  const candidate = row[key];
  if (candidate === null) return null;
  if (typeof candidate !== "string") {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  return candidate;
}

function requiredNumber(row: Row, key: string, context: string): number {
  const candidate = row[key];
  if (typeof candidate !== "number" || !Number.isFinite(candidate)) {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  return candidate;
}

function nullableNumber(row: Row, key: string, context: string): number | null {
  const candidate = row[key];
  if (candidate === null) return null;
  if (typeof candidate !== "number" || !Number.isFinite(candidate)) {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  return candidate;
}

function tenantString(row: Row, key: string, tenantId: string, context: string): string {
  const value = requiredString(row, key, context);
  if (value !== tenantId) {
    throw new Error(`tenant configuration backfill found cross-tenant ${context}.${key}`);
  }
  return value;
}

function jsonArray(row: Row, key: string, context: string): string {
  const value = requiredString(row, key, context);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== "string")) {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  return value;
}

function nullableJsonArray(row: Row, key: string, context: string): string | null {
  const value = nullableString(row, key, context);
  if (value === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== "string")) {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  return value;
}

function jsonObject(row: Row, key: string, context: string): string {
  const value = requiredString(row, key, context);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`tenant configuration backfill found invalid ${context}.${key}`);
  }
  return value;
}

function add(
  statements: TenantDataStatement[],
  sql: string,
  params: readonly TenantDataValue[],
): void {
  statements.push({ sql, params });
}

async function runTenantBatch(
  router: TenantDatabaseRouter,
  tenantId: string,
  statements: readonly TenantDataStatement[],
): Promise<void> {
  if (router.privilegedBatch !== undefined) {
    for (let offset = 0; offset < statements.length; offset += MAX_BACKFILL_STATEMENTS) {
      await router.privilegedBatch(
        tenantId,
        statements.slice(offset, offset + MAX_BACKFILL_STATEMENTS),
      );
    }
    return;
  }
  throw new Error(
    `tenant configuration backfill requires the trusted privilegedBatch capability for ${tenantId}`,
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
          tenantString(row, "tenant_id", tenantId, "provider"),
          requiredString(row, "alias", "provider"),
          requiredString(row, "provider", "provider"),
          requiredNumber(row, "key_version", "provider"),
          requiredString(row, "iv", "provider"),
          requiredString(row, "ciphertext", "provider"),
          requiredString(row, "last4", "provider"),
          requiredNumber(row, "created_at_unix", "provider"),
          requiredNumber(row, "rotated_at_unix", "provider"),
          nullableNumber(row, "revoked_at_unix", "provider"),
        ],
      );
    }
  }

  if (source.sso !== null) {
    for (const row of await all(
      controlDb,
      `SELECT * FROM ${source.sso} WHERE tenant_id = ?`,
      tenantId,
    )) {
      add(
        statements,
        "INSERT OR IGNORE INTO sso_provider_configs " +
          "(tenant_id, provider_kind, default_role, group_role_mapping_json, oidc_issuer, oidc_client_id, " +
          "oidc_client_secret_ref, oidc_redirect_uri, oidc_group_claim, saml_idp_entity_id, saml_idp_sso_url, " +
          "saml_idp_certificate, saml_sp_entity_id, saml_acs_url, saml_email_attribute, saml_name_attribute, " +
          "saml_groups_attribute, created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          tenantString(row, "tenant_id", tenantId, "sso"),
          requiredString(row, "provider_kind", "sso"),
          requiredString(row, "default_role", "sso"),
          jsonObject(row, "group_role_mapping_json", "sso"),
          nullableString(row, "oidc_issuer", "sso"),
          nullableString(row, "oidc_client_id", "sso"),
          nullableString(row, "oidc_client_secret_ref", "sso"),
          nullableString(row, "oidc_redirect_uri", "sso"),
          nullableString(row, "oidc_group_claim", "sso"),
          nullableString(row, "saml_idp_entity_id", "sso"),
          nullableString(row, "saml_idp_sso_url", "sso"),
          nullableString(row, "saml_idp_certificate", "sso"),
          nullableString(row, "saml_sp_entity_id", "sso"),
          nullableString(row, "saml_acs_url", "sso"),
          nullableString(row, "saml_email_attribute", "sso"),
          nullableString(row, "saml_name_attribute", "sso"),
          nullableString(row, "saml_groups_attribute", "sso"),
          requiredNumber(row, "created_at_unix", "sso"),
          requiredNumber(row, "updated_at_unix", "sso"),
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
          requiredString(row, "role_id", "binding"),
          requiredString(row, "name", "binding"),
          requiredString(row, "slug", "binding"),
          text(row, "description", "binding"),
          jsonArray(row, "permission_keys_json", "binding"),
          requiredNumber(row, "role_created_at_unix", "binding"),
          requiredNumber(row, "role_updated_at_unix", "binding"),
        ],
      );
      add(
        statements,
        "INSERT OR IGNORE INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) VALUES (?, ?, ?, ?)",
        [
          requiredString(row, "id", "binding"),
          tenantString(row, "tenant_id", tenantId, "binding"),
          requiredString(row, "role_id", "binding"),
          requiredNumber(row, "created_at_unix", "binding"),
        ],
      );
    }
  }

  if (source.cache !== null) {
    for (const row of await all(
      controlDb,
      `SELECT * FROM ${source.cache} WHERE scope_id = ? OR scope_id LIKE ?`,
      tenantId,
      `${tenantId}:%`,
    )) {
      add(
        statements,
        "INSERT OR IGNORE INTO semantic_cache_policies " +
          "(scope_type, scope_id, enabled, mode, similarity_threshold, ttl_seconds, scoped_models, " +
          "invalidation_epoch, updated_at_unix, updated_by, generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          requiredString(row, "scope_type", "cache"),
          requiredString(row, "scope_id", "cache"),
          nullableNumber(row, "enabled", "cache"),
          nullableString(row, "mode", "cache"),
          nullableNumber(row, "similarity_threshold", "cache"),
          nullableNumber(row, "ttl_seconds", "cache"),
          nullableJsonArray(row, "scoped_models", "cache"),
          requiredNumber(row, "invalidation_epoch", "cache"),
          requiredNumber(row, "updated_at_unix", "cache"),
          nullableString(row, "updated_by", "cache"),
          requiredNumber(row, "generation", "cache"),
        ],
      );
    }
  }

  if (source.revocations !== null) {
    for (const row of await all(
      controlDb,
      `SELECT * FROM ${source.revocations} WHERE tenant = ?`,
      tenantId,
    )) {
      add(
        statements,
        "INSERT OR IGNORE INTO delegation_revocations " +
          "(tenant, subject, reason, revoked_by, revoked_at_unix, expires_at_unix) VALUES (?, ?, ?, ?, ?, ?)",
        [
          tenantString(row, "tenant", tenantId, "revocation"),
          requiredString(row, "subject", "revocation"),
          nullableString(row, "reason", "revocation"),
          nullableString(row, "revoked_by", "revocation"),
          requiredNumber(row, "revoked_at_unix", "revocation"),
          nullableNumber(row, "expires_at_unix", "revocation"),
        ],
      );
    }
  }

  if (source.replayFloors !== null) {
    for (const row of await all(
      controlDb,
      `SELECT * FROM ${source.replayFloors} WHERE tenant_id = ?`,
      tenantId,
    )) {
      add(
        statements,
        "INSERT OR IGNORE INTO control_plane_replay_floors " +
          "(tenant_id, deployment_id, last_accepted_revision, updated_at_unix) VALUES (?, ?, ?, ?)",
        [
          tenantString(row, "tenant_id", tenantId, "replay_floor"),
          requiredString(row, "deployment_id", "replay_floor"),
          requiredNumber(row, "last_accepted_revision", "replay_floor"),
          requiredNumber(row, "updated_at_unix", "replay_floor"),
        ],
      );
    }
  }

  if (source.budgetAlerts !== null) {
    for (const row of await all(
      controlDb,
      `SELECT * FROM ${source.budgetAlerts} WHERE scope_id = ? OR scope_id LIKE ?`,
      tenantId,
      `${tenantId}:%`,
    )) {
      add(
        statements,
        "INSERT OR IGNORE INTO budget_alert_notifications " +
          "(id, tenant_id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          requiredString(row, "id", "budget_alert"),
          tenantId,
          requiredString(row, "scope_type", "budget_alert"),
          requiredString(row, "scope_id", "budget_alert"),
          requiredString(row, "period_month", "budget_alert"),
          requiredNumber(row, "threshold_pct", "budget_alert"),
          requiredNumber(row, "notified_at_unix", "budget_alert"),
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
