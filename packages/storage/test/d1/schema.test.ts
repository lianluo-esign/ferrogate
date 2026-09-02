/**
 * Schema-split and column-parity guards for `sql/d1-ts/**` (JOBs 1 and 2).
 *
 * Two things are asserted here that nothing else can catch:
 *
 *  1. **The split is real.** Each table must exist in exactly the database that
 *     owns it. In the Rust tree ONE migration file provisioned both roles, so
 *     every table existed everywhere and a mis-routed write landed silently.
 *     Here a control-only table is absent from tenant databases and vice versa,
 *     which turns that class of routing bug into a loud `no such table`.
 *
 *  2. **Column names are parity.** The Rust column names are the wire contract
 *     with `crates/ferrogate-storage`; a rename would still compile, still
 *     write, and simply stop carrying the value. The expected sets below are
 *     transcribed from `sql/d1/001_init_d1.sql`, so a drift in either direction
 *     fails here rather than in production.
 */
import { env } from "cloudflare:test";
import { beforeAll, describe, expect, test } from "vitest";
import { setupDatabases } from "./harness.js";

beforeAll(async () => {
  await setupDatabases();
});

async function tableNames(db: D1Database): Promise<Set<string>> {
  const result = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
    .all<{ name: string }>();
  return new Set(result.results.map((r) => r.name));
}

async function columnNames(db: D1Database, table: string): Promise<string[]> {
  const result = await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
  return result.results.map((r) => r.name);
}

/** Families that must live ONLY in the control database. */
const CONTROL_ONLY = [
  "tenants",
  "tenant_databases",
  "plans",
  "permissions",
  "roles",
  "admin_users",
  "admin_user_tenant_memberships",
  "admin_user_refresh_tokens",
  "sso_pending_flows",
  "site_domains",
  "site_domain_verifications",
  "control_plane_resources",
  "api_key_directory",
  "static_api_keys",
  "tenant_agent_cost_rollups",
  "tenant_spend_rollups",
  "tenant_asset_rollups",
  // #889: the platform default catalog. These are the control-side twins of
  // the tenant `provider_channels`/`catalog_models`/`catalog_model_offerings`
  // graph, and this list is what proves a tenant database can never contain
  // them — "tenants never see platform rows" held at the schema level.
  "platform_provider_channels",
  "platform_catalog_models",
  "platform_catalog_offerings",
  "platform_catalog_revisions",
  "guardrail_policy_revisions",
  "guardrail_policy_bindings",
  "siem_export_cursors", // 0005
] as const;

/** Retained only as migration input for tenant-object backfill. */
const CONTROL_LEGACY = [
  "tenant_provider_credentials_legacy",
  "sso_provider_configs_legacy",
  "tenant_role_bindings_legacy",
  "semantic_cache_policies_legacy",
  "delegation_revocations_legacy",
  "control_plane_replay_floors_legacy",
  "budget_alert_notifications_legacy",
] as const;

/**
 * Tenant-scoped config being RELOCATED off control into the tenant object
 * (control-D1 removal). The tenant copy is provisioned SCHEMA-FIRST — ahead of
 * the reader/writer switch — so during this window the table exists in BOTH
 * roles: the control copy is still the live one the admission path and the
 * finops writer use, while the tenant copy sits empty until the coordinated
 * cutover points every reader and writer at it. AFTER the cutover these move to
 * TENANT_ONLY and the control copy is dropped. Kept as its own list (neither
 * CONTROL_ONLY nor TENANT_ONLY) so the contract states the in-flight truth
 * rather than a topology that is momentarily false either way.
 *
 *  - `spend_throttles`  — 0010 (control) / 0032 (tenant); the finops auto-throttle.
 *  - `quota_policies`   — 0001 (control) / 0033 (tenant); the effective-quota
 *                         chain read by admission plus the gateway attribution /
 *                         online-eval / residency sources and the finops pass.
 */
const RELOCATING_TO_TENANT = ["spend_throttles", "quota_policies"] as const;

/** Evidence whose authority is tenant-local but whose compatibility projection remains in CONTROL. */
const DERIVED_EVIDENCE = [
  "request_logs",
  "guardrail_evaluations",
  "guardrail_check_evaluations",
  "audit_events",
  "billing_ledger",
  "billing_report_outbox",
  "billing_events",
] as const;

/**
 * Tenant-authoritative evidence whose CONTROL compatibility projection has been
 * DROPPED (Track A red-line): the tenant object is the only copy, every reader
 * fans out over the tenant objects, and no writer mirrors to control any more.
 *
 *  - 0036: the four usage/presence rollups plus the two dead projections.
 *  - 0037: `agent_runs` / `agent_run_events` (agent-runtime stopped mirroring;
 *          the control-plane list + timeline read the tenant objects).
 */
const DROPPED_CONTROL_PROJECTIONS = [
  "usage_aggregate_rollups",
  "usage_monthly_rollups",
  "usage_metadata_rollups",
  "observed_agent_presence",
  "managed_worker_isolation_evidence",
  "online_eval_regressions",
  "agent_runs",
  "agent_run_events",
] as const;

/** Families that must live ONLY in a tenant database. */
const TENANT_ONLY = [
  "projects",
  "workspaces",
  "api_keys",
  "wallets",
  "wallet_reservations",
  "wallet_settlements",
  "payment_methods",
  "tenant_contexts",
  "stored_assets",
  "asset_channels",
  "retention_policies",
  "workflow_run_budgets",
  "agent_schedules",
  "agent_schedule_fires",
  "agent_cost_burn",
  // Created AFTER `0001_init_tenant.sql`; see the note on CONTROL_ONLY. A
  // bundle's file index holds one tenant's paths and R2 keys, so landing it in
  // the control database would be the cross-tenant leak the split prevents.
  "asset_bundle_files", // 0004 (#736)
  // 0008/0009. The legacy one-row model catalog is converted by 0009 into the
  // tenant-qualified logical-model/channel/offering graph. The old table is
  // deliberately absent after the migration; the new graph is what #812 reads.
  "tenant_database_identity",
  "provider_channels",
  "catalog_models",
  "catalog_model_offerings",
  "catalog_audit_outbox",
  "catalog_revisions",
  "tenant_provisioning_marks",
  "tenant_provider_credentials",
  "sso_provider_configs",
  "tenant_role_catalog",
  "tenant_role_bindings",
  "semantic_cache_policies",
  "delegation_revocations",
  "control_plane_replay_floors",
  "budget_alert_notifications",
] as const;

describe("control / tenant split", () => {
  test("every control-only table is present in CONTROL and absent from a TENANT database", async () => {
    const control = await tableNames(env.CONTROL_DB);
    const tenant = await tableNames(env.TENANT_DB_A);
    for (const table of CONTROL_ONLY) {
      expect(control, `${table} must exist in the control database`).toContain(table);
      expect(tenant, `${table} must NOT exist in a tenant database`).not.toContain(table);
    }
  });

  test("derived request evidence is present in both roles", async () => {
    const control = await tableNames(env.CONTROL_DB);
    const tenant = await tableNames(env.TENANT_DB_A);
    for (const table of DERIVED_EVIDENCE) {
      expect(control, `${table} compatibility projection must exist in CONTROL`).toContain(table);
      expect(tenant, `${table} authority must exist in TENANT`).toContain(table);
    }
  });

  test("dropped control projections are absent from CONTROL and authoritative in TENANT", async () => {
    const control = await tableNames(env.CONTROL_DB);
    const tenant = await tableNames(env.TENANT_DB_A);
    for (const table of DROPPED_CONTROL_PROJECTIONS) {
      expect(control, `${table} mirror must be DROPPED from CONTROL`).not.toContain(table);
      expect(tenant, `${table} authority must exist in TENANT`).toContain(table);
    }
  });

  test("config relocating off control exists in both roles during the cutover", async () => {
    const control = await tableNames(env.CONTROL_DB);
    const tenant = await tableNames(env.TENANT_DB_A);
    for (const table of RELOCATING_TO_TENANT) {
      expect(control, `${table} live copy must still exist in CONTROL pre-cutover`).toContain(table);
      expect(tenant, `${table} relocation target must exist in TENANT`).toContain(table);
    }
  });

  test("moved control tables remain only as explicit backfill input", async () => {
    const control = await tableNames(env.CONTROL_DB);
    const tenant = await tableNames(env.TENANT_DB_A);
    for (const table of CONTROL_LEGACY) {
      expect(control, `${table} must remain in CONTROL for backfill`).toContain(table);
      expect(tenant, `${table} must NOT exist in a tenant database`).not.toContain(table);
    }
  });

  test("every tenant-only table is present in a TENANT database and absent from CONTROL", async () => {
    const control = await tableNames(env.CONTROL_DB);
    const tenant = await tableNames(env.TENANT_DB_A);
    for (const table of TENANT_ONLY) {
      expect(tenant, `${table} must exist in a tenant database`).toContain(table);
      expect(control, `${table} must NOT exist in the control database`).not.toContain(table);
    }
  });

  test("retired registries and the legacy catalog are absent from both roles", async () => {
    const control = await tableNames(env.CONTROL_DB);
    const tenant = await tableNames(env.TENANT_DB_A);
    for (const table of ["gateway_providers", "gateway_models", "model_catalog"]) {
      expect(control, `${table} must be retired from the control database`).not.toContain(table);
      expect(tenant, `${table} must be retired from the tenant database`).not.toContain(table);
    }
  });

  test("tenant registry no longer carries retired D1 identity columns", async () => {
    expect(await columnNames(env.CONTROL_DB, "tenant_databases")).toEqual([
      "tenant_id",
      "storage_backend",
      "provisioning_status",
      "schema_version",
      "catalog_seeded_at_unix",
      "last_error",
      "location_hint",
      "binding_name",
      "provisioned_at_unix",
      "updated_at_unix",
      "migration_state",
      "migration_epoch",
      "migration_frozen_at_unix",
      "migration_cutover_at_unix",
      "migration_retention_until_unix",
      "migration_last_error",
      "migration_receipt_json",
      "migration_progress_json",
      "location_hint_source",
      "location_hint_recorded_at_unix",
      "jurisdiction",
    ]);
  });

  test("both roles record their own migration version", async () => {
    const control = await env.CONTROL_DB.prepare(
      "SELECT name FROM storage_schema_migrations WHERE version = 1",
    ).first<{ name: string }>();
    const tenant = await env.TENANT_DB_A.prepare(
      "SELECT name FROM storage_schema_migrations WHERE version = 1",
    ).first<{ name: string }>();
    expect(control?.name).toBe("0001_init_control");
    expect(tenant?.name).toBe("0001_init_tenant");
  });

  test("the default 'free' plan is seeded, with the Rust-era values", async () => {
    const plan = await env.CONTROL_DB.prepare(
      "SELECT id, slug, admin_console_seats, asset_hosting_enabled, " +
        "default_asset_storage_quota_bytes, default_monthly_egress_bytes_budget, mcp_enabled " +
        "FROM plans WHERE id = 'free'",
    ).first<Record<string, number | string>>();
    expect(plan).toMatchObject({
      id: "free",
      slug: "free",
      admin_console_seats: 1,
      asset_hosting_enabled: 1,
      default_asset_storage_quota_bytes: 10_485_760,
      default_monthly_egress_bytes_budget: 104_857_600,
      mcp_enabled: 0,
    });
  });
});

describe("column parity with sql/d1/001_init_d1.sql", () => {
  test("wallets", async () => {
    expect(await columnNames(env.TENANT_DB_A, "wallets")).toEqual([
      "id",
      "tenant_id",
      "balance_credits",
      "auto_recharge_threshold_credits",
      "auto_recharge_amount_credits",
      "dunning",
      "created_at_unix",
      "updated_at_unix",
    ]);
  });

  test("wallet_reservations", async () => {
    expect(await columnNames(env.TENANT_DB_A, "wallet_reservations")).toEqual([
      "id",
      "tenant_id",
      "amount_credits",
      "status",
      "expires_at_unix",
      "settlement_id",
      "created_at_unix",
      "updated_at_unix",
    ]);
  });

  test("wallet_settlements", async () => {
    expect(await columnNames(env.TENANT_DB_A, "wallet_settlements")).toEqual([
      "id",
      "tenant_id",
      "delta_credits",
      "balance_after_credits",
      "created_at_unix",
    ]);
  });

  test("workflow_run_budgets", async () => {
    expect(await columnNames(env.TENANT_DB_A, "workflow_run_budgets")).toEqual([
      "id",
      "workflow_id",
      "workflow_version",
      "run_id",
      "tenant_id",
      "cost_budget_credits",
      "token_budget",
      "tool_call_budget",
      "wall_clock_deadline_unix",
      "spent_credits",
      "spent_tokens",
      "spent_tool_calls",
      "status",
      "created_at_unix",
      "updated_at_unix",
    ]);
  });

  test("api_keys keeps every per-key allowlist/budget column", async () => {
    // `attribution_tags_json` is LAST because `0003_api_key_attribution_tags.sql`
    // (#678) appended it; see the `usage_monthly_rollups` note below for why that
    // position is an assertion and not a formatting accident. Append new columns
    // here in migration order — never insert one alphabetically, and never
    // relax this to `toContain`: both would silently accept an in-place edit of
    // `0001_init_tenant.sql`, which is the drift this test exists to catch.
    expect(await columnNames(env.TENANT_DB_A, "api_keys")).toEqual([
      "id",
      "workspace_id",
      "tenant_id",
      "project_id",
      "name",
      "key_prefix",
      "key_hash",
      "last4",
      "enabled",
      "scopes_json",
      "allowed_models_json",
      "allowed_providers_json",
      "monthly_token_budget",
      "request_limit_per_minute",
      "created_at_unix",
      "updated_at_unix",
      "rotated_at_unix",
      "expires_at_unix",
      "revoked_at_unix",
      "attribution_tags_json",
      "billing_group_id",
    ]);
  });

  test("quota_policies keeps the asset/egress/agent-cost columns", async () => {
    const columns = await columnNames(env.CONTROL_DB, "quota_policies");
    for (const column of [
      "model_allowlist_json",
      "rpm_limit",
      "tpm_limit",
      "monthly_budget_usd",
      "alert_threshold_pcts_json",
      "asset_storage_quota_bytes",
      "monthly_egress_bytes_budget",
      "download_rpm_limit",
      "asset_max_object_bytes",
      "agent_cost_budget_usd",
    ]) {
      expect(columns, `quota_policies.${column}`).toContain(column);
    }
  });

  test("usage_aggregate_rollups", async () => {
    // The other half of `0002_cached_reasoning_tokens.sql` (#667): it appended
    // the same trio to BOTH rollup tables, but only the monthly one was pinned.
    // An unpinned table that a migration already touched is the next stale pin
    // waiting to happen, so the aggregate rollup is now held to the same
    // order-sensitive rule — see the comment on `usage_monthly_rollups`.
    expect(await columnNames(env.TENANT_DB_A, "usage_aggregate_rollups")).toEqual([
      "id",
      "tenant_context_id",
      "logical_model",
      "provider",
      "prompt_tokens",
      "completion_tokens",
      "total_tokens",
      "updated_at_unix",
      "cached_input_tokens",
      "cache_write_tokens",
      "reasoning_tokens",
    ]);
  });

  test("usage_monthly_rollups", async () => {
    // The last three names were APPENDED by `0002_cached_reasoning_tokens.sql`
    // (#667). This list is order-sensitive on purpose, and the order is the
    // evidence: `ALTER TABLE ... ADD COLUMN` appends, so seeing them anywhere
    // but at the end would mean someone edited `0001_init_tenant.sql` in place
    // — which would leave every already-migrated database disagreeing with the
    // committed schema while this test still passed.
    expect(await columnNames(env.TENANT_DB_A, "usage_monthly_rollups")).toEqual([
      "id",
      "period_month",
      "scope_type",
      "scope_id",
      "prompt_tokens",
      "completion_tokens",
      "total_tokens",
      "cost_usd",
      "request_count",
      "error_count",
      "updated_at_unix",
      "cached_input_tokens",
      "cache_write_tokens",
      "reasoning_tokens",
    ]);
  });

  test("observed_agent_presence", async () => {
    expect(await columnNames(env.TENANT_DB_A, "observed_agent_presence")).toEqual([
      "tenant_id",
      "api_key_id",
      "first_seen_at_unix",
      "last_seen_at_unix",
      "request_count",
      "updated_at_unix",
    ]);
  });

  test("agent_cost_burn", async () => {
    expect(await columnNames(env.TENANT_DB_A, "agent_cost_burn")).toEqual([
      "tenant_id",
      "agent_key",
      "period",
      "accumulated_usd",
      "first_seen_unix",
      "updated_at_unix",
    ]);
  });

  test("stored_assets drops ONLY the inline `content` column (documented divergence)", async () => {
    const columns = await columnNames(env.TENANT_DB_A, "stored_assets");
    // Everything the quota-admission guard and the pull path read is retained…
    for (const column of [
      "id",
      "tenant_id",
      "project_id",
      "asset_type",
      "name",
      "version",
      "content_type",
      "content_hash",
      "size_bytes",
      "storage_uri",
      "variant",
      "yanked",
      "visibility",
    ]) {
      expect(columns, `stored_assets.${column}`).toContain(column);
    }
    // …and the base64 inline body is gone, moved to R2 per inventory §1.7.
    expect(columns).not.toContain("content");
  });
});

describe("constraints that are load-bearing, not decorative", () => {
  test("usage_monthly_rollups.scope_type CHECK rejects an unknown scope", async () => {
    await expect(
      env.TENANT_DB_A.prepare(
        "INSERT INTO usage_monthly_rollups (id, period_month, scope_type, scope_id) " +
          "VALUES ('bad', '2026-07', 'organisation', 'x')",
      ).run(),
    ).rejects.toThrow();
  });

  test("admin_user_tenant_memberships.role CHECK rejects an unknown privilege tier", async () => {
    await expect(
      env.CONTROL_DB.prepare(
        "INSERT INTO admin_user_tenant_memberships (id, user_id, tenant_id, role) " +
          "VALUES ('m1', 'u1', 't1', 'superuser')",
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.CONTROL_DB.prepare(
        "INSERT INTO admin_user_tenant_memberships (id, user_id, tenant_id, role) " +
          "VALUES ('m2', 'u1', 't1', 'owner')",
      ).run(),
    ).resolves.toBeDefined();
  });

  test("agent_schedule_fires UNIQUE (schedule_id, slot) is the at-most-once fire gate", async () => {
    const insert = (fireId: string) =>
      env.TENANT_DB_A.prepare(
        "INSERT INTO agent_schedule_fires " +
          "(fire_id, schedule_id, scheduled_fire_at_unix, fired_at_unix, outcome) " +
          "VALUES (?, 'sched_1', 1000, 1000, 'dispatched') ON CONFLICT DO NOTHING",
      )
        .bind(fireId)
        .run();
    await insert("fire_a");
    await insert("fire_b"); // same slot, different fire id — must be swallowed
    const count = await env.TENANT_DB_A.prepare(
      "SELECT COUNT(*) AS n FROM agent_schedule_fires WHERE schedule_id = 'sched_1'",
    ).first<{ n: number }>();
    expect(count?.n).toBe(1);
  });
});
