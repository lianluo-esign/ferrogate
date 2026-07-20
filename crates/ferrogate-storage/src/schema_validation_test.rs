// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Focused schema-contract query regression coverage for issue #213.

use super::{
    POSTGRES_SCHEMA_NAME, POSTGRES_SCHEMA_SQL, POSTGRES_SCHEMA_VERSION,
    PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_QUERY,
};

#[test]
fn provider_attempt_foreign_key_query_uses_the_declared_constraint_alias() {
    assert!(PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_QUERY.contains("pg_constraint AS con"));
    assert!(PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_QUERY.contains("con.confdeltype::text"));
    assert!(!PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_QUERY.contains("constraint."));
}

#[test]
fn provider_attempt_foreign_key_query_rejects_same_named_tables_in_other_schemas() {
    assert!(PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_QUERY
        .contains("JOIN pg_namespace AS target_namespace"));
    assert!(PROVIDER_ATTEMPT_FOREIGN_KEY_VALIDATION_QUERY
        .contains("target_namespace.nspname = current_schema()"));
}

// (Removed `authoritative_reread_transport_caps_connect_and_tcp_user_timeouts`:
// it exercised the sync `postgres_transport_config`, deleted in #221's final
// slice. The same connect/tcp_user timeout capping now lives in
// `AsyncPostgresPool::new` (`pg_config.connect_timeout` / `tcp_user_timeout`).)

#[test]
fn schema_contract_includes_latest_asset_egress_migration() {
    assert_eq!(POSTGRES_SCHEMA_VERSION, 48);
    assert_eq!(POSTGRES_SCHEMA_NAME, "048_handoff_parent_identity");
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (31, '031_mcp_pending_flow_lookup_index')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (32, '032_guardrail_policy_binding_generation')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (33, '033_usage_metadata_rollups_per_tenant')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (34, '034_admin_refresh_token_tenant_scope')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (35, '035_agent_run_audit_index')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (36, '036_control_plane_replay_floors')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (37, '037_agent_schedules')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (38, '038_asset_registry_semantics')"));
    // #262: asset egress governance columns + migration (039, after #260's 038).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (39, '039_asset_egress_quota')"));
    // #281: durable wallet reserve/hold primitive (040, after #262's 039).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (40, '040_wallet_reservations')"));
    // #279: workflow-graph-level execution budgets (041, after #281's 040).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (42, '042_workflow_run_budgets')"));
    // #263: asset lifecycle retention policies (043, after #279's 042).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (43, '043_retention_policies')"));
    // #265: static-site custom-domain bindings (044, after #263's 043).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (44, '044_site_domains')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS site_domains"));
    // #304: action-identity projection columns on timeline/audit rows (045).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (45, '045_action_identity')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ALTER TABLE agent_run_events"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ALTER TABLE audit_events"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS action_fingerprint TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS decision TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS decision_reason TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS output_disposition TEXT"));
    // #305: correlation keys on the self-hosted dispatch queue (046).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (46, '046_dispatch_correlation')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ALTER TABLE self_hosted_run_dispatches"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS request_id TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS trace_id TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS agent_run_id TEXT"));
    // #306: shared action identity + stored canonical decisions on guardrail
    // evidence rows (047).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (47, '047_guardrail_action_identity')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ALTER TABLE guardrail_evaluations"));
    // #307: downstream handoff parent identity on the dispatch queue (048).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (48, '048_handoff_parent_identity')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS parent_action_fingerprint TEXT"));
    assert!(
        POSTGRES_SCHEMA_SQL.contains("monthly_egress_bytes_budget BIGINT")
            && POSTGRES_SCHEMA_SQL.contains("default_download_rpm_limit BIGINT")
    );
    // #283: durable per-tenant SSO config + restart-safe pending flows (040).
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (41, '041_tenant_sso_config')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS sso_provider_configs"));
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS sso_pending_flows"));
    // OIDC client secrets are persisted only as a secret_ref URI, never plaintext.
    assert!(POSTGRES_SCHEMA_SQL.contains("oidc_client_secret_ref TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("saml_idp_certificate TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains(
        "idx_mcp_oauth_flows_pending_subject\n            ON mcp_oauth_flows(tenant_id, workspace_id, user_id, server_name)\n            WHERE consumed_at_unix IS NULL"
    ));
}

#[test]
fn schema_contract_defines_the_asset_registry_tables() {
    // #260: platform/arch variants + cargo-style yank on stored_assets, plus
    // mutable channel pointers. The variant-widened UNIQUE lets one logical
    // version carry several per-triple artifacts.
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS asset_channels"));
    assert!(
        POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS variant TEXT NOT NULL DEFAULT ''")
    );
    assert!(POSTGRES_SCHEMA_SQL
        .contains("ADD COLUMN IF NOT EXISTS yanked BOOLEAN NOT NULL DEFAULT FALSE"));
    assert!(POSTGRES_SCHEMA_SQL.contains("UNIQUE (tenant_id, asset_type, name, version, variant)"));
    // #254: the constraint over the migration-added `variant` column must come
    // after the ADD COLUMN in the SQL text, never before.
    let add_variant = POSTGRES_SCHEMA_SQL
        .find("ADD COLUMN IF NOT EXISTS variant TEXT")
        .expect("variant ADD COLUMN present");
    let add_constraint = POSTGRES_SCHEMA_SQL
        .find("stored_assets_tenant_type_name_version_variant_key")
        .expect("variant-widened UNIQUE present");
    assert!(
        add_variant < add_constraint,
        "the variant-widened UNIQUE must come after its ADD COLUMN"
    );
}

#[test]
fn schema_contract_defines_the_wallet_reservations_table() {
    // #281: durable reserve/hold rows for exact-amount, irreversible spends.
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS wallet_reservations"));
    assert!(POSTGRES_SCHEMA_SQL.contains("idx_wallet_reservations_tenant_status"));
    assert!(POSTGRES_SCHEMA_SQL.contains("idx_wallet_reservations_active_expiry"));
    // #254: any CREATE INDEX over the table must come after the CREATE TABLE
    // that defines its columns, never before.
    let create_table = POSTGRES_SCHEMA_SQL
        .find("CREATE TABLE IF NOT EXISTS wallet_reservations")
        .expect("wallet_reservations table present");
    let create_index = POSTGRES_SCHEMA_SQL
        .find("idx_wallet_reservations_active_expiry")
        .expect("wallet_reservations expiry index present");
    assert!(
        create_table < create_index,
        "wallet_reservations indexes must come after the CREATE TABLE"
    );
}

#[test]
fn schema_contract_defines_the_workflow_run_budgets_table() {
    // #279: durable per-workflow-run execution budget ledger.
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS workflow_run_budgets"));
    assert!(POSTGRES_SCHEMA_SQL.contains("idx_workflow_run_budgets_tenant"));
    // #254: the CREATE INDEX must come after the CREATE TABLE that defines its
    // columns, never before.
    let create_table = POSTGRES_SCHEMA_SQL
        .find("CREATE TABLE IF NOT EXISTS workflow_run_budgets")
        .expect("workflow_run_budgets table present");
    let create_index = POSTGRES_SCHEMA_SQL
        .find("idx_workflow_run_budgets_tenant")
        .expect("workflow_run_budgets tenant index present");
    assert!(
        create_table < create_index,
        "workflow_run_budgets index must come after the CREATE TABLE"
    );
}

#[test]
fn schema_contract_defines_the_retention_policies_table() {
    // #263: generalizable retention-rule shape (not hard-coded to assets) +
    // its per-(tenant, resource_type) listing index. Per #254 the CREATE INDEX
    // must come after the CREATE TABLE that defines its columns.
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS retention_policies"));
    assert!(POSTGRES_SCHEMA_SQL.contains("idx_retention_policies_tenant_resource"));
    assert!(POSTGRES_SCHEMA_SQL.contains("keep_last_n BIGINT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("max_age_secs BIGINT"));
    let create_table = POSTGRES_SCHEMA_SQL
        .find("CREATE TABLE IF NOT EXISTS retention_policies")
        .expect("retention_policies table present");
    let create_index = POSTGRES_SCHEMA_SQL
        .find("CREATE INDEX IF NOT EXISTS idx_retention_policies_tenant_resource")
        .expect("retention_policies index present");
    assert!(
        create_table < create_index,
        "retention_policies index must come after the CREATE TABLE"
    );
}

#[test]
fn schema_contract_defines_the_agent_schedule_tables() {
    // #246: schedule definitions + idempotent fire-history ledger. The UNIQUE
    // (schedule_id, scheduled_fire_at_unix) constraint is the at-most-once
    // firing gate for multi-instance deployments.
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS agent_schedules"));
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS agent_schedule_fires"));
    assert!(POSTGRES_SCHEMA_SQL.contains("UNIQUE (schedule_id, scheduled_fire_at_unix)"));
    assert!(POSTGRES_SCHEMA_SQL.contains("idx_agent_schedules_due"));
}

#[test]
fn schema_contract_tenant_scopes_admin_refresh_tokens() {
    // #232: refresh tokens carry the tenant/role their session was issued
    // for, both on fresh installs (CREATE TABLE) and legacy databases
    // (ALTER TABLE ADD COLUMN IF NOT EXISTS).
    assert!(POSTGRES_SCHEMA_SQL.contains("ALTER TABLE admin_user_refresh_tokens"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS tenant_id TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("ADD COLUMN IF NOT EXISTS role TEXT"));
    assert!(POSTGRES_SCHEMA_SQL.contains("idx_admin_user_refresh_tokens_user_tenant"));
}

#[test]
fn schema_contract_defines_the_signed_snapshot_replay_floor_table() {
    // #206: the durable replay floor keyed by (tenant_id, deployment_id).
    assert!(POSTGRES_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS control_plane_replay_floors"));
    assert!(POSTGRES_SCHEMA_SQL.contains("last_accepted_revision BIGINT NOT NULL"));
    assert!(POSTGRES_SCHEMA_SQL.contains("PRIMARY KEY (tenant_id, deployment_id)"));
}

#[test]
fn upgrade_indexes_come_after_the_migration_that_adds_their_column() {
    // #254: on an UPGRADE the table already exists (CREATE TABLE IF NOT EXISTS is a
    // no-op), so a `CREATE INDEX ... (col)` over a column added by a later
    // `ALTER TABLE ... ADD COLUMN col` fails "column does not exist" and aborts
    // initialize_schema. The ADD COLUMN must therefore appear BEFORE any index that
    // references that migration-added column. Regression guard for the two cases
    // that broke migrating a real ferrogate_control that predated these columns.
    let cases = [
        (
            "ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''",
            "idx_usage_metadata_rollups_org_key",
        ),
        (
            "ADD COLUMN IF NOT EXISTS identity_expires_at_unix BIGINT",
            "idx_self_hosted_worker_registrations_identity_expiry",
        ),
    ];
    for (add_column, index_name) in cases {
        let add_at = POSTGRES_SCHEMA_SQL
            .find(add_column)
            .unwrap_or_else(|| panic!("schema must contain `{add_column}`"));
        // Match the actual CREATE statement, not a mention in a comment.
        let create_index = format!("CREATE INDEX IF NOT EXISTS {index_name}");
        let index_at = POSTGRES_SCHEMA_SQL
            .find(&create_index)
            .unwrap_or_else(|| panic!("schema must contain `{create_index}`"));
        assert!(
            add_at < index_at,
            "`{add_column}` (@{add_at}) must precede index `{index_name}` (@{index_at}) so the \
             upgrade path does not build the index over a not-yet-existent column (#254)",
        );
    }
}
