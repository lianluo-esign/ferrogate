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
fn schema_contract_includes_latest_replay_floor_migration() {
    assert_eq!(POSTGRES_SCHEMA_VERSION, 36);
    assert_eq!(POSTGRES_SCHEMA_NAME, "036_control_plane_replay_floors");
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (31, '031_mcp_pending_flow_lookup_index')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (32, '032_guardrail_policy_binding_generation')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (33, '033_usage_metadata_rollups_per_tenant')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (34, '034_admin_refresh_token_tenant_scope')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (35, '035_agent_run_audit_index')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (36, '036_control_plane_replay_floors')"));
    assert!(POSTGRES_SCHEMA_SQL.contains(
        "idx_mcp_oauth_flows_pending_subject\n            ON mcp_oauth_flows(tenant_id, workspace_id, user_id, server_name)\n            WHERE consumed_at_unix IS NULL"
    ));
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
