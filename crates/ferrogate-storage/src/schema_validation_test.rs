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
fn schema_contract_includes_latest_guardrail_generation_migration() {
    assert_eq!(POSTGRES_SCHEMA_VERSION, 32);
    assert_eq!(
        POSTGRES_SCHEMA_NAME,
        "032_guardrail_policy_binding_generation"
    );
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (31, '031_mcp_pending_flow_lookup_index')"));
    assert!(POSTGRES_SCHEMA_SQL.contains("VALUES (32, '032_guardrail_policy_binding_generation')"));
    assert!(POSTGRES_SCHEMA_SQL.contains(
        "idx_mcp_oauth_flows_pending_subject\n            ON mcp_oauth_flows(tenant_id, workspace_id, user_id, server_name)\n            WHERE consumed_at_unix IS NULL"
    ));
}
