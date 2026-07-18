// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: DSN-gated schema-routing coverage for the billing/metering
// settlement path (#238). Proves a `usage_metadata_rollups` row written by
// `append_billing_event` lands in the CONFIGURED `postgres_schema`, not the
// connection-default `public` schema, mirroring the #237 replay-floor test.

use crate::schema_routing_test_support::{
    block_on, query_i64, run_sql, serialize_db_test, unique_schema, SchemaGuard,
};
use crate::{
    PostgresStorageConfig, PostgresTlsMode, RuntimeStorageRepositories, POSTGRES_SCHEMA_SQL,
};
use ferrogate_billing::{BillingEvent, TokenUsage};
use ferrogate_core::TenantContext;

/// #238: with a non-default `postgres_schema`, the billing/metering settlement
/// transaction must write `usage_metadata_rollups` (and every other metering /
/// usage / outbox row) to the CONFIGURED schema, not the connection-default
/// `public` schema. This reproduces the same class of misroute #237 fixed for
/// the replay floor: the settlement table exists in both schemas (masking the
/// bug), so the row must land only in the configured schema. Gated on
/// `FERROGATE_TEST_POSTGRES_DSN` (non-TLS local Postgres, like the other
/// DSN-gated storage tests); skips cleanly when unset.
#[test]
fn live_usage_metadata_rollup_writes_to_configured_schema_not_public() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_usage_metadata_rollup_writes_to_configured_schema_not_public: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    // Serialize the DB-touching body against the sibling schema-routing tests so
    // the parallel run never opens a connection storm against the shared pooler.
    let _db = serialize_db_test();

    // A globally-unique, non-default control schema so the assertion is
    // meaningful and the test never collides with a real deployment schema or a
    // sibling test's schema.
    let schema = unique_schema("ferrogate_usage_metadata_test");
    // Unique metadata key so the `public`-schema negative assertion is
    // unambiguous even if a stale row from another run/table lingers.
    let metadata_key = format!("customer_id_238_{schema}");
    let metadata_value = "acme-238";
    // Drop the unique schema + the test's `public` shadow row on scope exit,
    // even if an assertion below panics.
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.usage_metadata_rollups WHERE metadata_key = '{metadata_key}';"
    ));

    // Provision the FULL control-plane schema in the configured schema (so the
    // settlement transaction's metering/usage/tenant tables all exist there),
    // then additionally create `usage_metadata_rollups` in `public`, exactly like
    // a stock-Supabase project where the table's presence in both schemas would
    // mask a misroute. The schema SQL has no `public.`-qualified references, so
    // it lands entirely in the search-path schema we set first.
    run_sql(
        &dsn,
        &format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\";"),
    );
    run_sql(
        &dsn,
        &format!("SET search_path TO \"{schema}\"; {POSTGRES_SCHEMA_SQL}"),
    );
    run_sql(
        &dsn,
        &format!(
            "CREATE TABLE IF NOT EXISTS public.usage_metadata_rollups ( \
                 id TEXT PRIMARY KEY, period_month TEXT NOT NULL, \
                 organization_id TEXT NOT NULL DEFAULT '', metadata_key TEXT NOT NULL, \
                 metadata_value TEXT NOT NULL, prompt_tokens BIGINT NOT NULL DEFAULT 0, \
                 completion_tokens BIGINT NOT NULL DEFAULT 0, total_tokens BIGINT NOT NULL DEFAULT 0, \
                 cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0, request_count BIGINT NOT NULL DEFAULT 0, \
                 error_count BIGINT NOT NULL DEFAULT 0, \
                 updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)); \
             DELETE FROM public.usage_metadata_rollups WHERE metadata_key = '{metadata_key}';"
        ),
    );

    let config = PostgresStorageConfig {
        dsn: dsn.clone(),
        // See `control_plane_schema_test::open_repositories`: generous timeouts +
        // a single connection keep the group hermetic on the shared live DB (#241).
        pool_size: 1,
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
        // Non-default schema, no `public` fallback in the search path: a
        // regression to bare (non-search-path) settlement queries would resolve
        // against the connection-default `public` schema and fail the assertions.
        schema: Some(schema.clone()),
        search_path: Vec::new(),
    };
    let repositories = RuntimeStorageRepositories::postgres_for_migration(config, false, false)
        .expect("open the postgres control plane against the test DSN");

    let tenant = TenantContext {
        organization_id: Some("org-238".into()),
        team_id: None,
        project_id: Some("project-238".into()),
        workspace_id: Some("workspace-238".into()),
        user_id: None,
        api_key_id: Some("key-238".into()),
    };
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert(metadata_key.clone(), metadata_value.to_string());

    let recorded = block_on(repositories.append_billing_event(BillingEvent {
        request_id: "req-238".into(),
        trace_id: None,
        provider_attempt: ferrogate_billing::ProviderAttempt::for_request("req-238", 0),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant,
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: TokenUsage::new(100, 50, 150),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_783_036_800),
        cost_usd: Some(0.01),
        latency_ms: Some(120),
        metadata,
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    }))
    .expect("append billing event must not error");
    assert!(
        recorded,
        "the billing event must be recorded (not a replay)"
    );
    drop(repositories);

    let in_schema = query_i64(
        &dsn,
        &format!(
            "SELECT request_count FROM \"{schema}\".usage_metadata_rollups \
             WHERE metadata_key = '{metadata_key}' AND metadata_value = '{metadata_value}'"
        ),
    );
    assert_eq!(
        in_schema,
        Some(1),
        "the usage-metadata rollup must be persisted in the configured schema",
    );

    let in_public = query_i64(
        &dsn,
        &format!(
            "SELECT request_count FROM public.usage_metadata_rollups \
             WHERE metadata_key = '{metadata_key}'"
        ),
    );
    assert_eq!(
        in_public, None,
        "the usage-metadata rollup must NOT be misrouted to the public schema (#238)",
    );

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}
