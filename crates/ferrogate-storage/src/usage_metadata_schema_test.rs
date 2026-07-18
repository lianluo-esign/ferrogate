// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: DSN-gated schema-routing coverage for the billing/metering
// settlement path (#238). Proves a `usage_metadata_rollups` row written by
// `append_billing_event` lands in the CONFIGURED `postgres_schema`, not the
// connection-default `public` schema, mirroring the #237 replay-floor test.

use crate::{
    PostgresStorageConfig, PostgresTlsMode, RuntimeStorageRepositories, POSTGRES_SCHEMA_SQL,
};
use ferrogate_billing::{BillingEvent, TokenUsage};
use ferrogate_core::TenantContext;

/// Run a batch of setup/teardown SQL against the test DSN over a throwaway
/// connection (helper for the DSN-gated schema-routing test below).
fn run_sql(dsn: &str, sql: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async {
            let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
                .await
                .expect("connect to the test postgres");
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            client
                .batch_execute(sql)
                .await
                .expect("execute test setup/teardown sql");
            drop(client);
            let _ = driver.await;
        });
}

/// Read a single `BIGINT` column from the test DSN, or `None` when no row
/// matches. Used to prove which physical schema the rollup row landed in.
fn query_i64(dsn: &str, sql: &str) -> Option<i64> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async {
            let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
                .await
                .expect("connect to the test postgres");
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let row = client
                .query_opt(sql, &[])
                .await
                .expect("query the usage-metadata-rollup probe row");
            drop(client);
            let _ = driver.await;
            row.map(|row| row.get::<_, i64>(0))
        })
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

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

    // A unique, non-default control schema so the assertion is meaningful and the
    // test never collides with a real deployment schema or a parallel run.
    let schema = format!("ferrogate_usage_metadata_test_{}", std::process::id());
    // Unique metadata key so the `public`-schema negative assertion is
    // unambiguous even if a stale row from another run/table lingers.
    let metadata_key = format!("customer_id_238_{}", std::process::id());
    let metadata_value = "acme-238";

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
        pool_size: 2,
        pool_acquire_timeout_millis: 5_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 5,
        statement_timeout_millis: 5_000,
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

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; \
             DELETE FROM public.usage_metadata_rollups WHERE metadata_key = '{metadata_key}';"
        ),
    );
}
