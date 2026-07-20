// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Backend coverage for custom-domain site bindings (#265):
// in-memory CRUD round-trip + tenant-filtered listing, and a DSN-gated
// live-Postgres test proving writes land in the CONFIGURED schema (#237
// schema-routing pin), not the connection-default `public`.

use crate::{RuntimeStorageRepositories, StorageProviderKind, StoredSiteDomain};

use crate::schema_routing_test_support::block_on;

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

fn sample_domain(hostname: &str, tenant_id: &str, site: &str) -> StoredSiteDomain {
    StoredSiteDomain {
        hostname: hostname.into(),
        tenant_id: tenant_id.into(),
        site: site.into(),
        created_at_unix: 1_000,
        updated_at_unix: 1_000,
    }
}

#[test]
fn in_memory_site_domain_crud_round_trips() {
    let repositories = memory_repositories();
    let domain = sample_domain("mysite.example.com", "org_demo", "marketing");
    block_on(repositories.upsert_site_domain(domain.clone())).expect("bind");

    let fetched = block_on(repositories.get_site_domain("mysite.example.com"))
        .expect("get")
        .expect("binding present");
    assert_eq!(fetched, domain);
    assert!(block_on(repositories.get_site_domain("other.example.com"))
        .expect("get")
        .is_none());

    // Rebinding the same hostname moves it to a new site (upsert semantics).
    let mut rebound = domain.clone();
    rebound.site = "docs".into();
    rebound.updated_at_unix = 2_000;
    block_on(repositories.upsert_site_domain(rebound.clone())).expect("rebind");
    let fetched = block_on(repositories.get_site_domain("mysite.example.com"))
        .expect("get")
        .expect("still present");
    assert_eq!(fetched.site, "docs");
    assert_eq!(fetched.updated_at_unix, 2_000);

    assert!(block_on(repositories.delete_site_domain("mysite.example.com")).expect("unbind"));
    assert!(block_on(repositories.get_site_domain("mysite.example.com"))
        .expect("get")
        .is_none());
    assert!(
        !block_on(repositories.delete_site_domain("mysite.example.com")).expect("unbind"),
        "unbinding a missing hostname reports no row removed",
    );
}

#[test]
fn in_memory_site_domain_listing_filters_by_tenant() {
    let repositories = memory_repositories();
    block_on(repositories.upsert_site_domain(sample_domain(
        "b.example.com",
        "org_demo",
        "marketing",
    )))
    .expect("bind b");
    block_on(repositories.upsert_site_domain(sample_domain("a.example.com", "org_demo", "docs")))
        .expect("bind a");
    block_on(repositories.upsert_site_domain(sample_domain(
        "c.example.org",
        "org_other",
        "landing",
    )))
    .expect("bind c");

    let all = block_on(repositories.list_site_domains(None)).expect("list all");
    assert_eq!(
        all.iter().map(|d| d.hostname.as_str()).collect::<Vec<_>>(),
        vec!["a.example.com", "b.example.com", "c.example.org"],
        "listing is hostname-sorted across tenants",
    );

    let scoped = block_on(repositories.list_site_domains(Some("org_demo"))).expect("list tenant");
    assert_eq!(scoped.len(), 2);
    assert!(scoped.iter().all(|d| d.tenant_id == "org_demo"));

    assert!(
        block_on(repositories.list_site_domains(Some("org_missing")))
            .expect("list missing tenant")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// DSN-gated live-Postgres coverage (#237 schema routing).
// ---------------------------------------------------------------------------

use crate::schema_routing_test_support::{
    query_i64, run_sql, serialize_db_test, unique_schema, SchemaGuard,
};
use crate::{PostgresStorageConfig, PostgresTlsMode};

/// With a non-default `postgres_schema`, site-domain writes must land in the
/// CONFIGURED schema, not the connection-default `public`. Gated on
/// `FERROGATE_TEST_POSTGRES_DSN`; skips cleanly when unset.
#[test]
fn live_site_domain_writes_to_configured_schema() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_site_domain_writes_to_configured_schema: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_site_domain_test");
    let hostname = "bound-265.example.com";
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.site_domains WHERE hostname = '{hostname}';"
    ));

    // Provision the table in BOTH the configured schema and `public`, so a
    // regression to bare (non-search-path) queries would misroute to `public`
    // and fail the negative assertion below.
    let ddl = "CREATE TABLE IF NOT EXISTS {S}.site_domains ( \
             hostname TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, site TEXT NOT NULL, \
             created_at_unix BIGINT NOT NULL, updated_at_unix BIGINT NOT NULL);";
    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\"; {} {}",
            ddl.replace("{S}", &format!("\"{schema}\"")),
            ddl.replace("{S}", "public"),
        ),
    );

    let config = PostgresStorageConfig {
        dsn: dsn.clone(),
        pool_size: 1,
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
        schema: Some(schema.clone()),
        search_path: Vec::new(),
    };
    let repositories = RuntimeStorageRepositories::postgres_for_migration(config, false, false)
        .expect("open the postgres control plane against the test DSN");

    let domain = sample_domain(hostname, "org_demo", "marketing");
    block_on(repositories.upsert_site_domain(domain.clone())).expect("bind");

    let fetched = block_on(repositories.get_site_domain(hostname))
        .expect("get")
        .expect("binding present");
    assert_eq!(fetched, domain);

    let listed = block_on(repositories.list_site_domains(Some("org_demo"))).expect("list");
    assert!(listed.iter().any(|d| d.hostname == hostname));

    assert!(block_on(repositories.delete_site_domain(hostname)).expect("unbind"));
    block_on(repositories.upsert_site_domain(domain.clone())).expect("re-bind for routing probe");
    drop(repositories);

    // The binding lands in the configured schema, not public (#237).
    assert_eq!(
        query_i64(
            &dsn,
            &format!(
                "SELECT count(*) FROM \"{schema}\".site_domains WHERE hostname = '{hostname}'"
            ),
        ),
        Some(1),
    );
    assert_eq!(
        query_i64(
            &dsn,
            &format!("SELECT count(*) FROM public.site_domains WHERE hostname = '{hostname}'"),
        ),
        Some(0),
        "binding must NOT be misrouted to public (#237)",
    );
}
