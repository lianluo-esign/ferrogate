// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Backend coverage for custom-domain site bindings (#265):
// in-memory CRUD round-trip + tenant-filtered listing, and a DSN-gated
// live-Postgres test proving writes land in the CONFIGURED schema (#237
// schema-routing pin), not the connection-default `public`.

use std::sync::{Arc, Barrier};

use crate::{
    RuntimeStorageRepositories, StorageError, StorageProviderKind, StoredSiteDomain,
    StoredSiteDomainVerification,
};

use crate::schema_routing_test_support::block_on;

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

/// A fresh current-thread runtime per call: the CAS-race workers below run on
/// raw `std::thread::spawn`, which have no ambient tokio runtime and must not
/// contend on a shared one (mirrors the guardrail-policy CAS test).
fn block_on_local<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("site-domain CAS test runtime")
        .block_on(future)
}

/// A live DNS ownership proof (`verified`, unexpired at `now`) for the holder.
fn live_proof(
    hostname: &str,
    tenant_id: &str,
    site: &str,
    now: i64,
) -> StoredSiteDomainVerification {
    let mut record = StoredSiteDomainVerification::pending(tenant_id, hostname, site, "token", now);
    record.mark_verified(now);
    record
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
// #575: the site-domain claim is a cross-backend conditional write. A bind is a
// security decision, not a read followed by an unrelated upsert -- the write
// itself carries a compare-and-set contract (create-if-absent, same-tenant
// replace, reject a DIFFERENT current tenant). These pin the in-memory backend;
// `control_plane_store_d1_test.rs` pins the identical D1 result, and the
// DSN-gated Postgres race below proves it under a real concurrent engine.
// ---------------------------------------------------------------------------

#[test]
fn claim_site_domain_creates_when_absent() {
    let repositories = memory_repositories();
    let domain = sample_domain("race.example.com", "org_a", "marketing");
    let claimed = block_on(repositories.claim_site_domain(domain.clone())).expect("first claim");
    assert_eq!(claimed, domain);
    assert_eq!(
        block_on(repositories.get_site_domain("race.example.com"))
            .expect("get")
            .expect("present")
            .tenant_id,
        "org_a",
    );
}

#[test]
fn claim_site_domain_same_tenant_replacement_preserves_created_at() {
    let repositories = memory_repositories();
    let original = sample_domain("race.example.com", "org_a", "marketing");
    block_on(repositories.claim_site_domain(original.clone())).expect("first claim");

    // Same tenant re-binds the hostname at a different site and a later clock.
    let mut update = original.clone();
    update.site = "docs".into();
    update.created_at_unix = 9_999; // a caller-supplied value that must be ignored
    update.updated_at_unix = 2_000;
    let claimed = block_on(repositories.claim_site_domain(update)).expect("same-tenant update");
    assert_eq!(claimed.site, "docs");
    assert_eq!(claimed.updated_at_unix, 2_000);
    assert_eq!(
        claimed.created_at_unix, original.created_at_unix,
        "a same-tenant claim preserves the original created_at, never the caller's value",
    );
}

#[test]
fn claim_site_domain_rejects_a_different_tenant() {
    let repositories = memory_repositories();
    block_on(repositories.claim_site_domain(sample_domain("race.example.com", "org_a", "site_a")))
        .expect("first claim");

    let theft = sample_domain("race.example.com", "org_b", "site_b");
    let error = block_on(repositories.claim_site_domain(theft)).expect_err("cross-tenant claim");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "a different current tenant is a typed Conflict (the non-leaking ownership response), \
         got {error:?}",
    );
    // The incumbent row is untouched: the losing write changed nothing.
    let row = block_on(repositories.get_site_domain("race.example.com"))
        .expect("get")
        .expect("present");
    assert_eq!(row.tenant_id, "org_a");
    assert_eq!(row.site, "site_a");
}

/// Acceptance: a stale preflight read cannot authorize the final write. Two
/// tenants both observe NO binding, then race the claim behind a barrier.
/// Exactly one wins; the other's write is rejected even though its preflight
/// read said the hostname was free. Under the pre-#575 unconditional upsert
/// BOTH would "succeed" and the later writer would silently overwrite the
/// earlier owner (last-write-wins theft).
#[test]
fn claim_site_domain_concurrent_race_has_exactly_one_winner() {
    let repositories = Arc::new(memory_repositories());
    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = [("org_a", "site_a"), ("org_b", "site_b")]
        .into_iter()
        .map(|(tenant, site)| {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                // Stale preflight read: the hostname is free from here.
                let preflight = block_on_local(repositories.get_site_domain("race.example.com"))
                    .expect("preflight read");
                assert!(
                    preflight.is_none(),
                    "both racers must observe an absent binding before the write",
                );
                // Release both racers simultaneously so neither ordering is baked in.
                barrier.wait();
                block_on_local(repositories.claim_site_domain(sample_domain(
                    "race.example.com",
                    tenant,
                    site,
                )))
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("claim worker panicked"))
        .collect();

    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one racer may take the hostname",
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StorageError::Conflict(_))))
            .count(),
        1,
        "the loser is a typed Conflict, not a silent overwrite",
    );
    // The stored row belongs to whichever racer won -- and to exactly one of them.
    let winner = results
        .iter()
        .find_map(|result| result.as_ref().ok())
        .expect("a winner");
    let row = block_on(repositories.get_site_domain("race.example.com"))
        .expect("get")
        .expect("present");
    assert_eq!(row.tenant_id, winner.tenant_id);
    assert_eq!(row.site, winner.site);
}

#[test]
fn claim_verified_site_domain_takes_over_a_holder_without_live_proof() {
    let repositories = memory_repositories();
    let now = 5_000;
    // org_a holds the binding but has only a PENDING challenge -- no live proof.
    block_on(repositories.claim_site_domain(sample_domain("race.example.com", "org_a", "site_a")))
        .expect("holder binding");
    block_on(
        repositories.upsert_site_domain_verification(StoredSiteDomainVerification::pending(
            "org_a",
            "race.example.com",
            "site_a",
            "tok",
            now,
        )),
    )
    .expect("holder pending proof");

    // org_b has just proven ownership: verification is allowed to take over an
    // unproven incumbent (#488/#575).
    let claimed = block_on(
        repositories
            .claim_verified_site_domain(sample_domain("race.example.com", "org_b", "site_b"), now),
    )
    .expect("verified takeover of an unproven incumbent");
    assert_eq!(claimed.tenant_id, "org_b");
    assert_eq!(
        block_on(repositories.get_site_domain("race.example.com"))
            .expect("get")
            .expect("present")
            .tenant_id,
        "org_b",
    );
}

#[test]
fn claim_verified_site_domain_rejects_a_holder_with_live_dns_proof() {
    let repositories = memory_repositories();
    let now = 5_000;
    block_on(repositories.claim_site_domain(sample_domain("race.example.com", "org_a", "site_a")))
        .expect("holder binding");
    // org_a holds a LIVE (verified, unexpired) DNS ownership proof.
    block_on(repositories.upsert_site_domain_verification(live_proof(
        "race.example.com",
        "org_a",
        "site_a",
        now,
    )))
    .expect("holder live proof");

    let error = block_on(
        repositories
            .claim_verified_site_domain(sample_domain("race.example.com", "org_b", "site_b"), now),
    )
    .expect_err("cannot take over a holder with a live proof");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "even a freshly verified challenger loses to a holder that ALSO holds a live proof \
         (first-proof-wins, not last-write), got {error:?}",
    );
    let row = block_on(repositories.get_site_domain("race.example.com"))
        .expect("get")
        .expect("present");
    assert_eq!(row.tenant_id, "org_a");
    assert_eq!(row.site, "site_a");
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

/// #575 under a REAL concurrent engine: two tenants race the guarded upsert for
/// one free hostname. The claim is a single `INSERT ... ON CONFLICT DO UPDATE
/// ... WHERE tenant_id = EXCLUDED.tenant_id`, so under READ COMMITTED the row's
/// unique index serializes the two writers -- one INSERTs, the other's
/// ON CONFLICT branch matches its own guard against the NOW-committed foreign
/// tenant and touches nothing (RETURNING yields no row -> `Conflict`). A
/// read-then-write would let both "succeed". Gated on `FERROGATE_TEST_POSTGRES_DSN`;
/// skips cleanly when unset (the dev-lane box has no live DSN).
#[test]
fn live_local_postgres_concurrent_site_domain_claims_have_one_winner() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_local_postgres_concurrent_site_domain_claims_have_one_winner: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_site_domain_cas");
    let hostname = "race-575.example.com";
    let _guard = SchemaGuard::new(&dsn, &schema);

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\"; \
             CREATE TABLE \"{schema}\".site_domains ( \
                 hostname TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, site TEXT NOT NULL, \
                 created_at_unix BIGINT NOT NULL, updated_at_unix BIGINT NOT NULL);"
        ),
    );

    let config = PostgresStorageConfig {
        dsn: dsn.clone(),
        pool_size: 4,
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
        schema: Some(schema.clone()),
        search_path: Vec::new(),
    };
    let repositories = Arc::new(
        RuntimeStorageRepositories::postgres_for_migration(config, false, false)
            .expect("open the postgres control plane against the test DSN"),
    );

    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = [("org_a", "site_a"), ("org_b", "site_b")]
        .into_iter()
        .map(|(tenant, site)| {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                // Both racers observe the hostname free, then claim in lockstep.
                let preflight =
                    block_on_local(repositories.get_site_domain(hostname)).expect("preflight read");
                assert!(
                    preflight.is_none(),
                    "the hostname starts free for both racers"
                );
                barrier.wait();
                block_on_local(
                    repositories.claim_site_domain(sample_domain(hostname, tenant, site)),
                )
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("claim worker panicked"))
        .collect();

    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one tenant may take the hostname under a real concurrent engine",
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StorageError::Conflict(_))))
            .count(),
        1,
        "the loser is a typed Conflict, never a silent last-write-wins overwrite",
    );
    let winner = results
        .iter()
        .find_map(|result| result.as_ref().ok())
        .expect("a winner");
    let stored = block_on(repositories.get_site_domain(hostname))
        .expect("get")
        .expect("present");
    assert_eq!(stored.tenant_id, winner.tenant_id);
    assert_eq!(stored.site, winner.site);
}
