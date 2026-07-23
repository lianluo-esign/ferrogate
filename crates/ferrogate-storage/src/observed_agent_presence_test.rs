// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: In-memory backend coverage for the durable observed-agent
// presence store (#357): the coalesced upsert folds repeated touches into a
// single (tenant, api_key) row (last_seen = MAX, first_seen = MIN, count bumped
// by one each touch), the window read returns only rows within the recency
// window and honors tenant scope, and a barrier-synchronised concurrency proof
// (no timing sleeps, per AGENTS.md) shows concurrent touches never lose an
// update. Live Postgres is exercised by the SQL contract + the same facade;
// here we prove the semantics deterministically on the memory backend.

use std::sync::{Arc, Barrier};

use crate::schema_routing_test_support::block_on;
use crate::{
    observed_agent_presence_key, ObservedAgentPresenceTouch, RuntimeStorageRepositories,
    StorageProviderKind,
};

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

fn touch(tenant: &str, api_key: &str, seen_at_unix: i64) -> ObservedAgentPresenceTouch {
    ObservedAgentPresenceTouch {
        tenant_id: tenant.to_string(),
        api_key_id: api_key.to_string(),
        seen_at_unix,
    }
}

#[test]
fn repeated_touches_coalesce_into_one_row_with_max_last_seen_and_bumped_count() {
    let repositories = memory_repositories();

    // Deliberately out of order: an older timestamp arrives last. last_seen must
    // stay the MAX and first_seen the MIN regardless of arrival order.
    block_on(repositories.touch_observed_agent_presence(touch("tenant-a", "key-1", 1_000)))
        .expect("first touch");
    block_on(repositories.touch_observed_agent_presence(touch("tenant-a", "key-1", 1_050)))
        .expect("second touch");
    block_on(repositories.touch_observed_agent_presence(touch("tenant-a", "key-1", 1_020)))
        .expect("third (older) touch");

    let rows = block_on(repositories.list_observed_agent_presence_since(Some("tenant-a"), 0))
        .expect("read presence");
    assert_eq!(
        rows.len(),
        1,
        "three touches fold into one (tenant, key) row"
    );
    let row = &rows[0];
    assert_eq!(row.tenant_id, "tenant-a");
    assert_eq!(row.api_key_id, "key-1");
    assert_eq!(
        row.last_seen_at_unix, 1_050,
        "last_seen is the max observed"
    );
    assert_eq!(
        row.first_seen_at_unix, 1_000,
        "first_seen is the min observed"
    );
    assert_eq!(row.request_count, 3, "each touch bumps the coalesced count");
}

#[test]
fn distinct_keys_and_tenants_get_distinct_rows() {
    let repositories = memory_repositories();
    block_on(repositories.touch_observed_agent_presence(touch("tenant-a", "key-1", 1_000)))
        .expect("touch a/1");
    block_on(repositories.touch_observed_agent_presence(touch("tenant-a", "key-2", 1_000)))
        .expect("touch a/2");
    block_on(repositories.touch_observed_agent_presence(touch("tenant-b", "key-1", 1_000)))
        .expect("touch b/1");

    // Cross-tenant (platform operator) view sees all three distinct rows.
    let all = block_on(repositories.list_observed_agent_presence_since(None, 0)).expect("read all");
    assert_eq!(all.len(), 3);

    // Tenant-scoped read isolates one tenant's rows.
    let tenant_a = block_on(repositories.list_observed_agent_presence_since(Some("tenant-a"), 0))
        .expect("read tenant-a");
    assert_eq!(tenant_a.len(), 2);
    assert!(tenant_a.iter().all(|row| row.tenant_id == "tenant-a"));
}

#[test]
fn window_read_returns_only_rows_within_the_recency_window() {
    let repositories = memory_repositories();
    block_on(repositories.touch_observed_agent_presence(touch("tenant-a", "recent", 1_000)))
        .expect("recent touch");
    block_on(repositories.touch_observed_agent_presence(touch("tenant-a", "stale", 500)))
        .expect("stale touch");

    // Window boundary at 900: only the recent row qualifies.
    let within = block_on(repositories.list_observed_agent_presence_since(Some("tenant-a"), 900))
        .expect("windowed read");
    assert_eq!(within.len(), 1);
    assert_eq!(within[0].api_key_id, "recent");

    // A window that includes both timestamps returns both, newest first.
    let both = block_on(repositories.list_observed_agent_presence_since(Some("tenant-a"), 0))
        .expect("full read");
    assert_eq!(both.len(), 2);
    assert_eq!(both[0].api_key_id, "recent", "newest last_seen first");
    assert_eq!(both[1].api_key_id, "stale");

    // Boundary is inclusive: since == last_seen still matches.
    let inclusive =
        block_on(repositories.list_observed_agent_presence_since(Some("tenant-a"), 1_000))
            .expect("inclusive read");
    assert_eq!(inclusive.len(), 1);
    assert_eq!(inclusive[0].api_key_id, "recent");
}

#[test]
fn concurrent_touches_do_not_lose_updates() {
    // Barrier-synchronised (no sleeps): N threads each fire one touch for the
    // SAME (tenant, key) at the same instant. The coalescing upsert is
    // serialized by the control-plane lock, so every touch must be counted --
    // a lost update would leave request_count < N.
    const THREADS: usize = 16;
    let repositories = Arc::new(memory_repositories());
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|index| {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                // Each thread carries a distinct timestamp; the max must win.
                let seen_at = 1_000 + index as i64;
                barrier.wait();
                block_on(
                    repositories.touch_observed_agent_presence(touch("tenant-a", "key-1", seen_at)),
                )
                .expect("concurrent touch");
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("touch thread panicked");
    }

    let rows = block_on(repositories.list_observed_agent_presence_since(Some("tenant-a"), 0))
        .expect("read presence");
    assert_eq!(rows.len(), 1, "all touches fold into a single row");
    assert_eq!(
        rows[0].request_count, THREADS as i64,
        "no touch is lost under concurrency",
    );
    assert_eq!(
        rows[0].last_seen_at_unix,
        1_000 + (THREADS as i64 - 1),
        "the maximum observed timestamp wins",
    );
    assert_eq!(rows[0].first_seen_at_unix, 1_000, "the minimum is retained");
}

#[test]
fn presence_key_is_length_prefixed_and_collision_safe() {
    // The tenant length prefix keeps a crafted tenant/key pair from aliasing a
    // different (tenant, key) -- e.g. ("a", "b:c") must not collide with
    // ("a:b", "c").
    assert_ne!(
        observed_agent_presence_key("a", "b:c"),
        observed_agent_presence_key("a:b", "c"),
    );
    assert_eq!(
        observed_agent_presence_key("tenant", "key"),
        observed_agent_presence_key("tenant", "key"),
    );
}
