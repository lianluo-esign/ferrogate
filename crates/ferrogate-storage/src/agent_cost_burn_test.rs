// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: In-memory backend coverage for the durable per-agent cost-burn
// ledger (#428, slice B-storage): add_agent_burn folds each delta into the
// single (tenant, agent, period) row and returns the running total, distinct
// (tenant, agent, period) triples accumulate independently, get_agent_burn is
// None for an unrecorded key, and a barrier-synchronised concurrency proof (no
// timing sleeps, per AGENTS.md) shows concurrent adds for one key never lose an
// increment. Live Postgres is exercised by the SQL contract (the atomic
// `ON CONFLICT ... DO UPDATE SET accumulated_usd = ... + EXCLUDED ... RETURNING`
// upsert) + the same facade; here we prove the semantics deterministically on
// the memory backend, which serializes under the control-plane lock exactly as
// the Postgres upsert serializes under the row lock.

use std::sync::{Arc, Barrier};

use crate::schema_routing_test_support::block_on;
use crate::{agent_cost_burn_key, RuntimeStorageRepositories, StorageProviderKind};

const EPSILON: f64 = 1e-9;

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

fn assert_close(actual: f64, expected: f64, context: &str) {
    assert!(
        (actual - expected).abs() < EPSILON,
        "{context}: expected {expected}, got {actual}",
    );
}

#[test]
fn adds_accumulate_and_return_the_running_total() {
    let repositories = memory_repositories();

    let after_first = block_on(repositories.add_agent_burn("tenant-a", "agent-1", "2026-07", 0.10))
        .expect("first add");
    assert_close(
        after_first,
        0.10,
        "first add returns its own delta as the total",
    );

    let after_second =
        block_on(repositories.add_agent_burn("tenant-a", "agent-1", "2026-07", 0.15))
            .expect("second add");
    assert_close(
        after_second,
        0.25,
        "second add returns the folded running total",
    );

    let read = block_on(repositories.get_agent_burn("tenant-a", "agent-1", "2026-07"))
        .expect("read burn")
        .expect("row exists after two adds");
    assert_close(read, 0.25, "get returns the accumulated total");
}

#[test]
fn distinct_agents_and_periods_accumulate_independently() {
    let repositories = memory_repositories();
    block_on(repositories.add_agent_burn("tenant-a", "agent-1", "2026-07", 1.0)).expect("a1/jul");
    block_on(repositories.add_agent_burn("tenant-a", "agent-2", "2026-07", 2.0)).expect("a2/jul");
    block_on(repositories.add_agent_burn("tenant-a", "agent-1", "2026-08", 4.0)).expect("a1/aug");
    block_on(repositories.add_agent_burn("tenant-b", "agent-1", "2026-07", 8.0)).expect("b1/jul");

    // Each (tenant, agent, period) triple is its own accumulator -- no bleed.
    assert_close(
        block_on(repositories.get_agent_burn("tenant-a", "agent-1", "2026-07"))
            .expect("read")
            .expect("row"),
        1.0,
        "agent-1 July burn is isolated from agent-2 and August",
    );
    assert_close(
        block_on(repositories.get_agent_burn("tenant-a", "agent-2", "2026-07"))
            .expect("read")
            .expect("row"),
        2.0,
        "agent-2 July burn",
    );
    assert_close(
        block_on(repositories.get_agent_burn("tenant-a", "agent-1", "2026-08"))
            .expect("read")
            .expect("row"),
        4.0,
        "agent-1 August burn is a separate period accumulator",
    );
    assert_close(
        block_on(repositories.get_agent_burn("tenant-b", "agent-1", "2026-07"))
            .expect("read")
            .expect("row"),
        8.0,
        "tenant-b is isolated from tenant-a",
    );
}

#[test]
fn get_is_none_for_an_unrecorded_key() {
    let repositories = memory_repositories();
    block_on(repositories.add_agent_burn("tenant-a", "agent-1", "2026-07", 1.0)).expect("seed");

    // Same tenant/agent, different period; and a wholly unseen key.
    assert!(
        block_on(repositories.get_agent_burn("tenant-a", "agent-1", "2026-08"))
            .expect("read")
            .is_none(),
        "an un-added period reads as None, never a fabricated zero",
    );
    assert!(
        block_on(repositories.get_agent_burn("tenant-z", "agent-9", "2026-07"))
            .expect("read")
            .is_none(),
        "a wholly unrecorded key reads as None",
    );
}

#[test]
fn concurrent_adds_never_lose_an_increment() {
    // Barrier-synchronised (no sleeps): N threads each add exactly 1.0 to the
    // SAME (tenant, agent, period) at the same instant. The accumulate is
    // serialized by the control-plane lock (the memory analogue of the Postgres
    // row-locked ON CONFLICT upsert), so the final total must be exactly N -- a
    // lost update would leave it < N. Each add also returns a post-add running
    // total; with perfect serialization those returns are exactly {1.0 .. N},
    // so their max is N.
    const THREADS: usize = 16;
    let repositories = Arc::new(memory_repositories());
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                block_on(repositories.add_agent_burn("tenant-a", "agent-1", "2026-07", 1.0))
                    .expect("concurrent add")
            })
        })
        .collect();
    let returned: Vec<f64> = handles
        .into_iter()
        .map(|handle| handle.join().expect("add thread panicked"))
        .collect();

    let final_total = block_on(repositories.get_agent_burn("tenant-a", "agent-1", "2026-07"))
        .expect("read")
        .expect("row exists");
    assert_close(
        final_total,
        THREADS as f64,
        "every concurrent add is counted -- no lost updates",
    );

    let max_returned = returned.iter().cloned().fold(0.0_f64, f64::max);
    assert_close(
        max_returned,
        THREADS as f64,
        "the last add to acquire the lock sees the full accumulated total",
    );
}

#[test]
fn list_agent_cost_burn_is_tenant_scoped_period_filtered_and_total_ordered() {
    let repositories = memory_repositories();
    // Two tenants, two periods, several agents.
    block_on(repositories.add_agent_burn("tenant-a", "agent-1", "2026-07", 3.0)).expect("a1/jul");
    block_on(repositories.add_agent_burn("tenant-a", "agent-2", "2026-07", 9.0)).expect("a2/jul");
    block_on(repositories.add_agent_burn("tenant-a", "agent-1", "2026-08", 5.0)).expect("a1/aug");
    block_on(repositories.add_agent_burn("tenant-b", "agent-9", "2026-07", 100.0)).expect("b9/jul");

    // Tenant-scoped read: only tenant-a's July rows, biggest total first.
    let scoped = block_on(repositories.list_agent_cost_burn(Some("tenant-a"), "2026-07"))
        .expect("scoped list");
    assert_eq!(scoped.len(), 2, "only tenant-a's July rows");
    assert!(
        scoped.iter().all(|row| row.tenant_id == "tenant-a"),
        "RBAC no-leak: a tenant-scoped list never returns another tenant's burn",
    );
    assert_eq!(scoped[0].agent_key, "agent-2", "biggest accumulated first");
    assert_close(scoped[0].accumulated_usd, 9.0, "agent-2 total");
    assert_eq!(scoped[1].agent_key, "agent-1");
    assert_close(scoped[1].accumulated_usd, 3.0, "agent-1 total");

    // Period isolation: August is a separate accumulator window.
    let august = block_on(repositories.list_agent_cost_burn(Some("tenant-a"), "2026-08"))
        .expect("august list");
    assert_eq!(august.len(), 1);
    assert_eq!(august[0].period, "2026-08");
    assert_close(august[0].accumulated_usd, 5.0, "agent-1 August total");

    // Operator (None scope): the cross-tenant July view, tenant-b's 100 first.
    let operator =
        block_on(repositories.list_agent_cost_burn(None, "2026-07")).expect("operator list");
    assert_eq!(operator.len(), 3, "both tenants' July rows");
    assert_eq!(
        operator[0].tenant_id, "tenant-b",
        "biggest total across tenants"
    );
    assert_close(operator[0].accumulated_usd, 100.0, "tenant-b total");

    // A period with no rows lists empty (never a fabricated row).
    let empty = block_on(repositories.list_agent_cost_burn(Some("tenant-a"), "2026-01"))
        .expect("empty list");
    assert!(empty.is_empty(), "an un-burned period lists no rows");
}

#[test]
fn burn_key_is_length_prefixed_and_collision_safe() {
    // The length prefix on each variable segment keeps a crafted triple from
    // aliasing another -- e.g. ("a", "b", "c:d") must not collide with
    // ("a", "b:c", "d").
    assert_ne!(
        agent_cost_burn_key("a", "b", "c:d"),
        agent_cost_burn_key("a", "b:c", "d"),
    );
    assert_ne!(
        agent_cost_burn_key("tenant", "agent", "2026-07"),
        agent_cost_burn_key("tenant", "agent", "2026-08"),
    );
    assert_eq!(
        agent_cost_burn_key("tenant", "agent", "2026-07"),
        agent_cost_burn_key("tenant", "agent", "2026-07"),
    );
}
