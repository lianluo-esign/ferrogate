// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Coverage for the bounded, keyset-paginated tenant listing of
// durable x402 payment attempts (issue #352 acceptance box 6, "reads are
// indexed, tenant-scoped BEFORE pagination"). The boundaries that matter are
// the ones a smaller-than-the-row-count limit and a cursor landing exactly on a
// `created_at_unix` TIE expose -- a limit test with fewer rows than the limit
// proves nothing, and a cursor that carries only the timestamp either skips or
// re-emits a whole tie group.

use crate::schema_routing_test_support::block_on;
use crate::{
    PaymentAttemptCursor, PaymentAttemptQuery, RuntimeStorageRepositories, StorageProviderKind,
    StoredPaymentAttempt, StoredWallet, PAYMENT_ATTEMPT_AUTHORIZED,
    PAYMENT_ATTEMPT_PAGE_DEFAULT_LIMIT, PAYMENT_ATTEMPT_PAGE_MAX_LIMIT,
};

fn repositories_with_wallet(tenant: &str) -> RuntimeStorageRepositories {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    block_on(repositories.upsert_wallet(StoredWallet {
        id: tenant.into(),
        tenant_id: tenant.into(),
        balance_credits: 1_000_000,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
    repositories
}

fn attempt(id: &str, tenant: &str, created_at_unix: i64) -> StoredPaymentAttempt {
    StoredPaymentAttempt {
        id: id.into(),
        tenant_id: tenant.into(),
        project_id: None,
        workspace_id: None,
        run_id: None,
        worker_id: None,
        request_id: None,
        trace_id: None,
        method: "GET".into(),
        resource_url: "https://api.example.com/v1/weather".into(),
        request_body_hash: None,
        challenge_hash: "b".repeat(64),
        x402_version: 2,
        scheme: "exact".into(),
        network_caip2: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".into(),
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
        atomic_amount: "250000".into(),
        recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM".into(),
        credits_amount: Some(250),
        conversion_version: None,
        policy_revision: 7,
        decision: "allow".into(),
        reason_code: "x402_allowed".into(),
        hold_id: None,
        state: PAYMENT_ATTEMPT_AUTHORIZED.into(),
        generation: 0,
        submitted_at_unix: None,
        transaction_signature: None,
        settled_atomic_amount: None,
        settlement_response: None,
        failure_code: None,
        created_at_unix,
        updated_at_unix: created_at_unix,
    }
}

/// Seed `(id, created_at_unix)` pairs for one tenant.
fn seed(repositories: &RuntimeStorageRepositories, tenant: &str, rows: &[(&str, i64)]) {
    for (id, created_at) in rows {
        block_on(repositories.create_payment_attempt(attempt(id, tenant, *created_at))).unwrap();
    }
}

fn page_ids(page: &crate::PaymentAttemptPage) -> Vec<String> {
    page.attempts.iter().map(|a| a.id.clone()).collect()
}

/// Drains the whole listing through the cursor and returns every id, in order.
fn drain_all(repositories: &RuntimeStorageRepositories, tenant: &str, limit: usize) -> Vec<String> {
    let mut query = PaymentAttemptQuery::new(limit);
    let mut ids = Vec::new();
    // Bounded: a cursor that fails to advance would otherwise hang the suite,
    // and hanging is a worse failure report than a count assertion.
    for _ in 0..100 {
        let page = block_on(repositories.list_payment_attempts(tenant, &query)).unwrap();
        assert!(
            page.attempts.len() <= limit,
            "a page must never exceed its limit"
        );
        ids.extend(page_ids(&page));
        match page.next_cursor {
            Some(cursor) => query = PaymentAttemptQuery::new(limit).after(cursor),
            None => return ids,
        }
    }
    panic!("cursor never reached the end of the listing: {ids:?}");
}

/// The boundary the review named: a `limit` SMALLER than the row count. With 7
/// rows and `limit = 3` the first page must be exactly 3 (not 7), and the
/// listing must still drain completely and in order through the cursor.
#[test]
fn a_limit_smaller_than_the_row_count_bounds_the_page_and_still_drains() {
    let repositories = repositories_with_wallet("tenant-a");
    seed(
        &repositories,
        "tenant-a",
        &[
            ("att-1", 100),
            ("att-2", 200),
            ("att-3", 300),
            ("att-4", 400),
            ("att-5", 500),
            ("att-6", 600),
            ("att-7", 700),
        ],
    );

    let first =
        block_on(repositories.list_payment_attempts("tenant-a", &PaymentAttemptQuery::new(3)))
            .unwrap();
    assert_eq!(
        page_ids(&first),
        vec!["att-7", "att-6", "att-5"],
        "the first page must carry exactly `limit` rows, newest-first"
    );
    assert_eq!(
        first.next_cursor,
        Some(PaymentAttemptCursor {
            created_at_unix: 500,
            id: "att-5".into()
        }),
        "the cursor is the LAST row of a full page"
    );

    // Every row exactly once, in the same total order the unbounded read used.
    assert_eq!(
        drain_all(&repositories, "tenant-a", 3),
        vec!["att-7", "att-6", "att-5", "att-4", "att-3", "att-2", "att-1"]
    );
    // And the page size does not change the sequence.
    assert_eq!(
        drain_all(&repositories, "tenant-a", 1),
        drain_all(&repositories, "tenant-a", 3)
    );
}

/// The other boundary the review named: a cursor landing EXACTLY on a
/// `created_at_unix` tie. Five attempts share second 300; `limit = 2` forces the
/// cursor to land in the middle of that tie group twice.
///
/// Drop the `created_at_unix = $2 AND id > $3` arm from the SQL (or the matching
/// arm from the memory twin) and this test goes red: the remaining
/// `created_at_unix < $2` predicate skips the rest of the tie group outright.
#[test]
fn a_cursor_landing_on_a_created_at_tie_neither_skips_nor_repeats() {
    let repositories = repositories_with_wallet("tenant-b");
    seed(
        &repositories,
        "tenant-b",
        &[
            ("att-a", 300),
            ("att-b", 300),
            ("att-c", 300),
            ("att-d", 300),
            ("att-e", 300),
            ("att-newer", 400),
            ("att-older", 200),
        ],
    );

    let drained = drain_all(&repositories, "tenant-b", 2);
    assert_eq!(
        drained,
        vec![
            "att-newer", // 400
            "att-a",
            "att-b",
            "att-c",
            "att-d",
            "att-e",     // the 300 tie group, id-ascending
            "att-older", // 200
        ],
        "the tie group must be traversed exactly once, in the index's own order"
    );

    // Explicitly resume from the middle of the tie group.
    let resumed = block_on(repositories.list_payment_attempts(
        "tenant-b",
        &PaymentAttemptQuery::new(10).after(PaymentAttemptCursor {
            created_at_unix: 300,
            id: "att-c".into(),
        }),
    ))
    .unwrap();
    assert_eq!(
        page_ids(&resumed),
        vec!["att-d", "att-e", "att-older"],
        "resuming mid-tie must return the STRICTLY later ids of the same second, then continue"
    );
}

/// The tenant predicate comes BEFORE the cursor: another tenant's rows can never
/// leak into a page, however the cursor is positioned.
#[test]
fn the_cursor_can_never_widen_a_page_past_its_tenant() {
    let repositories = repositories_with_wallet("tenant-c");
    block_on(repositories.upsert_wallet(StoredWallet {
        id: "tenant-d".into(),
        tenant_id: "tenant-d".into(),
        balance_credits: 1_000,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
    seed(&repositories, "tenant-c", &[("c-1", 300), ("c-2", 200)]);
    seed(&repositories, "tenant-d", &[("d-1", 300), ("d-2", 250)]);

    assert_eq!(drain_all(&repositories, "tenant-c", 1), vec!["c-1", "c-2"]);
    assert_eq!(drain_all(&repositories, "tenant-d", 1), vec!["d-1", "d-2"]);
    // A cursor built from the OTHER tenant's row still only walks this tenant.
    let page = block_on(repositories.list_payment_attempts(
        "tenant-c",
        &PaymentAttemptQuery::new(10).after(PaymentAttemptCursor {
            created_at_unix: 300,
            id: "d-1".into(),
        }),
    ))
    .unwrap();
    assert_eq!(page_ids(&page), vec!["c-2"]);
}

/// A page that fills exactly to `limit` on the LAST row still reports a cursor
/// (the backend cannot know it is the end without a lookahead), and the next
/// page is then definitively empty with `next_cursor = None`. That is the
/// terminating condition a paging client relies on.
#[test]
fn an_exactly_full_final_page_terminates_on_the_following_empty_page() {
    let repositories = repositories_with_wallet("tenant-e");
    seed(&repositories, "tenant-e", &[("e-1", 100), ("e-2", 200)]);

    let page =
        block_on(repositories.list_payment_attempts("tenant-e", &PaymentAttemptQuery::new(2)))
            .unwrap();
    assert_eq!(page_ids(&page), vec!["e-2", "e-1"]);
    let cursor = page
        .next_cursor
        .expect("a full page always offers a cursor");

    let next = block_on(
        repositories.list_payment_attempts("tenant-e", &PaymentAttemptQuery::new(2).after(cursor)),
    )
    .unwrap();
    assert!(next.attempts.is_empty());
    assert_eq!(next.next_cursor, None, "the empty page ends the listing");
}

/// The bound is not optional. `PaymentAttemptQuery::new` clamps, so no caller
/// can construct an unbounded (or zero-sized, which would spin a paging client
/// forever) read.
#[test]
fn the_page_limit_is_clamped_in_both_directions() {
    assert_eq!(PaymentAttemptQuery::new(0).limit(), 1);
    assert_eq!(PaymentAttemptQuery::new(1).limit(), 1);
    assert_eq!(
        PaymentAttemptQuery::new(usize::MAX).limit(),
        PAYMENT_ATTEMPT_PAGE_MAX_LIMIT
    );
    assert_eq!(
        PaymentAttemptQuery::default().limit(),
        PAYMENT_ATTEMPT_PAGE_DEFAULT_LIMIT
    );

    // And the clamp actually bounds a real read.
    let repositories = repositories_with_wallet("tenant-f");
    seed(
        &repositories,
        "tenant-f",
        &[("f-1", 100), ("f-2", 200), ("f-3", 300)],
    );
    let page =
        block_on(repositories.list_payment_attempts("tenant-f", &PaymentAttemptQuery::new(0)))
            .unwrap();
    assert_eq!(page.attempts.len(), 1, "a zero limit is clamped to one row");
}

/// The cursor's wire form round-trips, and a malformed one is refused rather
/// than silently treated as "start over" (which would loop a client forever).
#[test]
fn cursor_encoding_round_trips_and_refuses_malformed_input() {
    let cursor = PaymentAttemptCursor {
        created_at_unix: 1_753_500_000,
        id: "att-1".into(),
    };
    assert_eq!(cursor.encode(), "1753500000:att-1");
    assert_eq!(PaymentAttemptCursor::decode(&cursor.encode()), Some(cursor));

    // An id containing the separator survives the round trip.
    let colonised = PaymentAttemptCursor {
        created_at_unix: 5,
        id: "urn:att:1".into(),
    };
    assert_eq!(
        PaymentAttemptCursor::decode(&colonised.encode()),
        Some(colonised)
    );

    for malformed in ["", "abc", "100", "100:", ":att-1", "not-a-number:att-1"] {
        assert_eq!(
            PaymentAttemptCursor::decode(malformed),
            None,
            "{malformed:?} must be refused, never defaulted to the first page"
        );
    }
}
