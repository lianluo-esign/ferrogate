// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: CAS dead-letter replay coverage for the billing outbox (issue
// #388): a dead-lettered row transitions back to pending exactly once, a
// non-dead-lettered / missing row is rejected fail-closed, and concurrent
// replays of the same row resolve to a single winner behind a barrier.

use std::sync::{Arc, Barrier};

use super::{ReplayDeadLetterOutcome, RuntimeStorageRepositories};

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(Vec::new(), 0, 0)
}

fn billing_event(request_id: &str, tenant: &str) -> ferrogate_billing::BillingEvent {
    ferrogate_billing::BillingEvent {
        request_id: request_id.into(),
        trace_id: Some(format!("trace-{request_id}")),
        provider_attempt: ferrogate_billing::ProviderAttempt::for_request(request_id, 0),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext {
            organization_id: Some(tenant.into()),
            ..ferrogate_core::TenantContext::default()
        },
        logical_model: "chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: ferrogate_billing::TokenUsage::new(1, 1, 2),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: Some(0.000_01),
        latency_ms: Some(3),
        metadata: std::collections::BTreeMap::new(),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    }
}

#[test]
fn replay_re_enqueues_a_dead_lettered_report_and_clears_the_mark() {
    let repositories = repositories();
    let id = "report-dead";
    block_on(repositories.enqueue_billing_report(id, &billing_event(id, "tenant-a"), 100)).unwrap();
    block_on(repositories.dead_letter_billing_report(id, 200)).unwrap();

    // Precondition: dead-lettered rows are excluded from the due list.
    let due = block_on(repositories.list_due_billing_reports(1_000, 10)).unwrap();
    assert!(
        due.is_empty(),
        "dead-lettered row must not be due, got {due:?}"
    );

    let outcome = block_on(repositories.replay_dead_lettered_billing_report(id, 500)).unwrap();
    let entry = match outcome {
        ReplayDeadLetterOutcome::Replayed(entry) => entry,
        other => panic!("expected Replayed, got {other:?}"),
    };
    assert_eq!(entry.id, id);
    assert_eq!(
        entry.dead_lettered_at_unix, None,
        "replay must clear the mark"
    );
    assert_eq!(entry.attempts, 0, "replay must reset the attempt counter");
    assert_eq!(entry.next_attempt_unix, 500);

    // The row is now redeliverable: it reappears in the due list.
    let due = block_on(repositories.list_due_billing_reports(1_000, 10)).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].id, id);
    assert!(due[0].dead_lettered_at_unix.is_none());

    // And it is no longer dead-lettered.
    let dead = block_on(repositories.list_dead_lettered_billing_reports(10)).unwrap();
    assert!(
        dead.is_empty(),
        "row must leave the dead-letter set, got {dead:?}"
    );
}

#[test]
fn replaying_a_non_dead_lettered_report_is_rejected_fail_closed() {
    let repositories = repositories();
    let id = "report-live";
    block_on(repositories.enqueue_billing_report(id, &billing_event(id, "tenant-a"), 100)).unwrap();

    let outcome = block_on(repositories.replay_dead_lettered_billing_report(id, 500)).unwrap();
    match outcome {
        ReplayDeadLetterOutcome::NotDeadLettered(entry) => assert_eq!(entry.id, id),
        other => panic!("expected NotDeadLettered, got {other:?}"),
    }

    // The pending row is untouched: still scheduled at its original time.
    let entry = block_on(repositories.get_billing_report_outbox_entry(id))
        .unwrap()
        .expect("row still present");
    assert_eq!(entry.next_attempt_unix, 100);
    assert_eq!(entry.dead_lettered_at_unix, None);
}

#[test]
fn replaying_a_missing_report_reports_not_found() {
    let repositories = repositories();
    let outcome = block_on(repositories.replay_dead_lettered_billing_report("nope", 500)).unwrap();
    assert_eq!(outcome, ReplayDeadLetterOutcome::NotFound);
}

#[test]
fn replaying_an_already_replayed_report_is_rejected() {
    let repositories = repositories();
    let id = "report-twice";
    block_on(repositories.enqueue_billing_report(id, &billing_event(id, "tenant-a"), 100)).unwrap();
    block_on(repositories.dead_letter_billing_report(id, 200)).unwrap();

    let first = block_on(repositories.replay_dead_lettered_billing_report(id, 500)).unwrap();
    assert!(
        matches!(first, ReplayDeadLetterOutcome::Replayed(_)),
        "{first:?}"
    );

    let second = block_on(repositories.replay_dead_lettered_billing_report(id, 600)).unwrap();
    match second {
        ReplayDeadLetterOutcome::NotDeadLettered(entry) => {
            // The second replay is a no-op: the schedule from the first replay
            // survives, it is not re-stamped to 600.
            assert_eq!(entry.next_attempt_unix, 500);
        }
        other => panic!("expected NotDeadLettered, got {other:?}"),
    }
}

#[test]
fn concurrent_replays_of_one_row_resolve_to_a_single_winner() {
    let repositories = Arc::new(repositories());
    let id = "report-race";
    block_on(repositories.enqueue_billing_report(id, &billing_event(id, "tenant-a"), 100)).unwrap();
    block_on(repositories.dead_letter_billing_report(id, 200)).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|worker| {
            let repositories = Arc::clone(&repositories);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                block_on(repositories.replay_dead_lettered_billing_report(id, 500 + worker as i64))
                    .unwrap()
            })
        })
        .collect();

    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let replayed = outcomes
        .iter()
        .filter(|o| matches!(o, ReplayDeadLetterOutcome::Replayed(_)))
        .count();
    let rejected = outcomes
        .iter()
        .filter(|o| matches!(o, ReplayDeadLetterOutcome::NotDeadLettered(_)))
        .count();
    assert_eq!(
        replayed, 1,
        "exactly one replay may win the CAS: {outcomes:?}"
    );
    assert_eq!(
        rejected, 1,
        "the loser must observe NotDeadLettered: {outcomes:?}"
    );

    // Terminal state is a single re-enqueued, non-dead-lettered row.
    let dead = block_on(repositories.list_dead_lettered_billing_reports(10)).unwrap();
    assert!(
        dead.is_empty(),
        "row must be re-enqueued exactly once, got {dead:?}"
    );
}
