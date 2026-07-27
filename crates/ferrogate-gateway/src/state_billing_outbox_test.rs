// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the durable billing-report outbox: dead-lettering permanently
//! failing deliveries (#143), the enqueue-failure metric (#151), and
//! source-of-truth cost reconciliation before pricing (#145).

use super::*;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn unreachable_billing_config() -> Config {
    Config {
        billing_service: ferrogate_config::BillingServiceConfig {
            enabled: true,
            // Port 1 requires privileges nothing in a test sandbox has, so the
            // connection is refused immediately and deterministically.
            endpoint: "http://127.0.0.1:1".to_string(),
            timeout_millis: 200,
            token: None,
            token_env: None,
        },
        ..Config::default()
    }
}

fn sample_billing_event(request_id: &str) -> BillingEvent {
    BillingEvent {
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
            organization_id: Some("org_demo".into()),
            ..ferrogate_core::TenantContext::default()
        },
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: BillingTokenUsage::new(10, 20, 30),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: Some(0.01),
        latency_ms: None,
        metadata: std::collections::BTreeMap::new(),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    }
}

#[test]
fn sweep_dead_letters_after_max_attempts_and_stops_retrying() {
    let state = AppState::new(unreachable_billing_config());
    assert!(state.billing_reporter.is_some());

    let event = sample_billing_event("req-dead-letter");
    let id = ferrogate_billing::ledger::ledger_entry_id(&event);
    block_on(state.repositories.enqueue_billing_report(&id, &event, 0))
        .expect("enqueue must succeed");

    // Drive the entry's attempt count up to one below the give-up threshold by
    // rescheduling directly (bypassing real backoff wait times), keeping it
    // due (next_attempt_unix = 0) so the final sweep picks it up immediately.
    for _ in 0..(MAX_BILLING_OUTBOX_ATTEMPTS - 1) {
        block_on(state.repositories.reschedule_billing_report(&id, 0))
            .expect("reschedule must succeed");
    }
    let due = block_on(state.repositories.list_due_billing_reports(0, 10)).unwrap();
    assert_eq!(due[0].attempts, MAX_BILLING_OUTBOX_ATTEMPTS - 1);

    // One more failed delivery attempt crosses the threshold and dead-letters.
    block_on(state.sweep_billing_outbox_once());

    assert!(block_on(state.repositories.list_due_billing_reports(0, 10))
        .unwrap()
        .is_empty());
    let dead_letters = block_on(state.billing_outbox_dead_letters()).unwrap();
    assert_eq!(dead_letters.len(), 1);
    assert_eq!(dead_letters[0].id, id);

    // A dead-lettered entry is never picked up again, no matter how many more
    // times the sweeper runs.
    block_on(state.sweep_billing_outbox_once());
    block_on(state.sweep_billing_outbox_once());
    assert_eq!(
        block_on(state.billing_outbox_dead_letters()).unwrap().len(),
        1
    );
}

/// #388: an operator-driven replay re-enqueues a dead-lettered report for
/// redelivery. Drives the real dead-letter path (sweep to the give-up
/// threshold), then replays and proves the row is redeliverable again and no
/// longer dead-lettered.
#[test]
fn replay_re_enqueues_a_dead_lettered_report_for_redelivery() {
    let state = AppState::new(unreachable_billing_config());
    let event = sample_billing_event("req-replay");
    let id = ferrogate_billing::ledger::ledger_entry_id(&event);
    block_on(state.repositories.enqueue_billing_report(&id, &event, 0))
        .expect("enqueue must succeed");
    for _ in 0..MAX_BILLING_OUTBOX_ATTEMPTS {
        block_on(state.repositories.reschedule_billing_report(&id, 0)).expect("reschedule");
    }
    block_on(state.sweep_billing_outbox_once());
    assert_eq!(
        block_on(state.billing_outbox_dead_letters()).unwrap().len(),
        1,
        "precondition: the report is dead-lettered"
    );

    let outcome = block_on(state.replay_billing_outbox_dead_letter(&id)).unwrap();
    let entry = match outcome {
        ferrogate_storage::ReplayDeadLetterOutcome::Replayed(entry) => entry,
        other => panic!("expected Replayed, got {other:?}"),
    };
    assert_eq!(entry.id, id);
    assert_eq!(entry.dead_lettered_at_unix, None);
    assert_eq!(entry.attempts, 0);

    // No longer dead-lettered, and redeliverable (due) again.
    assert!(block_on(state.billing_outbox_dead_letters())
        .unwrap()
        .is_empty());
    let due = block_on(state.repositories.list_due_billing_reports(i64::MAX, 10)).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].id, id);
}

/// #388 fail-closed: replay only fires for an actually-dead-lettered row. A
/// missing id and a still-pending (never dead-lettered) row are both rejected
/// with a distinct typed outcome and leave state untouched.
#[test]
fn replay_rejects_missing_and_non_dead_lettered_reports() {
    let state = AppState::new(unreachable_billing_config());

    let missing = block_on(state.replay_billing_outbox_dead_letter("nope")).unwrap();
    assert_eq!(
        missing,
        ferrogate_storage::ReplayDeadLetterOutcome::NotFound
    );

    let event = sample_billing_event("req-live");
    let id = ferrogate_billing::ledger::ledger_entry_id(&event);
    block_on(state.repositories.enqueue_billing_report(&id, &event, 7))
        .expect("enqueue must succeed");
    let outcome = block_on(state.replay_billing_outbox_dead_letter(&id)).unwrap();
    match outcome {
        ferrogate_storage::ReplayDeadLetterOutcome::NotDeadLettered(entry) => {
            assert_eq!(entry.id, id);
        }
        other => panic!("expected NotDeadLettered, got {other:?}"),
    }
    // The pending row keeps its original schedule.
    let entry = block_on(state.repositories.get_billing_report_outbox_entry(&id))
        .unwrap()
        .expect("row present");
    assert_eq!(entry.next_attempt_unix, 7);
    assert_eq!(entry.dead_lettered_at_unix, None);
}

#[test]
fn sweep_reschedules_with_backoff_before_the_attempt_threshold() {
    let state = AppState::new(unreachable_billing_config());
    let event = sample_billing_event("req-retry");
    let id = ferrogate_billing::ledger::ledger_entry_id(&event);
    block_on(state.repositories.enqueue_billing_report(&id, &event, 0))
        .expect("enqueue must succeed");

    block_on(state.sweep_billing_outbox_once());

    // Not dead-lettered yet: rescheduled into the future instead. The sweeper
    // schedules `next_attempt_unix` from the real wall clock, so query with a
    // far-future cutoff rather than assuming a specific timestamp.
    assert!(block_on(state.billing_outbox_dead_letters())
        .unwrap()
        .is_empty());
    assert!(block_on(state.repositories.list_due_billing_reports(0, 10))
        .unwrap()
        .is_empty());
    let rescheduled = block_on(state.repositories.list_due_billing_reports(i64::MAX, 10)).unwrap();
    assert_eq!(rescheduled.len(), 1);
    assert_eq!(rescheduled[0].attempts, 1);
}

#[test]
fn billing_report_enqueue_failure_metric_increments_and_appears_in_snapshot() {
    let mut metrics = GatewayMetricsAccumulator::default();
    metrics.record_billing_report_enqueue_failure();
    metrics.record_billing_report_enqueue_failure();

    let snapshot = metrics.snapshot("ferrogate-test".to_string());
    assert_eq!(snapshot.billing_report_enqueue_failure_total, 2);
}

#[test]
fn billing_outbox_backoff_is_capped_exponential() {
    assert_eq!(billing_outbox_backoff_secs(0), 1);
    assert_eq!(billing_outbox_backoff_secs(1), 2);
    assert_eq!(billing_outbox_backoff_secs(2), 4);
    assert_eq!(billing_outbox_backoff_secs(6), 60);
    assert_eq!(billing_outbox_backoff_secs(100), 60);
}

/// #309 backpressure guarantee: billing events NEVER route through the bounded
/// background evidence writer — they keep the inline awaited durable-outbox
/// path — so a stalled evidence writer can neither drop nor delay a charge,
/// while evidence queued behind the stall still lands once the writer drains
/// (no silent loss on either side).
#[test]
fn billing_events_survive_a_stalled_evidence_writer() {
    let state = AppState::new(unreachable_billing_config());
    assert!(state.billing_reporter.is_some());

    // Park the evidence writer thread on a gate job, simulating a stalled
    // Postgres evidence writer.
    let (started_sender, started) = std::sync::mpsc::channel();
    let (release, release_receiver) = std::sync::mpsc::channel();
    assert!(state
        .evidence_writer
        .enqueue(crate::state::EvidenceWriteJob::Gate {
            started: started_sender,
            release: release_receiver,
        }));
    started
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("evidence writer never picked up the gate job");
    // Queue an audit row BEHIND the stall: it must not be processed yet.
    let audit_event = state.prepare_admin_audit_event(AdminAuditEventDraft {
        action_identity: Default::default(),
        request_id: "req-stalled-writer".into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        actor_api_key_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        action: "tool.execute".into(),
        target: "tool".into(),
        outcome: "success".into(),
        message: "queued behind the stalled writer".into(),
    });
    assert!(state
        .evidence_writer
        .enqueue(crate::state::EvidenceWriteJob::AuditEvent(audit_event)));
    assert_eq!(
        state.evidence_writer.metrics().written_total,
        0,
        "the audit row must still be stalled behind the gate"
    );

    // The billing event settles inline through the durable metering +
    // outbox-enqueue path while the evidence writer is parked.
    let request = RequestContext {
        request_id: "req-stalled-writer".into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        route: Some("openai.chat.completions".into()),
        upstream: Some("openai".into()),
        tenant: ferrogate_core::TenantContext {
            organization_id: Some("org_demo".into()),
            ..ferrogate_core::TenantContext::default()
        },
    };
    block_on(state.record_billing_event(
        BillingEventDraft {
            request: &request,
            logical_model: "fast-chat",
            provider: "openai",
            provider_model: "gpt-4o-mini",
            status_code: 200,
            latency_ms: Some(50),
            metadata: None,
        },
        &ProviderUsage {
            prompt_tokens: Some(3),
            completion_tokens: Some(5),
            total_tokens: Some(8),
        },
    ))
    .expect("billing settlement must not depend on the evidence writer");

    let events = state.billing_events();
    assert_eq!(events.len(), 1, "the charge must land despite the stall");
    assert_eq!(events[0].request_id, "req-stalled-writer");
    let pending = block_on(state.repositories.list_due_billing_reports(i64::MAX, 10)).unwrap();
    assert_eq!(
        pending.len(),
        1,
        "the durable outbox enqueue must also land despite the stall"
    );

    // Release the stall: the queued audit evidence drains and persists too —
    // nothing was silently lost.
    release.send(()).expect("writer thread must still be alive");
    assert!(state.evidence_writer.flush());
    let audited = block_on(state.repositories.audit_events());
    assert!(
        audited
            .iter()
            .any(|event| event.request_id == "req-stalled-writer"),
        "the stalled audit evidence must persist after the writer drains"
    );
}
