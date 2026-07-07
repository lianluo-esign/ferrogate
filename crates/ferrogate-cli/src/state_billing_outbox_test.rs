// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the durable billing-report outbox: dead-lettering permanently
//! failing deliveries (#143), the enqueue-failure metric (#151), and
//! source-of-truth cost reconciliation before pricing (#145).

use super::*;

fn unreachable_billing_config() -> Config {
    Config {
        billing_service: crate::config::BillingServiceConfig {
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
    state
        .repositories
        .enqueue_billing_report(&id, &event, 0)
        .expect("enqueue must succeed");

    // Drive the entry's attempt count up to one below the give-up threshold by
    // rescheduling directly (bypassing real backoff wait times), keeping it
    // due (next_attempt_unix = 0) so the final sweep picks it up immediately.
    for _ in 0..(MAX_BILLING_OUTBOX_ATTEMPTS - 1) {
        state
            .repositories
            .reschedule_billing_report(&id, 0)
            .expect("reschedule must succeed");
    }
    let due = state.repositories.list_due_billing_reports(0, 10).unwrap();
    assert_eq!(due[0].attempts, MAX_BILLING_OUTBOX_ATTEMPTS - 1);

    // One more failed delivery attempt crosses the threshold and dead-letters.
    state.sweep_billing_outbox_once();

    assert!(state
        .repositories
        .list_due_billing_reports(0, 10)
        .unwrap()
        .is_empty());
    let dead_letters = state.billing_outbox_dead_letters().unwrap();
    assert_eq!(dead_letters.len(), 1);
    assert_eq!(dead_letters[0].id, id);

    // A dead-lettered entry is never picked up again, no matter how many more
    // times the sweeper runs.
    state.sweep_billing_outbox_once();
    state.sweep_billing_outbox_once();
    assert_eq!(state.billing_outbox_dead_letters().unwrap().len(), 1);
}

#[test]
fn sweep_reschedules_with_backoff_before_the_attempt_threshold() {
    let state = AppState::new(unreachable_billing_config());
    let event = sample_billing_event("req-retry");
    let id = ferrogate_billing::ledger::ledger_entry_id(&event);
    state
        .repositories
        .enqueue_billing_report(&id, &event, 0)
        .expect("enqueue must succeed");

    state.sweep_billing_outbox_once();

    // Not dead-lettered yet: rescheduled into the future instead. The sweeper
    // schedules `next_attempt_unix` from the real wall clock, so query with a
    // far-future cutoff rather than assuming a specific timestamp.
    assert!(state.billing_outbox_dead_letters().unwrap().is_empty());
    assert!(state
        .repositories
        .list_due_billing_reports(0, 10)
        .unwrap()
        .is_empty());
    let rescheduled = state
        .repositories
        .list_due_billing_reports(i64::MAX, 10)
        .unwrap();
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
