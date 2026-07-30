// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Tests for the #545 self-hosted dispatch reclaim sweeper. Driven
// against an in-memory `AppState` (no Docker, no Postgres, no worker process):
// the durable rows are written straight through the repository facade, which is
// the same table the sweeper reads and the same one #502's reclaim has to
// shrink. Lease expiry is driven by the INJECTED `now_unix`, never by sleeping.

use super::*;

use ferrogate_config::Config;
use ferrogate_core::TenantContext;
use ferrogate_storage::{StoredAgentRun, StoredSelfHostedRunDispatch};

const NOW: u64 = 1_700_000_000;
const LEASE_GRACE_SECS: u64 = 300;

fn sweeper_config(enabled: bool, max_runs_per_tick: usize) -> Config {
    Config {
        self_hosted_dispatch_sweeper: ferrogate_config::SelfHostedDispatchSweeperConfig {
            enabled,
            tick_interval_secs: 300,
            max_runs_per_tick,
            lease_grace_secs: LEASE_GRACE_SECS,
        },
        ..Config::default()
    }
}

fn state_with_sweeper() -> AppState {
    AppState::new(sweeper_config(true, 200))
}

fn tenant() -> TenantContext {
    TenantContext {
        organization_id: Some("tenant-a".to_string()),
        workspace_id: Some("ws-1".to_string()),
        team_id: None,
        project_id: None,
        user_id: None,
        api_key_id: Some("key-1".to_string()),
    }
}

fn run_row(run_id: &str, status: &str) -> StoredAgentRun {
    StoredAgentRun {
        id: run_id.to_string(),
        request_id: "fg-submit".to_string(),
        trace_id: None,
        tenant: tenant(),
        status: status.to_string(),
        provider: "ferrogate.agent-job".to_string(),
        turns_executed: 0,
        output_recorded: false,
        started_at_unix: Some(NOW - 3_600),
        completed_at_unix: (status != "running").then_some(NOW - 1_800),
    }
}

/// Persist one durable dispatch row directly, the same direct-construction
/// pattern `lease_start_dispatch_to_worker` (agent_jobs_test.rs) uses: the
/// poll/ack handshake is irrelevant to what these tests prove, and driving it
/// would make the lease clock a moving target instead of an injected value.
fn persist_dispatch(
    state: &AppState,
    run_id: &str,
    action: &str,
    queued_at_unix: u64,
    lease: Option<(&str, u64)>,
) -> String {
    let dispatch_id = format!("{action}-{run_id}");
    let stored = StoredSelfHostedRunDispatch {
        dispatch_id: dispatch_id.clone(),
        action: action.to_string(),
        tenant_id: "tenant-a".to_string(),
        workspace_id: "ws-1".to_string(),
        session_id: format!("agent-job-session-{run_id}"),
        run_id: run_id.to_string(),
        framework_adapter: "claude-code".to_string(),
        required_capabilities: vec!["shell".to_string()],
        workload_ref: format!("agent-job://{run_id}"),
        queued_at_unix: Some(queued_at_unix),
        assigned_worker_id: lease.map(|(worker_id, _)| worker_id.to_string()),
        lease_id: lease.map(|(worker_id, _)| format!("{dispatch_id}:{worker_id}")),
        lease_expires_at_unix: lease.map(|(_, expires_at)| expires_at),
        attempt: u32::from(lease.is_some()),
        acknowledged_status: None,
        acknowledged_at_unix: None,
        request_id: Some("fg-submit".to_string()),
        trace_id: None,
        agent_run_id: Some(run_id.to_string()),
        parent_action_fingerprint: None,
    };
    ferrogate_sync_bridge::block_on_sync_bridge(
        state
            .repositories_arc()
            .upsert_self_hosted_run_dispatch(stored),
    )
    .expect("dispatch row persists");
    dispatch_id
}

/// Every dispatch id the DURABLE table still holds -- the thing this sweeper has
/// to actually shrink, read back the same way `durable_dispatch_ids` does in
/// `agent_jobs_test.rs`.
fn durable_dispatch_ids(state: &AppState) -> Vec<String> {
    let mut ids: Vec<String> = ferrogate_sync_bridge::block_on_sync_bridge(
        state.repositories_arc().self_hosted_run_dispatches(),
    )
    .into_iter()
    .map(|record| record.dispatch_id)
    .collect();
    ids.sort();
    ids
}

/// The lease-then-abandon shape #545 was split out for: a worker leased the
/// `start_run`, the job was cancelled, and the worker never came back -- so the
/// `cancel_run` is unacked and the superseded `start_run` was never deleted.
/// Both rows persist today until some caller happens to retry the cancel.
fn seed_abandoned_run(state: &AppState, run_id: &str, queued_at_unix: u64) -> Vec<String> {
    state.record_agent_run(run_row(run_id, "cancelled"));
    let start = persist_dispatch(
        state,
        run_id,
        "start_run",
        queued_at_unix,
        // Lease taken, then abandoned: expiry is already in the past, by more
        // than the skew grace.
        Some(("worker-1", NOW - LEASE_GRACE_SECS - 60)),
    );
    let cancel = persist_dispatch(state, run_id, "cancel_run", queued_at_unix, None);
    vec![start, cancel]
}

#[test]
fn a_disabled_sweeper_is_a_complete_no_op() {
    let state = AppState::new(sweeper_config(false, 200));
    let ids = seed_abandoned_run(&state, "job-abandoned", 100);

    let report = state.sweep_self_hosted_dispatches_once(NOW);

    assert_eq!(
        report,
        SelfHostedDispatchSweepReport::default(),
        "a disabled sweeper must not even read the table"
    );
    let mut expected = ids;
    expected.sort();
    assert_eq!(
        durable_dispatch_ids(&state),
        expected,
        "a disabled sweeper must leave every row in place"
    );
}

#[test]
fn a_run_terminal_longer_than_its_lease_has_its_orphaned_rows_reclaimed() {
    // Acceptance box 1: no caller touches the run -- the sweep is the only
    // actor, and both abandoned rows go.
    let state = state_with_sweeper();
    seed_abandoned_run(&state, "job-abandoned", 100);
    assert_eq!(
        durable_dispatch_ids(&state).len(),
        2,
        "the lease-then-abandon shape leaves exactly two rows behind"
    );

    let report = state.sweep_self_hosted_dispatches_once(NOW);

    assert_eq!(report.reclaimed_runs, 1);
    assert_eq!(report.reclaimed_rows, 2);
    assert_eq!(report.unchanged_rows, 0);
    assert_eq!(report.deferred_live_lease_runs, 0);
    assert_eq!(report.live_runs, 0);
    assert!(
        durable_dispatch_ids(&state).is_empty(),
        "the abandoned run's rows must be gone from the durable table"
    );
}

#[test]
fn a_live_runs_start_dispatch_is_never_deleted_and_keeps_its_lease_ownership_proof() {
    // Acceptance box 2, asserted directly rather than implied: the row survives
    // AND #503's ownership resolver still names the holder, which is the thing
    // that would actually break if a sweeper keyed off age alone.
    let state = state_with_sweeper();
    state.record_agent_run(run_row("job-live", "running"));
    // A long-running job whose lease lapsed while the worker was still working:
    // age says "old", the run status says "live". Only the run status may win.
    let start = persist_dispatch(
        &state,
        "job-live",
        "start_run",
        100,
        Some(("worker-live", NOW - LEASE_GRACE_SECS - 3_600)),
    );

    let report = state.sweep_self_hosted_dispatches_once(NOW);

    assert_eq!(report.live_runs, 1, "a non-terminal run is never reclaimed");
    assert_eq!(report.reclaimed_rows, 0);
    assert_eq!(
        durable_dispatch_ids(&state),
        vec![start],
        "a live run's start_run row must survive the sweep"
    );
    assert_eq!(
        state.self_hosted_dispatch_lease_owner("job-live", SelfHostedRunAction::StartRun),
        Some("worker-live".to_string()),
        "#503's lease-ownership proof must keep working after a sweep"
    );
}

#[test]
fn a_terminal_run_whose_lease_is_still_live_is_deferred_not_reclaimed() {
    // The #549 ack window: the worker that reported completion is by
    // construction the start_run lease holder and may not have acked yet.
    // Deferring is what makes "bound the delete by the lease expiry" possible
    // at all -- and the deferral must also hold back the sibling cancel_run row
    // the holder could still be told to act on.
    let state = state_with_sweeper();
    state.record_agent_run(run_row("job-just-finished", "completed"));
    let start = persist_dispatch(
        &state,
        "job-just-finished",
        "start_run",
        100,
        Some(("worker-1", NOW + 60)),
    );
    let cancel = persist_dispatch(&state, "job-just-finished", "cancel_run", 100, None);

    let report = state.sweep_self_hosted_dispatches_once(NOW);

    assert_eq!(report.deferred_live_lease_runs, 1);
    assert_eq!(report.reclaimed_rows, 0);
    let mut expected = vec![start, cancel];
    expected.sort();
    assert_eq!(
        durable_dispatch_ids(&state),
        expected,
        "a live lease holds back every row of its run, not just its own"
    );

    // Once the lease is dead -- past expiry AND past the skew grace -- the same
    // rows are reclaimed with no other change in the world.
    let later = state.sweep_self_hosted_dispatches_once(NOW + 60 + LEASE_GRACE_SECS + 1);
    assert_eq!(later.reclaimed_runs, 1);
    assert_eq!(later.reclaimed_rows, 2);
    assert!(durable_dispatch_ids(&state).is_empty());
}

#[test]
fn the_lease_grace_holds_back_a_lease_that_only_just_expired() {
    // The persisted expiry is computed from the WORKER-supplied `now_unix` of
    // the poll, so a slow worker clock can present a still-held lease as dead.
    // The grace is the bound on that skew; deleting it makes this test red.
    let state = state_with_sweeper();
    state.record_agent_run(run_row("job-skewed", "completed"));
    persist_dispatch(
        &state,
        "job-skewed",
        "start_run",
        100,
        Some(("worker-1", NOW - 1)),
    );

    let within_grace = state.sweep_self_hosted_dispatches_once(NOW);
    assert_eq!(within_grace.deferred_live_lease_runs, 1);
    assert_eq!(within_grace.reclaimed_rows, 0);
    assert_eq!(durable_dispatch_ids(&state).len(), 1);

    let past_grace = state.sweep_self_hosted_dispatches_once(NOW + LEASE_GRACE_SECS);
    assert_eq!(past_grace.reclaimed_rows, 1);
    assert!(durable_dispatch_ids(&state).is_empty());
}

#[test]
fn the_sweep_is_idempotent_and_a_second_pass_finds_nothing_left() {
    // Acceptance box 3, first half. Also the concurrency claim: the second pass
    // stands in for a peer instance sweeping the same run.
    let state = state_with_sweeper();
    seed_abandoned_run(&state, "job-abandoned", 100);

    let first = state.sweep_self_hosted_dispatches_once(NOW);
    assert_eq!(first.reclaimed_rows, 2);

    let second = state.sweep_self_hosted_dispatches_once(NOW);
    assert_eq!(
        second,
        SelfHostedDispatchSweepReport::default(),
        "an empty table is a clean no-op, not a re-delete"
    );
}

#[test]
fn one_tick_reclaims_at_most_max_runs_per_tick_and_drains_the_backlog_oldest_first() {
    // Acceptance box 3, second half: bounded. And bounded-with-progress -- a
    // bound that keeps re-picking the same subset would never drain.
    let state = AppState::new(sweeper_config(true, 2));
    for (index, run_id) in ["job-a", "job-b", "job-c"].iter().enumerate() {
        seed_abandoned_run(&state, run_id, 100 + index as u64);
    }
    assert_eq!(durable_dispatch_ids(&state).len(), 6);

    let first = state.sweep_self_hosted_dispatches_once(NOW);
    assert_eq!(first.reclaimed_runs, 2, "one tick may not exceed the bound");
    assert_eq!(first.reclaimed_rows, 4);
    assert_eq!(
        durable_dispatch_ids(&state),
        vec![
            "cancel_run-job-c".to_string(),
            "start_run-job-c".to_string()
        ],
        "the two OLDEST runs drain first; the newest is what is left"
    );

    let second = state.sweep_self_hosted_dispatches_once(NOW);
    assert_eq!(second.reclaimed_runs, 1, "successive ticks make progress");
    assert!(durable_dispatch_ids(&state).is_empty());
}

#[test]
fn a_never_leased_dispatch_of_a_terminal_run_is_reclaimed_without_any_lease_at_all() {
    // The workerless case: nothing ever leased the row, so there is no expiry to
    // outlive. Terminal status alone is the whole gate here -- and it is enough,
    // because a run that will never change again has no reader for its rows.
    let state = state_with_sweeper();
    state.record_agent_run(run_row("job-never-leased", "failed"));
    persist_dispatch(&state, "job-never-leased", "start_run", 100, None);

    let report = state.sweep_self_hosted_dispatches_once(NOW);

    assert_eq!(report.reclaimed_rows, 1);
    assert!(durable_dispatch_ids(&state).is_empty());
}

#[test]
fn a_dispatch_whose_run_row_does_not_exist_is_left_alone() {
    // Absence of evidence is not terminality: `settled_agent_run_ids` refuses to
    // settle a run id with no row, and the sweeper must inherit that refusal
    // rather than treat "no run" as "safe to delete".
    let state = state_with_sweeper();
    let orphan = persist_dispatch(&state, "job-no-run-row", "start_run", 100, None);

    let report = state.sweep_self_hosted_dispatches_once(NOW);

    assert_eq!(report.live_runs, 1);
    assert_eq!(report.reclaimed_rows, 0);
    assert_eq!(
        durable_dispatch_ids(&state),
        vec![orphan],
        "a dispatch with no run row must not be reclaimed by absence"
    );
}
