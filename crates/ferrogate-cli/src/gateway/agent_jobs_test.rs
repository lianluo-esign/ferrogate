// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Unit tests for the caller-facing async agent-job surface (#474).

//! Proves the four properties the async job protocol is judged on, without a
//! live HTTP session: idempotent submission (a retry addresses the ORIGINAL
//! run), tenant isolation on every read, cancellation that reaches the runtime
//! transport AND terminalizes the run, and a stable incremental event cursor.

use super::*;
use crate::config::Config;
use ferrogate_core::TenantContext;

fn tenant(organization_id: &str) -> TenantContext {
    TenantContext {
        organization_id: Some(organization_id.to_string()),
        workspace_id: Some("ws-1".to_string()),
        team_id: None,
        project_id: None,
        user_id: None,
        api_key_id: Some("key-1".to_string()),
    }
}

fn queued_run(run_id: &str, organization_id: &str) -> StoredAgentRun {
    StoredAgentRun {
        id: run_id.to_string(),
        request_id: "fg-submit".to_string(),
        trace_id: None,
        tenant: tenant(organization_id),
        status: "queued".to_string(),
        provider: "ferrogate.agent-job".to_string(),
        turns_executed: 0,
        output_recorded: false,
        started_at_unix: Some(100),
        completed_at_unix: None,
    }
}

fn start_dispatch(run_id: &str, organization_id: &str) -> SelfHostedRunDispatch {
    SelfHostedRunDispatch {
        dispatch_id: agent_job_start_dispatch_id(run_id),
        action: SelfHostedRunAction::StartRun,
        tenant_id: organization_id.to_string(),
        workspace_id: "ws-1".to_string(),
        session_id: format!("agent-job-session-{run_id}"),
        run_id: run_id.to_string(),
        framework_adapter: "claude-code".to_string(),
        required_capabilities: vec!["shell".to_string()],
        workload_ref: format!("agent-job://{run_id}"),
        queued_at_unix: 100,
        request_id: Some("fg-submit".to_string()),
        trace_id: None,
        agent_run_id: Some(run_id.to_string()),
        parent_action_fingerprint: None,
    }
}

fn timeline_event(run_id: &str, id: &str, occurred_at_unix: u64) -> StoredAgentRunEvent {
    StoredAgentRunEvent {
        id: id.to_string(),
        run_id: run_id.to_string(),
        request_id: "fg-submit".to_string(),
        trace_id: None,
        tenant: tenant("tenant-a"),
        turn: 0,
        kind: "turn_started".to_string(),
        target: format!("agent_run:{run_id}"),
        outcome: "started".to_string(),
        tool_call_id: None,
        message: None,
        occurred_at_unix: Some(occurred_at_unix),
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
        output_disposition: None,
    }
}

#[test]
fn a_retried_submit_derives_the_original_run_id_from_the_idempotency_key() {
    // The whole idempotency mechanism: the id is DERIVED, so the retry cannot
    // land on a different run even if it races the first submit.
    let first = agent_job_run_id("tenant-a", "fix-issue-474");
    let retry = agent_job_run_id("tenant-a", "fix-issue-474");
    assert_eq!(first, retry, "a retried key must address the same job id");
    assert!(first.starts_with("job-"), "job ids are namespaced: {first}");
    assert_eq!(first.len(), "job-".len() + 32, "16 bytes of digest as hex");

    // A different key is a different job.
    assert_ne!(first, agent_job_run_id("tenant-a", "fix-issue-475"));
    // The key is namespaced per tenant: tenant B reusing tenant A's key gets
    // its own job and can never address (or clobber) tenant A's.
    assert_ne!(first, agent_job_run_id("tenant-b", "fix-issue-474"));
    // The domain separator makes the (tenant, key) split unambiguous.
    assert_ne!(
        agent_job_run_id("ab", "c"),
        agent_job_run_id("a", "bc"),
        "the tenant/key boundary must not be forgeable by shifting characters"
    );
}

#[test]
fn a_duplicate_submit_finds_the_original_run_and_enqueues_no_second_dispatch() {
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "fix-issue-474");
    let dispatch = start_dispatch(&run_id, "tenant-a");

    // First submit: enqueue the dispatch, then claim the run row.
    state
        .enqueue_scheduled_self_hosted_dispatch(dispatch.clone())
        .expect("first submit enqueues the runtime dispatch");
    state.record_agent_run(queued_run(&run_id, "tenant-a"));

    // The retry's dedup gate: the derived id already has a run row, so the
    // handler returns the ORIGINAL id instead of spawning a second run.
    let existing = state
        .agent_run_record(&run_id)
        .expect("the retry must observe the original run record");
    assert_eq!(existing.id, run_id);
    assert_eq!(existing.request_id, "fg-submit");
    assert_eq!(existing.status, "queued");

    // And even a racing retry that got past the gate cannot double-dispatch:
    // the dispatch id is derived from the run id and the queue dedups on it.
    state
        .enqueue_scheduled_self_hosted_dispatch(dispatch)
        .expect("re-enqueuing the deterministic dispatch id is a no-op, not an error");
    assert!(state.self_hosted_dispatch_unacked(&agent_job_start_dispatch_id(&run_id)));
    assert_eq!(
        state
            .self_hosted_dispatch_for_run(&run_id, SelfHostedRunAction::StartRun)
            .map(|dispatch| dispatch.dispatch_id),
        Some(agent_job_start_dispatch_id(&run_id)),
        "exactly one start dispatch exists for the job"
    );
}

#[test]
fn agent_job_reads_do_not_leak_another_tenants_run() {
    // Mirrors overview_aggregate_tenant_scope_does_not_leak_other_tenants:
    // isolation is applied by the storage/query filter, so a foreign run id
    // resolves to None (404) rather than being trimmed out of a response.
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-b", "fix-issue-474");
    state.record_agent_run(queued_run(&run_id, "tenant-b"));

    let owner_view = state.agent_run_timeline(
        &run_id,
        AgentRunFilter {
            organization_id: Some("tenant-b".to_string()),
            ..AgentRunFilter::default()
        },
    );
    assert!(
        owner_view.is_some(),
        "the owning tenant must still see its own job"
    );

    let intruder_view = state.agent_run_timeline(
        &run_id,
        AgentRunFilter {
            organization_id: Some("tenant-a".to_string()),
            ..AgentRunFilter::default()
        },
    );
    assert!(
        intruder_view.is_none(),
        "a tenant-scoped caller must never observe another tenant's job"
    );

    // The runtime-reported timeline the status/result reads join is scoped the
    // same way.
    assert!(state
        .self_hosted_run_timeline(&run_id, Some("tenant-a"))
        .is_none());
}

#[test]
fn cancel_dispatches_a_runtime_cancel_and_terminalizes_the_run() {
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "cancel-me");
    state
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&run_id, "tenant-a"))
        .expect("submit enqueues the start dispatch");
    let run = queued_run(&run_id, "tenant-a");
    state.record_agent_run(run.clone());

    let dispatched =
        cancel_agent_job_in_runtime(&state, &run, "fg-cancel", 200).expect("cancel enqueues");
    assert!(dispatched, "a live job's cancel must reach the runtime");

    let cancel = state
        .self_hosted_dispatch_for_run(&run_id, SelfHostedRunAction::CancelRun)
        .expect("a cancel_run dispatch is queued for the runtime to lease");
    assert_eq!(cancel.dispatch_id, agent_job_cancel_dispatch_id(&run_id));
    assert_eq!(cancel.action, SelfHostedRunAction::CancelRun);
    assert_eq!(cancel.run_id, run_id);
    // The cancel addresses the SAME worker shape the start dispatch targeted,
    // so the worker that owns the run can lease it.
    assert_eq!(cancel.framework_adapter, "claude-code");
    assert_eq!(cancel.session_id, format!("agent-job-session-{run_id}"));
    assert_eq!(cancel.tenant_id, "tenant-a");

    // The handler then terminalizes the run itself.
    let mut cancelled = run;
    cancelled.status = "cancelled".to_string();
    cancelled.completed_at_unix = Some(200);
    state.record_agent_run(cancelled);
    let stored = state.agent_run_record(&run_id).expect("run record");
    assert_eq!(stored.status, "cancelled");
    assert_eq!(stored.completed_at_unix, Some(200));
    assert!(agent_job_status_is_terminal(&stored.status));

    // Cancelling a job the runtime never accepted is not an error; there is
    // simply no transport dispatch to address.
    let orphan = queued_run("job-orphan", "tenant-a");
    assert_eq!(
        cancel_agent_job_in_runtime(&state, &orphan, "fg-cancel", 200),
        Ok(false)
    );
}

#[test]
fn terminal_status_classification_gates_result_retrieval() {
    for status in [
        "completed",
        "failed",
        "cancelled",
        "timed_out",
        "max_turns_exceeded",
        "exhausted",
    ] {
        assert!(
            agent_job_status_is_terminal(status),
            "{status} must be terminal"
        );
    }
    for status in ["queued", "running", "blocked", ""] {
        assert!(
            !agent_job_status_is_terminal(status),
            "{status} must not be terminal"
        );
    }
}

#[test]
fn the_idempotency_key_is_explicit_with_a_header_over_body_precedence() {
    let mut headers = HeaderMap::new();
    headers.insert(IDEMPOTENCY_KEY_HEADER, "from-header".parse().unwrap());
    let resolved = resolve_idempotency_key(&headers, Some("from-body"), "fg-1").unwrap();
    assert_eq!(resolved.key, "from-header");
    assert_eq!(resolved.source, "header");

    let resolved = resolve_idempotency_key(&HeaderMap::new(), Some("from-body"), "fg-1").unwrap();
    assert_eq!(resolved.key, "from-body");
    assert_eq!(resolved.source, "body");

    // No key: the request id is used, so an un-keyed submit is its own job and
    // is never silently merged with another caller's.
    let resolved = resolve_idempotency_key(&HeaderMap::new(), None, "fg-1").unwrap();
    assert_eq!(resolved.key, "request:fg-1");
    assert_eq!(resolved.source, "request_id");

    // Blank values fall through rather than keying every job on "".
    let resolved = resolve_idempotency_key(&HeaderMap::new(), Some("   "), "fg-1").unwrap();
    assert_eq!(resolved.source, "request_id");

    let long = "k".repeat(IDEMPOTENCY_KEY_MAX_LEN + 1);
    assert!(resolve_idempotency_key(&HeaderMap::new(), Some(&long), "fg-1").is_err());
}

#[test]
fn the_event_feed_resumes_deterministically_after_a_cursor() {
    let run_id = "job-abc";
    // Deliberately out of order, and with a tie on occurred_at to prove the id
    // tiebreak keeps the ordering total.
    let events = vec![
        timeline_event(run_id, "e3", 20),
        timeline_event(run_id, "e1", 10),
        timeline_event(run_id, "e2", 10),
    ];

    let first = page_agent_job_events(
        events.clone(),
        &AgentJobEventCursor {
            after_event_id: None,
            limit: 2,
        },
    );
    assert_eq!(
        first.data.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        vec!["e1", "e2"]
    );
    assert!(first.has_more);
    assert!(!first.cursor_reset);
    // The emitted cursor is the POSITION key, not the bare id, so it stays
    // resolvable after the event it names is pruned.
    assert_eq!(first.next_after_event_id.as_deref(), Some("10:e2"));

    let second = page_agent_job_events(
        events.clone(),
        &AgentJobEventCursor {
            after_event_id: first.next_after_event_id,
            limit: 2,
        },
    );
    assert_eq!(
        second
            .data
            .iter()
            .map(|e| e.id.as_str())
            .collect::<Vec<_>>(),
        vec!["e3"]
    );
    assert!(!second.has_more);
    assert!(!second.cursor_reset);

    // A bare event id the caller copied out of `data[].id` still resolves.
    let from_bare_id = page_agent_job_events(
        events.clone(),
        &AgentJobEventCursor {
            after_event_id: Some("e2".to_string()),
            limit: 2,
        },
    );
    assert_eq!(
        from_bare_id
            .data
            .iter()
            .map(|e| e.id.as_str())
            .collect::<Vec<_>>(),
        vec!["e3"]
    );
    assert!(!from_bare_id.cursor_reset);
}

#[test]
fn a_pruned_cursor_resets_the_feed_instead_of_breaking_the_poll_loop() {
    // #474 rework: an `after_event_id` that no longer exists used to be a hard
    // 400, which made a resumable poll loop die permanently the moment
    // retention pruned the event its cursor pointed at.
    let run_id = "job-abc";
    let events = vec![
        timeline_event(run_id, "e5", 50),
        timeline_event(run_id, "e6", 60),
    ];

    // A composite cursor whose event is GONE still resolves by position: the
    // loop keeps making forward progress with no replay at all.
    let resumed = page_agent_job_events(
        events.clone(),
        &AgentJobEventCursor {
            after_event_id: Some("50:e5".to_string()),
            limit: 10,
        },
    );
    assert_eq!(
        resumed
            .data
            .iter()
            .map(|e| e.id.as_str())
            .collect::<Vec<_>>(),
        vec!["e6"]
    );
    assert!(!resumed.cursor_reset);

    // A cursor that cannot be located at all restarts the feed and SAYS SO,
    // rather than answering 400 forever.
    let reset = page_agent_job_events(
        events,
        &AgentJobEventCursor {
            after_event_id: Some("nope".to_string()),
            limit: 10,
        },
    );
    assert!(reset.cursor_reset, "the caller is told its cursor was lost");
    assert_eq!(
        reset.data.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        vec!["e5", "e6"],
        "the loop self-heals from the oldest retained event"
    );
}

#[test]
fn the_event_cursor_query_is_parsed_and_bounded() {
    let cursor = AgentJobEventCursor::from_query(None).unwrap();
    assert_eq!(cursor.limit, EVENT_PAGE_DEFAULT_LIMIT);
    assert_eq!(cursor.after_event_id, None);

    let cursor = AgentJobEventCursor::from_query(Some("after_event_id=e1&limit=5")).unwrap();
    assert_eq!(cursor.after_event_id.as_deref(), Some("e1"));
    assert_eq!(cursor.limit, 5);

    // Clamped, never unbounded.
    let cursor = AgentJobEventCursor::from_query(Some("limit=100000")).unwrap();
    assert_eq!(cursor.limit, EVENT_PAGE_MAX_LIMIT);

    assert!(AgentJobEventCursor::from_query(Some("limit=0")).is_err());
    assert!(AgentJobEventCursor::from_query(Some("limit=many")).is_err());
}

#[test]
fn submitted_input_evidence_is_bounded() {
    let long = "x".repeat(SUBMITTED_INPUT_EVIDENCE_MAX_CHARS + 50);
    let evidence = truncate_evidence(&long);
    assert_eq!(
        evidence.chars().count(),
        SUBMITTED_INPUT_EVIDENCE_MAX_CHARS + 1,
        "truncated to the cap plus the ellipsis marker"
    );
    assert!(evidence.ends_with('…'));
    assert_eq!(truncate_evidence("  fix the bug  "), "fix the bug");
}

/// A worker telemetry row as the ingest seam stores it, for the
/// worker->gateway bridge tests.
fn worker_report(
    run_id: &str,
    organization_id: &str,
    id: &str,
    kind: &str,
    event_json: &str,
    occurred_at_unix: u64,
) -> ferrogate_storage::StoredSelfHostedWorkerTelemetryEvent {
    ferrogate_storage::StoredSelfHostedWorkerTelemetryEvent {
        id: id.to_string(),
        worker_id: "worker-1".to_string(),
        tenant: tenant(organization_id),
        workspace_id: "ws-1".to_string(),
        session_id: Some(format!("agent-job-session-{run_id}")),
        run_id: Some(run_id.to_string()),
        kind: kind.to_string(),
        trust_level: "reported_by_self_hosted_worker".to_string(),
        occurred_at_unix: Some(occurred_at_unix),
        ingested_at_unix: Some(occurred_at_unix),
        event_json: event_json.to_string(),
        request_id: Some("fg-submit".to_string()),
        trace_id: None,
        agent_run_id: Some(run_id.to_string()),
        parent_action_fingerprint: None,
    }
}

#[test]
fn a_worker_run_report_terminalizes_the_job_and_carries_its_output() {
    // The #474 rework's central blocker: before the bridge, NOTHING on the
    // worker -> gateway path advanced `agent_runs.status`, so a job the runtime
    // finished reported `queued` forever and `/result` was a permanent 409.
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "fix-issue-474");
    state.record_agent_run(queued_run(&run_id, "tenant-a"));

    // Progress first: the run leaves `queued` but is NOT collectable yet.
    let running = state.apply_worker_reported_run_state(&worker_report(
        &run_id,
        "tenant-a",
        "evt-1",
        "lifecycle",
        r#"{"state":"started"}"#,
        150,
    ));
    assert_eq!(running.as_deref(), Some("running"));
    let stored = state.agent_run_record(&run_id).expect("run record");
    assert_eq!(stored.status, "running");
    assert!(!agent_job_status_is_terminal(&stored.status));

    // Then the completion, carrying the work product (#472's diff/PR lands
    // here) as the terminal output.
    let completed = state.apply_worker_reported_run_state(&worker_report(
        &run_id,
        "tenant-a",
        "evt-2",
        "run.completed",
        r#"{"state":"completed","turns_executed":7,"output":"opened PR #1234"}"#,
        200,
    ));
    assert_eq!(completed.as_deref(), Some("completed"));
    let stored = state.agent_run_record(&run_id).expect("run record");
    assert_eq!(stored.status, "completed");
    assert!(agent_job_status_is_terminal(&stored.status));
    assert_eq!(stored.turns_executed, 7);
    assert!(stored.output_recorded);
    assert_eq!(stored.completed_at_unix, Some(200));

    // ...and `/result` reads that output off the run's own timeline.
    let timeline = state
        .agent_run_timeline(
            &run_id,
            AgentRunFilter {
                organization_id: Some("tenant-a".to_string()),
                ..AgentRunFilter::default()
            },
        )
        .expect("the job's timeline");
    assert_eq!(agent_job_status(&timeline), "completed");
    assert_eq!(
        agent_job_output(&timeline).as_deref(),
        Some("opened PR #1234"),
        "/result must return the runtime's real output, not null"
    );

    // A late/duplicate report can never rewrite a collected result.
    assert_eq!(
        state.apply_worker_reported_run_state(&worker_report(
            &run_id,
            "tenant-a",
            "evt-3",
            "run.failed",
            r#"{"state":"failed","output":"rewritten"}"#,
            300,
        )),
        None
    );
    assert_eq!(
        state.agent_run_record(&run_id).expect("run record").status,
        "completed"
    );
}

#[test]
fn a_worker_cannot_report_state_onto_another_tenants_run() {
    // The bridge writes the canonical run row, so it is a privileged seam: a
    // worker registered to tenant B must not be able to terminalize (or attach
    // output to) tenant A's job by naming its id.
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "fix-issue-474");
    state.record_agent_run(queued_run(&run_id, "tenant-a"));

    assert_eq!(
        state.apply_worker_reported_run_state(&worker_report(
            &run_id,
            "tenant-b",
            "evt-x",
            "run.completed",
            r#"{"state":"completed","output":"exfiltrated"}"#,
            200,
        )),
        None
    );
    let stored = state.agent_run_record(&run_id).expect("run record");
    assert_eq!(stored.status, "queued");
    assert!(!stored.output_recorded);

    // A report naming a run the control plane does not own at all is ignored
    // rather than fabricating a run row.
    assert_eq!(
        state.apply_worker_reported_run_state(&worker_report(
            "job-unknown",
            "tenant-b",
            "evt-y",
            "run.completed",
            r#"{"state":"completed"}"#,
            200,
        )),
        None
    );
    assert!(state.agent_run_record("job-unknown").is_none());
}

#[test]
fn a_cancel_on_a_replica_that_never_served_the_submit_still_reaches_the_runtime() {
    // #474 rework: `self_hosted_dispatch_for_run` used to scan ONLY the
    // in-process queue, so on a replica that did not serve the submit the
    // cancel found no start dispatch, enqueued no `cancel_run`, and still
    // answered 200 while the worker kept running. The durable fallback closes
    // that: the peer's row IS the dispatch.
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "cancel-across-nodes");
    let dispatch = start_dispatch(&run_id, "tenant-a");
    state
        .enqueue_scheduled_self_hosted_dispatch(dispatch.clone())
        .expect("the submitting node enqueues + persists the start dispatch");

    // Simulate the OTHER replica: same durable rows, empty in-process queue.
    let persisted =
        crate::gateway::block_on_sync_bridge(state.repositories_arc().self_hosted_run_dispatches())
            .into_iter()
            .find(|record| record.run_id == run_id)
            .expect("the submit persisted a durable dispatch row");
    let replica = AppState::new(Config::default());
    crate::gateway::block_on_sync_bridge(
        replica
            .repositories_arc()
            .upsert_self_hosted_run_dispatch(persisted),
    )
    .expect("the replica reads the same durable table");
    assert!(
        !replica.self_hosted_dispatch_unacked(&agent_job_start_dispatch_id(&run_id)),
        "the replica's in-process lease queue genuinely does not hold the dispatch"
    );

    let resolved = replica
        .self_hosted_dispatch_for_run(&run_id, SelfHostedRunAction::StartRun)
        .expect("the replica resolves the start dispatch from durable storage");
    assert_eq!(resolved.dispatch_id, dispatch.dispatch_id);
    assert_eq!(resolved.framework_adapter, dispatch.framework_adapter);
    assert_eq!(resolved.session_id, dispatch.session_id);

    let run = queued_run(&run_id, "tenant-a");
    replica.record_agent_run(run.clone());
    assert_eq!(
        cancel_agent_job_in_runtime(&replica, &run, "fg-cancel", 300),
        Ok(true),
        "the cancel must actually reach the runtime transport from any replica"
    );
}

#[test]
fn a_submitted_job_survives_a_restart_of_the_serving_component() {
    // Acceptance box 5. The durable state a restart must preserve is (a) the
    // `agent_runs` row the caller polls and (b) the start dispatch the runtime
    // leases. A fresh AppState over the SAME repositories is exactly what
    // `try_new_with_repositories` builds on restart: it rebuilds the in-process
    // lease queue from `self_hosted_run_dispatches` and reads the run row
    // straight out of storage.
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "survive-a-restart");
    state
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&run_id, "tenant-a"))
        .expect("submit enqueues + persists the start dispatch");
    state.record_agent_run(queued_run(&run_id, "tenant-a"));

    let dispatch_rows =
        crate::gateway::block_on_sync_bridge(state.repositories_arc().self_hosted_run_dispatches());
    let run_row = state.agent_run_record(&run_id).expect("run row");
    drop(state);

    // Restart: brand-new process state, nothing carried in memory.
    let restarted = AppState::new(Config::default());
    crate::gateway::block_on_sync_bridge(restarted.repositories_arc().upsert_agent_run(run_row))
        .expect("the run row is durable");
    for record in dispatch_rows
        .into_iter()
        .filter(|record| record.run_id == run_id)
    {
        crate::gateway::block_on_sync_bridge(
            restarted
                .repositories_arc()
                .upsert_self_hosted_run_dispatch(record),
        )
        .expect("the dispatch row is durable");
    }
    restarted
        .rebuild_self_hosted_worker_dispatch_runtime()
        .expect("startup rebuilds the lease queue from the durable dispatch table");

    // The caller can still address the job by the id it was handed...
    let recovered = restarted.agent_run_record(&run_id).expect("run survives");
    assert_eq!(recovered.status, "queued");
    assert!(!agent_job_status_is_terminal(&recovered.status));
    // ...and the runtime can still lease its work.
    assert!(
        restarted.self_hosted_dispatch_unacked(&agent_job_start_dispatch_id(&run_id)),
        "the start dispatch is back in the lease queue after the restart"
    );
    let dispatch = restarted
        .self_hosted_dispatch_for_run(&run_id, SelfHostedRunAction::StartRun)
        .expect("the restarted node resolves the job's start dispatch");
    assert_eq!(dispatch.run_id, run_id);
    assert_eq!(dispatch.framework_adapter, "claude-code");
}

#[test]
fn only_single_segment_run_ids_are_addressable() {
    assert!(is_addressable_run_id("job-abc"));
    assert!(!is_addressable_run_id(""));
    assert!(!is_addressable_run_id("job-abc/events/extra"));
}

/// #472's "retrievable through the control plane" rides THIS route rather than
/// a parallel work-product surface: the diff is published as one artifact event
/// on the run timeline the result verb already reads, and the read re-derives
/// attribution instead of trusting the worker-reported payload.
#[test]
fn a_coding_runs_work_product_is_retrievable_from_the_job_result_and_is_tenant_scoped() {
    use ferrogate_runtime::coding_agent::{
        CodingRunIdentity, DiffStats, PinnedRef, ProducedBranch, RepoCoordinates, UnifiedDiff,
        WorkProduct, WorkProductArtifact, WorkProductView, WORK_PRODUCT_ARTIFACT_EVENT_KIND,
    };

    const BASE: &str = "1111111111111111111111111111111111111111";
    const HEAD: &str = "3333333333333333333333333333333333333333";

    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "fix-the-widget");
    let repo = RepoCoordinates::new("github", "github.com", "acme", "widget").expect("repo");
    let product = WorkProduct::assemble(
        CodingRunIdentity::new("tenant-a", "session-1", &run_id),
        repo,
        PinnedRef::new(BASE).expect("pin"),
        Some(
            ProducedBranch::new(
                "ferrogate/run-fix",
                HEAD,
                PinnedRef::new(BASE).expect("pin"),
            )
            .expect("branch"),
        ),
        UnifiedDiff::inline("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n").expect("diff"),
        DiffStats {
            files_changed: 1,
            insertions: 1,
            deletions: 1,
        },
        None,
        1_200,
    )
    .expect("work product");
    let envelope = WorkProductArtifact::new(product.clone(), None)
        .to_event_json()
        .expect("envelope");

    let (worker, _secret) = state
        .register_self_hosted_worker(crate::responses::AdminSelfHostedWorkerRegistrationRequest {
            tenant: tenant("tenant-a"),
            workspace_id: "ws-1".to_string(),
            worker_name: "coding-worker".to_string(),
            identity_fingerprint: "sha256:worker".to_string(),
            identity_expires_at_unix: None,
            orchestration_enabled: true,
            capability_envelope_json: None,
        })
        .expect("worker registers");

    // `artifact` is already an accepted telemetry kind, so publishing a work
    // product needs no new event kind, no new table, and no new route.
    for (kind, event_json) in [
        (WORK_PRODUCT_ARTIFACT_EVENT_KIND, envelope.as_str()),
        // An artifact on the same run that is not a work product must be
        // skipped, not fail the read.
        ("artifact", r#"{"object":"container.artifact"}"#),
        ("lifecycle", r#"{"state":"completed"}"#),
    ] {
        state
            .record_self_hosted_worker_telemetry_event(
                &worker.id,
                crate::responses::AdminSelfHostedWorkerTelemetryEventRequest {
                    session_id: "session-1".to_string(),
                    run_id: run_id.clone(),
                    kind: kind.to_string(),
                    occurred_at_unix: Some(120),
                    event_json: Some(event_json.to_string()),
                },
                ferrogate_runtime::SelfHostedRunEvidenceCorrelation::default(),
            )
            .expect("telemetry event is accepted");
    }

    // Exactly the expression `handle_agent_job_result` evaluates.
    let timeline = state
        .self_hosted_run_timeline(&run_id, Some("tenant-a"))
        .expect("the owning tenant sees its own run");
    let work_products = WorkProductView::from_timeline_events(
        timeline
            .events
            .iter()
            .map(|event| (event.kind.as_str(), event.event_json.as_str())),
        &run_id,
    );
    assert_eq!(work_products.len(), 1);
    let view = &work_products[0];
    assert_eq!(view.product_id, product.product_id());
    assert_eq!(view.repo_id, "github:github.com/acme/widget");
    assert_eq!(view.head_commit.as_deref(), Some(HEAD));
    assert!(view.attribution_verified, "the id re-derives for this run");
    assert!(view.repo_verified);
    assert!(view.published.is_none(), "nothing was pushed");

    // Tenant isolation is the timeline read's, applied before anything is
    // shaped: another tenant gets no timeline, so no work product.
    assert!(state
        .self_hosted_run_timeline(&run_id, Some("tenant-b"))
        .is_none());
}
