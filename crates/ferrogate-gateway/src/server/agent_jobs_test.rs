// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Unit tests for the caller-facing async agent-job surface (#474).

//! Proves the four properties the async job protocol is judged on, without a
//! live HTTP session: idempotent submission (a retry addresses the ORIGINAL
//! run), tenant isolation on every read, cancellation that STOPS THE WORK in
//! the runtime AND terminalizes the run, and a stable incremental event cursor.
//!
//! #551 settled what "stops the work" means, and it is not "a `cancel_run`
//! dispatch exists": a job no worker has leased is stopped by WITHDRAWING its
//! start dispatch, and a job a worker holds is stopped by handing that holder
//! a `cancel_run`. Both arms are asserted here, and so are the two places the
//! withdrawal alone does not reach -- a worker racing the cancel for the same
//! dispatch, and a peer replica whose rebuilt queue holds its own copy.

use super::*;
use ferrogate_config::Config;
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
fn cancel_stops_the_work_in_the_runtime_and_terminalizes_the_run() {
    // Was `cancel_dispatches_a_runtime_cancel_and_terminalizes_the_run`, which
    // asserted that EVERY cancel enqueues a `cancel_run`. #502 falsified that
    // assertion, and the invariant under it genuinely MOVED rather than merely
    // going stale: minting a `cancel_run` for a job no worker holds told nobody
    // anything (there is no holder to lease it), left the start dispatch in the
    // lease queue where a worker could still pick it up and START the cancelled
    // work, and left two permanent rows behind in a table nothing deleted. The
    // property the old assertion was standing in for -- "a cancel actually
    // stops the work in the runtime" -- is what is asserted here, on BOTH arms,
    // because it is the property and not the mechanism that must hold.
    let state = AppState::new(Config::default());
    let (_worker_id, identity) = register_job_worker(&state, "tenant-a");

    // Arm 1 -- nobody on this node holds it. Withdrawal is the local remedy:
    // out of this lease queue, with no `cancel_run` addressed at a worker that
    // does not exist. The durable row is removed separately as settled work,
    // never because this process pretended its local copy was unique.
    let idle_id = agent_job_run_id("tenant-a", "cancel-me");
    state
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&idle_id, "tenant-a"))
        .expect("submit enqueues the start dispatch");
    let idle = queued_run(&idle_id, "tenant-a");
    state.record_agent_run(idle.clone());
    assert_eq!(
        cancel_agent_job(&state, &idle, "fg-cancel", 200),
        Ok(AgentJobCancelDecision {
            status: "cancelled".to_string(),
            cancelled: true,
            runtime_cancel_dispatched: false,
            cancelled_at_unix: Some(200),
        }),
        "an unleased job has no holder to tell, so it is withdrawn, not dispatched at"
    );
    assert!(
        state
            .self_hosted_dispatch_for_run(&idle_id, SelfHostedRunAction::CancelRun)
            .is_none(),
        "no cancel_run may be minted for work no worker ever held"
    );
    assert!(
        !state.self_hosted_dispatch_unacked(&agent_job_start_dispatch_id(&idle_id)),
        "the withdrawn start dispatch is gone from the lease queue"
    );
    assert!(
        !durable_dispatch_ids(&state).contains(&agent_job_start_dispatch_id(&idle_id)),
        "settled-run cleanup reclaims the row after the node-local withdrawal"
    );

    // Arm 2 -- a worker holds it. Now there IS somebody to tell, and the
    // `cancel_run` has to address the same worker shape the start dispatch did
    // or the holder cannot lease it.
    let held_id = agent_job_run_id("tenant-a", "cancel-me-while-held");
    state
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&held_id, "tenant-a"))
        .expect("submit enqueues the start dispatch");
    let run = queued_run(&held_id, "tenant-a");
    state.record_agent_run(run.clone());
    let lease = poll_for_lease(&state, &identity, 1_000).expect("the worker leases the job");
    assert_eq!(
        lease.dispatch_id,
        agent_job_start_dispatch_id(&held_id),
        "the worker must have leased the submitted job, not the registration seed"
    );

    let decision =
        cancel_agent_job(&state, &run, "fg-cancel", 1_050).expect("cancel reaches the transport");
    assert!(
        decision.runtime_cancel_dispatched,
        "a job a worker HOLDS must have its cancel reach the runtime"
    );

    let cancel = state
        .self_hosted_dispatch_for_run(&held_id, SelfHostedRunAction::CancelRun)
        .expect("a cancel_run dispatch is queued for the runtime to lease");
    assert_eq!(cancel.dispatch_id, agent_job_cancel_dispatch_id(&held_id));
    assert_eq!(cancel.action, SelfHostedRunAction::CancelRun);
    assert_eq!(cancel.run_id, held_id);
    // The cancel addresses the SAME worker shape the start dispatch targeted,
    // so the worker that owns the run can lease it.
    assert_eq!(cancel.framework_adapter, "claude-code");
    assert_eq!(cancel.session_id, format!("agent-job-session-{held_id}"));
    assert_eq!(cancel.tenant_id, "tenant-a");
    // The holder's start dispatch is NOT withdrawn -- its ack still has to
    // resolve. It is superseded instead (asserted through the real poll seam by
    // `cancelling_an_already_leased_job_supersedes_its_start_dispatch`).
    assert!(
        durable_dispatch_ids(&state).contains(&agent_job_start_dispatch_id(&held_id)),
        "the holder's start dispatch survives the cancel so its ack can resolve"
    );

    // The run itself is terminal, and the cancel wrote it -- not the test.
    let stored = state.agent_run_record(&held_id).expect("run record");
    assert_eq!(stored.status, "cancelled");
    assert_eq!(stored.completed_at_unix, Some(1_050));
    assert!(agent_job_status_is_terminal(&stored.status));

    // Cancelling a job the runtime never accepted is not an error; there is
    // simply no transport dispatch to address.
    let orphan = queued_run("job-orphan", "tenant-a");
    assert_eq!(
        cancel_agent_job(&state, &orphan, "fg-cancel", 200),
        Ok(AgentJobCancelDecision {
            status: "cancelled".to_string(),
            cancelled: true,
            runtime_cancel_dispatched: false,
            cancelled_at_unix: Some(200),
        })
    );
}

#[test]
fn stopping_the_work_before_its_run_row_is_settled_is_refused() {
    // The ORDERING guard, which is the whole of #551's cross-replica fix and
    // is otherwise invisible: a cancel withdraws only this node's in-memory
    // copy while a peer may still hold the same dispatch. The settled
    // `agent_runs` row is what makes every peer copy unstartable. On the durable
    // backend that row is written through a background evidence writer that
    // returns before the write lands and drops the job outright under
    // back-pressure, so "write it afterwards" is a window a peer can poll
    // inside -- and did, in the arm the withdrawal exists to close.
    //
    // `cancel_agent_job` therefore settles FIRST and `cancel_agent_job_in_runtime`
    // refuses until it can READ the settled row back out of the store. Deleting
    // that guard reddens the first half here (the withdrawal would succeed on a
    // `queued` run and its local copy would be gone); swapping the settle and
    // the withdrawal in `cancel_agent_job` reddens the second, because the store
    // still answers `queued` when the guard runs and the cancel 503s.
    // `the_ordering_guard_reads_the_settled_row_not_the_callers_struct` is what
    // holds the guard to reading the store rather than the struct it is handed.
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "settle-before-withdraw");
    state
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&run_id, "tenant-a"))
        .expect("submit enqueues the start dispatch");
    let open = queued_run(&run_id, "tenant-a");
    state.record_agent_run(open.clone());

    let refusal = cancel_agent_job_in_runtime(&state, &open, "fg-cancel", 200)
        .expect_err("withdrawing the work of a run that is not yet settled must be refused");
    assert!(
        refusal.contains(&run_id),
        "the refusal must name the job it protected: {refusal}"
    );
    // Refused means UNTOUCHED -- the caller retries against intact state.
    assert!(
        durable_dispatch_ids(&state).contains(&agent_job_start_dispatch_id(&run_id)),
        "a refused cancel must destroy nothing"
    );
    assert!(state.self_hosted_dispatch_unacked(&agent_job_start_dispatch_id(&run_id)));

    // And the ordering the guard enforces is the one `cancel_agent_job` runs:
    // by the time the local queue entry is gone, the settled row a peer reads
    // is already durable.
    cancel_agent_job(&state, &open, "fg-cancel", 300).expect("the ordered cancel is accepted");
    assert_eq!(
        state
            .agent_run_record(&run_id)
            .expect("the cancel settled the run")
            .status,
        "cancelled"
    );
    assert!(
        !durable_dispatch_ids(&state).contains(&agent_job_start_dispatch_id(&run_id)),
        "separate settled-run cleanup reclaims the durable row after withdrawal"
    );
    assert!(!state.self_hosted_dispatch_unacked(&agent_job_start_dispatch_id(&run_id)));
}

#[test]
fn the_ordering_guard_reads_the_settled_row_not_the_callers_struct() {
    // Two ways the withdrawal could still strand a runnable peer copy while
    // the settled row meant to stop it is unreadable, and the one guard that
    // closes both.
    //
    // The guard used to test `run.status` -- the CALLER's struct, which
    // `cancel_agent_job` stamps `cancelled` before either statement runs. It
    // therefore passed whichever order the settle and the withdrawal ran in,
    // and it passed just as happily when the settle's write never landed: on
    // the durable backend `EvidenceWriter` counts an `upsert_agent_run` that
    // returned `Err` as processed, so `flush()` reports success for a row that
    // is not in the store.
    //
    // Reading the STORE separates all three states. Arm 1 is the reordering
    // (struct says cancelled, the row still says queued); arm 2 is the lost
    // write (struct says cancelled, there is no row at all -- which is exactly
    // what a swallowed upsert leaves behind, and is reachable on the in-memory
    // backend because absence and a failed write are the same state to a
    // reader). Reverting the guard to `agent_job_status_is_terminal(&run.status)`
    // reddens both arms.
    let state = AppState::new(Config::default());

    // Arm 1 -- reordered. The durable row is the `queued` one the submit wrote.
    let reordered_id = agent_job_run_id("tenant-a", "guard-reads-the-store");
    let reordered_dispatch_id = agent_job_start_dispatch_id(&reordered_id);
    state
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&reordered_id, "tenant-a"))
        .expect("submit enqueues the start dispatch");
    state.record_agent_run(queued_run(&reordered_id, "tenant-a"));
    let mut claims_settled = queued_run(&reordered_id, "tenant-a");
    claims_settled.status = "cancelled".to_string();
    claims_settled.completed_at_unix = Some(200);
    let refusal = cancel_agent_job_in_runtime(&state, &claims_settled, "fg-cancel", 200)
        .expect_err("a struct that says cancelled is not a row a peer can read");
    assert!(
        refusal.contains(&reordered_id),
        "the refusal must name the job it protected: {refusal}"
    );
    assert!(
        durable_dispatch_ids(&state).contains(&reordered_dispatch_id),
        "a refused cancel must destroy nothing"
    );
    assert!(state.self_hosted_dispatch_unacked(&reordered_dispatch_id));

    // Arm 2 -- the settle reported success and wrote nothing.
    let lost_id = agent_job_run_id("tenant-a", "guard-survives-a-lost-write");
    let lost_dispatch_id = agent_job_start_dispatch_id(&lost_id);
    state
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&lost_id, "tenant-a"))
        .expect("submit enqueues the start dispatch");
    let mut never_written = queued_run(&lost_id, "tenant-a");
    never_written.status = "cancelled".to_string();
    never_written.completed_at_unix = Some(200);
    assert!(
        state.agent_run_record(&lost_id).is_none(),
        "the premise of this arm is that the settle's write is not in the store"
    );
    let lost = cancel_agent_job_in_runtime(&state, &never_written, "fg-cancel", 200)
        .expect_err("a settle whose write did not land must not license destroying evidence");
    assert!(
        lost.contains(&lost_id),
        "the refusal must name the job it protected: {lost}"
    );
    assert!(
        durable_dispatch_ids(&state).contains(&lost_dispatch_id),
        "...so the row a peer could still be superseded by survives for the retry"
    );

    // The control. Once the row genuinely IS in the store, the same call on the
    // same struct withdraws the local copy -- so neither refusal above is a
    // guard that simply refuses everything, which is the shape #500 exists
    // about.
    assert!(
        state.settle_agent_run_record(never_written.clone()),
        "the in-memory settle must actually land, or the control proves nothing"
    );
    assert_eq!(
        cancel_agent_job_in_runtime(&state, &never_written, "fg-cancel", 200),
        Ok(false),
        "an unleased job whose run row is genuinely settled is withdrawn, not dispatched at"
    );
    assert!(
        durable_dispatch_ids(&state).contains(&lost_dispatch_id),
        "local withdrawal must retain the shared row until settled-run reclaim"
    );
    assert!(!state.self_hosted_dispatch_unacked(&lost_dispatch_id));
}

#[test]
fn a_retried_cancel_on_a_settled_job_reclaims_the_rows_it_stranded() {
    // The already-terminal branch of `cancel_agent_job`, which is reachable
    // only from the cancel route and which every reclaim test used to reach by
    // calling `reclaim_settled_run_dispatches` directly -- so deleting the call
    // from the branch itself reddened nothing. It is a real remedy: a run that
    // settled through worker telemetry leaves this node's dispatch rows behind,
    // an operator retries the cancel, and the retry has to drain them rather
    // than answering `cancelled: false` and leaving them where they were.
    let state = AppState::new(Config::default());
    let run_id =
        try_submit_job(&state, "tenant-a", "retry-cancel-after-settle").expect("submitted");
    let stranded = agent_job_start_dispatch_id(&run_id);

    // Settled by some OTHER route than this handler (worker telemetry).
    let mut reported = state.agent_run_record(&run_id).expect("run row");
    reported.status = "completed".to_string();
    reported.completed_at_unix = Some(400);
    state.record_agent_run(reported.clone());
    assert!(
        durable_dispatch_ids(&state).contains(&stranded),
        "the settle left the dispatch row behind, which is the condition being repaired"
    );

    let decision = cancel_agent_job(&state, &reported, "fg-cancel-retry", 500)
        .expect("a retried cancel is answered, not refused");
    assert_eq!(
        decision,
        AgentJobCancelDecision {
            status: "completed".to_string(),
            cancelled: false,
            runtime_cancel_dispatched: false,
            cancelled_at_unix: Some(400),
        },
        "a retried cancel must not re-terminalize the run or restate its end time"
    );
    assert!(
        !durable_dispatch_ids(&state).contains(&stranded),
        "the retried cancel must actually drain the stranded rows: {:?}",
        durable_dispatch_ids(&state)
    );
    assert!(
        !state.self_hosted_dispatch_unacked(&stranded),
        "...out of this node's lease queue as well as the durable table"
    );
}

#[test]
fn the_published_meaning_of_runtime_cancel_dispatched_matches_the_code() {
    // The field means one thing and had been written down twice, differing:
    // the published description said a `cancel_run` "happens only when a worker
    // had already leased the job", which
    // `a_cancel_on_a_replica_that_never_served_the_submit_still_reaches_the_runtime`
    // disproves -- a cancel served by a replica that holds no copy dispatches
    // one with nobody having leased anything. Nothing read both copies, so the
    // drift survived a review and a rework; `check-openapi.py` compares shapes,
    // not prose, and would pass on any wording at all.
    //
    // This is the reader that makes them one artifact. Editing either side
    // alone reddens it.
    const SPEC: &str = include_str!("../../../../docs/openapi/admin-api.openapi.json");
    let spec: serde_json::Value = serde_json::from_str(SPEC).expect("the OpenAPI document parses");
    let published = spec["components"]["schemas"]["AgentJobCancelResponse"]["properties"]
        ["runtime_cancel_dispatched"]["description"]
        .as_str()
        .expect("the published field carries a description");
    assert_eq!(
        published, RUNTIME_CANCEL_DISPATCHED_DESCRIPTION,
        "the published meaning of runtime_cancel_dispatched has drifted from the code"
    );
    // The claim the old wording made, named so it cannot come back by accident.
    assert!(
        !published.contains("only when a worker had already leased"),
        "a peer-served cancel dispatches one with no worker having leased the job"
    );
    assert!(
        !published.contains("held the only copy"),
        "a node-local queue cannot prove that no peer restored the durable StartRun row"
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
    worker_id: &str,
    id: &str,
    kind: &str,
    event_json: &str,
    occurred_at_unix: u64,
) -> ferrogate_storage::StoredSelfHostedWorkerTelemetryEvent {
    ferrogate_storage::StoredSelfHostedWorkerTelemetryEvent {
        id: id.to_string(),
        worker_id: worker_id.to_string(),
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

/// #503: lease `run_id`'s start dispatch to `worker_id` directly through the
/// durable `self_hosted_run_dispatches` row -- the same direct-construction
/// pattern `a_cancel_on_a_replica_that_never_served_the_submit_still_reaches_the_runtime`
/// already uses -- rather than driving a full register/poll handshake that is
/// irrelevant to what these tests are proving (lease-ownership enforcement in
/// `apply_worker_reported_run_state`, not the poll protocol itself).
fn lease_start_dispatch_to_worker(
    state: &AppState,
    run_id: &str,
    organization_id: &str,
    worker_id: &str,
) {
    let dispatch = start_dispatch(run_id, organization_id);
    let lease_id = format!("{}:attempt-1", dispatch.dispatch_id);
    let stored = ferrogate_storage::StoredSelfHostedRunDispatch {
        dispatch_id: dispatch.dispatch_id,
        action: "start_run".to_string(),
        tenant_id: dispatch.tenant_id,
        workspace_id: dispatch.workspace_id,
        session_id: dispatch.session_id,
        run_id: dispatch.run_id,
        framework_adapter: dispatch.framework_adapter,
        required_capabilities: dispatch.required_capabilities,
        workload_ref: dispatch.workload_ref,
        queued_at_unix: Some(dispatch.queued_at_unix),
        assigned_worker_id: Some(worker_id.to_string()),
        lease_id: Some(lease_id),
        lease_expires_at_unix: Some(u64::MAX),
        attempt: 1,
        acknowledged_status: None,
        acknowledged_at_unix: None,
        request_id: dispatch.request_id,
        trace_id: dispatch.trace_id,
        agent_run_id: dispatch.agent_run_id,
        parent_action_fingerprint: dispatch.parent_action_fingerprint,
    };
    ferrogate_sync_bridge::block_on_sync_bridge(
        state
            .repositories_arc()
            .upsert_self_hosted_run_dispatch(stored),
    )
    .expect("leased dispatch row persists");
}

#[test]
fn a_worker_run_report_terminalizes_the_job_and_carries_its_output() {
    // The #474 rework's central blocker: before the bridge, NOTHING on the
    // worker -> gateway path advanced `agent_runs.status`, so a job the runtime
    // finished reported `queued` forever and `/result` was a permanent 409.
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "fix-issue-474");
    state.record_agent_run(queued_run(&run_id, "tenant-a"));
    // #503: the run-state bridge only applies a report from the worker that
    // actually holds the run's dispatch lease.
    lease_start_dispatch_to_worker(&state, &run_id, "tenant-a", "worker-1");

    // Progress first: the run leaves `queued` but is NOT collectable yet.
    let running = state.apply_worker_reported_run_state(&worker_report(
        &run_id,
        "tenant-a",
        "worker-1",
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
        "worker-1",
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
            "worker-1",
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
    lease_start_dispatch_to_worker(&state, &run_id, "tenant-a", "worker-1");

    assert_eq!(
        state.apply_worker_reported_run_state(&worker_report(
            &run_id,
            "tenant-b",
            "worker-1",
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
            "worker-1",
            "evt-y",
            "run.completed",
            r#"{"state":"completed"}"#,
            200,
        )),
        None
    );
    assert!(state.agent_run_record("job-unknown").is_none());
}

/// Gate (#474): the run-row-must-exist guard, isolated from the guards that
/// were masking it. The existing unknown-run assertion in
/// `a_worker_cannot_report_state_onto_another_tenants_run` names a run with NO
/// dispatch, so the #503 lease guard rejects it before the existence check is
/// ever reached -- deleting `let run = self.agent_run_record(run_id)?;` and
/// fabricating a run row from the report leaves that assertion green.
///
/// Here the reporting worker genuinely holds the run's `StartRun` lease and
/// reports its own tenant, so the lease and tenant guards both PASS; the only
/// thing standing between the report and a fabricated `agent_runs` row is the
/// existence check. This is reachable in production whenever a dispatch row
/// outlives (or precedes) its `agent_runs` row -- a run enqueued through a
/// non-agent-job path, or a run row pruned while its dispatch is still leased.
#[test]
fn a_worker_report_for_a_leased_dispatch_with_no_run_row_fabricates_nothing() {
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "no-run-row-474");
    // Deliberately: NO `record_agent_run` -- the dispatch exists and is leased
    // to this very worker, but the canonical run row does not exist.
    lease_start_dispatch_to_worker(&state, &run_id, "tenant-a", "worker-1");
    assert!(
        state.agent_run_record(&run_id).is_none(),
        "precondition: the run row genuinely does not exist"
    );
    assert_eq!(
        ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories_arc().self_hosted_run_dispatches()
        )
        .into_iter()
        .find(|record| record.run_id == run_id && record.action == "start_run")
        .and_then(|record| record.assigned_worker_id),
        Some("worker-1".to_string()),
        "precondition: the reporting worker holds the lease, so the #503 lease \
         guard PASSES and cannot mask what this test is proving"
    );

    let result = state.apply_worker_reported_run_state(&worker_report(
        &run_id,
        "tenant-a",
        "worker-1",
        "evt-no-run-row",
        "run.completed",
        r#"{"state":"completed","turns_executed":3,"output":"fabricated"}"#,
        200,
    ));
    assert_eq!(
        result, None,
        "a report naming a run the control plane has no row for must be refused"
    );
    assert!(
        state.agent_run_record(&run_id).is_none(),
        "the bridge must never fabricate an agent_runs row out of worker telemetry"
    );
    // ...and it must not fabricate a timeline for the phantom run either, or
    // `/events` and `/result` would answer for a job that was never submitted.
    assert!(
        state
            .agent_run_timeline(
                &run_id,
                AgentRunFilter {
                    organization_id: Some("tenant-a".to_string()),
                    ..AgentRunFilter::default()
                },
            )
            .is_none(),
        "no run row means no addressable job timeline"
    );
}

/// #503: the core regression for the run-state bridge's lease-scope fix.
/// `worker-1` and `worker-2` both belong to `tenant-a` (a real cross-tenant
/// report is already covered by `a_worker_cannot_report_state_onto_another_tenants_run`);
/// only `worker-1` was ever dispatched/leased run A, so `worker-2` reporting
/// `run.completed` for it must be ignored exactly like a cross-tenant report
/// is -- a worker must not be able to complete a sibling worker's run just
/// because they share a tenant.
#[test]
fn a_worker_cannot_report_state_for_a_run_it_does_not_hold_the_lease_for() {
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "fix-issue-503");
    state.record_agent_run(queued_run(&run_id, "tenant-a"));
    lease_start_dispatch_to_worker(&state, &run_id, "tenant-a", "worker-1");

    let result = state.apply_worker_reported_run_state(&worker_report(
        &run_id,
        "tenant-a",
        "worker-2",
        "evt-intruder",
        "run.completed",
        r#"{"state":"completed","output":"stolen"}"#,
        200,
    ));
    assert_eq!(
        result, None,
        "a worker that does not hold the run's lease must not move its status"
    );
    let stored = state.agent_run_record(&run_id).expect("run record");
    assert_eq!(stored.status, "queued", "the run must remain unchanged");
    assert!(!stored.output_recorded);

    // The legitimate lease holder can still complete its own run.
    let completed = state.apply_worker_reported_run_state(&worker_report(
        &run_id,
        "tenant-a",
        "worker-1",
        "evt-owner",
        "run.completed",
        r#"{"state":"completed","output":"opened PR #9"}"#,
        201,
    ));
    assert_eq!(completed.as_deref(), Some("completed"));
}

/// #503: a run with no `StartRun` dispatch at all (submitted through a
/// non-worker path, or a run_id the worker path never enqueued) must reject
/// every worker report -- there is no lease to prove, so none is assumed.
#[test]
fn a_worker_cannot_report_state_for_a_run_with_no_dispatch_at_all() {
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "no-dispatch-503");
    state.record_agent_run(queued_run(&run_id, "tenant-a"));
    // Deliberately: no `lease_start_dispatch_to_worker` call, no
    // `enqueue_scheduled_self_hosted_dispatch` call either.

    let result = state.apply_worker_reported_run_state(&worker_report(
        &run_id,
        "tenant-a",
        "worker-1",
        "evt-1",
        "run.completed",
        r#"{"state":"completed"}"#,
        200,
    ));
    assert_eq!(result, None);
    assert_eq!(
        state.agent_run_record(&run_id).expect("run record").status,
        "queued"
    );
}

/// #503: a dispatch can exist (the job was submitted through the worker path)
/// without ever having been leased to anyone yet -- `assigned_worker_id` is
/// still `None`. That must be treated the same as "no dispatch at all", not as
/// "any worker may claim it".
#[test]
fn a_worker_cannot_report_state_for_a_dispatch_nobody_has_leased_yet() {
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "unleased-503");
    state.record_agent_run(queued_run(&run_id, "tenant-a"));
    state
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&run_id, "tenant-a"))
        .expect("submit enqueues the start dispatch");
    // Deliberately: the dispatch is queued but never leased (no poll/no
    // direct `assigned_worker_id` write).

    let result = state.apply_worker_reported_run_state(&worker_report(
        &run_id,
        "tenant-a",
        "worker-1",
        "evt-1",
        "run.completed",
        r#"{"state":"completed"}"#,
        200,
    ));
    assert_eq!(result, None);
    assert_eq!(
        state.agent_run_record(&run_id).expect("run record").status,
        "queued"
    );
}

#[test]
fn a_cancel_on_a_replica_that_never_served_the_submit_still_reaches_the_runtime() {
    // #474 rework: `self_hosted_dispatch_for_run` used to scan ONLY the
    // in-process queue, so on a replica that did not serve the submit the
    // cancel found no start dispatch, enqueued no `cancel_run`, and still
    // answered 200 while the worker kept running. The durable fallback closes
    // that: the peer's row IS the dispatch.
    //
    // #502's first cut regressed exactly this and this test caught it. Keying
    // the withdraw/dispatch choice on the LEASE OWNER alone made the peer-served
    // cancel take the withdraw arm (the durable row shows no assigned worker),
    // which deletes the durable row while the SUBMITTING replica's in-memory
    // copy stays queued and unacked -- and with no `cancel_run` anywhere, that
    // replica's superseded set is empty, so a worker polling it leases and
    // STARTS the cancelled job. Withdrawal is only a remedy for the node that
    // owns the runnable copy; every other node must leave durable `cancel_run`
    // evidence instead. That is what `Ok(true)` below is pinning.
    let state = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "cancel-across-nodes");
    let dispatch = start_dispatch(&run_id, "tenant-a");
    state
        .enqueue_scheduled_self_hosted_dispatch(dispatch.clone())
        .expect("the submitting node enqueues + persists the start dispatch");

    // Simulate the OTHER replica: same durable rows, empty in-process queue.
    let persisted = ferrogate_sync_bridge::block_on_sync_bridge(
        state.repositories_arc().self_hosted_run_dispatches(),
    )
    .into_iter()
    .find(|record| record.run_id == run_id)
    .expect("the submit persisted a durable dispatch row");
    let replica = AppState::new(Config::default());
    ferrogate_sync_bridge::block_on_sync_bridge(
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
    let decision =
        cancel_agent_job(&replica, &run, "fg-cancel", 300).expect("the cancel is accepted");
    assert!(
        decision.runtime_cancel_dispatched,
        "the cancel must actually reach the runtime transport from any replica"
    );
    // This receipt is also the counterexample to the description this field
    // carried until #551's rework: NO worker has leased anything here, and the
    // caller is still told `true`. `RUNTIME_CANCEL_DISPATCHED_DESCRIPTION` says
    // so, and `the_published_meaning_of_runtime_cancel_dispatched_matches_the_code`
    // holds the published copy to it.
    assert!(
        replica
            .self_hosted_dispatch_lease_owner(&run_id, SelfHostedRunAction::StartRun)
            .is_none(),
        "runtime_cancel_dispatched=true here with no lease owner at all, which is what the \
         published description used to deny"
    );

    // `Ok(true)` is only worth something if the evidence is really there, so
    // read it back the way the peer will: out of the DURABLE table, addressed
    // at the same worker shape the start dispatch targeted.
    let cancel_dispatch_id = agent_job_cancel_dispatch_id(&run_id);
    assert!(
        durable_dispatch_ids(&replica).contains(&cancel_dispatch_id),
        "the cancel_run must be persisted, not merely enqueued in this replica's memory: {:?}",
        durable_dispatch_ids(&replica)
    );
    let cancel = replica
        .self_hosted_dispatch_for_run(&run_id, SelfHostedRunAction::CancelRun)
        .expect("the replica queued a cancel_run for the runtime to lease");
    assert_eq!(cancel.dispatch_id, cancel_dispatch_id);
    assert_eq!(cancel.framework_adapter, dispatch.framework_adapter);
    assert_eq!(cancel.session_id, dispatch.session_id);
    assert_eq!(cancel.tenant_id, dispatch.tenant_id);

    // ...and the peer's start dispatch is NOT yanked out from under it. This
    // replica cannot remove the peer's in-memory copy, so deleting the durable
    // row would only destroy the evidence that a rebuild uses to supersede it.
    assert!(
        durable_dispatch_ids(&replica).contains(&dispatch.dispatch_id),
        "a peer-served cancel must not delete the durable row the holder still needs"
    );

    // The property the whole arm exists for: once the peer rebuilds its lease
    // queue from those durable rows, the cancelled job is no longer leasable.
    let rebuilt = AppState::new(Config::default());
    let (_worker_id, identity) = register_job_worker(&rebuilt, "tenant-a");
    for record in ferrogate_sync_bridge::block_on_sync_bridge(
        replica.repositories_arc().self_hosted_run_dispatches(),
    ) {
        ferrogate_sync_bridge::block_on_sync_bridge(
            rebuilt
                .repositories_arc()
                .upsert_self_hosted_run_dispatch(record),
        )
        .expect("the peer reads the same durable table");
    }
    rebuilt
        .rebuild_self_hosted_worker_dispatch_runtime()
        .expect("the peer rebuilds its lease queue from durable rows");
    for attempt in 0..4 {
        let Some(lease) = poll_for_lease(&rebuilt, &identity, 9_000 + attempt) else {
            break;
        };
        assert_ne!(
            lease.dispatch_id, dispatch.dispatch_id,
            "the cancel_run this replica wrote must stop the peer re-leasing the start dispatch"
        );
    }
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

    let dispatch_rows = ferrogate_sync_bridge::block_on_sync_bridge(
        state.repositories_arc().self_hosted_run_dispatches(),
    );
    let run_row = state.agent_run_record(&run_id).expect("run row");
    drop(state);

    // Restart: brand-new process state, nothing carried in memory.
    let restarted = AppState::new(Config::default());
    ferrogate_sync_bridge::block_on_sync_bridge(
        restarted.repositories_arc().upsert_agent_run(run_row),
    )
    .expect("the run row is durable");
    for record in dispatch_rows
        .into_iter()
        .filter(|record| record.run_id == run_id)
    {
        ferrogate_sync_bridge::block_on_sync_bridge(
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

// ---------------------------------------------------------------------------
// #502: the per-tenant submit budget, and what actually releases a slot.
//
// Before this slice the cap had NO test at all -- dropping the tenant filter,
// the acknowledged filter or the whole gate reddened nothing -- and the two
// remedies its own 429 named freed nothing: cancelling wrote no release at all,
// and the first cut of #502 released only on the runtime's ACK, which is not
// what the production completion path writes. A tenant with a perfectly healthy
// worker was still locked out after `cap` finished jobs.
//
// Every assertion below is on what the CALLER observes -- `agent_job_admit_submit`
// returns the verbatim status + error code the handler writes back, or `Ok` for
// the 202 path -- at the cap boundary, plus the durable rows a settled job must
// not leave behind.
// ---------------------------------------------------------------------------

/// Submits ONE genuinely new job for `tenant_id` exactly the way
/// `handle_agent_job_submit` does: gate-and-enqueue the start dispatch, then
/// claim the run row. `Err` is the refusal the caller would receive.
fn try_submit_job(
    state: &AppState,
    tenant_id: &str,
    idempotency_key: &str,
) -> Result<String, (StatusCode, &'static str, String)> {
    let run_id = agent_job_run_id(tenant_id, idempotency_key);
    agent_job_admit_submit(state, tenant_id, start_dispatch(&run_id, tenant_id))?;
    state.record_agent_run(queued_run(&run_id, tenant_id));
    Ok(run_id)
}

/// Submits `count` jobs that must all be admitted, returning their run ids in
/// submission order.
fn submit_open_jobs(
    state: &AppState,
    tenant_id: &str,
    key_prefix: &str,
    count: usize,
) -> Vec<String> {
    (0..count)
        .map(|index| {
            try_submit_job(state, tenant_id, &format!("{key_prefix}-{index}"))
                .unwrap_or_else(|refusal| panic!("submit {index} must be admitted: {refusal:?}"))
        })
        .collect()
}

/// Cancels `run_id` through the SAME function the route runs -- not a
/// hand-assembled imitation of it (#551 rework).
///
/// This helper used to call `cancel_agent_job_in_runtime` and then write the
/// terminal run row itself, in that order, which is precisely the ordering the
/// cancel path must NOT have; every caller of this helper was therefore
/// asserting against a sequence the product does not run, and the handler's
/// already-terminal repair branch was unreachable from any test at all.
fn cancel_open_job(state: &AppState, run_id: &str) {
    let run = state
        .agent_run_record(run_id)
        .expect("the job has a run row");
    let decision = cancel_agent_job(state, &run, "fg-cancel", 300)
        .expect("cancelling a live job must be accepted by the runtime transport");
    assert!(decision.cancelled, "the cancel must terminalize the run");
    assert!(
        !decision.runtime_cancel_dispatched,
        // No worker has leased these jobs, so there is nobody to hand a
        // `cancel_run` to -- the queued work is withdrawn instead.
        "an unleased job is withdrawn, not dispatched at"
    );
}

/// Registers a self-hosted worker able to lease the jobs `start_dispatch`
/// mints (same adapter, same capabilities), with its transport identity.
fn register_job_worker(
    state: &AppState,
    tenant_id: &str,
) -> (String, ferrogate_runtime::SelfHostedWorkerIdentity) {
    let (worker, transport_secret) = state
        .register_self_hosted_worker(crate::responses::AdminSelfHostedWorkerRegistrationRequest {
            tenant: tenant(tenant_id),
            workspace_id: "ws-1".to_string(),
            worker_name: "job-worker".to_string(),
            identity_fingerprint: "sha256:job-worker".to_string(),
            identity_expires_at_unix: Some(4_000_000_000),
            orchestration_enabled: true,
            capability_envelope_json: Some(
                r#"{"frameworks":["claude-code"],"capabilities":["shell"]}"#.to_string(),
            ),
        })
        .expect("worker registers");
    let identity = ferrogate_runtime::SelfHostedWorkerIdentity {
        tenant_id: tenant_id.to_string(),
        workspace_id: "ws-1".to_string(),
        worker_id: worker.id.clone(),
        token_id: "sha256:job-worker".to_string(),
        token_secret: transport_secret,
        observed_at_unix: None,
    };
    (worker.id, identity)
}

fn poll_for_lease(
    state: &AppState,
    identity: &ferrogate_runtime::SelfHostedWorkerIdentity,
    now_unix: u64,
) -> Option<ferrogate_runtime::SelfHostedRunLease> {
    state
        .poll_self_hosted_worker_run(ferrogate_runtime::SelfHostedRunPollRequest {
            protocol_version: 1,
            identity: identity.clone(),
            supported_capabilities: vec!["shell".to_string()],
            now_unix,
            lease_duration_secs: 60,
        })
        .expect("poll is accepted")
}

/// Every dispatch id the DURABLE `self_hosted_run_dispatches` table holds --
/// the rows read back in full at every startup and reload, and the thing #502's
/// reclaim has to actually shrink.
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

#[test]
fn the_submit_budget_admits_below_the_cap_and_refuses_exactly_at_it() {
    let state = AppState::new(Config::default());
    let opened = submit_open_jobs(&state, "tenant-a", "cap", AGENT_JOB_MAX_OPEN_PER_TENANT - 1);
    assert_eq!(opened.len(), AGENT_JOB_MAX_OPEN_PER_TENANT - 1);

    // cap-1 open: the LAST permitted submit is still admitted (the 202 path),
    // so `<` cannot be swapped for `<=` without reddening this.
    try_submit_job(&state, "tenant-a", "cap-last")
        .expect("a tenant one below the cap must still be able to submit");

    // The last slot is taken; the very next submit is refused.
    let (status, code, message) = try_submit_job(&state, "tenant-a", "cap-over")
        .expect_err("a tenant AT the cap must be refused");
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(code, "agent_job_open_limit_reached");
    assert!(
        message.contains(&format!(
            "tenant already has {AGENT_JOB_MAX_OPEN_PER_TENANT} agent jobs in flight"
        )),
        "the refusal reports the real open count: {message}"
    );
    // Every remedy the text names must be real (see the tests below): a run
    // reaching a terminal state, and cancelling on demand.
    assert!(
        message.contains("reaches a terminal state"),
        "the refusal must name the release condition that actually holds: {message}"
    );
    assert!(
        message.contains("/cancel"),
        "the refusal must name the verb that releases a slot on demand: {message}"
    );

    // A refused submit must leave nothing behind: the gate and the enqueue are
    // ONE operation, so a submit the budget rejects never lands a dispatch.
    let refused_dispatch_id =
        agent_job_start_dispatch_id(&agent_job_run_id("tenant-a", "cap-over"));
    assert!(
        !durable_dispatch_ids(&state).contains(&refused_dispatch_id),
        "a refused submit must enqueue nothing"
    );
}

#[test]
fn cancelling_a_job_frees_exactly_one_submit_slot_when_no_worker_will_ever_ack() {
    // The #502 lockout, reproduced: no worker is registered, so NOTHING on the
    // ack path will ever clear these dispatches. Cancel is the only remedy the
    // tenant has, and the 429 promises it works.
    let state = AppState::new(Config::default());
    let opened = submit_open_jobs(&state, "tenant-a", "lockout", AGENT_JOB_MAX_OPEN_PER_TENANT);
    assert!(
        try_submit_job(&state, "tenant-a", "at-cap").is_err(),
        "the tenant is at the cap"
    );

    cancel_open_job(&state, &opened[0]);
    try_submit_job(&state, "tenant-a", "after-one-cancel")
        .expect("cancelling must free the slot the 429 tells the caller to free");

    // Exactly ONE slot: that submit consumed it and the gate closes again, so
    // the release is per-cancel and not a blanket disabling of the cap.
    assert!(
        try_submit_job(&state, "tenant-a", "after-one-cancel-again").is_err(),
        "one cancel frees one slot, not the whole budget"
    );

    // Cancelling every remaining job clears the whole backlog, which is the
    // escape hatch a workerless tenant never had.
    for run_id in &opened[1..] {
        cancel_open_job(&state, run_id);
    }
    try_submit_job(&state, "tenant-a", "after-draining-the-backlog")
        .expect("a fully cancelled backlog must re-open the surface");
}

#[test]
fn a_submit_cancel_loop_leaves_no_permanent_dispatch_rows_behind() {
    // #502's retention half without reviving the unsafe ownership guess from
    // the first patch. Withdrawal touches only this node's queue; the separate
    // settled-run reclaim returns the durable rows. A submit -> cancel loop is
    // therefore bounded without claiming the serving node held a unique copy.
    let state = AppState::new(Config::default());
    let baseline = durable_dispatch_ids(&state);

    for round in 0..3 {
        let opened = submit_open_jobs(&state, "tenant-a", &format!("loop-{round}"), 5);
        assert_eq!(
            durable_dispatch_ids(&state).len(),
            baseline.len() + 5,
            "an open job holds exactly one durable dispatch row"
        );
        for run_id in &opened {
            cancel_open_job(&state, run_id);
        }
        assert_eq!(
            durable_dispatch_ids(&state),
            baseline,
            "round {round}: settled-run cleanup must reclaim every withdrawn row"
        );
    }
}

#[test]
fn a_worker_reported_completion_frees_a_submit_slot_and_reclaims_its_rows() {
    // The defect the first cut of #502 MOVED rather than removed. Release was
    // keyed on `acknowledged_status`, but the production completion path is
    // worker TELEMETRY (`apply_worker_reported_run_state`), which terminalizes
    // `agent_runs.status` and never touches the ack -- so a tenant with a
    // HEALTHY worker was still locked out after `cap` finished jobs, and
    // `POST .../cancel` on the now-terminal run answered `cancelled: false`
    // and wrote no release, leaving the slot unrecoverable by any caller.
    let state = AppState::new(Config::default());
    let (worker_id, identity) = register_job_worker(&state, "tenant-a");
    submit_open_jobs(
        &state,
        "tenant-a",
        "finished",
        AGENT_JOB_MAX_OPEN_PER_TENANT,
    );
    assert!(
        try_submit_job(&state, "tenant-a", "at-cap").is_err(),
        "the tenant is at the cap"
    );

    // The worker leases one of the submitted jobs -- and only LEASES it. It
    // never calls the ack seam, exactly like the worker in the HTTP e2e.
    let lease = poll_for_lease(&state, &identity, 1_000).expect("a queued job is leasable");
    assert!(
        lease
            .dispatch_id
            .starts_with(AGENT_JOB_START_DISPATCH_PREFIX),
        "the worker must have leased a submitted job, not the registration seed: {}",
        lease.dispatch_id
    );

    let completed = state.apply_worker_reported_run_state(&worker_report(
        &lease.run_id,
        "tenant-a",
        &worker_id,
        "evt-completed",
        "lifecycle",
        r#"{"state":"completed"}"#,
        1_100,
    ));
    assert_eq!(
        completed.as_deref(),
        Some("completed"),
        "the telemetry bridge terminalizes the run"
    );

    try_submit_job(&state, "tenant-a", "after-completion")
        .expect("a job the runtime FINISHED must release its slot with no ack and no cancel");
    assert!(
        try_submit_job(&state, "tenant-a", "after-completion-again").is_err(),
        "one completion frees one slot, not the whole budget"
    );
    assert!(
        !durable_dispatch_ids(&state).contains(&lease.dispatch_id),
        "a settled run's dispatch row is reclaimed, not retained for the life of the deployment"
    );
}

#[test]
fn a_job_settled_on_a_peer_replica_stops_counting_here() {
    // #502's multi-replica half. The open count is node-local, but the RELEASE
    // is a durable read of the run row: a peer that served the completion (or
    // the cancel) writes `agent_runs.status`, and this node -- which still
    // holds the start dispatch in memory and never saw a cancel dispatch of its
    // own -- must stop counting it. Before this, a cancel served by another
    // replica freed nothing here and the retried cancel hit the terminal
    // early-return, so the slot could never be repaired at all.
    let state = AppState::new(Config::default());
    let opened = submit_open_jobs(&state, "tenant-a", "peer", AGENT_JOB_MAX_OPEN_PER_TENANT);
    assert!(try_submit_job(&state, "tenant-a", "at-cap").is_err());

    // What a peer replica leaves behind: a terminal run row, and nothing in
    // this node's lease queue to show for it.
    let mut settled_elsewhere = state.agent_run_record(&opened[0]).expect("run row");
    settled_elsewhere.status = "cancelled".to_string();
    settled_elsewhere.completed_at_unix = Some(400);
    state.record_agent_run(settled_elsewhere);
    let stranded = agent_job_start_dispatch_id(&opened[0]);
    assert!(
        durable_dispatch_ids(&state).contains(&stranded),
        "the start dispatch is still here -- only the run row moved"
    );

    try_submit_job(&state, "tenant-a", "after-peer-settle")
        .expect("a job settled through a peer must release its slot on this node too");

    // ...and the repair the terminal-cancel early-return performs drains the
    // stranded row, so a retried cancel is a real remedy and not a no-op.
    assert_eq!(state.reclaim_settled_run_dispatches(&opened[0]), 1);
    assert!(
        !durable_dispatch_ids(&state).contains(&stranded),
        "reclaiming a settled run drops its stranded dispatch row"
    );
}

#[test]
fn a_settled_runs_rows_are_reclaimed_by_a_node_that_never_held_them_in_memory() {
    // The DURABLE FALLBACK inside `reclaim_settled_run_dispatches`, which is
    // the entire basis for "the durable delete is issued even when this node
    // did not hold the row in memory" -- and which every other reclaim test
    // leaves unexecuted, because they all still hold the dispatch in the local
    // queue and so never reach it. Replacing that fallback's body with
    // `Vec::new()` has to redden something, and this is it.
    let submitter = AppState::new(Config::default());
    let run_id = agent_job_run_id("tenant-a", "reclaim-across-nodes");
    let start_dispatch_id = agent_job_start_dispatch_id(&run_id);
    submitter
        .enqueue_scheduled_self_hosted_dispatch(start_dispatch(&run_id, "tenant-a"))
        .expect("the submitting node enqueues + persists the start dispatch");

    // The node that serves the settlement: same durable table, empty queue.
    let settling = AppState::new(Config::default());
    for record in ferrogate_sync_bridge::block_on_sync_bridge(
        submitter.repositories_arc().self_hosted_run_dispatches(),
    ) {
        ferrogate_sync_bridge::block_on_sync_bridge(
            settling
                .repositories_arc()
                .upsert_self_hosted_run_dispatch(record),
        )
        .expect("the settling node reads the same durable table");
    }
    assert!(
        settling
            .self_hosted_dispatch_ids_for_run(&run_id)
            .is_empty(),
        "this node's in-process lease queue genuinely holds nothing for the run"
    );
    assert!(durable_dispatch_ids(&settling).contains(&start_dispatch_id));

    assert_eq!(
        settling.reclaim_settled_run_dispatches(&run_id),
        1,
        "the reclaim must find the peer's row through the durable table"
    );
    assert!(
        !durable_dispatch_ids(&settling).contains(&start_dispatch_id),
        "...and actually delete it, which is the retention bound the cap used to stand in for"
    );
}

#[test]
fn a_cancelled_job_can_no_longer_be_leased_and_started() {
    // Cancel returned the caller's budget while leaving the work leasable, so a
    // worker would still poll, lease and START a job the caller had cancelled
    // (`can_lease_to` tests ack status, tenant, workspace, adapter,
    // capabilities and lease expiry -- none of which knows the run is over).
    let state = AppState::new(Config::default());
    let (_worker_id, identity) = register_job_worker(&state, "tenant-a");
    let run_id = try_submit_job(&state, "tenant-a", "cancel-before-lease").expect("submitted");

    cancel_open_job(&state, &run_id);

    // Drain everything this worker can still lease. The cancelled job must not
    // be among it; only the worker's own registration seed is left.
    for attempt in 0..4 {
        let Some(lease) = poll_for_lease(&state, &identity, 1_000 + attempt) else {
            break;
        };
        assert_ne!(
            lease.run_id, run_id,
            "a cancelled job must never be leased to a worker: {}",
            lease.dispatch_id
        );
    }
}

#[test]
fn a_peer_still_holding_a_cancelled_jobs_start_dispatch_refuses_to_lease_it() {
    // The hole the WITHDRAWAL arm leaves open, and the reason #551 could not be
    // settled by rewriting the harness alone. `restore_runs` replaces a node's
    // lease queue with the WHOLE `self_hosted_run_dispatches` table, unfiltered
    // by node, so any replica that rebuilds after a submit is holding every
    // other replica's dispatches in its own memory. Node A then cancels a job
    // nobody leased: it withdraws its own copy and correctly mints no
    // `cancel_run` -- there was no holder to address. Node B is still sitting
    // on a locally leasable `start_run` for work the caller paid to stop. A
    // node-local withdrawal must therefore retain the shared StartRun row and
    // rely on a predicate that crosses replicas rather than pretending it can
    // prove exclusive ownership.
    //
    // The only such predicate is the run row itself, which the cancel writes.
    // Deleting `start_run_lease_is_settled` from
    // `AppState::poll_self_hosted_worker_run` reddens this test.
    //
    // The two nodes share ONE set of repositories (#551 rework). They used to
    // be independent stores with rows hand-copied between them, and the copy
    // included the settled run row -- which handed the guard the precondition
    // the cancel path is responsible for establishing. Nothing here supplies
    // it now: if the cancel does not put that row where a peer reads it before
    // withdrawing locally, the peer below leases the cancelled job.
    let submitter = AppState::new(Config::default());
    let cancelled_id =
        try_submit_job(&submitter, "tenant-a", "cancel-then-a-peer-polls").expect("submitted");
    // Submitted alongside it and never cancelled. Without it, "the peer offered
    // nothing for the cancelled run" would also be satisfied by a peer whose
    // queue was empty or whose poll seam was broken -- which is precisely the
    // shape of vacuous assertion #500 exists about.
    let live_id =
        try_submit_job(&submitter, "tenant-a", "the-peer-may-still-run-this").expect("submitted");
    let cancelled_dispatch_id = agent_job_start_dispatch_id(&cancelled_id);

    // The peer replica: a second node over the SAME durable tables, which
    // rebuilt its lease queue AFTER the submits, so it holds its own in-memory
    // copy of both start dispatches.
    let peer = submitter.new_peer_replica(Config::default());
    let (_worker_id, identity) = register_job_worker(&peer, "tenant-a");
    peer.rebuild_self_hosted_worker_dispatch_runtime()
        .expect("the peer rebuilds its lease queue from the durable rows");
    assert!(
        peer.self_hosted_dispatch_unacked(&cancelled_dispatch_id),
        "the peer must genuinely hold a leasable copy before the cancel, or this proves nothing"
    );

    // The cancel is served by the OTHER node, the way a load balancer would.
    // Nothing after this line copies anything to the peer: whatever the peer
    // can see is what the cancel actually made durable.
    cancel_open_job(&submitter, &cancelled_id);
    // The cancel settles durably and only then withdraws its local copy.
    // `cancel_agent_job_in_runtime` refuses a run that is not yet settled, so
    // the peer protection cannot be installed in the other order. The shared
    // row is then reclaimed as settled work, not because success on one node's
    // queue said anything about copies another replica restored earlier.
    assert!(
        !durable_dispatch_ids(&submitter).contains(&cancelled_dispatch_id),
        "settled-run cleanup reclaims the shared row after local withdrawal"
    );
    assert_eq!(
        peer.agent_run_record(&cancelled_id)
            .expect("the peer reads the cancelled run row out of the shared table")
            .status,
        "cancelled",
        "the cancel must make the settled row durable itself; nothing in this test puts it there"
    );
    // Nothing reached the peer's own state: no `cancel_run` was minted at all,
    // and its queue still holds the cancelled job's start dispatch.
    assert!(
        peer.self_hosted_dispatch_ids_for_run(&cancelled_id)
            .contains(&cancelled_dispatch_id),
        "the peer's in-memory copy is exactly what a cancel on another node cannot reach"
    );
    assert!(
        peer.self_hosted_dispatch_for_run(&cancelled_id, SelfHostedRunAction::CancelRun)
            .is_none(),
        "an unleased job mints no cancel_run, so supersession cannot be what saves the peer"
    );

    // ...and yet the peer must not hand that work to a worker, while the job
    // nobody cancelled is still handed out normally.
    let mut offered_live = false;
    for attempt in 0..8 {
        let Some(lease) = poll_for_lease(&peer, &identity, 9_000 + attempt) else {
            break;
        };
        assert_ne!(
            lease.run_id, cancelled_id,
            "a peer must never START a job another node already cancelled: {}",
            lease.dispatch_id
        );
        if lease.run_id == live_id && lease.action == SelfHostedRunAction::StartRun {
            offered_live = true;
        }
    }
    assert!(
        offered_live,
        "the peer never offered the un-cancelled job either, so refusing the cancelled one is \
         not evidence of anything"
    );

    // The refusal also RECLAIMS: the row a settled run leaves in a peer's queue
    // is dropped as it is skipped, so a cancelled job does not cost a permanent
    // scan on every future poll of every replica that rebuilt after its submit.
    assert!(
        !peer
            .self_hosted_dispatch_ids_for_run(&cancelled_id)
            .contains(&cancelled_dispatch_id),
        "the skipped start dispatch must be dropped, not re-scanned on every poll forever"
    );
}

#[test]
fn cancelling_an_already_leased_job_supersedes_its_start_dispatch() {
    // The harder half of the same defect. When a worker HOLDS the job the start
    // dispatch cannot simply be withdrawn -- the holder still has to be told to
    // stop, and its own ack has to resolve -- so the start row stays. It must
    // nonetheless stop being leasable: once that lease expires, `can_lease_to`
    // would otherwise hand the SAME cancelled job to a second worker, which
    // would then start it.
    let state = AppState::new(Config::default());
    let (_worker_id, identity) = register_job_worker(&state, "tenant-a");
    let run_id = try_submit_job(&state, "tenant-a", "cancel-after-lease").expect("submitted");
    let start_dispatch_id = agent_job_start_dispatch_id(&run_id);

    let lease = poll_for_lease(&state, &identity, 1_000).expect("the worker leases the job");
    assert_eq!(lease.dispatch_id, start_dispatch_id);

    let run = state.agent_run_record(&run_id).expect("run row");
    assert!(
        cancel_agent_job(&state, &run, "fg-cancel", 1_050)
            .expect("the cancel is accepted")
            .runtime_cancel_dispatched,
        "a leased job must be cancelled by dispatching cancel_run to its holder"
    );

    // Long after the original lease expired: nothing may hand the start
    // dispatch out again. The `cancel_run` may (and must) still be leasable.
    let mut cancel_lease = None;
    for attempt in 0..4 {
        let Some(lease) = poll_for_lease(&state, &identity, 9_000 + attempt) else {
            break;
        };
        assert_ne!(
            lease.dispatch_id, start_dispatch_id,
            "a cancelled job's start dispatch must never be re-leased"
        );
        if lease.action == SelfHostedRunAction::CancelRun && lease.run_id == run_id {
            cancel_lease = Some(lease);
        }
    }
    let cancel_lease =
        cancel_lease.expect("the holder must still be able to lease the cancel_run that stops it");

    // Acking the cancel is the point at which BOTH rows lose their last reader,
    // and it is the only reclaim trigger the ack seam owns. Driven through the
    // real ack seam so deleting that trigger reddens this test rather than
    // passing silently.
    assert!(
        durable_dispatch_ids(&state).contains(&start_dispatch_id),
        "the superseded start row is still there while the cancel is unacked"
    );
    state
        .ack_self_hosted_worker_run(ferrogate_runtime::SelfHostedRunAckRequest {
            protocol_version: 1,
            identity,
            dispatch_id: cancel_lease.dispatch_id.clone(),
            action: cancel_lease.action,
            lease_id: cancel_lease.lease_id.clone(),
            run_id: cancel_lease.run_id.clone(),
            status: ferrogate_runtime::SelfHostedRunAckStatus::Cancelled,
            reported_at_unix: cancel_lease.lease_expires_at_unix,
        })
        .expect("the holder's cancel ack is accepted");
    let remaining = durable_dispatch_ids(&state);
    assert!(
        !remaining.contains(&start_dispatch_id),
        "an acknowledged cancel reclaims the start dispatch it superseded: {remaining:?}"
    );
    assert!(
        !remaining.contains(&cancel_lease.dispatch_id),
        "...and the cancel_run row itself, which now has no reader at all: {remaining:?}"
    );
}

#[test]
fn a_runtime_acknowledgement_frees_a_submit_slot() {
    // The other release the surface honours: a worker that leases and acks a
    // start dispatch releases its slot. Drives the REAL poll/ack seam.
    let state = AppState::new(Config::default());
    let (_worker_id, identity) = register_job_worker(&state, "tenant-a");
    submit_open_jobs(&state, "tenant-a", "acked", AGENT_JOB_MAX_OPEN_PER_TENANT);
    assert!(try_submit_job(&state, "tenant-a", "at-cap").is_err());

    let lease = poll_for_lease(&state, &identity, 1_000).expect("a queued job is leasable");
    assert!(
        lease
            .dispatch_id
            .starts_with(AGENT_JOB_START_DISPATCH_PREFIX),
        "the worker must have leased a submitted job, not the registration seed: {}",
        lease.dispatch_id
    );
    state
        .ack_self_hosted_worker_run(ferrogate_runtime::SelfHostedRunAckRequest {
            protocol_version: 1,
            identity,
            dispatch_id: lease.dispatch_id.clone(),
            action: lease.action,
            lease_id: lease.lease_id.clone(),
            run_id: lease.run_id.clone(),
            status: ferrogate_runtime::SelfHostedRunAckStatus::Accepted,
            reported_at_unix: 1_010,
        })
        .expect("ack is accepted");

    try_submit_job(&state, "tenant-a", "after-ack")
        .expect("an acknowledged job is no longer open and must free its slot");
}

#[test]
fn one_tenants_backlog_never_consumes_another_tenants_submit_budget() {
    let state = AppState::new(Config::default());
    submit_open_jobs(&state, "tenant-b", "noisy", AGENT_JOB_MAX_OPEN_PER_TENANT);
    assert!(
        try_submit_job(&state, "tenant-b", "at-cap").is_err(),
        "the tenant that filled the queue is refused"
    );
    // ...and tenant-a still gets its OWN full budget, not a share of one.
    submit_open_jobs(
        &state,
        "tenant-a",
        "quiet",
        AGENT_JOB_MAX_OPEN_PER_TENANT - 1,
    );
    try_submit_job(&state, "tenant-a", "quiet-last")
        .expect("a neighbour's backlog must never refuse this tenant's submits");
    assert!(
        try_submit_job(&state, "tenant-a", "quiet-over").is_err(),
        "tenant-a's own cap still closes"
    );
}

#[test]
fn background_start_dispatches_do_not_consume_the_callers_submit_budget() {
    // A schedule fire (#426) and a worker-registration seed enqueue `start_run`
    // dispatches for the same tenant into the SAME queue. The caller never
    // asked for either, so neither may eat the caller-facing submit budget.
    //
    // The dispatch ids are DERIVED from the producers themselves rather than
    // spelled out here: renaming a producer's prefix must redden this test
    // instead of silently starting to charge schedule fires to the caller.
    let state = AppState::new(Config::default());
    submit_open_jobs(
        &state,
        "tenant-a",
        "budget",
        AGENT_JOB_MAX_OPEN_PER_TENANT - 1,
    );
    for (dispatch_id, run_id) in [
        (
            crate::state::scheduled_dispatch_id("nightly-sweep", 1_700_000_000),
            "schedule-run-nightly-sweep-1700000000",
        ),
        (
            crate::state::self_hosted_seed_dispatch_id("self-hosted-worker-1"),
            "self-hosted-run-self-hosted-worker-1",
        ),
    ] {
        state
            .enqueue_scheduled_self_hosted_dispatch(SelfHostedRunDispatch {
                dispatch_id,
                run_id: run_id.to_string(),
                agent_run_id: Some(run_id.to_string()),
                ..start_dispatch("unused", "tenant-a")
            })
            .expect("background producers share the lease queue");
    }

    try_submit_job(&state, "tenant-a", "budget-last")
        .expect("scheduled and seeded runs must not spend the caller's submit budget");
    // The caller's own last slot still closes the gate.
    assert!(try_submit_job(&state, "tenant-a", "budget-over").is_err());
}
