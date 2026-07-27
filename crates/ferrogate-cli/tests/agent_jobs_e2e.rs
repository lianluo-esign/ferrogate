// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: End-to-end coverage for the #474 caller-facing async agent-job
// protocol against a real gateway process with the in-memory backend (no
// Docker, no Postgres). Drives the ACTUAL handlers over HTTP -- submit ->
// run_id -> observe -> collect -> cancel -- and proves the three acceptance
// boxes the code review found unmet: idempotent submission through the real
// response branch, a job that becomes terminal because the WORKER reported it
// (the worker -> gateway bridge), and a job that survives a restart of the
// serving component.

mod support;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

/// The caller's key carries ONLY `agent.runs.create` -- deliberately not the
/// newer `agent.runs.read` scope. An async protocol whose submitter cannot
/// observe its own job is write-only, so the observe verbs must accept the
/// submit scope as well (#474 rework).
const CALLER: [&str; 2] = [
    "Authorization: Bearer job-secret",
    "Content-Type: application/json",
];

/// A read-only key: `agent.runs.read` and nothing else. It must be able to
/// observe, and must NOT be able to submit or cancel.
const OBSERVER: [&str; 2] = [
    "Authorization: Bearer observer-secret",
    "Content-Type: application/json",
];

const TENANT: &str = "job-tenant";
const WORKSPACE: &str = "job-ws";
const WORKER_FINGERPRINT: &str = "sha256:job-worker";

fn gateway_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "job-caller"
name = "Async job submitter"
key = "job-secret"
scopes = ["agent.runs.create"]
organization_id = "{TENANT}"
workspace_id = "{WORKSPACE}"

[[api_keys]]
id = "job-observer"
name = "Async job observer"
key = "observer-secret"
scopes = ["agent.runs.read"]
organization_id = "{TENANT}"
workspace_id = "{WORKSPACE}"

[[api_keys]]
id = "other-tenant"
name = "A different tenant"
key = "intruder-secret"
scopes = ["agent.runs.create", "agent.runs.read"]
organization_id = "other-tenant"
workspace_id = "other-ws"

[agent_runtime]
enabled = true
"#
    )
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn body_of(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response)
}

fn response_json(response: &str) -> serde_json::Value {
    serde_json::from_str(body_of(response))
        .unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn worker_transport_headers() -> [&'static str; 2] {
    [
        "Content-Type: application/json",
        "x-ferrogate-transport-security: mutual_tls",
    ]
}

/// Registers a self-hosted worker in the caller's tenant/workspace so it can
/// lease the job's start dispatch and report telemetry against its run id.
fn register_worker(gateway_addr: &str) -> (String, String) {
    let register = http_request(
        gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &ADMIN,
        &serde_json::json!({
            "tenant": {
                "organization_id": TENANT,
                "team_id": null,
                "project_id": null,
                "workspace_id": WORKSPACE,
                "user_id": null,
                "api_key_id": "admin"
            },
            "workspace_id": WORKSPACE,
            "worker_name": "job-worker",
            "identity_fingerprint": WORKER_FINGERPRINT,
            "orchestration_enabled": false
        })
        .to_string(),
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "worker registration should succeed: {register}"
    );
    let json = response_json(&register);
    (
        json["worker"]["id"].as_str().unwrap().to_string(),
        json["transport_token_secret"].as_str().unwrap().to_string(),
    )
}

fn worker_identity(worker_id: &str, transport_secret: &str) -> serde_json::Value {
    serde_json::json!({
        "tenant_id": TENANT,
        "workspace_id": WORKSPACE,
        "worker_id": worker_id,
        "token_id": WORKER_FINGERPRINT,
        "token_secret": transport_secret,
    })
}

/// Polls until the worker leases a dispatch for `run_id` (or the window
/// elapses), returning the lease.
fn lease_dispatch_for(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
    run_id: &str,
) -> serde_json::Value {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        let body = serde_json::json!({
            "protocol_version": 1,
            "identity": worker_identity(worker_id, transport_secret),
            "supported_capabilities": ["shell"],
            "now_unix": now_unix(),
            "lease_duration_secs": 60
        })
        .to_string();
        let response = http_request(
            gateway_addr,
            "POST",
            "/v1/self-hosted-workers/runs/poll",
            &worker_transport_headers(),
            &body,
        );
        assert!(
            response.contains("HTTP/1.1 200"),
            "worker poll should be accepted: {response}"
        );
        let lease = response_json(&response);
        if lease["run_id"].as_str() == Some(run_id) {
            return lease;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("worker never leased the agent job's start dispatch for {run_id}");
}

/// The worker reports a lifecycle telemetry event for `run_id`. This is the
/// ONLY thing that advances the job to a terminal state in production, and
/// before the #474 rework it did not touch `agent_runs.status` at all.
fn report_run_state(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
    lease: &serde_json::Value,
    run_id: &str,
    event_json: serde_json::Value,
) {
    let body = serde_json::json!({
        "identity": worker_identity(worker_id, transport_secret),
        "session_id": lease["session_id"],
        "run_id": run_id,
        "kind": "lifecycle",
        "occurred_at_unix": now_unix(),
        "event_json": event_json.to_string(),
        "request_id": lease["request_id"],
        "trace_id": lease["trace_id"],
        "agent_run_id": lease["agent_run_id"],
    })
    .to_string();
    let response = http_request(
        gateway_addr,
        "POST",
        "/v1/self-hosted-workers/events",
        &worker_transport_headers(),
        &body,
    );
    assert!(
        response.contains("HTTP/1.1 201") || response.contains("HTTP/1.1 200"),
        "worker telemetry should be accepted: {response}"
    );
}

fn get_json(gateway_addr: &str, path: &str, headers: &[&str]) -> (String, serde_json::Value) {
    let response = http_request(gateway_addr, "GET", path, headers, "");
    let status = response
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    (status, response_json(&response))
}

#[test]
fn an_agent_job_is_submitted_idempotently_observed_collected_and_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let gateway_addr = free_addr();
    std::fs::write(&config_path, gateway_config(&gateway_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let (worker_id, transport_secret) = register_worker(&gateway_addr);

    // ---------------------------------------------------------------
    // Box 2: idempotent submission, through the REAL handler.
    // ---------------------------------------------------------------
    let submit_body = serde_json::json!({
        "input": "fix the flaky test in crates/ferrogate-cli",
        "required_capabilities": ["shell"],
        "framework_adapter": "native-harness"
    })
    .to_string();
    let idempotent: [&str; 3] = [
        "Authorization: Bearer job-secret",
        "Content-Type: application/json",
        "Idempotency-Key: fix-flaky-test-1",
    ];
    let first = http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-jobs",
        &idempotent,
        &submit_body,
    );
    assert!(
        first.contains("HTTP/1.1 202"),
        "the first submit is accepted: {first}"
    );
    let first_json = response_json(&first);
    let run_id = first_json["run_id"].as_str().unwrap().to_string();
    assert_eq!(first_json["deduplicated"], false);
    assert_eq!(first_json["status"], "queued");
    assert_eq!(first_json["idempotency_key"], "fix-flaky-test-1");
    assert_eq!(first_json["idempotency_key_source"], "header");
    assert_eq!(
        first_json["status_url"].as_str().unwrap(),
        format!("/v1/agent-jobs/{run_id}")
    );

    // The retry: same key, DIFFERENT body -- the response must still be the
    // original job, 200 + deduplicated, with no second run spawned.
    let retry = http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-jobs",
        &idempotent,
        &serde_json::json!({ "input": "a totally different task" }).to_string(),
    );
    assert!(
        retry.contains("HTTP/1.1 200"),
        "a retried submit is not a new job: {retry}"
    );
    let retry_json = response_json(&retry);
    assert_eq!(retry_json["deduplicated"], true);
    assert_eq!(retry_json["run_id"].as_str().unwrap(), run_id);

    // A different key IS a different job.
    let other_key: [&str; 3] = [
        "Authorization: Bearer job-secret",
        "Content-Type: application/json",
        "Idempotency-Key: fix-flaky-test-2",
    ];
    let second_job = http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-jobs",
        &other_key,
        &submit_body,
    );
    assert!(second_job.contains("HTTP/1.1 202"));
    assert_ne!(
        response_json(&second_job)["run_id"].as_str().unwrap(),
        run_id
    );

    // ---------------------------------------------------------------
    // Observe: the submit scope alone is enough to follow your own job,
    // and the read-only key can observe but not submit.
    // ---------------------------------------------------------------
    let (status_line, status) =
        get_json(&gateway_addr, &format!("/v1/agent-jobs/{run_id}"), &CALLER);
    assert!(
        status_line.contains("200"),
        "an agent.runs.create key must be able to observe its own job: {status_line}"
    );
    assert_eq!(status["status"], "queued");
    assert_eq!(status["terminal"], false);

    let (observer_line, _) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}"),
        &OBSERVER,
    );
    assert!(observer_line.contains("200"), "{observer_line}");
    let observer_submit = http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-jobs",
        &OBSERVER,
        &submit_body,
    );
    assert!(
        observer_submit.contains("HTTP/1.1 403"),
        "a read-only key must never be able to submit: {observer_submit}"
    );

    // Tenant isolation: a foreign tenant's key gets 404, not 403 -- the
    // surface is not an existence oracle.
    let intruder: [&str; 2] = [
        "Authorization: Bearer intruder-secret",
        "Content-Type: application/json",
    ];
    let (intruder_line, _) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}"),
        &intruder,
    );
    assert!(
        intruder_line.contains("404"),
        "a cross-tenant read must 404: {intruder_line}"
    );

    // The event feed carries the submission and hands back a resumable cursor.
    let (events_line, events) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/events"),
        &CALLER,
    );
    assert!(events_line.contains("200"), "{events_line}");
    assert_eq!(events["cursor_reset"], false);
    assert!(events["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["kind"] == "job_submitted"));
    let cursor = events["next_after_event_id"].as_str().unwrap().to_string();

    // A cursor that cannot be resolved resets the feed instead of 400-ing the
    // poll loop into a permanent dead end.
    let (reset_line, reset) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/events?after_event_id=pruned-long-ago"),
        &CALLER,
    );
    assert!(reset_line.contains("200"), "{reset_line}");
    assert_eq!(reset["cursor_reset"], true);

    // Collect is refused while the job is live -- that part was always right.
    let (result_line, result) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/result"),
        &CALLER,
    );
    assert!(result_line.contains("409"), "{result_line}");
    assert_eq!(result["error"]["code"], "agent_job_not_terminal");

    // ---------------------------------------------------------------
    // Box 1b: the worker -> gateway bridge. The runtime leases the job,
    // reports progress and then completion; the CANONICAL run status must
    // follow, and `/result` must return the real output.
    // ---------------------------------------------------------------
    let lease = lease_dispatch_for(&gateway_addr, &worker_id, &transport_secret, &run_id);
    assert_eq!(lease["action"], "start_run");

    report_run_state(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &lease,
        &run_id,
        serde_json::json!({ "state": "running" }),
    );
    let (_, running) = get_json(&gateway_addr, &format!("/v1/agent-jobs/{run_id}"), &CALLER);
    assert_eq!(
        running["status"], "running",
        "worker progress must move the canonical run status: {running}"
    );
    assert_eq!(running["terminal"], false);

    report_run_state(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &lease,
        &run_id,
        serde_json::json!({
            "state": "completed",
            "turns_executed": 5,
            "output": "opened https://example.test/pr/4711"
        }),
    );
    let (_, completed) = get_json(&gateway_addr, &format!("/v1/agent-jobs/{run_id}"), &CALLER);
    assert_eq!(
        completed["status"], "completed",
        "a job the runtime finished must report terminal, not queued forever: {completed}"
    );
    assert_eq!(completed["terminal"], true);
    assert_eq!(completed["turns_executed"], 5);
    assert_eq!(completed["output_recorded"], true);

    let (collect_line, collected) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/result"),
        &CALLER,
    );
    assert!(
        collect_line.contains("200"),
        "collect must succeed once the runtime reported completion: {collect_line}"
    );
    assert_eq!(collected["status"], "completed");
    assert_eq!(
        collected["output"], "opened https://example.test/pr/4711",
        "/result must return the runtime's real output, not null: {collected}"
    );

    // The completion is on the run's own timeline too, resumable from the
    // cursor the earlier poll handed back (no replay of the submit event).
    let (_, tail) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/events?after_event_id={cursor}"),
        &CALLER,
    );
    assert_eq!(tail["cursor_reset"], false);
    assert!(
        tail["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "run_completed"),
        "the cursor feed carries the completion: {tail}"
    );

    // ---------------------------------------------------------------
    // Cancel: idempotent on an already-terminal job, and effective on a live
    // one.
    // ---------------------------------------------------------------
    let cancel_completed = http_request(
        &gateway_addr,
        "POST",
        &format!("/v1/agent-jobs/{run_id}/cancel"),
        &CALLER,
        "",
    );
    assert!(cancel_completed.contains("HTTP/1.1 200"));
    let cancel_completed = response_json(&cancel_completed);
    assert_eq!(cancel_completed["cancelled"], false);
    assert_eq!(cancel_completed["status"], "completed");

    let live_run_id = response_json(&second_job)["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let cancel_live = http_request(
        &gateway_addr,
        "POST",
        &format!("/v1/agent-jobs/{live_run_id}/cancel"),
        &CALLER,
        "",
    );
    assert!(cancel_live.contains("HTTP/1.1 200"), "{cancel_live}");
    let cancel_live = response_json(&cancel_live);
    assert_eq!(cancel_live["cancelled"], true);
    // No worker ever leased this second job, so there is nobody to hand a
    // `cancel_run` to: its start dispatch is withdrawn from the queue instead
    // of being left leasable behind a cancel nobody will read (#502).
    assert_eq!(cancel_live["runtime_cancel_dispatched"], false);
    let (_, cancelled_status) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{live_run_id}"),
        &CALLER,
    );
    assert_eq!(cancelled_status["status"], "cancelled");
    assert_eq!(cancelled_status["terminal"], true);

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn a_submitted_agent_job_survives_a_restart_of_the_serving_component() {
    // Acceptance box 5. A config reload rebuilds the whole AppState --
    // including the in-process self-hosted lease queue, which is restored from
    // the durable `self_hosted_run_dispatches` table by the same
    // `try_new_with_repositories` path a process start runs. So after the
    // reload nothing about this job is left in the memory that served its
    // submit: the run row and its dispatch must both come back from storage.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let gateway_addr = free_addr();
    std::fs::write(&config_path, gateway_config(&gateway_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let (worker_id, transport_secret) = register_worker(&gateway_addr);

    let submit = http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-jobs",
        &[
            "Authorization: Bearer job-secret",
            "Content-Type: application/json",
            "Idempotency-Key: survive-a-restart",
        ],
        &serde_json::json!({
            "input": "a job that outlives the request that created it",
            "required_capabilities": ["shell"]
        })
        .to_string(),
    );
    assert!(submit.contains("HTTP/1.1 202"), "{submit}");
    let run_id = response_json(&submit)["run_id"]
        .as_str()
        .unwrap()
        .to_string();

    let reload = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &ADMIN,
        &serde_json::json!({ "config_toml": gateway_config(&gateway_addr) }).to_string(),
    );
    assert!(
        reload.contains("HTTP/1.1 200"),
        "the simulated restart should succeed: {reload}"
    );

    // The caller can still address the job by the id it was handed...
    let (status_line, status) =
        get_json(&gateway_addr, &format!("/v1/agent-jobs/{run_id}"), &CALLER);
    assert!(
        status_line.contains("200"),
        "the job must survive the restart: {status_line}"
    );
    assert_eq!(status["status"], "queued");
    assert_eq!(status["terminal"], false);

    // ...and the runtime can still lease its work, which is what proves the
    // dispatch came back out of durable storage rather than out of the queue
    // the submit populated.
    let lease = lease_dispatch_for(&gateway_addr, &worker_id, &transport_secret, &run_id);
    assert_eq!(lease["action"], "start_run");
    assert_eq!(lease["run_id"].as_str().unwrap(), run_id);

    // And the resumed job still completes end to end.
    report_run_state(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &lease,
        &run_id,
        serde_json::json!({ "state": "completed", "output": "done after restart" }),
    );
    let (collect_line, collected) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/result"),
        &CALLER,
    );
    assert!(collect_line.contains("200"), "{collect_line}");
    assert_eq!(collected["output"], "done after restart");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Mirrors `AGENT_JOB_MAX_OPEN_PER_TENANT` in `gateway/agent_jobs.rs` (private
/// to the binary crate, so the boundary is restated here). Changing the cap
/// without changing this constant reddens this test, which is the point: the
/// boundary is part of the contract's `429` response.
const OPEN_JOB_CAP: usize = 200;

/// Submits one NEW job under `idempotency_key` and returns `(status line, body)`.
fn submit_job(gateway_addr: &str, idempotency_key: &str) -> (String, serde_json::Value) {
    let headers = [
        "Authorization: Bearer job-secret".to_string(),
        "Content-Type: application/json".to_string(),
        format!("Idempotency-Key: {idempotency_key}"),
    ];
    let headers: Vec<&str> = headers.iter().map(String::as_str).collect();
    let response = http_request(
        gateway_addr,
        "POST",
        "/v1/agent-jobs",
        &headers,
        &serde_json::json!({ "input": "hold a slot", "required_capabilities": ["shell"] })
            .to_string(),
    );
    let status = response
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    (status, response_json(&response))
}

#[test]
fn cancelling_frees_a_submit_slot_so_a_workerless_tenant_is_never_locked_out() {
    // Issue #502, over the REAL HTTP surface. NO worker is registered, so
    // nothing will ever acknowledge a start dispatch -- the exact tenant that
    // used to be locked out of `POST /v1/agent-jobs` permanently once it hit
    // the cap, because the 429's "cancel an existing job" remedy freed nothing.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let gateway_addr = free_addr();
    std::fs::write(&config_path, gateway_config(&gateway_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // Fill the budget to exactly the cap. Every one of these is admitted --
    // including the LAST one, submitted with cap-1 jobs already open.
    let mut first_run_id = String::new();
    for index in 0..OPEN_JOB_CAP {
        let (status, body) = submit_job(&gateway_addr, &format!("cap-{index}"));
        assert!(
            status.contains("202"),
            "submit {index} (below the cap) must be accepted: {status} {body}"
        );
        if index == 0 {
            first_run_id = body["run_id"].as_str().unwrap().to_string();
        }
    }

    // At the cap: refused, with the contract's declared code.
    let (over_status, over_body) = submit_job(&gateway_addr, "cap-over");
    assert!(
        over_status.contains("429"),
        "the cap must refuse the {}th open job: {over_status} {over_body}",
        OPEN_JOB_CAP + 1
    );
    assert_eq!(over_body["error"]["code"], "agent_job_open_limit_reached");

    // The budget is per tenant: a different tenant's key is unaffected by this
    // tenant's backlog.
    let intruder: [&str; 3] = [
        "Authorization: Bearer intruder-secret",
        "Content-Type: application/json",
        "Idempotency-Key: neighbour-1",
    ];
    let neighbour = http_request(
        &gateway_addr,
        "POST",
        "/v1/agent-jobs",
        &intruder,
        &serde_json::json!({ "input": "a neighbour's job" }).to_string(),
    );
    assert!(
        neighbour.contains("HTTP/1.1 202"),
        "one tenant at its cap must never refuse another tenant: {neighbour}"
    );

    // The remedy the 429 names: cancel one job.
    let cancel = http_request(
        &gateway_addr,
        "POST",
        &format!("/v1/agent-jobs/{first_run_id}/cancel"),
        &CALLER,
        "",
    );
    assert!(cancel.contains("HTTP/1.1 200"), "{cancel}");
    let cancel = response_json(&cancel);
    assert_eq!(cancel["cancelled"], true);
    // No worker exists at all here, so nothing had leased the job: the start
    // dispatch is withdrawn rather than superseded by a `cancel_run` (#502).
    assert_eq!(cancel["runtime_cancel_dispatched"], false);

    // ...and the slot is genuinely free: the SAME submit that was refused a
    // moment ago now succeeds. This is the assertion the defect fails.
    let (after_cancel, after_cancel_body) = submit_job(&gateway_addr, "cap-over");
    assert!(
        after_cancel.contains("202"),
        "cancelling must free a slot the caller can actually use: \
         {after_cancel} {after_cancel_body}"
    );
    assert_eq!(after_cancel_body["deduplicated"], false);

    // Exactly one slot was freed -- the cap still holds for the next submit.
    let (refused_again, refused_body) = submit_job(&gateway_addr, "cap-over-again");
    assert!(
        refused_again.contains("429"),
        "one cancel frees one slot, not the whole cap: {refused_again} {refused_body}"
    );
    assert_eq!(
        refused_body["error"]["code"],
        "agent_job_open_limit_reached"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn a_finished_job_frees_a_submit_slot_for_a_tenant_whose_worker_is_healthy() {
    // Issue #502, the MAJORITY deployment, over the REAL HTTP surface. A tenant
    // whose worker is working perfectly never calls `/runs/ack` for a finished
    // job: the production completion path is worker TELEMETRY
    // (`POST /v1/self-hosted-workers/events`), which terminalizes
    // `agent_runs.status` and does not touch `acknowledged_status`. Keying the
    // slot release on the ack therefore locked such a tenant out of
    // `POST /v1/agent-jobs` after `OPEN_JOB_CAP` FINISHED jobs -- the identical
    // 429, with the identical remedy text, for the common case.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let gateway_addr = free_addr();
    std::fs::write(&config_path, gateway_config(&gateway_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let (worker_id, transport_secret) = register_worker(&gateway_addr);

    // One job the worker will actually pick up...
    let (status, body) = submit_job(&gateway_addr, "healthy-0");
    assert!(status.contains("202"), "{status} {body}");
    let leased_run_id = body["run_id"].as_str().unwrap().to_string();
    let lease = lease_dispatch_for(&gateway_addr, &worker_id, &transport_secret, &leased_run_id);

    // ...and enough more to reach exactly the cap.
    for index in 1..OPEN_JOB_CAP {
        let (status, body) = submit_job(&gateway_addr, &format!("healthy-{index}"));
        assert!(
            status.contains("202"),
            "submit {index} (below the cap) must be accepted: {status} {body}"
        );
    }
    let (over_status, over_body) = submit_job(&gateway_addr, "healthy-over");
    assert!(
        over_status.contains("429"),
        "the cap must refuse the {}th open job: {over_status} {over_body}",
        OPEN_JOB_CAP + 1
    );
    assert_eq!(over_body["error"]["code"], "agent_job_open_limit_reached");
    // The refusal must not name a remedy that does not work -- that is the
    // defect this issue is about, not the number.
    let message = over_body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("terminal state") && message.contains("/cancel"),
        "the 429 must name only remedies that release a slot: {message}"
    );

    // The worker finishes the job the only way production ever does. No ack,
    // no cancel.
    report_run_state(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &lease,
        &leased_run_id,
        serde_json::json!({"state": "completed", "output": "finished cleanly"}),
    );
    let (_, finished) = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{leased_run_id}"),
        &CALLER,
    );
    assert_eq!(finished["status"], "completed");
    assert_eq!(finished["terminal"], true);

    // ...and the slot the finished job held is genuinely free: the SAME submit
    // that was refused a moment ago now succeeds. This is the assertion the
    // defect fails.
    let (after_finish, after_finish_body) = submit_job(&gateway_addr, "healthy-over");
    assert!(
        after_finish.contains("202"),
        "a job the runtime FINISHED must free a slot the caller can use: \
         {after_finish} {after_finish_body}"
    );
    assert_eq!(after_finish_body["deduplicated"], false);

    // Exactly one slot -- the cap still holds for the next submit.
    let (refused_again, refused_body) = submit_job(&gateway_addr, "healthy-over-again");
    assert!(
        refused_again.contains("429"),
        "one completion frees one slot, not the whole cap: {refused_again} {refused_body}"
    );
    assert_eq!(
        refused_body["error"]["code"],
        "agent_job_open_limit_reached"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
