// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Docker-free E2E coverage for the caller-facing async agent-job protocol (#474).

//! End-to-end proof of the #474 async long-running job protocol against a REAL
//! `ferrogate` process (gate-owned harness growth): the harness had no scenario
//! touching `/v1/agent-jobs` at all, so nothing in `ferrogate-test ci` would
//! notice if the whole submit/observe/collect/cancel surface regressed.
//!
//! Every acceptance box on #474 is driven over the wire here:
//!
//! 1. submit -> `run_id` -> observe -> retrieve: `POST /v1/agent-jobs` returns
//!    202 + a durable id, `GET {id}` / `{id}/events` / `{id}/result` observe and
//!    collect it.
//! 2. idempotent submission: a retried submit under the same `Idempotency-Key`
//!    returns the ORIGINAL `run_id` and spawns no second run.
//! 3. cancellation STOPS THE WORK in the runtime and terminalizes the run.
//!    #551 pinned which mechanism discharges that, because it is not one
//!    mechanism: a job no worker has leased has its start dispatch WITHDRAWN
//!    (nothing is left to offer, and a `cancel_run` would be addressed at
//!    nobody), while a job a worker HOLDS gets a `cancel_run` its holder can
//!    lease. Both arms are driven, and the withdrawal is asserted positively
//!    -- against a control job submitted right after the cancelled one -- so
//!    the unleased arm cannot pass by asserting nothing.
//! 4. tenant isolation: another tenant's key can never observe or collect the
//!    run, by id.
//! 5. the job survives a restart of the serving component (a config reload
//!    rebuilds AppState, so the run row and its dispatch must come back out of
//!    durable storage, not out of the memory that served the submit).
//!
//! The terminal transition is driven the way production drives it: a registered
//! self-hosted worker LEASES the job's start dispatch over the real poll
//! protocol and reports lifecycle telemetry, which the #474 worker -> gateway
//! bridge projects onto the canonical `agent_runs` row.

use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{free_addr, http_request_addr, HttpResponse},
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env, fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ADMIN_AUTH: &str = "Authorization: Bearer job-e2e-admin-secret";
const CALLER_AUTH: &str = "Authorization: Bearer job-e2e-caller-secret";
const INTRUDER_AUTH: &str = "Authorization: Bearer job-e2e-intruder-secret";
const TENANT: &str = "org_job_e2e";
const WORKSPACE: &str = "ws_job_e2e";
const WORKER_FINGERPRINT: &str = "sha256:job-e2e-worker";
const GATEWAY_READINESS_TIMEOUT: Duration = Duration::from_secs(180);
const TRANSPORT_SECURITY: &str = "x-ferrogate-transport-security: mutual_tls";

pub(crate) fn run_agent_jobs_api(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("agent-jobs.yaml");
    fs::write(&config_path, scenario_config(&gateway_addr))?;
    let _gateway = GatewayGuard::start(&args.ferrogate_bin, &config_path, &gateway_addr)?;

    let (worker_id, transport_secret) = register_worker(&gateway_addr)?;

    // --- Box 1 + 2: submit -> run_id, and a retry addresses the SAME run. ---
    let run_id = submit_job(
        &gateway_addr,
        "harness-idempotent-job",
        "fix the flaky test",
    )?;
    let retried = resubmit_job(
        &gateway_addr,
        "harness-idempotent-job",
        "fix the flaky test",
    )?;
    if retried != run_id {
        bail!(
            "a retried submit under the same Idempotency-Key must return the ORIGINAL run_id; \
             got {retried} after {run_id}"
        );
    }

    // Observation before the runtime has touched it: durable, addressable, and
    // explicitly not collectable yet.
    let status = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}"),
        CALLER_AUTH,
    )?;
    expect_status(&status, 200, "GET /v1/agent-jobs/{id}")?;
    let body = json_body(&status)?;
    if body["status"] != "queued" || body["terminal"] != Value::Bool(false) {
        bail!(
            "a freshly submitted job must be non-terminal `queued`: {}",
            status.body
        );
    }
    let premature = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/result"),
        CALLER_AUTH,
    )?;
    if premature.status != 409 {
        bail!(
            "collecting a non-terminal job must be refused with 409, got {}: {}",
            premature.status,
            premature.body
        );
    }

    // --- Box 4: another tenant cannot observe or collect it, by id. ---
    for path in [
        format!("/v1/agent-jobs/{run_id}"),
        format!("/v1/agent-jobs/{run_id}/events"),
        format!("/v1/agent-jobs/{run_id}/result"),
    ] {
        let leaked = get_json(&gateway_addr, &path, INTRUDER_AUTH)?;
        if leaked.status != 404 {
            bail!(
                "another tenant must not observe {path} (expected 404, got {}): {}",
                leaked.status,
                leaked.body
            );
        }
        if leaked.body.contains("fix the flaky test") {
            bail!(
                "cross-tenant read leaked the submitted job input: {}",
                leaked.body
            );
        }
    }
    let cross_cancel = http_request_addr(
        &gateway_addr,
        "POST",
        &format!("/v1/agent-jobs/{run_id}/cancel"),
        &[INTRUDER_AUTH, JSON_CONTENT],
        "{}",
    )?;
    if cross_cancel.status != 404 {
        bail!(
            "another tenant must not cancel the run (expected 404, got {}): {}",
            cross_cancel.status,
            cross_cancel.body
        );
    }

    // --- Box 1 (collect): the WORKER drives the run terminal, which is the
    // only production path that advances `agent_runs.status`. ---
    let lease = lease_dispatch_for(&gateway_addr, &worker_id, &transport_secret, &run_id)?;
    report_run_state(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &lease,
        &run_id,
        &serde_json::json!({ "state": "started" }),
    )?;
    let running = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}"),
        CALLER_AUTH,
    )?;
    if json_body(&running)?["status"] != "running" {
        bail!(
            "a worker lifecycle report must advance the canonical run status: {}",
            running.body
        );
    }
    report_run_state(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &lease,
        &run_id,
        &serde_json::json!({
            "state": "completed",
            "turns_executed": 4,
            "output": "opened PR #474"
        }),
    )?;

    let events = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/events"),
        CALLER_AUTH,
    )?;
    expect_status(&events, 200, "GET /v1/agent-jobs/{id}/events")?;
    let events_body = json_body(&events)?;
    let rows = events_body["data"].as_array().cloned().unwrap_or_default();
    // The feed must carry BOTH the submit evidence and the worker-reported
    // state transitions -- the latter only exist because the #474 worker ->
    // gateway bridge writes the run's own timeline.
    let kinds: Vec<&str> = rows.iter().filter_map(|row| row["kind"].as_str()).collect();
    for expected in ["job_submitted", "run_state_reported", "run_completed"] {
        if !kinds.contains(&expected) {
            bail!(
                "the job's event feed must carry a `{expected}` entry, saw {kinds:?}: {}",
                events.body
            );
        }
    }
    if events_body["next_after_event_id"].is_null() {
        bail!(
            "the event feed must hand back a resumable cursor: {}",
            events.body
        );
    }

    // The cursor is a real resume point, not decoration: replaying from it
    // returns only what came after.
    let cursor = events_body["next_after_event_id"]
        .as_str()
        .unwrap_or_default();
    let resumed_feed = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/events?after_event_id={cursor}"),
        CALLER_AUTH,
    )?;
    expect_status(&resumed_feed, 200, "GET events after a cursor")?;
    let resumed_rows = json_body(&resumed_feed)?["data"]
        .as_array()
        .map(|rows| rows.len())
        .unwrap_or_default();
    if resumed_rows != 0 {
        bail!(
            "resuming from the feed's own cursor must return no already-seen events, got {resumed_rows}: {}",
            resumed_feed.body
        );
    }

    let result = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/result"),
        CALLER_AUTH,
    )?;
    expect_status(&result, 200, "GET /v1/agent-jobs/{id}/result")?;
    let result_body = json_body(&result)?;
    if result_body["status"] != "completed" || result_body["output"] != "opened PR #474" {
        bail!(
            "the collected result must be the runtime's real output, not null: {}",
            result.body
        );
    }

    // A late/duplicate worker report must not rewrite a collected result.
    report_run_state(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &lease,
        &run_id,
        &serde_json::json!({ "state": "failed", "output": "rewritten" }),
    )?;
    let recollected = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{run_id}/result"),
        CALLER_AUTH,
    )?;
    let recollected_body = json_body(&recollected)?;
    if recollected_body["status"] != "completed" || recollected_body["output"] != "opened PR #474" {
        bail!(
            "a late worker report must NOT rewrite an already-collected result: {}",
            recollected.body
        );
    }

    // --- Box 3: cancellation stops the work in the RUNTIME and terminalizes
    // the run. #551 settled which mechanism discharges "stops the work": it
    // depends on whether a worker holds the job, so BOTH arms are driven here.
    //
    // Asserting only the leased arm would leave the far more common unleased
    // one unheld; asserting the unleased arm as "no cancel_run appears" would
    // be satisfied by a cancel path that had been deleted outright. So the
    // unleased arm asserts the WITHDRAWAL positively (nothing for that run is
    // ever offered again, while an un-cancelled control job submitted right
    // after it still is), and the leased arm asserts the `cancel_run` reaches
    // the transport for real. ---

    // 3a. NOBODY has leased it: the queued work is withdrawn, and the flag says
    // so rather than claiming a dispatch that would have been addressed at no
    // one.
    let abandoned = submit_job(&gateway_addr, "harness-cancel-job", "a job to abandon")?;
    // Submitted AFTER the job being cancelled, and deliberately never
    // cancelled. It is the control that stops "the worker was offered nothing
    // for the cancelled run" from being satisfied by a poll seam that offers
    // nothing to anybody.
    let control = submit_job(
        &gateway_addr,
        "harness-cancel-control-job",
        "a job nobody cancels",
    )?;
    let cancelled = http_request_addr(
        &gateway_addr,
        "POST",
        &format!("/v1/agent-jobs/{abandoned}/cancel"),
        &[CALLER_AUTH, JSON_CONTENT],
        "{}",
    )?;
    expect_status(&cancelled, 200, "POST /v1/agent-jobs/{id}/cancel")?;
    let cancelled_receipt = json_body(&cancelled)?;
    if cancelled_receipt["cancelled"] != Value::Bool(true) {
        bail!(
            "cancelling a live job must report cancelled=true: {}",
            cancelled.body
        );
    }
    // `false` is deterministic HERE because this harness runs a SINGLE gateway
    // process, so the node serving the cancel is necessarily the node holding
    // the runnable copy. It is not a wire contract: the same cancel legitimately
    // answers `true` on a multi-replica deployment where the copy lives on a
    // peer, because then a durable `cancel_run` is the only supersedable
    // evidence available. The field reports WHICH remedy ran; `cancelled` above
    // is what reports that the cancel took effect.
    if cancelled_receipt["runtime_cancel_dispatched"] != Value::Bool(false) {
        bail!(
            "no worker had leased this job and this harness runs one gateway process, so there \
             was no holder to hand a cancel_run to; the receipt must report \
             runtime_cancel_dispatched=false: {}",
            cancelled.body
        );
    }
    let cancelled_status = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{abandoned}"),
        CALLER_AUTH,
    )?;
    let cancelled_body = json_body(&cancelled_status)?;
    if cancelled_body["status"] != "cancelled" || cancelled_body["terminal"] != Value::Bool(true) {
        bail!("cancel must terminalize the run: {}", cancelled_status.body);
    }
    // ...and the work must be GONE from the runtime queue. Drain everything the
    // worker can still be offered: the cancelled job must not appear in it at
    // all -- not as a `start_run` (which a worker would execute) and not as a
    // `cancel_run` (which would mean the cancel had left the start dispatch
    // runnable and papered over it with a message addressed at nobody).
    let offered = drain_offered_dispatches(&gateway_addr, &worker_id, &transport_secret)?;
    if let Some((run_id, action)) = offered
        .iter()
        .find(|(offered_run, _)| offered_run == &abandoned)
    {
        bail!(
            "cancelling a job no worker had leased must WITHDRAW its work from the runtime \
             queue, but the worker was still offered `{action}` for {run_id}; the whole drain \
             was {offered:?}"
        );
    }
    if !offered
        .iter()
        .any(|(run, action)| run == &control && action == "start_run")
    {
        bail!(
            "the drain never offered the un-cancelled control job {control}, so \"nothing was \
             offered for the cancelled job\" proves nothing about the withdrawal; the drain was \
             {offered:?}"
        );
    }

    // 3b. A worker HOLDS it: withdrawing the start dispatch would yank a row
    // its holder still has to ack, so the holder is TOLD instead -- and this is
    // the half that must keep real coverage. Suppressing the `cancel_run`
    // enqueue in `cancel_agent_job_in_runtime` reddens the lease below.
    let held = submit_job(
        &gateway_addr,
        "harness-cancel-leased-job",
        "a job a worker picks up first",
    )?;
    let held_lease = lease_dispatch_for(&gateway_addr, &worker_id, &transport_secret, &held)?;
    if held_lease["action"] != "start_run" {
        bail!("the worker must hold the job's start dispatch before it is cancelled: {held_lease}");
    }
    let held_cancel = http_request_addr(
        &gateway_addr,
        "POST",
        &format!("/v1/agent-jobs/{held}/cancel"),
        &[CALLER_AUTH, JSON_CONTENT],
        "{}",
    )?;
    expect_status(
        &held_cancel,
        200,
        "POST /v1/agent-jobs/{id}/cancel (leased)",
    )?;
    let held_receipt = json_body(&held_cancel)?;
    if held_receipt["runtime_cancel_dispatched"] != Value::Bool(true) {
        bail!(
            "a worker held this job, so the cancel had to be dispatched to the runtime: {}",
            held_cancel.body
        );
    }
    // The receipt is the gateway's own claim about itself; this is the
    // independent one. The cancel is only real if the RUNTIME transport hands
    // it to the worker over the same poll protocol that handed out the start.
    let cancel_lease = lease_action_for(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &held,
        "cancel_run",
    )?;
    if cancel_lease["action"] != "cancel_run"
        || cancel_lease["run_id"].as_str() != Some(held.as_str())
    {
        bail!("cancel did not reach the runtime transport: {cancel_lease}");
    }
    let held_status = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{held}"),
        CALLER_AUTH,
    )?;
    if json_body(&held_status)?["status"] != "cancelled" {
        bail!(
            "cancelling a leased job must terminalize it too: {}",
            held_status.body
        );
    }

    // --- Box 5: the job survives a restart of the serving component. ---
    let survivor = submit_job(
        &gateway_addr,
        "harness-restart-job",
        "a job that outlives its request",
    )?;
    let reload = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &[ADMIN_AUTH, JSON_CONTENT],
        &serde_json::json!({ "config_yaml": scenario_config(&gateway_addr) }).to_string(),
    )?;
    if reload.status != 200 {
        bail!(
            "the simulated restart (config reload) failed: {}",
            reload.raw
        );
    }
    let survived = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{survivor}"),
        CALLER_AUTH,
    )?;
    expect_status(&survived, 200, "GET /v1/agent-jobs/{id} after restart")?;
    if json_body(&survived)?["status"] != "queued" {
        bail!(
            "the job must still be queued after the restart: {}",
            survived.body
        );
    }
    // The dispatch must come back out of durable storage: the worker can still
    // lease the surviving job's work on the rebuilt state.
    //
    // The reload replaces the whole lease queue with whatever
    // `self_hosted_run_dispatches` still holds, which is the one moment a
    // dispatch that was only removed from memory would come back. The cancelled
    // job must not be offered on the far side of it (#551). Deliberately does
    // NOT claim to identify WHICH guard delivered that -- the withdrawal's
    // durable delete and the poll's settled-run refusal both hold here, and
    // holding twice is the point.
    let resumed = lease_dispatch_rejecting(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &survivor,
        &[abandoned.as_str()],
    )?;
    if resumed["run_id"].as_str() != Some(survivor.as_str()) {
        bail!("the restarted node did not re-offer the job's start dispatch: {resumed}");
    }
    report_run_state(
        &gateway_addr,
        &worker_id,
        &transport_secret,
        &resumed,
        &survivor,
        &serde_json::json!({ "state": "completed", "output": "done after restart" }),
    )?;
    let resumed_result = get_json(
        &gateway_addr,
        &format!("/v1/agent-jobs/{survivor}/result"),
        CALLER_AUTH,
    )?;
    expect_status(&resumed_result, 200, "collect after restart")?;
    if json_body(&resumed_result)?["output"] != "done after restart" {
        bail!(
            "the resumed job must still be collectable end to end: {}",
            resumed_result.body
        );
    }

    // --- Box 5 (#527): a submit that OMITS `required_capabilities` is accepted,
    // and the runtime's own default reaches the worker. ---
    //
    // This is the contract #527 bet the admin console on when it widened the
    // generated type to `required_capabilities?: string[]`. Asserting the 202
    // alone would be vacuous, and so would asserting only that a worker leases
    // it: verified by neutralizing the handler's `is_empty() -> ["shell"]`
    // fallback, a dispatch carrying `required_capabilities: []` is STILL offered
    // to and leased by this worker. The requirement the omitted field must
    // satisfy is that the dispatch reaches the runtime carrying the documented
    // default, so the assertion has to read the leased dispatch's own list.
    let defaulted = submit_job_omitting_capabilities(
        &gateway_addr,
        "harness-defaulted-capabilities",
        "run with no declared capabilities",
    )?;
    let defaulted_lease =
        lease_dispatch_for(&gateway_addr, &worker_id, &transport_secret, &defaulted)?;
    if defaulted_lease["required_capabilities"] != serde_json::json!(["shell"]) {
        bail!(
            "a submit omitting required_capabilities must dispatch the runtime default \
             [\"shell\"], got {}: {defaulted_lease}",
            defaulted_lease["required_capabilities"]
        );
    }

    println!("agent-jobs-api scenario passed");
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn json_body(response: &HttpResponse) -> Result<Value> {
    serde_json::from_str(&response.body)
        .with_context(|| format!("response body was not JSON: {}", response.raw))
}

fn expect_status(response: &HttpResponse, expected: u16, what: &str) -> Result<()> {
    if response.status != expected {
        bail!(
            "{what} expected HTTP {expected}, got {}: {}",
            response.status,
            response.body
        );
    }
    Ok(())
}

fn get_json(gateway_addr: &str, path: &str, auth: &str) -> Result<HttpResponse> {
    http_request_addr(gateway_addr, "GET", path, &[auth, JSON_CONTENT], "")
}

/// A first `POST /v1/agent-jobs` -> 202 Accepted + a fresh durable `run_id`.
fn submit_job(gateway_addr: &str, idempotency_key: &str, input: &str) -> Result<String> {
    let (run_id, deduplicated) = submit_raw(gateway_addr, idempotency_key, input, 202)?;
    if deduplicated {
        bail!("a first submit under {idempotency_key} must not report deduplicated=true");
    }
    Ok(run_id)
}

/// A retried `POST /v1/agent-jobs` under an already-used idempotency key: the
/// protocol answers 200 (nothing new was accepted) and MUST hand back the
/// original run id rather than spawning a second run.
fn resubmit_job(gateway_addr: &str, idempotency_key: &str, input: &str) -> Result<String> {
    let (run_id, deduplicated) = submit_raw(gateway_addr, idempotency_key, input, 200)?;
    if !deduplicated {
        bail!("a retried submit under {idempotency_key} must report deduplicated=true");
    }
    Ok(run_id)
}

/// A first `POST /v1/agent-jobs` whose body OMITS `required_capabilities`
/// entirely -> 202, and the runtime supplies its own default.
///
/// #527 made `required_capabilities` optional in the OpenAPI contract and in
/// the generated TS client, on the strength of `#[serde(default)]` plus the
/// `is_empty() -> ["shell"]` fallback in the submit handler. The admin console
/// now omits the field on every submit, so that fallback is load-bearing for a
/// real caller — and nothing exercised it: this harness and
/// `agent_jobs_test.rs` both only ever sent `["shell"]` explicitly.
fn submit_job_omitting_capabilities(
    gateway_addr: &str,
    idempotency_key: &str,
    input: &str,
) -> Result<String> {
    let (run_id, deduplicated) = submit_raw_with(gateway_addr, idempotency_key, input, 202, None)?;
    if deduplicated {
        bail!("a first submit under {idempotency_key} must not report deduplicated=true");
    }
    Ok(run_id)
}

fn submit_raw(
    gateway_addr: &str,
    idempotency_key: &str,
    input: &str,
    expected_status: u16,
) -> Result<(String, bool)> {
    submit_raw_with(
        gateway_addr,
        idempotency_key,
        input,
        expected_status,
        Some(&["shell"]),
    )
}

/// `capabilities: None` omits the `required_capabilities` key from the request
/// body altogether — not `[]`, not `null`, absent — which is what the console
/// and any other optional-field client actually put on the wire.
fn submit_raw_with(
    gateway_addr: &str,
    idempotency_key: &str,
    input: &str,
    expected_status: u16,
    capabilities: Option<&[&str]>,
) -> Result<(String, bool)> {
    let header = format!("Idempotency-Key: {idempotency_key}");
    let mut payload = serde_json::json!({ "input": input });
    if let Some(capabilities) = capabilities {
        payload["required_capabilities"] = serde_json::json!(capabilities);
    }
    let response = http_request_addr(
        gateway_addr,
        "POST",
        "/v1/agent-jobs",
        &[CALLER_AUTH, JSON_CONTENT, header.as_str()],
        &payload.to_string(),
    )?;
    if response.status != expected_status {
        bail!(
            "submit expected HTTP {expected_status}, got {}: {}",
            response.status,
            response.body
        );
    }
    let body = json_body(&response)?;
    let run_id = body["run_id"]
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("submit response carried no run_id: {}", response.body))?;
    if run_id.trim().is_empty() {
        bail!("submit returned an empty run_id: {}", response.body);
    }
    Ok((run_id, body["deduplicated"] == Value::Bool(true)))
}

fn register_worker(gateway_addr: &str) -> Result<(String, String)> {
    let response = http_request_addr(
        gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &[ADMIN_AUTH, JSON_CONTENT],
        &serde_json::json!({
            "tenant": {
                "organization_id": TENANT,
                "team_id": null,
                "project_id": null,
                "workspace_id": WORKSPACE,
                "user_id": null,
                "api_key_id": "job-e2e-admin"
            },
            "workspace_id": WORKSPACE,
            "worker_name": "job-e2e-worker",
            "identity_fingerprint": WORKER_FINGERPRINT,
            "orchestration_enabled": false
        })
        .to_string(),
    )?;
    if response.status != 200 && response.status != 201 {
        bail!("self-hosted worker registration failed: {}", response.raw);
    }
    let json = json_body(&response)?;
    let worker_id = json["worker"]["id"]
        .as_str()
        .with_context(|| format!("registration carried no worker id: {}", response.body))?
        .to_string();
    let secret = json["transport_token_secret"]
        .as_str()
        .with_context(|| {
            format!(
                "registration carried no transport secret: {}",
                response.body
            )
        })?
        .to_string();
    Ok((worker_id, secret))
}

fn worker_identity(worker_id: &str, transport_secret: &str) -> Value {
    serde_json::json!({
        "tenant_id": TENANT,
        "workspace_id": WORKSPACE,
        "worker_id": worker_id,
        "token_id": WORKER_FINGERPRINT,
        "token_secret": transport_secret,
    })
}

fn lease_dispatch_for(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
    run_id: &str,
) -> Result<Value> {
    lease_action_for(
        gateway_addr,
        worker_id,
        transport_secret,
        run_id,
        "start_run",
    )
}

/// [`lease_dispatch_for`], additionally failing if the queue ever offers this
/// worker anything at all for a run in `withdrawn` (#551).
fn lease_dispatch_rejecting(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
    run_id: &str,
    withdrawn: &[&str],
) -> Result<Value> {
    lease_action_rejecting(
        gateway_addr,
        worker_id,
        transport_secret,
        run_id,
        "start_run",
        withdrawn,
    )
}

/// Polls the real worker lease protocol until it is offered `action` for
/// `run_id`.
fn lease_action_for(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
    run_id: &str,
    action: &str,
) -> Result<Value> {
    lease_action_rejecting(
        gateway_addr,
        worker_id,
        transport_secret,
        run_id,
        action,
        &[],
    )
}

/// Polls the real worker lease protocol until it is offered `action` for
/// `run_id`, and fails outright if it is ever offered ANY dispatch for a run in
/// `withdrawn`.
///
/// The rejection is on the run, not on the action: a cancelled job whose work
/// was withdrawn has no dispatch of any kind left to offer, and a `cancel_run`
/// surfacing for it would mean the start dispatch had been left runnable
/// (#551).
fn lease_action_rejecting(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
    run_id: &str,
    action: &str,
    withdrawn: &[&str],
) -> Result<Value> {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < Duration::from_secs(20) {
        let response = poll_for_dispatch(gateway_addr, worker_id, transport_secret)?;
        if response.status == 204 {
            last = "204 (no dispatch offered)".to_string();
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let lease = json_body(&response)?;
        let leased_run = lease["run_id"].as_str().unwrap_or_default();
        if withdrawn.contains(&leased_run) {
            bail!(
                "a cancelled job's work must stay withdrawn from the runtime queue, but the \
                 worker was offered `{}` for {leased_run}: {lease}",
                lease["action"]
            );
        }
        if leased_run == run_id && lease["action"] == action {
            return Ok(lease);
        }
        last = response.body.clone();
        thread::sleep(Duration::from_millis(100));
    }
    bail!("worker never leased a {action} dispatch for {run_id}; last poll: {last}")
}

/// How many dispatches [`drain_offered_dispatches`] will take before it treats
/// the queue as one that never empties.
///
/// Each drained dispatch is leased to this worker for 60s and so cannot be
/// offered again, which is what makes the drain terminate; the bound only
/// exists so a poll seam that never answers 204 fails the scenario instead of
/// hanging it.
const DRAIN_MAX_DISPATCHES: usize = 16;

/// Leases everything the queue will currently offer this worker, until it
/// answers 204, and reports the `(run_id, action)` of each.
///
/// #551: this is how the harness observes a WITHDRAWAL. "The cancelled job was
/// not offered" is only evidence if the poll that failed to offer it was
/// offering other things, so the caller checks both directions against one
/// drain.
fn drain_offered_dispatches(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
) -> Result<Vec<(String, String)>> {
    let mut offered: Vec<(String, String)> = Vec::new();
    for _ in 0..DRAIN_MAX_DISPATCHES {
        let response = poll_for_dispatch(gateway_addr, worker_id, transport_secret)?;
        if response.status == 204 {
            return Ok(offered);
        }
        let lease = json_body(&response)?;
        offered.push((
            lease["run_id"].as_str().unwrap_or_default().to_string(),
            lease["action"].as_str().unwrap_or_default().to_string(),
        ));
    }
    bail!(
        "the worker lease queue never went empty after {DRAIN_MAX_DISPATCHES} dispatches: \
         {offered:?}"
    )
}

/// One trip through the real worker poll protocol: 200 + a lease, or 204.
fn poll_for_dispatch(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
) -> Result<HttpResponse> {
    let body = serde_json::json!({
        "protocol_version": 1,
        "identity": worker_identity(worker_id, transport_secret),
        "supported_capabilities": ["shell"],
        "now_unix": now_unix(),
        "lease_duration_secs": 60
    })
    .to_string();
    let response = http_request_addr(
        gateway_addr,
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, TRANSPORT_SECURITY],
        &body,
    )?;
    if response.status != 200 && response.status != 204 {
        bail!("worker poll was rejected: {}", response.raw);
    }
    Ok(response)
}

fn report_run_state(
    gateway_addr: &str,
    worker_id: &str,
    transport_secret: &str,
    lease: &Value,
    run_id: &str,
    event_json: &Value,
) -> Result<()> {
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
    let response = http_request_addr(
        gateway_addr,
        "POST",
        "/v1/self-hosted-workers/events",
        &[JSON_CONTENT, TRANSPORT_SECURITY],
        &body,
    )?;
    if response.status != 200 && response.status != 201 {
        bail!("worker telemetry was rejected: {}", response.raw);
    }
    Ok(())
}

fn scenario_config(gateway_addr: &str) -> String {
    format!(
        r#"listen: {gateway_addr:?}
cluster:
  enabled: true
  cluster_id: "agent-jobs-e2e"
  node_id: "agent-jobs-node"
  node_region: "local"
  node_zone: "local-a"
  state_backend: "local"
  counter_backend: "local"
providers:
  - name: "openai"
    kind: "openai"
    base_url: "http://127.0.0.1:1/v1"
    api_key_env: "FERROGATE_PROVIDER_SECRET"
models:
  - name: "fast-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini"
    capabilities: ["chat"]
api_keys:
  - id: "job-e2e-admin"
    name: "Async job E2E operator"
    key: "job-e2e-admin-secret"
    scopes: ["admin.read", "admin.write"]
  - id: "job-e2e-caller"
    name: "Async job E2E submitter"
    key: "job-e2e-caller-secret"
    scopes: ["agent.runs.create", "agent.runs.read"]
    organization_id: "{TENANT}"
    workspace_id: "{WORKSPACE}"
  - id: "job-e2e-intruder"
    name: "Async job E2E other tenant"
    key: "job-e2e-intruder-secret"
    scopes: ["agent.runs.create", "agent.runs.read"]
    organization_id: "org_job_e2e_other"
    workspace_id: "ws_job_e2e_other"
agent_runtime:
  enabled: true
"#
    )
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(binary: &Path, config_path: &Path, gateway_addr: &str) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < GATEWAY_READINESS_TIMEOUT {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before agent-jobs E2E readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for the agent-jobs E2E gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
