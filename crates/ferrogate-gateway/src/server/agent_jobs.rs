// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Caller-facing async agent-job surface (#474): submit -> run_id,
// observe (status + incremental run-timeline events), retrieve the result,
// and cancel -- all tenant-scoped and durable across restarts.

//! The async long-running agent-job protocol (issue #474).
//!
//! Every other ingress FerroGate exposes is request/response and therefore
//! bounded by an HTTP request lifetime: `POST /v1/agent-runs` drives the
//! bounded harness to completion *inside* the request. A coding-agent task runs
//! for minutes to hours, so this module adds the missing caller-facing verbs on
//! top of the SAME durable evidence the platform already keeps -- it does not
//! build a parallel job stack:
//!
//! | verb | route | reuses |
//! |------|-------|--------|
//! | submit | `POST /v1/agent-jobs` | `agent_runs` row + the self-hosted lease queue (#414 dispatch transport) |
//! | status | `GET /v1/agent-jobs/{run_id}` | `AppState::agent_run_timeline` + `AppState::self_hosted_run_timeline` |
//! | events | `GET /v1/agent-jobs/{run_id}/events` | the existing agent-run timeline (`agent_run_events`) |
//! | result | `GET /v1/agent-jobs/{run_id}/result` | the same timeline + worker-reported artifact events, including #472 coding-agent work products |
//! | cancel | `POST /v1/agent-jobs/{run_id}/cancel` | run terminalization + either withdrawal of the start dispatch or a `cancel_run` (#414) -- see [`cancel_agent_job`] |
//!
//! **Durability.** Submission writes the `agent_runs` row through the same
//! durable seam the synchronous create path uses and enqueues a
//! `SelfHostedRunAction::StartRun` dispatch, which is written through to
//! `self_hosted_run_dispatches` and rebuilt into the lease queue on startup.
//! Both survive the request that created them (and a restart of the serving
//! component) -- the entire point of the protocol.
//!
//! **Idempotency (the requirement most likely to be got wrong).** The
//! idempotency key is explicit and first-class: `Idempotency-Key:` (header) or
//! `idempotency_key` (body). The run id is *derived* from
//! `(resolved tenant, idempotency key)` by [`agent_job_run_id`], so a retried
//! submit addresses the SAME `run_id` by construction; the existing
//! `agent_runs` row is then the dedup gate and the original id is returned with
//! `deduplicated: true`. Two concurrent submits that both miss the gate still
//! converge on one job: the run row is an upsert on that derived id and the
//! dispatch id is derived from it too (the lease queue dedups on dispatch id).
//! The key is namespaced by tenant, so one tenant's key can never address (or
//! collide with) another tenant's run.
//!
//! **Tenant isolation.** Every read resolves the run through
//! `AppState::agent_run_timeline` with `AgentRunFilter::organization_id` pinned
//! by `crate::auth::enforce_tenant_filter` -- i.e. isolation is applied at the
//! storage/query layer, before anything is shaped for the response, exactly as
//! `handle_admin_agent_runs` does. A cross-tenant `run_id` resolves to `None`
//! and is reported as 404 (not 403), so the surface is not an existence oracle.
//!
//! **How a job ever becomes terminal.** The collect verb is only meaningful if
//! something advances `agent_runs.status` away from `queued`. Two writers do:
//! the caller's own `POST .../cancel`, and -- for a job the runtime actually
//! runs -- `AppState::apply_worker_reported_run_state`, the worker->gateway
//! bridge on the telemetry ingest seam. The worker's report is projected onto
//! the SAME run row and the SAME run timeline this surface reads, so `/result`
//! returns the runtime's real output rather than a permanent
//! `409 agent_job_not_terminal`.
//!
//! **Retention (#502).** A run reaching a terminal state is a single event with
//! two consequences, and both hang off `agent_runs.status` rather than off the
//! dispatch transport: it releases the submitter's slot against
//! [`AGENT_JOB_MAX_OPEN_PER_TENANT`], and it reclaims the run's rows from the
//! lease queue and from `self_hosted_run_dispatches`
//! ([`AppState::reclaim_settled_run_dispatches`]). Keying either on the
//! runtime's ack was wrong in opposite directions: the ack is not what the
//! production completion path writes, so slots leaked; and nothing deleted a
//! dispatch row at all, so the table only ever grew and the concurrency cap was
//! doing double duty as its only bound.

use std::time::{SystemTime, UNIX_EPOCH};

use ferrogate_runtime::{
    coding_agent::WorkProductView, SelfHostedRunAction, SelfHostedRunDispatch,
};
use ferrogate_storage::{StoredAgentRun, StoredAgentRunEvent};
use http::{HeaderMap, Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{enforce_tenant_filter, AuthContext};
use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_error_and_close, write_json_response},
    state::{AdminAuditEventDraft, AgentRunFilter, AgentRunTimeline, AppState},
};

use super::{body::read_request_body, FerroGateway, ProxyContext};

/// Explicit idempotency-key header. Mirrors the industry-standard spelling so a
/// generic HTTP client's retry middleware sets it without FerroGate-specific
/// wiring; the body field `idempotency_key` is the equivalent for clients that
/// cannot set headers.
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Max length of an idempotency key. Long enough for a UUID, a ULID, or a
/// caller's `{repo}:{issue}:{attempt}` composite; short enough that the key is
/// never a payload channel.
const IDEMPOTENCY_KEY_MAX_LEN: usize = 200;

/// Max characters of submitted input retained on the `job_submitted` timeline
/// event. The timeline is evidence, not a job store: enough to identify the
/// job, bounded so a large prompt cannot bloat every timeline read.
const SUBMITTED_INPUT_EVIDENCE_MAX_CHARS: usize = 2_000;

/// Default / maximum page size for the incremental event feed.
const EVENT_PAGE_DEFAULT_LIMIT: usize = 100;
const EVENT_PAGE_MAX_LIMIT: usize = 500;

/// Scope required to submit or cancel a job -- the same scope the synchronous
/// `POST /v1/agent-runs` create path enforces, because it is the same
/// privilege (start agent work billed to this tenant).
const AGENT_JOB_WRITE_SCOPE: &str = "agent.runs.create";

/// Scope required to observe a job (status / events / result).
const AGENT_JOB_READ_SCOPE: &str = "agent.runs.read";

/// Max jobs one tenant may hold OPEN at once (#474 rework): submitted through
/// THIS surface, unacknowledged, and whose run has not SETTLED.
///
/// `/v1/agent-jobs` is the first surface that lets an ordinary tenant API key
/// enqueue runtime dispatches at will, so it bounds concurrency per tenant: a
/// tenant whose jobs keep reaching a terminal state -- by finishing, failing or
/// being cancelled -- is never throttled, while a runaway submit loop is
/// refused with 429.
///
/// The cap is a CONCURRENCY bound and is no longer load-bearing for retention
/// (#502): a settled run's dispatch rows are reclaimed from the lease queue and
/// from `self_hosted_run_dispatches`
/// ([`AppState::reclaim_settled_run_dispatches`]), so a submit/cancel loop
/// leaves nothing behind rather than trading one permanent row per iteration
/// for a freed slot. Before that, the cap WAS the only thing standing between
/// a caller and a table nothing ever deleted.
const AGENT_JOB_MAX_OPEN_PER_TENANT: usize = 200;

/// Error code of the retention refusal. Named once so the handler, the
/// contract and the tests that hold the boundary all spell it the same way.
const AGENT_JOB_OPEN_LIMIT_CODE: &str = "agent_job_open_limit_reached";

/// Run statuses that mean "this job will not change again". A caller polling
/// status stops here; `.../result` only answers 200 in these states.
///
/// Delegates to the shared classifier the worker->gateway bridge uses when it
/// decides whether a reported state settles a run, so the collect verb and the
/// writer of the state it collects can never disagree.
fn agent_job_status_is_terminal(status: &str) -> bool {
    crate::state::agent_run_status_is_terminal(status)
}

/// Derive the durable job id from the tenant and the explicit idempotency key.
///
/// This is the whole idempotency mechanism: submission does not mint a random
/// id and then look for a duplicate afterwards (which races), it *addresses* a
/// deterministic id. A retry with the same key computes the same id, finds the
/// existing `agent_runs` row, and returns it. Tenant is mixed into the digest,
/// so identical keys in different tenants are different jobs and no key can be
/// used to probe for (or clobber) another tenant's run.
fn agent_job_run_id(tenant_id: &str, idempotency_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    // Unit-separator domain break so ("ab", "c") and ("a", "bc") cannot hash
    // to the same job id.
    hasher.update([0x1f]);
    hasher.update(idempotency_key.as_bytes());
    let digest = hasher.finalize();
    let mut id = String::from("job-");
    for byte in digest.iter().take(16) {
        id.push_str(&format!("{byte:02x}"));
    }
    id
}

/// Dispatch-id namespace of the START dispatches THIS surface mints. It is the
/// only thing that distinguishes a caller's submit from the other producers of
/// `start_run` dispatches in the same queue -- schedule fires
/// (`schedule-dispatch-*`, #426) and worker-registration seeds
/// (`self-hosted-dispatch-*`) -- so the submit budget can be scoped to work the
/// caller actually asked for (#502).
const AGENT_JOB_START_DISPATCH_PREFIX: &str = "agent-job-start-";

/// Deterministic dispatch ids derived from the job id, so a racing double
/// submit/cancel enqueues the SAME dispatch (the lease queue dedups on id).
fn agent_job_start_dispatch_id(run_id: &str) -> String {
    format!("{AGENT_JOB_START_DISPATCH_PREFIX}{run_id}")
}

fn agent_job_cancel_dispatch_id(run_id: &str) -> String {
    format!("agent-job-cancel-{run_id}")
}

/// The concurrency gate AND the enqueue, as one operation: `Ok(())` means the
/// job's start dispatch is queued and durable, `Err((status, code, message))`
/// is the VERBATIM refusal the handler writes back.
///
/// Gate and enqueue are fused deliberately (#502 rework). Splitting them left
/// the admission check-then-act -- the count took the queue lock, released it,
/// and the enqueue took a fresh one ~50 lines later, so K concurrent submits at
/// `cap - 1` all read "below the cap" and all landed. Nothing spanned the two
/// and no test could see it. [`AppState::admit_and_enqueue_agent_job_dispatch`]
/// recounts under the guard that performs the insert.
///
/// It is still the seam the boundary is tested through, as the response a
/// caller observes rather than as an internal counter (#500's rule that an
/// assertion which cannot fail is not coverage) -- now with the side effect
/// included, so a probe can no longer claim a slot the concurrent submit took.
///
/// Reached only on a genuinely NEW job -- a retry of an existing idempotency
/// key deduplicates before this point and is never refused -- so a caller can
/// always re-poll and cancel what it already has.
fn agent_job_admit_submit(
    state: &AppState,
    tenant_id: &str,
    dispatch: SelfHostedRunDispatch,
) -> Result<(), (StatusCode, &'static str, String)> {
    match state.admit_and_enqueue_agent_job_dispatch(
        tenant_id,
        AGENT_JOB_START_DISPATCH_PREFIX,
        AGENT_JOB_MAX_OPEN_PER_TENANT,
        dispatch,
    ) {
        crate::state::AgentJobDispatchAdmission::Enqueued => Ok(()),
        crate::state::AgentJobDispatchAdmission::OverBudget { open } => Err((
            StatusCode::TOO_MANY_REQUESTS,
            AGENT_JOB_OPEN_LIMIT_CODE,
            // Every remedy this names is real, which is the whole point of
            // #502. A job stops counting the moment its RUN settles, and the
            // three ways a run settles are: the runtime reporting it finished
            // or failed (worker telemetry -- the production completion path,
            // which the pre-#502 ack-keyed release never observed, so a tenant
            // with a healthy worker was locked out after `cap` finished jobs),
            // the runtime acknowledging the dispatch, and the caller cancelling
            // it. The settled check is a durable read of the run row, so a job
            // settled through another replica releases here too.
            format!(
                "tenant already has {open} agent jobs in flight (limit \
                 {AGENT_JOB_MAX_OPEN_PER_TENANT}); a job stops counting as soon as its run \
                 reaches a terminal state, so wait for a running job to finish or release one \
                 now with POST /v1/agent-jobs/{{run_id}}/cancel"
            ),
        )),
        crate::state::AgentJobDispatchAdmission::TransportRefused(error) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "agent_job_dispatch_unavailable",
            format!("agent job could not be handed to the runtime transport: {error}"),
        )),
    }
}

/// The caller's submission document. `input` is the task; everything else
/// describes how the runtime should be selected, with defaults that make a
/// minimal `{"input": "..."}` a valid submission.
#[derive(Debug, Deserialize)]
struct AgentJobSubmitRequest {
    input: String,
    /// The explicit idempotency key (equivalent to the `Idempotency-Key`
    /// header, which wins when both are present).
    #[serde(default)]
    idempotency_key: Option<String>,
    #[serde(default)]
    framework_adapter: Option<String>,
    #[serde(default)]
    required_capabilities: Vec<String>,
    #[serde(default)]
    workload_ref: Option<String>,
}

/// The submit response. `deduplicated` is the observable proof of idempotency:
/// `false` + 202 on the first submit, `true` + 200 on every retry of the same
/// key, always carrying the ORIGINAL `run_id`.
#[derive(Debug, Serialize)]
struct AgentJobSubmitResponse {
    object: &'static str,
    run_id: String,
    status: String,
    idempotency_key: String,
    idempotency_key_source: &'static str,
    deduplicated: bool,
    terminal: bool,
    submitted_at_unix: Option<u64>,
    status_url: String,
    events_url: String,
    result_url: String,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct AgentJobStatusResponse {
    object: &'static str,
    run_id: String,
    status: String,
    terminal: bool,
    provider: Option<String>,
    turns_executed: u32,
    output_recorded: bool,
    event_count: usize,
    started_at_unix: Option<u64>,
    completed_at_unix: Option<u64>,
    first_seen_unix: Option<u64>,
    last_seen_unix: Option<u64>,
    /// Latest lifecycle state the runtime itself reported for this run, read
    /// from the existing self-hosted run timeline (same `run_id`). `None` when
    /// the runtime has not reported yet.
    runtime_reported_state: Option<String>,
    runtime_reported_event_count: usize,
    request_id: String,
}

/// One page of the incremental event feed, cursored by event id.
#[derive(Debug, Serialize)]
struct AgentJobEventPage {
    object: &'static str,
    run_id: String,
    data: Vec<StoredAgentRunEvent>,
    limit: usize,
    after_event_id: Option<String>,
    next_after_event_id: Option<String>,
    has_more: bool,
    /// `true` when the supplied `after_event_id` could not be located in the
    /// run's current event set (retention pruned it, or the caller invented
    /// it) and the page therefore restarts from the run's oldest retained
    /// event. The caller may see events it has already seen; it is never left
    /// with a permanently unusable cursor.
    cursor_reset: bool,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct AgentJobResultResponse {
    object: &'static str,
    run_id: String,
    status: String,
    terminal: bool,
    turns_executed: u32,
    output_recorded: bool,
    /// Terminal output carried on the run timeline, when the runtime recorded
    /// one. `None` is honest absence -- nothing is fabricated.
    output: Option<String>,
    /// Artifact evidence the runtime reported for this run (for a coding agent
    /// this is where the diff/PR reference lands, #472).
    artifacts: Vec<AgentJobArtifact>,
    /// The #472 coding-agent work products carried by those artifact events,
    /// decoded and **re-verified** against the `run_id` in the path. This is
    /// the "retrievable through the control plane" half of #472's acceptance,
    /// and it deliberately rides this route rather than adding a parallel
    /// `/admin/v1/.../work-products/{id}` surface: a work product has no life
    /// outside its run, and the run timeline is already the durable,
    /// tenant-scoped evidence store this handler reads.
    ///
    /// Empty for every non-coding job — the projection skips artifacts it does
    /// not recognise rather than failing the read.
    work_products: Vec<WorkProductView>,
    request_count: usize,
    billing_event_count: usize,
    completed_at_unix: Option<u64>,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct AgentJobArtifact {
    id: String,
    worker_id: String,
    occurred_at_unix: Option<u64>,
    event_json: String,
}

#[derive(Debug, Serialize)]
struct AgentJobCancelResponse {
    object: &'static str,
    run_id: String,
    status: String,
    terminal: bool,
    /// `true` when this call terminalized the run; `false` when it was already
    /// terminal (cancel is idempotent).
    cancelled: bool,
    /// See [`RUNTIME_CANCEL_DISPATCHED_DESCRIPTION`], which is the one copy of
    /// this sentence and is pinned to the published one by
    /// `the_published_meaning_of_runtime_cancel_dispatched_matches_the_code`.
    runtime_cancel_dispatched: bool,
    cancelled_at_unix: Option<u64>,
    request_id: String,
}

/// What `runtime_cancel_dispatched` means, written ONCE (#551 rework).
///
/// It had been written twice -- here and in the published OpenAPI description
/// (which the console's generated TypeScript then copies a third time) -- and
/// the two said different things: the published copy claimed a `cancel_run`
/// "happens only when a worker had already leased the job", which
/// `a_cancel_on_a_replica_that_never_served_the_submit_still_reaches_the_runtime`
/// disproves. Nothing read both, so nothing could notice; `check-openapi.py`
/// compares shapes, not prose, and any wording at all survived it. This
/// constant is the source, and the test named above fails when the published
/// description drifts from it again.
///
/// Nothing reads it at runtime -- the wire copy is the published document, and
/// this is what that document is checked against -- so it is dead outside the
/// test build by construction, not by oversight.
#[cfg_attr(not(test), allow(dead_code))]
const RUNTIME_CANCEL_DISPATCHED_DESCRIPTION: &str = "true when a cancel_run dispatch was handed to the runtime transport, which happens whenever the serving node could not simply WITHDRAW the queued work itself: a worker had already leased the job, or the job was submitted through a peer replica that still holds the runnable copy in its own lease queue. false means the serving node held the only copy and took it back. The field reports WHICH of the two remedies ran, never whether the cancel took effect -- a receipt with cancelled=true stopped the work either way.";

impl FerroGateway {
    /// Fan out the whole `/v1/agent-jobs[...]` surface by path suffix + method.
    pub(super) async fn handle_agent_jobs(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        if path == "/v1/agent-jobs" {
            return match *method {
                Method::POST => self.handle_agent_job_submit(session, ctx, headers).await,
                _ => method_not_allowed(session, ctx, "agent job submission requires POST").await,
            };
        }

        let Some(rest) = path
            .strip_prefix("/v1/agent-jobs/")
            .filter(|rest| !rest.is_empty())
        else {
            return not_found(session, ctx).await;
        };

        if let Some(run_id) = rest.strip_suffix("/events") {
            if !is_addressable_run_id(run_id) {
                return not_found(session, ctx).await;
            }
            return match *method {
                Method::GET => {
                    self.handle_agent_job_events(session, ctx, &headers, run_id, query)
                        .await
                }
                _ => method_not_allowed(session, ctx, "agent job events require GET").await,
            };
        }

        if let Some(run_id) = rest.strip_suffix("/result") {
            if !is_addressable_run_id(run_id) {
                return not_found(session, ctx).await;
            }
            return match *method {
                Method::GET => {
                    self.handle_agent_job_result(session, ctx, &headers, run_id)
                        .await
                }
                _ => method_not_allowed(session, ctx, "agent job result requires GET").await,
            };
        }

        if let Some(run_id) = rest.strip_suffix("/cancel") {
            if !is_addressable_run_id(run_id) {
                return not_found(session, ctx).await;
            }
            return match *method {
                Method::POST => {
                    self.handle_agent_job_cancel(session, ctx, &headers, run_id)
                        .await
                }
                _ => method_not_allowed(session, ctx, "agent job cancel requires POST").await,
            };
        }

        if !is_addressable_run_id(rest) {
            return not_found(session, ctx).await;
        }
        match *method {
            Method::GET => {
                self.handle_agent_job_status(session, ctx, &headers, rest)
                    .await
            }
            _ => method_not_allowed(session, ctx, "agent job status requires GET").await,
        }
    }

    async fn handle_agent_job_submit(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        if !state.config.agent_runtime.enabled {
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "agent_runtime_disabled",
                "agent runtime is disabled by operator config",
                &ctx.request_id,
            )
            .await;
        }
        let auth =
            match authenticate(&state, &headers, AGENT_JOB_WRITE_SCOPE, &ctx.request_id).await {
                Ok(auth) => auth,
                Err(error) => return write_auth_error(session, ctx, error).await,
            };

        let body = match read_request_body(session, state.limits().tool_body_max_bytes()).await? {
            Ok(body) => body,
            Err(limit) => {
                return write_json_error_and_close(
                    session,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                    &ctx.request_id,
                )
                .await;
            }
        };
        let request: AgentJobSubmitRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    format!("invalid agent job JSON: {error}"),
                    &ctx.request_id,
                )
                .await;
            }
        };
        if request.input.trim().is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_agent_job_input",
                "agent job input must not be empty",
                &ctx.request_id,
            )
            .await;
        }
        if request
            .required_capabilities
            .iter()
            .any(|capability| capability.trim().is_empty())
        {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_agent_job_capabilities",
                "agent job required_capabilities must not contain empty values",
                &ctx.request_id,
            )
            .await;
        }

        let idempotency = match resolve_idempotency_key(
            &headers,
            request.idempotency_key.as_deref(),
            &ctx.request_id,
        ) {
            Ok(idempotency) => idempotency,
            Err(message) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_idempotency_key",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let tenant = auth.tenant_context();
        let tenant_id = crate::state::self_hosted_tenant_id(&tenant);
        let run_id = agent_job_run_id(&tenant_id, &idempotency.key);

        // The dedup gate. A retried submit lands here and returns the ORIGINAL
        // run_id without enqueuing a second dispatch. The cross-tenant arm is
        // defence in depth: the id already namespaces the key by tenant, so a
        // foreign owner here means an id collision, never a reachable key.
        if let Some(existing) = state.agent_run_record(&run_id) {
            if existing.tenant.organization_id != tenant.organization_id {
                return write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "agent_job_id_conflict",
                    "an agent job with this id already exists for another tenant",
                    &ctx.request_id,
                )
                .await;
            }
            let response = AgentJobSubmitResponse {
                object: "agent_job",
                terminal: agent_job_status_is_terminal(&existing.status),
                status: existing.status.clone(),
                idempotency_key: idempotency.key.clone(),
                idempotency_key_source: idempotency.source,
                deduplicated: true,
                submitted_at_unix: existing.started_at_unix,
                status_url: format!("/v1/agent-jobs/{run_id}"),
                events_url: format!("/v1/agent-jobs/{run_id}/events"),
                result_url: format!("/v1/agent-jobs/{run_id}/result"),
                run_id,
                request_id: ctx.request_id.clone(),
            };
            return write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await;
        }

        let now = now_unix_seconds();
        let workspace_id = auth
            .workspace_id
            .clone()
            .or_else(|| auth.project_id.clone())
            .unwrap_or_else(|| "default".to_string());
        let dispatch = SelfHostedRunDispatch {
            dispatch_id: agent_job_start_dispatch_id(&run_id),
            action: SelfHostedRunAction::StartRun,
            tenant_id: tenant_id.clone(),
            workspace_id: workspace_id.clone(),
            session_id: format!("agent-job-session-{run_id}"),
            run_id: run_id.clone(),
            framework_adapter: request
                .framework_adapter
                .as_deref()
                .map(str::trim)
                .filter(|adapter| !adapter.is_empty())
                .unwrap_or("native-harness")
                .to_string(),
            required_capabilities: if request.required_capabilities.is_empty() {
                vec!["shell".to_string()]
            } else {
                request.required_capabilities.clone()
            },
            workload_ref: request
                .workload_ref
                .as_deref()
                .map(str::trim)
                .filter(|workload| !workload.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("agent-job://{run_id}")),
            // The queue rejects queued_at_unix == 0.
            queued_at_unix: now.max(1),
            request_id: Some(ctx.request_id.clone()),
            trace_id: ctx.trace_id.clone(),
            agent_run_id: Some(run_id.clone()),
            // #307: a caller-submitted job has no upstream governed action, so
            // the parent stays an explicit None (never fabricated).
            parent_action_fingerprint: None,
        };
        // The concurrency gate and the enqueue, as ONE operation (#502 rework),
        // and BEFORE the run row is claimed -- the same ordering the scheduler
        // uses. If the row were written first and the enqueue then failed,
        // every retry would be deduped against a job the runtime was never told
        // about. Enqueue is idempotent on the deterministic id, so re-running
        // this path is safe.
        if let Err((status, code, message)) = agent_job_admit_submit(&state, &tenant_id, dispatch) {
            return write_json_error(session, status, code, message, &ctx.request_id).await;
        }

        state.record_agent_run(StoredAgentRun {
            id: run_id.clone(),
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            tenant: tenant.clone(),
            status: "queued".to_string(),
            provider: "ferrogate.agent-job".to_string(),
            turns_executed: 0,
            output_recorded: false,
            started_at_unix: Some(now),
            completed_at_unix: None,
        });
        // The submission itself is the first entry on the run's EXISTING
        // timeline -- no parallel event stream is introduced.
        state.record_agent_run_event(StoredAgentRunEvent {
            id: format!("agent-job-submitted:{run_id}"),
            run_id: run_id.clone(),
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            tenant: tenant.clone(),
            turn: 0,
            kind: "job_submitted".to_string(),
            target: format!("agent_run:{run_id}"),
            outcome: "accepted".to_string(),
            tool_call_id: None,
            message: Some(truncate_evidence(&request.input)),
            occurred_at_unix: Some(now),
            action_fingerprint: None,
            decision: None,
            decision_reason: None,
            output_disposition: None,
        });
        state.record_admin_audit_event(agent_job_audit_event(
            ctx,
            &auth,
            &run_id,
            "agent_job.submitted",
            "accepted",
            format!(
                "agent job {run_id} submitted with idempotency key {}",
                idempotency.key
            ),
        ));

        let response = AgentJobSubmitResponse {
            object: "agent_job",
            status: "queued".to_string(),
            terminal: false,
            idempotency_key: idempotency.key,
            idempotency_key_source: idempotency.source,
            deduplicated: false,
            submitted_at_unix: Some(now),
            status_url: format!("/v1/agent-jobs/{run_id}"),
            events_url: format!("/v1/agent-jobs/{run_id}/events"),
            result_url: format!("/v1/agent-jobs/{run_id}/result"),
            run_id,
            request_id: ctx.request_id.clone(),
        };
        write_json_response(session, StatusCode::ACCEPTED, &response, &ctx.request_id).await
    }

    async fn handle_agent_job_status(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &HeaderMap,
        run_id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate_agent_job_read(&state, headers, &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let Some(timeline) = scoped_agent_job_timeline(&state, &auth, run_id) else {
            return job_not_found(session, ctx, run_id).await;
        };
        let runtime_timeline =
            state.self_hosted_run_timeline(run_id, enforce_tenant_filter(&auth, None).as_deref());
        let status = agent_job_status(&timeline);
        let response = AgentJobStatusResponse {
            object: "agent_job",
            run_id: run_id.to_string(),
            terminal: agent_job_status_is_terminal(&status),
            status,
            provider: timeline.run.as_ref().map(|run| run.provider.clone()),
            turns_executed: timeline.run.as_ref().map_or(0, |run| run.turns_executed),
            output_recorded: timeline.run.as_ref().is_some_and(|run| run.output_recorded),
            event_count: timeline.agent_events.len(),
            started_at_unix: timeline.run.as_ref().and_then(|run| run.started_at_unix),
            completed_at_unix: timeline.run.as_ref().and_then(|run| run.completed_at_unix),
            first_seen_unix: timeline.summary.first_seen_unix,
            last_seen_unix: timeline.summary.last_seen_unix,
            runtime_reported_state: runtime_timeline
                .as_ref()
                .and_then(|runtime| runtime.latest_lifecycle_state.clone()),
            runtime_reported_event_count: runtime_timeline
                .as_ref()
                .map_or(0, |runtime| runtime.reported_event_count),
            request_id: ctx.request_id.clone(),
        };
        write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
    }

    async fn handle_agent_job_events(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &HeaderMap,
        run_id: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate_agent_job_read(&state, headers, &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let cursor = match AgentJobEventCursor::from_query(query) {
            Ok(cursor) => cursor,
            Err(message) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_event_cursor",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        // The poll loop reads the run's OWN events only -- not the full
        // investigation timeline (request logs + billing + audit), which this
        // endpoint never renders. See `AppState::agent_run_event_feed`.
        let filter = AgentRunFilter {
            organization_id: enforce_tenant_filter(&auth, None),
            ..AgentRunFilter::default()
        };
        let Some(events) = state.agent_run_event_feed(run_id, &filter) else {
            return job_not_found(session, ctx, run_id).await;
        };
        let page = page_agent_job_events(events, &cursor);
        let response = AgentJobEventPage {
            object: "agent_job_event_page",
            run_id: run_id.to_string(),
            limit: cursor.limit,
            after_event_id: cursor.after_event_id.clone(),
            next_after_event_id: page.next_after_event_id,
            has_more: page.has_more,
            cursor_reset: page.cursor_reset,
            data: page.data,
            request_id: ctx.request_id.clone(),
        };
        write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
    }

    async fn handle_agent_job_result(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &HeaderMap,
        run_id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate_agent_job_read(&state, headers, &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let Some(timeline) = scoped_agent_job_timeline(&state, &auth, run_id) else {
            return job_not_found(session, ctx, run_id).await;
        };
        let status = agent_job_status(&timeline);
        if !agent_job_status_is_terminal(&status) {
            return write_json_error(
                session,
                StatusCode::CONFLICT,
                "agent_job_not_terminal",
                format!("agent job {run_id} is {status}; poll /v1/agent-jobs/{run_id} until it is terminal"),
                &ctx.request_id,
            )
            .await;
        }
        let runtime_timeline =
            state.self_hosted_run_timeline(run_id, enforce_tenant_filter(&auth, None).as_deref());
        let response = AgentJobResultResponse {
            object: "agent_job_result",
            run_id: run_id.to_string(),
            terminal: true,
            turns_executed: timeline.run.as_ref().map_or(0, |run| run.turns_executed),
            output_recorded: timeline.run.as_ref().is_some_and(|run| run.output_recorded),
            output: agent_job_output(&timeline),
            // Decoded from the SAME already-tenant-scoped events, and verified
            // against the `run_id` the caller asked about rather than the one
            // the worker-reported payload claims.
            work_products: runtime_timeline
                .as_ref()
                .map(|runtime| {
                    WorkProductView::from_timeline_events(
                        runtime
                            .events
                            .iter()
                            .map(|event| (event.kind.as_str(), event.event_json.as_str())),
                        run_id,
                    )
                })
                .unwrap_or_default(),
            artifacts: runtime_timeline
                .as_ref()
                .map(|runtime| {
                    runtime
                        .events
                        .iter()
                        .filter(|event| event.kind == "artifact")
                        .map(|event| AgentJobArtifact {
                            id: event.id.clone(),
                            worker_id: event.worker_id.clone(),
                            occurred_at_unix: event.occurred_at_unix,
                            event_json: event.event_json.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            request_count: timeline.requests.len(),
            billing_event_count: timeline.billing_events.len(),
            completed_at_unix: timeline.run.as_ref().and_then(|run| run.completed_at_unix),
            status,
            request_id: ctx.request_id.clone(),
        };
        write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
    }

    async fn handle_agent_job_cancel(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &HeaderMap,
        run_id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, AGENT_JOB_WRITE_SCOPE, &ctx.request_id).await
        {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let Some(timeline) = scoped_agent_job_timeline(&state, &auth, run_id) else {
            return job_not_found(session, ctx, run_id).await;
        };
        let Some(run) = timeline.run.clone() else {
            // Evidence exists for the id but no canonical run row, so there is
            // nothing to terminalize (and no dispatch to address).
            return write_json_error(
                session,
                StatusCode::CONFLICT,
                "agent_job_not_cancellable",
                format!("agent job {run_id} has no cancellable run record"),
                &ctx.request_id,
            )
            .await;
        };
        let now = now_unix_seconds();
        // Everything the cancel DOES lives in `cancel_agent_job`, including the
        // already-terminal repair branch, so a test can drive the same sequence
        // the handler drives instead of re-assembling it by hand (#551 rework --
        // the repair branch was reachable only from here and therefore asserted
        // by nothing).
        let decision = match cancel_agent_job(&state, &run, ctx.request_id.as_str(), now) {
            Ok(decision) => decision,
            Err(message) => {
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "agent_job_cancel_unavailable",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        if !decision.cancelled {
            // Already terminal: the repair ran, but there is no new run state
            // and therefore no run event and no audit event to write.
            let response = AgentJobCancelResponse {
                object: "agent_job_cancel",
                run_id: run_id.to_string(),
                terminal: true,
                status: decision.status,
                cancelled: false,
                runtime_cancel_dispatched: decision.runtime_cancel_dispatched,
                cancelled_at_unix: decision.cancelled_at_unix,
                request_id: ctx.request_id.clone(),
            };
            return write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await;
        }
        let runtime_cancel_dispatched = decision.runtime_cancel_dispatched;
        state.record_agent_run_event(StoredAgentRunEvent {
            id: format!("agent-job-cancelled:{run_id}"),
            run_id: run_id.to_string(),
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            tenant: auth.tenant_context(),
            turn: 0,
            kind: "run_cancelled".to_string(),
            target: format!("agent_run:{run_id}"),
            outcome: "cancelled".to_string(),
            tool_call_id: None,
            message: Some(if runtime_cancel_dispatched {
                format!(
                    "agent job {run_id} cancelled; a worker held it, so cancel_run was \
                     dispatched to the runtime"
                )
            } else {
                format!(
                    "agent job {run_id} cancelled; no worker had leased it, so its start \
                     dispatch was withdrawn from the queue"
                )
            }),
            occurred_at_unix: Some(now),
            action_fingerprint: None,
            decision: None,
            decision_reason: None,
            output_disposition: None,
        });
        state.record_admin_audit_event(agent_job_audit_event(
            ctx,
            &auth,
            run_id,
            "agent_job.cancelled",
            "cancelled",
            format!("agent job {run_id} cancelled by caller"),
        ));

        let response = AgentJobCancelResponse {
            object: "agent_job_cancel",
            run_id: run_id.to_string(),
            status: decision.status,
            terminal: true,
            cancelled: true,
            runtime_cancel_dispatched,
            cancelled_at_unix: decision.cancelled_at_unix,
            request_id: ctx.request_id.clone(),
        };
        write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
    }
}

/// What one cancel did, as the handler needs to report it.
#[derive(Debug, PartialEq, Eq)]
struct AgentJobCancelDecision {
    /// The run's status AFTER the call.
    status: String,
    /// Whether THIS call terminalized the run (`false` = already terminal).
    cancelled: bool,
    /// See [`RUNTIME_CANCEL_DISPATCHED_DESCRIPTION`].
    runtime_cancel_dispatched: bool,
    cancelled_at_unix: Option<u64>,
}

/// Cancel `run`: settle it, then stop its work in the runtime. **In that
/// order, and the order is the guarantee (#551 rework).**
///
/// A cancel destroys evidence -- on the withdrawable arm it deletes the
/// `self_hosted_run_dispatches` row outright, which is the only thing a PEER
/// replica holding its own in-memory copy of that dispatch could ever have
/// been superseded by. What replaces it is the settled `agent_runs` row, the
/// one record every replica reads (`AppState::start_run_lease_is_settled`).
/// Writing the run row AFTER the deletion, as this path did until now, leaves
/// a window in which neither exists: on the durable backend `record_agent_run`
/// hands the row to a background writer that returns immediately and is
/// allowed to DROP it under back-pressure, so the window is not merely small,
/// it can be unbounded. A peer that polls inside it hands a worker the
/// cancelled job's `start_run` -- #474's defect, on the arm the withdrawal was
/// introduced to close.
///
/// So: [`AppState::record_agent_run_durably`] first, and a failed write aborts
/// the cancel having destroyed nothing (the caller sees 503 and may retry --
/// and a retry, once some other route settles the run, lands in the repair
/// branch below). [`cancel_agent_job_in_runtime`] then REFUSES a run that is
/// not already terminal, so this ordering cannot be quietly inverted by a
/// later edit: inverting it turns every cancel into a 503.
fn cancel_agent_job(
    state: &AppState,
    run: &StoredAgentRun,
    request_id: &str,
    now_unix: u64,
) -> Result<AgentJobCancelDecision, String> {
    if agent_job_status_is_terminal(&run.status) {
        // Nothing to cancel -- but this is also the REPAIR path (#502). The run
        // settled through some other route (worker telemetry, most often) and
        // this node may still be holding its dispatch rows: on the replica that
        // served the submit but not the completion, those rows are exactly what
        // an admission count would otherwise keep reading. Draining them here
        // makes a retried cancel a real remedy instead of a no-op that returns
        // `cancelled: false` and leaves the rows where they were.
        state.reclaim_settled_run_dispatches(&run.id);
        return Ok(AgentJobCancelDecision {
            status: run.status.clone(),
            cancelled: false,
            runtime_cancel_dispatched: false,
            cancelled_at_unix: run.completed_at_unix,
        });
    }

    // Terminalize the run itself: the cancel is not "requested", it is the
    // run's end state, so a caller polling status/result sees a terminal job
    // even if the worker never comes back for its lease -- and every replica
    // sees it before the work it would otherwise start is unprotected.
    let mut settled = run.clone();
    settled.status = "cancelled".to_string();
    settled.completed_at_unix = Some(now_unix);
    if !state.record_agent_run_durably(settled.clone()) {
        return Err(format!(
            "agent job {} could not be settled durably, so its work was left alone",
            run.id
        ));
    }
    let runtime_cancel_dispatched =
        cancel_agent_job_in_runtime(state, &settled, request_id, now_unix)?;
    Ok(AgentJobCancelDecision {
        status: settled.status,
        cancelled: true,
        runtime_cancel_dispatched,
        cancelled_at_unix: settled.completed_at_unix,
    })
}

/// Stop `run` in the runtime, and reclaim what it leaves behind.
///
/// **The contract, stated once (#551).** A cancel guarantees that the work
/// STOPS, not that a `cancel_run` dispatch exists. Those were the same thing
/// only while every job had a holder to deliver a `cancel_run` to. They are
/// not the same thing for a job no worker ever leased, and there the message
/// is strictly the weaker remedy: it is addressed at nobody, it leaves the
/// start dispatch in the queue for a worker to pick up and START, and it costs
/// two permanent rows. So the guarantee is discharged by whichever of the two
/// shapes below actually makes the work unreachable, and
/// `runtime_cancel_dispatched` reports WHICH -- it is not a success flag.
///
/// Two shapes, chosen by whether WITHDRAWING the start dispatch on this node
/// is by itself enough to stop the work (#502 rework):
///
/// * WITHDRAWABLE -- this process's own lease queue holds the start dispatch
///   and no worker has ever been assigned it, so nothing is executing the job
///   and this node owns the only runnable copy. The dispatch is removed from
///   the lease queue and then deleted from `self_hosted_run_dispatches`. The
///   test ("is it unleased?") and the removal happen under ONE acquisition of
///   the queue lock (#551) -- the poll seam takes the same lock, so splitting
///   them let a worker lease the dispatch in the gap and be left holding a row
///   that had just been deleted, with no `cancel_run` minted because the
///   cancel had already decided none was needed. A submit/cancel loop leaves
///   no permanent row behind, where before #502 it left two per iteration in a
///   table nothing ever deleted.
/// * NOT WITHDRAWABLE -- either a worker holds the lease, or the dispatch
///   resolved only out of the durable table because a PEER replica is the one
///   holding it in memory. Both get a `cancel_run` (#414) enqueued, addressing
///   the SAME worker/session/adapter the start dispatch targeted. The start
///   dispatch is left in place so the holder's ack still resolves, but it is
///   now SUPERSEDED: the lease queue refuses to hand out a `start_run` whose
///   run carries a `cancel_run`, so the expiry of that lease can no longer let
///   a second worker pick up and START work the caller cancelled. Both rows are
///   reclaimed when the worker acknowledges the cancel.
///
/// The lease queue is PER PROCESS, which is why the lease owner alone cannot
/// pick the shape. Deleting the durable row from a replica that never held the
/// dispatch does not touch the peer's in-memory entry: that entry stays
/// unacked, and with no `cancel_run` anywhere the peer's `poll_run` has an
/// empty superseded set, so a worker polling the peer leases and STARTS the
/// cancelled job. That is #474's original defect verbatim -- "the cancel found
/// no start dispatch, enqueued no `cancel_run`, and still answered 200 while
/// the worker kept running" -- so a cancel that cannot withdraw locally always
/// leaves durable `cancel_run` evidence instead.
///
/// Neither shape is node-local enough to stand alone, which is why the poll
/// seam carries the backstop (#551). Withdrawal empties THIS node's queue and
/// the durable table, but a peer that rebuilt its queue after the submit still
/// holds an in-memory copy nothing here can reach; supersession is computed
/// from THIS node's queue, so a peer that has not rebuilt since the
/// `cancel_run` was written has an empty superseded set. In both leftovers the
/// peer would hand a cancelled job's `start_run` to a worker. The predicate
/// that closes them is not in this function at all: it is
/// [`AppState::poll_self_hosted_worker_run`], which refuses to hand out a
/// `start_run` whose `agent_runs` row has already SETTLED, read durably --
/// the one record every replica shares, and the one [`cancel_agent_job`] has
/// already written, and flushed, BEFORE calling this.
///
/// That ordering is a precondition, not a convention, so it is checked: `run`
/// must already be terminal or this returns `Err` and touches nothing. A
/// cancel that withdrew first would delete the peer's only supersedable
/// evidence while the row meant to replace it was still queued in a background
/// evidence writer that is permitted to drop it (#551 rework).
///
/// Residue, stated rather than left implied: a worker that is ALREADY
/// executing the run is stopped only by collecting its `cancel_run`, so the
/// cancel is as prompt as that worker's next poll and no prompter. Nothing
/// here reaches into a process that is mid-run.
///
/// Returns which shape ran, NOT whether the cancel succeeded -- the cancel
/// succeeded in both, and the caller terminalizes the run either way. `true`
/// is "a `cancel_run` was enqueued for a holder"; `false` is "there was
/// nothing to hold it, and the queued work was withdrawn".
fn cancel_agent_job_in_runtime(
    state: &AppState,
    run: &StoredAgentRun,
    request_id: &str,
    now_unix: u64,
) -> Result<bool, String> {
    if !agent_job_status_is_terminal(&run.status) {
        // The ordering guard. Failing here costs the caller a 503 on a cancel
        // that has changed nothing; the alternative it prevents is a peer
        // starting cancelled work with no evidence left anywhere to stop it.
        return Err(format!(
            "agent job {} must be settled before its queued work is withdrawn",
            run.id
        ));
    }
    let Some(start) = state.self_hosted_dispatch_for_run(&run.id, SelfHostedRunAction::StartRun)
    else {
        return Ok(false);
    };
    let start_dispatch_id = start.dispatch_id.clone();
    // Node-local AND atomic on purpose (#551). Node-local because
    // `self_hosted_dispatch_for_run` above may have resolved `start` out of the
    // durable table, and a durable row is evidence that SOME node holds the
    // dispatch, not that this one does. Atomic because the poll seam shares
    // this lock: asking "is it unleased?" and then withdrawing under a second
    // acquisition let a worker lease it in between and be left holding a row
    // that had just been deleted, with no `cancel_run` ever minted for it --
    // the exact "a cancelled job's runtime is never told" defect, narrowed to a
    // race. A lost race reports `false` and falls through to the `cancel_run`
    // below, which is the right remedy for the holder that won it.
    if state.withdraw_unleased_self_hosted_dispatch(&start_dispatch_id) {
        return Ok(false);
    }
    let cancel = SelfHostedRunDispatch {
        dispatch_id: agent_job_cancel_dispatch_id(&run.id),
        action: SelfHostedRunAction::CancelRun,
        queued_at_unix: now_unix.max(1),
        request_id: Some(request_id.to_string()),
        trace_id: run.trace_id.clone(),
        agent_run_id: Some(run.id.clone()),
        ..start
    };
    state
        .enqueue_scheduled_self_hosted_dispatch(cancel)
        .map(|()| true)
        .map_err(|error| format!("agent job cancel could not reach the runtime: {error}"))
}

/// Authenticate an OBSERVE call (status / events / result).
///
/// `agent.runs.read` is the precise scope, but `agent.runs.create` is strictly
/// broader in practice: a key that may start agent work billed to this tenant
/// is already trusted with that work's evidence, and an async job whose caller
/// cannot observe it is a write-only protocol. So a submitter may always follow
/// its own job even when its key predates the read scope, while a read-only key
/// still needs `agent.runs.read` and never gains the ability to submit or
/// cancel (#474 rework). The read scope is tried FIRST so the denial message a
/// key with neither scope sees names the narrower privilege it should be given.
async fn authenticate_agent_job_read(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<AuthContext, crate::auth::AuthError> {
    match authenticate(state, headers, AGENT_JOB_READ_SCOPE, request_id).await {
        Ok(auth) => Ok(auth),
        Err(error) if error.code == "scope_denied" => {
            match authenticate(state, headers, AGENT_JOB_WRITE_SCOPE, request_id).await {
                Ok(auth) => Ok(auth),
                // Report the READ scope's denial: it is the least privilege that
                // would have satisfied the call.
                Err(_) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

/// Resolve a job's timeline with tenant isolation applied at the query layer.
///
/// The `AgentRunFilter.organization_id` is pinned by `enforce_tenant_filter`
/// BEFORE the storage read, so a tenant-scoped caller's cross-tenant `run_id`
/// resolves to `None` (reported as 404) rather than being filtered out of a
/// response that already leaked its existence. A platform-operator key
/// (`organization_id: None`) is unpinned and sees every tenant, matching every
/// other admin read.
fn scoped_agent_job_timeline(
    state: &AppState,
    auth: &AuthContext,
    run_id: &str,
) -> Option<AgentRunTimeline> {
    let filter = AgentRunFilter {
        organization_id: enforce_tenant_filter(auth, None),
        ..AgentRunFilter::default()
    };
    state.agent_run_timeline(run_id, filter)
}

/// The job's status: the canonical `agent_runs.status` when the run row exists,
/// otherwise the timeline summary's derived status (evidence-only runs).
fn agent_job_status(timeline: &AgentRunTimeline) -> String {
    timeline
        .run
        .as_ref()
        .map(|run| run.status.clone())
        .unwrap_or_else(|| timeline.summary.status.to_string())
}

/// The terminal output the runtime recorded on the run timeline, if any. Read
/// from the newest completion-shaped event rather than a separate result store.
fn agent_job_output(timeline: &AgentRunTimeline) -> Option<String> {
    timeline
        .agent_events
        .iter()
        .filter(|event| {
            matches!(
                event.kind.as_str(),
                "run_completed" | "job_result" | "run_output"
            )
        })
        .max_by_key(|event| (event.occurred_at_unix.unwrap_or_default(), event.id.clone()))
        .and_then(|event| event.message.clone())
}

/// The resolved idempotency key plus where it came from, so the response can
/// tell the caller exactly which key its job is keyed on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedIdempotencyKey {
    key: String,
    source: &'static str,
}

/// Resolve the explicit idempotency key: `Idempotency-Key` header wins, then
/// the body's `idempotency_key`. When neither is supplied the request id is
/// used, which makes every un-keyed submit its own job (never a silent merge)
/// while still yielding a deterministic id; the response echoes the effective
/// key and `idempotency_key_source: "request_id"` so the caller can see that a
/// retry of that request will NOT dedup.
fn resolve_idempotency_key(
    headers: &HeaderMap,
    body_key: Option<&str>,
    request_id: &str,
) -> Result<ResolvedIdempotencyKey, String> {
    let header_key = match headers.get(IDEMPOTENCY_KEY_HEADER) {
        Some(value) => Some(value.to_str().map_err(|_| {
            format!("{IDEMPOTENCY_KEY_HEADER} must be valid visible ASCII/UTF-8 header text")
        })?),
        None => None,
    };
    let (raw, source) = match header_key
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(|key| (key, "header"))
        .or_else(|| {
            body_key
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(|key| (key, "body"))
        }) {
        Some(resolved) => resolved,
        None => {
            return Ok(ResolvedIdempotencyKey {
                key: format!("request:{request_id}"),
                source: "request_id",
            })
        }
    };
    if raw.chars().count() > IDEMPOTENCY_KEY_MAX_LEN {
        return Err(format!(
            "idempotency key must be at most {IDEMPOTENCY_KEY_MAX_LEN} characters"
        ));
    }
    if raw.chars().any(|ch| ch.is_control()) {
        return Err("idempotency key must not contain control characters".to_string());
    }
    Ok(ResolvedIdempotencyKey {
        key: raw.to_string(),
        source,
    })
}

/// Cursor for the incremental event feed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentJobEventCursor {
    after_event_id: Option<String>,
    limit: usize,
}

impl AgentJobEventCursor {
    fn from_query(query: Option<&str>) -> Result<Self, String> {
        let mut cursor = Self {
            after_event_id: None,
            limit: EVENT_PAGE_DEFAULT_LIMIT,
        };
        let Some(query) = query else {
            return Ok(cursor);
        };
        for part in query.split('&') {
            let Some((name, value)) = part.split_once('=') else {
                continue;
            };
            match name {
                "after_event_id" | "after" => {
                    let value = value.trim();
                    if !value.is_empty() {
                        cursor.after_event_id = Some(value.to_string());
                    }
                }
                "limit" => {
                    let limit = value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| "limit must be an unsigned integer".to_string())?;
                    if limit == 0 {
                        return Err("limit must be greater than zero".to_string());
                    }
                    cursor.limit = limit.min(EVENT_PAGE_MAX_LIMIT);
                }
                _ => {}
            }
        }
        Ok(cursor)
    }
}

struct AgentJobEventSlice {
    data: Vec<StoredAgentRunEvent>,
    next_after_event_id: Option<String>,
    has_more: bool,
    cursor_reset: bool,
}

/// The total order the feed is paged in: `(occurred_at_unix, id)`. Storage
/// order is not a contract, so ordering explicitly is what makes a cursor a
/// stable resume point across polls, backends and retries.
fn agent_job_event_key(event: &StoredAgentRunEvent) -> (u64, String) {
    (event.occurred_at_unix.unwrap_or_default(), event.id.clone())
}

/// Render a resume cursor as `"<occurred_at_unix>:<event id>"` (#474 rework).
///
/// The cursor used to be the bare event id, which made resumption depend on
/// that event STILL EXISTING: once retention pruned it, the poll loop's cursor
/// was permanently unresolvable. Emitting the position key instead makes the
/// cursor self-describing -- "everything ordered at or before here is
/// delivered" -- so the loop keeps working after the event it names is gone.
fn agent_job_event_cursor_token(event: &StoredAgentRunEvent) -> String {
    format!(
        "{}:{}",
        event.occurred_at_unix.unwrap_or_default(),
        event.id
    )
}

/// Parse a cursor into its position key.
///
/// Accepts both the composite token this endpoint emits and a bare event id
/// copied out of `data[].id` (resolved by lookup, so a caller can page from any
/// event it has actually seen). A leading numeric segment is what distinguishes
/// the two; FerroGate's own event ids are never all-digits before their first
/// `:` (`agent-job-submitted:<run>`, `agent-run-worker-report:<id>`).
fn resolve_agent_job_cursor(after: &str, events: &[StoredAgentRunEvent]) -> Option<(u64, String)> {
    if let Some((occurred_at, id)) = after.split_once(':') {
        if let Ok(occurred_at) = occurred_at.parse::<u64>() {
            return Some((occurred_at, id.to_string()));
        }
    }
    events
        .iter()
        .find(|event| event.id == after)
        .map(agent_job_event_key)
}

/// Order the run's timeline events deterministically and take the page after
/// the cursor.
///
/// An unresolvable cursor is NOT an error: a poll loop whose cursor points at a
/// pruned event restarts from the oldest retained event with `cursor_reset`
/// set, so it self-heals (at the cost of re-seeing some events) instead of
/// dying on a permanent 400.
fn page_agent_job_events(
    mut events: Vec<StoredAgentRunEvent>,
    cursor: &AgentJobEventCursor,
) -> AgentJobEventSlice {
    events.sort_by_key(agent_job_event_key);
    let resolved = cursor
        .after_event_id
        .as_deref()
        .map(|after| resolve_agent_job_cursor(after, &events));
    let cursor_reset = matches!(resolved, Some(None));
    let start = match resolved.flatten() {
        None => 0,
        Some(key) => events
            .iter()
            .position(|event| agent_job_event_key(event) > key)
            .unwrap_or(events.len()),
    };
    let remaining = events.split_off(start);
    let has_more = remaining.len() > cursor.limit;
    let data: Vec<StoredAgentRunEvent> = remaining.into_iter().take(cursor.limit).collect();
    let next_after_event_id = data
        .last()
        .map(agent_job_event_cursor_token)
        .or_else(|| cursor.after_event_id.clone().filter(|_| !cursor_reset));
    AgentJobEventSlice {
        data,
        next_after_event_id,
        has_more,
        cursor_reset,
    }
}

/// A run id is addressable when it is a single non-empty path segment.
fn is_addressable_run_id(run_id: &str) -> bool {
    !run_id.is_empty() && !run_id.contains('/')
}

fn truncate_evidence(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.chars().count() <= SUBMITTED_INPUT_EVIDENCE_MAX_CHARS {
        return trimmed.to_string();
    }
    let mut truncated: String = trimmed
        .chars()
        .take(SUBMITTED_INPUT_EVIDENCE_MAX_CHARS)
        .collect();
    truncated.push('…');
    truncated
}

fn agent_job_audit_event(
    ctx: &ProxyContext,
    auth: &AuthContext,
    run_id: &str,
    action: &str,
    outcome: &str,
    message: String,
) -> AdminAuditEventDraft {
    AdminAuditEventDraft {
        action_identity: Default::default(),
        request_id: ctx.request_id.clone(),
        trace_id: ctx.trace_id.clone(),
        agent_run_id: Some(run_id.to_string()),
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        actor_api_key_id: auth.api_key_id.clone(),
        tenant: auth.tenant_context(),
        action: action.to_string(),
        target: format!("agent_job:{run_id}"),
        outcome: outcome.to_string(),
        message,
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn job_not_found(
    session: &mut Session,
    ctx: &ProxyContext,
    run_id: &str,
) -> PingoraResult<()> {
    // Deliberately 404 (not 403) for a cross-tenant id: the tenant filter is
    // applied at the query layer, so this path cannot distinguish "does not
    // exist" from "belongs to someone else", and must not.
    write_json_error(
        session,
        StatusCode::NOT_FOUND,
        "agent_job_not_found",
        format!("agent job {run_id} was not found"),
        &ctx.request_id,
    )
    .await
}

async fn not_found(session: &mut Session, ctx: &ProxyContext) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::NOT_FOUND,
        "agent_job_endpoint_not_found",
        "agent job endpoint not found",
        &ctx.request_id,
    )
    .await
}

async fn method_not_allowed(
    session: &mut Session,
    ctx: &ProxyContext,
    message: &'static str,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        message,
        &ctx.request_id,
    )
    .await
}

async fn write_auth_error(
    session: &mut Session,
    ctx: &ProxyContext,
    error: crate::auth::AuthError,
) -> PingoraResult<()> {
    write_json_error(
        session,
        error.status,
        error.code,
        error.message,
        &ctx.request_id,
    )
    .await
}

#[cfg(test)]
#[path = "agent_jobs_test.rs"]
mod agent_jobs_test;
