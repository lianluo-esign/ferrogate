// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Real CloudflareControlSurface impl (issue #413): maps the #412 scheduler
//   lifecycle verbs onto the deployed agent-gateway Worker's authenticated control routes.

//! The live [`CloudflareControlSurface`] backed by the deployed agent-gateway
//! Worker (issue #413).
//!
//! The #412 seam ([`CloudflareControlSurface`]) is intentionally
//! **synchronous** to match the managed-worker scheduler's
//! `AgentWorkerControlClient`. This module supplies a real implementation,
//! [`WorkerGatewayControlSurface`], that maps each lifecycle verb onto one HTTP
//! call to the deployed Worker's control routes, presenting the DIY bearer
//! token:
//! The mapping is refined (issue #414) to match the **actual Cloudflare agent
//! primitives**, which are narrower than a typical lifecycle API:
//!
//! | verb ([`CloudflareControlSurface`]) | CF primitive | Worker route |
//! |---|---|---|
//! | `start_run`   | LAZY create; props resolved into state at start | `POST /control/start` (`getAgentByName` + `agent.start(props)`) |
//! | `exec_run`    | agent RPC method | `POST /control/invoke` |
//! | `stop_run`    | **hibernation** (automatic; no primitive) | *(none — local no-op; see below)* |
//! | `cancel_run`  | **cooperative** `AbortSignal` + durable latch (NOT fibers — see below) | `POST /control/cancel` |
//! | `cleanup_run` | `this.destroy()` | `POST /control/destroy` |
//! | `run_status`  | **custom** `onRequest`/RPC (no `getStatus`) | `GET  /control/status?runRef=…` |
//!
//! ## Why `stop_run` sends no request
//!
//! Cloudflare exposes **no stop/pause/resume/restart/getStatus** primitive.
//! Hibernation is automatic (~70–140s idle → zero compute, state retained; the
//! instance wakes on the next HTTP/WS/alarm). So a terminal "stop" is nothing to
//! call — `stop_run` returns [`CloudflareRunStatus::Stopped`] **without any HTTP
//! request** and the agent hibernates on its own, staying re-addressable by name.
//! Active cancellation of in-flight work is a *different* operation
//! (`cancel_run`). `run_status` is a **custom** status method we expose, not a
//! built-in `getStatus`. A terminal stop vs. an operator cancel is decided by the
//! scheduler's typed `ManagedWorkerStopKind`, never by parsing the stop reason.
//!
//! ## What `cancel_run` actually is (and is not)
//!
//! Cloudflare's docs name **fibers** (`startFiber().cancel` / `abortSubAgent`)
//! as the in-run cancellation primitive, but the pinned Agents SDK
//! (`agents@0.0.109`) ships **no fiber API at all**. The gateway Worker
//! therefore implements cancel with what the runtime does give it: it aborts an
//! `AbortSignal` the workload observes, and sets a **durable** latch that makes
//! every later `invoke` on that run refuse. A workload that observes the signal
//! stops; one that ignores it, or that executes outside the agent's Durable
//! Object, does not — so a caller that needs "stopped" to be a guarantee must
//! verify with `run_status` and escalate to `cleanup_run`
//! ([`crate::KillMode::Cancel`] does exactly that for the #428 budget kill).
//!
//! **The status `cancel_run` returns is the one that makes that verification
//! mean something.** The Worker writes `stopped` only once a workload has
//! actually unwound (or when there was nothing in flight to wait on); a cancel
//! that merely *signalled* a running workload leaves the run `running`. Before
//! that, `cancel` wrote `stopped` unconditionally and the verify-then-escalate
//! loop was vacuous — [`crate::kill_is_settled`] treats `Stopped` as terminal, so
//! it always observed the status the cancel itself had just written and never
//! escalated. See `workers/agent-gateway/test/lifecycle.test.ts`, "a cancel the
//! workload IGNORES is NOT reported as stopped".
//!
//! ## Refusals are errors, not statuses
//!
//! Addressing an agent by name ALWAYS yields a Durable Object stub, so a verb
//! against an unknown `run_ref` used to return 200 and a fabricated status. The
//! Worker now refuses with 404 `not_found` (and 409 `run_conflict` for a
//! contradictory re-start), which this surface maps onto
//! [`CloudflareControlSurfaceError::RunNotFound`] / `StartFailed` so the caller
//! never records lifecycle evidence for a run that does not exist.
//!
//! The same rule now covers `invoke`: a run whose cancel latch is set refuses
//! with 409 `run_cancelled` and this surface maps it onto
//! [`CloudflareControlSurfaceError::RunCancelled`]. It used to answer 200 with
//! an exec success envelope, so `exec_or_attach` recorded `outcome = "executed"`
//! for an invocation that never ran.
//!
//! HTTP goes through a small synchronous [`GatewayControlTransport`] seam so the
//! verb→route→status mapping is unit-tested with a scripted mock and **no
//! network**. The production transport ([`BlockingHttpControlTransport`])
//! bridges the async #405 [`HttpTransport`] onto this sync seam via a dedicated
//! runtime's `block_on` — the same block-on bridge the CLI uses elsewhere.

use std::sync::Arc;

use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse, HttpTransport};
use serde::Deserialize;
use serde_json::json;

use crate::cloudflare_worker::{
    CloudflareControlSurface, CloudflareControlSurfaceError, CloudflareRunExecOutcome,
    CloudflareRunExecRequest, CloudflareRunHandle, CloudflareRunStartRequest, CloudflareRunStatus,
};

/// A synchronous HTTP seam for talking to the deployed Worker's control routes.
///
/// Kept separate from the async #405 [`HttpTransport`] so the
/// [`CloudflareControlSurface`] (which is synchronous) can be implemented and
/// unit-tested without an async runtime. The production impl
/// ([`BlockingHttpControlTransport`]) wraps an async [`HttpTransport`].
pub trait GatewayControlTransport: Send + Sync {
    /// Execute a request against the Worker. Returns `Ok` for any HTTP status;
    /// only connect/transport failures are `Err`.
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareControlSurfaceError>;
}

/// The live [`CloudflareControlSurface`] backed by the deployed agent-gateway
/// Worker.
pub struct WorkerGatewayControlSurface<T: GatewayControlTransport> {
    /// Base URL of the deployed Worker, e.g.
    /// `https://ferrogate-agent-gateway.<subdomain>.workers.dev`.
    base_url: String,
    /// The DIY bearer token (matches the Worker's `GATEWAY_CONTROL_TOKEN`).
    control_token: String,
    transport: T,
}

impl<T: GatewayControlTransport> WorkerGatewayControlSurface<T> {
    /// Build a control surface for a Worker reachable at `base_url`, presenting
    /// `control_token` as the bearer credential.
    pub fn new(
        base_url: impl Into<String>,
        control_token: impl Into<String>,
        transport: T,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            control_token: control_token.into(),
            transport,
        }
    }

    /// Borrow the underlying transport (tests inspect the mock through this).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn route(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        let bytes = serde_json::to_vec(&body).map_err(|e| {
            CloudflareControlSurfaceError::Transport(format!("failed to encode control body: {e}"))
        })?;
        self.transport.send(HttpRequest {
            method: HttpMethod::Post,
            url: self.route(path),
            bearer_token: self.control_token.clone(),
            body: Some(bytes),
            content_type: None,
        })
    }

    fn get(&self, path: &str) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        self.transport.send(HttpRequest {
            method: HttpMethod::Get,
            url: self.route(path),
            bearer_token: self.control_token.clone(),
            body: None,
            content_type: None,
        })
    }
}

/// Decode a control-route JSON body into `T`, treating a non-2xx status as
/// `map_err(status, body)`.
///
/// HTTP 404 is intercepted first and always becomes
/// [`CloudflareControlSurfaceError::RunNotFound`], whatever the verb: "there is
/// no such run" must never be reported as that verb's success value (a
/// `cleanup_run` against a typo'd `run_ref` returning `CleanedUp` is how
/// FerroGate came to record cleanup evidence for runs that never existed).
fn decode_ok<T: for<'de> Deserialize<'de>>(
    response: HttpResponse,
    map_err: impl FnOnce(u16, String) -> CloudflareControlSurfaceError,
) -> Result<T, CloudflareControlSurfaceError> {
    if response.status == 404 {
        let body = String::from_utf8_lossy(&response.body).into_owned();
        return Err(CloudflareControlSurfaceError::RunNotFound(body));
    }
    if !(200..300).contains(&response.status) {
        let body = String::from_utf8_lossy(&response.body).into_owned();
        return Err(map_err(response.status, body));
    }
    serde_json::from_slice(&response.body).map_err(|e| {
        CloudflareControlSurfaceError::Transport(format!("failed to decode control response: {e}"))
    })
}

/// Read the `error` code out of a gateway-Worker refusal envelope
/// (`{"error":"…","runRef":"…","detail":"…"}`), or `None` when the body is not
/// one.
///
/// Refusal codes are matched on this field and never on the human-readable
/// `detail`: substring-matching prose is how a wording change silently becomes a
/// behaviour change.
fn refusal_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(value.get("error")?.as_str()?.to_string())
}

/// Percent-encode `value` for use as a URL query-string value.
///
/// Hand-rolled rather than adding a dependency for one call site: the run-ref
/// alphabet is `fg.{tenant}.{session}.{run}` today, but an unescaped `&`, `#` or
/// `?` in a name would silently truncate or corrupt the `runRef` the Worker
/// reads, and status would then answer about a *different* instance.
fn encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(*byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

/// Parse the Worker's `status` string into a [`CloudflareRunStatus`].
fn parse_status(raw: &str) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
    match raw {
        "queued" => Ok(CloudflareRunStatus::Queued),
        "running" => Ok(CloudflareRunStatus::Running),
        "completed" => Ok(CloudflareRunStatus::Completed),
        "failed" => Ok(CloudflareRunStatus::Failed),
        "stopped" => Ok(CloudflareRunStatus::Stopped),
        "cleaned_up" => Ok(CloudflareRunStatus::CleanedUp),
        other => Err(CloudflareControlSurfaceError::Transport(format!(
            "unknown run status from gateway Worker: {other}"
        ))),
    }
}

#[derive(Debug, Deserialize)]
struct StartResponse {
    #[serde(rename = "runRef")]
    run_ref: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct InvokeResponse {
    #[serde(rename = "runRef")]
    run_ref: String,
    status: String,
    #[serde(rename = "exitCode")]
    exit_code: Option<i32>,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    status: String,
}

impl<T: GatewayControlTransport> CloudflareControlSurface for WorkerGatewayControlSurface<T> {
    fn start_run(
        &mut self,
        request: CloudflareRunStartRequest,
    ) -> Result<CloudflareRunHandle, CloudflareControlSurfaceError> {
        // `props` are the transient per-run init (model/tools/prompt + placement)
        // the Worker's `start()` parses into the run's persistent state —
        // `onStart` is a zero-argument wake hook in the pinned Agents SDK, so it
        // is NOT the delivery path. Serialize them into the start body so the
        // agent can read its runtime-selectable model in code.
        let props = serde_json::to_value(&request.props).map_err(|e| {
            CloudflareControlSurfaceError::Transport(format!("failed to encode run props: {e}"))
        })?;
        let response = self.post(
            "control/start",
            json!({
                "sessionId": request.session_id,
                "runId": request.run_id,
                "workerTemplateId": request.worker_template_id,
                "frameworkAdapter": request.framework_adapter,
                "capabilityEnvelopeId": request.capability_envelope_id,
                "props": props,
            }),
        )?;
        let decoded: StartResponse = decode_ok(response, |status, body| {
            CloudflareControlSurfaceError::StartFailed(format!("HTTP {status}: {body}"))
        })?;
        Ok(CloudflareRunHandle {
            run_ref: decoded.run_ref,
            status: parse_status(&decoded.status)?,
        })
    }

    fn exec_run(
        &mut self,
        request: CloudflareRunExecRequest,
    ) -> Result<CloudflareRunExecOutcome, CloudflareControlSurfaceError> {
        let response = self.post(
            "control/invoke",
            json!({
                "runRef": request.run_ref,
                "workloadRef": request.workload_ref,
                "args": request.args,
            }),
        )?;
        let decoded: InvokeResponse = decode_ok(response, |status, body| {
            // A cancelled run REFUSES the invoke (409 `run_cancelled`); it does
            // not fail it. Kept as its own error so a caller can tell "this run
            // is closed to further work" from "the work was attempted and blew
            // up" without reading prose — and so `exec_or_attach` records no
            // `executed` evidence for work that never ran.
            if status == 409 && refusal_code(&body).as_deref() == Some("run_cancelled") {
                return CloudflareControlSurfaceError::RunCancelled(body);
            }
            CloudflareControlSurfaceError::ExecFailed(format!("HTTP {status}: {body}"))
        })?;
        Ok(CloudflareRunExecOutcome {
            run_ref: decoded.run_ref,
            status: parse_status(&decoded.status)?,
            exit_code: decoded.exit_code,
            message: decoded.message,
        })
    }

    fn stop_run(
        &mut self,
        _run_ref: &str,
        _reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        // Hibernation is automatic on Cloudflare — there is no stop/pause
        // primitive and therefore no control route to call. A terminal "stop" is
        // a no-op: the idle agent goes to zero compute on its own and stays
        // re-addressable by name. (Active cancellation is `cancel_run`.)
        Ok(CloudflareRunStatus::Stopped)
    }

    fn cancel_run(
        &mut self,
        run_ref: &str,
        reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        // Cooperative cancel: the Worker aborts the signal the workload observes
        // and sets the durable latch that refuses further work. NOT a fiber
        // cancel — `agents@0.0.109` ships no fiber API (see the module doc), and
        // it cannot stop a workload that ignores the signal.
        //
        // The returned status is therefore NOT a claim that the run stopped: it
        // is `stopped` only when a workload actually unwound or there was none
        // in flight, and stays `running` while a signalled workload is still
        // going. `KillMode::Cancel` depends on that distinction.
        let response = self.post(
            "control/cancel",
            json!({ "runRef": run_ref, "reason": reason }),
        )?;
        let decoded: StatusResponse = decode_ok(response, |status, body| {
            CloudflareControlSurfaceError::StopFailed(format!("HTTP {status}: {body}"))
        })?;
        parse_status(&decoded.status)
    }

    fn cleanup_run(
        &mut self,
        run_ref: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        let response = self.post("control/destroy", json!({ "runRef": run_ref }))?;
        let decoded: StatusResponse = decode_ok(response, |status, body| {
            CloudflareControlSurfaceError::CleanupFailed(format!("HTTP {status}: {body}"))
        })?;
        parse_status(&decoded.status)
    }

    fn run_status(
        &mut self,
        run_ref: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        let response = self.get(&format!(
            "control/status?runRef={}",
            encode_query_value(run_ref)
        ))?;
        let decoded: StatusResponse = decode_ok(response, |status, body| {
            CloudflareControlSurfaceError::Transport(format!("status HTTP {status}: {body}"))
        })?;
        parse_status(&decoded.status)
    }
}

/// Production [`GatewayControlTransport`]: bridges the synchronous seam onto the
/// async #405 [`HttpTransport`] via a dedicated multi-thread runtime's
/// `block_on`.
///
/// This is the block-on bridge the module doc references. It is **not exercised
/// by the offline unit tests against a live Worker** — those mock the sync seam
/// directly — but the bridge logic itself is covered with a mock async
/// transport. A live control round-trip against a deployed Worker is the test
/// agent's to prove.
pub struct BlockingHttpControlTransport {
    inner: Arc<dyn HttpTransport>,
    runtime: tokio::runtime::Runtime,
}

impl BlockingHttpControlTransport {
    /// Wrap an async transport, creating a dedicated current-thread runtime for
    /// the block-on bridge.
    pub fn new(inner: Arc<dyn HttpTransport>) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self { inner, runtime })
    }
}

impl GatewayControlTransport for BlockingHttpControlTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        self.runtime
            .block_on(self.inner.execute(request))
            .map_err(|e| CloudflareControlSurfaceError::Transport(e.to_string()))
    }
}

#[cfg(test)]
#[path = "cloudflare_gateway_control_test.rs"]
mod tests;
