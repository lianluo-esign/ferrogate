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
//!
//! | verb ([`CloudflareControlSurface`]) | Worker route |
//! |---|---|
//! | `start_run`   | `POST /control/start` |
//! | `exec_run`    | `POST /control/invoke` |
//! | `stop_run`    | `POST /control/cancel` |
//! | `cleanup_run` | `POST /control/destroy` |
//! | `run_status`  | `GET  /control/status?runRef=…` |
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
        })
    }

    fn get(&self, path: &str) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        self.transport.send(HttpRequest {
            method: HttpMethod::Get,
            url: self.route(path),
            bearer_token: self.control_token.clone(),
            body: None,
        })
    }
}

/// Decode a control-route JSON body into `T`, treating a non-2xx status as
/// `map_err(status, body)`.
fn decode_ok<T: for<'de> Deserialize<'de>>(
    response: HttpResponse,
    map_err: impl FnOnce(u16, String) -> CloudflareControlSurfaceError,
) -> Result<T, CloudflareControlSurfaceError> {
    if !(200..300).contains(&response.status) {
        let body = String::from_utf8_lossy(&response.body).into_owned();
        return Err(map_err(response.status, body));
    }
    serde_json::from_slice(&response.body).map_err(|e| {
        CloudflareControlSurfaceError::Transport(format!("failed to decode control response: {e}"))
    })
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
        let response = self.post(
            "control/start",
            json!({
                "sessionId": request.session_id,
                "runId": request.run_id,
                "workerTemplateId": request.worker_template_id,
                "frameworkAdapter": request.framework_adapter,
                "capabilityEnvelopeId": request.capability_envelope_id,
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
        run_ref: &str,
        reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
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
        let response = self.get(&format!("control/status?runRef={run_ref}"))?;
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
