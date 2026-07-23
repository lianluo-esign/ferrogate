// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: WorkerGatewayControlSurface mapping tests (issue #413) — assert each
//   CloudflareControlSurface verb hits the right Worker route with the bearer token and
//   maps the JSON response, using a scripted sync transport. NO network.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ferrogate_cloudflare::{CloudflareError, HttpMethod, HttpRequest, HttpResponse, HttpTransport};

use super::{BlockingHttpControlTransport, GatewayControlTransport, WorkerGatewayControlSurface};
use crate::cloudflare_worker::{
    CloudflareControlSurface, CloudflareControlSurfaceError, CloudflareRunExecRequest,
    CloudflareRunStartRequest, CloudflareRunStatus,
};

/// A synchronous scripted transport: records requests, replays responses.
struct MockControlTransport {
    responses: Mutex<VecDeque<HttpResponse>>,
    captured: Mutex<Vec<HttpRequest>>,
}

impl MockControlTransport {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            captured: Mutex::new(Vec::new()),
        }
    }

    fn last(&self) -> HttpRequest {
        self.captured.lock().unwrap().last().cloned().unwrap()
    }
}

impl GatewayControlTransport for MockControlTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        self.captured.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("mock control transport ran out of responses"))
    }
}

fn ok(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn surface(responses: Vec<HttpResponse>) -> WorkerGatewayControlSurface<MockControlTransport> {
    WorkerGatewayControlSurface::new(
        "https://ferrogate-agent-gateway.example.workers.dev",
        "control-secret",
        MockControlTransport::new(responses),
    )
}

fn body_json(req: &HttpRequest) -> serde_json::Value {
    serde_json::from_slice(req.body.as_ref().unwrap()).unwrap()
}

#[test]
fn start_run_posts_to_control_start_with_bearer_and_body() {
    let mut s = surface(vec![ok(
        r#"{ "runRef": "cf-run-r1", "status": "running" }"#,
    )]);
    let handle = s
        .start_run(CloudflareRunStartRequest {
            session_id: "sess-1".into(),
            run_id: "r1".into(),
            worker_template_id: "tmpl-1".into(),
            framework_adapter: "native".into(),
            capability_envelope_id: "env-1".into(),
        })
        .unwrap();

    assert_eq!(handle.run_ref, "cf-run-r1");
    assert_eq!(handle.status, CloudflareRunStatus::Running);

    let req = s.transport().last();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/control/start"
    );
    assert_eq!(req.bearer_token, "control-secret");
    let body = body_json(&req);
    assert_eq!(body["runId"], "r1");
    assert_eq!(body["sessionId"], "sess-1");
    assert_eq!(body["capabilityEnvelopeId"], "env-1");
}

#[test]
fn exec_run_posts_to_control_invoke_and_maps_outcome() {
    let mut s = surface(vec![ok(
        r#"{ "runRef": "cf-run-r1", "status": "completed", "exitCode": 0, "message": "done" }"#,
    )]);
    let outcome = s
        .exec_run(CloudflareRunExecRequest {
            run_ref: "cf-run-r1".into(),
            workload_ref: "workload-9".into(),
            args: vec!["--flag".into()],
        })
        .unwrap();

    assert_eq!(outcome.status, CloudflareRunStatus::Completed);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(outcome.message, "done");

    let req = s.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/control/invoke"
    );
    let body = body_json(&req);
    assert_eq!(body["runRef"], "cf-run-r1");
    assert_eq!(body["workloadRef"], "workload-9");
    assert_eq!(body["args"][0], "--flag");
}

#[test]
fn stop_run_posts_to_control_cancel_with_reason() {
    let mut s = surface(vec![ok(r#"{ "status": "stopped" }"#)]);
    let status = s.stop_run("cf-run-r1", "operator-cancel").unwrap();
    assert_eq!(status, CloudflareRunStatus::Stopped);

    let req = s.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/control/cancel"
    );
    let body = body_json(&req);
    assert_eq!(body["runRef"], "cf-run-r1");
    assert_eq!(body["reason"], "operator-cancel");
}

#[test]
fn cleanup_run_posts_to_control_destroy() {
    let mut s = surface(vec![ok(r#"{ "status": "cleaned_up" }"#)]);
    let status = s.cleanup_run("cf-run-r1").unwrap();
    assert_eq!(status, CloudflareRunStatus::CleanedUp);

    let req = s.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/control/destroy"
    );
    assert_eq!(req.method, HttpMethod::Post);
}

#[test]
fn run_status_gets_control_status_with_query() {
    let mut s = surface(vec![ok(r#"{ "status": "running" }"#)]);
    let status = s.run_status("cf-run-r1").unwrap();
    assert_eq!(status, CloudflareRunStatus::Running);

    let req = s.transport().last();
    assert_eq!(req.method, HttpMethod::Get);
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/control/status?runRef=cf-run-r1"
    );
    assert!(req.body.is_none());
}

#[test]
fn non_2xx_maps_to_verb_specific_error() {
    let mut s = WorkerGatewayControlSurface::new(
        "https://gw.example.workers.dev",
        "control-secret",
        MockControlTransport::new(vec![HttpResponse {
            status: 403,
            retry_after: None,
            body: b"forbidden".to_vec(),
        }]),
    );
    let err = s
        .start_run(CloudflareRunStartRequest {
            session_id: "s".into(),
            run_id: "r".into(),
            worker_template_id: "t".into(),
            framework_adapter: "native".into(),
            capability_envelope_id: "e".into(),
        })
        .unwrap_err();
    match err {
        CloudflareControlSurfaceError::StartFailed(m) => {
            assert!(m.contains("403"), "got {m}");
        }
        other => panic!("expected StartFailed, got {other:?}"),
    }
}

#[test]
fn unknown_status_string_is_a_transport_error() {
    let mut s = surface(vec![ok(r#"{ "status": "melted" }"#)]);
    let err = s.run_status("cf-run-r1").unwrap_err();
    assert!(
        matches!(err, CloudflareControlSurfaceError::Transport(_)),
        "got {err:?}"
    );
}

// ---- Block-on bridge (production transport) --------------------------------

/// A mock async transport for exercising the BlockingHttpControlTransport bridge
/// without a network.
struct MockAsyncTransport {
    captured: Mutex<Vec<HttpRequest>>,
}

#[async_trait]
impl HttpTransport for MockAsyncTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        self.captured.lock().unwrap().push(request);
        Ok(HttpResponse {
            status: 200,
            retry_after: None,
            body: br#"{ "status": "running" }"#.to_vec(),
        })
    }
}

#[test]
fn blocking_bridge_drives_async_transport_to_completion() {
    let inner = Arc::new(MockAsyncTransport {
        captured: Mutex::new(Vec::new()),
    });
    let bridge = BlockingHttpControlTransport::new(inner.clone()).unwrap();
    let mut s = WorkerGatewayControlSurface::new(
        "https://gw.example.workers.dev",
        "control-secret",
        bridge,
    );

    // A synchronous CloudflareControlSurface call flows through the async
    // transport via the block-on bridge with no ambient runtime.
    let status = s.run_status("cf-run-xyz").unwrap();
    assert_eq!(status, CloudflareRunStatus::Running);
    assert_eq!(inner.captured.lock().unwrap().len(), 1);
}
