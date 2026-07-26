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
    CloudflareRunProps, CloudflareRunStartRequest, CloudflareRunStatus,
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

    fn captured_len(&self) -> usize {
        self.captured.lock().unwrap().len()
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
            props: CloudflareRunProps::default(),
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
fn stop_run_is_a_local_hibernation_no_op() {
    // CF has no stop primitive: `stop_run` must NOT hit any control route. It
    // reports Stopped locally (the idle agent hibernates on its own). The surface
    // is given zero canned responses — if it tried to send, the mock would panic.
    let mut s = surface(vec![]);
    let status = s.stop_run("cf-run-r1", "completed").unwrap();
    assert_eq!(status, CloudflareRunStatus::Stopped);
    assert_eq!(
        s.transport().captured_len(),
        0,
        "stop_run must send no HTTP"
    );
}

#[test]
fn cancel_run_posts_to_control_cancel_with_reason() {
    // Active cancellation IS a route (unlike a terminal stop, which sends
    // nothing). It is the Worker's COOPERATIVE cancel, not a fiber cancel.
    let mut s = surface(vec![ok(r#"{ "status": "stopped" }"#)]);
    let status = s.cancel_run("cf-run-r1", "operator-cancel").unwrap();
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
fn start_run_props_round_trip_into_the_start_body() {
    let mut s = surface(vec![ok(
        r#"{ "runRef": "cf-run-r1", "status": "running" }"#,
    )]);
    s.start_run(CloudflareRunStartRequest {
        session_id: "sess-1".into(),
        run_id: "r1".into(),
        worker_template_id: "tmpl-1".into(),
        framework_adapter: "native".into(),
        capability_envelope_id: "env-1".into(),
        props: CloudflareRunProps {
            model: Some("claude-opus-4-8".into()),
            tools: vec!["shell".into()],
            system_prompt: Some("be terse".into()),
            location_hint: Some("weur".into()),
            jurisdiction: Some("eu".into()),
            routing_retry: Some(3),
        },
    })
    .unwrap();

    // The runtime-selected model (and the rest) reach the Worker under `props`,
    // where `onStart(props)` reads them.
    let body = body_json(&s.transport().last());
    assert_eq!(body["props"]["model"], "claude-opus-4-8");
    assert_eq!(body["props"]["tools"][0], "shell");
    assert_eq!(body["props"]["systemPrompt"], "be terse");
    assert_eq!(body["props"]["locationHint"], "weur");
    assert_eq!(body["props"]["jurisdiction"], "eu");
    assert_eq!(body["props"]["routingRetry"], 3);
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
            props: CloudflareRunProps::default(),
        })
        .unwrap_err();
    match err {
        CloudflareControlSurfaceError::StartFailed(m) => {
            assert!(m.contains("403"), "got {m}");
        }
        other => panic!("expected StartFailed, got {other:?}"),
    }
}

// ---- #414: refusals are errors, and the query is encoded -------------------

/// A 404 `not_found` envelope from the gateway Worker.
fn not_found(run_ref: &str) -> HttpResponse {
    HttpResponse {
        status: 404,
        retry_after: None,
        body: format!(r#"{{ "error": "not_found", "runRef": "{run_ref}" }}"#).into_bytes(),
    }
}

#[test]
fn cleanup_of_an_unknown_run_is_run_not_found_not_cleaned_up() {
    // ISSUE #414 ITEM 4, the half that matters to the control plane: addressing
    // a Durable Object by name always yields a stub, so `destroy` on an unknown
    // runRef used to answer 200 `cleaned_up` and FerroGate recorded
    // IsolationLifecycleEvidence{outcome:"cleaned_up"} for a run that never
    // existed. `CleanedUp` here would mean that regression is back.
    let mut s = surface(vec![not_found("cf-run-ghost")]);
    let err = s.cleanup_run("cf-run-ghost").unwrap_err();
    match err {
        CloudflareControlSurfaceError::RunNotFound(m) => assert!(m.contains("not_found"), "{m}"),
        other => panic!("expected RunNotFound, got {other:?}"),
    }
}

#[test]
fn cancel_and_status_of_an_unknown_run_are_run_not_found() {
    let mut s = surface(vec![not_found("cf-run-ghost")]);
    assert!(matches!(
        s.cancel_run("cf-run-ghost", "operator").unwrap_err(),
        CloudflareControlSurfaceError::RunNotFound(_)
    ));

    let mut s = surface(vec![not_found("cf-run-ghost")]);
    assert!(matches!(
        s.run_status("cf-run-ghost").unwrap_err(),
        CloudflareControlSurfaceError::RunNotFound(_)
    ));
}

#[test]
fn a_conflicting_restart_surfaces_as_start_failed() {
    // The Worker refuses a start that would re-bind a live instance to a
    // different run (409 `run_conflict`); it must not look like a success.
    let mut s = surface(vec![HttpResponse {
        status: 409,
        retry_after: None,
        body: br#"{ "error": "run_conflict", "runRef": "cf-run-r1" }"#.to_vec(),
    }]);
    let err = s
        .start_run(CloudflareRunStartRequest {
            session_id: "s".into(),
            run_id: "r".into(),
            worker_template_id: "t".into(),
            framework_adapter: "native".into(),
            capability_envelope_id: "e".into(),
            props: CloudflareRunProps::default(),
        })
        .unwrap_err();
    match err {
        CloudflareControlSurfaceError::StartFailed(m) => assert!(m.contains("run_conflict"), "{m}"),
        other => panic!("expected StartFailed, got {other:?}"),
    }
}

#[test]
fn run_status_percent_encodes_the_run_ref_in_the_query() {
    // ISSUE #414 ITEM 7. An unescaped `&` or `#` in a run ref truncates or
    // corrupts the query, so the Worker would answer about a DIFFERENT instance
    // (or none) while the caller believed it asked about this one.
    let mut s = surface(vec![ok(r#"{ "status": "running" }"#)]);
    s.run_status("fg.tenant&evil.sess#1.run 2").unwrap();
    assert_eq!(
        s.transport().last().url,
        "https://ferrogate-agent-gateway.example.workers.dev/control/status\
?runRef=fg.tenant%26evil.sess%231.run%202"
    );
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
