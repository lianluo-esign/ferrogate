// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: CloudflareContainerIsolationBackend lifecycle tests (issue #415) — drive the full
//   prepare/start/exec/logs/artifacts/stop/cleanup path against a scripted mock transport (NO
//   network), assert the runtime evidence + wire bodies, and prove snapshot fails closed.

use std::collections::VecDeque;
use std::sync::Mutex;

use ferrogate_runtime::{
    ContainerControlClient, ContainerInstanceTier, GatewayControlTransport, HttpRequest,
    HttpResponse, IsolationBackendKind, IsolationBackendLifecycle, IsolationError,
    IsolationExecRequest, IsolationPolicy, IsolationPrepareRequest,
};

use super::CloudflareContainerIsolationBackend;

struct MockTransport {
    responses: Mutex<VecDeque<HttpResponse>>,
    captured: Mutex<Vec<HttpRequest>>,
}

impl MockTransport {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            captured: Mutex::new(Vec::new()),
        }
    }

    fn paths(&self) -> Vec<String> {
        self.captured
            .lock()
            .unwrap()
            .iter()
            .map(|req| req.url.clone())
            .collect()
    }
}

impl GatewayControlTransport for MockTransport {
    fn send(
        &self,
        request: HttpRequest,
    ) -> Result<HttpResponse, ferrogate_runtime::CloudflareControlSurfaceError> {
        self.captured.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("mock transport ran out of responses"))
    }
}

fn ok(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn prepare_request() -> IsolationPrepareRequest {
    IsolationPrepareRequest {
        session_id: "sess-1".to_string(),
        run_id: "run-9".to_string(),
        worker_template_id: "template-1".to_string(),
        framework_adapter: "codex".to_string(),
        capability_envelope_id: "cap-1".to_string(),
        policy: IsolationPolicy::default(),
    }
}

fn backend(responses: Vec<HttpResponse>) -> CloudflareContainerIsolationBackend<MockTransport> {
    let client = ContainerControlClient::new(
        "https://ferrogate-agent-gateway.example.workers.dev",
        "control-secret",
        MockTransport::new(responses),
    );
    CloudflareContainerIsolationBackend::new(
        "tenant-a",
        "agent-worker-1",
        "gateway-driven",
        client,
        "registry/agent-sandbox:latest",
        ContainerInstanceTier::Standard1,
    )
}

#[test]
fn descriptor_is_gateway_driven_with_no_snapshot_capability() {
    let backend = backend(vec![]);
    let descriptor = backend.backend_descriptor();
    assert_eq!(descriptor.kind, IsolationBackendKind::CloudflareContainer);
    assert_eq!(descriptor.backend_name, "cloudflare-container");
    assert!(descriptor.gateway_controls_backend);
    assert_eq!(descriptor.host_lifecycle_owner, "cloudflare-agent-gateway");
    // Fail-closed: snapshot/checkpoint is not implemented, so it is not
    // advertised — selection can never route that op here.
    assert!(!descriptor.capabilities.snapshot_or_checkpoint);
    assert!(descriptor.capabilities.prepare && descriptor.capabilities.exec_or_attach);
}

#[test]
fn full_lifecycle_drives_the_worker_routes_and_records_evidence() {
    let mut backend = backend(vec![
        ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "preparedId": "prep-1" }"#),
        ok(
            r#"{ "instance": "fg.tenant-a.sess-1.run-9", "instanceId": "cf-abc", "running": true }"#,
        ),
        ok(
            r#"{ "instance": "fg.tenant-a.sess-1.run-9", "exitCode": 0, "stdout": "ok\n", "stderr": "" }"#,
        ),
        ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "lines": ["started"] }"#),
        ok(
            r#"{ "instance": "fg.tenant-a.sess-1.run-9", "artifacts": [ { "path": "/workspace/out.txt", "sizeBytes": 3 } ] }"#,
        ),
        ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "signal": "SIGTERM", "running": false }"#),
        ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "destroyed": true }"#),
    ]);

    let prepared = backend.prepare(prepare_request()).unwrap();
    assert_eq!(prepared.evidence.outcome, "prepared");
    assert_eq!(prepared.evidence.agent_worker_id, "agent-worker-1");

    let started = backend.start(prepared).unwrap();
    assert_eq!(started.instance_id, "cf-abc");
    assert_eq!(started.evidence.outcome, "started");
    // No direct public egress leaks through the isolation network policy.
    assert!(!started.evidence.network_policy.direct_public_egress);

    let exec = backend
        .exec_or_attach(IsolationExecRequest {
            instance_id: started.instance_id.clone(),
            workload_ref: "agent://managed/readiness".to_string(),
            args: vec!["/bin/echo".to_string(), "ok".to_string()],
        })
        .unwrap();
    assert_eq!(exec.exit_code, Some(0));
    assert_eq!(exec.message, "ok\n");

    let logs = backend.collect_logs(&started.instance_id).unwrap();
    assert_eq!(logs.lines, vec!["started"]);

    let artifacts = backend.collect_artifacts(&started.instance_id).unwrap();
    assert_eq!(artifacts.artifacts.len(), 1);
    assert_eq!(artifacts.artifacts[0].path, "/workspace/out.txt");

    let stopped = backend.stop(&started.instance_id, "completed").unwrap();
    assert_eq!(stopped.evidence.outcome, "stopped:completed");

    let cleaned = backend.cleanup(&started.instance_id).unwrap();
    assert_eq!(cleaned.evidence.outcome, "cleaned_up");
    assert!(backend.instance_id().is_none());

    assert_eq!(backend.descriptor().backend_name, "cloudflare-container");
}

#[test]
fn lifecycle_hits_each_container_route_in_order() {
    // Re-run the happy path and assert the exact route sequence, proving each
    // verb is wired to its own fronting-Worker route.
    let mut backend = backend(vec![
        ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "preparedId": "prep-1" }"#),
        ok(
            r#"{ "instance": "fg.tenant-a.sess-1.run-9", "instanceId": "cf-abc", "running": true }"#,
        ),
        ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "signal": "SIGTERM", "running": false }"#),
        ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "destroyed": true }"#),
    ]);
    let prepared = backend.prepare(prepare_request()).unwrap();
    let started = backend.start(prepared).unwrap();
    backend.stop(&started.instance_id, "done").unwrap();
    backend.cleanup(&started.instance_id).unwrap();

    let paths = backend.client().transport().paths();
    assert_eq!(
        paths,
        vec![
            "https://ferrogate-agent-gateway.example.workers.dev/container/prepare",
            "https://ferrogate-agent-gateway.example.workers.dev/container/start",
            "https://ferrogate-agent-gateway.example.workers.dev/container/stop",
            "https://ferrogate-agent-gateway.example.workers.dev/container/cleanup",
        ]
    );
}

#[test]
fn snapshot_fails_closed_with_an_honest_error() {
    let mut backend = backend(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "preparedId": "prep-1" }"#,
    )]);
    backend.prepare(prepare_request()).unwrap();
    let error = backend.snapshot_or_checkpoint("cf-abc").unwrap_err();
    match error {
        IsolationError::Backend(message) => {
            assert!(message.contains("snapshot/checkpoint"), "got {message}");
        }
        other => panic!("expected Backend error, got {other:?}"),
    }
}

#[test]
fn prepare_fails_when_identity_is_unusable() {
    let mut backend = {
        let client = ContainerControlClient::new(
            "https://ferrogate-agent-gateway.example.workers.dev",
            "control-secret",
            MockTransport::new(vec![]),
        );
        // A tenant id containing the reserved separator can never mint a safe
        // instance name — prepare must fail before any remote call.
        CloudflareContainerIsolationBackend::new(
            "tenant.bad",
            "agent-worker-1",
            "gateway-driven",
            client,
            "img",
            ContainerInstanceTier::Lite,
        )
    };
    let error = backend.prepare(prepare_request()).unwrap_err();
    assert!(matches!(error, IsolationError::Backend(_)));
}
