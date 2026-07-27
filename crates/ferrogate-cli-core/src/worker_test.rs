// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the worker command families (#362): registration, verb →
//! operationId/method/path resolution, identity/telemetry lifecycle actions,
//! typed request building against a fake transport, and error/exit-class
//! mapping. Pure logic and a fake transport — no live network.

use super::*;
use crate::action_identity::ClientActionIdentity;
use crate::auth::AuthSource;
use crate::command::CommandGroup;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::{CliResult, ExitClass};
use crate::output::OutputFormat;
use crate::registry_helpers::ResourceInput;
use crate::transport::{ControlPlaneClient, PreparedRequest, RawResponse, RequestSpec, Transport};
use http::Method;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};

type Seen = Arc<Mutex<Option<PreparedRequest>>>;
type BuildFn = fn(&str, &ResourceInput) -> CliResult<RequestSpec>;

fn context() -> EffectiveContext {
    EffectiveContext {
        context_name: Some("test".to_string()),
        endpoint: "https://cp.example.com".to_string(),
        tenant: Some("acme".to_string()),
        project: None,
        workspace: None,
        ca_bundle_path: None,
        tls_insecure_skip_verify: false,
        timeout_millis: DEFAULT_TIMEOUT_MILLIS,
        auth: AuthSource::None,
        output: OutputFormat::Json,
        non_interactive: true,
    }
}

fn block_on<F: std::future::Future>(mut future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = TaskContext::from_waker(waker);
    let mut future = unsafe { std::pin::Pin::new_unchecked(&mut future) };
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => continue,
        }
    }
}

struct FakeTransport {
    response: RawResponse,
    seen: Seen,
}

fn fake(status: u16, body: &[u8]) -> (FakeTransport, Seen) {
    let seen: Seen = Arc::new(Mutex::new(None));
    let transport = FakeTransport {
        response: RawResponse {
            status,
            headers: vec![],
            body: body.to_vec(),
        },
        seen: seen.clone(),
    };
    (transport, seen)
}

impl Transport for FakeTransport {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        *self.seen.lock().unwrap() = Some(request);
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }
}

/// Satisfies every verb across the families (a worker id plus a body).
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["wk_1"])
        .with_body(serde_json::json!({"status": "ready"}))
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "self-hosted-workers",
            "managed-workers",
            "managed-worker-sessions",
            "self-hosted-worker-records",
            "self-hosted-runs",
        ]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (
            SelfHostedWorkersGroup.descriptor(),
            build_self_hosted_workers,
        ),
        (ManagedWorkersGroup.descriptor(), build_managed_workers),
        (
            ManagedWorkerSessionsGroup.descriptor(),
            build_managed_worker_sessions,
        ),
        (
            SelfHostedWorkerRecordsGroup.descriptor(),
            build_self_hosted_worker_records,
        ),
        (SelfHostedRunsGroup.descriptor(), build_self_hosted_runs),
    ];
    let input = universal_input();
    for (descriptor, build) in cases {
        for verb in &descriptor.verbs {
            let built = build(&verb.name, &input);
            assert!(
                built.is_ok(),
                "group {} verb {} failed to build: {:?}",
                descriptor.name,
                verb.name,
                built.err()
            );
        }
    }
}

#[test]
fn coverage_manifest_has_exactly_the_declared_operation_ids() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let manifest = registry.coverage_manifest();
    for op in [
        "listAdminSelfHostedWorkers",
        "getAdminSelfHostedWorker",
        "registerSelfHostedWorker",
        "rotateAdminSelfHostedWorkerIdentity",
        "recordAdminSelfHostedWorkerHeartbeat",
        "listAdminSelfHostedWorkerTelemetryEvents",
        "recordAdminSelfHostedWorkerTelemetryEvent",
        "recordAdminSelfHostedWorkerCheckpoint",
        "recordAdminSelfHostedWorkerArtifact",
        "listAdminManagedWorkers",
        "listAdminManagedWorkerSessions",
        "listAdminSelfHostedWorkerRecords",
        "getAdminSelfHostedRunTimeline",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 9 (self-hosted) + 1 + 1 + 1 + 1 = 13 distinct ids.
    assert_eq!(manifest.len(), 13);
}

#[test]
fn register_creates_on_the_collection() {
    let spec = build_self_hosted_workers(
        "register",
        &ResourceInput::new().with_body(serde_json::json!({"name": "edge-1"})),
    )
    .unwrap();
    assert_eq!(spec.method, Method::POST);
    assert_eq!(spec.path, "/admin/v1/self-hosted-workers");
    assert_eq!(spec.body.unwrap()["name"], "edge-1");
}

#[test]
fn lifecycle_actions_map_to_their_own_paths() {
    let id = ResourceInput::new().with_segments(["wk_1"]);

    let rotate = build_self_hosted_workers("rotate", &id).unwrap();
    assert_eq!(rotate.method, Method::POST);
    assert_eq!(rotate.path, "/admin/v1/self-hosted-workers/wk_1/rotate");

    let heartbeat = build_self_hosted_workers("heartbeat", &id).unwrap();
    assert_eq!(
        heartbeat.path,
        "/admin/v1/self-hosted-workers/wk_1/heartbeat"
    );

    let record_event = build_self_hosted_workers("record-event", &id).unwrap();
    assert_eq!(record_event.method, Method::POST);
    assert_eq!(
        record_event.path,
        "/admin/v1/self-hosted-workers/wk_1/events"
    );

    let checkpoint = build_self_hosted_workers("checkpoint", &id).unwrap();
    assert_eq!(
        checkpoint.path,
        "/admin/v1/self-hosted-workers/wk_1/checkpoints"
    );

    let artifact = build_self_hosted_workers("artifact", &id).unwrap();
    assert_eq!(
        artifact.path,
        "/admin/v1/self-hosted-workers/wk_1/artifacts"
    );
}

#[test]
fn events_reads_the_nested_stream_as_a_get() {
    let events =
        build_self_hosted_workers("events", &ResourceInput::new().with_segments(["wk_1"])).unwrap();
    assert_eq!(events.method, Method::GET);
    assert_eq!(events.path, "/admin/v1/self-hosted-workers/wk_1/events");
    assert!(events.body.is_none());
}

#[test]
fn rotate_without_id_is_a_usage_error() {
    let error = build_self_hosted_workers("rotate", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn self_hosted_run_get_reads_the_timeline() {
    let spec =
        build_self_hosted_runs("get", &ResourceInput::new().with_segments(["run_7"])).unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/self-hosted-runs/run_7");
}

#[test]
fn rotate_reaches_the_transport_with_the_absolute_url() {
    let spec =
        build_self_hosted_workers("rotate", &ResourceInput::new().with_segments(["wk_1"])).unwrap();
    let (transport, seen) = fake(200, br#"{"worker_id":"wk_1","certificate_serial":"c9"}"#);
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let response = block_on(client.send(&spec)).unwrap();
    assert_eq!(response.body["certificate_serial"], "c9");
    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.method, Method::POST);
    assert_eq!(
        seen.url,
        "https://cp.example.com/admin/v1/self-hosted-workers/wk_1/rotate"
    );
}

#[test]
fn revoking_unknown_worker_maps_to_not_found_conflict_class() {
    let spec =
        build_self_hosted_workers("get", &ResourceInput::new().with_segments(["wk_gone"])).unwrap();
    let (transport, _seen) = fake(
        404,
        br#"{"error":{"message":"worker not found","type":"ferrogate_error","code":"not_found","request_id":"fgadm-n"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}
