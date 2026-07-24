// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Cloudflare container remote-provisioning dispatch tests (issue #442). Drive the
//   provision → exec → stop → cleanup path and the fail-closed snapshot path against a scripted
//   mock GatewayControlTransport (NO network), through the same management dispatch entrypoint the
//   Docker/local-process tiers use.

use std::collections::VecDeque;
use std::sync::Mutex;

use ferrogate_runtime::{
    cloudflare_container_descriptor, AgentWorkerManagementAction, AgentWorkerManagementEnvelope,
    AgentWorkerManagementErrorCode, AgentWorkerManagementResult, AgentWorkerManagementSecurity,
    AgentWorkerSecurityAlgorithm, AgentWorkerTransportSecurity, CloudflareControlSurfaceError,
    ContainerControlClient, ContainerInstanceTier, FrameworkAdapterMode, HttpRequest, HttpResponse,
    IsolationBackendDescriptor, ManagedWorkerSessionStatus, AGENT_WORKER_PROTOCOL_VERSION,
};

use super::{provision_cloudflare_container_backend, CloudflareContainerIsolationBackend};
use crate::lifecycle::dispatch_lifecycle_action;
use crate::state::{AgentWorkerStateStore, InMemoryAgentWorkerStateStore};

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
}

impl ferrogate_runtime::GatewayControlTransport for MockTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareControlSurfaceError> {
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

fn descriptor() -> IsolationBackendDescriptor {
    cloudflare_container_descriptor("gateway-driven")
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

fn envelope(action: AgentWorkerManagementAction) -> AgentWorkerManagementEnvelope {
    AgentWorkerManagementEnvelope {
        protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
        action,
        request_id: "cf-container-request".to_string(),
        idempotency_key: "cf-container-idempotency".to_string(),
        issued_at_unix_millis: 1_000,
        deadline_unix_millis: 60_000,
        tenant_id: "tenant-a".to_string(),
        workspace_id: "cf-container-workspace".to_string(),
        worker_id: "agent-worker-1".to_string(),
        session_id: Some("sess-1".to_string()),
        run_id: Some("run-9".to_string()),
        framework_adapter: Some("native-harness".to_string()),
        security: AgentWorkerManagementSecurity {
            key_id: "cf-container-key".to_string(),
            nonce: "cf-container-nonce".to_string(),
            signature: String::new(),
            algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
            transport_security: AgentWorkerTransportSecurity::LocalUnixSocket,
            encrypted: false,
        },
    }
}

fn prepared_response() -> HttpResponse {
    ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "preparedId": "prep-1" }"#)
}

fn started_response() -> HttpResponse {
    ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "instanceId": "cf-abc", "running": true }"#)
}

/// Provision mirrors `provision_docker`: prepare + start drive the fronting
/// Worker routes, the backend is stored keyed by session/run, and the lifecycle
/// result records the gateway-driven descriptor and the assigned instance id.
#[test]
fn provision_prepares_starts_and_stores_the_backend() {
    let mut state = InMemoryAgentWorkerStateStore::new();
    let env = envelope(AgentWorkerManagementAction::Provision);
    let backend = backend(vec![prepared_response(), started_response()]);

    let result = provision_cloudflare_container_backend(&mut state, &env, &descriptor(), backend)
        .unwrap()
        .unwrap();

    let AgentWorkerManagementResult::Lifecycle { lifecycle } = result else {
        panic!("expected lifecycle result, got {result:?}");
    };
    assert_eq!(lifecycle.status, ManagedWorkerSessionStatus::Running);
    assert_eq!(lifecycle.outcome, "provisioned");
    assert_eq!(lifecycle.backend_name, "cloudflare-container");
    assert_eq!(lifecycle.backend_kind, "cloudflare_container");
    assert_eq!(lifecycle.backend_version, "gateway-driven");
    assert_eq!(lifecycle.isolation_instance_id.as_deref(), Some("cf-abc"));
    assert!(lifecycle.message.contains("deny-by-default egress"));
    // The backend is now retained for the session/run, exactly like the Docker
    // tier, so later lifecycle verbs find it.
    assert!(state
        .get_cloudflare_container_backend_mut("sess-1", "run-9")
        .is_some());
}

/// A second provision for an already-provisioned session/run short-circuits to
/// `already_running` without consuming any transport calls (fresh empty mock).
#[test]
fn provision_is_idempotent_for_an_existing_session() {
    let mut state = InMemoryAgentWorkerStateStore::new();
    let env = envelope(AgentWorkerManagementAction::Provision);
    provision_cloudflare_container_backend(
        &mut state,
        &env,
        &descriptor(),
        backend(vec![prepared_response(), started_response()]),
    )
    .unwrap();

    let result =
        provision_cloudflare_container_backend(&mut state, &env, &descriptor(), backend(vec![]))
            .unwrap()
            .unwrap();
    let AgentWorkerManagementResult::Lifecycle { lifecycle } = result else {
        panic!("expected lifecycle result, got {result:?}");
    };
    assert_eq!(lifecycle.outcome, "already_running");
}

/// After provision, exec/stop/cleanup route through the SAME management dispatch
/// the Docker tier uses (`dispatch_lifecycle_action`), proving the wiring.
#[test]
fn dispatch_drives_exec_stop_and_cleanup_after_provision() {
    let mut state = InMemoryAgentWorkerStateStore::new();
    let provision_env = envelope(AgentWorkerManagementAction::Provision);
    provision_cloudflare_container_backend(
        &mut state,
        &provision_env,
        &descriptor(),
        backend(vec![
            prepared_response(),
            started_response(),
            ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "exitCode": 0, "stdout": "ready\n", "stderr": "" }"#),
            ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "signal": "SIGTERM", "running": false }"#),
            ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "destroyed": true }"#),
        ]),
    )
    .unwrap();

    let exec = dispatch_lifecycle_action(
        &mut state,
        &envelope(AgentWorkerManagementAction::ExecOrAttach),
        None,
        FrameworkAdapterMode::Managed,
    )
    .unwrap()
    .unwrap();
    let AgentWorkerManagementResult::Lifecycle { lifecycle } = exec else {
        panic!("expected exec lifecycle, got {exec:?}");
    };
    assert_eq!(lifecycle.outcome, "executed");
    assert_eq!(lifecycle.status, ManagedWorkerSessionStatus::Running);
    assert!(lifecycle.message.contains("exit_code=Some(0)"));

    let stop = dispatch_lifecycle_action(
        &mut state,
        &envelope(AgentWorkerManagementAction::Stop),
        None,
        FrameworkAdapterMode::Managed,
    )
    .unwrap()
    .unwrap();
    let AgentWorkerManagementResult::Lifecycle { lifecycle } = stop else {
        panic!("expected stop lifecycle, got {stop:?}");
    };
    assert_eq!(lifecycle.outcome, "stopped");
    assert_eq!(lifecycle.status, ManagedWorkerSessionStatus::Cancelled);

    let cleanup = dispatch_lifecycle_action(
        &mut state,
        &envelope(AgentWorkerManagementAction::Cleanup),
        None,
        FrameworkAdapterMode::Managed,
    )
    .unwrap()
    .unwrap();
    let AgentWorkerManagementResult::Lifecycle { lifecycle } = cleanup else {
        panic!("expected cleanup lifecycle, got {cleanup:?}");
    };
    assert_eq!(lifecycle.outcome, "cleaned_up");
    assert_eq!(lifecycle.status, ManagedWorkerSessionStatus::CleanedUp);
    // Cleanup removes the retained backend.
    assert!(state
        .get_cloudflare_container_backend_mut("sess-1", "run-9")
        .is_none());
}

/// Collect-artifacts routes through dispatch and maps the workspace listing to
/// framework artifact results.
#[test]
fn dispatch_collects_container_artifacts() {
    let mut state = InMemoryAgentWorkerStateStore::new();
    provision_cloudflare_container_backend(
        &mut state,
        &envelope(AgentWorkerManagementAction::Provision),
        &descriptor(),
        backend(vec![
            prepared_response(),
            started_response(),
            ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9", "artifacts": [ { "path": "/workspace/out.txt", "sizeBytes": 3, "contentType": "text/plain" } ] }"#),
        ]),
    )
    .unwrap();

    let result = dispatch_lifecycle_action(
        &mut state,
        &envelope(AgentWorkerManagementAction::CollectArtifacts),
        None,
        FrameworkAdapterMode::Managed,
    )
    .unwrap()
    .unwrap();
    let AgentWorkerManagementResult::HandlerArtifacts { artifacts, .. } = result else {
        panic!("expected handler artifacts, got {result:?}");
    };
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].name, "/workspace/out.txt");
    assert_eq!(artifacts[0].media_type, "text/plain");
}

/// Snapshot fails closed through dispatch: Cloudflare exposes no checkpoint
/// primitive, so the honest error is surfaced (never a fabricated checkpoint)
/// and no transport call is made.
#[test]
fn dispatch_snapshot_fails_closed() {
    let mut state = InMemoryAgentWorkerStateStore::new();
    provision_cloudflare_container_backend(
        &mut state,
        &envelope(AgentWorkerManagementAction::Provision),
        &descriptor(),
        backend(vec![prepared_response(), started_response()]),
    )
    .unwrap();

    let error = dispatch_lifecycle_action(
        &mut state,
        &envelope(AgentWorkerManagementAction::SnapshotOrCheckpoint),
        None,
        FrameworkAdapterMode::Managed,
    )
    .unwrap_err();
    assert_eq!(
        error.management_error().code,
        AgentWorkerManagementErrorCode::IncompatibleBackend
    );
    assert!(error.to_string().contains("snapshot/checkpoint"));
    // The backend is still retained (a failed snapshot does not tear it down).
    assert!(state
        .get_cloudflare_container_backend_mut("sess-1", "run-9")
        .is_some());
}
