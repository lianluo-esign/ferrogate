// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the agent command families (#362): registration, verb →
//! operationId/method/path resolution, lifecycle actions, typed request
//! building against a fake transport, and error/exit-class mapping. Pure logic
//! and a fake transport — no live network.

use super::*;
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

/// An input that satisfies every verb across the families (an id segment plus a
/// body), so the "every declared verb builds" sweep never fails for missing
/// inputs.
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["sch_1"])
        .with_body(serde_json::json!({"workflow_id": "wf_1"}))
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "agent-workflows",
            "agent-schedules",
            "agent-upstreams",
            "agent-runs",
            "agent-jobs",
        ]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (AgentWorkflowsGroup.descriptor(), build_agent_workflows),
        (AgentSchedulesGroup.descriptor(), build_agent_schedules),
        (AgentUpstreamsGroup.descriptor(), build_agent_upstreams),
        (AgentRunsGroup.descriptor(), build_agent_runs),
        (AgentJobsGroup.descriptor(), build_agent_jobs),
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
        "listAdminAgentWorkflows",
        "getAdminAgentWorkflow",
        "createAdminAgentWorkflow",
        "putAdminAgentWorkflow",
        "patchAdminAgentWorkflow",
        "deleteAdminAgentWorkflow",
        "listAdminAgentSchedules",
        "runAdminAgentScheduleNow",
        "listAdminAgentScheduleFires",
        "listAdminAgentUpstreams",
        "putAdminAgentUpstream",
        "listAdminAgentRuns",
        "getAdminAgentRunTimeline",
        "createAgentRun",
        "submitAgentJob",
        "getAgentJob",
        "listAgentJobEvents",
        "getAgentJobResult",
        "cancelAgentJob",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 6 (workflows) + 8 (schedules) + 6 (upstreams) + 3 (runs) + 5 (jobs) = 28
    // distinct ids.
    assert_eq!(manifest.len(), 28);
}

#[test]
fn schedule_run_now_and_fires_map_to_their_sub_paths() {
    let id = ResourceInput::new().with_segments(["sch_1"]);

    let run_now = build_agent_schedules("run-now", &id).unwrap();
    assert_eq!(run_now.method, Method::POST);
    assert_eq!(run_now.path, "/admin/v1/agent-schedules/sch_1/run-now");

    let fires = build_agent_schedules("fires", &id).unwrap();
    assert_eq!(fires.method, Method::GET);
    assert_eq!(fires.path, "/admin/v1/agent-schedules/sch_1/fires");
    assert!(fires.body.is_none());
}

#[test]
fn schedule_crud_verbs_use_the_admin_collection() {
    let create = build_agent_schedules(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"cron": "0 * * * *"})),
    )
    .unwrap();
    assert_eq!(create.method, Method::POST);
    assert_eq!(create.path, "/admin/v1/agent-schedules");

    let update = build_agent_schedules(
        "update",
        &ResourceInput::new()
            .with_segments(["sch_1"])
            .with_body(serde_json::json!({"enabled": false})),
    )
    .unwrap();
    assert_eq!(update.method, Method::PATCH);
    assert_eq!(update.path, "/admin/v1/agent-schedules/sch_1");
}

#[test]
fn run_now_without_id_is_a_usage_error() {
    let error = build_agent_schedules("run-now", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn agent_run_start_posts_to_the_runtime_endpoint() {
    let spec = build_agent_runs(
        "start",
        &ResourceInput::new().with_body(serde_json::json!({"workflow_id": "wf_1"})),
    )
    .unwrap();
    assert_eq!(spec.method, Method::POST);
    // The run-start is the runtime operation, not the admin timeline view.
    assert_eq!(spec.path, "/v1/agent-runs");

    let (transport, seen) = fake(202, br#"{"run_id":"run_1","status":"queued"}"#);
    let client = ControlPlaneClient::new(context(), None, transport);
    let response = block_on(client.send(&spec)).unwrap();
    assert_eq!(response.body["run_id"], "run_1");
    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.method, Method::POST);
    assert_eq!(seen.url, "https://cp.example.com/v1/agent-runs");
}

#[test]
fn agent_run_get_reads_the_admin_timeline() {
    let spec = build_agent_runs("get", &ResourceInput::new().with_segments(["run_9"])).unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/agent-runs/run_9");
}

#[test]
fn agent_run_start_without_body_is_a_usage_error() {
    let error = build_agent_runs("start", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn already_terminal_run_now_maps_to_not_found_conflict_class() {
    let spec =
        build_agent_schedules("run-now", &ResourceInput::new().with_segments(["sch_1"])).unwrap();
    let (transport, _seen) = fake(
        409,
        br#"{"error":{"message":"schedule already firing","type":"ferrogate_error","code":"conflict","request_id":"fgadm-c"}}"#,
    );
    let client = ControlPlaneClient::new(context(), None, transport);
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}

#[test]
fn insufficient_scope_on_workflow_create_maps_to_auth_class() {
    let spec = build_agent_workflows(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"name": "nightly"})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        403,
        br#"{"error":{"message":"missing agent:write scope","type":"ferrogate_error","code":"forbidden","request_id":"fgadm-s"}}"#,
    );
    let client = ControlPlaneClient::new(context(), None, transport);
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}
