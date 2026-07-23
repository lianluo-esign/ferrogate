// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Mock end-to-end tests for the Cloudflare-hosted managed-worker control client.

//! Mock end-to-end coverage for issue #412: drive [`ManagedWorkerScheduler`]
//! with a [`CloudflareAgentControlClient`] over a [`MockCloudflareControlSurface`]
//! (no network) and assert the provision/exec/stop/cleanup mapping plus that the
//! reconciled session/run status flows into the existing storage row types.

use super::*;
use crate::{
    FrameworkAdapterCapabilities, IsolationBackendKind, IsolationPolicy,
    ManagedWorkerLifecycleAction, ManagedWorkerRunRequest, ManagedWorkerScheduler,
    ManagedWorkerSchedulerConfig, ManagedWorkerSessionRequest, ManagedWorkerSessionStatus,
    WorkerTemplate,
};
use ferrogate_core::TenantContext;
use ferrogate_storage::{StoredAgentRun, StoredManagedWorkerSession};

fn scheduler() -> ManagedWorkerScheduler {
    ManagedWorkerScheduler::new(ManagedWorkerSchedulerConfig::default(), vec![template()]).unwrap()
}

fn template() -> WorkerTemplate {
    WorkerTemplate {
        id: "template-codex-cloudflare".to_string(),
        framework_adapter: "codex".to_string(),
        expected_handler_version: None,
        isolation_policy: IsolationPolicy {
            // The default Cloudflare descriptor advertises the `Gvisor` tier.
            allowed_kinds: vec![IsolationBackendKind::Gvisor],
            ..IsolationPolicy::default()
        },
        enabled: true,
    }
}

fn session_request() -> ManagedWorkerSessionRequest {
    ManagedWorkerSessionRequest {
        tenant_id: "tenant-1".to_string(),
        workspace_id: "workspace-1".to_string(),
        session_id: "session-1".to_string(),
        run_id: "run-1".to_string(),
        requested_framework_adapter: "codex".to_string(),
        capability_envelope_id: "capability-1".to_string(),
        active_tenant_sessions: 0,
        active_workspace_sessions: 0,
    }
}

fn run_request() -> ManagedWorkerRunRequest {
    ManagedWorkerRunRequest {
        workload_ref: "agent://codex/run".to_string(),
        args: vec!["--task".to_string(), "smoke".to_string()],
    }
}

fn codex_handler() -> AgentWorkerFrameworkHandler {
    AgentWorkerFrameworkHandler {
        adapter_name: "codex".to_string(),
        framework: "codex".to_string(),
        version: "cloudflare-1".to_string(),
        capabilities: FrameworkAdapterCapabilities::code_process_shim()
            .capability_names()
            .into_iter()
            .map(str::to_string)
            .collect(),
        ready: true,
        readiness_reason: None,
    }
}

fn client(
    surface: MockCloudflareControlSurface,
) -> CloudflareAgentControlClient<MockCloudflareControlSurface> {
    CloudflareAgentControlClient::new(surface, "cf-worker-1", vec![codex_handler()])
}

#[test]
fn cloudflare_backend_descriptor_is_advertised_and_selectable() {
    let mut client = client(MockCloudflareControlSurface::new());

    let backends = client.backends();
    assert_eq!(backends.len(), 1);
    let descriptor = &backends[0];
    assert_eq!(descriptor.backend_name, CLOUDFLARE_BACKEND_NAME);
    assert_eq!(descriptor.backend_name, "cloudflare");
    assert_eq!(
        descriptor.host_lifecycle_owner,
        CLOUDFLARE_HOST_LIFECYCLE_OWNER
    );
    assert_eq!(descriptor.backend_version, CLOUDFLARE_BACKEND_VERSION);
    // FerroGate drives the CF-hosted run's lifecycle through the control surface.
    assert!(descriptor.gateway_controls_backend);
    assert_eq!(descriptor.kind, IsolationBackendKind::Gvisor);

    // The advertised descriptor satisfies a policy that allows its kind.
    let selected =
        crate::select_isolation_backend(&template().isolation_policy, client.backends()).unwrap();
    assert_eq!(selected.backend_name, "cloudflare");
}

#[test]
fn runs_hosted_session_end_to_end_against_mock_cloudflare_surface() {
    let scheduler = scheduler();
    let mut client = client(MockCloudflareControlSurface::new());

    let execution = scheduler
        .run_to_completion(session_request(), run_request(), &mut client)
        .unwrap();

    // The session ran through the same state machine and cleaned up.
    assert_eq!(
        execution.session.status,
        ManagedWorkerSessionStatus::CleanedUp
    );
    assert_eq!(
        execution.session.selected_backend.backend_name,
        "cloudflare"
    );
    assert!(execution.session.selected_backend.gateway_controls_backend);
    assert_eq!(
        execution.session.worker_template_id,
        "template-codex-cloudflare"
    );
    assert_eq!(execution.session.capability_envelope_id, "capability-1");
    // The scheduler's instance id is the Cloudflare-side run handle.
    assert_eq!(execution.session.instance_id, "cf-run-run-1");
    assert_eq!(execution.exec.exit_code, Some(0));
    assert!(execution
        .exec
        .message
        .contains("cloudflare hosted run executed agent://codex/run"));

    // provision/exec/stop/cleanup mapped onto the control surface in order.
    assert_eq!(
        client.surface().calls(),
        &[
            MockCloudflareCall::StartRun(CloudflareRunStartRequest {
                session_id: "session-1".to_string(),
                run_id: "run-1".to_string(),
                worker_template_id: "template-codex-cloudflare".to_string(),
                framework_adapter: "codex".to_string(),
                capability_envelope_id: "capability-1".to_string(),
                props: CloudflareRunProps::default(),
            }),
            MockCloudflareCall::ExecRun(CloudflareRunExecRequest {
                run_ref: "cf-run-run-1".to_string(),
                workload_ref: "agent://codex/run".to_string(),
                args: vec!["--task".to_string(), "smoke".to_string()],
            }),
            MockCloudflareCall::StopRun {
                run_ref: "cf-run-run-1".to_string(),
                reason: "completed".to_string(),
            },
            MockCloudflareCall::CleanupRun {
                run_ref: "cf-run-run-1".to_string(),
            },
        ]
    );

    // Evidence carries the Cloudflare backend + the run handle as the instance.
    assert_eq!(execution.cleanup.evidence.backend_name, "cloudflare");
    assert_eq!(execution.cleanup.evidence.agent_worker_id, "cf-worker-1");
    assert_eq!(
        execution.cleanup.evidence.isolation_instance_id.as_deref(),
        Some("cf-run-run-1")
    );
    assert_eq!(
        execution.cleanup.evidence.capability_envelope_id,
        "capability-1"
    );

    // Lifecycle records project cleanly for audit.
    let records = execution.lifecycle_records();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[0].action,
        ManagedWorkerLifecycleAction::ExecOrAttach
    );
    assert_eq!(records[0].agent_worker_id, "cf-worker-1");
    assert_eq!(
        records[0].isolation_instance_id.as_deref(),
        Some("cf-run-run-1")
    );
    assert_eq!(records[2].action, ManagedWorkerLifecycleAction::Cleanup);
    assert_eq!(records[2].outcome, "cleaned_up");
}

#[test]
fn reconciles_session_and_run_status_through_storage_row_types() {
    let scheduler = scheduler();
    let mut client = client(MockCloudflareControlSurface::new());

    let execution = scheduler
        .run_to_completion(session_request(), run_request(), &mut client)
        .unwrap();
    let run_ref = execution.session.instance_id.clone();

    // The client reconciles the last observed CF status onto the scheduler's
    // managed-worker session status (what persistence records).
    assert_eq!(
        client.observed_status(&run_ref),
        Some(CloudflareRunStatus::CleanedUp)
    );
    assert_eq!(
        client.reconciled_session_status(&run_ref),
        Some(ManagedWorkerSessionStatus::CleanedUp)
    );

    // Persist the session through the existing storage row type.
    let reconciled = client.reconciled_session_status(&run_ref).unwrap();
    let tenant = TenantContext {
        organization_id: Some(execution.session.tenant_id.clone()),
        workspace_id: Some(execution.session.workspace_id.clone()),
        ..TenantContext::default()
    };
    let stored_session = StoredManagedWorkerSession {
        id: execution.session.session_id.clone(),
        run_id: execution.session.run_id.clone(),
        tenant: tenant.clone(),
        workspace_id: execution.session.workspace_id.clone(),
        worker_template_id: execution.session.worker_template_id.clone(),
        agent_worker_instance_id: Some("cf-worker-1".to_string()),
        status: managed_worker_session_status_wire(reconciled).to_string(),
        isolation_backend_kind: "gvisor".to_string(),
        microvm_id: execution
            .session
            .selected_backend
            .gateway_controls_backend
            .then(|| run_ref.clone()),
        capability_envelope_id: execution.session.capability_envelope_id.clone(),
        requested_at_unix: Some(1_000),
        started_at_unix: Some(1_001),
        completed_at_unix: Some(1_002),
        cleanup_completed_at_unix: Some(1_003),
        capability_envelope_json: "{}".to_string(),
        resource_limits_json: "{}".to_string(),
    };
    assert_eq!(stored_session.status, "cleaned_up");
    assert_eq!(stored_session.run_id, "run-1");
    assert_eq!(stored_session.microvm_id.as_deref(), Some("cf-run-run-1"));
    assert_eq!(stored_session.capability_envelope_id, "capability-1");

    // Persist the agent run through the existing storage row type, reconciling
    // the CF run status onto the run's status string.
    let run_status = client.observed_status(&run_ref).unwrap().agent_run_status();
    let stored_run = StoredAgentRun {
        id: execution.session.run_id.clone(),
        request_id: "request-1".to_string(),
        trace_id: None,
        tenant,
        status: run_status.to_string(),
        provider: "cloudflare".to_string(),
        turns_executed: 1,
        output_recorded: true,
        started_at_unix: Some(1_001),
        completed_at_unix: Some(1_002),
    };
    assert_eq!(stored_run.status, "completed");
    assert_eq!(stored_run.id, "run-1");
}

#[test]
fn refresh_reconciled_status_queries_the_control_surface() {
    let mut client = client(MockCloudflareControlSurface::new());
    // Provision so the client has a run to reconcile.
    let started = client
        .provision_managed_worker(IsolationPrepareRequest {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            worker_template_id: "template-codex-cloudflare".to_string(),
            framework_adapter: "codex".to_string(),
            capability_envelope_id: "capability-1".to_string(),
            policy: template().isolation_policy,
        })
        .unwrap();

    let reconciled = client
        .refresh_reconciled_status(&started.instance_id)
        .unwrap();
    // The mock's `run_status` reports `Running`, which reconciles to `Running`.
    assert_eq!(reconciled, ManagedWorkerSessionStatus::Running);
    assert!(matches!(
        client.surface().calls().last(),
        Some(MockCloudflareCall::RunStatus { run_ref }) if run_ref == &started.instance_id
    ));
}

#[test]
fn props_resolver_round_trips_model_selection_into_start_request() {
    // FerroGate's per-run parameterization: a resolver maps the prepare request
    // (here keyed on the worker template) onto the model/tools/prompt props that
    // the gateway Worker delivers to `onStart(props)`. The scheduler seam is
    // untouched — the resolver is the only injection point.
    let resolver: CloudflareRunPropsResolver = Arc::new(|request: &IsolationPrepareRequest| {
        assert_eq!(request.worker_template_id, "template-codex-cloudflare");
        CloudflareRunProps {
            model: Some("claude-opus-4-8".to_string()),
            tools: vec!["shell".to_string(), "browser".to_string()],
            system_prompt: Some("be terse".to_string()),
            location_hint: Some("weur".to_string()),
            jurisdiction: Some("eu".to_string()),
            routing_retry: Some(2),
        }
    });
    let mut client = client(MockCloudflareControlSurface::new()).with_props_resolver(resolver);

    client
        .provision_managed_worker(IsolationPrepareRequest {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            worker_template_id: "template-codex-cloudflare".to_string(),
            framework_adapter: "codex".to_string(),
            capability_envelope_id: "capability-1".to_string(),
            policy: template().isolation_policy,
        })
        .unwrap();

    // The resolved props (incl. the runtime-selected model) reached the surface's
    // start_run — i.e. they will be delivered to `onStart(props)`.
    match client.surface().calls().first().unwrap() {
        MockCloudflareCall::StartRun(request) => {
            assert_eq!(request.props.model.as_deref(), Some("claude-opus-4-8"));
            assert_eq!(request.props.tools, vec!["shell", "browser"]);
            assert_eq!(request.props.system_prompt.as_deref(), Some("be terse"));
            assert_eq!(request.props.location_hint.as_deref(), Some("weur"));
            assert_eq!(request.props.jurisdiction.as_deref(), Some("eu"));
            assert_eq!(request.props.routing_retry, Some(2));
        }
        other => panic!("expected StartRun, got {other:?}"),
    }
}

#[test]
fn default_props_resolver_yields_empty_props() {
    let mut client = client(MockCloudflareControlSurface::new());
    client
        .provision_managed_worker(IsolationPrepareRequest {
            session_id: "s".to_string(),
            run_id: "r".to_string(),
            worker_template_id: "template-codex-cloudflare".to_string(),
            framework_adapter: "codex".to_string(),
            capability_envelope_id: "e".to_string(),
            policy: template().isolation_policy,
        })
        .unwrap();
    match client.surface().calls().first().unwrap() {
        MockCloudflareCall::StartRun(request) => {
            assert_eq!(request.props, CloudflareRunProps::default());
        }
        other => panic!("expected StartRun, got {other:?}"),
    }
}

#[test]
fn terminal_stop_is_modeled_as_hibernation_not_a_cancel() {
    // The scheduler's terminal reasons (`completed`/`failed`) map to hibernation:
    // `stop_run` (a no-op that reports Stopped), NOT the fiber-cancel route.
    let mut client = client(MockCloudflareControlSurface::new());
    client.stop_managed_worker("cf-run-x", "completed").unwrap();
    client.stop_managed_worker("cf-run-x", "failed").unwrap();

    let calls = client.surface().calls();
    assert!(matches!(
        calls[0],
        MockCloudflareCall::StopRun { ref reason, .. } if reason == "completed"
    ));
    assert!(matches!(
        calls[1],
        MockCloudflareCall::StopRun { ref reason, .. } if reason == "failed"
    ));
    assert!(!calls
        .iter()
        .any(|c| matches!(c, MockCloudflareCall::CancelRun { .. })));
}

#[test]
fn operator_cancel_routes_to_the_fiber_cancel_primitive() {
    // A non-terminal (operator) reason is an active cancel → fiber-cancel route,
    // not hibernation.
    let mut client = client(MockCloudflareControlSurface::new());
    client
        .stop_managed_worker("cf-run-x", "operator_cancelled")
        .unwrap();

    let calls = client.surface().calls();
    assert!(matches!(
        calls.last().unwrap(),
        MockCloudflareCall::CancelRun { run_ref, reason }
            if run_ref == "cf-run-x" && reason == "operator_cancelled"
    ));
    assert!(!calls
        .iter()
        .any(|c| matches!(c, MockCloudflareCall::StopRun { .. })));
}

#[test]
fn provision_failure_surfaces_as_agent_worker_error_and_skips_persistence() {
    let scheduler = scheduler();
    let mut client = client(MockCloudflareControlSurface::failing_start());

    let error = scheduler
        .start_session(session_request(), &mut client)
        .unwrap_err();

    assert!(matches!(error, ManagedWorkerError::AgentWorker(_)));
    assert!(error
        .to_string()
        .contains("cloudflare control surface not ready"));
    // Only the start attempt was made; nothing was recorded as a live run.
    assert_eq!(client.observed_status("cf-run-run-1"), None);
}

#[test]
fn exec_failure_still_stops_and_cleans_up_the_hosted_run() {
    let scheduler = scheduler();
    let mut client = client(MockCloudflareControlSurface::failing_exec());

    let failure = scheduler
        .run_with_cleanup(session_request(), run_request(), &mut client)
        .unwrap_err();

    assert!(matches!(failure.error, ManagedWorkerError::AgentWorker(_)));
    assert_eq!(
        failure.session.status,
        ManagedWorkerSessionStatus::CleanedUp
    );
    // provision + exec(fail) + stop + cleanup were all issued to the surface.
    let calls = client.surface().calls();
    assert!(matches!(calls[0], MockCloudflareCall::StartRun(_)));
    assert!(matches!(calls[1], MockCloudflareCall::ExecRun(_)));
    assert!(matches!(calls[2], MockCloudflareCall::StopRun { .. }));
    assert!(matches!(calls[3], MockCloudflareCall::CleanupRun { .. }));
    // After cleanup the run reconciles to CleanedUp.
    assert_eq!(
        client.reconciled_session_status("cf-run-run-1"),
        Some(ManagedWorkerSessionStatus::CleanedUp)
    );
}
