// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Worker-owned framework handler execution.
//!
//! This module is deliberately inside `agent-worker`. The gateway management
//! API may ask for lifecycle actions, but framework handler execution and event
//! normalization stay on the worker side.

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::HashMap;

use ferrogate_runtime::{
    AgentWorkerFrameworkArtifactResult, AgentWorkerFrameworkEventResult,
    AgentWorkerManagementErrorCode, AgentWorkerManagementResult, FrameworkAdapter,
    FrameworkAdapterArtifact, FrameworkAdapterSession, ManagedWorkerError, NativeHarnessAdapter,
    NormalizedFrameworkEvent, ProcessFrameworkAdapter,
};
#[cfg(test)]
use ferrogate_runtime::{
    AgentWorkerManagementEnvelope, CapabilityAuthorizationDecision,
    FrameworkAdapterArtifactRequest, FrameworkAdapterCapabilities, FrameworkAdapterEventKind,
    FrameworkAdapterMode, FrameworkAdapterRunRequest, FrameworkAdapterSessionRequest,
    ManagedCliAction, ManagedExternalAction, ManagedMemoryAccess, ManagedMemoryAction,
    ManagedToolAction,
};

#[cfg(test)]
use crate::external_actions::{
    request_handler_external_action_decision, ExternalActionGateRequest,
    GatewayExternalActionAuthorizer,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandlerRunState {
    pub(crate) session: FrameworkAdapterSession,
    pub(crate) events: Vec<NormalizedFrameworkEvent>,
    pub(crate) artifacts: Vec<FrameworkAdapterArtifact>,
    pub(crate) closed: bool,
}

#[cfg(test)]
pub(crate) fn exec_or_attach_framework_handler_with_authorizer(
    envelope: &AgentWorkerManagementEnvelope,
    external_action_authorizer: Option<&dyn GatewayExternalActionAuthorizer>,
) -> Result<(HandlerRunState, AgentWorkerManagementResult), ManagedWorkerError> {
    let mut adapter = selected_adapter(envelope)?;
    let session_request = FrameworkAdapterSessionRequest {
        session_id: lifecycle_session_id(envelope)?,
        run_id: lifecycle_run_id(envelope)?,
        tenant_id: envelope.tenant_id.clone(),
        workspace_id: envelope.workspace_id.clone(),
        worker_id: envelope.worker_id.clone(),
        isolation_backend: "firecracker".to_string(),
        mode: FrameworkAdapterMode::Managed,
        required_capabilities: required_capabilities(envelope.framework_adapter.as_deref()),
    };
    let (session, started) = adapter
        .start_session(session_request)
        .map_err(handler_runtime_error)?;
    let mut events = vec![started];
    let decision = request_handler_external_action_decision(
        external_action_authorizer,
        ExternalActionGateRequest {
            session: session.clone(),
            action: managed_action_for_session(&session),
            high_risk: false,
        },
    )
    .map_err(handler_runtime_error)?;
    events.push(decision.event);
    if decision.decision != CapabilityAuthorizationDecision::Allowed {
        return Ok((
            HandlerRunState {
                session,
                events: events.clone(),
                artifacts: vec![],
                closed: false,
            },
            AgentWorkerManagementResult::HandlerEvents {
                events: events.into_iter().map(event_result).collect(),
            },
        ));
    }
    if let Some(binary_event) = process_handler_binary_event(&session)? {
        events.push(binary_event);
    }
    if let Some(task_event) = process_handler_task_event(&session)? {
        let task_failed = task_event.kind == FrameworkAdapterEventKind::RunFailed;
        events.push(task_event);
        if task_failed {
            return Ok((
                HandlerRunState {
                    session,
                    events: events.clone(),
                    artifacts: vec![],
                    closed: false,
                },
                AgentWorkerManagementResult::HandlerEvents {
                    events: events.into_iter().map(event_result).collect(),
                },
            ));
        }
    }
    events.extend(
        adapter
            .submit_run(FrameworkAdapterRunRequest {
                session: session.clone(),
                input_ref: format!("managed://{}/{}", session.session_id, session.run_id),
            })
            .map_err(handler_runtime_error)?,
    );
    let artifacts = adapter
        .collect_artifacts(FrameworkAdapterArtifactRequest {
            session: session.clone(),
            artifact_id: Some(format!("{}-artifact", session.adapter_name)),
        })
        .map_err(handler_runtime_error)?;
    events.push(artifacts.event.clone());
    let closed = adapter
        .close_session(&session)
        .map_err(handler_runtime_error)?;
    events.push(closed);
    let state = HandlerRunState {
        session,
        events: events.clone(),
        artifacts: artifacts.artifacts.clone(),
        closed: true,
    };
    Ok((
        state,
        AgentWorkerManagementResult::HandlerEvents {
            events: events.into_iter().map(event_result).collect(),
        },
    ))
}

pub(crate) fn stream_native_harness_status(state: &HandlerRunState) -> AgentWorkerManagementResult {
    AgentWorkerManagementResult::HandlerEvents {
        events: state.events.iter().cloned().map(event_result).collect(),
    }
}

pub(crate) fn collect_native_harness_artifacts(
    state: &HandlerRunState,
) -> AgentWorkerManagementResult {
    AgentWorkerManagementResult::HandlerArtifacts {
        artifacts: state
            .artifacts
            .iter()
            .cloned()
            .map(artifact_result)
            .collect(),
        events: state.events.iter().cloned().map(event_result).collect(),
    }
}

pub(crate) fn cancel_native_harness(
    state: &mut HandlerRunState,
) -> Result<AgentWorkerManagementResult, ManagedWorkerError> {
    let mut adapter = adapter_for_name(&state.session.adapter_name)?;
    let cancelled = adapter
        .cancel_run(&state.session)
        .map_err(handler_runtime_error)?;
    state.events.push(cancelled.clone());
    Ok(AgentWorkerManagementResult::HandlerEvents {
        events: vec![event_result(cancelled)],
    })
}

pub(crate) fn cleanup_native_harness(
    state: &mut HandlerRunState,
) -> Result<AgentWorkerManagementResult, ManagedWorkerError> {
    if state.closed {
        return Ok(AgentWorkerManagementResult::HandlerEvents { events: vec![] });
    }
    let mut adapter = adapter_for_name(&state.session.adapter_name)?;
    let closed = adapter
        .close_session(&state.session)
        .map_err(handler_runtime_error)?;
    state.closed = true;
    state.events.push(closed.clone());
    Ok(AgentWorkerManagementResult::HandlerEvents {
        events: vec![event_result(closed)],
    })
}

fn event_result(event: NormalizedFrameworkEvent) -> AgentWorkerFrameworkEventResult {
    AgentWorkerFrameworkEventResult {
        session_id: event.session_id,
        run_id: event.run_id,
        adapter_name: event.adapter_name,
        adapter_version: event.adapter_version,
        framework: event.framework.as_str().to_string(),
        mode: event.mode.as_str().to_string(),
        kind: event.kind.as_str().to_string(),
        message: event.message,
        metadata: event.metadata.into_iter().collect::<HashMap<_, _>>(),
    }
}

fn artifact_result(artifact: FrameworkAdapterArtifact) -> AgentWorkerFrameworkArtifactResult {
    AgentWorkerFrameworkArtifactResult {
        artifact_id: artifact.artifact_id,
        name: artifact.name,
        media_type: artifact.media_type,
        byte_len: artifact.byte_len,
    }
}

#[cfg(test)]
fn selected_adapter(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<Box<dyn FrameworkAdapter>, ManagedWorkerError> {
    let adapter = envelope
        .framework_adapter
        .as_deref()
        .unwrap_or("native-harness");
    match adapter {
        "native-harness" | "native_harness" => adapter_for_name("native-harness"),
        "codex" => adapter_for_name("codex"),
        "claude-code" | "claude_code" => adapter_for_name("claude-code"),
        "hermes" => adapter_for_name("hermes"),
        other => Err(ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::HandlerUnavailable,
            format!("agent-worker has no framework handler for adapter {other}"),
        )),
    }
}

fn adapter_for_name(adapter_name: &str) -> Result<Box<dyn FrameworkAdapter>, ManagedWorkerError> {
    match adapter_name {
        "native-harness" | "native_harness" => Ok(Box::new(NativeHarnessAdapter::default())),
        "codex" => Ok(Box::new(ProcessFrameworkAdapter::codex())),
        "claude-code" | "claude_code" => Ok(Box::new(ProcessFrameworkAdapter::claude_code())),
        "hermes" => Ok(Box::new(ProcessFrameworkAdapter::hermes())),
        other => Err(ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::HandlerUnavailable,
            format!("agent-worker has no framework handler for adapter {other}"),
        )),
    }
}

#[cfg(test)]
fn required_capabilities(adapter: Option<&str>) -> FrameworkAdapterCapabilities {
    match adapter.unwrap_or("native-harness") {
        "hermes" => FrameworkAdapterCapabilities {
            memory_read: true,
            memory_write: true,
            checkpoint: true,
            artifacts: true,
            subagents: true,
            streaming: true,
            ..FrameworkAdapterCapabilities::default()
        },
        "codex" | "claude-code" | "claude_code" => FrameworkAdapterCapabilities {
            tools: true,
            checkpoint: true,
            artifacts: true,
            filesystem: true,
            shell: true,
            streaming: true,
            ..FrameworkAdapterCapabilities::default()
        },
        _ => FrameworkAdapterCapabilities {
            tools: true,
            checkpoint: true,
            artifacts: true,
            streaming: true,
            ..FrameworkAdapterCapabilities::default()
        },
    }
}

#[cfg(test)]
fn managed_action_for_session(session: &FrameworkAdapterSession) -> ManagedExternalAction {
    match session.adapter_name.as_str() {
        "codex" | "claude-code" => ManagedExternalAction::Cli(ManagedCliAction {
            command: session.adapter_name.clone(),
            args: vec!["run".to_string(), "--json".to_string()],
            working_dir: format!("/workspaces/{}", session.workspace_id),
            env_policy: "gateway_injected_only".to_string(),
            timeout_millis: 30_000,
            stdout_limit_bytes: 1024 * 1024,
            stderr_limit_bytes: 256 * 1024,
            artifact_capture: true,
        }),
        "hermes" => ManagedExternalAction::Memory(ManagedMemoryAction {
            access: ManagedMemoryAccess::Read,
            namespace: format!(
                "tenant:{}/workspace:{}",
                session.tenant_id, session.workspace_id
            ),
            key: format!("run-context:{}", session.run_id),
        }),
        _ => ManagedExternalAction::Tool(ManagedToolAction {
            tool_name: format!("{}.dispatch", session.adapter_name),
            arguments_policy: "redacted_json".to_string(),
        }),
    }
}

fn handler_runtime_error(error: ferrogate_runtime::FrameworkAdapterError) -> ManagedWorkerError {
    ManagedWorkerError::management_protocol_error(
        AgentWorkerManagementErrorCode::RunFailed,
        format!("agent-worker framework handler failed: {error}"),
    )
}

#[cfg(test)]
fn process_handler_binary_event(
    session: &FrameworkAdapterSession,
) -> Result<Option<NormalizedFrameworkEvent>, ManagedWorkerError> {
    if !matches!(
        session.adapter_name.as_str(),
        "codex" | "claude-code" | "hermes"
    ) {
        return Ok(None);
    }
    let smoke =
        crate::handlers::smoke_handler_binary(&session.adapter_name, 5_000).map_err(|error| {
            ManagedWorkerError::management_protocol_error(
                AgentWorkerManagementErrorCode::RunFailed,
                format!(
                    "agent-worker failed to execute configured {} handler binary smoke: {error}",
                    session.adapter_name
                ),
            )
        })?;
    Ok(Some(NormalizedFrameworkEvent {
        session_id: session.session_id.clone(),
        run_id: session.run_id.clone(),
        adapter_name: session.adapter_name.clone(),
        adapter_version: session.adapter_version.clone(),
        framework: session.framework,
        mode: session.mode,
        kind: FrameworkAdapterEventKind::CliRequested,
        message: Some(format!(
            "{} configured handler binary executed by agent-worker",
            session.adapter_name
        )),
        metadata: BTreeMap::from([
            ("handler_owner".to_string(), "agent-worker".to_string()),
            ("gateway_handler_probe".to_string(), "false".to_string()),
            ("real_binary_probe".to_string(), "true".to_string()),
            ("adapter_name".to_string(), smoke.adapter_name.to_string()),
            ("env_var".to_string(), smoke.env_var.to_string()),
            (
                "binary_path".to_string(),
                smoke.binary_path.display().to_string(),
            ),
            ("probe_args".to_string(), smoke.probe_args.join(" ")),
            (
                "status_code".to_string(),
                smoke
                    .status_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
            ),
            ("stdout_excerpt".to_string(), smoke.stdout_excerpt),
            ("stderr_excerpt".to_string(), smoke.stderr_excerpt),
        ]),
    }))
}

#[cfg(test)]
fn process_handler_task_event(
    session: &FrameworkAdapterSession,
) -> Result<Option<NormalizedFrameworkEvent>, ManagedWorkerError> {
    if !matches!(
        session.adapter_name.as_str(),
        "codex" | "claude-code" | "hermes"
    ) || std::env::var("AGENT_WORKER_HANDLER_TASK_SMOKE")
        .ok()
        .as_deref()
        != Some("1")
    {
        return Ok(None);
    }
    let prompt = std::env::var("AGENT_WORKER_HANDLER_TASK_SMOKE_PROMPT")
        .unwrap_or_else(|_| "Return exactly: ferrogate-agent-worker-task-smoke".to_string());
    let timeout_millis = std::env::var("AGENT_WORKER_HANDLER_TASK_SMOKE_TIMEOUT_MILLIS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30_000);
    let smoke =
        match crate::handlers::smoke_handler_task(&session.adapter_name, timeout_millis, &prompt) {
            Ok(smoke) => smoke,
            Err(error) => {
                return Ok(Some(NormalizedFrameworkEvent {
                    session_id: session.session_id.clone(),
                    run_id: session.run_id.clone(),
                    adapter_name: session.adapter_name.clone(),
                    adapter_version: session.adapter_version.clone(),
                    framework: session.framework,
                    mode: session.mode,
                    kind: FrameworkAdapterEventKind::RunFailed,
                    message: Some(format!(
                        "{} configured handler task failed after gateway authorization",
                        session.adapter_name
                    )),
                    metadata: BTreeMap::from([
                        ("handler_owner".to_string(), "agent-worker".to_string()),
                        ("gateway_handler_probe".to_string(), "false".to_string()),
                        ("real_binary_task_smoke".to_string(), "true".to_string()),
                        ("failed_after_authorization".to_string(), "true".to_string()),
                        ("adapter_name".to_string(), session.adapter_name.clone()),
                        (
                            "prompt_chars".to_string(),
                            prompt.chars().count().to_string(),
                        ),
                        ("failure_reason".to_string(), error.to_string()),
                    ]),
                }));
            }
        };
    Ok(Some(NormalizedFrameworkEvent {
        session_id: session.session_id.clone(),
        run_id: session.run_id.clone(),
        adapter_name: session.adapter_name.clone(),
        adapter_version: session.adapter_version.clone(),
        framework: session.framework,
        mode: session.mode,
        kind: FrameworkAdapterEventKind::RunStarted,
        message: Some(format!(
            "{} configured handler task executed by agent-worker",
            session.adapter_name
        )),
        metadata: BTreeMap::from([
            ("handler_owner".to_string(), "agent-worker".to_string()),
            ("gateway_handler_probe".to_string(), "false".to_string()),
            ("real_binary_task_smoke".to_string(), "true".to_string()),
            ("adapter_name".to_string(), smoke.adapter_name.to_string()),
            ("env_var".to_string(), smoke.env_var.to_string()),
            (
                "binary_path".to_string(),
                smoke.binary_path.display().to_string(),
            ),
            (
                "task_args".to_string(),
                crate::handlers::redacted_args(&smoke.task_args, smoke.prompt_arg_index).join(" "),
            ),
            ("prompt_chars".to_string(), smoke.prompt_chars.to_string()),
            (
                "status_code".to_string(),
                smoke
                    .status_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
            ),
            ("stdout_excerpt".to_string(), smoke.stdout_excerpt),
            ("stderr_excerpt".to_string(), smoke.stderr_excerpt),
        ]),
    }))
}

#[cfg(test)]
fn lifecycle_session_id(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<String, ManagedWorkerError> {
    envelope.session_id.clone().ok_or_else(|| {
        ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::MissingRequiredField,
            "session_id is required for handler execution",
        )
    })
}

#[cfg(test)]
fn lifecycle_run_id(
    envelope: &AgentWorkerManagementEnvelope,
) -> Result<String, ManagedWorkerError> {
    envelope.run_id.clone().ok_or_else(|| {
        ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::MissingRequiredField,
            "run_id is required for handler execution",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::{
        AgentWorkerManagementAction, AgentWorkerManagementSecurity, AgentWorkerSecurityAlgorithm,
        AgentWorkerTransportSecurity, CapabilityAction, CapabilityPolicy,
        SimpleCapabilityAuthorizer, AGENT_WORKER_PROTOCOL_VERSION,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{collections::BTreeSet, env, fs};

    #[test]
    fn native_harness_execution_returns_normalized_worker_events_after_authorization() {
        let envelope = envelope();
        let authorizer = authorizer();

        let (state, result) =
            exec_or_attach_framework_handler_with_authorizer(&envelope, Some(&authorizer)).unwrap();

        let AgentWorkerManagementResult::HandlerEvents { events } = result else {
            panic!("expected handler events");
        };
        assert_eq!(state.session.adapter_name, "native-harness");
        assert!(state.closed);
        assert!(events.iter().any(|event| event.kind == "session.started"
            && event.framework == "native_harness"
            && event.mode == "managed"));
        assert!(events
            .iter()
            .any(|event| event.kind == "capability.allowed"));
        assert!(events.iter().any(|event| event.kind == "run.completed"));
        assert!(events.iter().any(|event| event.kind == "session.closed"));
        assert_eq!(state.artifacts[0].artifact_id, "native-harness-artifact");
    }

    #[test]
    fn native_harness_artifacts_reuse_recorded_worker_state() {
        let authorizer = authorizer();
        let (state, _) =
            exec_or_attach_framework_handler_with_authorizer(&envelope(), Some(&authorizer))
                .unwrap();

        let result = collect_native_harness_artifacts(&state);

        let AgentWorkerManagementResult::HandlerArtifacts { artifacts, events } = result else {
            panic!("expected handler artifacts");
        };
        assert_eq!(artifacts[0].artifact_id, "native-harness-artifact");
        assert!(events.iter().any(|event| event.kind == "artifact.created"));
    }

    #[test]
    fn native_harness_execution_fails_closed_without_gateway_authorizer() {
        let error =
            exec_or_attach_framework_handler_with_authorizer(&envelope(), None).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("run_failed"));
        assert!(message.contains("gateway authorization client is unavailable"));
    }

    #[test]
    fn codex_process_shim_uses_same_worker_event_contract_after_authorization() {
        let _env_lock = crate::test_support::lock_handler_env();
        let _binary = configured_fake_handler_binary(
            "AGENT_WORKER_CODEX_BIN",
            "codex-smoke",
            "codex binary smoke",
        );
        let mut envelope = envelope();
        envelope.framework_adapter = Some("codex".to_string());
        let authorizer = authorizer();

        let (state, result) =
            exec_or_attach_framework_handler_with_authorizer(&envelope, Some(&authorizer)).unwrap();

        let AgentWorkerManagementResult::HandlerEvents { events } = result else {
            panic!("expected handler events");
        };
        assert_eq!(state.session.adapter_name, "codex");
        assert!(events.iter().any(|event| {
            event.kind == "session.started" && event.framework == "codex" && event.mode == "managed"
        }));
        assert!(events.iter().any(|event| {
            event.kind == "capability.allowed"
                && event
                    .metadata
                    .get("external_target")
                    .is_some_and(|target| target == "codex")
                && event
                    .metadata
                    .get("external_action")
                    .is_some_and(|action| action == "cli")
                && event
                    .metadata
                    .get("env_policy")
                    .is_some_and(|policy| policy == "gateway_injected_only")
        }));
        assert!(events.iter().any(|event| {
            event.kind == "cli.requested"
                && event
                    .metadata
                    .get("real_binary_probe")
                    .is_some_and(|value| value == "true")
                && event
                    .metadata
                    .get("handler_owner")
                    .is_some_and(|value| value == "agent-worker")
                && event
                    .metadata
                    .get("stdout_excerpt")
                    .is_some_and(|value| value.contains("codex binary smoke --version"))
        }));
        assert!(events.iter().any(|event| event.kind == "model.requested"));
        assert!(!events.iter().any(|event| event.kind == "tool.completed"));
        assert!(state
            .artifacts
            .iter()
            .any(|artifact| artifact.artifact_id == "codex-artifact"));
    }

    #[test]
    fn codex_process_shim_can_run_explicit_task_smoke_after_authorization() {
        let _env_lock = crate::test_support::lock_handler_env();
        let _binary = configured_fake_handler_binary(
            "AGENT_WORKER_CODEX_BIN",
            "codex-task-smoke",
            "codex handler args",
        );
        env::set_var("AGENT_WORKER_HANDLER_TASK_SMOKE", "1");
        env::set_var(
            "AGENT_WORKER_HANDLER_TASK_SMOKE_PROMPT",
            "Return exactly smoke-ok",
        );
        let mut envelope = envelope();
        envelope.framework_adapter = Some("codex".to_string());
        let authorizer = authorizer();

        let (_, result) =
            exec_or_attach_framework_handler_with_authorizer(&envelope, Some(&authorizer)).unwrap();

        env::remove_var("AGENT_WORKER_HANDLER_TASK_SMOKE");
        env::remove_var("AGENT_WORKER_HANDLER_TASK_SMOKE_PROMPT");
        let AgentWorkerManagementResult::HandlerEvents { events } = result else {
            panic!("expected handler events");
        };
        let task_event = events
            .iter()
            .find(|event| {
                event.kind == "run.started"
                    && event
                        .metadata
                        .get("real_binary_task_smoke")
                        .is_some_and(|value| value == "true")
            })
            .expect("expected explicit task smoke event");
        assert!(task_event
            .metadata
            .get("handler_owner")
            .is_some_and(|value| value == "agent-worker"));
        assert!(task_event
            .metadata
            .get("task_args")
            .is_some_and(|value| value.contains("<prompt>") && !value.contains("smoke-ok")));
        assert_eq!(
            task_event.metadata.get("prompt_chars").map(String::as_str),
            Some("23")
        );
        assert!(task_event
            .metadata
            .get("stdout_excerpt")
            .is_some_and(|value| value.contains("codex handler args exec")));
        let capability_index = events
            .iter()
            .position(|event| event.kind == "capability.allowed")
            .unwrap();
        let task_index = events
            .iter()
            .position(|event| {
                event
                    .metadata
                    .get("real_binary_task_smoke")
                    .is_some_and(|value| value == "true")
            })
            .unwrap();
        assert!(capability_index < task_index);
    }

    #[test]
    fn explicit_task_smoke_failure_is_returned_as_timeline_evidence() {
        let _env_lock = crate::test_support::lock_handler_env();
        let _binary = configured_fake_handler_binary_with_exit(
            "AGENT_WORKER_CODEX_BIN",
            "codex-task-failure",
            "codex task failed",
            42,
        );
        env::set_var("AGENT_WORKER_HANDLER_TASK_SMOKE", "1");
        env::set_var(
            "AGENT_WORKER_HANDLER_TASK_SMOKE_PROMPT",
            "Return exactly smoke-ok",
        );
        let mut envelope = envelope();
        envelope.framework_adapter = Some("codex".to_string());
        let authorizer = authorizer();

        let (state, result) =
            exec_or_attach_framework_handler_with_authorizer(&envelope, Some(&authorizer)).unwrap();

        env::remove_var("AGENT_WORKER_HANDLER_TASK_SMOKE");
        env::remove_var("AGENT_WORKER_HANDLER_TASK_SMOKE_PROMPT");
        let AgentWorkerManagementResult::HandlerEvents { events } = result else {
            panic!("expected handler events");
        };
        assert!(!state.closed);
        assert!(state.artifacts.is_empty());
        let failed = events
            .iter()
            .find(|event| event.kind == "run.failed")
            .expect("expected task smoke failure evidence");
        assert!(failed
            .metadata
            .get("real_binary_task_smoke")
            .is_some_and(|value| value == "true"));
        assert!(failed
            .metadata
            .get("failed_after_authorization")
            .is_some_and(|value| value == "true"));
        assert!(failed
            .metadata
            .get("failure_reason")
            .is_some_and(|value| value.contains("exited with status Some(42)")));
        assert!(!events.iter().any(|event| event.kind == "model.requested"));
        assert!(!events.iter().any(|event| event.kind == "artifact.created"));
        assert!(!events.iter().any(|event| event.kind == "session.closed"));
    }

    #[test]
    fn approval_required_framework_capability_is_returned_without_handler_execution() {
        let mut envelope = envelope();
        envelope.framework_adapter = Some("codex".to_string());
        let authorizer = crate::external_actions::RuntimeGatewayExternalActionAuthorizer::new(
            SimpleCapabilityAuthorizer::new(CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                approval_required_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            }),
        );

        let (state, result) =
            exec_or_attach_framework_handler_with_authorizer(&envelope, Some(&authorizer)).unwrap();

        let AgentWorkerManagementResult::HandlerEvents { events } = result else {
            panic!("expected handler events");
        };
        assert!(!state.closed);
        assert!(state.artifacts.is_empty());
        assert!(events.iter().any(|event| {
            event.kind == "capability.requested"
                && event
                    .metadata
                    .get("decision")
                    .is_some_and(|decision| decision == "approval_required")
                && event
                    .metadata
                    .get("external_action")
                    .is_some_and(|action| action == "cli")
        }));
        assert!(!events.iter().any(|event| event.kind == "model.requested"));
        assert!(!events.iter().any(|event| event.kind == "artifact.created"));
        assert!(!events.iter().any(|event| event.kind == "session.closed"));
    }

    #[test]
    fn hermes_process_shim_requests_memory_capability_before_execution() {
        let _env_lock = crate::test_support::lock_handler_env();
        let _binary = configured_fake_handler_binary(
            "AGENT_WORKER_HERMES_BIN",
            "hermes-smoke",
            "hermes binary smoke",
        );
        let mut envelope = envelope();
        envelope.framework_adapter = Some("hermes".to_string());
        let authorizer = authorizer();

        let (_, result) =
            exec_or_attach_framework_handler_with_authorizer(&envelope, Some(&authorizer)).unwrap();

        let AgentWorkerManagementResult::HandlerEvents { events } = result else {
            panic!("expected handler events");
        };
        assert!(events.iter().any(|event| {
            event.kind == "capability.allowed"
                && event
                    .metadata
                    .get("external_action")
                    .is_some_and(|action| action == "memory.read")
                && event
                    .metadata
                    .get("memory_access")
                    .is_some_and(|access| access == "read")
                && event
                    .metadata
                    .get("namespace")
                    .is_some_and(|namespace| namespace == "tenant:tenant-1/workspace:workspace-1")
        }));
        assert!(events.iter().any(|event| {
            event.kind == "cli.requested"
                && event
                    .metadata
                    .get("stdout_excerpt")
                    .is_some_and(|value| value.contains("hermes binary smoke --version"))
        }));
    }

    fn configured_fake_handler_binary(
        env_var: &str,
        filename: &str,
        output_prefix: &str,
    ) -> FakeHandlerBinary {
        configured_fake_handler_binary_with_exit(env_var, filename, output_prefix, 0)
    }

    fn configured_fake_handler_binary_with_exit(
        env_var: &str,
        filename: &str,
        output_prefix: &str,
        exit_code: i32,
    ) -> FakeHandlerBinary {
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join(filename);
        fs::write(
            &binary_path,
            format!(
                "#!/bin/sh\nprintf '{output_prefix}'\nprintf ' %s' \"$@\"\nprintf '\\n'\nif [ \"${{1:-}}\" = \"--version\" ]; then exit 0; fi\nexit {exit_code}\n"
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&binary_path).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&binary_path, permissions).unwrap();
        }
        env::set_var(env_var, &binary_path);
        FakeHandlerBinary {
            _temp: temp,
            env_var: env_var.to_string(),
        }
    }

    struct FakeHandlerBinary {
        _temp: tempfile::TempDir,
        env_var: String,
    }

    impl Drop for FakeHandlerBinary {
        fn drop(&mut self) {
            env::remove_var(&self.env_var);
        }
    }

    fn authorizer(
    ) -> crate::external_actions::RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer>
    {
        crate::external_actions::RuntimeGatewayExternalActionAuthorizer::new(
            SimpleCapabilityAuthorizer::new(CapabilityPolicy {
                allowed_actions: BTreeSet::from([
                    CapabilityAction::Tool,
                    CapabilityAction::Cli,
                    CapabilityAction::MemoryRead,
                ]),
                ..CapabilityPolicy::default()
            }),
        )
    }

    fn envelope() -> AgentWorkerManagementEnvelope {
        AgentWorkerManagementEnvelope {
            protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
            action: AgentWorkerManagementAction::ExecOrAttach,
            request_id: "handler-request".to_string(),
            idempotency_key: "handler-idempotency".to_string(),
            issued_at_unix_millis: 900,
            deadline_unix_millis: 2_000,
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            session_id: Some("session-1".to_string()),
            run_id: Some("run-1".to_string()),
            framework_adapter: Some("native-harness".to_string()),
            security: AgentWorkerManagementSecurity {
                key_id: "key-1".to_string(),
                nonce: "nonce-1".to_string(),
                signature: "signature-1".to_string(),
                algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
                transport_security: AgentWorkerTransportSecurity::LocalUnixSocket,
                encrypted: true,
            },
        }
    }
}
