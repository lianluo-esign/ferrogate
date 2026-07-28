// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Process-boundary contract for #519 managed-action project attribution.

use crate::{
    cli::LocalArgs,
    constants::{ADMIN_AUTH, JSON_CONTENT},
    http::{free_addr, http_request_addr},
};
use anyhow::{bail, ensure, Context, Result};
use ferrogate_guardrails::{
    all_content_sources, CheckBinding, DetectorDefinition, DetectorStage, ManagedActionClass,
    ManagedActionSelector, PolicyAction, PolicyAggregation, PolicyExecution, PolicyMode,
    PolicyRevision, PolicyScopeSelector, PolicyStreamingMode,
};
use ferrogate_runtime::{
    ExternalActionAuthorizationRequest, ExternalActionDecision, ExternalActionFramework,
    ExternalActionMode, ExternalActionSession, ExternalActionSpec,
    GatewayExternalActionTransportRequest, GatewayExternalActionTransportResponse,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const RESOLVED_TENANT: &str = "managed-project-resolved-tenant";
const RESOLVED_PROJECT: &str = "managed-project-resolved-project";
const RESOLVED_WORKSPACE: &str = "managed-project-resolved-workspace";
const UNKNOWN_ENFORCE_TENANT: &str = "managed-project-unknown-enforce-tenant";
const UNKNOWN_ENFORCE_PROJECT: &str = "managed-project-unknown-enforce-project";
const UNKNOWN_SHADOW_TENANT: &str = "managed-project-unknown-shadow-tenant";
const UNKNOWN_SHADOW_PROJECT: &str = "managed-project-unknown-shadow-project";
const UNKNOWN_RESPONSE_TENANT: &str = "managed-project-unknown-response-tenant";
const UNKNOWN_RESPONSE_PROJECT: &str = "managed-project-unknown-response-project";
const MISMATCH_TENANT: &str = "managed-project-mismatch-tenant";
const MISMATCH_PROJECT: &str = "managed-project-mismatch-project";
const PERMISSION_ID: &str = "managed-project-permission";
const PERMISSION_KEY: &str = "managed_actions.mcp.local_echo";
const ROLE_ID: &str = "managed-project-role";

/// Issue #519's executable contract. The scenario crosses the Admin API,
/// dynamic guardrail reload, managed-worker Unix authorizer, and agent-run
/// evidence API in one local process. It deliberately uses in-memory storage:
/// the behavior under test is attribution and policy selection, not a storage
/// adapter, so a DSN would only make this deterministic gate less stable.
pub(crate) fn run_managed_action_project(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run cargo build -p ferrogate-cli first",
            args.ferrogate_bin.display()
        );
    }

    let gateway_addr = free_addr()?;
    let scenario_dir = tempfile::tempdir()?;
    fs::set_permissions(scenario_dir.path(), fs::Permissions::from_mode(0o700))?;
    let config_path = scenario_dir.path().join("ferrogate.toml");
    let authorizer_socket = scenario_dir.path().join("managed-actions.sock");
    fs::write(
        &config_path,
        managed_action_project_config(&gateway_addr, &authorizer_socket),
    )?;

    let _gateway = GatewayGuard::start(
        &args.ferrogate_bin,
        &config_path,
        &gateway_addr,
        &authorizer_socket,
    )?;
    provision_hierarchy(&gateway_addr)?;
    provision_target_capability_rbac(&gateway_addr)?;
    provision_policies(&gateway_addr)?;

    assert_resolved_project_binds_policy_and_evidence(&gateway_addr, &authorizer_socket)?;
    assert_unresolved_enforcing_project_fails_closed(&gateway_addr, &authorizer_socket)?;
    assert_unresolved_shadow_project_stays_allowed(&gateway_addr, &authorizer_socket)?;
    assert_unresolved_response_only_project_stays_allowed(&gateway_addr, &authorizer_socket)?;
    assert_cross_tenant_workspace_fails_closed(&gateway_addr, &authorizer_socket)?;

    println!(
        "managed-action-project scenario passed: resolved attribution, enforcing refusal, shadow/response controls, and tenant mismatch"
    );
    Ok(())
}

fn assert_resolved_project_binds_policy_and_evidence(
    gateway_addr: &str,
    socket: &Path,
) -> Result<()> {
    let clean_run = "managed-project-resolved-clean-run";
    let clean = authorize(
        socket,
        RESOLVED_TENANT,
        RESOLVED_WORKSPACE,
        clean_run,
        "routine hello",
    )?;
    assert_allowed(&clean, "resolved clean action")?;
    let clean_timeline = timeline(gateway_addr, clean_run)?;
    let clean_event = event_of_kind(&clean_timeline, "capability.allowed")?;
    assert_event_attribution(
        clean_event,
        RESOLVED_TENANT,
        Some(RESOLVED_PROJECT),
        RESOLVED_WORKSPACE,
    )?;
    ensure!(
        clean_timeline["summary"]["tenant"]["project_id"] == RESOLVED_PROJECT,
        "resolved run summary used the wrong project: {clean_timeline}"
    );

    // This is more than a row-shape assertion: if the runtime regresses to
    // workspace_id-as-project_id, the project-scoped policy is deselected and
    // this flagged action incorrectly becomes allowed.
    let blocked_run = "managed-project-resolved-blocked-run";
    let blocked = authorize(
        socket,
        RESOLVED_TENANT,
        RESOLVED_WORKSPACE,
        blocked_run,
        "contains project-block-token",
    )?;
    assert_rejected(&blocked, "resolved project guardrail block")?;
    ensure!(
        blocked
            .response
            .error
            .as_ref()
            .is_some_and(|error| error.message.contains("guardrail policy")),
        "resolved project policy did not produce the guardrail refusal: {blocked:?}"
    );
    let blocked_timeline = timeline(gateway_addr, blocked_run)?;
    let blocked_event = event_of_kind(&blocked_timeline, "guardrail.blocked")?;
    assert_event_attribution(
        blocked_event,
        RESOLVED_TENANT,
        Some(RESOLVED_PROJECT),
        RESOLVED_WORKSPACE,
    )?;
    assert_decision_evidence(blocked_event, "guardrail:fail:block:enforced")
}

fn assert_unresolved_enforcing_project_fails_closed(
    gateway_addr: &str,
    socket: &Path,
) -> Result<()> {
    let run_id = "managed-project-unknown-enforce-run";
    let response = authorize(
        socket,
        UNKNOWN_ENFORCE_TENANT,
        "managed-project-missing-enforce-workspace",
        run_id,
        "routine hello",
    )?;
    assert_rejected(&response, "unknown workspace with enforcing project policy")?;
    ensure!(
        response
            .response
            .error
            .as_ref()
            .is_some_and(|error| error.message.contains("project-scoped")
                && error.message.contains("unresolved")),
        "unknown project refusal did not explain the attribution failure: {response:?}"
    );
    let timeline = timeline(gateway_addr, run_id)?;
    let event = event_of_kind(&timeline, "guardrail.blocked")?;
    assert_event_attribution(
        event,
        UNKNOWN_ENFORCE_TENANT,
        None,
        "managed-project-missing-enforce-workspace",
    )?;
    assert_decision_evidence(event, "guardrail:error:block:enforced")
}

fn assert_unresolved_shadow_project_stays_allowed(gateway_addr: &str, socket: &Path) -> Result<()> {
    let run_id = "managed-project-unknown-shadow-run";
    let response = authorize(
        socket,
        UNKNOWN_SHADOW_TENANT,
        "managed-project-missing-shadow-workspace",
        run_id,
        "contains shadow-block-token",
    )?;
    assert_allowed(&response, "unknown workspace with shadow project policy")?;
    let timeline = timeline(gateway_addr, run_id)?;
    let event = event_of_kind(&timeline, "capability.allowed")?;
    assert_event_attribution(
        event,
        UNKNOWN_SHADOW_TENANT,
        None,
        "managed-project-missing-shadow-workspace",
    )
}

fn assert_unresolved_response_only_project_stays_allowed(
    gateway_addr: &str,
    socket: &Path,
) -> Result<()> {
    let run_id = "managed-project-unknown-response-run";
    let response = authorize(
        socket,
        UNKNOWN_RESPONSE_TENANT,
        "managed-project-missing-response-workspace",
        run_id,
        "contains response-block-token",
    )?;
    assert_allowed(
        &response,
        "unknown workspace with response-only project policy",
    )?;
    let timeline = timeline(gateway_addr, run_id)?;
    let event = event_of_kind(&timeline, "capability.allowed")?;
    assert_event_attribution(
        event,
        UNKNOWN_RESPONSE_TENANT,
        None,
        "managed-project-missing-response-workspace",
    )
}

fn assert_cross_tenant_workspace_fails_closed(gateway_addr: &str, socket: &Path) -> Result<()> {
    let run_id = "managed-project-tenant-mismatch-run";
    let response = authorize(
        socket,
        MISMATCH_TENANT,
        RESOLVED_WORKSPACE,
        run_id,
        "routine hello",
    )?;
    assert_rejected(&response, "workspace owned by another tenant")?;
    let timeline = timeline(gateway_addr, run_id)?;
    let event = event_of_kind(&timeline, "guardrail.blocked")?;
    assert_event_attribution(event, MISMATCH_TENANT, None, RESOLVED_WORKSPACE)?;
    assert_decision_evidence(event, "guardrail:error:block:enforced")
}

fn assert_allowed(response: &GatewayExternalActionTransportResponse, case: &str) -> Result<()> {
    ensure!(
        response.response.accepted
            && response.response.decision == Some(ExternalActionDecision::Allowed)
            && response.response.error.is_none(),
        "{case} should be allowed: {response:?}"
    );
    Ok(())
}

fn assert_rejected(response: &GatewayExternalActionTransportResponse, case: &str) -> Result<()> {
    ensure!(
        !response.response.accepted
            && response.response.decision.is_none()
            && response.response.event.is_none()
            && response
                .response
                .error
                .as_ref()
                .is_some_and(|error| error.code == "capability_denied"),
        "{case} should fail closed with capability_denied: {response:?}"
    );
    Ok(())
}

fn assert_event_attribution(
    event: &Value,
    tenant_id: &str,
    project_id: Option<&str>,
    workspace_id: &str,
) -> Result<()> {
    ensure!(
        event["tenant"]["organization_id"] == tenant_id,
        "event used the wrong tenant: {event}"
    );
    match project_id {
        Some(project_id) => ensure!(
            event["tenant"]["project_id"] == project_id,
            "event used the wrong project: {event}"
        ),
        None => ensure!(
            event["tenant"]["project_id"].is_null(),
            "unresolved event fabricated a project: {event}"
        ),
    }
    ensure!(
        event["tenant"]["workspace_id"] == workspace_id,
        "event used the wrong workspace: {event}"
    );
    Ok(())
}

fn assert_decision_evidence(event: &Value, reason: &str) -> Result<()> {
    ensure!(event["decision"] == "deny", "event was not a deny: {event}");
    ensure!(
        event["decision_reason"] == reason,
        "event reason was not {reason}: {event}"
    );
    ensure!(
        event["output_disposition"] == "withheld",
        "event did not withhold output: {event}"
    );
    Ok(())
}

fn event_of_kind<'a>(timeline: &'a Value, kind: &str) -> Result<&'a Value> {
    timeline["agent_events"]
        .as_array()
        .and_then(|events| events.iter().find(|event| event["kind"] == kind))
        .with_context(|| format!("timeline omitted {kind} evidence: {timeline}"))
}

fn timeline(gateway_addr: &str, run_id: &str) -> Result<Value> {
    admin_json(
        gateway_addr,
        "GET",
        &format!("/admin/v1/agent-runs/{run_id}"),
        None,
        200,
    )
}

fn authorize(
    socket: &Path,
    tenant_id: &str,
    workspace_id: &str,
    run_id: &str,
    message: &str,
) -> Result<GatewayExternalActionTransportResponse> {
    let authorization = ExternalActionAuthorizationRequest {
        session: ExternalActionSession {
            session_id: format!("session-{run_id}"),
            run_id: run_id.to_string(),
            tenant_id: tenant_id.to_string(),
            workspace_id: workspace_id.to_string(),
            worker_id: format!("worker-{run_id}"),
            isolation_backend: "firecracker".to_string(),
            adapter_name: "native-harness".to_string(),
            adapter_version: "test".to_string(),
            framework: ExternalActionFramework::NativeHarness,
            mode: ExternalActionMode::Managed,
        },
        action: ExternalActionSpec::McpTool {
            server_name: "local-smoke".to_string(),
            tool_name: "echo".to_string(),
            arguments_policy: "exact_arguments".to_string(),
            arguments: json!({"message": message}),
        },
        high_risk: false,
    };
    let request = GatewayExternalActionTransportRequest {
        request_id: authorization.stable_request_id(),
        authorization,
    };
    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "failed to connect managed-action authorizer {}",
            socket.display()
        )
    })?;
    let io_timeout = Some(Duration::from_secs(5));
    stream
        .set_read_timeout(io_timeout)
        .with_context(|| format!("failed to set authorizer read timeout for run {run_id}"))?;
    stream
        .set_write_timeout(io_timeout)
        .with_context(|| format!("failed to set authorizer write timeout for run {run_id}"))?;
    stream
        .write_all(serde_json::to_string(&request)?.as_bytes())
        .with_context(|| format!("failed to write authorizer request for run {run_id}"))?;
    stream
        .shutdown(Shutdown::Write)
        .with_context(|| format!("failed to finish authorizer request for run {run_id}"))?;
    let mut body = String::new();
    stream
        .read_to_string(&mut body)
        .with_context(|| format!("timed out reading authorizer response for run {run_id}"))?;
    let response: GatewayExternalActionTransportResponse = serde_json::from_str(&body)
        .with_context(|| format!("invalid managed-action response: {body}"))?;
    ensure!(
        response.request_id == request.request_id,
        "managed-action response request id mismatch: {response:?}"
    );
    Ok(response)
}

fn provision_hierarchy(gateway_addr: &str) -> Result<()> {
    for tenant_id in [
        RESOLVED_TENANT,
        UNKNOWN_ENFORCE_TENANT,
        UNKNOWN_SHADOW_TENANT,
        UNKNOWN_RESPONSE_TENANT,
        MISMATCH_TENANT,
    ] {
        let body = json!({"id": tenant_id, "name": tenant_id, "slug": tenant_id});
        let created = admin_json(
            gateway_addr,
            "POST",
            "/admin/v1/tenant-accounts",
            Some(&body),
            201,
        )?;
        ensure!(
            created["tenant"]["id"] == tenant_id,
            "wrong tenant: {created}"
        );
    }
    for (project_id, tenant_id) in [
        (RESOLVED_PROJECT, RESOLVED_TENANT),
        (UNKNOWN_ENFORCE_PROJECT, UNKNOWN_ENFORCE_TENANT),
        (UNKNOWN_SHADOW_PROJECT, UNKNOWN_SHADOW_TENANT),
        (UNKNOWN_RESPONSE_PROJECT, UNKNOWN_RESPONSE_TENANT),
        (MISMATCH_PROJECT, MISMATCH_TENANT),
    ] {
        let body = json!({
            "id": project_id,
            "tenant_id": tenant_id,
            "name": project_id,
            "slug": project_id,
        });
        let created = admin_json(gateway_addr, "POST", "/admin/v1/projects", Some(&body), 201)?;
        ensure!(
            created["project"]["tenant_id"] == tenant_id,
            "wrong project hierarchy: {created}"
        );
    }
    let workspace = json!({
        "id": RESOLVED_WORKSPACE,
        "project_id": RESOLVED_PROJECT,
        "name": RESOLVED_WORKSPACE,
        "slug": RESOLVED_WORKSPACE,
    });
    let created = admin_json(
        gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        Some(&workspace),
        201,
    )?;
    ensure!(
        created["workspace"]["project_id"] == RESOLVED_PROJECT,
        "wrong workspace hierarchy: {created}"
    );
    Ok(())
}

fn provision_target_capability_rbac(gateway_addr: &str) -> Result<()> {
    let permission = json!({"id": PERMISSION_ID, "key": PERMISSION_KEY, "name": PERMISSION_KEY});
    let created = admin_json(
        gateway_addr,
        "POST",
        "/admin/v1/permissions",
        Some(&permission),
        200,
    )?;
    ensure!(
        created["permission"]["key"] == PERMISSION_KEY,
        "wrong permission: {created}"
    );

    let role = json!({
        "id": ROLE_ID,
        "name": "Managed action project E2E role",
        "slug": "managed-action-project-e2e-role",
        "permission_keys": [PERMISSION_KEY],
    });
    let created = admin_json(gateway_addr, "POST", "/admin/v1/roles", Some(&role), 200)?;
    ensure!(created["role"]["id"] == ROLE_ID, "wrong role: {created}");

    for tenant_id in [
        RESOLVED_TENANT,
        UNKNOWN_ENFORCE_TENANT,
        UNKNOWN_SHADOW_TENANT,
        UNKNOWN_RESPONSE_TENANT,
        MISMATCH_TENANT,
    ] {
        let body = json!({"role_id": ROLE_ID});
        let binding = admin_json(
            gateway_addr,
            "POST",
            &format!("/admin/v1/tenant-roles/{tenant_id}"),
            Some(&body),
            200,
        )?;
        ensure!(
            binding["tenant_id"] == tenant_id,
            "wrong tenant-role binding: {binding}"
        );
    }
    Ok(())
}

fn provision_policies(gateway_addr: &str) -> Result<()> {
    for policy in [
        project_policy(
            "managed-project-resolved-policy",
            RESOLVED_TENANT,
            RESOLVED_PROJECT,
            PolicyMode::Enforce,
            DetectorStage::Request,
            "project-block-token",
        ),
        project_policy(
            "managed-project-unknown-enforce-policy",
            UNKNOWN_ENFORCE_TENANT,
            UNKNOWN_ENFORCE_PROJECT,
            PolicyMode::Enforce,
            DetectorStage::Request,
            "enforce-block-token",
        ),
        project_policy(
            "managed-project-unknown-shadow-policy",
            UNKNOWN_SHADOW_TENANT,
            UNKNOWN_SHADOW_PROJECT,
            PolicyMode::Shadow,
            DetectorStage::Request,
            "shadow-block-token",
        ),
        project_policy(
            "managed-project-unknown-response-policy",
            UNKNOWN_RESPONSE_TENANT,
            UNKNOWN_RESPONSE_PROJECT,
            PolicyMode::Enforce,
            DetectorStage::Response,
            "response-block-token",
        ),
        project_policy(
            "managed-project-mismatch-policy",
            MISMATCH_TENANT,
            MISMATCH_PROJECT,
            PolicyMode::Enforce,
            DetectorStage::Request,
            "mismatch-block-token",
        ),
    ] {
        let policy_id = policy.policy_id.clone();
        let body = serde_json::to_value(policy)?;
        let created = admin_json(
            gateway_addr,
            "POST",
            "/admin/v1/guardrail-policies",
            Some(&body),
            201,
        )?;
        let revision = created["policy"]["revision"]
            .as_u64()
            .with_context(|| format!("policy create omitted revision: {created}"))?;
        let activate = json!({"revision": revision});
        let activated = admin_json(
            gateway_addr,
            "POST",
            &format!("/admin/v1/guardrail-policies/{policy_id}/activate"),
            Some(&activate),
            200,
        )?;
        ensure!(
            activated["active_revision"] == revision,
            "policy did not activate: {activated}"
        );
    }
    Ok(())
}

fn project_policy(
    policy_id: &str,
    tenant_id: &str,
    project_id: &str,
    mode: PolicyMode,
    stage: DetectorStage,
    keyword: &str,
) -> PolicyRevision {
    PolicyRevision {
        policy_id: policy_id.to_string(),
        revision: 1,
        name: format!("{policy_id} E2E"),
        description: None,
        enforced: true,
        scope: PolicyScopeSelector {
            organization_ids: vec![tenant_id.to_string()],
            project_ids: vec![project_id.to_string()],
            managed_action: Some(ManagedActionSelector {
                classes: vec![ManagedActionClass::Mcp],
                targets: vec!["mcp:local-smoke:echo".to_string()],
            }),
            ..PolicyScopeSelector::default()
        },
        checks: vec![CheckBinding {
            id: "keyword".to_string(),
            enabled: true,
            stage,
            sources: all_content_sources(),
            detector: DetectorDefinition::local(vec![keyword.to_string()], Vec::new(), None),
            fallback_detector: None,
        }],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![PolicyAction::block(
            "managed_project_blocked",
            "managed action blocked by project policy",
        )],
        on_error: vec![PolicyAction::block(
            "managed_project_unavailable",
            "managed action project policy unavailable",
        )],
        deadline_ms: 2_000,
        created_at_unix: 1,
        created_by: "test-admin".to_string(),
    }
}

fn admin_json(
    gateway_addr: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    expected_status: u16,
) -> Result<Value> {
    let encoded = body.map(Value::to_string).unwrap_or_default();
    let headers = if body.is_some() {
        &[ADMIN_AUTH, JSON_CONTENT][..]
    } else {
        &[ADMIN_AUTH][..]
    };
    let response = http_request_addr(gateway_addr, method, path, headers, &encoded)?;
    ensure!(
        response.status == expected_status,
        "{method} {path} expected {expected_status}, got {}: {}",
        response.status,
        response.raw
    );
    serde_json::from_str(&response.body)
        .with_context(|| format!("{method} {path} returned invalid JSON: {}", response.body))
}

fn managed_action_project_config(gateway_addr: &str, authorizer_socket: &Path) -> String {
    format!(
        r#"listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Managed action project E2E admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[agent_runtime]
enabled = true
provider = "managed_worker"

[agent_runtime.managed_worker]
external_action_authorizer_socket = {:?}
external_action_authorizer_max_requests = 16
policy_revision = "managed-project-e2e-1"
class_only_policy_mode = "deny"

[[agent_runtime.managed_worker.target_grants]]
selector_id = "local-echo"
permission_key = "{PERMISSION_KEY}"
action = "mcp_tool"
[agent_runtime.managed_worker.target_grants.selector]
kind = "mcp"
server = "local-smoke"
tool = "echo"
risk = "read"
allow_extra_arguments = false
[agent_runtime.managed_worker.target_grants.selector.argument_schema]
kind = "object"
[agent_runtime.managed_worker.target_grants.selector.argument_schema.fields.message]
kind = "string"
"#,
        authorizer_socket.to_string_lossy()
    )
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(
        binary: &Path,
        config: &Path,
        gateway_addr: &str,
        authorizer_socket: &Path,
    ) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr, authorizer_socket)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str, socket: &Path) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before managed-action-project readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 && socket.exists() => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for managed-action-project gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
