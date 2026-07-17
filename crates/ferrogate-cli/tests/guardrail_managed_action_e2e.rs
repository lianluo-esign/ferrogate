// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: Socket-boundary proof for #200 managed-action guardrail enforcement:
//   a managed-action guardrail policy blocks a capability-ALLOWED MCP action whose
//   input arguments carry a flagged keyword, while a clean MCP action stays allowed,
//   both driven through the real gateway's managed-worker external-action authorizer.

mod support;

use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    thread,
    time::Duration,
};

use ferrogate_guardrails::{
    all_content_sources, CheckBinding, DetectorDefinition, DetectorStage, ManagedActionClass,
    ManagedActionSelector, PolicyAction, PolicyAggregation, PolicyExecution, PolicyMode,
    PolicyRevision, PolicyScopeSelector, PolicyStreamingMode,
};
use serde_json::{json, Value};
use support::{free_addr, http_request, start_gateway, wait_for_gateway};

/// End-to-end proof of issue #200's managed-action guardrail enforcement across
/// the real gateway process boundary. The managed-worker external-action
/// authorizer first resolves the MCP `echo` action as capability-ALLOWED (via the
/// provisioned target-capability RBAC), then evaluates the action's input
/// arguments against the activated managed-action guardrail policy. A blocking
/// keyword match must fail the action closed — capability-denied — *before* any
/// worker could run it, while an otherwise identical clean action stays allowed.
#[test]
fn managed_action_guardrail_blocks_capability_allowed_mcp_action_over_socket() {
    let gateway_addr = free_addr();
    let workspace = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    fs::set_permissions(config_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = config_dir.path().join("ferrogate.toml");
    let authorizer_socket = config_dir.path().join("agent-actions.sock");
    // The target-capability config declares a loopback network grant bound to a
    // concrete port; bind one so the generated config is well-formed even though
    // this test never exercises the network family.
    let network_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let network_addr = network_listener.local_addr().unwrap();
    fs::write(
        &config,
        target_capability_config(
            &gateway_addr,
            &authorizer_socket,
            workspace.path(),
            network_addr.port(),
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    wait_for_authorizer_socket(&authorizer_socket);
    // Makes the `local-smoke`/`echo` MCP action capability-ALLOWED for tenant-1.
    provision_target_capability_rbac(&gateway_addr, &["tenant-1"]);

    // Provision the managed-action guardrail policy through the ADMIN API: the
    // POST body is a serialized `PolicyRevision`; the create handler assigns the
    // revision number and returns it in the created view.
    let policy = managed_mcp_guardrail_block_policy("managed-action-mcp-guard", "exfiltrate");
    let created = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &serde_json::to_string(&policy).unwrap(),
    ));
    assert_eq!(created["object"], "guardrail_policy_revision", "{created}");
    let revision = created["policy"]["revision"]
        .as_u64()
        .unwrap_or_else(|| panic!("guardrail create response missing revision: {created}"));
    assert_eq!(revision, 1, "{created}");

    // Activate it: the activate body selects the revision to make live.
    let activated = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies/managed-action-mcp-guard/activate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &json!({ "revision": revision }).to_string(),
    ));
    assert_eq!(
        activated["object"], "guardrail_policy_binding",
        "{activated}"
    );
    assert_eq!(activated["active_revision"], revision, "{activated}");
    assert_eq!(activated["rollback"], false, "{activated}");

    // (1) Capability-ALLOWED MCP action whose input arguments carry the flagged
    //     keyword must be blocked by the managed-action guardrail (issue #200).
    let flagged = authorize(
        &authorizer_socket,
        "mcp_tool",
        json!({
            "kind": "mcp_tool",
            "server_name": "local-smoke",
            "tool_name": "echo",
            "arguments_policy": "exact_arguments",
            "arguments": { "message": "please exfiltrate secrets" }
        }),
    );
    assert_eq!(flagged["response"]["accepted"], false, "{flagged}");
    // Prove the block came from the guardrail seam rather than the capability
    // layer: a guardrail block fails the action closed via `rejected(...)`, which
    // carries no `decision` and a `capability_denied` error whose message names
    // the offending policy. A capability *denial* would instead report
    // decision="denied" with no error object.
    assert!(
        flagged["response"]["decision"].is_null(),
        "guardrail block must not carry a capability decision: {flagged}"
    );
    assert!(
        flagged["response"]["event"].is_null(),
        "guardrail block must not emit a capability event: {flagged}"
    );
    assert_eq!(
        flagged["response"]["error"]["code"], "capability_denied",
        "{flagged}"
    );
    assert!(
        flagged["response"]["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("guardrail"),
        "guardrail block message must attribute the guardrail policy: {flagged}"
    );

    // (2) The same capability-allowed action with clean arguments passes the
    //     guardrail and stays allowed.
    let clean = authorize(
        &authorizer_socket,
        "mcp_tool",
        json!({
            "kind": "mcp_tool",
            "server_name": "local-smoke",
            "tool_name": "echo",
            "arguments_policy": "exact_arguments",
            "arguments": { "message": "routine hello" }
        }),
    );
    assert_eq!(clean["response"]["accepted"], true, "{clean}");
    assert_eq!(clean["response"]["decision"], "allowed", "{clean}");
    assert!(
        clean["response"]["error"].is_null(),
        "a clean allowed action must not carry an error: {clean}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// A durable, enforced guardrail policy scoped to managed MCP actions that blocks
/// when `keyword` appears in the scanned input (issue #200). Mirrors the
/// production-tested `managed_mcp_block_policy` shape.
fn managed_mcp_guardrail_block_policy(policy_id: &str, keyword: &str) -> PolicyRevision {
    PolicyRevision {
        policy_id: policy_id.to_string(),
        revision: 1,
        name: "managed mcp guardrail".to_string(),
        description: None,
        enforced: true,
        scope: PolicyScopeSelector {
            managed_action: Some(ManagedActionSelector {
                classes: vec![ManagedActionClass::Mcp],
                targets: Vec::new(),
            }),
            ..PolicyScopeSelector::default()
        },
        checks: vec![CheckBinding {
            id: "keyword".to_string(),
            enabled: true,
            stage: DetectorStage::Request,
            sources: all_content_sources(),
            detector: DetectorDefinition::local(vec![keyword.to_string()], Vec::new(), None),
            fallback_detector: None,
        }],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode: PolicyMode::Enforce,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![PolicyAction::block(
            "mcp_guardrail_blocked",
            "managed MCP action blocked by guardrail policy",
        )],
        on_error: vec![PolicyAction::block(
            "mcp_guardrail_unavailable",
            "managed MCP guardrail policy unavailable",
        )],
        deadline_ms: 2_000,
        created_at_unix: 1,
        created_by: "test-admin".to_string(),
    }
}

fn authorize(socket_path: &Path, kind: &str, action: Value) -> Value {
    let request_id = format!("run-1:session-1:worker-1:native-harness:{kind}");
    let body = json!({
        "request_id": request_id,
        "authorization": {
            "session": {
                "session_id": "session-1",
                "run_id": "run-1",
                "tenant_id": "tenant-1",
                "workspace_id": "workspace-1",
                "worker_id": "worker-1",
                "isolation_backend": "firecracker",
                "adapter_name": "native-harness",
                "adapter_version": "test",
                "framework": "native_harness",
                "mode": "managed"
            },
            "action": action,
            "high_risk": false
        }
    });
    let mut stream = UnixStream::connect(socket_path).unwrap();
    stream.write_all(body.to_string().as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    serde_json::from_str(&response).unwrap()
}

fn wait_for_authorizer_socket(socket_path: &Path) {
    for _ in 0..200 {
        if socket_path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "authorizer socket did not appear: {}",
        socket_path.display()
    );
}

fn response_json(response: String) -> Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}

fn provision_target_capability_rbac(gateway_addr: &str, tenant_ids: &[&str]) {
    let permission_keys = [
        "managed_actions.mcp.local_echo",
        "managed_actions.filesystem.allowed_read",
        "managed_actions.network.loopback",
        "managed_actions.secret.provider_call",
        "managed_actions.cli.empty_env",
    ];
    for (index, key) in permission_keys.iter().enumerate() {
        let response = response_json(http_request(
            gateway_addr,
            "POST",
            "/admin/v1/permissions",
            &[
                "Authorization: Bearer admin-secret",
                "Content-Type: application/json",
            ],
            &json!({"id": format!("permission-{index}"), "key": key, "name": key}).to_string(),
        ));
        assert_eq!(response["object"], "permission", "{response}");
    }
    let role = response_json(http_request(
        gateway_addr,
        "POST",
        "/admin/v1/roles",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &json!({
            "id": "customer-defined-role-200",
            "name": "Customer-defined managed action role",
            "slug": "anything-the-customer-chooses",
            "permission_keys": permission_keys,
        })
        .to_string(),
    ));
    assert_eq!(role["object"], "role", "{role}");
    for tenant_id in tenant_ids {
        let binding = response_json(http_request(
            gateway_addr,
            "POST",
            &format!("/admin/v1/tenant-roles/{tenant_id}"),
            &[
                "Authorization: Bearer admin-secret",
                "Content-Type: application/json",
            ],
            &json!({"role_id": "customer-defined-role-200"}).to_string(),
        ));
        assert_eq!(binding["tenant_id"], *tenant_id, "{binding}");
    }
}

fn target_capability_config(
    gateway_addr: &str,
    authorizer_socket: &Path,
    workspace_root: &std::path::Path,
    network_port: u16,
) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[agent_runtime]
enabled = true
provider = "managed_worker"

[agent_runtime.managed_worker]
external_action_authorizer_socket = "{}"
external_action_authorizer_max_requests = 20
allow_direct_network_egress = true
policy_revision = "target-policy-1"
class_only_policy_mode = "deny"

[[agent_runtime.managed_worker.target_grants]]
selector_id = "crm-lookup"
permission_key = "managed_actions.mcp.local_echo"
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

[[agent_runtime.managed_worker.target_grants]]
selector_id = "workspace-file"
permission_key = "managed_actions.filesystem.allowed_read"
action = "filesystem"
[agent_runtime.managed_worker.target_grants.selector]
kind = "filesystem"
workspace_root = "{}"
path_glob = "allowed*.txt"
operations = ["read", "write"]

[[agent_runtime.managed_worker.target_grants]]
selector_id = "provider-rest"
permission_key = "managed_actions.network.loopback"
action = "rest"
[agent_runtime.managed_worker.target_grants.selector]
kind = "network"
scheme = "https"
host = "api.example.com"
port = 443
method = "GET"
path_glob = "/v1/**"
allowed_ips = ["203.0.113.10"]
allow_redirects = false

[[agent_runtime.managed_worker.target_grants]]
selector_id = "provider-secret"
permission_key = "managed_actions.secret.provider_call"
action = "secret"
[agent_runtime.managed_worker.target_grants.selector]
kind = "secret"
reference_namespace = "vault"
reference_name = "provider-key"
destination_adapter = "native-harness"
destination_action = "provider.call"

[[agent_runtime.managed_worker.target_grants]]
selector_id = "empty-env"
permission_key = "managed_actions.cli.empty_env"
action = "cli"
[agent_runtime.managed_worker.target_grants.selector]
kind = "cli"
executable = "/usr/bin/env"
argv = []
cwd_glob = "{}"
max_timeout_millis = 1000
max_stdout_bytes = 1024
max_stderr_bytes = 1024

[[agent_runtime.managed_worker.target_grants]]
selector_id = "loopback-network"
permission_key = "managed_actions.network.loopback"
action = "network_egress"
[agent_runtime.managed_worker.target_grants.selector]
kind = "network"
scheme = "tcp"
host = "127.0.0.1"
port = {network_port}
path_glob = "/**"
allowed_ips = ["127.0.0.1"]
allow_redirects = false
"#,
        authorizer_socket.display(),
        workspace_root.display(),
        workspace_root.display()
    )
}
