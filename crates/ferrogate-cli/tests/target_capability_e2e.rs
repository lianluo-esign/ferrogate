// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Local process-boundary proof for target-level managed action capabilities (#204).

mod support;

use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

use serde_json::{json, Value};
use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[test]
fn managed_worker_target_capability_openapi_matches_runtime_serde_shape() {
    let contract: Value =
        serde_json::from_str(include_str!("../../../docs/openapi/admin-api.openapi.json")).unwrap();
    let schemas = &contract["components"]["schemas"];
    let grant = &schemas["AdminManagedWorkerTargetGrant"];
    let grant_required = grant["required"].as_array().unwrap();
    assert!(grant_required.contains(&json!("permission_key")));
    assert_eq!(grant["properties"]["permission_key"]["type"], "string");

    let selectors = schemas["CapabilityTargetSelector"]["oneOf"]
        .as_array()
        .unwrap();
    let mcp = selectors
        .iter()
        .find(|schema| schema["properties"]["kind"]["const"] == "mcp")
        .unwrap();
    assert!(mcp["required"]
        .as_array()
        .unwrap()
        .contains(&json!("argument_schema")));
    assert_eq!(
        mcp["properties"]["argument_schema"]["$ref"],
        "#/components/schemas/JsonShape"
    );
    assert!(schemas["JsonShape"]["oneOf"].is_array());

    let cli = selectors
        .iter()
        .find(|schema| schema["properties"]["kind"]["const"] == "cli")
        .unwrap();
    assert_eq!(cli["properties"]["environment"]["type"], "object");
    assert_eq!(cli["properties"]["environment"]["maxProperties"], 0);

    let network = selectors
        .iter()
        .find(|schema| schema["properties"]["kind"]["const"] == "network")
        .unwrap();
    assert_eq!(
        network["properties"]["method"]["type"],
        json!(["string", "null"])
    );
}

#[test]
fn typed_target_capabilities_cover_all_managed_action_families() {
    let gateway_addr = free_addr();
    let workspace = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("allowed.txt"), "allowed").unwrap();
    fs::write(workspace.path().join("sibling.txt"), "sibling").unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    fs::set_permissions(config_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = config_dir.path().join("ferrogate.toml");
    let authorizer_socket = config_dir.path().join("agent-actions.sock");
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
    assert_eq!(
        fs::metadata(&authorizer_socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    provision_target_capability_rbac(&gateway_addr, &["tenant-1", "smoke-tenant"]);

    let admin = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/managed-workers",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(
        admin["data"][0]["capability_policy"]["revision"],
        "target-policy-1"
    );
    assert_eq!(
        admin["data"][0]["capability_policy"]["class_only_policy_mode"],
        "deny"
    );
    assert_eq!(
        admin["data"][0]["capability_policy"]["target_level_enforced"],
        true
    );
    assert_eq!(
        admin["data"][0]["capability_policy"]["action_fingerprint_contract"],
        "canonical_target_sha256"
    );
    assert_eq!(
        admin["data"][0]["capability_policy"]["exact_action_approval_enforced"],
        false
    );
    assert_eq!(
        admin["data"][0]["capability_policy"]["target_grants"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    let target_grants = admin["data"][0]["capability_policy"]["target_grants"]
        .as_array()
        .unwrap();
    let mcp_grant = target_grants
        .iter()
        .find(|grant| grant["selector_id"] == "crm-lookup")
        .unwrap();
    assert_eq!(
        mcp_grant["permission_key"],
        "managed_actions.mcp.local_echo"
    );
    assert_eq!(mcp_grant["selector"]["argument_schema"]["kind"], "object");
    let cli_grant = target_grants
        .iter()
        .find(|grant| grant["selector_id"] == "empty-env")
        .unwrap();
    assert_eq!(cli_grant["selector"]["environment"], json!({}));
    assert!(!admin.to_string().contains("resolved-secret-value"));

    let cases = [
        (
            "mcp_tool",
            json!({"kind":"mcp_tool","server_name":"local-smoke","tool_name":"echo","arguments_policy":"exact_arguments","arguments":{"message":"ferrogate governed mcp smoke"}}),
            json!({"kind":"mcp_tool","server_name":"local-smoke","tool_name":"delete","arguments_policy":"exact_arguments","arguments":{"message":"ferrogate governed mcp smoke"}}),
        ),
        (
            "filesystem",
            json!({"kind":"filesystem","path":"allowed.txt","access":"read","workspace_relative":true}),
            json!({"kind":"filesystem","path":"sibling.txt","access":"read","workspace_relative":true}),
        ),
        (
            "rest",
            json!({"kind":"rest","method":"GET","url":"https://api.example.com/v1/data","headers_policy":"deny_credentials","body_policy":"empty","timeout_millis":1000,"retry_limit":0,"resolved_ips":["203.0.113.10"],"redirect_chain":[]}),
            json!({"kind":"rest","method":"POST","url":"https://api.example.com/v1/data","headers_policy":"deny_credentials","body_policy":"empty","timeout_millis":1000,"retry_limit":0,"resolved_ips":["203.0.113.10"],"redirect_chain":[]}),
        ),
        (
            "secret",
            json!({"kind":"secret","secret_id":"vault/provider-key","purpose":"provider.call"}),
            json!({"kind":"secret","secret_id":"vault/provider-key","purpose":"shell.env"}),
        ),
        (
            "cli",
            json!({"kind":"cli","command":"/usr/bin/env","args":[],"working_dir":workspace.path().display().to_string(),"env_policy":"empty","timeout_millis":1000,"stdout_limit_bytes":1024,"stderr_limit_bytes":1024,"artifact_capture":false}),
            json!({"kind":"cli","command":"/usr/bin/env","args":["PATH=/tmp"],"working_dir":workspace.path().display().to_string(),"env_policy":"empty","timeout_millis":1000,"stdout_limit_bytes":1024,"stderr_limit_bytes":1024,"artifact_capture":false}),
        ),
        (
            "network_egress",
            json!({"kind":"network_egress","host":"127.0.0.1","port":network_addr.port(),"protocol":"tcp","resolved_ips":["127.0.0.1"]}),
            json!({"kind":"network_egress","host":"127.0.0.1","port":network_addr.port().saturating_add(1),"protocol":"tcp","resolved_ips":["127.0.0.1"]}),
        ),
    ];

    for (kind, allowed, denied) in cases {
        let allowed = authorize(&authorizer_socket, kind, allowed);
        assert_eq!(allowed["response"]["accepted"], true, "{kind}: {allowed}");
        assert_eq!(allowed["response"]["decision"], "allowed");
        let metadata = &allowed["response"]["event"]["metadata"];
        assert_eq!(metadata["policy_revision"], "target-policy-1");
        assert_eq!(
            metadata["subject"],
            "tenant:tenant-1/workspace:workspace-1/worker:worker-1"
        );
        assert_ne!(metadata["selector"], "none");
        assert_eq!(metadata["decision"], "allowed");
        let canonical_kind = match kind {
            "mcp_tool" => "mcp",
            "rest" | "network_egress" => "network",
            other => other,
        };
        assert!(
            metadata["canonical_target"]
                .as_str()
                .unwrap()
                .contains(canonical_kind),
            "{kind}: {allowed}"
        );
        assert!(metadata["action_fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(
            metadata["request_id"],
            format!("run-1:session-1:worker-1:native-harness:{kind}")
        );
        assert_eq!(metadata["trace_id"], "run-1");

        let denied = authorize(&authorizer_socket, kind, denied);
        assert_eq!(denied["response"]["accepted"], false, "{kind}: {denied}");
        assert_eq!(denied["response"]["decision"], "denied");
    }

    let network_capture = thread::spawn(move || {
        let (mut stream, _) = network_listener.accept().unwrap();
        let mut payload = String::new();
        stream.read_to_string(&mut payload).unwrap();
        payload
    });
    let worker = run_target_execution_worker(
        &authorizer_socket,
        gateway.id(),
        workspace.path(),
        &network_addr,
    );
    assert!(
        worker.status.success(),
        "agent-worker failed: {}",
        String::from_utf8_lossy(&worker.stderr)
    );
    let execution: Value = serde_json::from_slice(&worker.stdout).unwrap();
    for family in [
        "mcp",
        "filesystem",
        "filesystem_write",
        "network",
        "secret",
        "cli",
    ] {
        assert_eq!(
            execution[family]["executed_after_authorization"], true,
            "{family}: {execution}"
        );
    }
    assert_eq!(execution["filesystem"]["content_excerpt"], "allowed");
    assert_eq!(
        fs::read(workspace.path().join("allowed-created.txt")).unwrap(),
        b""
    );
    assert_eq!(
        execution["mcp"]["output_excerpt"],
        "ferrogate governed mcp smoke"
    );
    assert_eq!(execution["cli"]["stdout_excerpt"], "");
    assert!(!execution.to_string().contains("resolved-secret-value"));
    assert_eq!(
        network_capture.join().unwrap(),
        "ferrogate governed network smoke\n"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn admin_reports_target_enforcement_false_during_legacy_class_wide_migration() {
    let gateway_addr = free_addr();
    let config_dir = tempfile::tempdir().unwrap();
    let config = config_dir.path().join("ferrogate.toml");
    fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]

[agent_runtime]
enabled = true
provider = "managed_worker"

[agent_runtime.managed_worker]
allowed_actions = ["tool"]
class_only_policy_mode = "legacy_class_wide"
policy_revision = "legacy-policy-1"
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let admin = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/managed-workers",
        &["Authorization: Bearer admin-secret"],
        "",
    ));

    assert_eq!(
        admin["data"][0]["capability_policy"]["class_only_policy_mode"],
        "legacy_class_wide"
    );
    assert_eq!(
        admin["data"][0]["capability_policy"]["target_level_enforced"],
        false
    );
    assert_eq!(
        admin["data"][0]["capability_policy"]["exact_action_approval_enforced"],
        false
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
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
            "id": "customer-defined-role-204",
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
            &json!({"role_id": "customer-defined-role-204"}).to_string(),
        ));
        assert_eq!(binding["tenant_id"], *tenant_id, "{binding}");
    }
}

fn run_target_execution_worker(
    authorizer_socket: &Path,
    gateway_pid: u32,
    workspace: &std::path::Path,
    network_addr: &std::net::SocketAddr,
) -> std::process::Output {
    Command::new(env!("CARGO"))
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "run",
            "--quiet",
            "-p",
            "agent-worker",
            "--",
            "governed-target-execution-unix-smoke",
            "--gateway-authorizer-socket",
            authorizer_socket.to_str().unwrap(),
            "--gateway-authorizer-pid",
            &gateway_pid.to_string(),
            "--workspace-root",
            workspace.to_str().unwrap(),
            "--network-target",
            &network_addr.to_string(),
        ])
        .output()
        .unwrap()
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
