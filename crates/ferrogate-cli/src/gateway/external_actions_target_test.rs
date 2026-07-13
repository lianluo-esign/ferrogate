use super::*;
use crate::{
    config::{
        AgentRuntimeProvider, Config, ManagedWorkerCapabilityActionConfig,
        ManagedWorkerCapabilityTargetGrantConfig,
    },
    state::SharedAppState,
};
use ferrogate_runtime::{
    CapabilityTargetSelector, ExternalActionAuthorizationRequest, ExternalActionFramework,
    ExternalActionMode, ExternalActionSession, ExternalActionSpec, JsonShape, McpRisk,
};
use ferrogate_storage::{
    tenant_role_binding_id, StoredPermission, StoredRole, StoredTenantRoleBinding,
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
};

const PERMISSION_KEY: &str = "managed_actions.crm.lookup";

#[test]
fn authorizer_request_limit_counts_total_accepts() {
    assert!(!external_action_request_limit_reached(0, Some(2)));
    assert!(!external_action_request_limit_reached(1, Some(2)));
    assert!(external_action_request_limit_reached(2, Some(2)));
    assert!(!external_action_request_limit_reached(usize::MAX, None));
}

#[test]
fn unix_authorizer_max_requests_counts_completed_sequential_requests_cumulatively() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.path().join("authorizer.sock");
    let shared = shared_state_with_mcp_grant("request-limit-policy");
    grant_permission(&shared.current());
    let server_socket = socket.clone();
    let server = std::thread::spawn(move || {
        serve_gateway_external_action_authorizer_unix(
            &server_socket,
            GatewayExternalActionAuthorizerService::new(shared),
            Some(3),
        )
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(socket.exists());

    for suffix in ["one", "two", "three"] {
        let mut request = mcp_request("42");
        request.request_id = format!("{}:{suffix}", request.request_id);
        request.authorization.session.run_id = format!("run-{suffix}");
        request.request_id = request.authorization.stable_request_id();
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream
            .write_all(serde_json::to_string(&request).unwrap().as_bytes())
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let response: GatewayExternalActionTransportResponse =
            serde_json::from_str(&response).unwrap();
        assert!(response.response.accepted, "{response:?}");
    }

    let served = server.join().unwrap().unwrap();
    assert_eq!(served.len(), 3);
}

#[test]
fn tenant_rbac_role_binding_controls_target_grant_without_fixed_role_names() {
    let shared = shared_state_with_mcp_grant("policy-1");
    let state = shared.current();
    state
        .upsert_permission(StoredPermission {
            id: "permission-any-name".into(),
            key: PERMISSION_KEY.into(),
            name: "CRM lookup action".into(),
            description: String::new(),
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
    state
        .upsert_role(StoredRole {
            id: "role-42".into(),
            name: "Customer-defined operator role".into(),
            slug: "not-a-hard-coded-role".into(),
            description: String::new(),
            permission_keys: vec![PERMISSION_KEY.into()],
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
    state
        .bind_tenant_role(StoredTenantRoleBinding {
            id: tenant_role_binding_id("tenant-1", "role-42"),
            tenant_id: "tenant-1".into(),
            role_id: "role-42".into(),
            created_at_unix: 1,
        })
        .unwrap();

    let service = GatewayExternalActionAuthorizerService::new(shared.clone());
    let allowed = service.authorize_transport_request(mcp_request("42"));
    assert!(allowed.response.accepted, "{allowed:?}");

    state.unbind_tenant_role("tenant-1", "role-42").unwrap();
    let denied = service.authorize_transport_request(mcp_request("42"));
    assert!(!denied.response.accepted, "{denied:?}");
    assert_eq!(
        denied.response.decision,
        Some(ferrogate_runtime::ExternalActionDecision::Denied)
    );
}

#[test]
fn running_authorizer_reads_reloaded_policy_instead_of_startup_snapshot() {
    let shared = shared_state_with_mcp_grant("policy-before-reload");
    grant_permission(&shared.current());
    let service = GatewayExternalActionAuthorizerService::new(shared.clone());

    let before = service.authorize_transport_request(mcp_request("42"));
    assert!(before.response.accepted, "{before:?}");
    assert_eq!(
        event_metadata(&before, "policy_revision"),
        "policy-before-reload"
    );

    let mut candidate = (*shared.current().config).clone();
    candidate.agent_runtime.managed_worker.target_grants.clear();
    candidate.agent_runtime.managed_worker.policy_revision = "policy-after-reload".into();
    let reload = shared.reload_process_local(candidate);
    assert!(reload.committed, "{reload:?}");

    let after = service.authorize_transport_request(mcp_request("42"));
    assert!(!after.response.accepted, "{after:?}");
    assert_eq!(
        event_metadata(&after, "policy_revision"),
        "policy-after-reload"
    );
}

#[test]
fn unix_authorizer_requires_owner_only_parent_and_creates_owner_only_socket() {
    let error = validate_external_action_authorizer_parent_access(1000, 0o700, 1001).unwrap_err();
    assert!(error.to_string().contains("effective uid"));

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let shared_parent = root.path().join("shared");
    std::fs::create_dir(&shared_parent).unwrap();
    std::fs::set_permissions(&shared_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let shared_socket = shared_parent.join("authorizer.sock");
    let error = validate_external_action_authorizer_socket_parent(&shared_socket).unwrap_err();
    assert!(error.to_string().contains("mode 0700"));

    let secure_parent = root.path().join("private");
    std::fs::create_dir(&secure_parent).unwrap();
    std::fs::set_permissions(&secure_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = secure_parent.join("authorizer.sock");
    let shared = shared_state_with_mcp_grant("socket-policy-1");
    grant_permission(&shared.current());
    let server_socket = socket.clone();
    let server = std::thread::spawn(move || {
        serve_gateway_external_action_authorizer_unix(
            &server_socket,
            GatewayExternalActionAuthorizerService::new(shared),
            Some(1),
        )
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if !socket.exists() {
        let result = server.join().unwrap();
        panic!("authorizer failed before creating socket: {result:?}");
    }
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let request = mcp_request("42");
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let response: GatewayExternalActionTransportResponse = serde_json::from_str(&response).unwrap();
    assert!(response.response.accepted, "{response:?}");
    server.join().unwrap().unwrap();
}

#[test]
fn unix_authorizer_rejects_symlink_and_non_sticky_writable_ancestors() {
    let error =
        validate_external_action_authorizer_socket_parent(Path::new("relative.sock")).unwrap_err();
    assert!(error.to_string().contains("absolute"), "{error:#}");

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let real_parent = root.path().join("real");
    std::fs::create_dir(&real_parent).unwrap();
    std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let linked_parent = root.path().join("linked");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
    let error =
        validate_external_action_authorizer_socket_parent(&linked_parent.join("authorizer.sock"))
            .unwrap_err();
    assert!(error.to_string().contains("canonical"), "{error:#}");

    let writable = root.path().join("writable");
    let owned_child = writable.join("owned");
    std::fs::create_dir_all(&owned_child).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(&owned_child, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error =
        validate_external_action_authorizer_socket_parent(&owned_child.join("authorizer.sock"))
            .unwrap_err();
    assert!(format!("{error:#}").contains("sticky"), "{error:#}");
}

#[test]
fn unix_authorizer_accepts_sticky_writable_ancestor_with_owned_private_child() {
    assert!(
        validate_external_action_authorizer_ancestor_access(2000, 0o755, 1001, 1001)
            .unwrap_err()
            .to_string()
            .contains("owner")
    );
    assert!(
        validate_external_action_authorizer_ancestor_access(2000, 0o1777, 1001, 1001)
            .unwrap_err()
            .to_string()
            .contains("owner")
    );
    validate_external_action_authorizer_ancestor_access(0, 0o1777, 1001, 1001).unwrap();

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let sticky = root.path().join("sticky");
    let owned_child = sticky.join("owned");
    std::fs::create_dir_all(&owned_child).unwrap();
    std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
    std::fs::set_permissions(&owned_child, std::fs::Permissions::from_mode(0o700)).unwrap();

    let validated =
        validate_external_action_authorizer_socket_parent(&owned_child.join("authorizer.sock"))
            .unwrap();

    assert_eq!(
        validated.canonical_socket_path,
        owned_child.join("authorizer.sock")
    );
}

#[test]
fn unix_authorizer_detects_parent_swap_while_waiting_to_accept() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let secure_parent = root.path().join("private");
    let outside = root.path().join("outside");
    std::fs::create_dir(&secure_parent).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::set_permissions(&secure_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = secure_parent.join("authorizer.sock");
    let original_parent = root.path().join("private-original");
    let shared = shared_state_with_mcp_grant("socket-accept-swap-policy");
    let (bound_tx, bound_rx) = std::sync::mpsc::channel();
    let server_socket = socket.clone();
    let server = std::thread::spawn(move || {
        serve_gateway_external_action_authorizer_unix_with_hooks(
            &server_socket,
            GatewayExternalActionAuthorizerService::new(shared),
            Some(1),
            || {},
            || bound_tx.send(()).unwrap(),
        )
    });
    bound_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();

    std::fs::rename(&secure_parent, &original_parent).unwrap();
    std::os::unix::fs::symlink(&outside, &secure_parent).unwrap();
    let error = server.join().unwrap().unwrap_err();

    assert!(
        error.to_string().contains("changed after validation"),
        "{error:#}"
    );
    assert!(!outside.join("authorizer.sock").exists());
    assert!(!original_parent.join("authorizer.sock").exists());
}

#[test]
fn unix_authorizer_parent_swap_cannot_redirect_socket() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let secure_parent = root.path().join("private");
    let outside = root.path().join("outside");
    std::fs::create_dir(&secure_parent).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::set_permissions(&secure_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = secure_parent.join("authorizer.sock");
    let original_parent = root.path().join("private-original");
    let shared = shared_state_with_mcp_grant("socket-swap-policy");

    let error = serve_gateway_external_action_authorizer_unix_with_pre_bind_hook(
        &socket,
        GatewayExternalActionAuthorizerService::new(shared),
        Some(1),
        || {
            std::fs::rename(&secure_parent, &original_parent).unwrap();
            std::os::unix::fs::symlink(&outside, &secure_parent).unwrap();
        },
    )
    .unwrap_err();

    assert!(
        error.to_string().contains("changed after validation"),
        "{error:#}"
    );
    assert!(!outside.join("authorizer.sock").exists());
    assert!(!original_parent.join("authorizer.sock").exists());
}

fn shared_state_with_mcp_grant(revision: &str) -> SharedAppState {
    let mut config = Config::default();
    config.agent_runtime.enabled = true;
    config.agent_runtime.provider = AgentRuntimeProvider::ManagedWorker;
    config.agent_runtime.managed_worker.policy_revision = revision.into();
    config.agent_runtime.managed_worker.target_grants =
        vec![ManagedWorkerCapabilityTargetGrantConfig {
            selector_id: "crm-lookup".into(),
            permission_key: PERMISSION_KEY.into(),
            action: ManagedWorkerCapabilityActionConfig::McpTool,
            selector: CapabilityTargetSelector::Mcp {
                server: "crm".into(),
                tool: "lookup".into(),
                risk: McpRisk::Read,
                argument_schema: JsonShape::Object {
                    fields: BTreeMap::from([("id".into(), JsonShape::String)]),
                },
                allow_extra_arguments: false,
            },
        }];
    SharedAppState::with_source_path(config, None)
}

fn grant_permission(state: &crate::state::AppState) {
    state
        .upsert_permission(StoredPermission {
            id: "permission-1".into(),
            key: PERMISSION_KEY.into(),
            name: "CRM lookup action".into(),
            description: String::new(),
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
    state
        .upsert_role(StoredRole {
            id: "arbitrary-role-id".into(),
            name: "Arbitrary role".into(),
            slug: "arbitrary-role".into(),
            description: String::new(),
            permission_keys: vec![PERMISSION_KEY.into()],
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
    state
        .bind_tenant_role(StoredTenantRoleBinding {
            id: tenant_role_binding_id("tenant-1", "arbitrary-role-id"),
            tenant_id: "tenant-1".into(),
            role_id: "arbitrary-role-id".into(),
            created_at_unix: 1,
        })
        .unwrap();
}

fn mcp_request(id: &str) -> GatewayExternalActionTransportRequest {
    let authorization = ExternalActionAuthorizationRequest {
        session: ExternalActionSession {
            session_id: "session-1".into(),
            run_id: "run-1".into(),
            tenant_id: "tenant-1".into(),
            workspace_id: "workspace-1".into(),
            worker_id: "worker-1".into(),
            isolation_backend: "firecracker".into(),
            adapter_name: "native-harness".into(),
            adapter_version: "test".into(),
            framework: ExternalActionFramework::NativeHarness,
            mode: ExternalActionMode::Managed,
        },
        action: ExternalActionSpec::McpTool {
            server_name: "crm".into(),
            tool_name: "lookup".into(),
            arguments_policy: "exact_arguments".into(),
            arguments: serde_json::json!({"id": id}),
        },
        high_risk: false,
    };
    GatewayExternalActionTransportRequest {
        request_id: authorization.stable_request_id(),
        authorization,
    }
}

fn event_metadata<'a>(response: &'a GatewayExternalActionTransportResponse, key: &str) -> &'a str {
    response.response.event.as_ref().unwrap()["metadata"][key]
        .as_str()
        .unwrap()
}
