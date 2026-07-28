// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the IAM command families (#361): lifecycle actions, secret
//! redaction, tenant-role bindings, and error-class mapping. Pure logic and a
//! fake transport — no live network.

use super::*;
use crate::action_identity::ClientActionIdentity;
use crate::auth::AuthSource;
use crate::command::CommandGroup;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::{CliResult, ExitClass};
use crate::output::OutputFormat;
use crate::registry_helpers::ResourceInput;
use crate::resource::redact_secret_fields;
use crate::transport::{ControlPlaneClient, PreparedRequest, RawResponse, RequestSpec, Transport};
use http::Method;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};

type Seen = Arc<Mutex<Option<PreparedRequest>>>;
/// A family's verb → request builder, aliased to keep the sweep table simple.
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

fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["tenant", "role"])
        .with_body(serde_json::json!({"role_id": "r1"}))
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "virtual-keys",
            "api-keys",
            "roles",
            "permissions",
            "access-policies",
            "tenant-roles",
        ]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (VirtualKeysGroup.descriptor(), build_virtual_keys),
        (ApiKeysGroup.descriptor(), build_api_keys),
        (RolesGroup.descriptor(), build_roles),
        (PermissionsGroup.descriptor(), build_permissions),
        (AccessPoliciesGroup.descriptor(), build_access_policies),
        (TenantRolesGroup.descriptor(), build_tenant_roles),
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
fn coverage_manifest_includes_lifecycle_operations() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let manifest = registry.coverage_manifest();
    for op in [
        "listVirtualKeys",
        "createVirtualKey",
        "revokeVirtualKey",
        "rotateVirtualKey",
        "enableVirtualKey",
        "disableVirtualKey",
        "revokeVirtualKeyAction",
        "listAdminApiKeys",
        "putAdminApiKey",
        "listRoles",
        "listPermissions",
        "listAdminPolicies",
        "putAdminPolicy",
        "listTenantRoles",
        "bindTenantRole",
        "unbindTenantRole",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 8 + 6 + 4 + 4 + 6 + 3 = 31 distinct operation ids.
    assert_eq!(manifest.len(), 31);
}

#[test]
fn virtual_key_lifecycle_actions_map_to_their_own_paths() {
    let id = ResourceInput::new().with_segments(["vk_1"]);
    let rotate = build_virtual_keys("rotate", &id).unwrap();
    assert_eq!(rotate.method, Method::POST);
    assert_eq!(rotate.path, "/admin/v1/virtual-keys/vk_1/rotate");

    let disable = build_virtual_keys("disable", &id).unwrap();
    assert_eq!(disable.path, "/admin/v1/virtual-keys/vk_1/disable");

    let enable = build_virtual_keys("enable", &id).unwrap();
    assert_eq!(enable.path, "/admin/v1/virtual-keys/vk_1/enable");

    // `revoke` is a DELETE on the item; `revoke-action` is the POST action.
    let revoke = build_virtual_keys("revoke", &id).unwrap();
    assert_eq!(revoke.method, Method::DELETE);
    assert_eq!(revoke.path, "/admin/v1/virtual-keys/vk_1");

    let revoke_action = build_virtual_keys("revoke-action", &id).unwrap();
    assert_eq!(revoke_action.method, Method::POST);
    assert_eq!(revoke_action.path, "/admin/v1/virtual-keys/vk_1/revoke");
}

#[test]
fn lifecycle_action_without_id_is_usage_error() {
    let error = build_virtual_keys("rotate", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn tenant_role_bind_and_unbind_address_the_right_paths() {
    let bind = build_tenant_roles(
        "bind",
        &ResourceInput::new()
            .with_segments(["t_1"])
            .with_body(serde_json::json!({"role_id": "admin"})),
    )
    .unwrap();
    assert_eq!(bind.method, Method::POST);
    assert_eq!(bind.path, "/admin/v1/tenant-roles/t_1");
    assert_eq!(bind.body.unwrap()["role_id"], "admin");

    let unbind = build_tenant_roles(
        "unbind",
        &ResourceInput::new().with_segments(["t_1", "admin"]),
    )
    .unwrap();
    assert_eq!(unbind.method, Method::DELETE);
    assert_eq!(unbind.path, "/admin/v1/tenant-roles/t_1/admin");

    let list = build_tenant_roles("list", &ResourceInput::new().with_segments(["t_1"])).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/tenant-roles/t_1");
}

#[test]
fn tenant_role_list_requires_a_tenant() {
    let error = build_tenant_roles("list", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
}

#[test]
fn tenant_role_mutations_reject_incomplete_targets() {
    let bind = build_tenant_roles(
        "bind",
        &ResourceInput::new().with_body(serde_json::json!({"role_id": "admin"})),
    )
    .expect_err("bind requires the tenant path segment");
    assert_eq!(bind.exit_class(), ExitClass::Usage);
    assert!(bind.to_string().contains("requires a target id"));

    for segments in [vec![], vec!["t_1"]] {
        let error = build_tenant_roles("unbind", &ResourceInput::new().with_segments(segments))
            .expect_err("unbind requires both tenant and role path segments");
        assert_eq!(error.exit_class(), ExitClass::Usage);
        assert!(error.to_string().contains("requires 2"));
    }
}

#[test]
fn create_virtual_key_secret_is_returned_once_then_redacted_from_reads() {
    // create returns the one-time secret material.
    let spec = build_virtual_keys(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"name": "ci"})),
    )
    .unwrap();
    let (transport, seen) = fake(
        201,
        br#"{"id":"vk_1","key":"vk_live_public","secret":"sk-live-onetime","status":"active"}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let response = block_on(client.send(&spec)).unwrap();
    // At create, the secret is present (the command layer routes it to a safe
    // sink); redaction is what a later read applies.
    assert_eq!(response.body["secret"], "sk-live-onetime");
    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.method, Method::POST);
    assert_eq!(seen.url, "https://cp.example.com/admin/v1/virtual-keys");

    // A subsequent get must never re-expose key material.
    let mut read = response.body.clone();
    redact_secret_fields(&mut read, VIRTUAL_KEY_SECRET_FIELDS);
    assert_eq!(read["secret"], "<redacted>");
    assert_eq!(read["key"], "<redacted>");
    assert_eq!(read["status"], "active");
}

#[test]
fn cross_tenant_access_maps_to_auth_class() {
    let spec =
        build_virtual_keys("get", &ResourceInput::new().with_segments(["vk_other"])).unwrap();
    let (transport, _seen) = fake(
        403,
        br#"{"error":{"message":"virtual key belongs to another tenant","type":"ferrogate_error","code":"forbidden","request_id":"fgadm-f"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}

#[test]
fn validation_error_on_create_maps_to_validation_class() {
    let spec = build_roles(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"name": ""})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        422,
        br#"{"error":{"message":"name is required","type":"ferrogate_error","code":"invalid_request","request_id":"fgadm-v"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Validation);
}

#[test]
fn access_policy_addresses_items_by_name() {
    let spec = build_access_policies(
        "replace",
        &ResourceInput::new()
            .with_segments(["default-deny"])
            .with_body(serde_json::json!({"rules": []})),
    )
    .unwrap();
    assert_eq!(spec.method, Method::PUT);
    assert_eq!(spec.path, "/admin/v1/policies/default-deny");
}
