// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the operator-action command families (#364): registration
//! order, verb → operationId/method/path resolution, the config validate/reload
//! and drain get/set action shapes, generation-token pass-through, and error →
//! exit-class mapping against a fake transport. Pure logic plus a fake transport —
//! no live network.

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

/// An input satisfying every declared verb across the families: an id segment
/// (for gateway-config item verbs) plus a body for the write/action verbs.
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["cfg-1"])
        .with_body(serde_json::json!({"toml": "x = 1"}))
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "system",
            "provider-health",
            "config",
            "drain",
            "gateway-configs"
        ]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (SystemGroup.descriptor(), build_system),
        (ProviderHealthGroup.descriptor(), build_provider_health),
        (ConfigGroup.descriptor(), build_config),
        (DrainGroup.descriptor(), build_drain),
        (GatewayConfigsGroup.descriptor(), build_gateway_configs),
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
        "getAdminStatus",
        "getAdminStatusAlias",
        "getReadyz",
        "getHealthz",
        "listAdminObservability",
        "listAdminProviderHealth",
        "validateAdminConfig",
        "reloadAdminConfig",
        "getAdminDrain",
        "setAdminDrain",
        "listAdminGatewayConfigs",
        "getAdminGatewayConfig",
        "createAdminGatewayConfig",
        "putAdminGatewayConfig",
        "patchAdminGatewayConfig",
        "deleteAdminGatewayConfig",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 5 (system) + 1 (provider-health) + 2 (config) + 2 (drain) + 6 (gateway) = 16.
    assert_eq!(manifest.len(), 16);
}

#[test]
fn every_operation_id_exists_in_the_openapi_contract() {
    let spec = include_str!("../../../docs/openapi/admin-api.openapi.json");
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    for op in registry.coverage_manifest() {
        let needle = format!("\"operationId\": \"{op}\"");
        assert!(
            spec.contains(&needle),
            "operationId {op} not found in admin-api.openapi.json"
        );
    }
}

#[test]
fn system_verbs_map_to_their_probes_and_status() {
    for (verb, path) in [
        ("status", "/admin/v1/status"),
        ("status-alias", "/admin/status"),
        ("ready", "/readyz"),
        ("health", "/healthz"),
        ("observability", "/admin/v1/observability"),
    ] {
        let spec = build_system(verb, &ResourceInput::new()).unwrap();
        assert_eq!(spec.method, Method::GET, "verb {verb} method");
        assert_eq!(spec.path, path, "verb {verb} path");
    }
}

#[test]
fn provider_health_maps_to_its_collection() {
    let spec = build_provider_health("list", &ResourceInput::new()).unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/provider-health");
}

#[test]
fn config_validate_and_reload_map_to_post_actions() {
    let validate = build_config(
        "validate",
        &ResourceInput::new().with_body(serde_json::json!({"toml": "x = 1"})),
    )
    .unwrap();
    assert_eq!(validate.method, Method::POST);
    assert_eq!(validate.path, "/admin/v1/config/validate");
    assert!(validate.body.is_some());

    // reload accepts an optional candidate; a body-less reload (from on-disk
    // source) is still a valid POST with no request document.
    let reload = build_config("reload", &ResourceInput::new()).unwrap();
    assert_eq!(reload.method, Method::POST);
    assert_eq!(reload.path, "/admin/v1/config/reload");
    assert!(reload.body.is_none());
}

#[test]
fn config_validate_requires_a_candidate_body() {
    let error = build_config("validate", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn drain_get_reads_and_set_posts_the_desired_state() {
    let get = build_drain("get", &ResourceInput::new()).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/drain");
    assert!(get.body.is_none());

    let set = build_drain(
        "set",
        &ResourceInput::new().with_body(serde_json::json!({"draining": true})),
    )
    .unwrap();
    assert_eq!(set.method, Method::POST);
    assert_eq!(set.path, "/admin/v1/drain");
    assert!(set.body.is_some());
}

#[test]
fn drain_set_without_body_is_a_usage_error() {
    let error = build_drain("set", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn reload_generation_token_passes_through_exactly() {
    // A generation/commit token the operator carries in the reload document must
    // reach the server verbatim (never rewritten by the CLI) so stale-generation
    // rejection is decided by the server, not guessed here.
    let reload = build_config(
        "reload",
        &ResourceInput::new().with_body(serde_json::json!({"expected_generation": 42})),
    )
    .unwrap();
    let (transport, seen) = fake(200, br#"{"generation": 43, "committed": true}"#);
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    block_on(client.send(&reload)).unwrap();
    let seen = seen.lock().unwrap().clone().unwrap();
    let sent: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
    assert_eq!(sent["expected_generation"], 42);
}

#[test]
fn gateway_configs_crud_maps_to_the_collection_and_item() {
    let list = build_gateway_configs("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/gateway-configs");

    let get = build_gateway_configs("get", &ResourceInput::new().with_segments(["cfg-1"])).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/gateway-configs/cfg-1");

    let replace = build_gateway_configs(
        "replace",
        &ResourceInput::new()
            .with_segments(["cfg-1"])
            .with_body(serde_json::json!({"name": "prod"})),
    )
    .unwrap();
    assert_eq!(replace.method, Method::PUT);
    assert_eq!(replace.path, "/admin/v1/gateway-configs/cfg-1");

    let update = build_gateway_configs(
        "update",
        &ResourceInput::new()
            .with_segments(["cfg-1"])
            .with_body(serde_json::json!({"name": "prod2"})),
    )
    .unwrap();
    assert_eq!(update.method, Method::PATCH);
    assert_eq!(update.path, "/admin/v1/gateway-configs/cfg-1");

    let delete =
        build_gateway_configs("delete", &ResourceInput::new().with_segments(["cfg-1"])).unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert_eq!(delete.path, "/admin/v1/gateway-configs/cfg-1");
}

#[test]
fn stale_generation_on_reload_maps_to_conflict_class() {
    let spec = build_config(
        "reload",
        &ResourceInput::new().with_body(serde_json::json!({"expected_generation": 1})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        409,
        br#"{"error":{"message":"stale config generation","type":"ferrogate_error","code":"conflict","request_id":"fgadm-gen"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}

#[test]
fn invalid_candidate_on_validate_maps_to_validation_class() {
    let spec = build_config(
        "validate",
        &ResourceInput::new().with_body(serde_json::json!({"toml": "!!broken"})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        422,
        br#"{"error":{"message":"invalid config","type":"ferrogate_error","code":"unprocessable_entity","request_id":"fgadm-cfg"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Validation);
}

#[test]
fn reload_server_failure_maps_to_server_class_without_false_success() {
    let spec = build_config("reload", &ResourceInput::new()).unwrap();
    let (transport, _seen) = fake(
        500,
        br#"{"error":{"message":"reload failed mid-apply","type":"ferrogate_error","code":"server_error","request_id":"fgadm-500"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Server);
}
