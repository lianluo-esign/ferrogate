// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the MCP command families (#362): registration, verb →
//! operationId/method/path resolution, identity lifecycle actions, typed
//! request building against a fake transport, and error/exit-class mapping.
//! Pure logic and a fake transport — no live network.

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

/// Satisfies every verb across the families (an id segment plus a body).
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["srv_1"])
        .with_body(serde_json::json!({"endpoint": "https://mcp.example.com"}))
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["mcp-servers", "mcp-identity", "tool-sessions", "tools"]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (McpServersGroup.descriptor(), build_mcp_servers),
        (McpIdentityGroup.descriptor(), build_mcp_identity),
        (ToolSessionsGroup.descriptor(), build_tool_sessions),
        (ToolsGroup.descriptor(), build_tools),
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
        "listAdminMcpServers",
        "getAdminMcpServer",
        "createAdminMcpServer",
        "putAdminMcpServer",
        "patchAdminMcpServer",
        "deleteAdminMcpServer",
        "authorizeMcpIdentity",
        "getMcpIdentity",
        "revokeMcpIdentity",
        "completeMcpIdentityOauth",
        "listAdminToolSessionEvents",
        "listAdminTools",
        "listAdminPluginTools",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 6 (servers) + 4 (identity) + 1 (tool-sessions) + 2 (tools) = 13 distinct ids.
    assert_eq!(manifest.len(), 13);
}

#[test]
fn mcp_server_crud_addresses_items_by_name() {
    let replace = build_mcp_servers(
        "replace",
        &ResourceInput::new()
            .with_segments(["github"])
            .with_body(serde_json::json!({"endpoint": "https://mcp.github.com"})),
    )
    .unwrap();
    assert_eq!(replace.method, Method::PUT);
    assert_eq!(replace.path, "/admin/v1/mcp-servers/github");

    let delete =
        build_mcp_servers("delete", &ResourceInput::new().with_segments(["github"])).unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert_eq!(delete.path, "/admin/v1/mcp-servers/github");
    assert!(delete.body.is_none());
}

#[test]
fn identity_lifecycle_maps_to_runtime_paths() {
    let server = ResourceInput::new().with_segments(["github"]);

    let authorize = build_mcp_identity("authorize", &server).unwrap();
    assert_eq!(authorize.method, Method::POST);
    assert_eq!(authorize.path, "/v1/mcp/identity/github/authorize");

    let get = build_mcp_identity("get", &server).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/v1/mcp/identity/github");

    let revoke = build_mcp_identity("revoke", &server).unwrap();
    assert_eq!(revoke.method, Method::DELETE);
    assert_eq!(revoke.path, "/v1/mcp/identity/github");

    // The OAuth callback hits the fixed completion path, no server id needed.
    let callback = build_mcp_identity("callback", &ResourceInput::new()).unwrap();
    assert_eq!(callback.method, Method::GET);
    assert_eq!(callback.path, "/v1/mcp/identity/callback");
}

#[test]
fn identity_authorize_without_server_is_a_usage_error() {
    let error = build_mcp_identity("authorize", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn tool_session_events_read_the_session_stream() {
    let spec =
        build_tool_sessions("events", &ResourceInput::new().with_segments(["sess_5"])).unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/tool-sessions/sess_5");
}

#[test]
fn plugin_tools_reads_the_nested_sub_collection() {
    let list = build_tools("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/tools");

    let plugin = build_tools(
        "plugin-tools",
        &ResourceInput::new().with_segments(["pl_1"]),
    )
    .unwrap();
    assert_eq!(plugin.method, Method::GET);
    assert_eq!(plugin.path, "/admin/v1/plugins/pl_1/tools");
}

#[test]
fn authorize_reaches_the_transport_with_the_absolute_url() {
    let spec = build_mcp_identity(
        "authorize",
        &ResourceInput::new()
            .with_segments(["github"])
            .with_body(serde_json::json!({"scopes": ["repo"]})),
    )
    .unwrap();
    let (transport, seen) = fake(200, br#"{"authorization_url":"https://auth.example/x"}"#);
    let client = ControlPlaneClient::new(context(), None, transport);
    let response = block_on(client.send(&spec)).unwrap();
    assert_eq!(response.body["authorization_url"], "https://auth.example/x");
    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.method, Method::POST);
    assert_eq!(
        seen.url,
        "https://cp.example.com/v1/mcp/identity/github/authorize"
    );
}

#[test]
fn invalid_mcp_server_body_maps_to_validation_class() {
    let spec = build_mcp_servers(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"endpoint": ""})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        422,
        br#"{"error":{"message":"endpoint is required","type":"ferrogate_error","code":"invalid_request","request_id":"fgadm-v"}}"#,
    );
    let client = ControlPlaneClient::new(context(), None, transport);
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Validation);
}
