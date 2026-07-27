// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the tool-approval command family (#362): registration, verb →
//! operationId/method/path resolution, the approve/deny/expire lifecycle
//! actions, typed request building against a fake transport, and error/exit-class
//! mapping. Pure logic and a fake transport — no live network.

use super::*;
use crate::action_identity::ClientActionIdentity;
use crate::auth::AuthSource;
use crate::command::CommandGroup;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::{CliResult, ExitClass};
use crate::output::OutputFormat;
use crate::registry_helpers::ResourceInput;
use crate::transport::{ControlPlaneClient, PreparedRequest, RawResponse, Transport};
use http::Method;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};

type Seen = Arc<Mutex<Option<PreparedRequest>>>;

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

#[test]
fn group_registers_once() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["tool-approvals"]);
}

#[test]
fn every_declared_verb_builds_a_request() {
    let descriptor = ToolApprovalsGroup.descriptor();
    let input = ResourceInput::new()
        .with_segments(["appr_1"])
        .with_body(serde_json::json!({"actor": "op@example.com"}));
    for verb in &descriptor.verbs {
        let built = build_tool_approvals(&verb.name, &input);
        assert!(
            built.is_ok(),
            "verb {} failed to build: {:?}",
            verb.name,
            built.err()
        );
    }
}

#[test]
fn coverage_manifest_has_exactly_the_declared_operation_ids() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let manifest = registry.coverage_manifest();
    for op in [
        "listAdminToolApprovals",
        "getAdminToolApproval",
        "approveAdminToolApproval",
        "denyAdminToolApproval",
        "expireAdminToolApproval",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    assert_eq!(manifest.len(), 5);
}

#[test]
fn list_and_get_are_plain_reads() {
    let list = build_tool_approvals("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/tool-approvals");
    assert!(list.body.is_none());

    let get = build_tool_approvals("get", &ResourceInput::new().with_segments(["appr_9"])).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/tool-approvals/appr_9");
}

#[test]
fn resolutions_post_to_the_action_subpaths() {
    let target = ResourceInput::new()
        .with_segments(["appr_9"])
        .with_body(serde_json::json!({"actor": "op@example.com", "justification": "reviewed"}));

    for (verb, action) in [
        ("approve", "approve"),
        ("deny", "deny"),
        ("expire", "expire"),
    ] {
        let spec = build_tool_approvals(verb, &target).unwrap();
        assert_eq!(spec.method, Method::POST, "verb {verb}");
        assert_eq!(
            spec.path,
            format!("/admin/v1/tool-approvals/appr_9/{action}"),
            "verb {verb}"
        );
        assert!(spec.body.is_some(), "verb {verb} carries actor evidence");
    }
}

#[test]
fn resolution_without_id_is_a_usage_error() {
    let error = build_tool_approvals("approve", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn approve_reaches_the_transport_with_the_absolute_url() {
    let spec = build_tool_approvals(
        "approve",
        &ResourceInput::new()
            .with_segments(["appr_9"])
            .with_body(serde_json::json!({"actor": "op@example.com"})),
    )
    .unwrap();
    let (transport, seen) = fake(200, br#"{"status":"approved"}"#);
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let response = block_on(client.send(&spec)).unwrap();
    assert_eq!(response.body["status"], "approved");
    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.method, Method::POST);
    assert_eq!(
        seen.url,
        "https://cp.example.com/admin/v1/tool-approvals/appr_9/approve"
    );
}

#[test]
fn stale_fingerprint_conflict_maps_to_its_exit_class() {
    // The server rejects an approval whose immutable action fingerprint no
    // longer matches with a 409; the classifier must surface that faithfully.
    let spec =
        build_tool_approvals("approve", &ResourceInput::new().with_segments(["appr_9"])).unwrap();
    let (transport, _seen) = fake(
        409,
        br#"{"error":{"message":"fingerprint mismatch","type":"ferrogate_error","code":"conflict","request_id":"fgadm-a"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}
