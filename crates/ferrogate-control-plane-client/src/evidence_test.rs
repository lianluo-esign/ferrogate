// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the evidence command families (#364): registration order,
//! verb → operationId/method/path resolution, export routing, pagination/filter
//! preservation against a fake transport, and error → exit-class mapping. Pure
//! logic plus a fake transport — no live network.

use super::*;
use crate::action_identity::ClientActionIdentity;
use crate::auth::AuthSource;
use crate::command::CommandGroup;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::{CliResult, ExitClass};
use crate::output::OutputFormat;
use crate::registry_helpers::ResourceInput;
use crate::resource::ListParams;
use crate::transport::{
    ControlPlaneClient, PageRequest, PreparedRequest, RawResponse, RequestSpec, Transport,
};
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

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["request-logs", "audit-events", "observed-agent-activity"]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (RequestLogsGroup.descriptor(), build_request_logs),
        (AuditEventsGroup.descriptor(), build_audit_events),
        (
            ObservedAgentActivityGroup.descriptor(),
            build_observed_agent_activity,
        ),
    ];
    let input = ResourceInput::new();
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
        "listAdminRequestLogs",
        "exportAdminRequestLogsJsonl",
        "listAdminAuditEvents",
        "listAdminObservedAgentActivity",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 2 (request-logs) + 1 (audit-events) + 1 (observed-agent-activity) = 4.
    assert_eq!(manifest.len(), 4);
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
fn request_log_list_and_export_map_to_distinct_endpoints() {
    let list = build_request_logs("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/request-logs");

    let export = build_request_logs("export", &ResourceInput::new()).unwrap();
    assert_eq!(export.method, Method::GET);
    assert_eq!(export.path, "/admin/v1/request-log-exports");
}

#[test]
fn export_preserves_investigation_filters_on_the_query() {
    let export = build_request_logs(
        "export",
        &ResourceInput::new().with_list(
            ListParams::new()
                .with_filter("provider", "openai")
                .with_filter("status", "error")
                .with_filter("since", "1721000000"),
        ),
    )
    .unwrap();
    for pair in [
        ("provider", "openai"),
        ("status", "error"),
        ("since", "1721000000"),
    ] {
        assert!(
            export
                .query
                .contains(&(pair.0.to_string(), pair.1.to_string())),
            "missing filter {pair:?}"
        );
    }
}

#[test]
fn audit_and_activity_map_to_their_collections_with_pagination() {
    let audit = build_audit_events(
        "list",
        &ResourceInput::new().with_list(ListParams::new().with_page(PageRequest::first(25))),
    )
    .unwrap();
    assert_eq!(audit.path, "/admin/v1/audit-events");
    assert!(audit
        .query
        .contains(&("limit".to_string(), "25".to_string())));

    let activity = build_observed_agent_activity("list", &ResourceInput::new()).unwrap();
    assert_eq!(activity.method, Method::GET);
    assert_eq!(activity.path, "/admin/v1/observed-agent-activity");
}

#[test]
fn export_preserves_correlation_ids_from_the_response() {
    // The export/read responses carry request/trace ids the investigation needs;
    // classify must surface them for audit attribution rather than dropping them.
    let export = build_request_logs("export", &ResourceInput::new()).unwrap();
    let seen: Seen = Arc::new(Mutex::new(None));
    let transport = FakeTransport {
        response: RawResponse {
            status: 200,
            headers: vec![
                ("x-request-id".to_string(), "req-evidence-1".to_string()),
                ("x-trace-id".to_string(), "trace-evidence-1".to_string()),
            ],
            body: b"{\"a\":1}\n{\"b\":2}".to_vec(),
        },
        seen: seen.clone(),
    };
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let response = block_on(client.send(&export)).unwrap();
    assert_eq!(response.request_id.as_deref(), Some("req-evidence-1"));
    assert_eq!(response.trace_id.as_deref(), Some("trace-evidence-1"));
}

#[test]
fn scope_denial_on_audit_read_maps_to_auth_class() {
    let spec = build_audit_events("list", &ResourceInput::new()).unwrap();
    let (transport, _seen) = fake(
        403,
        br#"{"error":{"message":"audit scope denied","type":"ferrogate_error","code":"forbidden","request_id":"fgadm-audit"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}

#[test]
fn export_timeout_maps_to_transport_class_without_false_success() {
    let spec = build_request_logs("export", &ResourceInput::new()).unwrap();
    let (transport, _seen) = fake(
        408,
        br#"{"error":{"message":"export timed out","type":"ferrogate_error","code":"request_timeout","request_id":"fgadm-to"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Transport);
}
