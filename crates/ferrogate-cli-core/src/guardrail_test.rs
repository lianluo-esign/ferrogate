// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the guardrail command families (#362): registration, verb →
//! operationId/method/path resolution across the immutable-revision policy store,
//! the activate/rollback/dry-run promotion lifecycle, the nested revision
//! sub-collection, the read-only evaluation stream, and the investigation
//! evidence join — plus typed request building against a fake transport and
//! error/exit-class mapping. Pure logic and a fake transport, no live network.

use super::*;
use crate::auth::AuthSource;
use crate::command::CommandGroup;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::{CliResult, ExitClass};
use crate::output::OutputFormat;
use crate::registry_helpers::ResourceInput;
use crate::resource::ListParams;
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

/// An input rich enough to satisfy every verb: two id segments (policy +
/// revision) plus a body for the mutating verbs.
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["pol_1", "3"])
        .with_body(serde_json::json!({"revision": 3}))
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "guardrail-policies",
            "guardrail-evaluations",
            "investigations"
        ]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (
            GuardrailPoliciesGroup.descriptor(),
            build_guardrail_policies as BuildFn,
        ),
        (
            GuardrailEvaluationsGroup.descriptor(),
            build_guardrail_evaluations,
        ),
        (InvestigationsGroup.descriptor(), build_investigations),
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
        "listGuardrailPolicyRevisions",
        "createGuardrailPolicyRevision",
        "listGuardrailPolicyRevisionsByPolicy",
        "listGuardrailPolicyRevisionHistory",
        "createNextGuardrailPolicyRevision",
        "getGuardrailPolicyRevision",
        "archiveGuardrailPolicyRevision",
        "activateGuardrailPolicyRevision",
        "rollbackGuardrailPolicyRevision",
        "dryRunGuardrailPolicyRevision",
        "listGuardrailEvaluations",
        "getGuardrailInvestigation",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 10 (policies) + 1 (evaluations) + 1 (investigations) = 12 distinct ids.
    assert_eq!(manifest.len(), 12);
}

#[test]
fn policy_collection_crud_maps_to_expected_requests() {
    let list = build_guardrail_policies("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/guardrail-policies");

    let create = build_guardrail_policies(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"name": "pii"})),
    )
    .unwrap();
    assert_eq!(create.method, Method::POST);
    assert_eq!(create.path, "/admin/v1/guardrail-policies");
    assert!(create.body.is_some());

    let get =
        build_guardrail_policies("get", &ResourceInput::new().with_segments(["pol_1"])).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/guardrail-policies/pol_1");
}

#[test]
fn revision_subcollection_addresses_nested_paths() {
    let policy = ResourceInput::new().with_segments(["pol_1"]);

    let revisions = build_guardrail_policies("revisions", &policy).unwrap();
    assert_eq!(revisions.method, Method::GET);
    assert_eq!(
        revisions.path,
        "/admin/v1/guardrail-policies/pol_1/revisions"
    );

    let create_revision = build_guardrail_policies(
        "create-revision",
        &ResourceInput::new()
            .with_segments(["pol_1"])
            .with_body(serde_json::json!({"rules": []})),
    )
    .unwrap();
    assert_eq!(create_revision.method, Method::POST);
    assert_eq!(
        create_revision.path,
        "/admin/v1/guardrail-policies/pol_1/revisions"
    );
    assert!(create_revision.body.is_some());

    let both = ResourceInput::new().with_segments(["pol_1", "3"]);

    let get_revision = build_guardrail_policies("get-revision", &both).unwrap();
    assert_eq!(get_revision.method, Method::GET);
    assert_eq!(
        get_revision.path,
        "/admin/v1/guardrail-policies/pol_1/revisions/3"
    );

    let archive = build_guardrail_policies("archive", &both).unwrap();
    assert_eq!(archive.method, Method::DELETE);
    assert_eq!(
        archive.path,
        "/admin/v1/guardrail-policies/pol_1/revisions/3"
    );
    assert!(archive.body.is_none());
}

#[test]
fn promotion_actions_post_to_policy_subpaths() {
    let target = ResourceInput::new()
        .with_segments(["pol_1"])
        .with_body(serde_json::json!({"revision": 3}));

    for (verb, action) in [
        ("activate", "activate"),
        ("rollback", "rollback"),
        ("dry-run", "dry-run"),
    ] {
        let spec = build_guardrail_policies(verb, &target).unwrap();
        assert_eq!(spec.method, Method::POST, "verb {verb}");
        assert_eq!(
            spec.path,
            format!("/admin/v1/guardrail-policies/pol_1/{action}"),
            "verb {verb}"
        );
    }
}

#[test]
fn create_revision_without_body_is_a_usage_error() {
    let error = build_guardrail_policies(
        "create-revision",
        &ResourceInput::new().with_segments(["pol_1"]),
    )
    .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn get_revision_without_revision_segment_is_a_usage_error() {
    let error = build_guardrail_policies(
        "get-revision",
        &ResourceInput::new().with_segments(["pol_1"]),
    )
    .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a revision id"));
}

#[test]
fn evaluations_are_a_read_only_stream() {
    let list = build_guardrail_evaluations("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/guardrail-evaluations");
}

#[test]
fn investigation_join_is_keyed_by_correlation_filters() {
    let spec = build_investigations(
        "get",
        &ResourceInput::new().with_list(
            ListParams::new()
                .with_filter("request_id", "req_42")
                .with_filter("trace_id", "tr_7"),
        ),
    )
    .unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/investigations");
    assert_eq!(
        spec.query,
        vec![
            ("request_id".to_string(), "req_42".to_string()),
            ("trace_id".to_string(), "tr_7".to_string()),
        ]
    );
}

#[test]
fn activate_reaches_the_transport_with_the_absolute_url() {
    let spec = build_guardrail_policies(
        "activate",
        &ResourceInput::new()
            .with_segments(["pol_1"])
            .with_body(serde_json::json!({"revision": 3})),
    )
    .unwrap();
    let (transport, seen) = fake(200, br#"{"active_revision":3}"#);
    let client = ControlPlaneClient::new(context(), None, transport);
    let response = block_on(client.send(&spec)).unwrap();
    assert_eq!(response.body["active_revision"], 3);
    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.method, Method::POST);
    assert_eq!(
        seen.url,
        "https://cp.example.com/admin/v1/guardrail-policies/pol_1/activate"
    );
}

#[test]
fn rollback_to_missing_revision_maps_to_not_found_class() {
    let spec = build_guardrail_policies(
        "rollback",
        &ResourceInput::new()
            .with_segments(["pol_1"])
            .with_body(serde_json::json!({"revision": 99})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        404,
        br#"{"error":{"message":"revision not found","type":"ferrogate_error","code":"not_found","request_id":"fgadm-g"}}"#,
    );
    let client = ControlPlaneClient::new(context(), None, transport);
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}
