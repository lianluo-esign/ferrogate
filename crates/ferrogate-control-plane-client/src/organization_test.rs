// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the organization command families (#361). Requests are built
//! and, where end-to-end behavior matters, driven through a fake transport — no
//! live network.

use super::*;
use crate::action_identity::ClientActionIdentity;
use crate::auth::AuthSource;
use crate::command::CommandGroup;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::{CliResult, ExitClass};
use crate::output::OutputFormat;
use crate::transport::{ControlPlaneClient, PreparedRequest, RawResponse, RequestSpec, Transport};
use http::Method;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};

type Seen = Arc<Mutex<Option<PreparedRequest>>>;
/// A family's verb → request builder, aliased to keep the sweep table simple.
type BuildFn = fn(&str, &ResourceInput) -> CliResult<RequestSpec>;

fn context(tenant: Option<&str>) -> EffectiveContext {
    EffectiveContext {
        context_name: Some("test".to_string()),
        endpoint: "https://cp.example.com".to_string(),
        tenant: tenant.map(str::to_string),
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

/// Build a fake transport plus a shared handle onto the request it records, so
/// a test can assert on the prepared request after the client has consumed the
/// transport by value.
fn fake(status: u16, headers: Vec<(String, String)>, body: &[u8]) -> (FakeTransport, Seen) {
    let seen: Seen = Arc::new(Mutex::new(None));
    let transport = FakeTransport {
        response: RawResponse {
            status,
            headers,
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

/// An input that satisfies every verb across the families, so a coverage sweep
/// can assert each declared verb is actually wired to a request builder.
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["scope", "id"])
        .with_body(serde_json::json!({"name": "x"}))
}

#[test]
fn all_groups_register_and_resolve_their_verbs() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "tenant-accounts",
            "tenants",
            "projects",
            "workspaces",
            "plans",
            "quota-policies",
        ]
    );
    // Representative verb resolution across groups.
    assert_eq!(
        registry
            .resolve("tenant-accounts", "resolved-defaults")
            .unwrap()
            .operation_id
            .as_deref(),
        Some("getTenantResolvedDefaults")
    );
    assert_eq!(
        registry
            .resolve("workspaces", "delete")
            .unwrap()
            .operation_id
            .as_deref(),
        Some("deleteWorkspace")
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    // For each group, walk its descriptor verbs and prove the matching build
    // function wires each one (guards operationId metadata vs. request drift).
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (TenantAccountsGroup.descriptor(), build_tenant_accounts),
        (TenantsGroup.descriptor(), build_tenants),
        (ProjectsGroup.descriptor(), build_projects),
        (WorkspacesGroup.descriptor(), build_workspaces),
        (PlansGroup.descriptor(), build_plans),
        (QuotaPoliciesGroup.descriptor(), build_quota_policies),
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
fn coverage_manifest_declares_the_expected_operation_ids() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let manifest = registry.coverage_manifest();
    for op in [
        "listTenantAccounts",
        "getTenantAccount",
        "createTenantAccount",
        "replaceTenantAccount",
        "updateTenantAccount",
        "getTenantResolvedDefaults",
        "assignTenantPlan",
        "listAdminTenants",
        "listProjects",
        "deleteProject",
        "listWorkspaces",
        "deleteWorkspace",
        "listPlans",
        "updatePlan",
        "listQuotaPolicies",
        "deleteQuotaPolicy",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 7 + 1 + 6 + 6 + 5 + 6 = 31 distinct operation ids.
    assert_eq!(manifest.len(), 31);
}

#[test]
fn quota_policy_get_addresses_the_composite_scope_key() {
    let input = ResourceInput::new().with_segments(["tenant", "acme"]);
    let spec = build_quota_policies("get", &input).unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/quota-policies/tenant/acme");
}

#[test]
fn quota_policy_item_verbs_require_the_complete_composite_key() {
    for verb in ["get", "delete"] {
        let error = build_quota_policies(verb, &ResourceInput::new().with_segments(["tenant"]))
            .expect_err("scope_type without scope_id is not a quota-policy key");
        assert_eq!(error.exit_class(), ExitClass::Usage, "{verb}: {error}");
        assert!(error.to_string().contains("requires 2"), "{verb}: {error}");
    }

    for verb in ["replace", "update"] {
        let error = build_quota_policies(
            verb,
            &ResourceInput::new()
                .with_segments(["tenant"])
                .with_body(serde_json::json!({"limit": 10})),
        )
        .expect_err("a body cannot make an incomplete quota-policy key valid");
        assert_eq!(error.exit_class(), ExitClass::Usage, "{verb}: {error}");
        assert!(error.to_string().contains("requires 2"), "{verb}: {error}");
    }
}

#[test]
fn resolved_defaults_builds_the_nested_read() {
    let input = ResourceInput::new().with_segments(["t_1"]);
    let spec = build_tenant_accounts("resolved-defaults", &input).unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/tenant-accounts/t_1/resolved-defaults");
}

#[test]
fn assign_plan_puts_the_plan_document_onto_the_tenant_plan_subpath() {
    // assignTenantPlan is a first-class subscription action: PUT the operator's
    // plan-assignment document onto `.../{tenant_id}/plan`, carried verbatim.
    let spec = build_tenant_accounts(
        "assign-plan",
        &ResourceInput::new()
            .with_segments(["t_1"])
            .with_body(serde_json::json!({"plan_id": "pro"})),
    )
    .unwrap();
    assert_eq!(spec.method, Method::PUT);
    assert_eq!(spec.path, "/admin/v1/tenant-accounts/t_1/plan");
    assert_eq!(spec.body.as_ref().unwrap()["plan_id"], "pro");
}

#[test]
fn assign_plan_without_body_is_a_usage_error() {
    let error = build_tenant_accounts("assign-plan", &ResourceInput::new().with_segments(["t_1"]))
        .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn assign_plan_without_tenant_is_a_usage_error() {
    let error = build_tenant_accounts(
        "assign-plan",
        &ResourceInput::new().with_body(serde_json::json!({"plan_id": "pro"})),
    )
    .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn create_tenant_account_round_trips_through_the_transport() {
    let body = serde_json::json!({"name": "acme", "plan_id": "pro"});
    let spec =
        build_tenant_accounts("create", &ResourceInput::new().with_body(body.clone())).unwrap();
    let (transport, _seen) = fake(
        201,
        vec![("x-request-id".to_string(), "fgadm-42".to_string())],
        br#"{"id":"t_1","version":7,"name":"acme"}"#,
    );
    let client = ControlPlaneClient::new(
        context(Some("acme")),
        None,
        transport,
        ClientActionIdentity::fixture(),
    );
    let response = block_on(client.send(&spec)).unwrap();
    assert_eq!(response.status, 201);
    assert_eq!(response.request_id.as_deref(), Some("fgadm-42"));
    // The server-returned resource version is preserved for the caller to show.
    assert_eq!(response.body["version"], 7);
}

/// The resolved tenant rides an explicit header rather than being folded into
/// the path. This asserts the *sending* side only — it would pass just as well
/// if no server read the header, which is exactly the situation today; see
/// `transport_test::tenant_scope_is_not_yet_an_openapi_parameter` for the
/// contract-side half and `context::unhonored_scope_notice` for what the
/// operator is told.
#[test]
fn tenant_scope_is_carried_as_an_explicit_header() {
    let spec = build_projects("list", &ResourceInput::new()).unwrap();
    let (transport, seen) = fake(200, vec![], br#"{"items":[]}"#);
    let client = ControlPlaneClient::new(
        context(Some("acme")),
        None,
        transport,
        ClientActionIdentity::fixture(),
    );
    let _ = block_on(client.send(&spec)).unwrap();
    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.header("x-ferrogate-tenant"), Some("acme"));
    assert_eq!(seen.url, "https://cp.example.com/admin/v1/projects");
    assert_eq!(seen.method, Method::GET);
}

#[test]
fn delete_not_found_maps_to_not_found_conflict_class() {
    let spec = build_projects("delete", &ResourceInput::new().with_segments(["missing"])).unwrap();
    let (transport, _seen) = fake(
        404,
        vec![],
        br#"{"error":{"message":"no such project","type":"ferrogate_error","code":"project_not_found","request_id":"fgadm-x"}}"#,
    );
    let client = ControlPlaneClient::new(
        context(Some("acme")),
        None,
        transport,
        ClientActionIdentity::fixture(),
    );
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}

#[test]
fn conflict_on_update_is_surfaced_not_swallowed() {
    let spec = build_workspaces(
        "update",
        &ResourceInput::new()
            .with_segments(["w1"])
            .with_body(serde_json::json!({"name": "renamed"})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        409,
        vec![],
        br#"{"error":{"message":"version mismatch","type":"ferrogate_error","code":"conflict","request_id":"fgadm-c","expected_version":3}}"#,
    );
    let client = ControlPlaneClient::new(
        context(Some("acme")),
        None,
        transport,
        ClientActionIdentity::fixture(),
    );
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
    // The optimistic-concurrency detail is preserved, not overwritten silently.
    if let crate::CliError::Api(api) = &error {
        assert_eq!(api.details.as_ref().unwrap()["expected_version"], 3);
    } else {
        panic!("expected an API error");
    }
}
