// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the catalog command families (#363): registration order, verb
//! → operationId/method/path resolution against a fake transport, and
//! error/exit-class mapping. Pure logic and a fake transport — no live network.

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

/// An input satisfying every declared verb across the families: a single id
/// segment plus a body for the write verbs.
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["tmpl-1"])
        .with_body(serde_json::json!({"name": "greeting"}))
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "prompt-templates",
            "skill-packages",
            "plugins",
            "catalog",
            "dashboard",
        ]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (PromptTemplatesGroup.descriptor(), build_prompt_templates),
        (SkillPackagesGroup.descriptor(), build_skill_packages),
        (PluginsGroup.descriptor(), build_plugins),
        (CatalogGroup.descriptor(), build_catalog),
        (DashboardGroup.descriptor(), build_dashboard),
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
        "listAdminPromptTemplates",
        "getAdminPromptTemplate",
        "createAdminPromptTemplate",
        "putAdminPromptTemplate",
        "patchAdminPromptTemplate",
        "archiveAdminPromptTemplate",
        "renderPromptTemplate",
        "listAdminSkillPackages",
        "getAdminSkillPackage",
        "createAdminSkillPackage",
        "putAdminSkillPackage",
        "patchAdminSkillPackage",
        "deleteAdminSkillPackage",
        "listAdminPlugins",
        "getAdminPlugin",
        "createAdminPlugin",
        "updateAdminPlugin",
        "deleteAdminPlugin",
        "listAdminModels",
        "listAdminProviders",
        "listAdminProviderModels",
        "listAdminExtensions",
        "listAdminFrameworkAdapters",
        "getAdminDashboard",
        "getAdminDashboardAlias",
        "getAdminDashboardSlash",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 7 (prompt-templates) + 6 (skill-packages) + 5 (plugins) + 5 (catalog)
    // + 3 (dashboard) = 26 ids.
    assert_eq!(manifest.len(), 26);
}

#[test]
fn every_operation_id_exists_in_the_openapi_contract() {
    // The declared operationIds are what the #365 parity gate diffs against the
    // contract, so a typo here would silently break coverage. Assert each one is
    // a real operationId in the shipped OpenAPI document.
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
fn prompt_template_crud_maps_to_the_admin_collection() {
    let list = build_prompt_templates("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/prompt-templates");

    let create = build_prompt_templates(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"name": "greeting"})),
    )
    .unwrap();
    assert_eq!(create.method, Method::POST);
    assert_eq!(create.path, "/admin/v1/prompt-templates");

    let id = ResourceInput::new().with_segments(["tmpl-1"]);

    let get = build_prompt_templates("get", &id).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/prompt-templates/tmpl-1");

    let replace = build_prompt_templates(
        "replace",
        &id.clone().with_body(serde_json::json!({"body": "hi"})),
    )
    .unwrap();
    assert_eq!(replace.method, Method::PUT);
    assert_eq!(replace.path, "/admin/v1/prompt-templates/tmpl-1");

    let update = build_prompt_templates(
        "update",
        &id.clone().with_body(serde_json::json!({"body": "hi"})),
    )
    .unwrap();
    assert_eq!(update.method, Method::PATCH);
    assert_eq!(update.path, "/admin/v1/prompt-templates/tmpl-1");
}

#[test]
fn prompt_template_archive_deletes_the_item() {
    let archive =
        build_prompt_templates("archive", &ResourceInput::new().with_segments(["tmpl-1"])).unwrap();
    assert_eq!(archive.method, Method::DELETE);
    assert_eq!(archive.path, "/admin/v1/prompt-templates/tmpl-1");
    assert!(archive.body.is_none());
}

#[test]
fn prompt_template_render_posts_to_the_public_render_path() {
    let render = build_prompt_templates(
        "render",
        &ResourceInput::new()
            .with_segments(["tmpl-1"])
            .with_body(serde_json::json!({"inputs": {"name": "ada"}})),
    )
    .unwrap();
    assert_eq!(render.method, Method::POST);
    assert_eq!(render.path, "/v1/prompts/tmpl-1/render");
    assert!(render.body.is_some());
}

#[test]
fn prompt_template_render_without_body_is_a_usage_error() {
    let error = build_prompt_templates("render", &ResourceInput::new().with_segments(["tmpl-1"]))
        .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn prompt_template_archive_without_id_is_a_usage_error() {
    let error = build_prompt_templates("archive", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn skill_package_crud_maps_to_the_admin_collection() {
    let list = build_skill_packages("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/skill-packages");

    let id = ResourceInput::new().with_segments(["skill-1"]);

    let delete = build_skill_packages("delete", &id).unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert_eq!(delete.path, "/admin/v1/skill-packages/skill-1");

    let update = build_skill_packages(
        "update",
        &id.clone().with_body(serde_json::json!({"version": "2"})),
    )
    .unwrap();
    assert_eq!(update.method, Method::PATCH);
    assert_eq!(update.path, "/admin/v1/skill-packages/skill-1");
}

#[test]
fn plugin_crud_has_no_replace_and_uses_patch_for_update() {
    let create = build_plugins(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"name": "waf"})),
    )
    .unwrap();
    assert_eq!(create.method, Method::POST);
    assert_eq!(create.path, "/admin/v1/plugins");

    let id = ResourceInput::new().with_segments(["plugin-1"]);

    let get = build_plugins("get", &id).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/plugins/plugin-1");

    let update = build_plugins(
        "update",
        &id.clone().with_body(serde_json::json!({"enabled": true})),
    )
    .unwrap();
    assert_eq!(update.method, Method::PATCH);
    assert_eq!(update.path, "/admin/v1/plugins/plugin-1");

    let delete = build_plugins("delete", &id).unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert_eq!(delete.path, "/admin/v1/plugins/plugin-1");

    // `plugins` deliberately declares no `replace` verb (no PUT operation).
    assert!(PluginsGroup.descriptor().verb("replace").is_none());
}

#[test]
fn catalog_reads_map_to_their_distinct_collections() {
    let cases = [
        ("models", "/admin/v1/models"),
        ("providers", "/admin/v1/providers"),
        ("provider-models", "/admin/v1/provider-models"),
        ("extensions", "/admin/v1/extensions"),
        ("framework-adapters", "/admin/v1/framework-adapters"),
    ];
    for (verb, path) in cases {
        let spec = build_catalog(verb, &ResourceInput::new()).unwrap();
        assert_eq!(spec.method, Method::GET, "verb {verb}");
        assert_eq!(spec.path, path, "verb {verb}");
        assert!(spec.body.is_none(), "verb {verb}");
    }
}

#[test]
fn catalog_unknown_verb_is_a_usage_error() {
    let error = build_catalog("nope", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("is not a catalog verb"));
}

#[test]
fn dashboard_verbs_map_to_the_three_alias_paths() {
    let cases = [
        ("show", "/admin"),
        ("alias", "/admin/dashboard"),
        ("root", "/admin/"),
    ];
    for (verb, path) in cases {
        let spec = build_dashboard(verb, &ResourceInput::new()).unwrap();
        assert_eq!(spec.method, Method::GET, "verb {verb}");
        assert_eq!(spec.path, path, "verb {verb}");
    }
}

#[test]
fn dashboard_unknown_verb_is_a_usage_error() {
    let error = build_dashboard("nope", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("is not a dashboard verb"));
}

#[test]
fn catalog_list_reaches_the_transport_at_the_expected_url() {
    let spec = build_catalog("providers", &ResourceInput::new()).unwrap();
    let (transport, seen) = fake(200, br#"{"object":"list","data":[]}"#);
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    block_on(client.send(&spec)).unwrap();
    let seen = seen.lock().unwrap().clone().unwrap();
    assert!(
        seen.url.contains("/admin/v1/providers"),
        "expected providers path in {}",
        seen.url
    );
}

#[test]
fn not_found_prompt_template_maps_to_not_found_conflict_class() {
    let spec =
        build_prompt_templates("get", &ResourceInput::new().with_segments(["missing"])).unwrap();
    let (transport, _seen) = fake(
        404,
        br#"{"error":{"message":"prompt template not found","type":"ferrogate_error","code":"not_found","request_id":"fgadm-nf"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}

#[test]
fn validation_rejection_on_create_maps_to_validation_class() {
    let spec = build_skill_packages(
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"name": ""})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        422,
        br#"{"error":{"message":"skill package manifest invalid","type":"ferrogate_error","code":"unprocessable_entity","request_id":"fgadm-val"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Validation);
}

#[test]
fn forbidden_plugin_delete_maps_to_auth_class() {
    let spec = build_plugins("delete", &ResourceInput::new().with_segments(["plugin-1"])).unwrap();
    let (transport, _seen) = fake(
        403,
        br#"{"error":{"message":"insufficient scope to delete plugin","type":"ferrogate_error","code":"forbidden","request_id":"fgadm-fb"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}
