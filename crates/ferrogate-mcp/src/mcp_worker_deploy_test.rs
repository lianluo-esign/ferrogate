// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Deploy/status/teardown pipeline tests (issue #409) — construct the Workers
//   Script PUT (metadata + DO/KV bindings + SQLite migration), the status/list GETs, and the
//   teardown DELETE against a scripted #405 transport, asserting the exact request. NO network.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ferrogate_cloudflare::{
    CloudflareConfig, CloudflareError, EnvTokenResolver, HttpMethod, HttpRequest, HttpResponse,
    HttpTransport,
};

use super::{McpWorkerDeployer, McpWorkerSpec, DEFAULT_MCP_SCRIPT_NAME, MCP_MULTIPART_BOUNDARY};

/// A transport that captures every request and replays a scripted response.
/// (`CloudflareError` is not `Clone`, so the mock stores an owned `HttpResponse`
/// and always returns `Ok`; the pipeline exercises HTTP-status/envelope error
/// paths, not transport-connect errors.)
struct CapturingTransport {
    response: HttpResponse,
    captured: Mutex<Vec<HttpRequest>>,
}

impl CapturingTransport {
    fn new(response: HttpResponse) -> Arc<Self> {
        Arc::new(Self {
            response,
            captured: Mutex::new(Vec::new()),
        })
    }

    fn last(&self) -> HttpRequest {
        self.captured.lock().unwrap().last().cloned().unwrap()
    }
}

#[async_trait]
impl HttpTransport for CapturingTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        self.captured.lock().unwrap().push(request);
        Ok(self.response.clone())
    }
}

fn ok(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn deployer(transport: Arc<CapturingTransport>) -> McpWorkerDeployer {
    McpWorkerDeployer::new(
        CloudflareConfig::new("acct-777", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        transport,
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn spec_metadata_carries_do_sqlite_migration_do_binding_and_oauth_kv() {
    let spec = McpWorkerSpec::new("export default {};").with_kv_namespace_id("kv-abc123");
    let meta = spec.metadata_json();

    assert_eq!(meta["main_module"], "index.js");

    // Binding 0: the McpAgent DO namespace binding.
    let do_binding = &meta["bindings"][0];
    assert_eq!(do_binding["type"], "durable_object_namespace");
    assert_eq!(do_binding["name"], "MCP_OBJECT");
    assert_eq!(do_binding["class_name"], "FerroGateMcp");

    // Binding 1: the OAUTH_KV namespace binding, carrying the namespace id.
    let kv_binding = &meta["bindings"][1];
    assert_eq!(kv_binding["type"], "kv_namespace");
    assert_eq!(kv_binding["name"], "OAUTH_KV");
    assert_eq!(kv_binding["namespace_id"], "kv-abc123");

    // Crucially: new_sqlite_classes (NOT new_classes) — Agents SDK needs SQLite.
    assert_eq!(meta["migrations"]["new_sqlite_classes"][0], "FerroGateMcp");
    assert_eq!(meta["migrations"]["new_tag"], "v1");
    assert!(meta
        .get("migrations")
        .and_then(|m| m.get("new_classes"))
        .is_none());
}

#[test]
fn multipart_body_has_metadata_and_module_parts() {
    let spec = McpWorkerSpec::new("export default { fetch() {} };");
    let body = String::from_utf8(spec.multipart_body()).unwrap();

    assert!(body.contains(&format!("--{MCP_MULTIPART_BOUNDARY}")));
    assert!(body.contains("name=\"metadata\""));
    assert!(body.contains("application/javascript+module"));
    assert!(body.contains("export default { fetch() {} };"));
    assert!(body.contains("new_sqlite_classes"));
    assert!(body.contains("kv_namespace"));
    // Properly terminated multipart.
    assert!(body
        .trim_end()
        .ends_with(&format!("--{MCP_MULTIPART_BOUNDARY}--")));
    assert_eq!(
        spec.content_type(),
        format!("multipart/form-data; boundary={MCP_MULTIPART_BOUNDARY}")
    );
}

#[test]
fn deploy_puts_script_to_correct_url_with_bearer_and_body() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "id": "ferrogate-mcp-server" } }"#,
    ));
    let deployer = deployer(transport.clone());
    let spec = McpWorkerSpec::new("export default {};").with_kv_namespace_id("kv-abc123");

    let outcome = runtime()
        .block_on(deployer.deploy(&spec))
        .expect("deploy ok");
    assert_eq!(outcome.script_name, "ferrogate-mcp-server");

    let req = transport.last();
    assert_eq!(req.method, HttpMethod::Put);
    assert_eq!(
        req.url,
        "https://api.cloudflare.com/client/v4/accounts/acct-777/workers/scripts/ferrogate-mcp-server"
    );
    assert_eq!(req.bearer_token, "plaintext-token");
    // The module upload must carry the multipart content type (not the transport's
    // `application/json` default), or Cloudflare rejects the script PUT.
    assert_eq!(
        req.content_type.as_deref(),
        Some(spec.content_type().as_str())
    );
    assert_eq!(
        req.content_type.as_deref(),
        Some("multipart/form-data; boundary=----FerroGateMcpServerBoundary")
    );
    let sent = String::from_utf8(req.body.unwrap()).unwrap();
    assert!(sent.contains("new_sqlite_classes"));
    assert!(sent.contains("durable_object_namespace"));
    assert!(sent.contains("kv_namespace"));
    assert!(sent.contains("kv-abc123"));
}

#[test]
fn default_script_name_matches_wrangler_toml() {
    let spec = McpWorkerSpec::new("export default {};");
    assert_eq!(spec.script_name, DEFAULT_MCP_SCRIPT_NAME);
    assert_eq!(spec.script_name, "ferrogate-mcp-server");
}

#[test]
fn deploy_falls_back_to_requested_name_when_result_omits_id() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": {} }"#,
    ));
    let deployer = deployer(transport);
    let mut spec = McpWorkerSpec::new("export default {};");
    spec.script_name = "tenant-mcp".to_string();

    let outcome = runtime().block_on(deployer.deploy(&spec)).unwrap();
    assert_eq!(outcome.script_name, "tenant-mcp");
}

#[test]
fn deploy_maps_api_error_envelope() {
    let transport = CapturingTransport::new(ok(
        403,
        r#"{ "success": false, "errors": [{ "code": 10021, "message": "workers scripts edit required" }] }"#,
    ));
    let deployer = deployer(transport);
    let spec = McpWorkerSpec::new("export default {};");

    let err = runtime().block_on(deployer.deploy(&spec)).unwrap_err();
    // A 403 maps to Unauthorized via the shared client's typed error mapping
    // (a missing-scope *code* would instead surface MissingScope).
    assert!(
        matches!(
            err,
            CloudflareError::Unauthorized { .. } | CloudflareError::MissingScope { .. }
        ),
        "got {err:?}"
    );
}

#[test]
fn list_gets_scripts_collection_and_decodes_ids() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": [ { "id": "ferrogate-mcp-server" }, { "id": "other" } ] }"#,
    ));
    let deployer = deployer(transport.clone());

    let scripts = runtime().block_on(deployer.list()).expect("list ok");
    assert_eq!(scripts.len(), 2);
    assert_eq!(scripts[0].id, "ferrogate-mcp-server");

    let req = transport.last();
    assert_eq!(req.method, HttpMethod::Get);
    assert_eq!(
        req.url,
        "https://api.cloudflare.com/client/v4/accounts/acct-777/workers/scripts"
    );
    assert!(req.body.is_none());
    assert_eq!(req.bearer_token, "plaintext-token");
}

#[test]
fn status_reports_deployed_when_script_present() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": [ { "id": "ferrogate-mcp-server" } ] }"#,
    ));
    let deployer = deployer(transport);

    let status = runtime()
        .block_on(deployer.status("ferrogate-mcp-server"))
        .expect("status ok");
    assert!(status.deployed);
    assert_eq!(status.script_name, "ferrogate-mcp-server");
}

#[test]
fn status_reports_not_deployed_when_absent() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": [ { "id": "something-else" } ] }"#,
    ));
    let deployer = deployer(transport);

    let status = runtime()
        .block_on(deployer.status("ferrogate-mcp-server"))
        .expect("status ok");
    assert!(!status.deployed);
}

#[test]
fn teardown_issues_delete_to_script_url() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": null }"#,
    ));
    let deployer = deployer(transport.clone());

    runtime()
        .block_on(deployer.teardown("ferrogate-mcp-server"))
        .expect("teardown ok");

    let req = transport.last();
    assert_eq!(req.method, HttpMethod::Delete);
    assert_eq!(
        req.url,
        "https://api.cloudflare.com/client/v4/accounts/acct-777/workers/scripts/ferrogate-mcp-server"
    );
    assert!(req.body.is_none());
    // A bodyless DELETE sends no content type.
    assert!(req.content_type.is_none());
    assert_eq!(req.bearer_token, "plaintext-token");
}

#[test]
fn teardown_maps_error_envelope() {
    let transport = CapturingTransport::new(ok(
        404,
        r#"{ "success": false, "errors": [{ "code": 10007, "message": "script not found" }] }"#,
    ));
    let deployer = deployer(transport);

    let err = runtime()
        .block_on(deployer.teardown("missing-mcp"))
        .unwrap_err();
    assert!(
        matches!(err, CloudflareError::Api { status: 404, .. }),
        "got {err:?}"
    );
}

#[test]
fn build_deploy_request_is_inspectable_without_sending() {
    let transport = CapturingTransport::new(ok(200, "{}"));
    let deployer = deployer(transport.clone());
    let spec = McpWorkerSpec::new("export default {};");

    let req = deployer.build_deploy_request(&spec).unwrap();
    assert_eq!(req.method, HttpMethod::Put);
    // The built request carries the spec's multipart content type so the
    // #411-honoring transport sends `multipart/form-data; boundary=…` rather than
    // defaulting to `application/json`.
    assert_eq!(req.content_type, Some(spec.content_type()));
    // Nothing was sent by merely constructing the request.
    assert!(transport.captured.lock().unwrap().is_empty());
}

#[test]
fn wrangler_fallback_command_names_script_and_compat_date() {
    let spec = McpWorkerSpec::new("export default {};");
    let cmd = spec.wrangler_deploy_command();
    assert!(cmd.contains("wrangler deploy"));
    assert!(cmd.contains("ferrogate-mcp-server"));
    assert!(cmd.contains("2025-06-01"));
}
