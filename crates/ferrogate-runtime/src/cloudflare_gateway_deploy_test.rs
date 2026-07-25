// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Deploy/teardown pipeline tests (issue #413) — construct the Workers Script
//   PUT (metadata + DO SQLite migration) + teardown DELETE against a scripted #405
//   transport, asserting the exact request. NO network.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ferrogate_cloudflare::{
    CloudflareConfig, CloudflareError, EnvTokenResolver, HttpMethod, HttpRequest, HttpResponse,
    HttpTransport,
};

use super::{GatewayWorkerDeployer, GatewayWorkerSpec, GATEWAY_MULTIPART_BOUNDARY};

/// A transport that captures every request and replays a scripted response.
/// (`CloudflareError` is not `Clone`, so the mock stores an owned `HttpResponse`
/// and always returns `Ok`; the deploy pipeline exercises HTTP-status/envelope
/// error paths, not transport-connect errors.)
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

fn deployer(transport: Arc<CapturingTransport>) -> GatewayWorkerDeployer {
    GatewayWorkerDeployer::new(
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
fn spec_metadata_carries_do_sqlite_migration_and_binding() {
    let spec = GatewayWorkerSpec::new("export default {};");
    let meta = spec.metadata_json();

    assert_eq!(meta["main_module"], "index.js");
    // DO namespace binding for the agent class.
    let binding = &meta["bindings"][0];
    assert_eq!(binding["type"], "durable_object_namespace");
    assert_eq!(binding["name"], "AGENT_GATEWAY");
    assert_eq!(binding["class_name"], "AgentGateway");
    // Crucially: new_sqlite_classes (NOT new_classes) — Agents SDK needs SQLite.
    assert_eq!(meta["migrations"]["new_sqlite_classes"][0], "AgentGateway");
    assert_eq!(meta["migrations"]["new_tag"], "v1");
    assert!(meta
        .get("migrations")
        .and_then(|m| m.get("new_classes"))
        .is_none());
}

#[test]
fn multipart_body_has_metadata_and_module_parts() {
    let spec = GatewayWorkerSpec::new("export default { fetch() {} };");
    let body = String::from_utf8(spec.multipart_body()).unwrap();

    assert!(body.contains(&format!("--{GATEWAY_MULTIPART_BOUNDARY}")));
    assert!(body.contains("name=\"metadata\""));
    assert!(body.contains("application/javascript+module"));
    assert!(body.contains("export default { fetch() {} };"));
    assert!(body.contains("new_sqlite_classes"));
    // Properly terminated multipart.
    assert!(body
        .trim_end()
        .ends_with(&format!("--{GATEWAY_MULTIPART_BOUNDARY}--")));
    assert_eq!(
        spec.content_type(),
        format!("multipart/form-data; boundary={GATEWAY_MULTIPART_BOUNDARY}")
    );
}

#[test]
fn deploy_puts_script_to_correct_url_with_bearer_and_body() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": { "id": "ferrogate-agent-gateway" } }"#,
    ));
    let deployer = deployer(transport.clone());
    let spec = GatewayWorkerSpec::new("export default {};");

    let outcome = runtime()
        .block_on(deployer.deploy(&spec))
        .expect("deploy ok");
    assert_eq!(outcome.script_name, "ferrogate-agent-gateway");

    let req = transport.last();
    assert_eq!(req.method, HttpMethod::Put);
    assert_eq!(
        req.url,
        "https://api.cloudflare.com/client/v4/accounts/acct-777/workers/scripts/ferrogate-agent-gateway"
    );
    assert_eq!(req.bearer_token, "plaintext-token");
    // The upload must carry the multipart content type (with the boundary the
    // body is framed by), not the transport's `application/json` default — the
    // live Script API rejects a JSON-typed multipart body. #411's honoring
    // transport forwards whatever this `Some(..)` carries.
    assert_eq!(req.content_type, Some(spec.content_type()));
    assert_eq!(
        req.content_type.as_deref(),
        Some(format!("multipart/form-data; boundary={GATEWAY_MULTIPART_BOUNDARY}").as_str())
    );
    let sent = String::from_utf8(req.body.unwrap()).unwrap();
    assert!(sent.contains("new_sqlite_classes"));
    assert!(sent.contains("durable_object_namespace"));
}

#[test]
fn deploy_falls_back_to_requested_name_when_result_omits_id() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": {} }"#,
    ));
    let deployer = deployer(transport);
    let mut spec = GatewayWorkerSpec::new("export default {};");
    spec.script_name = "custom-gateway".to_string();

    let outcome = runtime().block_on(deployer.deploy(&spec)).unwrap();
    assert_eq!(outcome.script_name, "custom-gateway");
}

#[test]
fn deploy_maps_api_error_envelope() {
    let transport = CapturingTransport::new(ok(
        403,
        r#"{ "success": false, "errors": [{ "code": 10021, "message": "workers scripts edit required" }] }"#,
    ));
    let deployer = deployer(transport);
    let spec = GatewayWorkerSpec::new("export default {};");

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
fn teardown_issues_delete_to_script_url() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{ "success": true, "errors": [], "result": null }"#,
    ));
    let deployer = deployer(transport.clone());

    runtime()
        .block_on(deployer.teardown("ferrogate-agent-gateway"))
        .expect("teardown ok");

    let req = transport.last();
    assert_eq!(req.method, HttpMethod::Delete);
    assert_eq!(
        req.url,
        "https://api.cloudflare.com/client/v4/accounts/acct-777/workers/scripts/ferrogate-agent-gateway"
    );
    assert!(req.body.is_none());
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
        .block_on(deployer.teardown("missing-gateway"))
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
    let spec = GatewayWorkerSpec::new("export default {};");

    let req = deployer.build_deploy_request(&spec).unwrap();
    assert_eq!(req.method, HttpMethod::Put);
    // The constructed request pins the multipart content type so the honoring
    // transport won't fall back to `application/json`.
    assert_eq!(req.content_type, Some(spec.content_type()));
    // Nothing was sent by merely constructing the request.
    assert!(transport.captured.lock().unwrap().is_empty());
}

#[test]
fn wrangler_fallback_command_names_script_and_compat_date() {
    let spec = GatewayWorkerSpec::new("export default {};");
    let cmd = spec.wrangler_deploy_command();
    assert!(cmd.contains("wrangler deploy"));
    assert!(cmd.contains("ferrogate-agent-gateway"));
    assert!(cmd.contains("2025-06-01"));
}
