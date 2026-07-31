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

use super::{
    McpAuthMode, McpSecretsStoreBinding, McpWorkerDeployer, McpWorkerSpec,
    DEFAULT_MCP_AUTH_MODE_BINDING, DEFAULT_MCP_BEARER_SECRET_BINDING,
    DEFAULT_MCP_BEARER_SECRET_NAME, DEFAULT_MCP_SCRIPT_NAME, MCP_MULTIPART_BOUNDARY,
    MCP_WORKER_UPSTREAM_AUTHORIZATION_ENV,
};
use crate::config::{McpAuthType, McpTransport};

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

#[test]
fn metadata_keeps_secret_text_bindings_so_a_redeploy_does_not_strip_the_bearer() {
    // A Script-API PUT replaces the whole binding set, so a `wrangler secret put
    // MCP_BEARER_TOKEN` value survives only because the upload asks for it.
    let meta = McpWorkerSpec::new("export default {};").metadata_json();
    assert_eq!(meta["keep_bindings"][0], "secret_text");
}

#[test]
fn a_store_binding_declared_only_in_wrangler_toml_is_not_preserved_by_a_redeploy() {
    // The chosen resolution of the #409 review's keep_bindings finding, pinned so
    // that changing it is deliberate. `secrets_store_secret` is NOT preserved
    // across a Script-API PUT, so a `[[secrets_store_secrets]]` block that lives
    // only in wrangler.toml is dropped by the next Rust-side deploy — the Worker's
    // env.MCP_BEARER_TOKEN_STORE goes undefined and the automation path silently
    // degrades to OAuth-only. That constraint is documented (workers/mcp-server/
    // README.md + wrangler.toml + docs/cloudflare-mcp-hosting.md) rather than
    // papered over with an undocumented keep_bindings value that could 400 every
    // upload; see DEFAULT_KEEP_BINDINGS.
    let meta = McpWorkerSpec::new("export default {};").metadata_json();
    let kept: Vec<&str> = meta["keep_bindings"]
        .as_array()
        .expect("keep_bindings is an array")
        .iter()
        .map(|kind| kind.as_str().expect("keep_bindings entries are strings"))
        .collect();
    assert_eq!(kept, ["secret_text"]);

    // …and a redeploy that does not declare the binding does not re-send it,
    // which is what makes the erasure reachable in the first place.
    let bindings = meta["bindings"].as_array().expect("bindings is an array");
    assert!(
        bindings
            .iter()
            .all(|binding| binding["type"] != "secrets_store_secret"),
        "a spec with no declared store binding must not emit one: {bindings:?}"
    );
}

#[test]
fn a_secrets_store_binding_is_declared_alongside_the_do_and_kv_bindings() {
    let spec = McpWorkerSpec::new("export default {};")
        .with_kv_namespace_id("kv-abc123")
        .with_bearer_token_from_secrets_store("store-9f3");
    let meta = spec.metadata_json();

    // The DO + KV bindings keep their positions; the secret is appended.
    assert_eq!(meta["bindings"][0]["type"], "durable_object_namespace");
    assert_eq!(meta["bindings"][1]["type"], "kv_namespace");

    let secret = &meta["bindings"][2];
    assert_eq!(secret["type"], "secrets_store_secret");
    assert_eq!(secret["name"], DEFAULT_MCP_BEARER_SECRET_BINDING);
    assert_eq!(secret["store_id"], "store-9f3");
    assert_eq!(secret["secret_name"], DEFAULT_MCP_BEARER_SECRET_NAME);
    // …and it reaches the wire, not just the metadata value.
    let body = String::from_utf8(spec.multipart_body()).unwrap();
    assert!(body.contains("secrets_store_secret"));
    assert!(body.contains("store-9f3"));
}

#[test]
fn the_default_bearer_secret_name_is_resolvable_through_the_cf_seam() {
    // The whole point of pinning a canonical name: the same Secrets Store secret
    // the Worker binds must also be addressable as `cf://<store>/<name>` from the
    // gateway, whose env convention is only injective on canonical names (#423).
    assert!(ferrogate_secrets::cf_binding_name_is_unambiguous(
        DEFAULT_MCP_BEARER_SECRET_NAME
    ));
}

#[test]
fn a_secrets_store_binding_without_a_store_id_is_refused_before_the_request_is_built() {
    let transport = CapturingTransport::new(ok(200, "{}"));
    let deployer = deployer(transport.clone());
    let spec = McpWorkerSpec::new("export default {};").with_bearer_token_from_secrets_store("");

    let err = deployer.build_deploy_request(&spec).unwrap_err();
    assert!(
        matches!(&err, CloudflareError::Config(message) if message.contains("store_id")),
        "expected a typed config error naming the missing field, got {err:?}"
    );
    assert!(transport.captured.lock().unwrap().is_empty());
}

#[test]
fn a_non_canonical_secret_name_is_refused_with_the_variable_it_would_collide_on() {
    let spec = McpWorkerSpec::new("export default {};").with_secrets_store_binding(
        McpSecretsStoreBinding {
            binding_name: "MCP_BEARER_TOKEN_STORE".to_string(),
            store_id: "store-9f3".to_string(),
            secret_name: "MCP.Bearer_Token".to_string(),
        },
    );

    let err = spec.validate().unwrap_err();
    let CloudflareError::Config(message) = &err else {
        panic!("expected a config error, got {err:?}");
    };
    assert!(
        message.contains("FERROGATE_CF_SECRET_MCP_BEARER_TOKEN"),
        "the error must name the ambiguous variable: {message}"
    );
}

#[test]
fn an_empty_secret_name_is_refused_as_missing_rather_than_as_non_canonical() {
    // "" is not "the wrong shape", it is "not filled in". Reporting the canonical
    // [a-z0-9-]+ rule for it sends the operator off to fix a name they never wrote.
    let spec = McpWorkerSpec::new("export default {};").with_secrets_store_binding(
        McpSecretsStoreBinding {
            binding_name: "MCP_BEARER_TOKEN_STORE".to_string(),
            store_id: "store-9f3".to_string(),
            secret_name: "   ".to_string(),
        },
    );

    let err = spec.validate().unwrap_err();
    let CloudflareError::Config(message) = &err else {
        panic!("expected a config error, got {err:?}");
    };
    assert!(
        message.contains("has no secret_name"),
        "an absent secret_name must be reported as absent: {message}"
    );
    assert!(
        !message.contains("canonical"),
        "an absent secret_name must not be reported as a shape violation: {message}"
    );
}

#[test]
fn binding_fields_reach_cloudflare_trimmed_rather_than_as_typed() {
    // Validating a trimmed value while sending the raw one is how " store-9f3 "
    // passes here and comes back as an opaque Cloudflare 400 naming nothing.
    let spec = McpWorkerSpec::new("export default {};").with_secrets_store_binding(
        McpSecretsStoreBinding {
            binding_name: " MCP_BEARER_TOKEN_STORE ".to_string(),
            store_id: " store-9f3 ".to_string(),
            secret_name: " mcp-bearer-token ".to_string(),
        },
    );

    spec.validate().unwrap();
    let secret = &spec.metadata_json()["bindings"][2];
    assert_eq!(secret["name"], "MCP_BEARER_TOKEN_STORE");
    assert_eq!(secret["store_id"], "store-9f3");
    assert_eq!(secret["secret_name"], "mcp-bearer-token");
}

#[test]
fn a_binding_name_colliding_with_the_do_or_kv_binding_is_refused() {
    // bindings[] is a flat name-keyed list, so a duplicate makes which binding
    // env.<NAME> resolves to Cloudflare's choice rather than ours.
    let collides_with_kv = McpWorkerSpec::new("export default {};").with_secrets_store_binding(
        McpSecretsStoreBinding {
            binding_name: "OAUTH_KV".to_string(),
            store_id: "store-9f3".to_string(),
            secret_name: "mcp-bearer-token".to_string(),
        },
    );
    let err = collides_with_kv.validate().unwrap_err();
    assert!(
        matches!(&err, CloudflareError::Config(message) if message.contains("OAUTH_KV")),
        "the error must name the binding that collided, got {err:?}"
    );

    // Two secrets sharing a name collide with each other, not just with DO/KV.
    let duplicate_secrets = McpWorkerSpec::new("export default {};")
        .with_bearer_token_from_secrets_store("store-9f3")
        .with_bearer_token_from_secrets_store("store-other");
    let err = duplicate_secrets.validate().unwrap_err();
    assert!(
        matches!(
            &err,
            CloudflareError::Config(message) if message.contains(DEFAULT_MCP_BEARER_SECRET_BINDING)
        ),
        "the error must name the duplicated binding, got {err:?}"
    );

    // The default spec plus one bearer binding is still accepted.
    McpWorkerSpec::new("export default {};")
        .with_bearer_token_from_secrets_store("store-9f3")
        .validate()
        .unwrap();
}

#[test]
fn deploy_reports_the_mcp_url_when_the_workers_dev_subdomain_is_known() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":{"id":"ferrogate-mcp-server"}}"#,
    ));
    let deployer = deployer(transport.clone());
    let spec = McpWorkerSpec::new("export default {};").with_workers_dev_subdomain("acme");

    let outcome = runtime().block_on(deployer.deploy(&spec)).unwrap();
    assert_eq!(outcome.script_name, "ferrogate-mcp-server");
    // Exactly the shape the #408 upstream detector accepts.
    assert_eq!(
        outcome.mcp_url.as_deref(),
        Some("https://ferrogate-mcp-server.acme.workers.dev/mcp")
    );
}

#[test]
fn an_unknown_subdomain_reports_no_url_rather_than_a_guessed_one() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":{"id":"ferrogate-mcp-server"}}"#,
    ));
    let deployer = deployer(transport.clone());
    let spec = McpWorkerSpec::new("export default {};");

    let outcome = runtime().block_on(deployer.deploy(&spec)).unwrap();
    assert_eq!(outcome.mcp_url, None);
    // A blank subdomain is "unknown", not a host with an empty label.
    assert_eq!(
        McpWorkerSpec::new("export default {};")
            .with_workers_dev_subdomain("   ")
            .mcp_endpoint_url(),
        None
    );
}

#[test]
fn workers_dev_subdomain_reads_the_account_endpoint() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":{"subdomain":"acme"}}"#,
    ));
    let deployer = deployer(transport.clone());

    let subdomain = runtime()
        .block_on(deployer.workers_dev_subdomain())
        .unwrap();
    assert_eq!(subdomain, "acme");
    assert_eq!(transport.last().method, HttpMethod::Get);
    assert!(transport
        .last()
        .url
        .ends_with("/accounts/acct-777/workers/subdomain"));
}

#[test]
fn an_account_without_a_workers_dev_subdomain_is_an_error_not_an_empty_string() {
    // `{"result":{}}` is what an account with workers.dev disabled answers, and it
    // is also what a response whose shape we guessed wrong decodes to. Returning
    // Ok("") from either would surface downstream as "there is just no URL", with
    // nothing pointing at the subdomain lookup as the cause.
    let transport = CapturingTransport::new(ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":{}}"#,
    ));
    let deployer = deployer(transport.clone());

    let err = runtime()
        .block_on(deployer.workers_dev_subdomain())
        .unwrap_err();
    let CloudflareError::Config(message) = &err else {
        panic!("expected a config error, got {err:?}");
    };
    assert!(
        message.contains("workers/subdomain") && message.contains("workers.dev"),
        "the error must name the endpoint and the likely cause: {message}"
    );
}

#[test]
fn status_for_a_spec_carries_the_url_while_status_by_name_stays_silent() {
    let transport = CapturingTransport::new(ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":[{"id":"ferrogate-mcp-server"}]}"#,
    ));
    let deployer = deployer(transport.clone());
    let spec = McpWorkerSpec::new("export default {};").with_workers_dev_subdomain("acme");

    let by_spec = runtime().block_on(deployer.status_for(&spec)).unwrap();
    assert!(by_spec.deployed);
    assert_eq!(
        by_spec.mcp_url.as_deref(),
        Some("https://ferrogate-mcp-server.acme.workers.dev/mcp")
    );

    let by_name = runtime()
        .block_on(deployer.status(DEFAULT_MCP_SCRIPT_NAME))
        .unwrap();
    assert!(by_name.deployed);
    assert_eq!(by_name.mcp_url, None);
}

#[test]
fn status_for_an_undeployed_script_reports_no_url_even_though_the_spec_knows_one() {
    // A spec carries its subdomain whether or not anything was ever uploaded, so
    // an unconditional fill would report a live-looking endpoint for a script
    // Cloudflare is not hosting — and callers register this field as an upstream.
    let transport = CapturingTransport::new(ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":[{"id":"some-other-script"}]}"#,
    ));
    let deployer = deployer(transport.clone());
    let spec = McpWorkerSpec::new("export default {};").with_workers_dev_subdomain("acme");

    let status = runtime().block_on(deployer.status_for(&spec)).unwrap();
    assert!(!status.deployed);
    assert_eq!(status.mcp_url, None);
    // The spec itself still knows the URL; it is `status_for` that withholds it.
    assert_eq!(
        spec.mcp_endpoint_url().as_deref(),
        Some("https://ferrogate-mcp-server.acme.workers.dev/mcp")
    );
}

// ---------------------------------------------------------------------------
// #409 test-lane additions: the authless variant and the register-back-as-an-
// upstream leg landed in d1a62932 with NO Rust coverage at all ("Not-tested: no
// Worker-side coverage added for the authless route or for `upstream_config`").
// Everything below either drives one of those paths or pins a value that two
// separate artifacts (this crate and workers/mcp-server) must agree on.
// ---------------------------------------------------------------------------

/// The Worker source this crate deploys, read from the repo so a rename on
/// either side of the deploy boundary is a failing test rather than a runtime
/// binding that is simply never read.
fn worker_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../workers/mcp-server/src/index.ts");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read the deployed Worker source at {path:?}: {e}"))
}

#[test]
fn an_authless_deploy_omits_the_oauth_kv_binding_it_would_have_no_namespace_for() {
    // An authless deploy persists no grants. Emitting `OAUTH_KV` anyway would
    // carry the unset namespace id and fail the upload for a reason the operator
    // never asked about.
    let spec = McpWorkerSpec::new("export default {};").authless();
    let meta = spec.metadata_json();
    let bindings = meta["bindings"].as_array().expect("bindings is an array");

    assert!(
        bindings.iter().all(|b| b["type"] != "kv_namespace"),
        "authless must declare no KV binding: {bindings:?}"
    );
    // The DO binding is NOT optional: authless still serves from the DO.
    assert_eq!(bindings[0]["type"], "durable_object_namespace");
    assert_eq!(meta["migrations"]["new_sqlite_classes"][0], "FerroGateMcp");
    // …and it must not reach the wire either, not merely be absent from a view.
    let body = String::from_utf8(spec.multipart_body()).unwrap();
    assert!(!body.contains("kv_namespace"), "authless body: {body}");

    // Setting a namespace id does not resurrect it: the mode decides.
    let with_id = McpWorkerSpec::new("export default {};")
        .authless()
        .with_kv_namespace_id("kv-abc123");
    let body = String::from_utf8(with_id.multipart_body()).unwrap();
    assert!(
        !body.contains("kv-abc123"),
        "authless body leaked a KV id: {body}"
    );

    // The OAuth default keeps it, so the assertion above is about the mode and
    // not about a binding this pipeline stopped emitting entirely.
    let oauth = McpWorkerSpec::new("export default {};").with_kv_namespace_id("kv-abc123");
    assert!(oauth.metadata_json()["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["type"] == "kv_namespace"));
}

#[test]
fn the_auth_mode_reaches_the_worker_as_a_plain_text_binding_in_both_modes() {
    for (mode, wire) in [
        (McpAuthMode::Oauth, "oauth"),
        (McpAuthMode::Authless, "authless"),
    ] {
        let spec = McpWorkerSpec::new("export default {};").with_auth_mode(mode);
        let meta = spec.metadata_json();
        let binding = meta["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == DEFAULT_MCP_AUTH_MODE_BINDING)
            .unwrap_or_else(|| panic!("{wire}: no {DEFAULT_MCP_AUTH_MODE_BINDING} binding"));

        // `plain_text`, not `secret_text`: it carries no credential, and an
        // operator reading the script's bindings must be able to see the mode.
        assert_eq!(binding["type"], "plain_text", "{wire}");
        assert_eq!(binding["text"], wire, "{wire}");
        assert_eq!(mode.as_str(), wire);
        assert_eq!(mode.requires_oauth_kv(), wire == "oauth");
        assert!(String::from_utf8(spec.multipart_body())
            .unwrap()
            .contains(&format!("\"text\":\"{wire}\"")));
    }
    // The default is the guarded mode, so an unspecified deploy is not authless.
    assert_eq!(McpWorkerSpec::new("x").auth_mode, McpAuthMode::Oauth);
}

#[test]
fn the_deployed_worker_reads_exactly_the_binding_names_and_mode_values_this_crate_sends() {
    // These are two separate artifacts: a metadata binding the Worker never reads
    // (or a mode string it compares differently) is inert, and no amount of
    // per-side testing catches it. Both sides are pinned here.
    let source = worker_source();

    for binding in [
        DEFAULT_MCP_AUTH_MODE_BINDING,
        DEFAULT_MCP_BEARER_SECRET_BINDING,
        super::DEFAULT_MCP_DO_BINDING,
        super::DEFAULT_OAUTH_KV_BINDING,
    ] {
        assert!(
            source.contains(&format!("{binding}:")) || source.contains(&format!("{binding}?:")),
            "the deployed Worker declares no env.{binding}, so the deploy metadata binds \
             something nothing reads"
        );
    }
    assert!(
        source.contains(&format!("env.{DEFAULT_MCP_AUTH_MODE_BINDING}")),
        "the Worker must actually branch on the auth-mode binding, not just type it"
    );
    // The mode value is a string comparison on the Worker side; `oauth` is only
    // "everything that is not authless", so `authless` is the one that must match.
    assert!(
        source.contains(&format!("\"{}\"", McpAuthMode::Authless.as_str())),
        "the Worker does not recognise the authless value this crate sends"
    );
    assert!(
        source.contains(&format!("class {}", super::DEFAULT_MCP_DO_CLASS)),
        "the DO class the migration declares does not exist in the deployed module"
    );
}

#[test]
fn an_oauth_deploy_registers_back_as_a_routable_shared_headers_upstream() {
    let spec = McpWorkerSpec::new("export default {};").with_workers_dev_subdomain("acme");
    let config = spec.upstream_config(vec!["*".to_string()]).unwrap();

    assert_eq!(
        config.url.as_deref(),
        Some(spec.mcp_endpoint_url().unwrap().as_str())
    );
    assert_eq!(
        config.url.as_deref(),
        Some("https://ferrogate-mcp-server.acme.workers.dev/mcp")
    );
    assert_eq!(config.transport, McpTransport::StreamableHttp);
    assert_eq!(config.auth_type, McpAuthType::SharedHeaders);
    assert_eq!(config.headers.len(), 1);
    assert_eq!(config.headers[0].name, "Authorization");
    assert_eq!(
        config.headers[0].value_env.as_deref(),
        Some(MCP_WORKER_UPSTREAM_AUTHORIZATION_ENV)
    );
    // A literal value would put the credential in config; only the env indirection
    // is acceptable here.
    assert_eq!(config.headers[0].value, None);

    // "Deployed" and "routable" must be the same fact: the gateway's own
    // validator accepts what this produced.
    crate::config::validate_mcp_server_config(&config).expect("registered upstream must validate");
    // The tool namespace is `serverName-toolName`, so the registered name cannot
    // contain '-' — the default SCRIPT name does.
    assert!(!config.name.contains('-'), "{}", config.name);
    assert_eq!(config.name, "ferrogate_mcp_server");
    assert!(spec.wire_script_name().contains('-'));
}

#[test]
fn an_authless_deploy_registers_with_no_credential_rather_than_an_unusable_header() {
    let config = McpWorkerSpec::new("export default {};")
        .authless()
        .with_workers_dev_subdomain("acme")
        .upstream_config(vec!["echo".to_string()])
        .unwrap();

    assert_eq!(config.auth_type, McpAuthType::None);
    // `auth_type: none` + a static header is a config the validator rejects
    // outright, so an authless registration MUST carry no headers.
    assert!(config.headers.is_empty());
    crate::config::validate_mcp_server_config(&config).expect("authless upstream must validate");
    assert_eq!(config.tools_to_execute, vec!["echo".to_string()]);
}

#[test]
fn the_authorization_the_gateway_sends_is_the_complete_header_value_the_worker_accepts() {
    // The Worker's front door parses `Authorization: Bearer <token>` and rejects
    // anything whose first token is not the `Bearer` scheme. FerroGate substitutes
    // a static header's `value_env` VERBATIM, so the variable must hold the whole
    // header value. This is the write-path/read-path pair that a "the env var is
    // named correctly" assertion would never catch.
    let config = McpWorkerSpec::new("export default {};")
        .with_workers_dev_subdomain("acme")
        .upstream_config(vec!["*".to_string()])
        .unwrap();

    std::env::set_var(MCP_WORKER_UPSTREAM_AUTHORIZATION_ENV, "Bearer s3cret-token");
    let resolved = crate::config::resolved_headers(&config).expect("headers resolve");
    std::env::remove_var(MCP_WORKER_UPSTREAM_AUTHORIZATION_ENV);

    assert_eq!(
        resolved,
        vec![(
            "Authorization".to_string(),
            "Bearer s3cret-token".to_string()
        )]
    );
    let (_, value) = &resolved[0];
    let (scheme, token) = value.split_once(' ').expect("a scheme and a credential");
    assert!(
        scheme.eq_ignore_ascii_case("bearer"),
        "the Worker only accepts the Bearer scheme"
    );
    assert_eq!(
        token, "s3cret-token",
        "the token must reach the Worker unmodified"
    );

    // And an unset variable is a named failure, not a silently empty header.
    let err = crate::config::resolved_headers(&config).unwrap_err();
    assert!(
        format!("{err:#}").contains(MCP_WORKER_UPSTREAM_AUTHORIZATION_ENV),
        "the error must name the variable to set: {err:#}"
    );
}

#[test]
fn a_deployed_server_with_no_known_url_is_refused_registration_rather_than_guessed() {
    let err = McpWorkerSpec::new("export default {};")
        .upstream_config(vec!["*".to_string()])
        .unwrap_err();
    let CloudflareError::Config(message) = &err else {
        panic!("expected a config error, got {err:?}");
    };
    assert!(
        message.contains("workers.dev") && message.contains("with_workers_dev_subdomain"),
        "the error must say how to obtain the URL: {message}"
    );
}

#[test]
fn a_registration_the_gateway_would_reject_fails_at_the_deploy_seam_not_at_load_time() {
    // Execution is deny-by-default: an empty allowlist is not "allow nothing
    // yet", it is a config the gateway refuses. Better to learn that here than
    // from a gateway that will not start after a successful deploy.
    let spec = McpWorkerSpec::new("export default {};").with_workers_dev_subdomain("acme");
    let err = spec.upstream_config(Vec::new()).unwrap_err();
    let CloudflareError::Config(message) = &err else {
        panic!("expected a config error, got {err:?}");
    };
    assert!(
        message.contains("tools_to_execute"),
        "the deploy seam must forward the validator's reason: {message}"
    );
    assert!(
        message.contains("ferrogate-mcp-server"),
        "and name the script: {message}"
    );
}

#[test]
fn the_registered_url_is_the_same_string_deploy_and_status_report() {
    // Three call sites produce "the URL of the deployed server". If they can
    // disagree, an operator registers one thing and monitors another.
    let transport = CapturingTransport::new(ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":{"id":"ferrogate-mcp-server"}}"#,
    ));
    let deploy_client = deployer(transport.clone());
    let spec = McpWorkerSpec::new("export default {};").with_workers_dev_subdomain("acme");
    let rt = runtime();

    let deployed = rt.block_on(deploy_client.deploy(&spec)).unwrap().mcp_url;
    let registered = spec.upstream_config(vec!["*".to_string()]).unwrap().url;
    assert_eq!(deployed, registered);

    let listing = CapturingTransport::new(ok(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":[{"id":"ferrogate-mcp-server"}]}"#,
    ));
    let status_client = deployer(listing);
    let status = rt.block_on(status_client.status_for(&spec)).unwrap();
    assert_eq!(status.mcp_url, registered);
}

#[test]
fn an_empty_script_name_is_refused_before_anything_is_signed_or_sent() {
    // `wrangler.toml`'s name is an operator-typed field; empty, it would PUT to
    // `/workers/scripts/` — a different endpoint entirely.
    let transport = CapturingTransport::new(ok(200, "{}"));
    let deployer = deployer(transport.clone());
    let mut spec = McpWorkerSpec::new("export default {};");
    spec.script_name = "   ".to_string();

    let err = deployer.build_deploy_request(&spec).unwrap_err();
    assert!(
        matches!(&err, CloudflareError::Config(message) if message.contains("script_name")),
        "got {err:?}"
    );
    assert!(transport.captured.lock().unwrap().is_empty());
}

#[test]
fn the_do_binding_class_and_kv_names_reach_cloudflare_trimmed_and_agree_with_the_migration() {
    // A class name that disagrees between the binding and `new_sqlite_classes`
    // declares a migration for a class nothing binds — Cloudflare accepts the
    // upload and the DO is unreachable.
    let mut spec = McpWorkerSpec::new("export default {};").with_kv_namespace_id(" kv-abc123 ");
    spec.do_binding_name = " MCP_OBJECT ".to_string();
    spec.do_class_name = " FerroGateMcp\t".to_string();
    spec.kv_binding_name = " OAUTH_KV ".to_string();

    spec.validate().unwrap();
    let meta = spec.metadata_json();
    assert_eq!(meta["bindings"][0]["name"], "MCP_OBJECT");
    assert_eq!(meta["bindings"][0]["class_name"], "FerroGateMcp");
    assert_eq!(meta["bindings"][1]["name"], "OAUTH_KV");
    assert_eq!(meta["bindings"][1]["namespace_id"], "kv-abc123");
    assert_eq!(
        meta["migrations"]["new_sqlite_classes"][0], meta["bindings"][0]["class_name"],
        "the migrated class and the bound class must be the same string"
    );

    // Untrimmed names must not survive anywhere in the request body either.
    let body = String::from_utf8(spec.multipart_body()).unwrap();
    assert!(!body.contains(" MCP_OBJECT "), "{body}");
    assert!(!body.contains(" kv-abc123 "), "{body}");

    // And the URL the PUT goes to is the trimmed script name, not the typed one.
    let mut padded = McpWorkerSpec::new("export default {};");
    padded.script_name = " tenant-mcp ".to_string();
    let request = deployer(CapturingTransport::new(ok(200, "{}")))
        .build_deploy_request(&padded)
        .unwrap();
    assert!(
        request.url.ends_with("/workers/scripts/tenant-mcp"),
        "{}",
        request.url
    );
}

#[test]
fn a_secret_binding_colliding_with_the_auth_mode_binding_is_refused_too() {
    // MCP_AUTH_MODE shares the flat bindings[] namespace, so a secret named the
    // same would make `env.MCP_AUTH_MODE` Cloudflare's choice — and the mode
    // fails closed, so the silent outcome is "the authless deploy kept OAuth".
    let spec = McpWorkerSpec::new("export default {};").with_secrets_store_binding(
        McpSecretsStoreBinding {
            binding_name: DEFAULT_MCP_AUTH_MODE_BINDING.to_string(),
            store_id: "store-9f3".to_string(),
            secret_name: "mcp-bearer-token".to_string(),
        },
    );
    let err = spec.validate().unwrap_err();
    assert!(
        matches!(&err, CloudflareError::Config(m) if m.contains(DEFAULT_MCP_AUTH_MODE_BINDING)),
        "got {err:?}"
    );

    // In authless mode the KV binding is not emitted, so a secret may legally
    // take that name — the duplicate check must follow what is actually sent.
    McpWorkerSpec::new("export default {};")
        .authless()
        .with_secrets_store_binding(McpSecretsStoreBinding {
            binding_name: "OAUTH_KV".to_string(),
            store_id: "store-9f3".to_string(),
            secret_name: "mcp-bearer-token".to_string(),
        })
        .validate()
        .expect("authless emits no KV binding, so there is nothing to collide with");
}
