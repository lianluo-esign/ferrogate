// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the asset command families (#363): registration order, verb →
//! operationId/method/path resolution, composite-key and query-param request
//! building against a fake transport, presigned-URL redaction, and
//! error/exit-class mapping. Pure logic and a fake transport — no live network.

use super::*;
use crate::action_identity::ClientActionIdentity;
use crate::auth::AuthSource;
use crate::command::{CommandGroup, SecretDisclosure};
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::dispatch::build_request;
use crate::dispatch::redact_response;
use crate::error::{CliResult, ExitClass};
use crate::output::OutputFormat;
use crate::registry_helpers::ResourceInput;
use crate::resource::{redact_secret_fields, ListParams};
use crate::transport::{
    ControlPlaneClient, PageRequest, PreparedRequest, RawResponse, RequestBody, RequestSpec,
    Transport,
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

/// An input satisfying every declared verb across the families: the full
/// composite key plus a `channel`/`version` tail (so `asset-channels set`'s
/// four-segment arity is met) and a body for the write verbs.
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["models", "llama", "stable", "1.2.3"])
        .with_body(serde_json::json!({"size_bytes": 42}))
        // `assets put` takes the artifact's bytes, not a document, so the
        // universal input carries both payload shapes.
        .with_raw_body("application/octet-stream", b"artifact".to_vec())
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["assets", "asset-transfer", "asset-channels", "site-domains"]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (AssetsGroup.descriptor(), build_assets),
        (AssetTransferGroup.descriptor(), build_asset_transfer),
        (AssetChannelsGroup.descriptor(), build_asset_channels),
        (SiteDomainsGroup.descriptor(), build_site_domains),
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
        "listAssets",
        "listAssetsByType",
        "getAsset",
        "putAsset",
        "deleteAsset",
        "getAssetManifest",
        "getAssetStorageSummary",
        "listWithheldAssets",
        "promoteAssetVisibility",
        "yankAssetVersion",
        "unyankAssetVersion",
        "createAssetUploadIntent",
        "commitAssetUpload",
        "abortAssetUpload",
        "getAssetDownloadUrl",
        "listAssetChannels",
        "putAssetChannel",
        "deleteAssetChannel",
        "listSiteDomains",
        "getSiteDomain",
        "bindSiteDomain",
        "verifySiteDomain",
        "unbindSiteDomain",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 11 (assets) + 4 (transfer) + 3 (channels) + 5 (site-domains) = 23 ids.
    assert_eq!(manifest.len(), 23);
}

#[test]
fn every_operation_id_exists_in_the_openapi_contract() {
    // The declared operationIds are what the #365 parity gate diffs against the
    // contract, so a typo here would silently break coverage. Assert each one
    // is a real operationId in the shipped OpenAPI document.
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
fn asset_item_verbs_use_the_composite_key() {
    let key = ResourceInput::new().with_segments(["models", "llama", "1.2.3"]);

    let get = build_assets("get", &key).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/v1/assets/models/llama/1.2.3");

    let delete = build_assets("delete", &key).unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert_eq!(delete.path, "/v1/assets/models/llama/1.2.3");

    let put = build_assets(
        "put",
        &key.clone()
            .with_raw_body("application/octet-stream", b"artifact".to_vec()),
    )
    .unwrap();
    assert_eq!(put.method, Method::PUT);
    assert_eq!(put.path, "/v1/assets/models/llama/1.2.3");
    assert_eq!(
        put.body,
        Some(RequestBody::Bytes {
            media_type: "application/octet-stream".to_string(),
            bytes: b"artifact".to_vec(),
        })
    );
}

#[test]
fn asset_list_reads_and_manifest_and_storage_summary() {
    let list = build_assets("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/v1/assets");

    let by_type = build_assets(
        "list-by-type",
        &ResourceInput::new().with_segments(["models"]),
    )
    .unwrap();
    assert_eq!(by_type.path, "/v1/assets/models");

    let manifest = build_assets(
        "manifest",
        &ResourceInput::new().with_segments(["models", "llama"]),
    )
    .unwrap();
    assert_eq!(manifest.method, Method::GET);
    assert_eq!(manifest.path, "/v1/assets/models/llama/manifest");

    let summary = build_assets("storage-summary", &ResourceInput::new()).unwrap();
    assert_eq!(summary.method, Method::GET);
    assert_eq!(summary.path, "/v1/assets/storage/summary");
}

#[test]
fn withheld_reads_the_operator_view_and_preserves_filters() {
    use crate::resource::ListParams;

    let withheld = build_assets("withheld", &ResourceInput::new()).unwrap();
    assert_eq!(withheld.method, Method::GET);
    assert_eq!(withheld.path, "/v1/assets/withheld");

    // The contract's `asset_type`/`search` filters ride the query verbatim.
    let filtered = build_assets(
        "withheld",
        &ResourceInput::new().with_list(
            ListParams::new()
                .with_filter("asset_type", "models")
                .with_filter("search", "llama"),
        ),
    )
    .unwrap();
    assert!(filtered
        .query
        .contains(&("asset_type".to_string(), "models".to_string())));
    assert!(filtered
        .query
        .contains(&("search".to_string(), "llama".to_string())));
}

#[test]
fn yank_and_unyank_map_to_the_yank_subpath_with_the_right_method() {
    let key = ResourceInput::new().with_segments(["models", "llama", "1.2.3"]);

    let yank = build_assets("yank", &key).unwrap();
    assert_eq!(yank.method, Method::POST);
    assert_eq!(yank.path, "/v1/assets/models/llama/1.2.3/yank");

    let unyank = build_assets("unyank", &key).unwrap();
    assert_eq!(unyank.method, Method::DELETE);
    assert_eq!(unyank.path, "/v1/assets/models/llama/1.2.3/yank");
    assert!(unyank.body.is_none());
}

#[test]
fn asset_get_without_full_key_is_a_usage_error() {
    let error = build_assets(
        "get",
        &ResourceInput::new().with_segments(["models", "llama"]),
    )
    .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("<asset_type> <name> <version>"));
}

#[test]
fn transfer_verbs_prefix_the_presign_action() {
    let key = ResourceInput::new()
        .with_segments(["models", "llama", "1.2.3"])
        .with_body(serde_json::json!({"sha256": "abc", "size_bytes": 10}));

    let intent = build_asset_transfer("upload-intent", &key).unwrap();
    assert_eq!(intent.method, Method::POST);
    assert_eq!(intent.path, "/v1/assets/presign/upload/models/llama/1.2.3");
    assert!(intent.body.is_some());

    let commit = build_asset_transfer("commit", &key).unwrap();
    assert_eq!(commit.method, Method::POST);
    assert_eq!(commit.path, "/v1/assets/presign/commit/models/llama/1.2.3");

    let download = build_asset_transfer(
        "download-url",
        &ResourceInput::new().with_segments(["models", "llama", "1.2.3"]),
    )
    .unwrap();
    assert_eq!(download.method, Method::GET);
    assert_eq!(
        download.path,
        "/v1/assets/presign/download/models/llama/1.2.3"
    );
    assert!(download.body.is_none());
}

#[test]
fn upload_intent_without_body_is_a_usage_error() {
    let error = build_asset_transfer(
        "upload-intent",
        &ResourceInput::new().with_segments(["models", "llama", "1.2.3"]),
    )
    .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn presigned_urls_are_named_for_redaction() {
    // The transfer responses carry one-time presigned URLs; the declared secret
    // fields must blank them so they never leak into diagnostics.
    let mut body = serde_json::json!({
        "object": "asset_download",
        "download_url": "https://bucket.example.com/signed?sig=SECRET",
        "upload_url": "https://bucket.example.com/put?sig=SECRET",
        "expires_in_seconds": 900
    });
    redact_secret_fields(&mut body, ASSET_TRANSFER_SECRET_FIELDS);
    assert_eq!(body["download_url"], "<redacted>");
    assert_eq!(body["upload_url"], "<redacted>");
    // Non-secret metadata is preserved.
    assert_eq!(body["expires_in_seconds"], 900);
}

/// The regression the #363 review caught: `presigned_urls_are_named_for_redaction`
/// above exercises `redact_secret_fields` in isolation, which is why nobody
/// noticed that the layer actually wired into the binary — `redact_response` —
/// blanked `download-url`'s own payload. This drives that layer, through the
/// verb's declared disclosure, exactly as `read_output` does.
#[test]
fn download_url_response_survives_redaction_but_a_plain_read_does_not() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();

    let download_spec = build_asset_transfer(
        "download-url",
        &ResourceInput::new().with_segments(["models", "llama", "1.2.3"]),
    )
    .unwrap();
    let download_verb = registry.resolve("asset-transfer", "download-url").unwrap();
    assert_eq!(download_spec.method, Method::GET);
    let mut body = serde_json::json!({
        "download_url": "https://bucket.example.com/signed?sig=GRANT",
        "expires_in_seconds": 900
    });
    redact_response(
        "asset-transfer",
        download_verb.secret_disclosure(),
        &download_spec,
        &mut body,
    );
    assert_eq!(
        body["download_url"], "https://bucket.example.com/signed?sig=GRANT",
        "download-url's only load-bearing field must reach the operator; \
         blanking it leaves a verb that cannot perform its operation"
    );
    assert_eq!(body["expires_in_seconds"], 900);

    // The exception is scoped to the issuing verb, not to the group: a read
    // that merely echoes a stored URL is still blanked.
    let echo_spec = RequestSpec::new(
        Method::GET,
        "/v1/assets/presign/download/models/llama/1.2.3",
    );
    let mut echoed = serde_json::json!({"download_url": "https://bucket.example.com/x?sig=ECHO"});
    redact_response(
        "asset-transfer",
        SecretDisclosure::Redacted,
        &echo_spec,
        &mut echoed,
    );
    assert_eq!(echoed["download_url"], "<redacted>");
}

/// `getAsset`'s body is `*/*` binary. Declaring it a structured read is what
/// turned every non-UTF-8 byte into U+FFFD on the way to stdout.
#[test]
fn asset_get_is_a_byte_faithful_read_and_forwards_the_platform_filter() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let verb = registry.resolve("assets", "get").unwrap();
    assert_eq!(
        verb.raw_response_media_type(),
        Some("*/*"),
        "asset bytes must bypass the structured renderer"
    );

    // `platform` is the contract's disambiguator for a multi-variant asset; it
    // reaches the CLI as a filter and used to be dropped on the floor.
    let spec = build_assets(
        "get",
        &ResourceInput::new()
            .with_segments(["cli_tool", "mytool", "1.0.0"])
            .with_list(ListParams::new().with_filter("platform", "linux-x64")),
    )
    .unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/v1/assets/cli_tool/mytool/1.0.0");
    assert_eq!(
        spec.query,
        vec![("platform".to_string(), "linux-x64".to_string())]
    );
}

/// The parity gate was green only because this issue's own gap was whitelisted.
#[test]
fn visibility_promotion_is_a_real_verb_not_a_parity_exclusion() {
    let spec = build_assets(
        "promote-visibility",
        &ResourceInput::new()
            .with_segments(["cli_tool", "mytool", "1.0.0"])
            .with_body(serde_json::json!({"visibility": "public"})),
    )
    .unwrap();
    assert_eq!(spec.method, Method::POST);
    assert_eq!(spec.path, "/v1/assets/cli_tool/mytool/1.0.0/visibility");
    assert!(spec.body.is_some());
    assert!(
        !crate::parity::REVIEWED_EXCLUSIONS
            .iter()
            .any(|exclusion| exclusion.operation_id == "promoteAssetVisibility"),
        "the verb exists now, so the gate must cover it rather than excuse it"
    );
}

#[test]
fn channel_set_puts_with_version_query_and_no_body() {
    let spec = build_asset_channels(
        "set",
        &ResourceInput::new().with_segments(["models", "llama", "stable", "1.2.3"]),
    )
    .unwrap();
    assert_eq!(spec.method, Method::PUT);
    assert_eq!(spec.path, "/v1/assets/models/llama/channels/stable");
    assert!(spec.body.is_none());

    // The target version rides the contract's ?version= query parameter, so it
    // reaches the server as the URL query, not a request body.
    let (transport, seen) = fake(200, br#"{"channel":"stable","version":"1.2.3"}"#);
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    block_on(client.send(&spec)).unwrap();
    let seen = seen.lock().unwrap().clone().unwrap();
    assert!(
        seen.url.contains("version=1.2.3"),
        "expected version query in {}",
        seen.url
    );
}

#[test]
fn channel_list_and_delete_map_to_the_channels_subpath() {
    let list = build_asset_channels(
        "list",
        &ResourceInput::new().with_segments(["models", "llama"]),
    )
    .unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/v1/assets/models/llama/channels");

    let delete = build_asset_channels(
        "delete",
        &ResourceInput::new().with_segments(["models", "llama", "stable"]),
    )
    .unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert_eq!(delete.path, "/v1/assets/models/llama/channels/stable");
}

#[test]
fn channel_set_without_version_is_a_usage_error() {
    let error = build_asset_channels(
        "set",
        &ResourceInput::new().with_segments(["models", "llama", "stable"]),
    )
    .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("<asset_type> <name> <channel> <version>"));
}

#[test]
fn site_domain_verbs_map_to_the_admin_collection() {
    let list = build_site_domains("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/site-domains");

    let bind = build_site_domains(
        "bind",
        &ResourceInput::new().with_body(serde_json::json!({"hostname": "app.example.com"})),
    )
    .unwrap();
    assert_eq!(bind.method, Method::POST);
    assert_eq!(bind.path, "/admin/v1/site-domains");

    let get = build_site_domains(
        "get",
        &ResourceInput::new().with_segments(["app.example.com"]),
    )
    .unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/site-domains/app.example.com");

    // #488: redeeming the DNS ownership challenge is a POST action sub-path.
    let verify = build_site_domains(
        "verify",
        &ResourceInput::new().with_segments(["app.example.com"]),
    )
    .unwrap();
    assert_eq!(verify.method, Method::POST);
    assert_eq!(verify.path, "/admin/v1/site-domains/app.example.com/verify");

    let unbind = build_site_domains(
        "unbind",
        &ResourceInput::new().with_segments(["app.example.com"]),
    )
    .unwrap();
    assert_eq!(unbind.method, Method::DELETE);
    assert_eq!(unbind.path, "/admin/v1/site-domains/app.example.com");
}

#[test]
fn site_domain_unbind_without_hostname_is_a_usage_error() {
    let error = build_site_domains("unbind", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn signature_rejection_on_put_maps_to_validation_class() {
    let spec = build_assets(
        "put",
        &ResourceInput::new()
            .with_segments(["models", "llama", "1.2.3"])
            .with_raw_body("application/octet-stream", b"artifact".to_vec()),
    )
    .unwrap();
    let (transport, _seen) = fake(
        422,
        br#"{"error":{"message":"asset signature verification failed","type":"ferrogate_error","code":"unprocessable_entity","request_id":"fgadm-sig"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Validation);
}

#[test]
fn expired_presigned_transfer_maps_to_not_found_conflict_class() {
    let spec = build_asset_transfer(
        "commit",
        &ResourceInput::new()
            .with_segments(["models", "llama", "1.2.3"])
            .with_body(serde_json::json!({"upload_id": "u1"})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        409,
        br#"{"error":{"message":"presigned upload expired","type":"ferrogate_error","code":"conflict","request_id":"fgadm-exp"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}

#[test]
fn quota_denial_on_upload_intent_maps_to_its_class() {
    let spec = build_asset_transfer(
        "upload-intent",
        &ResourceInput::new()
            .with_segments(["models", "llama", "1.2.3"])
            .with_body(serde_json::json!({"size_bytes": 999999999})),
    )
    .unwrap();
    // A storage quota denial surfaces as 403 forbidden and must fail closed on
    // the auth/authorization exit class rather than being mistaken for success.
    let (transport, _seen) = fake(
        403,
        br#"{"error":{"message":"asset storage quota exceeded","type":"ferrogate_error","code":"forbidden","request_id":"fgadm-q"}}"#,
    );
    let client =
        ControlPlaneClient::new(context(), None, transport, ClientActionIdentity::fixture());
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}

/// The destructive sibling of the `get` fix. `deleteAsset` declares `platform`,
/// and dropping it does not fail the call — the server resolves some other
/// variant, destroys it, and the operator sees exit 0 with no diagnostic.
#[test]
fn asset_delete_forwards_the_platform_filter() {
    let spec = build_assets(
        "delete",
        &ResourceInput::new()
            .with_segments(["cli_tool", "mytool", "1.0.0"])
            .with_list(ListParams::new().with_filter("platform", "linux-x64")),
    )
    .unwrap();
    assert_eq!(spec.method, Method::DELETE);
    assert_eq!(spec.path, "/v1/assets/cli_tool/mytool/1.0.0");
    assert_eq!(
        spec.query,
        vec![("platform".to_string(), "linux-x64".to_string())]
    );
}

/// `putAsset`'s body is the artifact. Publishing must send the bytes verbatim
/// and carry both query parameters the operation declares.
#[test]
fn asset_put_publishes_bytes_and_forwards_platform_and_channel() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let verb = registry.resolve("assets", "put").unwrap();
    assert_eq!(
        verb.raw_request_media_type(),
        Some("application/octet-stream"),
        "the publish body is opaque bytes, not a JSON document"
    );

    // Deliberately not valid UTF-8: a document-shaped path would have to lose
    // or re-encode these bytes.
    let artifact = vec![0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe];
    let spec = build_assets(
        "put",
        &ResourceInput::new()
            .with_segments(["static_site", "docs", "1.0.0"])
            .with_raw_body("application/zip", artifact.clone())
            .with_list(
                ListParams::new()
                    .with_filter("platform", "linux-x64")
                    .with_filter("channel", "stable"),
            ),
    )
    .unwrap();
    assert_eq!(spec.method, Method::PUT);
    assert_eq!(spec.path, "/v1/assets/static_site/docs/1.0.0");
    assert_eq!(
        spec.body,
        Some(RequestBody::Bytes {
            media_type: "application/zip".to_string(),
            bytes: artifact,
        })
    );
    assert_eq!(
        spec.query,
        vec![
            ("platform".to_string(), "linux-x64".to_string()),
            ("channel".to_string(), "stable".to_string()),
        ]
    );
}

/// A mutation carries the operator's filters and nothing else. `--limit`/
/// `--sort` are list-walking state; putting them on a `POST` would make a
/// mutating verb look like a paginated read.
#[test]
fn promote_visibility_carries_filters_but_not_pagination_or_sort() {
    let spec = build_assets(
        "promote-visibility",
        &ResourceInput::new()
            .with_segments(["cli_tool", "mytool", "1.0.0"])
            .with_body(serde_json::json!({"scan_outcome": "clean", "evidence": "ev_1"}))
            .with_list(
                ListParams::new()
                    .with_filter("platform", "linux-x64")
                    .with_page(PageRequest {
                        offset: 0,
                        limit: Some(5),
                    })
                    .with_sort("created_at"),
            ),
    )
    .unwrap();
    assert_eq!(spec.method, Method::POST);
    assert_eq!(
        spec.path, "/v1/assets/cli_tool/mytool/1.0.0/visibility",
        "the visibility promotion posts to its own sub-path"
    );
    assert_eq!(
        spec.query,
        vec![("platform".to_string(), "linux-x64".to_string())],
        "only the variant selector belongs on a mutation"
    );
}

/// Static-site publish is `assets put` plus the header parameters `putAsset`
/// declares for it — there is no separate publish operation in the contract, so
/// there must be no invented verb either. The header seam is generic and folded
/// on centrally, so this holds for every family.
#[test]
fn static_site_publish_carries_the_site_headers_through_the_generic_seam() {
    let spec = build_request(
        "assets",
        "put",
        &ResourceInput::new()
            .with_segments(["static_site", "docs", "2.0.0"])
            .with_raw_body("application/zip", b"PK\x03\x04".to_vec())
            .with_headers([
                ("x-site-public", "true"),
                ("x-site-spa-fallback", "true"),
                ("x-asset-visibility", "public"),
            ]),
    )
    .unwrap();
    assert_eq!(spec.method, Method::PUT);
    assert_eq!(
        spec.headers,
        vec![
            ("x-site-public".to_string(), "true".to_string()),
            ("x-site-spa-fallback".to_string(), "true".to_string()),
            ("x-asset-visibility".to_string(), "public".to_string()),
        ]
    );
}

/// `verifySiteDomain` declares `tenant`; the sweep found it discarding it.
#[test]
fn site_domain_verify_forwards_the_tenant_filter() {
    let spec = build_site_domains(
        "verify",
        &ResourceInput::new()
            .with_segments(["docs.example.com"])
            .with_list(ListParams::new().with_filter("tenant", "acme")),
    )
    .unwrap();
    assert_eq!(spec.method, Method::POST);
    assert_eq!(spec.query, vec![("tenant".to_string(), "acme".to_string())]);
}
