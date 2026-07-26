// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Built-in gateway tools (issue #257). Today this is the
// `fetch_asset` tool that closes the publish -> govern -> agent-consume loop by
// letting a tool-only MCP client pull a hosted asset (#176/#177) through the
// SAME governed tool-execution chokepoint as every other tool. The asset->
// resource URI mapping and content shaping is shared with the native MCP
// `resources/list` / `resources/read` ingress so both surfaces agree on the
// `asset://{asset_type}/{name}/{version}` addressing and metadata.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde_json::{json, Value};
use std::time::Instant;

use ferrogate_core::ApprovalPolicy;
use ferrogate_storage::{stored_asset_id, StoredAsset};

use crate::auth::AuthContext;
use crate::extensions::{
    RegisteredTool, ToolExecutionError, ToolExecutionRequest, ToolExecutionResponse,
};
use crate::state::{AppState, AssetReadError};

/// The single built-in tool name. Namespaced with a `builtin.` prefix so it can
/// never collide with an MCP `serverName-toolName` (which the chokepoint splits
/// on `-`) or an extension/plugin tool id.
pub(crate) const FETCH_ASSET_TOOL_NAME: &str = "builtin.fetch_asset";

/// The scope a caller must hold to see or fetch assets -- the EXACT scope
/// `handle_asset_list` / `handle_asset_pull` authenticate with, reused here so
/// `fetch_asset` inherits their visibility rather than inventing a new path.
pub(crate) const ASSET_READ_SCOPE: &str = "assets.read";

/// The full built-in tool registry. Kept tiny and allocation-cheap so callers
/// can materialize it on demand instead of threading yet another handle through
/// `AppState`.
pub(crate) fn builtin_tools() -> Vec<RegisteredTool> {
    vec![fetch_asset_tool()]
}

pub(crate) fn is_builtin_tool(name: &str) -> bool {
    name == FETCH_ASSET_TOOL_NAME
}

pub(crate) fn builtin_tool_by_name(name: &str) -> Option<RegisteredTool> {
    is_builtin_tool(name).then(fetch_asset_tool)
}

fn fetch_asset_tool() -> RegisteredTool {
    RegisteredTool {
        name: FETCH_ASSET_TOOL_NAME.to_string(),
        description: Some(
            "Fetch a governed hosted asset by its asset:// URI (or asset_type/name/version) \
             and return its content with the stored sha256 fingerprint. Visibility is scoped \
             to the calling key's tenant and requires the assets.read scope."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "uri": {
                    "type": "string",
                    "description": "asset://{asset_type}/{name}/{version}"
                },
                "asset_type": { "type": "string" },
                "name": { "type": "string" },
                "version": { "type": "string" }
            },
            "additionalProperties": false
        }),
        // The built-in tool has no owning extension/MCP server; `builtin` marks
        // its provenance without matching the `mcp.` prefix `mcp_tools_for`
        // filters on.
        extension_id: "builtin".to_string(),
        // Approval is driven by managed-action guardrails at the chokepoint
        // (RequireApproval), same as any other tool; the tool itself does not
        // hard-require approval.
        approval_policy: ApprovalPolicy::Never,
        tenant_allowlist: Vec::new(),
        api_key_allowlist: Vec::new(),
        route_allowlist: Vec::new(),
    }
}

/// The canonical resource URI for an asset, shared by `resources/list`,
/// `resources/read`, and `fetch_asset`.
pub(crate) fn asset_uri(asset_type: &str, name: &str, version: &str) -> String {
    format!("asset://{asset_type}/{name}/{version}")
}

/// Parse `asset://{asset_type}/{name}/{version}` back into its three segments.
/// Returns `None` for any malformed URI (wrong scheme, wrong arity, or an empty
/// segment) so callers can fail closed with a clear error.
pub(crate) fn parse_asset_uri(uri: &str) -> Option<(String, String, String)> {
    let rest = uri.strip_prefix("asset://")?;
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    Some((
        segments[0].to_string(),
        segments[1].to_string(),
        segments[2].to_string(),
    ))
}

/// The `resources/list` descriptor for an asset: the addressing URI plus the
/// content metadata (mime type, size, sha256) an agent needs to decide whether
/// to read it.
pub(crate) fn asset_resource_descriptor(asset: &StoredAsset) -> Value {
    json!({
        "uri": asset_uri(&asset.asset_type, &asset.name, &asset.version),
        "name": format!("{}/{}/{}", asset.asset_type, asset.name, asset.version),
        "description": format!(
            "{} asset {} version {}",
            asset.asset_type, asset.name, asset.version
        ),
        "mimeType": asset.content_type,
        "size": asset.size_bytes,
        "_meta": {
            "assetType": asset.asset_type,
            "assetName": asset.name,
            "version": asset.version,
            "sha256": asset.content_hash,
            "sizeBytes": asset.size_bytes,
            "storageBacked": asset.storage_uri.is_some(),
        }
    })
}

/// A single MCP resource-contents entry for an asset's verified bytes. Textual
/// content is inlined as `text`; anything else is inlined as base64 `blob` --
/// which costs ~1.33x the object, on top of the bytes themselves and the
/// `serde_json` copy of the encoded string.
///
/// Inlining is only acceptable because the caller has already been through
/// [`AppState::read_asset_content`](crate::state::AppState::read_asset_content),
/// which refuses anything above `[asset_bucket].max_gateway_buffer_bytes`
/// (10 MiB by default). Issue #259 removed the flat 10 MB asset cap this used
/// to lean on, so the bound is now the memory budget, not the asset size limit:
/// larger assets are served by presigned direct download, not inlined here.
pub(crate) fn asset_resource_content_entry(asset: &StoredAsset, content: &[u8]) -> Value {
    let uri = asset_uri(&asset.asset_type, &asset.name, &asset.version);
    let mut entry = json!({
        "uri": uri,
        "mimeType": asset.content_type,
        "_meta": {
            "sha256": asset.content_hash,
            "sizeBytes": asset.size_bytes,
        }
    });
    match textual_content(&asset.content_type, content) {
        Some(text) => {
            entry["text"] = json!(text);
        }
        None => {
            entry["blob"] = json!(BASE64_STANDARD.encode(content));
        }
    }
    entry
}

fn textual_content(content_type: &str, content: &[u8]) -> Option<String> {
    if !looks_textual(content_type) {
        return None;
    }
    std::str::from_utf8(content).ok().map(ToOwned::to_owned)
}

fn looks_textual(content_type: &str) -> bool {
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    content_type.starts_with("text/")
        || matches!(
            content_type.as_str(),
            "application/json"
                | "application/xml"
                | "application/yaml"
                | "application/x-yaml"
                | "application/toml"
                | "application/javascript"
                | "application/x-ndjson"
                | "image/svg+xml"
        )
        || content_type.ends_with("+json")
        || content_type.ends_with("+xml")
}

/// Execute the `fetch_asset` built-in tool. Called ONLY from the governed
/// tool-execution chokepoint (`execute_tool_request_with_governance`), so the
/// approval gate, managed-action guardrails, and audit trail wrap this exactly
/// as they wrap every other tool backend. Visibility here mirrors
/// `handle_asset_pull`: the `assets.read` scope plus a tenant-attributed key,
/// with tenant scoping applied through `stored_asset_id`.
pub(crate) async fn execute_fetch_asset(
    state: &AppState,
    auth: &AuthContext,
    request: &ToolExecutionRequest,
    request_id: &str,
) -> Result<ToolExecutionResponse, ToolExecutionError> {
    let started = Instant::now();

    if !auth.has_scope(ASSET_READ_SCOPE) {
        return Err(ToolExecutionError::Denied(format!(
            "{FETCH_ASSET_TOOL_NAME} requires the {ASSET_READ_SCOPE} scope"
        )));
    }
    let Some(tenant_id) = auth.organization_id.as_deref() else {
        return Err(ToolExecutionError::Denied(
            "assets require a tenant-attributed API key".to_string(),
        ));
    };

    let (asset_type, name, version) = asset_coordinates(&request.arguments).ok_or_else(|| {
        ToolExecutionError::Failed(
            "fetch_asset requires either a `uri` of the form asset://{asset_type}/{name}/{version} \
             or explicit `asset_type`, `name`, and `version` arguments"
                .to_string(),
        )
    })?;

    let id = stored_asset_id(tenant_id, &asset_type, &name, &version);
    match state.read_asset_content(&id, request_id).await {
        Ok((asset, content)) => {
            let latency_ms = elapsed_ms(started);
            let entry = asset_resource_content_entry(&asset, &content);
            let content = json!({
                "content": [
                    { "type": "resource", "resource": entry }
                ],
                "_meta": {
                    "uri": asset_uri(&asset.asset_type, &asset.name, &asset.version),
                    "sha256": asset.content_hash,
                    "sizeBytes": asset.size_bytes,
                    "contentType": asset.content_type,
                }
            });
            Ok(ToolExecutionResponse {
                object: "tool_execution",
                name: request.name.clone(),
                content,
                is_error: false,
                request_id: request_id.to_string(),
                session_id: request.session_id.clone(),
                latency_ms,
            })
        }
        Err(AssetReadError::NotFound) => Err(ToolExecutionError::NotFound(format!(
            "no asset at {asset_type}/{name}/{version}"
        ))),
        Err(AssetReadError::Integrity) => Err(ToolExecutionError::Failed(
            "stored asset content hash does not match recorded hash".to_string(),
        )),
        // Issue #259: an agent asking for a 5 GiB object over this tool used to
        // get it -- the full object, a second pass to re-hash it, and a ~1.33x
        // base64 copy on top. It now gets the refusal and the endpoint that
        // does work without the gateway in the data path.
        Err(AssetReadError::TooLarge(message)) => Err(ToolExecutionError::Failed(message)),
        Err(AssetReadError::BucketUnavailable(message)) => Err(ToolExecutionError::Failed(message)),
        Err(AssetReadError::Storage(message)) => Err(ToolExecutionError::Failed(message)),
    }
}

/// Resolve the `(asset_type, name, version)` triple from the tool arguments.
/// A `uri` argument wins; otherwise the three explicit fields are required.
fn asset_coordinates(arguments: &Value) -> Option<(String, String, String)> {
    if let Some(uri) = arguments.get("uri").and_then(Value::as_str) {
        return parse_asset_uri(uri);
    }
    let asset_type = non_empty(arguments.get("asset_type"))?;
    let name = non_empty(arguments.get("name"))?;
    let version = non_empty(arguments.get("version"))?;
    Some((asset_type, name, version))
}

fn non_empty(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
#[path = "builtin_tools_test.rs"]
mod builtin_tools_test;
