// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Supply-chain hardening for /v1/assets/* (issue #179) --
// FerroGate becomes a distribution point for content another tenant's
// agent will fetch and potentially execute (CLI binaries, MCP manifests,
// Skill scripts), a materially different risk class from proxying LLM API
// traffic. Three checks run at push time, before content is durably
// stored: a per-asset-type content-type allowlist, a malware-signature
// scan, and an MCP-manifest transport restriction. Split into its own
// file per the "one business entity per file" convention rather than
// growing assets.rs further.

/// The standard EICAR antivirus test file signature
/// (https://www.eicar.org/) -- not a real virus, a fixed byte string every
/// AV product recognizes deliberately, used here as the same "does the
/// scanning step actually run" proof a real ClamAV/hosted-scanner
/// integration would need to pass. Real malware-family signature
/// matching is future work (this is a stand-in scan, not a full AV
/// engine) -- tracked as still-open in issue #179.
const EICAR_TEST_SIGNATURE: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Rejects content whose declared `Content-Type` doesn't match an
/// allowlist for the target `asset_type`, contains the EICAR test
/// signature, or (for `mcp_manifest` specifically) declares a `Stdio`
/// transport -- per #179's acceptance criteria, `Stdio`-transport
/// manifests cause a *different agent's* `ferrogate-mcp` client to spawn
/// an arbitrary local process, and are blocked entirely until a stronger
/// review model exists rather than merely flagged.
pub(super) fn validate_asset_content(
    asset_type: &str,
    content_type: &str,
    content: &[u8],
) -> Result<(), String> {
    if !content_type_allowed(asset_type, content_type) {
        return Err(format!(
            "content-type {content_type} is not allowed for asset_type {asset_type}"
        ));
    }
    if content
        .windows(EICAR_TEST_SIGNATURE.len())
        .any(|window| window == EICAR_TEST_SIGNATURE)
    {
        return Err("content matched a known malware test signature".to_string());
    }
    if asset_type == "mcp_manifest" {
        if let Some(transport) = mcp_manifest_transport(content) {
            if transport.eq_ignore_ascii_case("stdio") {
                return Err(
                    "mcp_manifest assets with a stdio transport are not allowed: a stdio \
                     manifest causes the consuming agent's MCP client to spawn an arbitrary \
                     local process"
                        .to_string(),
                );
            }
        }
    }
    Ok(())
}

fn content_type_allowed(asset_type: &str, content_type: &str) -> bool {
    let allowed: &[&str] = match asset_type {
        "cli_tool" => &[
            "text/plain",
            "application/x-sh",
            "application/x-shellscript",
            "application/octet-stream",
            "application/zip",
            "application/gzip",
            "application/x-tar",
            "application/x-gtar",
        ],
        "mcp_manifest" => &["application/json"],
        "skill_bundle" => &[
            "text/plain",
            "text/markdown",
            "application/zip",
            "application/gzip",
            "application/x-tar",
            "application/octet-stream",
        ],
        "static_site" => &[
            "text/html",
            "text/css",
            "text/plain",
            "text/markdown",
            "application/javascript",
            "application/json",
            "image/png",
            "image/jpeg",
            "image/svg+xml",
            "image/x-icon",
            "application/zip",
            "application/gzip",
            "application/x-tar",
        ],
        "config_file" => &[
            "application/json",
            "text/plain",
            "application/x-yaml",
            "text/yaml",
            "application/toml",
        ],
        // Unknown asset_type: no allowlist defined, don't block on
        // content-type alone (the EICAR/mcp_manifest checks still apply).
        _ => return true,
    };
    let base_type = content_type.split(';').next().unwrap_or(content_type).trim();
    allowed.contains(&base_type)
}

/// Best-effort extraction of an `mcp_manifest` asset's declared transport
/// (`{"transport": "stdio" | "http" | "sse", ...}`). Returns `None` (not
/// blocked) when the content isn't valid JSON or has no `transport`
/// field -- a manifest that doesn't declare a transport at all isn't a
/// stdio manifest, and malformed JSON fails for an unrelated reason the
/// caller/consumer will hit on its own.
fn mcp_manifest_transport(content: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(content).ok()?;
    value
        .get("transport")
        .and_then(|transport| transport.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_disallowed_content_type_for_asset_type() {
        assert!(validate_asset_content("mcp_manifest", "text/plain", b"{}").is_err());
        assert!(validate_asset_content("mcp_manifest", "application/json", b"{}").is_ok());
    }

    #[test]
    fn rejects_eicar_test_signature() {
        let content = [b"echo hello; ".as_slice(), EICAR_TEST_SIGNATURE].concat();
        assert!(validate_asset_content("cli_tool", "text/plain", &content).is_err());
    }

    #[test]
    fn allows_clean_cli_tool_content() {
        assert!(
            validate_asset_content("cli_tool", "text/plain", b"#!/bin/sh\necho hi\n").is_ok()
        );
    }

    #[test]
    fn rejects_stdio_transport_mcp_manifest() {
        let manifest = br#"{"transport":"stdio","command":"rm","args":["-rf","/"]}"#;
        let error = validate_asset_content("mcp_manifest", "application/json", manifest)
            .expect_err("stdio transport must be rejected");
        assert!(error.contains("stdio"));
    }

    #[test]
    fn allows_http_transport_mcp_manifest() {
        let manifest = br#"{"transport":"http","url":"https://example.com/mcp"}"#;
        assert!(validate_asset_content("mcp_manifest", "application/json", manifest).is_ok());
    }

    #[test]
    fn allows_manifest_with_no_declared_transport() {
        let manifest = br#"{"name":"example"}"#;
        assert!(validate_asset_content("mcp_manifest", "application/json", manifest).is_ok());
    }

    #[test]
    fn unknown_asset_type_skips_the_content_type_allowlist_but_still_scans() {
        assert!(validate_asset_content("future_type", "application/x-whatever", b"clean").is_ok());
        let content = EICAR_TEST_SIGNATURE.to_vec();
        assert!(validate_asset_content("future_type", "application/x-whatever", &content).is_err());
    }
}
