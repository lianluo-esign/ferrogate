// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Supply-chain hardening for /v1/assets/* (issues #179 + #261) --
// FerroGate becomes a distribution point for content another tenant's agent
// will fetch and potentially execute (CLI binaries, MCP manifests, Skill
// scripts), a materially different risk class from proxying LLM API traffic.
//
// #179 landed the synchronous push-time checks kept in
// `validate_asset_content` below: a per-asset-type content-type allowlist, a
// stand-in malware-signature scan, and an MCP-manifest transport restriction.
//
// #261 makes the trust bar real. The stand-in EICAR scan becomes the offline
// *default* of a pluggable scanner seam (`asset_scan`) that a deployment can
// swap for ClamAV/hosted-scanner backends; detached publisher signatures are
// verified (`asset_signature`); and a cross-tenant publish passes an approval
// gate (`asset_publish_gate`). `screen_asset_push` is the async orchestrator
// the push handler calls to run all of it and emit a verification manifest.

use http::StatusCode;

use super::asset_publish_gate::{
    evaluate_publish_gate, PublishApprovalEvidence, PublishGateDecision, PublishVisibility,
};
use super::asset_scan::{
    contains_eicar, resolve_scan_outcome, AssetScanConfig, ScanOutcome, ScanState,
};
use super::asset_signature::{
    verify_asset_signature, AssetSignatureInput, PublisherKeyRegistry, SignatureStatus,
    VerificationManifest,
};
use crate::approval::ApprovalStatus;
use ferrogate_storage::AssetVisibility;

/// Rejects content whose declared `Content-Type` doesn't match an allowlist
/// for the target `asset_type`, contains the EICAR test signature, or (for
/// `mcp_manifest` specifically) declares a `Stdio` transport. These are the
/// cheap synchronous gates that run before any async scan -- a `stdio`
/// manifest causes a *different agent's* `ferrogate-mcp` client to spawn an
/// arbitrary local process and is blocked entirely (per #179).
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
    if contains_eicar(content) {
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
    let base_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    allowed.contains(&base_type)
}

/// Best-effort extraction of an `mcp_manifest` asset's declared transport
/// (`{"transport": "stdio" | "http" | "sse", ...}`). Returns `None` (not
/// blocked) when the content isn't valid JSON or has no `transport` field.
fn mcp_manifest_transport(content: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(content).ok()?;
    value
        .get("transport")
        .and_then(|transport| transport.as_str())
        .map(str::to_string)
}

/// Deployment-wide asset-security configuration, resolved from the environment
/// so real scanner/signature backends are opt-in without a control-plane
/// config-schema change (keeping #261's blast radius to the gateway crate).
pub(super) struct AssetSecurityContext {
    scan_config: AssetScanConfig,
    keys: PublisherKeyRegistry,
    /// When set, an unsigned or unverifiable push is rejected (signed-only
    /// mode). Default: unsigned pushes are allowed but labeled `unsigned`.
    require_signature: bool,
}

impl AssetSecurityContext {
    pub(super) fn from_env() -> Self {
        Self {
            scan_config: AssetScanConfig::from_env(),
            keys: PublisherKeyRegistry::from_env(),
            require_signature: matches!(
                std::env::var("FERROGATE_ASSET_REQUIRE_SIGNATURE")
                    .ok()
                    .as_deref(),
                Some("1") | Some("true")
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(
        scan_config: AssetScanConfig,
        keys: PublisherKeyRegistry,
        require_signature: bool,
    ) -> Self {
        Self {
            scan_config,
            keys,
            require_signature,
        }
    }
}

/// Per-request inputs to [`screen_asset_push`].
pub(super) struct AssetPushScreeningRequest<'a> {
    pub(super) asset_id: &'a str,
    pub(super) tenant_id: &'a str,
    pub(super) asset_type: &'a str,
    pub(super) content_type: &'a str,
    pub(super) content: &'a [u8],
    pub(super) content_sha256: &'a str,
    pub(super) signature: Option<AssetSignatureInput>,
    pub(super) visibility: PublishVisibility,
    /// The cross-tenant publish approval on record, if any (`id`, `status`).
    pub(super) approval: Option<(String, ApprovalStatus)>,
    pub(super) now_unix: i64,
}

/// The result of screening a push that is allowed to be stored. `scan_state`
/// may still be non-`Clean` (quarantined/pending) -- meaning the bytes are
/// stored but withheld from consumers until proven clean.
#[derive(Debug)]
pub(super) struct AssetScreening {
    scan_state: ScanState,
    scan_backend: &'static str,
    signature: SignatureStatus,
    gate: PublishGateDecision,
    manifest: VerificationManifest,
    evidence: PublishApprovalEvidence,
}

impl AssetScreening {
    /// Whether the stored asset is visible to consumers right now (clean scan).
    pub(super) fn is_visible(&self) -> bool {
        self.scan_state.is_visible()
    }

    /// The durable [`AssetVisibility`] state to persist on the asset row so the
    /// read path can withhold a still-unproven object (#366). This is the one
    /// mapping from the transient screening `ScanState` to the stored state,
    /// used identically by the inline and the presigned publish path -- the
    /// persisted state is exactly what the download path enforces (#188 guard).
    pub(super) fn visibility(&self) -> AssetVisibility {
        match self.scan_state {
            ScanState::Clean => AssetVisibility::Visible,
            ScanState::PendingScan => AssetVisibility::PendingScan,
            ScanState::Quarantined => AssetVisibility::Quarantined,
        }
    }

    /// The verification manifest, serialized for the response / Admin API.
    pub(super) fn manifest_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.manifest).unwrap_or(serde_json::Value::Null)
    }

    /// A single-line, immutable audit detail capturing every trust decision --
    /// scan, signature, and the cross-tenant approval evidence -- retrievable
    /// via the Admin audit surface.
    pub(super) fn audit_detail(&self) -> String {
        let evidence = serde_json::to_string(&self.evidence).unwrap_or_else(|_| "{}".to_string());
        format!(
            "scan={} backend={} signature={} visibility_gate={} visible={} evidence={evidence}",
            self.scan_state.as_str(),
            self.scan_backend,
            self.signature.label(),
            self.gate.approval_state(),
            self.is_visible(),
        )
    }
}

/// Why a push was rejected outright (never stored). Fail-closed reasons only.
#[derive(Debug)]
pub(super) struct ScreeningRejection {
    pub(super) code: &'static str,
    pub(super) message: String,
    status: StatusCode,
}

impl ScreeningRejection {
    pub(super) fn status(&self) -> StatusCode {
        self.status
    }
}

/// Orchestrate every #261 push-time trust check, fail-closed:
/// 1. synchronous content validation (`validate_asset_content`),
/// 2. detached-signature verification (reject if signed-only and unverified),
/// 3. cross-tenant publish approval gate (reject a cross-tenant push with no
///    terminal approval),
/// 4. malware scan through the pluggable backend -- inline, or deferred to a
///    `pending_scan` state for large objects; `Infected`/fail-closed-unavailable
///    reject, `Quarantine`/`pending_scan` store-but-withhold.
///
/// Returns the resolved [`AssetScreening`] (with a verification manifest) when
/// the asset may be stored, or a [`ScreeningRejection`] when it must not be.
pub(super) async fn screen_asset_push(
    context: &AssetSecurityContext,
    request: AssetPushScreeningRequest<'_>,
) -> Result<AssetScreening, ScreeningRejection> {
    // (1) Cheap synchronous gates first.
    if let Err(message) =
        validate_asset_content(request.asset_type, request.content_type, request.content)
    {
        return Err(ScreeningRejection {
            code: "asset_rejected",
            message,
            status: StatusCode::UNPROCESSABLE_ENTITY,
        });
    }

    // (2) Signature verification.
    let signature = match request.signature {
        Some(input) => verify_asset_signature(request.content, &input, &context.keys),
        None => SignatureStatus::Unsigned,
    };
    if context.require_signature && !signature.is_verified() {
        let detail = match &signature {
            SignatureStatus::Unsigned => {
                "this tenant requires signed assets but no signature was presented".to_string()
            }
            SignatureStatus::Unverified { reason } | SignatureStatus::Invalid { reason } => {
                format!("this tenant requires signed assets: {reason}")
            }
            SignatureStatus::Verified { .. } => unreachable!(),
        };
        return Err(ScreeningRejection {
            code: "asset_signature_required",
            message: detail,
            status: StatusCode::UNPROCESSABLE_ENTITY,
        });
    }

    // (3) Cross-tenant publish approval gate.
    let approval_ref = request
        .approval
        .as_ref()
        .map(|(id, status)| (id.as_str(), *status));
    let gate = evaluate_publish_gate(request.visibility, approval_ref);
    if !gate.permits_visibility() {
        let reason = match &gate {
            PublishGateDecision::Blocked { reason } => reason.clone(),
            _ => "cross-tenant publish is not approved".to_string(),
        };
        return Err(ScreeningRejection {
            code: "cross_tenant_publish_denied",
            message: reason,
            status: StatusCode::FORBIDDEN,
        });
    }

    // (4) Malware scan -- deferred for large objects, inline otherwise.
    let scanner = context.scan_config.build_scanner();
    let scan_backend = scanner.backend_name();
    let scan_state = if context.scan_config.should_defer_scan(request.content.len()) {
        // Large object: admit to `pending_scan` (invisible) and let an
        // out-of-band scan promote it to clean once verified.
        ScanState::PendingScan
    } else {
        let verdict = scanner.scan(request.content).await;
        match resolve_scan_outcome(verdict, context.scan_config.unavailable_policy) {
            ScanOutcome::Admit => ScanState::Clean,
            ScanOutcome::Quarantine(_) => ScanState::Quarantined,
            ScanOutcome::Reject(reason) => {
                return Err(ScreeningRejection {
                    code: "asset_scan_rejected",
                    message: reason,
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                });
            }
        }
    };

    let evidence = PublishApprovalEvidence::from_decision(
        request.asset_id,
        request.tenant_id,
        request.visibility,
        &gate,
        request.content_sha256,
        request.now_unix,
    );
    let manifest = VerificationManifest {
        object: "asset.verification_manifest",
        asset_id: request.asset_id.to_string(),
        content_sha256: request.content_sha256.to_string(),
        size_bytes: request.content.len() as u64,
        scan_state: scan_state.as_str(),
        scan_backend,
        signature: signature.clone(),
        publish_visibility: request.visibility.as_str(),
        approval_state: gate.approval_state(),
    };

    Ok(AssetScreening {
        scan_state,
        scan_backend,
        signature,
        gate,
        manifest,
        evidence,
    })
}

#[cfg(test)]
#[path = "asset_security_test.rs"]
mod asset_security_test;
