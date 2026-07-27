// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Unit coverage for the shared asset push-screening orchestrator
// (`asset_security`). Moved out of the production module into this dedicated
// sibling per the AGENTS.md testing architecture when #366 added the
// screening -> persisted `AssetVisibility` mapping both publish paths share.

use super::*;
use crate::server::asset_scan::{ScanBackend, ScannerUnavailablePolicy, EICAR_TEST_SIGNATURE};
use crate::server::asset_signature::SignatureFormat;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

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
    assert!(validate_asset_content("cli_tool", "text/plain", b"#!/bin/sh\necho hi\n").is_ok());
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

fn eicar_context(require_signature: bool, keys: PublisherKeyRegistry) -> AssetSecurityContext {
    AssetSecurityContext::for_test(AssetScanConfig::default(), keys, require_signature)
}

fn base_request<'a>(
    asset_id: &'a str,
    content: &'a [u8],
    sha: &'a str,
) -> AssetPushScreeningRequest<'a> {
    AssetPushScreeningRequest {
        asset_id,
        tenant_id: "tenant-a",
        asset_type: "cli_tool",
        content_type: "text/plain",
        content: ScreenedContent::Buffered(content),
        content_sha256: sha,
        signature: None,
        visibility: PublishVisibility::TenantPrivate,
        approval: None,
        now_unix: 1000,
    }
}

#[tokio::test]
async fn clean_private_push_is_visible() {
    let context = eicar_context(false, PublisherKeyRegistry::new());
    let screening = screen_asset_push(&context, base_request("a1", b"#!/bin/sh\n", "hash"))
        .await
        .expect("clean push allowed");
    assert!(screening.is_visible());
    // #366: the persisted state a clean push maps to must be `Visible`.
    assert_eq!(screening.visibility(), AssetVisibility::Visible);
    assert!(screening.audit_detail().contains("scan=clean"));
    assert!(screening.manifest_json().get("content_sha256").is_some());
}

#[tokio::test]
async fn eicar_push_is_rejected_by_scanner_path() {
    let context = eicar_context(false, PublisherKeyRegistry::new());
    // Use application/octet-stream so it clears the content-type allowlist
    // and reaches the scanner path (not just the synchronous fast-reject).
    let content = [b"payload".as_slice(), EICAR_TEST_SIGNATURE].concat();
    let mut req = base_request("a2", &content, "hash");
    req.content_type = "application/octet-stream";
    let rejection = screen_asset_push(&context, req)
        .await
        .expect_err("eicar must be rejected");
    assert_eq!(rejection.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn scanner_unavailable_fail_closed_rejects() {
    let scan_config = AssetScanConfig {
        backend: ScanBackend::ClamAv {
            // An unroutable address so the connect fails fast -> Unavailable.
            addr: "240.0.0.1:1".to_string(),
            timeout_secs: 1,
        },
        unavailable_policy: ScannerUnavailablePolicy::FailClosed,
        async_threshold_bytes: None,
    };
    let context = AssetSecurityContext::for_test(scan_config, PublisherKeyRegistry::new(), false);
    let rejection = screen_asset_push(&context, base_request("a3", b"clean", "hash"))
        .await
        .expect_err("fail-closed unavailable rejects");
    assert_eq!(rejection.code, "asset_scan_rejected");
}

#[tokio::test]
async fn scanner_unavailable_quarantine_withholds() {
    let scan_config = AssetScanConfig {
        backend: ScanBackend::ClamAv {
            addr: "240.0.0.1:1".to_string(),
            timeout_secs: 1,
        },
        unavailable_policy: ScannerUnavailablePolicy::Quarantine,
        async_threshold_bytes: None,
    };
    let context = AssetSecurityContext::for_test(scan_config, PublisherKeyRegistry::new(), false);
    let screening = screen_asset_push(&context, base_request("a4", b"clean", "hash"))
        .await
        .expect("quarantine still stores");
    assert!(!screening.is_visible());
    // #366: a quarantine verdict persists as `Quarantined`, never downloadable.
    assert_eq!(screening.visibility(), AssetVisibility::Quarantined);
    assert!(!screening.visibility().is_downloadable());
    assert!(screening.audit_detail().contains("scan=quarantined"));
}

#[tokio::test]
async fn large_object_defers_to_pending_scan_invisible() {
    let scan_config = AssetScanConfig {
        backend: ScanBackend::Eicar,
        unavailable_policy: ScannerUnavailablePolicy::FailClosed,
        async_threshold_bytes: Some(4),
    };
    let context = AssetSecurityContext::for_test(scan_config, PublisherKeyRegistry::new(), false);
    let screening = screen_asset_push(&context, base_request("a5", b"larger-than-four", "hash"))
        .await
        .expect("large object admitted pending");
    assert!(!screening.is_visible(), "pending_scan must be invisible");
    // #366: a deferred scan persists as `PendingScan`, withheld until promoted.
    assert_eq!(screening.visibility(), AssetVisibility::PendingScan);
    assert!(!screening.visibility().is_downloadable());
    assert!(screening.audit_detail().contains("scan=pending_scan"));
}

#[tokio::test]
async fn signed_only_rejects_unsigned() {
    let context = eicar_context(true, PublisherKeyRegistry::new());
    let rejection = screen_asset_push(&context, base_request("a6", b"clean", "hash"))
        .await
        .expect_err("signed-only rejects unsigned");
    assert_eq!(rejection.code, "asset_signature_required");
}

#[tokio::test]
async fn signed_only_accepts_verified_signature() {
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let content = b"signed payload";
    let signature = key.sign(content);
    let mut keys = PublisherKeyRegistry::new();
    keys.register_ed25519("pub-1", &BASE64.encode(key.verifying_key().as_bytes()))
        .expect("register");
    let context = eicar_context(true, keys);
    let mut req = base_request("a7", content, "hash");
    req.signature = Some(AssetSignatureInput {
        format: SignatureFormat::Ed25519,
        material: BASE64.encode(signature.to_bytes()),
        key_id: Some("pub-1".to_string()),
    });
    let screening = screen_asset_push(&context, req)
        .await
        .expect("verified signature accepted");
    assert!(screening.audit_detail().contains("signature=verified"));
}

#[tokio::test]
async fn cross_tenant_publish_without_approval_is_blocked() {
    let context = eicar_context(false, PublisherKeyRegistry::new());
    let mut req = base_request("a8", b"clean", "hash");
    req.visibility = PublishVisibility::Public;
    let rejection = screen_asset_push(&context, req)
        .await
        .expect_err("cross-tenant without approval blocked");
    assert_eq!(rejection.status(), StatusCode::FORBIDDEN);
    assert_eq!(rejection.code, "cross_tenant_publish_denied");
}

#[tokio::test]
async fn cross_tenant_publish_with_approval_is_allowed() {
    let context = eicar_context(false, PublisherKeyRegistry::new());
    let mut req = base_request("a9", b"clean", "hash");
    req.visibility = PublishVisibility::Public;
    req.approval = Some(("approval-1".to_string(), ApprovalStatus::Approved));
    let screening = screen_asset_push(&context, req)
        .await
        .expect("approved cross-tenant publish allowed");
    assert!(screening
        .audit_detail()
        .contains("visibility_gate=approved"));
    assert!(screening.audit_detail().contains("approval-1"));
}

// ---- streamed screening (issue #259) ----------------------------------------
//
// An object above the gateway's in-memory budget is verified and copied in a
// bounded pass, so the screener is handed the facts that pass established
// instead of the bytes. These pin which controls survive that, and -- more
// importantly -- that the ones which cannot are FAILED CLOSED rather than
// quietly skipped.

fn streamed_request<'a>(
    asset_id: &'a str,
    size_bytes: u64,
    eicar_found: bool,
    sha: &'a str,
) -> AssetPushScreeningRequest<'a> {
    AssetPushScreeningRequest {
        asset_id,
        tenant_id: "tenant-a",
        asset_type: "cli_tool",
        content_type: "application/octet-stream",
        content: ScreenedContent::Streamed {
            size_bytes,
            eicar_found,
        },
        content_sha256: sha,
        signature: None,
        visibility: PublishVisibility::TenantPrivate,
        approval: None,
        now_unix: 1000,
    }
}

#[tokio::test]
async fn a_clean_streamed_object_is_visible_and_reports_its_streamed_size() {
    let context = eicar_context(false, PublisherKeyRegistry::new());
    let screening = screen_asset_push(&context, streamed_request("s1", 104_857_600, false, "hash"))
        .await
        .expect("a clean streamed object is admitted");
    assert!(screening.is_visible());
    assert_eq!(screening.visibility(), AssetVisibility::Visible);
    // The manifest's size must come from the streamed accounting, not from a
    // buffer length that no longer exists.
    assert_eq!(screening.manifest_json()["size_bytes"], 104_857_600_u64);
}

#[tokio::test]
async fn a_streamed_object_whose_stream_matched_malware_is_rejected() {
    // The offline signature scan ran over every byte during the copy pass; its
    // verdict must reject exactly as `contains_eicar(&buffer)` does.
    let context = eicar_context(false, PublisherKeyRegistry::new());
    let rejection = screen_asset_push(&context, streamed_request("s2", 104_857_600, true, "hash"))
        .await
        .expect_err("a streamed malware match must be rejected");
    assert_eq!(rejection.code, "asset_rejected");
    assert_eq!(rejection.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_signed_streamed_object_is_rejected_rather_than_downgraded_to_unsigned() {
    // A detached signature is a claim about the whole file. With no bytes to
    // check it against, the only two options are "reject" and "pretend it was
    // never presented" -- and the second silently voids a publisher's signing
    // requirement for exactly the largest, highest-value artifacts.
    let context = eicar_context(false, PublisherKeyRegistry::new());
    let mut req = streamed_request("s3", 104_857_600, false, "hash");
    req.signature = Some(AssetSignatureInput {
        format: SignatureFormat::Ed25519,
        material: BASE64.encode([7_u8; 64]),
        key_id: Some("pub-1".to_string()),
    });
    let rejection = screen_asset_push(&context, req)
        .await
        .expect_err("a signature that cannot be verified must not be ignored");
    assert_eq!(rejection.code, "asset_signature_requires_buffering");
    assert_eq!(rejection.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_signed_only_tenant_still_rejects_an_unsigned_streamed_object() {
    // The signature REQUIREMENT is unaffected by streaming: it is enforced on
    // the absence of a verified signature, which streaming can only ever make
    // more likely, never less.
    let context = eicar_context(true, PublisherKeyRegistry::new());
    let rejection = screen_asset_push(&context, streamed_request("s4", 104_857_600, false, "hash"))
        .await
        .expect_err("signed-only must still reject an unsigned streamed object");
    assert_eq!(rejection.code, "asset_signature_required");
}

#[tokio::test]
async fn an_out_of_process_scanner_withholds_a_streamed_object_instead_of_calling_it_clean() {
    // ClamAV/HTTP backends need bytes the streamed path never has. The object
    // is stored but WITHHELD (`pending_scan`, not downloadable) until an
    // out-of-band scan proves it -- the same store-but-withhold semantics the
    // async threshold already expresses, and never a silent pass.
    let scan_config = AssetScanConfig {
        backend: ScanBackend::ClamAv {
            addr: "240.0.0.1:1".to_string(),
            timeout_secs: 1,
        },
        unavailable_policy: ScannerUnavailablePolicy::FailClosed,
        async_threshold_bytes: None,
    };
    let context = AssetSecurityContext::for_test(scan_config, PublisherKeyRegistry::new(), false);
    let screening = screen_asset_push(&context, streamed_request("s5", 104_857_600, false, "hash"))
        .await
        .expect("a streamed object is stored, withheld");
    assert!(!screening.is_visible());
    assert_eq!(screening.visibility(), AssetVisibility::PendingScan);
    assert!(!screening.visibility().is_downloadable());
    assert!(screening
        .audit_detail()
        .contains("backend=deferred_streaming"));
}

#[tokio::test]
async fn a_streamed_mcp_manifest_is_refused_because_its_transport_cannot_be_parsed() {
    // A `stdio` manifest makes a CONSUMING agent's MCP client spawn an
    // arbitrary local process. That check needs the whole JSON document, so a
    // manifest too large to hold is refused rather than admitted unread.
    let context = eicar_context(false, PublisherKeyRegistry::new());
    let mut req = streamed_request("s6", 104_857_600, false, "hash");
    req.asset_type = "mcp_manifest";
    req.content_type = "application/json";
    let rejection = screen_asset_push(&context, req)
        .await
        .expect_err("an unparseable manifest must not be admitted");
    assert_eq!(rejection.code, "asset_rejected");
    assert!(rejection.message.contains("stdio"));
}

#[test]
fn the_streamed_content_validator_agrees_with_the_buffered_one_where_it_can() {
    // Same allowlist, same malware verdict; the only divergence is the
    // manifest rule, and it diverges in the safe direction.
    assert!(validate_streamed_asset_content("cli_tool", "text/plain", false).is_ok());
    assert!(validate_streamed_asset_content("cli_tool", "application/json", false).is_err());
    assert!(validate_streamed_asset_content("cli_tool", "text/plain", true).is_err());
    assert!(
        validate_streamed_asset_content("future_type", "application/x-whatever", false).is_ok()
    );
    assert!(validate_streamed_asset_content("mcp_manifest", "application/json", false).is_err());
}
