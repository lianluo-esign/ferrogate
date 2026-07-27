// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the shared ctl dispatch glue (#360): the error-path secret
//! redaction that keeps a server error envelope from being the one output path
//! that leaks key material.

use super::*;
use ferrogate_control_plane_client::dispatch::secret_fields_for;
use serde_json::json;

/// A server error echoing key material is redacted exactly like a success body.
///
/// The transport's `collect_extra_details` forwards every error-object key
/// except `message`/`type`/`code`/`request_id`, so an API that rejects a
/// virtual-key create and echoes the offending document put `key`/`secret` on
/// stderr in clear — while the same fields on the 200 path went through
/// `redact_response`. Redaction that covers only the happy path is not
/// redaction.
#[test]
fn error_details_redact_the_groups_one_time_secrets() {
    let details = json!({
        "expected_version": 3,
        "echo": {"key": "vk_live_super_secret", "secret": "sh-hh"},
    });
    let rendered = render_details(&details, secret_fields_for("virtual-keys"));

    assert!(
        !rendered.contains("vk_live_super_secret"),
        "key material must not reach stderr: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // The actionable half of the payload survives — redaction must not blank
    // the diagnostic that makes the error useful.
    assert!(rendered.contains("expected_version"), "{rendered}");
}

/// Asset-transfer presign URLs are one-time capability grants, so they are
/// redacted from an error payload too — proving the fix is driven by the
/// group's declared field list rather than by one hard-coded name.
#[test]
fn error_details_redact_presign_urls_for_the_transfer_group() {
    let details = json!({"upload_url": "https://bucket.example.com/put?sig=abc"});
    let rendered = render_details(&details, secret_fields_for("asset-transfer"));
    assert!(!rendered.contains("sig=abc"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

/// A group with no secret material renders its details untouched: redaction
/// must not become a blanket scrubber that hides ordinary diagnostics.
#[test]
fn error_details_of_a_secret_free_group_are_unchanged() {
    let details = json!({"expected_version": 3, "field": "name"});
    let rendered = render_details(&details, secret_fields_for("projects"));
    assert!(rendered.contains("expected_version") && rendered.contains("name"));
    assert!(!rendered.contains("<redacted>"), "{rendered}");
}
