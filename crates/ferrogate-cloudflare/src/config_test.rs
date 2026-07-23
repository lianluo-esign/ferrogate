// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit tests for the Cloudflare config model; kept out of the business-logic file.

use crate::config::{default_ai_gateway_base_url, default_api_base_url, CloudflareConfig};

#[test]
fn deserializes_minimal_config_with_defaulted_base_urls() {
    let cfg: CloudflareConfig =
        serde_json::from_str(r#"{ "account_id": "acct-123", "api_token": "env://CF_API_TOKEN" }"#)
            .unwrap();
    assert_eq!(cfg.account_id, "acct-123");
    assert_eq!(cfg.api_token, "env://CF_API_TOKEN");
    assert_eq!(cfg.api_base_url, default_api_base_url());
    assert_eq!(cfg.ai_gateway_base_url, default_ai_gateway_base_url());
    assert!(cfg.tenant_tokens.is_empty());
}

#[test]
fn r2_endpoint_derives_from_account_when_unset() {
    let cfg = CloudflareConfig::new("acct-xyz", "token");
    assert_eq!(
        cfg.r2_s3_endpoint(),
        "https://acct-xyz.r2.cloudflarestorage.com"
    );
}

#[test]
fn r2_endpoint_override_is_honored() {
    let mut cfg = CloudflareConfig::new("acct-xyz", "token");
    cfg.r2_s3_endpoint = Some("https://custom.example.test".to_string());
    assert_eq!(cfg.r2_s3_endpoint(), "https://custom.example.test");
}

#[test]
fn tenant_token_override_is_selected_when_present() {
    let cfg: CloudflareConfig = serde_json::from_str(
        r#"{
            "account_id": "a",
            "api_token": "env://DEFAULT",
            "tenant_tokens": { "tenant-a": "env://TENANT_A" }
        }"#,
    )
    .unwrap();
    assert_eq!(cfg.token_reference(Some("tenant-a")), "env://TENANT_A");
    assert_eq!(cfg.token_reference(Some("tenant-unknown")), "env://DEFAULT");
    assert_eq!(cfg.token_reference(None), "env://DEFAULT");
}

#[test]
fn config_round_trips_through_serde() {
    let cfg = CloudflareConfig::new("acct-1", "env://TOK");
    let json = serde_json::to_string(&cfg).unwrap();
    let back: CloudflareConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}
