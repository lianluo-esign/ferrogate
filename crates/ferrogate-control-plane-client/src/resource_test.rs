// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the shared REST request builders and redaction (#361).
//! Pure logic only — no live network.

use super::*;
use crate::error::ExitClass;
use crate::transport::PageRequest;
use http::Method;

const TENANTS: ResourceApi = ResourceApi::new("/admin/v1/tenant-accounts");

#[test]
fn encode_segment_preserves_unreserved_and_encodes_the_rest() {
    assert_eq!(encode_segment("t_1-a.b~c"), "t_1-a.b~c");
    // A slash cannot extend the path.
    assert_eq!(encode_segment("a/b"), "a%2Fb");
    assert_eq!(encode_segment("a b"), "a%20b");
    assert_eq!(encode_segment("k=v&x"), "k%3Dv%26x");
}

#[test]
fn list_builds_collection_get_with_page_and_filters() {
    let params = ListParams::new()
        .with_page(PageRequest::first(25))
        .with_filter("status", "active");
    let spec = TENANTS.list(&params).unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/tenant-accounts");
    assert!(spec.body.is_none());
    assert_eq!(
        spec.query,
        vec![
            ("offset".to_string(), "0".to_string()),
            ("limit".to_string(), "25".to_string()),
            ("status".to_string(), "active".to_string()),
        ]
    );
}

#[test]
fn get_builds_item_path_with_encoded_segment() {
    let spec = TENANTS.get(&["ten ant/1"]).unwrap();
    assert_eq!(spec.method, Method::GET);
    assert_eq!(spec.path, "/admin/v1/tenant-accounts/ten%20ant%2F1");
    assert!(spec.query.is_empty());
}

#[test]
fn create_replace_update_delete_use_the_right_methods() {
    let body = serde_json::json!({"name": "acme"});
    assert_eq!(TENANTS.create(body.clone()).unwrap().method, Method::POST);
    assert_eq!(
        TENANTS.replace(&["t1"], body.clone()).unwrap().method,
        Method::PUT
    );
    assert_eq!(
        TENANTS.update(&["t1"], body.clone()).unwrap().method,
        Method::PATCH
    );
    let del = TENANTS.delete(&["t1"]).unwrap();
    assert_eq!(del.method, Method::DELETE);
    assert!(del.body.is_none());
    // The create body is carried through unchanged.
    assert_eq!(TENANTS.create(body.clone()).unwrap().body, Some(body));
}

#[test]
fn composite_key_and_action_paths() {
    // Quota-policy style two-segment key.
    let quota = ResourceApi::new("/admin/v1/quota-policies");
    let spec = quota.get(&["tenant", "acme"]).unwrap();
    assert_eq!(spec.path, "/admin/v1/quota-policies/tenant/acme");

    // A lifecycle action sub-path.
    let vkeys = ResourceApi::new("/admin/v1/virtual-keys");
    let action = vkeys.action(&["vk_1", "rotate"], None).unwrap();
    assert_eq!(action.method, Method::POST);
    assert_eq!(action.path, "/admin/v1/virtual-keys/vk_1/rotate");
    assert!(action.body.is_none());
}

#[test]
fn empty_segment_is_a_usage_error() {
    let error = TENANTS.get(&["   "]).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("must not be empty"));
}

#[test]
fn redact_blanks_named_secret_fields_recursively() {
    let mut value = serde_json::json!({
        "id": "vk_1",
        "secret": "sk-live-abc",
        "key": "vk_live_xyz",
        "monthly_token_budget": 1000,
        "nested": {"secret": "inner"},
        "items": [{"key": "one"}, {"key": "two", "id": "vk_2"}]
    });
    redact_secret_fields(&mut value, &["key", "secret"]);
    assert_eq!(value["secret"], "<redacted>");
    assert_eq!(value["key"], "<redacted>");
    // Non-secret fields (including one whose name merely contains "token") are
    // untouched.
    assert_eq!(value["monthly_token_budget"], 1000);
    assert_eq!(value["id"], "vk_1");
    assert_eq!(value["nested"]["secret"], "<redacted>");
    assert_eq!(value["items"][0]["key"], "<redacted>");
    assert_eq!(value["items"][1]["key"], "<redacted>");
    assert_eq!(value["items"][1]["id"], "vk_2");
}

#[test]
fn redact_leaves_null_secret_as_null() {
    let mut value = serde_json::json!({"secret": null, "key": "present"});
    redact_secret_fields(&mut value, &["key", "secret"]);
    assert!(value["secret"].is_null());
    assert_eq!(value["key"], "<redacted>");
}

/// Sort keys reach the server as repeatable, order-preserving `sort` query
/// parameters alongside pagination and filters — the `--sort` half of the
/// list surface that was previously unimplemented end to end.
#[test]
fn list_forwards_sort_keys_in_declaration_order() {
    let params = ListParams::new()
        .with_page(PageRequest::first(10))
        .with_filter("status", "active")
        .with_sort("tier")
        .with_sort("-created_at");
    let spec = TENANTS.list(&params).unwrap();
    assert_eq!(
        spec.query,
        vec![
            ("offset".to_string(), "0".to_string()),
            ("limit".to_string(), "10".to_string()),
            ("status".to_string(), "active".to_string()),
            // The leading `-` descending marker is passed through verbatim:
            // ordering is evaluated server-side over the whole collection.
            ("sort".to_string(), "tier".to_string()),
            ("sort".to_string(), "-created_at".to_string()),
        ]
    );
}

/// No sort key means no `sort` parameter at all — the client never invents an
/// ordering the operator did not ask for.
#[test]
fn list_without_sort_sends_no_sort_parameter() {
    let spec = TENANTS.list(&ListParams::new()).unwrap();
    assert!(spec.query.is_empty(), "unexpected query: {:?}", spec.query);
}
