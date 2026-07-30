// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Tests for the generic resource-dispatch router (#361–#365 wiring seam).

use http::Method;
use serde_json::json;

use crate::command::{Registry, SecretDisclosure};
use crate::dispatch::{build_request, redact_response, resource_builder, secret_fields_for};
use crate::register_resource_families;
use crate::registry_helpers::ResourceInput;

/// Every group the crate registers must resolve to a request-builder. This is
/// the guard that keeps `resource_builder` in lockstep with
/// `register_resource_families`: a family added to the registry without a
/// routing entry fails here rather than surfacing only when an operator runs
/// the (registered, help-listed) command and hits "unknown resource group".
#[test]
fn every_registered_group_is_dispatchable() {
    let mut registry = Registry::new();
    register_resource_families(&mut registry).expect("families register");

    let mut checked = 0;
    for group in registry.groups() {
        assert!(
            resource_builder(&group.name).is_some(),
            "registered group '{}' has no dispatch entry in resource_builder",
            group.name
        );
        checked += 1;
    }
    assert!(
        checked >= 40,
        "expected the full family surface, saw {checked}"
    );
}

/// A representative CRUD verb from each of #361/#362/#363/#364 builds the
/// expected method + absolute path through the shared REST builders.
#[test]
fn representative_verbs_build_expected_requests() {
    // #361 IAM: list is a GET on the collection.
    let list = build_request("virtual-keys", "list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/virtual-keys");

    // #361 IAM: get addresses the item by id segment.
    let get = build_request(
        "virtual-keys",
        "get",
        &ResourceInput::new().with_segments(["vk-1"]),
    )
    .unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/virtual-keys/vk-1");

    // #362 MCP: create posts the operator document to the collection.
    let create = build_request(
        "mcp-servers",
        "create",
        &ResourceInput::new().with_body(json!({"name": "srv"})),
    )
    .unwrap();
    assert_eq!(create.method, Method::POST);
    assert_eq!(create.path, "/admin/v1/mcp-servers");
    assert_eq!(create.body, Some(json!({"name": "srv"})));

    // #363 Assets: list is a GET on the collection.
    let assets = build_request("assets", "list", &ResourceInput::new()).unwrap();
    assert_eq!(assets.method, Method::GET);
    assert_eq!(assets.path, "/v1/assets");

    // #364 Billing: a usage read verb is a GET on its collection.
    let usage = build_request("usage", "reports", &ResourceInput::new()).unwrap();
    assert_eq!(usage.method, Method::GET);
    assert_eq!(usage.path, "/admin/v1/usage-reports");
}

#[test]
fn unknown_group_is_a_usage_error() {
    let error = build_request("not-a-group", "list", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), crate::error::ExitClass::Usage);
    assert!(error.to_string().contains("unknown resource group"));
}

/// A read (GET) blanks a group's secret fields; a mutation (POST) leaves the
/// one-time secret intact so the operator can capture it.
#[test]
fn redaction_applies_only_to_reads() {
    let read = build_request(
        "virtual-keys",
        "get",
        &ResourceInput::new().with_segments(["vk-1"]),
    )
    .unwrap();
    let mut body = json!({"id": "vk-1", "key": "sk-LEAK", "secret": "SHHH"});
    redact_response("virtual-keys", SecretDisclosure::Redacted, &read, &mut body);
    assert_eq!(body["key"], "<redacted>");
    assert_eq!(body["secret"], "<redacted>");

    let create = build_request(
        "virtual-keys",
        "create",
        &ResourceInput::new().with_body(json!({"name": "k"})),
    )
    .unwrap();
    let mut created = json!({"id": "vk-2", "key": "sk-ONE-TIME"});
    redact_response(
        "virtual-keys",
        SecretDisclosure::Redacted,
        &create,
        &mut created,
    );
    assert_eq!(
        created["key"], "sk-ONE-TIME",
        "a create response must surface the one-time secret"
    );
}

#[test]
fn groups_without_secrets_have_no_secret_fields() {
    assert!(secret_fields_for("tenant-accounts").is_empty());
    assert!(secret_fields_for("not-a-group").is_empty());
    assert_eq!(secret_fields_for("virtual-keys"), &["key", "secret"]);
}
