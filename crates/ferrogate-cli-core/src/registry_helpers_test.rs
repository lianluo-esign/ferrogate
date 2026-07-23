// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the shared verb-dispatch helpers (#361). Pure logic only.

use super::*;
use crate::error::ExitClass;
use http::Method;

const API: ResourceApi = ResourceApi::new("/admin/v1/projects");

#[test]
fn build_crud_maps_each_verb_to_method_and_path() {
    let body = serde_json::json!({"name": "p"});
    let list = build_crud(&API, "list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/projects");

    let get = build_crud(&API, "get", &ResourceInput::new().with_segments(["p1"])).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/projects/p1");

    let create = build_crud(
        &API,
        "create",
        &ResourceInput::new().with_body(body.clone()),
    )
    .unwrap();
    assert_eq!(create.method, Method::POST);
    assert_eq!(create.body, Some(body.clone()));

    let replace = build_crud(
        &API,
        "replace",
        &ResourceInput::new()
            .with_segments(["p1"])
            .with_body(body.clone()),
    )
    .unwrap();
    assert_eq!(replace.method, Method::PUT);
    assert_eq!(replace.path, "/admin/v1/projects/p1");

    let update = build_crud(
        &API,
        "update",
        &ResourceInput::new().with_segments(["p1"]).with_body(body),
    )
    .unwrap();
    assert_eq!(update.method, Method::PATCH);

    let delete = build_crud(&API, "delete", &ResourceInput::new().with_segments(["p1"])).unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert!(delete.body.is_none());
}

#[test]
fn write_verbs_require_a_body() {
    let error = build_crud(&API, "create", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn unknown_verb_is_usage_error() {
    let error = build_crud(&API, "frobnicate", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
}

#[test]
fn first_segment_requires_a_target_id() {
    let error = first_segment(&ResourceInput::new(), "widget").unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));

    let input = ResourceInput::new().with_segments(["w1"]);
    let ok = first_segment(&input, "widget").unwrap();
    assert_eq!(ok, "w1");
}

#[test]
fn item_action_and_delete_helpers() {
    let vkeys = ResourceApi::new("/admin/v1/virtual-keys");
    let input = ResourceInput::new().with_segments(["vk_1"]);
    let action = build_item_action(&vkeys, "virtual-key", "disable", &input).unwrap();
    assert_eq!(action.method, Method::POST);
    assert_eq!(action.path, "/admin/v1/virtual-keys/vk_1/disable");

    let delete = build_item_delete(&vkeys, "virtual-key", &input).unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert_eq!(delete.path, "/admin/v1/virtual-keys/vk_1");
}
