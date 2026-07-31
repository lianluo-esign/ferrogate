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
    assert_eq!(create.json_body(), Some(&body));

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

// --- #361 review finding 1: item verbs must not fall back to the collection ---
//
// `item_path(&[])` returns the BARE COLLECTION path, so before this guard an
// omitted id silently retargeted the whole collection: `projects get` issued
// `GET /admin/v1/projects` (the LIST operation, from a verb declaring
// `getProject`) and `projects delete` issued a collection-level DELETE.
//
// These assert on the RESULT of building the request, not on the presence of a
// guard call, so reverting `build_crud` to pass `&segments` straight through
// reds them.

#[test]
fn item_verbs_refuse_to_address_the_collection_when_the_id_is_omitted() {
    for verb in ["get", "delete"] {
        let error = build_crud(&API, verb, &ResourceInput::new())
            .expect_err("an item verb with no id must be a usage error");
        let rendered = error.to_string();
        assert!(
            rendered.contains("requires a target id"),
            "{verb}: unhelpful error: {rendered}"
        );
        assert!(
            rendered.contains("/admin/v1/projects"),
            "{verb}: the error must name the collection it would have hit: {rendered}"
        );
    }
}

#[test]
fn body_bearing_item_verbs_also_refuse_the_bare_collection() {
    // A body is supplied, so the only thing that can refuse these is the id
    // arity check -- this is what stops `api-keys replace --data '{...}'`
    // becoming `PUT /admin/v1/api-keys`.
    for verb in ["replace", "update"] {
        let input = ResourceInput::new().with_body(serde_json::json!({"name": "x"}));
        assert!(
            build_crud(&API, verb, &input).is_err(),
            "{verb} with a body but no id must still be refused"
        );
    }
}

#[test]
fn a_blank_id_is_refused_rather_than_collapsing_to_the_collection() {
    let input = ResourceInput::new().with_segments(["   "]);
    assert!(
        build_crud(&API, "delete", &input).is_err(),
        "a whitespace-only id must not be treated as an absent path segment"
    );
}

#[test]
fn list_and_create_still_address_the_collection_deliberately() {
    // The guard must not overreach: an empty segment list IS the top-level
    // list, and create addresses the collection by definition. If this reds,
    // the fix broke the two verbs that are supposed to hit the collection.
    let list = build_crud(&API, "list", &ResourceInput::new()).expect("list needs no id");
    assert_eq!(list.path, "/admin/v1/projects");
    let create = build_crud(
        &API,
        "create",
        &ResourceInput::new().with_body(serde_json::json!({"name": "x"})),
    )
    .expect("create needs no id");
    assert_eq!(create.path, "/admin/v1/projects");
}
