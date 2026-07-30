// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for process-local application state reload behavior.

//! Process-local reload behaviour, and the #512 inline-payload merge.
//!
//! An inline `POST /admin/v1/config/reload` writes its payload back over the
//! durable control plane, and a config document cannot name a row minted
//! through the admin API. Every test below that mentions `#512` pins one edge
//! of `reload_process_local_from_inline_payload`, and each names in its doc
//! comment the production line whose deletion reddens it -- the convention
//! `state_tenant_identity_test.rs` established, and the one the #512 review
//! asked for after finding 74 lines of new product code that no test held.

use super::*;

/// A payload an operator could plausibly write: it declares the listener and
/// the model/provider pair the node already runs, and nothing about
/// credentials, because a config document has no way to name one that was
/// minted at runtime.
fn payload_toml(extra: &str) -> String {
    format!(
        r#"
listen = "127.0.0.1:18512"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:10001/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-test"
{extra}
"#
    )
}

fn payload(extra: &str) -> Config {
    Config::from_toml_str(&payload_toml(extra)).expect("the payload is a valid config on its own")
}

/// The running config: the same document the operator would reload, before any
/// runtime-minted row exists.
fn booted_node() -> SharedAppState {
    SharedAppState::with_source_path(payload(""), None)
}

fn minted_key(id: &str, extra: serde_json::Value) -> ApiKey {
    let mut document = serde_json::json!({
        "id": id,
        "name": id,
        "key": format!("{id}-secret"),
        "scopes": ["chat.completions"],
        "organization_id": "tenant-a",
    });
    let serde_json::Value::Object(extra) = extra else {
        panic!("extra must be a JSON object");
    };
    for (field, value) in extra {
        document
            .as_object_mut()
            .expect("document is an object")
            .insert(field, value);
    }
    serde_json::from_value(document).expect("a valid runtime-minted api key")
}

/// A deny rule bound to one credential -- the shape whose loss is an
/// authorization change rather than an availability one.
fn deny_policy(name: &str, api_key_id: &str, model: &str) -> ConfigPolicyRule {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "effect": "deny",
        "api_key_ids": [api_key_id],
        "models": [model],
    }))
    .expect("a valid deny policy")
}

fn api_key_ids(config: &Config) -> Vec<&str> {
    config.api_keys.iter().map(|key| key.id.as_str()).collect()
}

fn policy_names(config: &Config) -> Vec<&str> {
    config
        .policies
        .iter()
        .map(|policy| policy.name.as_str())
        .collect()
}

#[test]
fn process_local_reload_preserves_request_id_sequence() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    let first = shared.next_request_id();

    let result = shared.reload_process_local(Config::default());

    assert!(result.committed);
    let second = shared.next_request_id();
    let first = u64::from_str_radix(first.trim_start_matches("fg-"), 16).unwrap();
    let second = u64::from_str_radix(second.trim_start_matches("fg-"), 16).unwrap();
    assert_eq!(second, first.wrapping_add(1));
}

/// #512, the defect itself: reloading a payload that says nothing about
/// credentials used to DELETE every credential minted through
/// `POST /admin/v1/api-keys`, and the next request presenting one answered
/// `401 invalid_api_key` -- fail-closed, but reporting a deleted credential as
/// a bad one, which is what masked the #514 lifecycle seam this issue probes.
///
/// Delete the `merge_undeclared_durable_control_plane_documents` call in
/// `inline_reload_candidate` and this reds: `k1` is gone from the committed
/// config.
#[test]
fn an_inline_reload_of_an_unrelated_section_keeps_a_runtime_minted_api_key() {
    let node = booted_node();
    node.upsert_api_key(minted_key("k1", serde_json::json!({})))
        .expect("mint a runtime credential");

    let result = node
        .reload_process_local_from_inline_payload(payload("\n[scheduler]\nenabled = true\n"))
        .expect("an unrelated section is not a reason to refuse the reload");

    assert!(result.committed, "{result:?}");
    assert_eq!(api_key_ids(&node.current().config), vec!["k1"]);
}

/// #512: the payload stays authoritative for everything it CAN name. An id the
/// operator re-declares is theirs, so the payload's version wins and the id
/// appears exactly once.
///
/// Delete the declared-id filter in `restore_undeclared_durable_documents` and
/// this reds twice over: `k1` appears twice, and `validate()` refuses the
/// duplicate id.
#[test]
fn a_payload_declared_id_still_wins_over_the_durable_row() {
    let node = booted_node();
    node.upsert_api_key(minted_key(
        "k1",
        serde_json::json!({"name": "minted at runtime"}),
    ))
    .expect("mint a runtime credential");

    let result = node
        .reload_process_local_from_inline_payload(payload(
            r#"
[[api_keys]]
id = "k1"
name = "redeclared by the payload"
key = "k1-secret"
organization_id = "tenant-a"
"#,
        ))
        .expect("re-declaring an id is an ordinary payload edit");

    assert!(result.committed, "{result:?}");
    let live = node.current();
    assert_eq!(api_key_ids(&live.config), vec!["k1"]);
    assert_eq!(live.config.api_keys[0].name, "redeclared by the payload");
}

/// #512: the merge reads the durable SNAPSHOT, not the previously running
/// config, so a credential revoked through `DELETE /admin/v1/api-keys/{id}`
/// stays revoked. Restoring "whatever the last config had" would have turned
/// this fix into the resurrection bug #80 already refused for the file path.
///
/// The revocation is done at the repository level ON PURPOSE. `delete_api_key`
/// reloads immediately, so after it the running config and the durable snapshot
/// agree and the test cannot tell the two sources apart; removing the row
/// underneath the running config is the only state in which they disagree, and
/// it is a state the node genuinely reaches -- it is what `delete_api_key`
/// itself looks like between its store write and its reload, and what a peer's
/// revocation looks like before this node syncs.
///
/// Source `durable_keys` from `self.config.api_keys` instead of
/// `self.repositories.control_plane_snapshot()` and this reds: `k1` comes back
/// from the dead.
#[test]
fn a_deleted_durable_key_is_not_resurrected_by_an_inline_reload() {
    let node = booted_node();
    node.upsert_api_key(minted_key("k1", serde_json::json!({})))
        .expect("mint a runtime credential");
    assert_eq!(
        api_key_ids(&node.current().config),
        vec!["k1"],
        "the running config carries the credential the revocation is about to remove"
    );
    assert!(
        node.current()
            .repositories
            .delete_control_plane_api_key("k1")
            .expect("revoking a credential must succeed"),
        "the credential existed"
    );

    let result = node
        .reload_process_local_from_inline_payload(payload(""))
        .expect("reload after a revocation");

    assert!(result.committed, "{result:?}");
    assert!(
        api_key_ids(&node.current().config).is_empty(),
        "a revoked credential must not be restored by a later reload"
    );
}

/// #512 review blocker: restoring the credential without the rule that
/// constrains it is worse than restoring neither.
///
/// `config.policies` are pure DENY rules and can bind to one credential through
/// `api_key_ids`, so dropping one REMOVES a restriction. With api-keys merged
/// and policies still overwritten, an inline reload of an unrelated section
/// reached a state the tree could not reach before: `k1` alive and the rule
/// denying it `fast-chat` gone. That is fail-closed loss traded for fail-open
/// survival.
///
/// Delete the `config.policies` arm of
/// `merge_undeclared_durable_control_plane_documents` and this reds on the
/// policy assertion while the key assertion still passes -- which is precisely
/// the combination the blocker describes.
#[test]
fn a_restored_key_does_not_outlive_the_deny_policy_that_constrains_it() {
    let node = booted_node();
    node.upsert_api_key(minted_key("k1", serde_json::json!({})))
        .expect("mint a runtime credential");
    node.upsert_policy(deny_policy("no-fast-chat", "k1", "fast-chat"))
        .expect("create the durable deny rule that constrains it");

    let result = node
        .reload_process_local_from_inline_payload(payload("\n[scheduler]\nenabled = true\n"))
        .expect("an unrelated section is not a reason to refuse the reload");

    assert!(result.committed, "{result:?}");
    let live = node.current();
    assert_eq!(api_key_ids(&live.config), vec!["k1"]);
    assert_eq!(
        policy_names(&live.config),
        vec!["no-fast-chat"],
        "the credential survived, so the rule that constrains it must too"
    );
}

/// #512 review major: the restored rows were never seen by the validation the
/// payload itself passed, so the merged whole is validated before it is
/// committed -- and a failure is a REJECTION, not a silently-persisted illegal
/// config.
///
/// Without that validation the illegal row is written straight into the control
/// plane by `sync_control_plane_storage_from_config`, and every later admin
/// write -- including the one that would repair it -- 400s on the same message,
/// because `upsert_policy` and friends validate a candidate built from exactly
/// those durable rows. Delete the `candidate.validate()` in
/// `inline_reload_candidate` and this reds: the reload returns `Ok`.
#[test]
fn an_inline_reload_the_restored_rows_contradict_is_rejected_and_changes_nothing() {
    let node = booted_node();
    node.upsert_api_key(minted_key(
        "k1",
        serde_json::json!({"allowed_models": ["fast-chat"]}),
    ))
    .expect("mint a credential scoped to the model the node runs");

    // A payload that drops `fast-chat` while `k1` still allows only that model.
    let without_the_model = Config::from_toml_str(
        r#"
listen = "127.0.0.1:18512"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:10001/v1"
"#,
    )
    .expect("the payload is valid on its own -- it names no api keys at all");

    let error = node
        .reload_process_local_from_inline_payload(without_the_model)
        .expect_err("a merged candidate that cannot validate must not commit");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("config reload rejected"),
        "the operator is told the reload was refused: {rendered}"
    );

    let live = node.current();
    assert_eq!(
        api_key_ids(&live.config),
        vec!["k1"],
        "the running config is unchanged"
    );
    assert!(
        live.config
            .models
            .iter()
            .any(|model| model.name == "fast-chat"),
        "including the model the rejected payload would have dropped"
    );
}

/// #512 review major, the other half: validating the merged candidate must not
/// become a NEW lockout. A pre-#515 durable row -- no `organization_id`, no
/// `platform_operator` -- is warned about and still refused at authentication
/// (#540); it is not a reason to refuse a reload the operator needs.
///
/// Delete `config.api_keys_are_control_plane_documents = true` from
/// `merge_undeclared_durable_control_plane_documents` and this reds: the
/// validation added above turns a tolerated legacy row into a reload refusal,
/// which is the exact lockout #540 exists to prevent.
#[test]
fn a_pre_515_durable_row_is_warned_about_rather_than_refusing_the_reload() {
    let node = booted_node();
    node.current()
        .repositories
        .upsert_control_plane_api_key(
            "legacy-one".to_string(),
            serde_json::json!({
                // #540-undeclared-on-purpose: pre-#515 durable control-plane row.
                "id": "legacy-one",
                "name": "Minted before #515",
                "key": "legacy-one-secret",
                "scopes": ["chat.completions"],
            })
            .to_string(),
        )
        .expect("seed the pre-#515 durable row");

    let result = node
        .reload_process_local_from_inline_payload(payload(""))
        .expect("a tolerated legacy row is not a reload refusal");

    assert!(result.committed, "{result:?}");
    let live = node.current();
    assert_eq!(api_key_ids(&live.config), vec!["legacy-one"]);
    assert_eq!(
        live.config.api_keys_without_tenant_identity(),
        vec!["legacy-one"],
        "it is tolerated at reload, not stopped being seen"
    );
}
