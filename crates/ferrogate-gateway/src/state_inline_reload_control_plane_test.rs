// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Unit tests for the #605 inline config reload union against durable control-plane documents.

//! #605: an inline `POST /admin/v1/config/reload` must not delete what it does
//! not mention.
//!
//! The inline branch used to hand its payload straight to
//! `reload_process_local`, and `with_reloaded_config` ends in
//! `sync_control_plane_storage_from_config` → `replace_control_plane`, which
//! replaces every document class WHOLESALE. So a payload appending `[scheduler]
//! enabled = true` deleted every control-plane document provisioned at runtime
//! through the Admin API -- api-keys included -- permanently, while answering
//! `200 {"valid":true,"committed":true}`.
//!
//! Nothing in the tree covered this: the only reload tests drive
//! `reload_process_local` directly, which is BELOW the branch that chooses
//! whether to reconcile, and the harness scenario that would have walked into it
//! (`enable_scheduler`) panicked earlier on an assertion against a field the
//! reload response never declares.

use super::*;

/// Every control-plane document class, provisioned the way the Admin API
/// provisions them: as durable rows, in a config the operator's next inline
/// payload will not mention.
///
/// Built by running the real `control_plane_documents_from_config` projection
/// over a config carrying one document per class, so the seeded bytes are
/// exactly what a runtime mutation would have written -- a hand-written JSON
/// fixture could drift from the projection and still pass.
fn runtime_provisioned_config() -> Config {
    Config {
        api_keys: vec![serde_json::from_value(serde_json::json!({
            "id": "minted-at-runtime",
            "name": "Minted via POST /admin/v1/api-keys",
            "key": "minted-at-runtime-secret",
            "scopes": ["chat.completions"],
            "organization_id": "tenant-a",
        }))
        .expect("api key fixture")],
        policies: vec![serde_json::from_value(serde_json::json!({
            "name": "runtime-policy",
            "effect": "deny",
            "models": ["gpt-4o"],
        }))
        .expect("policy fixture")],
        gateway_configs: vec![serde_json::from_value(serde_json::json!({
            "id": "runtime-profile",
            "name": "Runtime profile",
        }))
        .expect("gateway config fixture")],
        agent_workflows: vec![serde_json::from_value(serde_json::json!({
            "id": "runtime-workflow",
            "name": "Runtime workflow",
            "nodes": [{"id": "only-node"}],
        }))
        .expect("agent workflow fixture")],
        skill_packages: vec![serde_json::from_value(serde_json::json!({
            "id": "runtime-skill-package",
            "name": "Runtime skill package",
        }))
        .expect("skill package fixture")],
        prompt_templates: vec![serde_json::from_value(serde_json::json!({
            "id": "runtime-template",
            "name": "Runtime template",
            "model": "gpt-4o",
            "versions": [{"revision": 1, "messages": [{"role": "user", "content": "hi"}]}],
        }))
        .expect("prompt template fixture")],
        plugins: vec![serde_json::from_value(serde_json::json!({
            "id": "runtime-plugin",
            "kind": "request_hook",
        }))
        .expect("plugin fixture")],
        mcp_servers: vec![serde_json::from_value(serde_json::json!({
            "name": "runtime-mcp",
            "transport": "streamable_http",
            "url": "https://mcp.example.com/mcp",
        }))
        .expect("mcp server fixture")],
        agent_upstreams: vec![serde_json::from_value(serde_json::json!({
            "id": "runtime-upstream",
            "name": "Runtime upstream",
            "endpoint": "https://agent.example.com/a2a",
        }))
        .expect("agent upstream fixture")],
        ..Config::default()
    }
}

/// The operator's inline payload, verbatim from the issue: turn the scheduler
/// on, mention no control-plane document at all.
///
/// Parsed rather than constructed, so the fixture is a real inline
/// `config_toml` body walking the same `Config::from_toml_str` the endpoint
/// runs, not a struct that skipped it.
fn unrelated_inline_payload() -> Config {
    Config::from_toml_str("[scheduler]\nenabled = true\n").expect("the operator's payload is valid")
}

fn seed_runtime_provisioned_documents(node: &SharedAppState) {
    node.current()
        .repositories
        .replace_control_plane(control_plane_documents_from_config(
            &runtime_provisioned_config(),
        ))
        .expect("seed the runtime-provisioned control plane");
}

/// The headline defect, at the smallest scale that shows it: one key minted
/// through `POST /admin/v1/api-keys`, one inline reload that never mentions it.
///
/// Reverting `reload_from_admin_payload`'s inline branch to
/// `state.reload_process_local(config_from_admin_payload(...))` reds this on the
/// durable assertion AND the in-memory one -- the row is gone from the store,
/// not merely absent from the live config, which is what makes the loss
/// permanent across a subsequent `source=file` reload.
#[test]
fn an_inline_reload_that_never_mentions_a_minted_key_does_not_revoke_it() {
    let node = SharedAppState::with_source_path(Config::default(), None);
    seed_runtime_provisioned_documents(&node);

    let result = node
        .reload_from_inline_config(unrelated_inline_payload())
        .expect("the inline reload itself succeeds");
    assert!(result.committed, "{result:?}");

    let live = node.current();
    assert!(
        live.config
            .api_keys
            .iter()
            .any(|key| key.id == "minted-at-runtime"),
        "the minted key must still be in the running config: {:?}",
        live.config
            .api_keys
            .iter()
            .map(|key| key.id.as_str())
            .collect::<Vec<_>>()
    );
    let snapshot = live
        .repositories
        .control_plane_snapshot()
        .expect("read the control plane back");
    assert_eq!(
        snapshot.api_keys.len(),
        1,
        "and must still be a durable row, or the loss survives the next reload"
    );
    // The operator's actual edit still took effect -- a merge that silently
    // dropped the payload would pass every assertion above.
    assert!(live.config.scheduler.enabled);
}

/// Acceptance box 2: the same holds for every class in `ControlPlaneDocuments`,
/// because they all go through one projection and one wholesale replace.
///
/// Asserted against the durable snapshot rather than the live config so a class
/// that is merged into memory but not written back cannot pass.
#[test]
fn an_inline_reload_preserves_every_control_plane_document_class() {
    let node = SharedAppState::with_source_path(Config::default(), None);
    seed_runtime_provisioned_documents(&node);

    let result = node
        .reload_from_inline_config(unrelated_inline_payload())
        .expect("the inline reload itself succeeds");
    assert!(result.committed, "{result:?}");

    let snapshot = node
        .current()
        .repositories
        .control_plane_snapshot()
        .expect("read the control plane back");
    for (class, documents) in [
        ("api_keys", &snapshot.api_keys),
        ("tenants", &snapshot.tenants),
        ("policies", &snapshot.policies),
        ("gateway_configs", &snapshot.gateway_configs),
        ("agent_workflows", &snapshot.agent_workflows),
        ("skill_packages", &snapshot.skill_packages),
        ("prompt_templates", &snapshot.prompt_templates),
        ("plugin_registrations", &snapshot.plugin_registrations),
        ("mcp_servers", &snapshot.mcp_servers),
        ("agent_upstreams", &snapshot.agent_upstreams),
    ] {
        assert_eq!(
            documents.len(),
            1,
            "control-plane class {class} was destroyed by an inline reload that never mentioned it"
        );
    }
}

/// Acceptance box 3, the other half: the payload keeps its explicit powers.
/// Absence must not delete, but presence must still introduce and update.
///
/// Both directions matter. A "fix" that reconciled by REPLACE the way
/// `source=file` does would keep the untouched documents and pass the tests
/// above, while silently discarding the operator's new upstream and their edit
/// to the existing one -- so those are asserted here, not assumed.
#[test]
fn an_inline_reload_still_introduces_new_documents_and_updates_existing_ones_by_id() {
    let node = SharedAppState::with_source_path(Config::default(), None);
    seed_runtime_provisioned_documents(&node);

    let payload = Config {
        agent_upstreams: vec![
            serde_json::from_value(serde_json::json!({
                "id": "runtime-upstream",
                "name": "Renamed by the operator",
                "endpoint": "https://agent.example.com/a2a",
            }))
            .expect("updated upstream fixture"),
            serde_json::from_value(serde_json::json!({
                "id": "introduced-by-payload",
                "name": "Introduced by the operator",
                "endpoint": "https://new.example.com/a2a",
            }))
            .expect("new upstream fixture"),
        ],
        ..Config::default()
    };

    let result = node
        .reload_from_inline_config(payload)
        .expect("the inline reload itself succeeds");
    assert!(result.committed, "{result:?}");

    let live = node.current();
    let upstreams: Vec<(&str, &str)> = live
        .config
        .agent_upstreams
        .iter()
        .map(|upstream| (upstream.id.as_str(), upstream.name.as_str()))
        .collect();
    assert_eq!(
        upstreams,
        vec![
            ("runtime-upstream", "Renamed by the operator"),
            ("introduced-by-payload", "Introduced by the operator"),
        ],
        "an update lands in the durable document's slot; a new id is appended"
    );
    // The classes the payload stayed silent about are still whole.
    assert!(
        live.config
            .api_keys
            .iter()
            .any(|key| key.id == "minted-at-runtime"),
        "updating one class must not revoke another"
    );
}
