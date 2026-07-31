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
            "revision": 1,
            "cache_enabled": false,
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
            "version": "1.0.0",
            // A package must expose at least one capability, and the capability
            // must resolve -- this one points at the MCP server declared below.
            "capabilities": [{"kind": "mcp_server", "id": "runtimemcp"}],
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
            // An enabled plugin must be one the gateway can actually load;
            // `hook.noop` is the in-tree request hook that exists for exactly
            // this purpose.
            "id": "hook.noop",
            "kind": "request_hook",
        }))
        .expect("plugin fixture")],
        mcp_servers: vec![serde_json::from_value(serde_json::json!({
            // No '-': `validate_mcp_servers` reserves it as the
            // `serverName-toolName` separator, and the merged whole is now
            // validated, so a name the Admin API would itself have rejected can
            // no longer sit in the fixture.
            "name": "runtimemcp",
            "transport": "streamable_http",
            "url": "https://mcp.example.com/mcp",
            // Execution is deny-by-default and an EMPTY list is rejected, so a
            // registered server has to name at least one tool.
            "tools_to_execute": ["search"],
        }))
        .expect("mcp server fixture")],
        agent_upstreams: vec![serde_json::from_value(serde_json::json!({
            "id": "runtime-upstream",
            "name": "Runtime upstream",
            "endpoint": "https://agent.example.com/a2a",
            "capabilities": ["invoke"],
        }))
        .expect("agent upstream fixture")],
        ..Config::default()
    }
}

/// The operator's inline payload, from the issue: turn the scheduler on, mention
/// no control-plane document at all.
///
/// Parsed rather than constructed, so the fixture is a real inline
/// `config_toml` body walking the same `Config::from_toml_str` the endpoint
/// runs, not a struct that skipped it.
///
/// It carries the providers and models too, because a real inline payload does:
/// those are NOT control-plane documents, so they come only from the payload and
/// a body that omitted them would be asking to delete every model. That is also
/// what keeps the merged whole valid now that it is validated -- the durable
/// documents below reference `gpt-4o`, and dropping it is the rejection asserted
/// by `an_inline_reload_whose_payload_orphans_a_durable_reference_is_rejected`.
fn unrelated_inline_payload() -> Config {
    Config::from_toml_str(
        r#"
[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:65535/v1"

[[models]]
name = "gpt-4o"
provider = "openai"
provider_model = "gpt-4o"

[scheduler]
enabled = true
"#,
    )
    .expect("the operator's payload is valid")
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
                "capabilities": ["invoke"],
            }))
            .expect("updated upstream fixture"),
            serde_json::from_value(serde_json::json!({
                "id": "introduced-by-payload",
                "name": "Introduced by the operator",
                "endpoint": "https://new.example.com/a2a",
                "capabilities": ["invoke"],
            }))
            .expect("new upstream fixture"),
        ],
        ..unrelated_inline_payload()
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

/// Acceptance box 4: a failed durable write is surfaced, not swallowed.
///
/// This is the box that had no test. The `?` on
/// `sync_control_plane_storage_from_config` is unreachable on the default
/// in-memory control plane -- `replace_config_documents` there cannot fail -- so
/// the failure is injected at the repository boundary instead, which is the same
/// boundary a Postgres/D1 write error crosses.
///
/// Restoring `let _ =` in `with_reloaded_config` reds this on `committed`: the
/// reload would answer `200 {"committed":true}` for a control plane that was
/// never written.
#[test]
fn an_inline_reload_whose_durable_write_fails_is_not_committed() {
    let node = SharedAppState::with_source_path(Config::default(), None);
    seed_runtime_provisioned_documents(&node);
    let before = node.current().config.clone();

    node.current()
        .repositories
        .fail_next_control_plane_replacement("simulated durable control-plane write failure");

    let result = node
        .reload_from_inline_config(unrelated_inline_payload())
        .expect("a failed durable write is a rejected reload, not a caller-visible error");

    assert!(
        !result.committed,
        "a reload whose durable write failed must not report committed: {result:?}"
    );
    let reason = result
        .reason
        .as_deref()
        .expect("a rejected reload must carry a reason");
    assert!(
        reason.contains("could not be persisted to the durable control plane"),
        "the operator must be told persistence is what failed: {reason}"
    );
    // The raw `StorageError` goes to the log, never to the response body: on the
    // Postgres backend it can carry DSN or SQL detail.
    assert!(
        !reason.contains("simulated durable control-plane write failure"),
        "the storage error detail must not reach the admin response: {reason}"
    );

    // And the running config really is the pre-reload one -- the claim the
    // rejection message makes.
    let live = node.current();
    assert!(
        !live.config.scheduler.enabled,
        "the rejected candidate's scheduler setting must not have been applied"
    );
    assert_eq!(
        live.config.models.len(),
        before.models.len(),
        "the rejected candidate's models must not have been applied"
    );
}

/// The union produces a combination neither side validated on its own, so the
/// merged whole is validated before it can commit.
///
/// `models` is not a control-plane document class, so it comes only from the
/// payload: a payload that drops `gpt-4o` while a durable `deny` policy still
/// names it yields a config `validate_policies` rejects. Committing it would
/// silently retire that deny rule -- a security control disabled by a reload the
/// operator ran for an unrelated reason.
///
/// Deleting `candidate.validate()?` from `merged_inline_candidate` reds this.
#[test]
fn an_inline_reload_whose_payload_orphans_a_durable_reference_is_rejected() {
    let node = SharedAppState::with_source_path(Config::default(), None);
    seed_runtime_provisioned_documents(&node);

    // Same payload, minus the model the durable `runtime-policy` denies.
    let payload = Config::from_toml_str("[scheduler]\nenabled = true\n")
        .expect("the operator's payload parses on its own");

    let error = node
        .reload_from_inline_config(payload)
        .expect_err("the merged whole must be rejected");
    let message = format!("{error:#}");
    assert!(
        message.contains("runtime-policy") || message.contains("gpt-4o"),
        "the rejection must name the dangling reference: {message}"
    );

    let live = node.current();
    assert!(
        !live.config.scheduler.enabled,
        "a rejected candidate must not have been applied"
    );
    let snapshot = live
        .repositories
        .control_plane_snapshot()
        .expect("read the control plane back");
    assert_eq!(
        snapshot.api_keys.len(),
        1,
        "and must not have reached the destructive durable write"
    );
}

/// `POST /admin/v1/config/validate` is a pre-flight for `POST
/// /admin/v1/config/reload`, so for one body it must answer for one candidate.
///
/// The inline reload applies the MERGED config, and `reload_process_local`
/// derives `candidate_snapshot` from it. A validate that judged the raw payload
/// would return a different `snapshot` for the same body, which breaks the
/// `active_snapshot` vs `candidate_snapshot` comparison an operator uses to tell
/// "already applied" from "will change something" -- and would answer
/// `valid: true` for the payload rejected by the test above.
///
/// Reverting the validate handler to `config_from_admin_payload` reds this.
#[test]
fn validate_and_reload_describe_the_same_candidate_for_one_inline_body() {
    let node = SharedAppState::with_source_path(Config::default(), None);
    seed_runtime_provisioned_documents(&node);

    let validated = node
        .merged_inline_candidate(unrelated_inline_payload())
        .expect("the pre-flight accepts the body");
    let preflight_snapshot = config_snapshot_id(&validated);

    let result = node
        .reload_from_inline_config(unrelated_inline_payload())
        .expect("and so does the reload");
    assert!(result.committed, "{result:?}");
    assert_eq!(
        preflight_snapshot, result.candidate_snapshot,
        "validate and reload must report one snapshot id for one body"
    );

    // The pre-flight must also REJECT what the reload rejects.
    let orphaning_payload = Config::from_toml_str("[scheduler]\nenabled = true\n")
        .expect("the operator's payload parses on its own");
    assert!(
        node.merged_inline_candidate(orphaning_payload).is_err(),
        "a pre-flight that answers valid:true for a body the reload rejects is worthless"
    );
}
