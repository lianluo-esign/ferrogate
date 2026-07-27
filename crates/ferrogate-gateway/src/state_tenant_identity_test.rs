// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Unit tests for the #540 tenant-identity refusal on the runtime control-plane mutation path.

//! The half of #540 that had no test, and the lockout that came of it.
//!
//! `apply_control_plane_snapshot_to_config` replaces `config.api_keys`
//! wholesale with the durable control-plane documents, and every runtime
//! mutation then calls `candidate.validate()` on the result. So the refusal
//! written for a config *file* was being applied to durable rows an operator
//! cannot edit out of a file -- and a single pre-#515 row answered `400
//! invalid_api_key` to every admin write, naming a key the request never
//! touched. With two such rows there was no order in which they could be fixed.
//!
//! Both tests here seed exactly that state, which nothing in the tree did
//! before.

use super::*;

/// A pre-#515 durable row: no `organization_id`, no `platform_operator`. This
/// is what a control-plane store minted before the field existed.
fn seed_legacy_undeclared_durable_key(node: &SharedAppState, id: &str) {
    let document = serde_json::json!({
        "id": id,
        "name": "Minted before #515",
        "key": format!("{id}-secret"),
        "scopes": ["chat.completions"],
    })
    .to_string();
    node.current()
        .repositories
        .upsert_control_plane_api_key(id.to_string(), document)
        .expect("seed the pre-#515 durable row");
}

fn declared_key(id: &str) -> ferrogate_config::ApiKey {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "name": id,
        "key": format!("{id}-secret"),
        "scopes": ["chat.completions"],
        "organization_id": "tenant-a",
    }))
    .expect("valid test api key")
}

/// #540 rework, review finding 3. Two legacy rows -- the case that had no exit
/// at all, because each candidate config still contained the other.
///
/// Pins the `if self.api_keys_are_control_plane_documents { warn; return
/// Ok(()) }` arm of `Config::ensure_every_key_declares_tenant_identity`, and
/// the `config.api_keys_are_control_plane_documents = true` assignment in
/// `apply_control_plane_snapshot_to_config`. Delete either and this test reds
/// with `refusing to start: these API keys declare neither organization_id nor
/// platform_operator ... legacy-one, legacy-two`.
///
/// It cannot be satisfied by annotating a fixture: the fixture that must be
/// tolerated is written straight into the control-plane store as raw JSON with
/// no identity, which is the whole input.
#[test]
fn two_pre_515_durable_rows_do_not_block_an_admin_write_that_never_touches_them() {
    let mut config = Config::default();
    config.api_keys = vec![declared_key("config-key")];
    config.validate().expect("the config file itself is clean");

    let node = SharedAppState::with_source_path(config, None);
    seed_legacy_undeclared_durable_key(&node, "legacy-one");
    seed_legacy_undeclared_durable_key(&node, "legacy-two");

    let result = node
        .upsert_api_key(declared_key("brand-new"))
        .expect("a pre-#515 durable row must not 400 an unrelated admin write");
    assert!(result.committed, "{result:?}");

    let live = node.current();
    assert!(
        live.config.api_keys.iter().any(|key| key.id == "brand-new"),
        "and the write actually landed rather than being silently dropped"
    );
    // The legacy rows are still there, still undeclared, still not root. The
    // change is where the operator is told, never what the key may do:
    // `finalize_auth` answers `tenant_identity_required` to both.
    assert_eq!(
        live.config.api_keys_without_tenant_identity(),
        vec!["legacy-one", "legacy-two"],
        "the durable branch reports them; it does not stop seeing them"
    );
    for legacy in live
        .config
        .api_keys
        .iter()
        .filter(|key| key.id == "legacy-one" || key.id == "legacy-two")
    {
        assert!(
            !crate::auth::resolve_platform_operator(
                live.config.tenancy.implicit_platform_operator,
                legacy.platform_operator,
                legacy.organization_id.as_deref(),
            ),
            "a tolerated legacy row is emphatically not a platform operator: {}",
            legacy.id
        );
    }
}

/// The other door, and the reason the change above is not a hole: the mint
/// refusal #540 established for `POST`/`PUT /admin/v1/api-keys` still fires,
/// aimed at the one key the request produces.
///
/// Pins the `candidate.ensure_api_key_declares_tenant_identity(stored)?` call
/// in `SharedAppState::upsert_api_key`. Delete it and the first assertion reds
/// -- the mutation would otherwise be invisible, because the whole-config check
/// beside it deliberately no longer refuses on this path.
#[test]
fn the_admin_api_still_refuses_to_mint_a_key_with_no_tenant_identity() {
    let mut config = Config::default();
    config.api_keys = vec![declared_key("config-key")];
    config.validate().expect("the config file itself is clean");

    let node = SharedAppState::with_source_path(config, None);
    seed_legacy_undeclared_durable_key(&node, "legacy-one");

    // #540-undeclared-on-purpose: the request body that must be refused.
    let undeclared: ferrogate_config::ApiKey = serde_json::from_value(serde_json::json!({
        "id": "brand-new",
        "name": "Brand new",
        "key": "brand-new-secret",
        "scopes": ["chat.completions"],
    }))
    .expect("valid test api key");

    let error = node
        .upsert_api_key(undeclared)
        .expect_err("#540: the admin API must not mint a credential with no tenant identity")
        .to_string();
    assert!(
        error.contains("brand-new"),
        "the 400 names the key the CALLER sent: {error}"
    );
    assert!(
        !error.contains("legacy-one"),
        "and NOT the legacy rows the request never touched -- naming those is the defect this \
         whole change is about: {error}"
    );
    assert!(
        error.contains("platform_operator") && error.contains("organization_id"),
        "and says which of the two to add: {error}"
    );

    assert!(
        !node
            .current()
            .config
            .api_keys
            .iter()
            .any(|key| key.id == "brand-new"),
        "a refused mint leaves nothing behind: the repository write is rolled back"
    );
}
