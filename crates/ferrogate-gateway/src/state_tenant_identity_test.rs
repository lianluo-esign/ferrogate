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
    let config = Config {
        api_keys: vec![declared_key("config-key")],
        ..Config::default()
    };
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

/// #540 rework 2, review minor 1: the warning that PAYS for the relaxation
/// above, at the moment it is worth something.
///
/// Relaxing a security refusal into a log line is only defensible if the log
/// line exists and reaches the operator. Neither held: deleting the whole
/// `tracing::warn!` reddened nothing in the tree, and it could not fire at boot
/// at all, because `try_new_with_repositories` applies the durable snapshot and
/// never re-validates while `serve` runs only `ensure_auth_posture_is_declared`.
/// A node whose store held pre-#515 rows therefore started in silence and first
/// mentioned them on the operator's next admin write -- the exact "find out
/// from live traffic" failure #540 exists to prevent, reintroduced by #540's
/// own fix.
///
/// This drives a real restart: a second `SharedAppState` over the SAME
/// repositories handle, which is the boot path
/// (`try_new_with_repositories(..., apply_durable_snapshot = true)`).
///
/// Pins three lines, each with its own mutation:
///
/// * delete `config.warn_undeclared_control_plane_api_keys()` from
///   `apply_control_plane_snapshot_to_config_from_repositories` and the
///   captured-log assertions red (nothing is emitted at boot);
/// * delete the `tracing::warn!` inside
///   `Config::warn_undeclared_control_plane_api_keys` and the same two red,
///   while the returned-ids assertion still passes -- which is why both forms
///   are asserted;
/// * delete `config.api_keys_are_control_plane_documents = true` from that same
///   boot function (review minor 10 called that assignment redundant and
///   unpinned) and every assertion here reds, because the method returns empty
///   for a config that is not a durable snapshot.
///
/// It cannot be satisfied by annotating a fixture: the fixture is written into
/// the control-plane store as raw JSON with no identity, and an annotation
/// would red the assertions instead of quieting them.
#[test]
fn a_pre_515_durable_row_is_reported_at_boot_not_only_at_the_next_admin_write() {
    let config = Config {
        api_keys: vec![declared_key("config-key")],
        ..Config::default()
    };
    config.validate().expect("the config file itself is clean");

    let first_boot = SharedAppState::with_source_path(config.clone(), None);
    seed_legacy_undeclared_durable_key(&first_boot, "legacy-one");
    seed_legacy_undeclared_durable_key(&first_boot, "legacy-two");
    let store = first_boot.current().repositories.clone();

    // The restart. Same store, a config document that is itself clean -- which
    // is precisely the deployment that used to boot without a word.
    let mut restarted = None;
    let logged = crate::auth::auth_admission_test::capture_tracing_output(|| {
        restarted = Some(SharedAppState::with_source_path_and_repositories(
            config, None, store,
        ));
    });

    assert!(
        logged.contains("legacy-one") && logged.contains("legacy-two"),
        "boot must name every pre-#515 durable row by id, or the operator's first news of them \
         is a 403 on live traffic: {logged}"
    );
    assert!(
        logged.contains("PUT /admin/v1/api-keys"),
        "...and say how to repair one, since it is a row and not a line in a file: {logged}"
    );

    let restarted = restarted.expect("the restart itself must succeed");
    assert_eq!(
        restarted
            .current()
            .config
            .warn_undeclared_control_plane_api_keys(),
        vec!["legacy-one", "legacy-two"],
        "and the same answer is available without scraping a log"
    );
    assert!(
        restarted
            .current()
            .config
            .api_keys
            .iter()
            .any(|key| key.id == "config-key"),
        "the node really did boot with its config document, so the assertions above are about a \
         warning and not about a failed startup"
    );
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
    let config = Config {
        api_keys: vec![declared_key("config-key")],
        ..Config::default()
    };
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
