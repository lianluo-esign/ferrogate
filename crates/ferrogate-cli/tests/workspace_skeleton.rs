// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::path::Path;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
}

#[test]
fn each_p0_crate_has_manifest_and_lib_or_bin_target() {
    let crates = [
        "ferrogate-admin",
        "ferrogate-auth-service",
        "ferrogate-billing",
        "ferrogate-cli",
        "ferrogate-config",
        // Renamed from `ferrogate-cli-core` (#553). Listed here for the same
        // reason `ferrogate-auth-service` is: the directory move is the half
        // of a crate rename that `cargo check` alone would not catch if the
        // manifest and the tree disagreed, so an assertion has to name it.
        // Revert `git mv crates/ferrogate-cli-core
        // crates/ferrogate-control-plane-client` and this fails.
        "ferrogate-control-plane-client",
        "ferrogate-core",
        "ferrogate-observability",
        "ferrogate-policy",
        "ferrogate-providers",
        "ferrogate-routing",
        "ferrogate-runtime",
        "ferrogate-storage",
    ];

    for krate in crates {
        let root = repo_root().join("crates").join(krate);
        assert!(
            root.join("Cargo.toml").is_file(),
            "{krate} missing Cargo.toml"
        );
        assert!(
            root.join("src/lib.rs").is_file() || root.join("src/main.rs").is_file(),
            "{krate} missing Rust target"
        );
    }
}

/// The root manifest's `[workspace]` arrays, parsed rather than grepped.
///
/// The previous version of this test asked `manifest.contains("\"crates/x\"")`.
/// That is a question about the bytes of the file, not about the workspace:
/// moving a member entry into `exclude`, or commenting it out, leaves the
/// substring exactly where it was and the assertion green -- and the workspace
/// still *builds*, because every crate named here is also a path dependency of
/// `ferrogate-cli`, so nothing else would have noticed either.
///
/// Parsing is also what lets the retired-path check compare whole entries. The
/// old spelling needed a hand-written closing quote on `crates/ferrogate-auth`
/// to stop it matching `crates/ferrogate-auth-service`; one of the two retired
/// paths carried that anchor and the other did not, and a future prose mention
/// of either path anywhere in the manifest would have failed the test for no
/// reason at all.
fn workspace_array(manifest: &str, key: &str) -> Option<Vec<String>> {
    let document: toml::Value = manifest.parse().expect("root Cargo.toml is not valid TOML");
    let entries = document.get("workspace")?.get(key)?.as_array()?;
    Some(
        entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("[workspace] {key} entry is not a string"))
                    .to_string()
            })
            .collect(),
    )
}

fn required_workspace_array(manifest: &str, key: &str) -> Vec<String> {
    workspace_array(manifest, key).unwrap_or_else(|| panic!("[workspace] has no {key} array"))
}

#[test]
fn root_manifest_declares_workspace_members() {
    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();
    let members = required_workspace_array(&manifest, "members");
    let default_members = required_workspace_array(&manifest, "default-members");

    for required in [
        "crates/ferrogate-config",
        "crates/ferrogate-runtime",
        "crates/ferrogate-control-plane-client",
    ] {
        assert!(
            members.iter().any(|member| member == required),
            "[workspace] members does not contain {required}: {members:?}"
        );
    }
    assert_eq!(default_members, ["crates/ferrogate-cli"]);

    // A half-finished crate rename leaves the workspace still building --
    // cargo is happy to carry a member path that also still exists. The
    // #553 renames are therefore asserted from BOTH sides: the new name is
    // present above, and the retired ones are absent here. Re-adding
    // `crates/ferrogate-cli-core` or `crates/ferrogate-auth` to `members`
    // fails this, and so does parking either one in `exclude` or
    // `default-members` instead: "still named by the workspace" is the
    // property, not "still named by the one array someone thought to check".
    let exclude = workspace_array(&manifest, "exclude").unwrap_or_default();
    for retired in ["crates/ferrogate-cli-core", "crates/ferrogate-auth"] {
        for (array, entries) in [
            ("members", &members),
            ("default-members", &default_members),
            ("exclude", &exclude),
        ] {
            assert!(
                !entries.iter().any(|entry| entry == retired),
                "[workspace] {array} still lists retired crate path {retired}"
            );
        }
        assert!(
            !repo_root().join(retired).exists(),
            "{retired} still exists on disk, so the rename is half-done"
        );
    }
}
