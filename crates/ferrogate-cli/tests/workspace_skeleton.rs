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

#[test]
fn root_manifest_declares_workspace_members() {
    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();

    assert!(manifest.contains("[workspace]"));
    assert!(manifest.contains("\"crates/ferrogate-config\""));
    assert!(manifest.contains("\"crates/ferrogate-runtime\""));
    assert!(manifest.contains("\"crates/ferrogate-control-plane-client\""));
    assert!(manifest.contains("default-members = [\"crates/ferrogate-cli\"]"));

    // A half-finished crate rename leaves the workspace still building --
    // cargo is happy to carry a member path that also still exists. The
    // #553 renames are therefore asserted from BOTH sides: the new name is
    // present above, and the retired ones are absent here. Re-adding
    // `crates/ferrogate-cli-core` or `crates/ferrogate-auth` to `members`
    // fails this.
    for retired in ["crates/ferrogate-cli-core", "crates/ferrogate-auth\""] {
        assert!(
            !manifest.contains(retired),
            "root manifest still lists retired crate path {retired}"
        );
    }
}
