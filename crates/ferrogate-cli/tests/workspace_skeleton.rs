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
        "ferrogate-auth",
        "ferrogate-billing",
        "ferrogate-cli",
        "ferrogate-config",
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
    assert!(manifest.contains("default-members = [\"crates/ferrogate-cli\"]"));
}
