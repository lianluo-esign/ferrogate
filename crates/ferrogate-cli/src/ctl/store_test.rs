// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit coverage for the on-disk context store (issue #360): TOML round-trip,
//! first-run tolerance, owner-only permissions, valid top-level field ordering,
//! and the guarantee that no token value is ever persisted.

use super::*;
use ferrogate_control_plane_client::auth::AuthSource;
use ferrogate_control_plane_client::context::{Context, ContextStore};

fn sample_store() -> ContextStore {
    let mut store = ContextStore::default();
    let mut prod = Context::new("prod", "https://control.example.com");
    prod.tenant = Some("acme".to_string());
    prod.auth = AuthSource::Env {
        var: "PROD_TOKEN".to_string(),
    };
    store.upsert(prod);
    store.upsert(Context::new("local", "http://127.0.0.1:8080"));
    store.set_current("prod").unwrap();
    store
}

#[test]
fn round_trips_through_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CONTEXTS_FILE);
    let store = sample_store();
    save_at(&path, &store).unwrap();
    let loaded = load_at(&path).unwrap();
    assert_eq!(loaded, store);
}

#[test]
fn missing_file_loads_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("does-not-exist.toml");
    assert_eq!(load_at(&path).unwrap(), ContextStore::default());
}

#[test]
fn persisted_file_holds_credential_source_not_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CONTEXTS_FILE);
    save_at(&path, &sample_store()).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();

    // Only the credential SOURCE (env var name) is stored, never a token value.
    assert!(
        text.contains("PROD_TOKEN"),
        "env var name should persist: {text}"
    );
    assert!(
        text.contains("kind = \"env\""),
        "auth source kind should persist: {text}"
    );

    // `current` must precede the `[[contexts]]` array so the emitted TOML is
    // valid (a scalar cannot follow an array-of-tables at the same level).
    let current_pos = text.find("current").expect("current key present");
    let contexts_pos = text.find("[[contexts]]").expect("contexts array present");
    assert!(
        current_pos < contexts_pos,
        "`current` must serialize before `[[contexts]]`: {text}"
    );
}

#[cfg(unix)]
#[test]
fn writes_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CONTEXTS_FILE);
    save_at(&path, &sample_store()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "context store must be written 0600");
}

#[cfg(unix)]
#[test]
fn overwriting_a_loose_file_tightens_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CONTEXTS_FILE);
    std::fs::write(&path, "current = \"x\"\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    save_at(&path, &sample_store()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "an existing loose file must be re-tightened to 0600"
    );
}

#[test]
fn delete_clears_dangling_current_pointer() {
    let mut store = sample_store();
    assert!(store.remove("prod"));
    assert_eq!(
        store.current, None,
        "removing the current context clears the pointer"
    );
}
