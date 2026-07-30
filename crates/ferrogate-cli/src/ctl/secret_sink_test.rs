// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the `--secret-file` safe sink (#361).

use super::*;
use ferrogate_control_plane_client::error::ExitClass;
use serde_json::json;

/// A unique path under the OS temp dir that does not exist yet. Named from the
/// test's own label plus a process-unique counter so parallel tests cannot
/// collide.
fn scratch_path(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ferrogate-secret-sink-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn diverted(field: &str, pointer: &str, value: Value) -> DivertedSecret {
    DivertedSecret {
        pointer: pointer.to_string(),
        field: field.to_string(),
        value,
    }
}

#[test]
fn reserve_creates_the_file_before_anything_is_sent() {
    let path = scratch_path("reserve");
    let file = SecretFile::reserve(&path).expect("fresh path must be reservable");
    assert!(path.exists(), "the reservation must exist on disk");
    assert_eq!(file.path(), path.as_path());
    file.discard();
    let _ = std::fs::remove_file(&path);
}

#[cfg(unix)]
#[test]
fn the_reserved_file_is_created_0600_not_chmodded_afterwards() {
    use std::os::unix::fs::PermissionsExt;
    let path = scratch_path("mode");
    let file = SecretFile::reserve(&path).expect("fresh path must be reservable");
    // Read the mode while the file is still empty: the point of setting it at
    // creation is that there is no window in which key material sits in a
    // world-readable file.
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mode was {mode:o}");
    file.commit(&json!({"key": "sk-live"})).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mode after commit was {mode:o}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_existing_path_is_refused_with_nothing_sent() {
    let path = scratch_path("exists");
    std::fs::write(&path, b"operator data").unwrap();
    let error = SecretFile::reserve(&path).expect_err("an existing path must be refused");
    assert_eq!(error.exit_class(), ExitClass::Usage);
    let message = error.to_string();
    assert!(message.contains("already exists"), "{message}");
    // The refusal must promise that nothing was sent — that promise is only
    // true because the reservation happens before the request.
    assert!(message.contains("Nothing was sent"), "{message}");
    // The operator's file is untouched.
    assert_eq!(std::fs::read(&path).unwrap(), b"operator data");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn commit_writes_the_secret_document_as_json() {
    let path = scratch_path("commit");
    let file = SecretFile::reserve(&path).unwrap();
    file.commit(&json!({"key": "sk-live-abc"})).unwrap();
    let written: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(written, json!({"key": "sk-live-abc"}));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn discard_removes_a_reservation_that_received_no_key_material() {
    let path = scratch_path("discard");
    let file = SecretFile::reserve(&path).unwrap();
    assert_eq!(file.discard(), None);
    assert!(
        !path.exists(),
        "an empty reservation must not survive: it would make the next run's already-exists \
         refusal fire on a file holding nothing"
    );
}

#[test]
fn wrote_notice_names_every_diverted_field_and_the_path() {
    let notice = wrote_notice(
        Path::new("/tmp/key.json"),
        &[
            diverted("key", "/key", json!("sk-1")),
            diverted("key_id", "/key_id", json!("id-1")),
        ],
    );
    assert!(notice.contains("key, key_id"), "{notice}");
    assert!(notice.contains("/tmp/key.json"), "{notice}");
    assert!(notice.contains("0600"), "{notice}");
}

#[test]
fn the_stdout_warning_names_the_flag_that_would_have_prevented_it() {
    let warning = stdout_exposure_warning(&["key".to_string()]);
    assert!(warning.contains("--secret-file"), "{warning}");
    assert!(warning.contains("key"), "{warning}");
}
