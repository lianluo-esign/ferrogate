// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Scenario coverage for the config file loader entrypoint (#102).

use ferrogate_config::{is_caddyfile_path, load_caddyfile};
use std::path::Path;

#[test]
fn is_caddyfile_path_matches_case_insensitively() {
    assert!(is_caddyfile_path(Path::new("/etc/ferrogate/Caddyfile")));
    assert!(is_caddyfile_path(Path::new("caddyfile")));
    assert!(is_caddyfile_path(Path::new("/x/CADDYFILE")));
    // A different name or an extension is not a Caddyfile.
    assert!(!is_caddyfile_path(Path::new("Caddyfile.txt")));
    assert!(!is_caddyfile_path(Path::new("gateway.yaml")));
    assert!(!is_caddyfile_path(Path::new("/")));
}

#[test]
fn load_caddyfile_reads_and_parses_a_valid_file() {
    let raw = include_str!("../../../Ferrogate/Caddyfile");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(&path, raw).unwrap();

    let config = load_caddyfile(&path).expect("valid Caddyfile must load");
    assert_eq!(config.listen, "0.0.0.0:8080");
    assert!(!config.routes.is_empty());
}

#[test]
fn load_caddyfile_missing_file_errors_with_path_context() {
    let err = load_caddyfile(Path::new("/no/such/dir/Caddyfile")).unwrap_err();
    assert!(err.to_string().contains("failed to read Caddyfile"));
}

#[test]
fn load_caddyfile_invalid_content_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(&path, "}{ this is not a valid caddyfile @@@ {{").unwrap();

    assert!(load_caddyfile(&path).is_err());
}
