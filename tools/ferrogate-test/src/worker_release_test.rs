// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Focused tests for the clean Worker release gate (#468).

use super::*;
use serde_json::json;

#[test]
fn lockfile_rejects_external_package_without_integrity() {
    let temp = tempfile::tempdir().unwrap();
    let lock = temp.path().join("package-lock.json");
    fs::write(
        &lock,
        serde_json::to_vec(&json!({
            "packages": {
                "": { "name": "fixture" },
                "node_modules/complete": {
                    "resolved": "https://registry.example/complete.tgz",
                    "integrity": "sha512-complete"
                },
                "node_modules/broken": {
                    "resolved": "https://registry.example/broken.tgz"
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let error = verify_lockfile(&lock).unwrap_err().to_string();
    assert!(error.contains("node_modules/broken"), "{error}");
}

#[test]
fn exact_dependency_pin_rejects_a_floating_range() {
    let manifest = json!({ "devDependencies": { "wrangler": "^4.107.1" } });
    let error = assert_dependency(
        &manifest,
        Path::new("package.json"),
        "devDependencies",
        "wrangler",
        WRANGLER_VERSION,
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("pin wrangler exactly"), "{error}");
}

#[test]
fn clean_copy_excludes_installed_modules_and_local_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let destination = temp.path().join("destination");
    fs::create_dir_all(source.join("src")).unwrap();
    fs::create_dir_all(source.join("node_modules/pkg")).unwrap();
    fs::create_dir_all(source.join(".wrangler/state")).unwrap();
    fs::create_dir_all(source.join("coverage")).unwrap();
    fs::create_dir_all(source.join("dist")).unwrap();
    fs::write(source.join("src/index.ts"), "export {};\n").unwrap();
    fs::write(source.join("node_modules/pkg/index.js"), "installed\n").unwrap();
    fs::write(source.join(".dev.vars"), "TOKEN=secret\n").unwrap();
    fs::write(source.join(".env"), "TOKEN=secret\n").unwrap();

    copy_tree(&source, &destination).unwrap();

    assert!(destination.join("src/index.ts").is_file());
    assert!(!destination.join("node_modules").exists());
    assert!(!destination.join(".wrangler").exists());
    assert!(!destination.join("coverage").exists());
    assert!(!destination.join("dist").exists());
    assert!(!destination.join(".dev.vars").exists());
    assert!(!destination.join(".env").exists());
}

#[test]
fn vitest_result_rejects_an_empty_suite() {
    let temp = tempfile::tempdir().unwrap();
    let result = temp.path().join("vitest-results.json");
    fs::write(
        &result,
        serde_json::to_vec(&json!({
            "success": true,
            "numTotalTests": 0,
            "numPassedTests": 0
        }))
        .unwrap(),
    )
    .unwrap();

    let error = verify_vitest_result(&result).unwrap_err().to_string();
    assert!(error.contains("empty Vitest suite"), "{error}");
}
