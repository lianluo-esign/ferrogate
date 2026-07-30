// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Release-policy snapshot and invariant tests (issue #365).
//!
//! Two kinds of test live here:
//!
//! * **Snapshot** — the committed `scripts/cli-release-targets.json` and
//!   `docs/cli-compatibility.md` must equal what [`super`] generates, so the
//!   packaging script and the operator-facing matrix cannot drift from the
//!   policy. `FERROGATE_REGENERATE_DOCS=1` rewrites them instead of asserting.
//! * **Invariant** — the policy tables are internally consistent, and the
//!   claims they make about the rest of the tree (the deprecated `admin-api`
//!   command, the frozen exit codes) are checked against that tree rather than
//!   taken on trust.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ferrogate_control_plane_client::error::ExitClass;

use super::{ArchiveFormat, TargetTier, COMPATIBILITY_SURFACES, DEPRECATIONS, SUPPORTED_TARGETS};

/// Absolute path to a repository-root-relative file, resolved from this
/// crate's manifest dir so tests are CWD-independent.
fn repo_path(segments: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    for segment in segments {
        path = path.join(segment);
    }
    path
}

/// Shared snapshot assertion: committed file equals `generated`, or is
/// rewritten when `FERROGATE_REGENERATE_DOCS` is set.
fn assert_committed_matches(path: &Path, generated: &str, label: &str) {
    if std::env::var_os("FERROGATE_REGENERATE_DOCS").is_some() {
        std::fs::write(path, generated).unwrap_or_else(|error| {
            panic!("write regenerated {}: {error}", path.display());
        });
        return;
    }

    let committed = std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}. Generate it with \
             `FERROGATE_REGENERATE_DOCS=1 cargo test -p ferrogate-cli release`",
            path.display()
        )
    });

    assert_eq!(
        committed, generated,
        "{label} is out of sync with crates/ferrogate-cli/src/release.rs. Regenerate with \
         `FERROGATE_REGENERATE_DOCS=1 cargo test -p ferrogate-cli release`"
    );
}

/// The manifest `scripts/package-cli.sh` reads is the one this module declares.
#[test]
fn target_manifest_is_in_sync() {
    assert_committed_matches(
        &repo_path(&["scripts", "cli-release-targets.json"]),
        &super::render_target_manifest(),
        "scripts/cli-release-targets.json",
    );
}

/// The operator-facing compatibility matrix is the one this module declares.
#[test]
fn compatibility_doc_is_in_sync() {
    assert_committed_matches(
        &repo_path(&["docs", "cli-compatibility.md"]),
        &super::render_compatibility_doc(),
        "docs/cli-compatibility.md",
    );
}

/// Target triples are unique: `scripts/package-cli.sh` keys its build plan on
/// the triple, so a duplicate would silently package one entry twice.
#[test]
fn target_triples_are_unique() {
    let mut seen = BTreeSet::new();
    for target in SUPPORTED_TARGETS {
        assert!(
            seen.insert(target.triple),
            "duplicate target triple in SUPPORTED_TARGETS: {}",
            target.triple
        );
    }
}

/// Every released target is one the repository can actually build today.
///
/// The two musl triples are released precisely because
/// `scripts/build-image-crane.sh` already cross-compiles them; this test reads
/// that script and fails if a triple is promoted to `Released` without the
/// build path that justifies it, or if the script stops building one.
#[test]
fn released_targets_are_built_by_an_in_tree_path() {
    let script = std::fs::read_to_string(repo_path(&["scripts", "build-image-crane.sh"]))
        .expect("read scripts/build-image-crane.sh");

    let released: Vec<&str> = SUPPORTED_TARGETS
        .iter()
        .filter(|target| target.tier == TargetTier::Released)
        .map(|target| target.triple)
        .collect();

    assert!(
        !released.is_empty(),
        "the release process must publish at least one target"
    );

    for triple in released {
        assert!(
            script.contains(triple),
            "target '{triple}' is tier `released`, but scripts/build-image-crane.sh does not \
             build it — either demote it to `build-from-source` or add the build path"
        );
    }
}

/// Windows ships a `.exe` in a zip; every other target ships a bare binary in
/// a tarball. Mismatches here produce archives operators cannot unpack with
/// the documented command.
#[test]
fn archive_format_and_binary_name_match_the_os() {
    for target in SUPPORTED_TARGETS {
        if target.os == "windows" {
            assert_eq!(
                target.archive,
                ArchiveFormat::Zip,
                "{} is a Windows target and must ship a zip",
                target.triple
            );
            assert!(
                target.binary.ends_with(".exe"),
                "{} is a Windows target and must ship ferrogate.exe",
                target.triple
            );
        } else {
            assert_eq!(
                target.archive,
                ArchiveFormat::TarGz,
                "{} must ship a tar.gz",
                target.triple
            );
            assert_eq!(
                target.binary, "ferrogate",
                "{} must ship a bare `ferrogate` binary",
                target.triple
            );
        }
        assert!(
            target.triple.contains(target.os) || target.os == "macos",
            "target '{}' is declared os '{}', which its triple does not name",
            target.triple,
            target.os
        );
    }
}

/// The policy covers all three operating systems #365 names explicitly. A
/// silently dropped OS is the failure this test exists to catch: the issue
/// asks for the position to be stated, not for the position to be "released".
#[test]
fn every_named_operating_system_has_a_stated_position() {
    for os in ["linux", "macos", "windows"] {
        assert!(
            SUPPORTED_TARGETS.iter().any(|target| target.os == os),
            "#365 requires an explicit target policy for {os}; none is declared"
        );
    }
}

/// The frozen exit-code table really is frozen: the codes rendered into the
/// document are the codes `ExitClass` returns, and no two classes collide.
#[test]
fn exit_codes_are_unique_and_documented() {
    let document = super::render_compatibility_doc();
    let mut seen = BTreeSet::new();
    for class in [
        ExitClass::Success,
        ExitClass::Usage,
        ExitClass::Auth,
        ExitClass::NotFoundConflict,
        ExitClass::Validation,
        ExitClass::Transport,
        ExitClass::Server,
    ] {
        let code = class.code();
        assert!(
            seen.insert(code),
            "exit code {code} is claimed by more than one ExitClass"
        );
        assert!(
            document.contains(&format!("| `{code}` | {class:?} |")),
            "exit class {class:?} (code {code}) is missing from the generated matrix"
        );
    }
}

/// Each deprecation names a real replacement and cites code that exists.
///
/// The `admin-api` entry is checked against the module that actually emits the
/// notice, so deleting the deprecation path without updating the table fails
/// here rather than leaving a stale operator promise.
#[test]
fn deprecations_cite_live_code() {
    assert!(
        !DEPRECATIONS.is_empty(),
        "the deprecation table documents the #359 rename; emptying it needs a release note"
    );

    for deprecation in DEPRECATIONS {
        assert!(
            !deprecation.replacement.is_empty(),
            "deprecation '{}' has no replacement — the policy forbids removal without one",
            deprecation.deprecated
        );
        assert_ne!(
            deprecation.deprecated, deprecation.replacement,
            "deprecation '{}' points at itself",
            deprecation.deprecated
        );
    }

    let admin_api = std::fs::read_to_string(repo_path(&[
        "crates",
        "ferrogate-cli",
        "src",
        "admin_api.rs",
    ]))
    .expect("read crates/ferrogate-cli/src/admin_api.rs");
    assert!(
        admin_api.contains("emit_admin_api_command_deprecation"),
        "the compatibility matrix promises `ferrogate admin-api serve` still emits a \
         deprecation notice, but admin_api.rs no longer defines one"
    );
}

/// Every surface #365 names is present, and each carries all four columns —
/// a surface with an empty guarantee is a promise nobody can check.
#[test]
fn compatibility_surfaces_are_complete() {
    for expected in [
        "Command names",
        "Flags",
        "JSON output",
        "Exit codes",
        "Context schema",
        "Control Plane API versions",
    ] {
        assert!(
            COMPATIBILITY_SURFACES
                .iter()
                .any(|surface| surface.name == expected),
            "#365 names the '{expected}' surface; the matrix omits it"
        );
    }

    for surface in COMPATIBILITY_SURFACES {
        for (column, value) in [
            ("guarantee", surface.guarantee),
            ("breaking change", surface.breaking_change),
            ("evidence", surface.evidence),
        ] {
            assert!(
                !value.trim().is_empty(),
                "surface '{}' has an empty {column}",
                surface.name
            );
        }
    }
}

/// The generated JSON is parseable and exposes exactly the fields the
/// packaging script reads. `scripts/package-cli.sh` resolves its build plan by
/// loading this file with `python3 -m json`, keying on `triple`, `tier`,
/// `archive` and `binary`, so both the syntax and those key spellings are
/// load-bearing.
#[test]
fn target_manifest_exposes_the_fields_the_packaging_script_reads() {
    let manifest = super::render_target_manifest();
    let parsed: serde_json::Value =
        serde_json::from_str(&manifest).expect("generated target manifest must be valid JSON");

    let targets = parsed["targets"]
        .as_array()
        .expect("manifest must carry a `targets` array");
    assert_eq!(
        targets.len(),
        SUPPORTED_TARGETS.len(),
        "manifest target count must match SUPPORTED_TARGETS"
    );

    for (entry, target) in targets.iter().zip(SUPPORTED_TARGETS) {
        for key in ["triple", "os", "tier", "linkage", "archive", "binary"] {
            assert!(
                entry[key].is_string(),
                "manifest entry for '{}' is missing string field '{key}'",
                target.triple
            );
        }
        assert_eq!(entry["triple"].as_str(), Some(target.triple));
    }
}
