// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! CLI release-artifact policy (issue #365).
//!
//! #365 asks for two things this module owns: an explicit supported
//! Linux/macOS/Windows **target policy** for the `ferrogate` binary as a
//! released artifact, and a **CLI/API compatibility matrix plus deprecation
//! policy** covering command names, flags, JSON output, exit codes, the
//! context schema, and Control Plane API versions.
//!
//! Both are declared once here as typed Rust data and rendered into two
//! committed artifacts:
//!
//! * `scripts/cli-release-targets.json` — machine-readable, consumed by
//!   `scripts/package-cli.sh`, so the packaging script cannot build a target
//!   set the policy does not declare;
//! * `docs/cli-compatibility.md` — the operator-facing matrix.
//!
//! The companion sync tests in `release_test.rs` fail on drift, exactly like
//! the `docs/cli-reference.md` snapshot in [`crate::reference`]. Regenerate
//! both with:
//! ```sh
//! FERROGATE_REGENERATE_DOCS=1 cargo test -p ferrogate-cli release
//! ```
//!
//! The exit-code rows are derived from
//! [`ferrogate_control_plane_client::error::ExitClass`] through an exhaustive
//! `match`, so adding a class to the client fails to compile here until it is
//! given a documented stability meaning — the table cannot silently drift from
//! the codes the binary actually returns.

use std::fmt::Write as _;

use ferrogate_control_plane_client::error::ExitClass;

/// How the release process treats a target triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetTier {
    /// The release process builds, checksums and (when a signer is available)
    /// signs a binary for this triple. Only triples the project can actually
    /// produce evidence for belong here.
    Released,
    /// Supported to build and run from source, but the release process
    /// publishes no binary because the project has no build/signing host for
    /// it. Stated explicitly rather than left ambiguous.
    BuildFromSource,
}

impl TargetTier {
    /// Stable identifier used in the JSON manifest and consumed by
    /// `scripts/package-cli.sh`.
    fn id(self) -> &'static str {
        match self {
            TargetTier::Released => "released",
            TargetTier::BuildFromSource => "build-from-source",
        }
    }
}

/// Archive container published for a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveFormat {
    TarGz,
    Zip,
}

impl ArchiveFormat {
    fn id(self) -> &'static str {
        match self {
            ArchiveFormat::TarGz => "tar.gz",
            ArchiveFormat::Zip => "zip",
        }
    }
}

/// One entry of the supported-target policy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SupportedTarget {
    /// Rust target triple.
    pub(crate) triple: &'static str,
    /// Operating system family, as an operator would name it.
    pub(crate) os: &'static str,
    pub(crate) tier: TargetTier,
    /// How the produced binary links against the platform C runtime.
    pub(crate) linkage: &'static str,
    pub(crate) archive: ArchiveFormat,
    /// File name of the binary inside the archive.
    pub(crate) binary: &'static str,
    /// Why this triple sits in its tier. Kept factual: a `Released` entry must
    /// name the in-tree path that already produces it.
    pub(crate) rationale: &'static str,
}

/// The supported target policy for the `ferrogate` CLI.
///
/// The two musl triples are `Released` because the repository already
/// cross-compiles exactly those, fully static, in
/// `scripts/build-image-crane.sh` (zig cc + static musl OpenSSL,
/// `-C target-feature=+crt-static`); packaging them as standalone archives
/// reuses a proven build, it does not assume a new one.
///
/// Everything else is `BuildFromSource`: the project has no macOS or Windows
/// build host and no glibc-baseline policy, so publishing a binary for those
/// would be an unverified claim. `cargo install --path crates/ferrogate-cli`
/// is the supported route there.
pub(crate) const SUPPORTED_TARGETS: &[SupportedTarget] = &[
    SupportedTarget {
        triple: "x86_64-unknown-linux-musl",
        os: "linux",
        tier: TargetTier::Released,
        linkage: "static (musl, +crt-static)",
        archive: ArchiveFormat::TarGz,
        binary: "ferrogate",
        rationale: "already cross-compiled by scripts/build-image-crane.sh; \
                    static, so it carries no glibc baseline",
    },
    SupportedTarget {
        triple: "aarch64-unknown-linux-musl",
        os: "linux",
        tier: TargetTier::Released,
        linkage: "static (musl, +crt-static)",
        archive: ArchiveFormat::TarGz,
        binary: "ferrogate",
        rationale: "already cross-compiled by scripts/build-image-crane.sh; \
                    static, so it carries no glibc baseline",
    },
    SupportedTarget {
        triple: "x86_64-unknown-linux-gnu",
        os: "linux",
        tier: TargetTier::BuildFromSource,
        linkage: "dynamic (glibc of the build host)",
        archive: ArchiveFormat::TarGz,
        binary: "ferrogate",
        rationale: "the container image builds this triple, but a published \
                    archive would inherit an undeclared glibc baseline; use \
                    the musl archive or build from source",
    },
    SupportedTarget {
        triple: "aarch64-unknown-linux-gnu",
        os: "linux",
        tier: TargetTier::BuildFromSource,
        linkage: "dynamic (glibc of the build host)",
        archive: ArchiveFormat::TarGz,
        binary: "ferrogate",
        rationale: "same undeclared glibc baseline as the x86_64 gnu triple",
    },
    SupportedTarget {
        triple: "aarch64-apple-darwin",
        os: "macos",
        tier: TargetTier::BuildFromSource,
        linkage: "dynamic (system libSystem)",
        archive: ArchiveFormat::TarGz,
        binary: "ferrogate",
        rationale: "no macOS build or notarization host in the release \
                    process; nothing signs or verifies a published binary",
    },
    SupportedTarget {
        triple: "x86_64-apple-darwin",
        os: "macos",
        tier: TargetTier::BuildFromSource,
        linkage: "dynamic (system libSystem)",
        archive: ArchiveFormat::TarGz,
        binary: "ferrogate",
        rationale: "no macOS build or notarization host in the release \
                    process; nothing signs or verifies a published binary",
    },
    SupportedTarget {
        triple: "x86_64-pc-windows-msvc",
        os: "windows",
        tier: TargetTier::BuildFromSource,
        linkage: "dynamic (MSVC CRT)",
        archive: ArchiveFormat::Zip,
        binary: "ferrogate.exe",
        rationale: "no Windows build host in the release process; the MSVC \
                    toolchain cannot be driven from the Linux release path",
    },
];

/// A surface whose stability the CLI promises something about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CompatibilitySurface {
    /// Operator-facing name of the surface.
    pub(crate) name: &'static str,
    /// What the project guarantees within a major (calendar) release line.
    pub(crate) guarantee: &'static str,
    /// The change that counts as breaking for this surface — the thing that
    /// must go through the deprecation path rather than ship directly.
    pub(crate) breaking_change: &'static str,
    /// In-tree location a reviewer can check the claim against.
    pub(crate) evidence: &'static str,
}

/// The six surfaces #365 names, in the order the issue names them.
pub(crate) const COMPATIBILITY_SURFACES: &[CompatibilitySurface] = &[
    CompatibilitySurface {
        name: "Command names",
        guarantee: "A command that has shipped keeps parsing. A rename adds \
                    the new name and keeps the old one as an alias that still \
                    performs the same action.",
        breaking_change: "Removing a command or an alias, or changing what an \
                          existing command path does.",
        evidence: "docs/cli-reference.md (drift-checked against the assembled \
                   clap tree by the `reference_doc_is_in_sync` test)",
    },
    CompatibilitySurface {
        name: "Flags",
        guarantee: "An existing flag keeps its name, arity and meaning. New \
                    flags are optional and default to the previous behaviour.",
        breaking_change: "Removing a flag, making an optional flag required, \
                          or changing a default so an unchanged invocation \
                          behaves differently.",
        evidence: "docs/cli-reference.md renders every flag of every command",
    },
    CompatibilitySurface {
        name: "JSON output",
        guarantee: "`--output json` is additive: fields may be added, and \
                    consumers must ignore unknown fields. Field names, types \
                    and nesting of already-emitted fields do not change.",
        breaking_change: "Removing or renaming a field, changing its type, or \
                          re-nesting it.",
        evidence: "crates/ferrogate-cli/src/ctl/resource_cmd.rs and its \
                   `resource_cmd_test.rs` output-contract tests",
    },
    CompatibilitySurface {
        name: "Exit codes",
        guarantee: "The exit-code classes below are frozen: a given failure \
                    class keeps its numeric code, because scripts branch on it.",
        breaking_change: "Renumbering a class, or reclassifying a failure into \
                          a different class.",
        evidence: "crates/ferrogate-control-plane-client/src/error.rs \
                   (`ExitClass::code`)",
    },
    CompatibilitySurface {
        name: "Context schema",
        guarantee: "`contexts.toml` is read forward- and backward-compatibly: \
                    every optional field is `#[serde(default)]`, so an older \
                    file loads in a newer CLI and a newer file loads in an \
                    older one with unknown keys ignored. The file never holds \
                    a token value, only how to obtain one.",
        breaking_change: "Adding a required field, changing the meaning of an \
                          existing field, or moving the file's default path.",
        evidence: "crates/ferrogate-control-plane-client/src/context.rs and \
                   crates/ferrogate-cli/src/ctl/store.rs",
    },
    CompatibilitySurface {
        name: "Control Plane API versions",
        guarantee: "The CLI targets the Control Plane API surface declared in \
                    the checked-in OpenAPI document and tolerates unknown \
                    response fields. Coverage of that surface is enforced, not \
                    asserted: every public operation ID is either mapped to a \
                    command or carries a reviewed exclusion with an owner.",
        breaking_change: "An OpenAPI operation becoming unreachable from the \
                          CLI without a reviewed exclusion, or a duplicate \
                          command mapping.",
        evidence: "crates/ferrogate-control-plane-client/src/parity.rs \
                   (`REVIEWED_EXCLUSIONS`, `build_report`)",
    },
];

/// A deprecation currently in its migration window.
///
/// Only surfaces that really are deprecated in the tree belong here; each
/// entry names the code that emits or accepts the deprecated form so a
/// reviewer can check it rather than take the table's word.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deprecation {
    pub(crate) deprecated: &'static str,
    pub(crate) replacement: &'static str,
    /// Issue that introduced the replacement.
    pub(crate) since_issue: &'static str,
    /// What the CLI does today when the deprecated form is used.
    pub(crate) current_behaviour: &'static str,
    pub(crate) evidence: &'static str,
}

/// Deprecations in flight. Both entries are the #359 Control Plane API rename.
pub(crate) const DEPRECATIONS: &[Deprecation] = &[
    Deprecation {
        deprecated: "`ferrogate admin-api serve`",
        replacement: "`ferrogate control-api serve`",
        since_issue: "#359",
        current_behaviour: "Runs the identical service, preceded by an \
                            actionable deprecation notice on stderr.",
        evidence: "crates/ferrogate-cli/src/admin_api.rs \
                   (`emit_admin_api_command_deprecation`)",
    },
    Deprecation {
        deprecated: "config section `[admin_api]`",
        replacement: "config section `[control_api]`",
        since_issue: "#359",
        current_behaviour: "Accepted and migrated into the effective config at \
                            load; never re-serialized under the old name.",
        evidence: "crates/ferrogate-config/src/config/loader.rs \
                   (`migrate_control_plane_aliases`)",
    },
];

/// Human-readable meaning of an exit class, for the frozen exit-code table.
///
/// Exhaustive on purpose: a new [`ExitClass`] variant breaks this build until
/// its stability meaning is written down, which is the whole point of deriving
/// the table from the enum instead of hand-listing it.
fn exit_class_meaning(class: ExitClass) -> &'static str {
    match class {
        ExitClass::Success => "The command completed and any mutation was accepted.",
        ExitClass::Usage => {
            "Caller-side misuse: bad flags, unknown command, or invalid local \
             configuration/context. Nothing was sent."
        }
        ExitClass::Auth => {
            "Authentication or authorization failure: missing or invalid \
             credential, insufficient scope, or wrong tenant."
        }
        ExitClass::NotFoundConflict => {
            "The addressed resource does not exist, or the mutation conflicts \
             with current state."
        }
        ExitClass::Validation => "The request reached the server and was rejected as invalid.",
        ExitClass::Transport => {
            "No authoritative server answer: connection failure, timeout, TLS \
             failure, or a retryable throttle. Safe to retry only for reads or \
             idempotent mutations."
        }
        ExitClass::Server => "The server accepted the request but failed to process it.",
    }
}

/// Every exit class, in ascending code order — the order the table is read in.
const EXIT_CLASSES: &[ExitClass] = &[
    ExitClass::Success,
    ExitClass::Usage,
    ExitClass::Auth,
    ExitClass::NotFoundConflict,
    ExitClass::Validation,
    ExitClass::Transport,
    ExitClass::Server,
];

/// Render the machine-readable target manifest consumed by
/// `scripts/package-cli.sh`.
///
/// Hand-rolled rather than `serde_json`-derived so the field order and the
/// two-space indentation are fixed by this function: the file is committed and
/// diffed, and a serializer's ordering is not part of this crate's contract.
/// Ends with exactly one trailing newline.
pub(crate) fn render_target_manifest() -> String {
    let mut out = String::new();
    out.push_str(
        "{\n  \"$comment\": \"Generated by crates/ferrogate-cli/src/release.rs (issue #365); \
         do NOT edit by hand. Regenerate: FERROGATE_REGENERATE_DOCS=1 cargo test -p \
         ferrogate-cli release\",\n  \"binary\": \"ferrogate\",\n  \"package\": \
         \"ferrogate-cli\",\n  \"targets\": [\n",
    );
    for (index, target) in SUPPORTED_TARGETS.iter().enumerate() {
        let separator = if index + 1 == SUPPORTED_TARGETS.len() {
            "\n"
        } else {
            ",\n"
        };
        let _ = write!(
            out,
            "    {{\n      \"triple\": \"{triple}\",\n      \"os\": \"{os}\",\n      \
             \"tier\": \"{tier}\",\n      \"linkage\": \"{linkage}\",\n      \
             \"archive\": \"{archive}\",\n      \"binary\": \"{binary}\"\n    }}{separator}",
            triple = target.triple,
            os = target.os,
            tier = target.tier.id(),
            linkage = target.linkage,
            archive = target.archive.id(),
            binary = target.binary,
        );
    }
    out.push_str("  ]\n}\n");
    out
}

/// Render `docs/cli-compatibility.md`: the target policy, the compatibility
/// matrix, the frozen exit codes, and the deprecation policy.
///
/// Deterministic, with no version string embedded, so a release bump does not
/// churn the document (same rule as [`crate::reference`]).
pub(crate) fn render_compatibility_doc() -> String {
    let mut out = String::new();
    out.push_str(PREAMBLE);

    out.push_str("\n## Supported targets\n\n");
    out.push_str(
        "`released` targets are built, archived and checksummed by \
         `scripts/package-cli.sh` as part of a release. `build-from-source` \
         targets are expected to compile and pass tests, but the release \
         process publishes no binary for them — install with `cargo install \
         --path crates/ferrogate-cli` instead. A target is only `released` if \
         something in this repository already builds it.\n\n",
    );
    out.push_str("| Target triple | OS | Tier | Linkage | Archive | Why |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for target in SUPPORTED_TARGETS {
        let _ = writeln!(
            out,
            "| `{triple}` | {os} | {tier} | {linkage} | `{archive}` | {rationale} |",
            triple = target.triple,
            os = target.os,
            tier = target.tier.id(),
            linkage = target.linkage,
            archive = target.archive.id(),
            rationale = target.rationale,
        );
    }

    out.push_str("\n## Compatibility matrix\n\n");
    out.push_str(
        "What each operator-visible surface promises within a release line, \
         and what counts as a breaking change to it.\n\n",
    );
    for surface in COMPATIBILITY_SURFACES {
        let _ = writeln!(out, "### {}\n", surface.name);
        let _ = writeln!(out, "- **Guarantee:** {}", surface.guarantee);
        let _ = writeln!(out, "- **Breaking change:** {}", surface.breaking_change);
        let _ = writeln!(out, "- **Checked in:** {}\n", surface.evidence);
    }

    out.push_str("## Exit codes\n\n");
    out.push_str(
        "Frozen. Generated from `ExitClass` in \
         `crates/ferrogate-control-plane-client/src/error.rs`, so a new class \
         cannot reach the binary without appearing here.\n\n",
    );
    out.push_str("| Code | Class | Meaning |\n| --- | --- | --- |\n");
    for class in EXIT_CLASSES {
        let _ = writeln!(
            out,
            "| `{code}` | {class:?} | {meaning} |",
            code = class.code(),
            meaning = exit_class_meaning(*class),
        );
    }

    out.push_str("\n## Deprecation policy\n\n");
    out.push_str(DEPRECATION_POLICY);

    out.push_str("\n### Deprecations in flight\n\n");
    out.push_str("| Deprecated | Replacement | Since | Behaviour today | Checked in |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for deprecation in DEPRECATIONS {
        let _ = writeln!(
            out,
            "| {deprecated} | {replacement} | {since} | {behaviour} | {evidence} |",
            deprecated = deprecation.deprecated,
            replacement = deprecation.replacement,
            since = deprecation.since_issue,
            behaviour = deprecation.current_behaviour,
            evidence = deprecation.evidence,
        );
    }

    out
}

/// Title and orientation. Constant text, so it stays trivially in sync with
/// the generated body below it.
const PREAMBLE: &str = "\
# FerroGate CLI compatibility and release policy

<!--
Generated by `crates/ferrogate-cli/src/release.rs`; do NOT edit by hand.
Regenerate after changing the policy:
    FERROGATE_REGENERATE_DOCS=1 cargo test -p ferrogate-cli release
The `release` sync tests fail CI when this file, or
`scripts/cli-release-targets.json`, drifts from that module.
-->

This document is the contract for operators and for anything scripting the
`ferrogate` CLI: which binaries a release publishes, and what may change about
the command surface between releases.

The full command surface itself lives in
[`docs/cli-reference.md`](./cli-reference.md), which is generated from the same
`clap` tree the binary parses. Migration notes from the legacy `admin-api`
naming live in [`docs/cli-migration.md`](./cli-migration.md).
";

/// The deprecation rules, as prose. Kept as one constant because it is policy
/// text rather than data derived from the tables.
const DEPRECATION_POLICY: &str = "\
A surface listed in the matrix above is never removed outright. It goes
through:

1. **Deprecate.** The replacement ships and the old form keeps working
   unchanged. Using the old form emits an actionable notice on **stderr**,
   never on stdout, so `--output json` stays machine-parseable and a piped
   consumer is unaffected. The deprecation is recorded in the table below and
   in `docs/cli-migration.md`.
2. **Migrate.** The deprecated form stays for at least one full calendar
   release line (`vYYYY.MM.DD` tags share a line while the year and month are
   unchanged). Documentation and examples move to the replacement immediately.
3. **Remove.** Removal happens only in a release whose notes name the removed
   surface and the replacement. Removing a command, a flag, a JSON field, an
   exit-code class or a context field without that notice is a defect, not a
   release decision.

Anything not listed in the matrix — log line wording, help text prose, the
ordering of human-readable (non-JSON) output — carries no stability promise and
may change in any release.
";

#[cfg(test)]
#[path = "release_test.rs"]
mod release_test;
