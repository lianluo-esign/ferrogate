// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! # ferrogate-control-plane-client
//!
//! The typed **client** for the FerroGate **Control Plane API** (epic #358,
//! foundation slice #360): the transport, the credential and context
//! resolution in front of it, the receipt envelope behind it, and the
//! resource command registry the `ferrogate` binary composes into
//! `ferrogate ctl <group> <verb>`.
//!
//! ## What the name asserts, and how to check it
//!
//! Renamed from `ferrogate-cli-core` in #553's rework. Two claims are packed
//! into the new name, and both are falsifiable rather than aspirational:
//!
//! * **"control-plane"** — every path this crate builds is under
//!   `/admin/v1/`. That is not a convention here, it is enforced: the #365
//!   parity gate in [`parity`] places the *data plane* — the
//!   OpenAI-compatible inference endpoints, MCP/tool execution, and agent
//!   invoke/messaging — structurally outside the surface this crate is
//!   allowed to cover, via the operation-level `x-ferrogate-data-plane`
//!   OpenAPI extension (#390). A verb for live inference is a gate failure,
//!   not a coverage win. So "the client of the control plane, and nothing
//!   else" is the one thing about this crate a test can already fail on.
//! * **"client"** — it binds no listener, exposes no `main`, and its
//!   dependency list contains no `ferrogate-*` crate at all: `clap`, `http`,
//!   `reqwest`, `serde`, `serde_json`, `sha2`. Nothing here can serve the API
//!   it talks to.
//!
//! The old name asserted neither. Worse, it asserted something false: at
//! `4c2ba43`, an ancestor of the commit that writes this line, the crate is
//! **20,961 `.rs` lines across 53 files against `crates/ferrogate-cli/src`'s
//! 6,200 across 28 — 3.38×** the crate it claimed to be the `-core` of, and
//! "core" described none of the contents. The figure names a commit instead of
//! saying "this tree" because every previous phrasing of it went stale inside
//! one review round, and the command beside it has to name the commit too:
//!
//! ```text
//! git ls-tree -r --name-only 4c2ba43 -- crates/<dir> | grep '\.rs$' \
//!   | xargs -I{} git show 4c2ba43:{} | wc -l
//! ```
//!
//! reproduces both halves. The `git ls-files … | xargs cat | wc -l` published
//! here before reads the working tree instead, and returns 20,965 and 136,724
//! at `801b449` for the two figures pinned as 20,961 and 136,681 — the same
//! stale-number defect, one level down in the instructions for checking it.
//! #553's
//! objective is that a module's name and its code agree; the fold below is
//! refused, so the rename is what carries that objective for this crate.
//!
//! ## Crate boundary and why it is a library, not a binary
//!
//! Epic #358 made an explicit product decision: extend the existing
//! `ferrogate` binary as the one management CLI and **do not** ship a second
//! `ferrogatectl` binary that duplicates packaging, auth, and command
//! discovery. It also mandated that the *reusable typed Control Plane API
//! client and shared schemas* live "behind a narrowly justified dedicated
//! crate" rather than being copy-pasted into every command family. This crate
//! is exactly that dedicated crate: a **library** the `ferrogate` binary (and
//! later resource command modules #361–#365) compose. It deliberately exposes
//! no `main` and registers no second binary, so it satisfies #360's
//! foundation without violating #358's single-binary decision.
//!
//! ## Modules (narrow interfaces, one concern each)
//!
//! * [`error`] — stable [`error::ExitClass`] exit-code taxonomy and the typed
//!   [`error::ApiError`] / [`error::CliError`] surface every command maps onto.
//! * [`context`] — named [`context::Context`] server profiles, the
//!   [`context::ContextStore`], and the deterministic precedence resolver
//!   ([`context::resolve`]): flag > env > context > default.
//! * [`auth`] — pluggable, typed credential sources ([`auth::AuthSource`]) and
//!   a self-redacting [`auth::Credential`]; tokens are never persisted in a
//!   context, only *how to obtain* them.
//! * [`action_identity`] — the per-invocation [`action_identity::ClientActionIdentity`]
//!   (`action_id`, client fingerprint, the client's own unverified clock
//!   reading, and the server-issued time token it echoes), which
//!   [`transport::prepare_request`] takes as a **required** argument so a new
//!   verb cannot issue an unattributable request (issue #548).
//! * [`transport`] — one typed Control Plane API transport: pure request
//!   building ([`transport::prepare_request`]), response classification
//!   ([`transport::classify`]) preserving status/error-code/request-id/
//!   trace-id/retry hint, pagination planning, and a [`transport::Transport`]
//!   seam with a `reqwest` implementation.
//! * [`output`] — stable machine JSON and human tables; stdout is data,
//!   stderr is diagnostics.
//! * [`receipt`] — the [`receipt::MutationReceipt`] decision envelope, the ONE
//!   sanctioned return shape of a mutating verb (issue #505), plus the render
//!   gate that makes "a mutating verb rendered a bare body" a type error and
//!   the `--dry-run` plan that cannot issue a request because no transport is
//!   in scope.
//! * [`command`] — the extensible [`command::Registry`] / [`command::CommandGroup`]
//!   skeleton that lets #361–#365 add resource families (and their OpenAPI
//!   `operationId` coverage) as compile-time metadata, with no rewiring.
//! * [`dispatch`] — the generic `<group> <verb>` → [`transport::RequestSpec`]
//!   router (and read-only secret redaction) a composing binary drives to reach
//!   every registered resource family without naming a single resource.
//! * [`args`] — Clap-derived shared global flags folded into
//!   [`context::GlobalOverrides`].
//! * [`version`] — CLI/API version reporting and a fail-closed compatibility
//!   check against the Control Plane API contract version.
//!
//! ## Contract-friendly, not contract-hardwired
//!
//! The transport carries `serde_json` bodies and preserves the server's
//! `ferrogate_error` envelope shape from the enforced OpenAPI contract, but it
//! does **not** bake in per-resource request/response structs. Issue #365
//! layers typed, generated-from-OpenAPI models on top of this seam without
//! having to rip out ad-hoc shapes.
//!
//! ## Why this was NOT folded back into `ferrogate-cli` (#553 stage 4)
//!
//! Stage 4 asked the question, because the reason this crate was carved out
//! has expired: #505 needed somewhere to put CLI command machinery while
//! `ferrogate-cli` was 154k lines, and `ferrogate-cli` is ~5.6k lines now.
//! Nothing but `ferrogate-cli` depends on this crate, so folding would drag
//! the CLI binary into no third party. It was still refused, for three
//! reasons a reviewer can check:
//!
//! 1. **The fold would erase a load-bearing *absence* of a dependency.** This
//!    crate deliberately does not depend on `ferrogate-runtime`, so
//!    [`receipt::CliActionTarget`] MIRRORS `CanonicalCapabilityTarget::Network`
//!    rather than reusing it, and `ferrogate-cli` -- which depends on both --
//!    pins the mirror by asserting byte equality of the canonical JSON and the
//!    `canonical_target_sha256` digest (`ctl/fingerprint_parity_test.rs`).
//!    Merged into `ferrogate-cli`, `receipt.rs` would sit in a crate that
//!    already links `ferrogate-runtime`; the mirror could be quietly replaced
//!    by a call or a re-export, and a test that today has real force would
//!    become a crate comparing itself to itself. That is issue #500's failure
//!    mode -- a green test that no longer holds anything -- bought for a
//!    cosmetic gain.
//! 2. **The two crates are different kinds of thing, and the dependency lists
//!    say so.** This is a client library: `clap`, `http`, `reqwest`, `serde`,
//!    `sha2`. `ferrogate-cli` is the process entrypoint: `pingora`, `rustls`,
//!    `tokio`, `ferrogate-storage`, `ferrogate-runtime`, `ferrogate-gateway`.
//!    Epic #358 decided in writing that the reusable typed Control Plane API
//!    client lives "behind a narrowly justified dedicated crate"; that
//!    justification is the dependency list above, not the line count that
//!    happened to prompt the carve-out.
//! 3. **CI would lose a fast hermetic slice.** `rust-cli-tooling-tests.yml`
//!    runs `cargo test -p ferrogate-control-plane-client --all-features` over
//!    19.6k lines with **no pingora, no gateway, no storage and no
//!    `ferrogate-runtime`** in the build. Folded, those cases only run behind
//!    a full Pingora + storage + runtime compile.
//!
//!    An earlier draft of this box said "no gateway, storage or TLS in the
//!    build". The TLS half was wrong and is corrected here rather than
//!    quietly dropped: the workspace pins `reqwest` with
//!    `features = ["rustls-no-provider", "stream"]`, so rustls and reqwest's
//!    tokio client ARE linked into this slice. What is absent is a rustls
//!    *crypto provider* (the composing binary installs one) and the whole
//!    server stack. The absence that makes the slice worth having is the
//!    dependency-graph one, not a TLS one.
//!
//! ## The name was the remaining defect, and it is fixed rather than deferred
//!
//! Refusing the fold left `ferrogate-cli-core` — a name that claimed to be
//! the core of a crate a third its size. #553's objective is that a module's
//! name and its code agree, so refusing the fold and keeping the name would
//! have closed the issue with the defect intact. The crate is therefore
//! `ferrogate-control-plane-client`, and the two claims that name makes are
//! stated and made checkable at the top of this file. The fold stays refused;
//! the naming argument is answered by the rename, which costs no test.

pub mod action_identity;
pub mod agent;
pub mod args;
pub mod asset;
pub mod auth;
pub mod billing;
pub mod catalog;
pub mod command;
pub mod context;
pub mod dispatch;
pub mod error;
pub mod evidence;
pub mod guardrail;
pub mod iam;
pub mod mcp;
pub mod ops;
pub mod organization;
pub mod output;
pub mod parity;
pub mod raw_transfer;
pub mod receipt;
pub mod registry_helpers;
pub mod resource;
pub mod tool_approval;
pub mod transport;
pub mod version;
pub mod worker;

pub use command::Registry;
pub use error::{ApiError, CliError, CliResult, ExitClass};

/// Register every resource command family this crate provides onto a fresh
/// [`Registry`]. The composing `ferrogate` binary (epic #358) calls this to get
/// the full client command surface; #361 contributes the organization and IAM
/// families, #362 the agent / worker / MCP / tool-approval / guardrail lifecycle
/// families, #363 the asset families plus the catalog families (prompt
/// templates, skill packages, plugins, read-only model/provider/extension
/// catalogs, and the admin dashboard aggregate reads), and #364 the
/// billing/usage, evidence, and operator-action families (including gateway
/// config profiles).
pub fn register_resource_families(registry: &mut Registry) -> CliResult<()> {
    organization::register(registry)?;
    iam::register(registry)?;
    agent::register(registry)?;
    worker::register(registry)?;
    mcp::register(registry)?;
    tool_approval::register(registry)?;
    guardrail::register(registry)?;
    asset::register(registry)?;
    catalog::register(registry)?;
    billing::register(registry)?;
    evidence::register(registry)?;
    ops::register(registry)?;
    Ok(())
}
