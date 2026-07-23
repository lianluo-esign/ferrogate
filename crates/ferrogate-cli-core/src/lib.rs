// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! # ferrogate-cli-core
//!
//! Reusable foundation for the FerroGate **Control Plane API** command-line
//! client (epic #358, foundation slice #360).
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
//! * [`transport`] — one typed Control Plane API transport: pure request
//!   building ([`transport::prepare_request`]), response classification
//!   ([`transport::classify`]) preserving status/error-code/request-id/
//!   trace-id/retry hint, pagination planning, and a [`transport::Transport`]
//!   seam with a `reqwest` implementation.
//! * [`output`] — stable machine JSON and human tables; stdout is data,
//!   stderr is diagnostics.
//! * [`command`] — the extensible [`command::Registry`] / [`command::CommandGroup`]
//!   skeleton that lets #361–#365 add resource families (and their OpenAPI
//!   `operationId` coverage) as compile-time metadata, with no rewiring.
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

pub mod agent;
pub mod args;
pub mod asset;
pub mod auth;
pub mod billing;
pub mod command;
pub mod context;
pub mod error;
pub mod evidence;
pub mod guardrail;
pub mod iam;
pub mod mcp;
pub mod ops;
pub mod organization;
pub mod output;
pub mod parity;
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
/// families, #363 the asset families, and #364 the billing/usage, evidence, and
/// operator-action families (including gateway config profiles).
pub fn register_resource_families(registry: &mut Registry) -> CliResult<()> {
    organization::register(registry)?;
    iam::register(registry)?;
    agent::register(registry)?;
    worker::register(registry)?;
    mcp::register(registry)?;
    tool_approval::register(registry)?;
    guardrail::register(registry)?;
    asset::register(registry)?;
    billing::register(registry)?;
    evidence::register(registry)?;
    ops::register(registry)?;
    Ok(())
}
