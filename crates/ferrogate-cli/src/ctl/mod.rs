// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Control Plane API client commands wired onto the shared `ferrogate-control-plane-client`
//! foundation (issue #360).
//!
//! The `ferrogate-control-plane-client` crate (foundation commit for #360) already owns the
//! typed transport, context/precedence resolution, credential sources, output
//! rendering, error/exit taxonomy, and the compile-time command registry — with
//! its own unit tests. What was missing was any *consumer*: nothing composed the
//! library into the shipping `ferrogate` binary, so no operator could actually
//! run a command through the shared client.
//!
//! This module is that composition. It delivers the first user-reachable
//! vertical slice — `ferrogate ops status` on the shared typed transport, plus
//! `ferrogate context` management with on-disk persistence — establishing the
//! wiring pattern that later resource families (#361–#365) plug into without
//! touching transport, renderer, or context code.
//!
//! `mod.rs` stays thin (declarations + the dispatch entrypoints main.rs
//! calls); each concern lives in its own file:
//! * [`store`] — on-disk persistence for the library's in-memory `ContextStore`.
//! * [`dispatch`] — shared glue: precedence resolution, credential/stdin/env
//!   readers, the async runtime, and stderr diagnostics.
//! * [`context_cmd`] — the `context` verbs (create/list/show/use/delete).
//! * [`ops_cmd`] — the `ops status` vertical slice on the shared client.
//! * [`resource_cmd`] — the generic `ctl <group> <verb>` tree (#361–#365) built
//!   from the `ferrogate-control-plane-client` registry and dispatched through the same
//!   foundation, with no per-resource code in the binary.

pub(crate) mod context_cmd;
pub(crate) mod dispatch;
pub(crate) mod ops_cmd;
pub(crate) mod resource_cmd;
pub(crate) mod store;

/// Cross-crate pin that the CLI's `action_fingerprint` byte-matches the
/// runtime's `CanonicalCapabilityTarget::fingerprint` (issue #505). It lives
/// here, in the binary, because this is the only crate that depends on BOTH
/// `ferrogate-control-plane-client` and `ferrogate-runtime`.
#[cfg(test)]
#[path = "fingerprint_parity_test.rs"]
mod fingerprint_parity_test;

pub(crate) use context_cmd::run_context;
pub(crate) use ops_cmd::run_ops;
pub(crate) use resource_cmd::{build_ctl_command, run_resource, CTL_COMMAND};
