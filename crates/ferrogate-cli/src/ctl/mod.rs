// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Control Plane API client commands wired onto the shared `ferrogate-cli-core`
//! foundation (issue #360).
//!
//! The `ferrogate-cli-core` crate (foundation commit for #360) already owns the
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
//! `mod.rs` stays thin (declarations + the two dispatch entrypoints main.rs
//! calls); each concern lives in its own file:
//! * [`store`] — on-disk persistence for the library's in-memory `ContextStore`.
//! * [`dispatch`] — shared glue: precedence resolution, credential/stdin/env
//!   readers, the async runtime, and stderr diagnostics.
//! * [`context_cmd`] — the `context` verbs (create/list/show/use/delete).
//! * [`ops_cmd`] — the `ops status` vertical slice on the shared client.

pub(crate) mod context_cmd;
pub(crate) mod dispatch;
pub(crate) mod ops_cmd;
pub(crate) mod store;

pub(crate) use context_cmd::run_context;
pub(crate) use ops_cmd::run_ops;
