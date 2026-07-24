// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Typed, bounded Guardrail detector contracts for FerroGate.

//! Narrow Guardrail detector contracts and the built-in `custom_http` runtime.
//!
//! Policy composition belongs to `ferrogate-policy`; gateway request wiring
//! belongs to `ferrogate-cli`. This crate owns only detector execution and its
//! safety boundary: async I/O, deadlines, bulkheads, circuit state, safe DNS,
//! typed results, and constrained text patches.
//!
//! The crate entry file stays thin (docs/engineering-standards.md, issue
//! #434): each concern lives in a sibling module below and the full public
//! API is re-exported here unchanged.

mod policy;
pub use policy::*;
mod envelope;
pub use envelope::*;
mod deterministic;
pub use deterministic::*;
mod adapters;
pub use adapters::*;
mod contract;
pub use contract::*;
mod custom_http;
pub use custom_http::*;
mod net;
pub use net::*;

/// Reusable detector conformance harness and its in-repo mock adapter. Gated so
/// the mock never enters a production build: available under `cfg(test)` and
/// behind the opt-in `conformance` feature for downstream adapter authors.
#[cfg(any(test, feature = "conformance"))]
pub mod conformance;

/// Versioned detector evaluation corpus + accuracy/latency runner (#201). Same
/// gating as `conformance`: never in a production build.
#[cfg(any(test, feature = "conformance"))]
pub mod evaluation;

#[cfg(test)]
mod adapters_test;
#[cfg(test)]
mod conformance_test;
#[cfg(test)]
mod deterministic_test;
#[cfg(test)]
mod evaluation_test;
#[cfg(test)]
mod lib_test;

// The sibling test file below is declared at the crate root (its pre-split
// home) and reaches these std names through `use super::*`; keep them
// resolvable at the root scope, test builds only.
#[cfg(test)]
use std::{
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, Instant},
};
