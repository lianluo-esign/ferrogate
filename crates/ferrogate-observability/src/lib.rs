// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Logging, metrics, and tracing boundaries.

//!
//! The crate entry file stays thin (docs/engineering-standards.md, issue
//! #434): each concern lives in a sibling module below and the full public
//! API is re-exported here unchanged.

mod backend;
mod cloudflare;
mod config;
mod metrics;
mod otlp;
mod prometheus;
mod spans;

pub use backend::*;
pub use cloudflare::*;
pub use config::*;
pub use metrics::*;
pub use otlp::*;
pub use prometheus::*;
pub use spans::*;

#[cfg(test)]
#[path = "lib_test.rs"]
mod lib_test;
