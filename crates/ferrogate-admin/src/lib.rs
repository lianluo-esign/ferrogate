// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Admin API boundary.
//!
//! Home of the [`control_plane`] contract that promotes this admin surface into
//! the supported, versioned public **FerroGate Control Plane API** (issue #359)
//! without breaking existing admin clients.

pub mod control_plane;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayStatus {
    pub service: String,
    pub version: String,
    pub runtime: String,
}
