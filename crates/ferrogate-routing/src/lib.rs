// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Route matching and upstream selection boundaries.

pub mod rollout;

pub use rollout::{canary_selected, rollout_bucket, shadow_sampled, ShadowBudgetLedger};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch {
    pub route_name: String,
    pub upstream_name: String,
}

pub trait RouteMatcher {
    fn match_route(&self, host: Option<&str>, path: &str) -> Option<RouteMatch>;
}
