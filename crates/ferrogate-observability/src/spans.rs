// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Canonical gateway tracing span templates (request, auth, policy,
//! route, dispatch, metering).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySpanKind {
    GatewayRequest,
    Auth,
    Policy,
    ModelRoute,
    ProviderDispatch,
    BillingWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySpanTemplate {
    pub name: &'static str,
    pub kind: GatewaySpanKind,
    pub fields: &'static [&'static str],
}

impl GatewaySpanTemplate {
    pub const fn new(
        name: &'static str,
        kind: GatewaySpanKind,
        fields: &'static [&'static str],
    ) -> Self {
        Self { name, kind, fields }
    }
}

pub const GATEWAY_REQUEST_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.gateway.request",
    GatewaySpanKind::GatewayRequest,
    &[
        "request_id",
        "trace_id",
        "method",
        "path",
        "route",
        "status_code",
    ],
);

pub const AUTH_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.auth",
    GatewaySpanKind::Auth,
    &[
        "request_id",
        "api_key_id",
        "organization_id",
        "project_id",
        "scope",
        "result",
    ],
);

pub const POLICY_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.policy.evaluate",
    GatewaySpanKind::Policy,
    &[
        "request_id",
        "api_key_id",
        "organization_id",
        "project_id",
        "model",
        "provider",
        "result",
    ],
);

pub const MODEL_ROUTE_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.model.route",
    GatewaySpanKind::ModelRoute,
    &[
        "request_id",
        "logical_model",
        "provider",
        "provider_model",
        "candidate_index",
        "fallback_count",
    ],
);

pub const PROVIDER_DISPATCH_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.provider.dispatch",
    GatewaySpanKind::ProviderDispatch,
    &[
        "request_id",
        "logical_model",
        "provider",
        "provider_model",
        "stream",
        "status_code",
        "retryable",
    ],
);

pub const BILLING_WRITE_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.metering.write",
    GatewaySpanKind::BillingWrite,
    &[
        "request_id",
        "organization_id",
        "project_id",
        "api_key_id",
        "logical_model",
        "provider",
        "total_tokens",
        "result",
    ],
);

pub fn default_span_templates() -> &'static [GatewaySpanTemplate] {
    &[
        GATEWAY_REQUEST_SPAN,
        AUTH_SPAN,
        POLICY_SPAN,
        MODEL_ROUTE_SPAN,
        PROVIDER_DISPATCH_SPAN,
        BILLING_WRITE_SPAN,
    ]
}
