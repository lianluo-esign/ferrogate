//! Logging, metrics, and tracing boundaries.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityConfig {
    pub service_name: String,
    pub traces_enabled: bool,
    pub metrics_enabled: bool,
    pub logs_enabled: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "ferrogate".to_string(),
            traces_enabled: true,
            metrics_enabled: true,
            logs_enabled: true,
        }
    }
}

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
    "ferrogate.billing.write",
    GatewaySpanKind::BillingWrite,
    &[
        "request_id",
        "organization_id",
        "project_id",
        "api_key_id",
        "logical_model",
        "provider",
        "total_tokens",
        "cost",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_observability_config_enables_all_signal_types() {
        let config = ObservabilityConfig::default();

        assert_eq!(config.service_name, "ferrogate");
        assert!(config.traces_enabled);
        assert!(config.metrics_enabled);
        assert!(config.logs_enabled);
    }

    #[test]
    fn span_templates_cover_prd_request_provider_and_billing_hierarchy() {
        let templates = default_span_templates();

        assert_eq!(templates[0].name, "ferrogate.gateway.request");
        assert!(templates.iter().any(|template| template.kind
            == GatewaySpanKind::ProviderDispatch
            && template.fields.contains(&"retryable")));
        assert!(templates
            .iter()
            .any(|template| template.kind == GatewaySpanKind::BillingWrite
                && template.fields.contains(&"total_tokens")
                && template.fields.contains(&"cost")));
    }
}
