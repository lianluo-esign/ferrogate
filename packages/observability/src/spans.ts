/**
 * Canonical gateway tracing span templates (request, auth, policy, route,
 * dispatch, metering). Clean-room port of `ferrogate-observability::spans`.
 */

export const GatewaySpanKind = {
  GatewayRequest: "GatewayRequest",
  Auth: "Auth",
  Policy: "Policy",
  ModelRoute: "ModelRoute",
  ProviderDispatch: "ProviderDispatch",
  BillingWrite: "BillingWrite",
} as const;
export type GatewaySpanKind = (typeof GatewaySpanKind)[keyof typeof GatewaySpanKind];

export interface GatewaySpanTemplate {
  readonly name: string;
  readonly kind: GatewaySpanKind;
  readonly fields: readonly string[];
}

export const GATEWAY_REQUEST_SPAN: GatewaySpanTemplate = {
  name: "ferrogate.gateway.request",
  kind: GatewaySpanKind.GatewayRequest,
  fields: ["request_id", "trace_id", "method", "path", "route", "status_code"],
};

export const AUTH_SPAN: GatewaySpanTemplate = {
  name: "ferrogate.auth",
  kind: GatewaySpanKind.Auth,
  fields: [
    "request_id",
    "api_key_id",
    "organization_id",
    "project_id",
    "scope",
    "result",
  ],
};

export const POLICY_SPAN: GatewaySpanTemplate = {
  name: "ferrogate.policy.evaluate",
  kind: GatewaySpanKind.Policy,
  fields: [
    "request_id",
    "api_key_id",
    "organization_id",
    "project_id",
    "model",
    "provider",
    "result",
  ],
};

export const MODEL_ROUTE_SPAN: GatewaySpanTemplate = {
  name: "ferrogate.model.route",
  kind: GatewaySpanKind.ModelRoute,
  fields: [
    "request_id",
    "logical_model",
    "provider",
    "provider_model",
    "candidate_index",
    "fallback_count",
  ],
};

export const PROVIDER_DISPATCH_SPAN: GatewaySpanTemplate = {
  name: "ferrogate.provider.dispatch",
  kind: GatewaySpanKind.ProviderDispatch,
  fields: [
    "request_id",
    "logical_model",
    "provider",
    "provider_model",
    "stream",
    "status_code",
    "retryable",
  ],
};

export const BILLING_WRITE_SPAN: GatewaySpanTemplate = {
  name: "ferrogate.metering.write",
  kind: GatewaySpanKind.BillingWrite,
  fields: [
    "request_id",
    "organization_id",
    "project_id",
    "api_key_id",
    "logical_model",
    "provider",
    "total_tokens",
    "result",
  ],
};

const DEFAULT_SPAN_TEMPLATES: readonly GatewaySpanTemplate[] = [
  GATEWAY_REQUEST_SPAN,
  AUTH_SPAN,
  POLICY_SPAN,
  MODEL_ROUTE_SPAN,
  PROVIDER_DISPATCH_SPAN,
  BILLING_WRITE_SPAN,
];

export function defaultSpanTemplates(): readonly GatewaySpanTemplate[] {
  return DEFAULT_SPAN_TEMPLATES;
}
