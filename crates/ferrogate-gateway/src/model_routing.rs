// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Typed physical-model route requirements, exclusion decisions,
// and bounded request-correlated audit evidence (issue #582).

use std::collections::{BTreeSet, HashSet};

use ferrogate_core::TenantContext;
use ferrogate_providers::{ModelCapability, ModelRoute, RoutingStrategy};
use http::StatusCode;
use serde::Serialize;
use serde_json::Value;

use crate::state::{AdminAuditEventDraft, AppState};

const MAX_ROUTE_EXCLUSIONS: usize = 32;
const MAX_EVIDENCE_COMPONENT_CHARS: usize = 160;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModelEndpointKind {
    ChatCompletions,
    Responses,
    AnthropicMessages,
    Embeddings,
    Images,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ModelRouteRequirements {
    capabilities: BTreeSet<ModelCapability>,
    /// Compatibility applies only to an otherwise feature-neutral chat-style
    /// request and only when the physical route has no capability declaration
    /// at all. An explicitly declared non-chat route must not inherit this
    /// exemption.
    allow_undeclared_capabilities: bool,
    /// Conservative upper bound for ordinary text input tokens. It uses
    /// serialized UTF-8 bytes, not the billing estimator: every ordinary input
    /// token consumes at least one byte, and the full JSON envelope also covers
    /// structural message framing.
    pub(crate) input_token_upper_bound: Option<u64>,
    /// Exact caller-declared maximum output tokens.
    pub(crate) explicit_output_tokens: Option<u64>,
    /// Conservative total of input upper bound plus explicit output maximum.
    pub(crate) required_context_window: Option<u64>,
    /// The request carries media whose provider-side token cost cannot be
    /// bounded from the request envelope. Such a request is excluded before
    /// dispatch instead of treating a short URL or compressed payload as the
    /// media token cost.
    unbounded_media_context: bool,
}

impl ModelRouteRequirements {
    pub(crate) fn from_request(
        endpoint: ModelEndpointKind,
        body: &Value,
        stream: bool,
        request_input_token_upper_bound: u64,
        injected_tool_token_upper_bound: u64,
    ) -> Self {
        let mut requirements = Self::default();
        match endpoint {
            ModelEndpointKind::Embeddings => requirements.require(ModelCapability::Embeddings),
            ModelEndpointKind::Images => requirements.require(ModelCapability::Images),
            ModelEndpointKind::ChatCompletions
            | ModelEndpointKind::Responses
            | ModelEndpointKind::AnthropicMessages => {
                requirements.require(ModelCapability::Chat);
            }
        }
        if stream {
            requirements.require(ModelCapability::Streaming);
        }
        if injected_tool_token_upper_bound > 0 || non_empty(body.get("tools")) {
            requirements.require(ModelCapability::Tools);
        }
        if structured_output_requested(body, endpoint) {
            requirements.require(ModelCapability::StructuredOutput);
        }
        let contains_image_input = request_contains_image_input(body, endpoint);
        if contains_image_input {
            requirements.require(ModelCapability::Vision);
        }
        requirements.explicit_output_tokens = explicit_output_token_bound(body, endpoint);
        if contains_image_input {
            requirements.unbounded_media_context = true;
        } else if matches!(
            endpoint,
            ModelEndpointKind::ChatCompletions
                | ModelEndpointKind::Responses
                | ModelEndpointKind::AnthropicMessages
        ) {
            let input_tokens =
                request_input_token_upper_bound.saturating_add(injected_tool_token_upper_bound);
            requirements.input_token_upper_bound = Some(input_tokens);
            let required_context_window = input_tokens
                .saturating_add(requirements.explicit_output_tokens.unwrap_or_default());
            if required_context_window > 0 {
                requirements.required_context_window = Some(required_context_window);
            }
        }
        requirements.allow_undeclared_capabilities =
            matches!(
                endpoint,
                ModelEndpointKind::ChatCompletions
                    | ModelEndpointKind::Responses
                    | ModelEndpointKind::AnthropicMessages
            ) && requirements.explicit_output_tokens.is_none()
                && !requirements.unbounded_media_context
                && requirements.capabilities.len() == 1
                && requirements.capabilities.contains(&ModelCapability::Chat);
        requirements
    }

    pub(crate) fn require(&mut self, capability: ModelCapability) {
        self.capabilities.insert(capability);
    }

    pub(crate) fn capabilities(&self) -> impl Iterator<Item = ModelCapability> + '_ {
        self.capabilities.iter().copied()
    }

    #[cfg(test)]
    pub(crate) fn is_neutral(&self) -> bool {
        self.allow_undeclared_capabilities
    }

    fn summary(&self) -> String {
        let capabilities = if self.capabilities.is_empty() {
            "none".to_string()
        } else {
            self.capabilities()
                .map(ModelCapability::as_str)
                .collect::<Vec<_>>()
                .join(",")
        };
        let input = self
            .input_token_upper_bound
            .map_or_else(|| "none".to_string(), |value| value.to_string());
        let output = self
            .explicit_output_tokens
            .map_or_else(|| "none".to_string(), |value| value.to_string());
        let context = self
            .required_context_window
            .map_or_else(|| "none".to_string(), |value| value.to_string());
        format!(
            "required_capabilities={capabilities};input_token_upper_bound={input};explicit_output_tokens={output};required_context_window={context};unbounded_media_context={};allow_undeclared_capabilities={}",
            self.unbounded_media_context,
            self.allow_undeclared_capabilities
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelRouteCandidateIdentity {
    pub(crate) provider: String,
    pub(crate) provider_model: String,
}

impl From<&ModelRoute> for ModelRouteCandidateIdentity {
    fn from(route: &ModelRoute) -> Self {
        Self {
            provider: route.provider.clone(),
            provider_model: route.provider_model.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ModelRouteExclusionReason {
    MissingCapability(ModelCapability),
    MediaContextUnbounded,
    ContextWindowUndeclared { required: u64 },
    ContextWindowTooSmall { required: u64, declared: u32 },
    RegionUndeclared,
    RegionNotAllowed { declared: String },
}

impl ModelRouteExclusionReason {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::MissingCapability(_) => "missing_capability",
            Self::MediaContextUnbounded => "media_context_unbounded",
            Self::ContextWindowUndeclared { .. } => "context_window_undeclared",
            Self::ContextWindowTooSmall { .. } => "context_window_too_small",
            Self::RegionUndeclared => "region_undeclared",
            Self::RegionNotAllowed { .. } => "region_not_allowed",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::MissingCapability(capability) => {
                format!("required_capability={}", capability.as_str())
            }
            Self::MediaContextUnbounded => {
                "media_kind=image;provider_neutral_token_upper_bound=unavailable".to_string()
            }
            Self::ContextWindowUndeclared { required } => {
                format!("required_context_window={required};declared_context_window=none")
            }
            Self::ContextWindowTooSmall { required, declared } => {
                format!("required_context_window={required};declared_context_window={declared}")
            }
            Self::RegionUndeclared => "declared_region=none".to_string(),
            Self::RegionNotAllowed { declared } => {
                format!("declared_region={}", bounded(declared))
            }
        }
    }

    pub(crate) fn is_request_requirement(&self) -> bool {
        matches!(
            self,
            Self::MissingCapability(_)
                | Self::MediaContextUnbounded
                | Self::ContextWindowUndeclared { .. }
                | Self::ContextWindowTooSmall { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelRouteExclusion {
    pub(crate) candidate: ModelRouteCandidateIdentity,
    pub(crate) reason: ModelRouteExclusionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModelRouteSelectionReason {
    PriorityOrder,
    LowestCost,
    LowestLatency,
    Balanced,
    CanaryBucket,
}

impl ModelRouteSelectionReason {
    pub(crate) const fn for_strategy(strategy: RoutingStrategy) -> Self {
        match strategy {
            RoutingStrategy::Priority => Self::PriorityOrder,
            RoutingStrategy::LowestCost => Self::LowestCost,
            RoutingStrategy::LowestLatency => Self::LowestLatency,
            RoutingStrategy::Balanced => Self::Balanced,
        }
    }

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::PriorityOrder => "priority_order",
            Self::LowestCost => "lowest_cost",
            Self::LowestLatency => "lowest_latency",
            Self::Balanced => "balanced",
            Self::CanaryBucket => "canary_bucket",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ModelRoutingDecision {
    pub(crate) requirements: ModelRouteRequirements,
    pub(crate) eligible_routes: Vec<ModelRoute>,
    pub(crate) exclusions: Vec<ModelRouteExclusion>,
    pub(crate) exclusions_truncated: bool,
    pub(crate) selection_reason: ModelRouteSelectionReason,
}

impl std::ops::Deref for ModelRoutingDecision {
    type Target = [ModelRoute];

    fn deref(&self) -> &Self::Target {
        &self.eligible_routes
    }
}

impl ModelRoutingDecision {
    pub(crate) fn new(requirements: ModelRouteRequirements, strategy: RoutingStrategy) -> Self {
        Self {
            requirements,
            eligible_routes: Vec::new(),
            exclusions: Vec::new(),
            exclusions_truncated: false,
            selection_reason: ModelRouteSelectionReason::for_strategy(strategy),
        }
    }

    pub(crate) fn consider(
        &mut self,
        route: ModelRoute,
        region_allowlist: &HashSet<String>,
    ) -> bool {
        let reasons = route_exclusion_reasons(&route, &self.requirements, region_allowlist);
        if reasons.is_empty() {
            self.eligible_routes.push(route);
            return true;
        }
        for reason in reasons {
            if self.exclusions.len() == MAX_ROUTE_EXCLUSIONS {
                self.exclusions_truncated = true;
                break;
            }
            self.exclusions.push(ModelRouteExclusion {
                candidate: ModelRouteCandidateIdentity::from(&route),
                reason,
            });
        }
        false
    }

    pub(crate) fn has_request_requirement_exclusion(&self) -> bool {
        self.exclusions
            .iter()
            .any(|exclusion| exclusion.reason.is_request_requirement())
    }

    pub(crate) fn rejection(
        &self,
        logical_model: &str,
    ) -> Option<(StatusCode, &'static str, String)> {
        if !self.eligible_routes.is_empty() {
            return None;
        }
        if self.has_request_requirement_exclusion() {
            return Some((
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!(
                    "no physical route for model {logical_model} satisfies the request requirements"
                ),
            ));
        }
        Some((
            StatusCode::FORBIDDEN,
            "region_not_allowed",
            format!(
                "no candidate route for model {logical_model} satisfies this tenant's region allowlist"
            ),
        ))
    }

    pub(crate) fn audit_event_actions(&self) -> Vec<String> {
        let mut actions = self
            .exclusions
            .iter()
            .map(|_| "model_route.excluded".to_string())
            .collect::<Vec<_>>();
        if self.exclusions_truncated {
            actions.push("model_route.exclusions_truncated".to_string());
        }
        if !self.eligible_routes.is_empty() {
            actions.push("model_route.selected".to_string());
        }
        actions
    }
}

pub(crate) fn route_exclusion_reasons(
    route: &ModelRoute,
    requirements: &ModelRouteRequirements,
    region_allowlist: &HashSet<String>,
) -> Vec<ModelRouteExclusionReason> {
    let legacy_undeclared_route =
        route.capabilities.is_empty() && requirements.allow_undeclared_capabilities;
    let mut reasons = if legacy_undeclared_route {
        Vec::new()
    } else {
        requirements
            .capabilities()
            .filter(|required| !route.capabilities.contains(required))
            .map(ModelRouteExclusionReason::MissingCapability)
            .collect::<Vec<_>>()
    };
    if requirements.unbounded_media_context {
        reasons.push(ModelRouteExclusionReason::MediaContextUnbounded);
    } else if let Some(required) = requirements.required_context_window {
        match route.context_window {
            None if legacy_undeclared_route => {}
            None => reasons.push(ModelRouteExclusionReason::ContextWindowUndeclared { required }),
            Some(declared) if u64::from(declared) < required => {
                reasons
                    .push(ModelRouteExclusionReason::ContextWindowTooSmall { required, declared });
            }
            Some(_) => {}
        }
    }
    if !region_allowlist.is_empty() {
        match route.region.as_deref() {
            None => reasons.push(ModelRouteExclusionReason::RegionUndeclared),
            Some(region) if !region_allowlist.contains(region) => {
                reasons.push(ModelRouteExclusionReason::RegionNotAllowed {
                    declared: region.to_string(),
                });
            }
            Some(_) => {}
        }
    }
    reasons
}

pub(crate) struct ModelRoutingAuditContext<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) trace_id: Option<&'a str>,
    pub(crate) agent_run_id: Option<&'a str>,
    pub(crate) workflow_id: Option<&'a str>,
    pub(crate) workflow_version: Option<u32>,
    pub(crate) workflow_node_id: Option<&'a str>,
    pub(crate) actor_api_key_id: Option<&'a str>,
    pub(crate) tenant: &'a TenantContext,
    pub(crate) logical_model: &'a str,
}

impl AppState {
    pub(crate) fn record_model_routing_decision(
        &self,
        context: ModelRoutingAuditContext<'_>,
        decision: &ModelRoutingDecision,
    ) {
        for exclusion in &decision.exclusions {
            self.record_admin_audit_event(route_audit_event(
                &context,
                "model_route.excluded",
                &exclusion.candidate,
                exclusion.reason.code(),
                format!(
                    "{};{}",
                    exclusion.reason.detail(),
                    decision.requirements.summary()
                ),
            ));
        }
        if decision.exclusions_truncated {
            self.record_admin_audit_event(AdminAuditEventDraft {
                action_identity: Default::default(),
                request_id: context.request_id.to_string(),
                trace_id: context.trace_id.map(str::to_string),
                agent_run_id: context.agent_run_id.map(str::to_string),
                workflow_id: context.workflow_id.map(str::to_string),
                workflow_version: context.workflow_version,
                workflow_node_id: context.workflow_node_id.map(str::to_string),
                actor_api_key_id: context.actor_api_key_id.map(str::to_string),
                tenant: context.tenant.clone(),
                action: "model_route.exclusions_truncated".into(),
                target: format!("logical_model={}", bounded(context.logical_model)),
                outcome: "evidence_limit_reached".into(),
                message: format!("exclusion_limit={MAX_ROUTE_EXCLUSIONS}"),
            });
        }
        if let Some(selected) = decision.eligible_routes.first() {
            self.record_admin_audit_event(route_audit_event(
                &context,
                "model_route.selected",
                &ModelRouteCandidateIdentity::from(selected),
                decision.selection_reason.code(),
                decision.requirements.summary(),
            ));
        }
    }
}

fn route_audit_event(
    context: &ModelRoutingAuditContext<'_>,
    action: &str,
    candidate: &ModelRouteCandidateIdentity,
    outcome: &str,
    message: String,
) -> AdminAuditEventDraft {
    AdminAuditEventDraft {
        action_identity: Default::default(),
        request_id: context.request_id.to_string(),
        trace_id: context.trace_id.map(str::to_string),
        agent_run_id: context.agent_run_id.map(str::to_string),
        workflow_id: context.workflow_id.map(str::to_string),
        workflow_version: context.workflow_version,
        workflow_node_id: context.workflow_node_id.map(str::to_string),
        actor_api_key_id: context.actor_api_key_id.map(str::to_string),
        tenant: context.tenant.clone(),
        action: action.to_string(),
        target: format!(
            "logical_model={};provider={};provider_model={}",
            bounded(context.logical_model),
            bounded(&candidate.provider),
            bounded(&candidate.provider_model)
        ),
        outcome: outcome.to_string(),
        message,
    }
}

fn non_empty(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Array(values)) => !values.is_empty(),
        Some(Value::Object(values)) => !values.is_empty(),
        Some(Value::Null) | None => false,
        Some(_) => true,
    }
}

fn structured_output_requested(body: &Value, endpoint: ModelEndpointKind) -> bool {
    let response_format = body.get("response_format");
    if structured_format(response_format) {
        return true;
    }
    endpoint == ModelEndpointKind::Responses && structured_format(body.pointer("/text/format"))
}

fn structured_format(value: Option<&Value>) -> bool {
    value
        .and_then(|format| format.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "json_object" | "json_schema"))
}

fn explicit_output_token_bound(body: &Value, endpoint: ModelEndpointKind) -> Option<u64> {
    match endpoint {
        ModelEndpointKind::ChatCompletions => body
            .get("max_completion_tokens")
            .or_else(|| body.get("max_tokens")),
        ModelEndpointKind::Responses => body.get("max_output_tokens"),
        ModelEndpointKind::AnthropicMessages => body.get("max_tokens"),
        ModelEndpointKind::Embeddings | ModelEndpointKind::Images => None,
    }
    .and_then(Value::as_u64)
}

pub(crate) fn conservative_input_token_upper_bound<T: Serialize>(value: &T) -> u64 {
    serde_json::to_vec(value)
        .ok()
        .and_then(|bytes| u64::try_from(bytes.len()).ok())
        .unwrap_or(u64::MAX)
}

fn request_contains_image_input(body: &Value, endpoint: ModelEndpointKind) -> bool {
    let input = match endpoint {
        ModelEndpointKind::Responses => body.get("input"),
        ModelEndpointKind::ChatCompletions | ModelEndpointKind::AnthropicMessages => {
            body.get("messages")
        }
        ModelEndpointKind::Embeddings | ModelEndpointKind::Images => None,
    };
    input.is_some_and(content_contains_image)
}

fn content_contains_image(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(content_contains_image),
        Value::Object(object) => {
            let is_image = object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "image" | "image_url" | "input_image"));
            is_image || object.get("content").is_some_and(content_contains_image)
        }
        _ => false,
    }
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_EVIDENCE_COMPONENT_CHARS).collect()
}

#[cfg(test)]
#[path = "model_routing_test.rs"]
mod model_routing_test;
