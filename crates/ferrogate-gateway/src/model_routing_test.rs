// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Focused model-route requirement and exclusion invariants (#582).

use super::*;
use serde_json::json;

fn route(capabilities: &[ModelCapability], context_window: Option<u32>) -> ModelRoute {
    ModelRoute::new("provider", "physical-model")
        .with_capabilities_and_context(capabilities.to_vec(), context_window)
}

#[test]
fn neutral_legacy_request_keeps_a_route_with_no_declarations() {
    let requirements = ModelRouteRequirements::from_request(
        ModelEndpointKind::ChatCompletions,
        &json!({"model": "logical", "messages": []}),
        false,
        false,
    );
    assert!(requirements.is_neutral());
    assert_eq!(
        requirements.capabilities().collect::<Vec<_>>(),
        [ModelCapability::Chat]
    );
    assert!(route_exclusion_reasons(&route(&[], None), &requirements, &HashSet::new()).is_empty());
    assert_eq!(
        route_exclusion_reasons(
            &route(&[ModelCapability::Embeddings], None),
            &requirements,
            &HashSet::new()
        ),
        [ModelRouteExclusionReason::MissingCapability(
            ModelCapability::Chat
        )]
    );
}

#[test]
fn request_features_become_exact_typed_requirements() {
    let requirements = ModelRouteRequirements::from_request(
        ModelEndpointKind::Responses,
        &json!({
            "model": "logical",
            "stream": true,
            "max_output_tokens": 4096,
            "tools": [{"type": "function", "name": "lookup"}],
            "text": {"format": {"type": "json_schema", "name": "answer"}},
            "input": [{"role": "user", "content": [{"type": "input_image", "image_url": "https://example.test/a.png"}]}]
        }),
        true,
        false,
    );
    assert_eq!(
        requirements.capabilities().collect::<Vec<_>>(),
        [
            ModelCapability::Chat,
            ModelCapability::Streaming,
            ModelCapability::Vision,
            ModelCapability::Tools,
            ModelCapability::StructuredOutput,
        ]
    );
    assert_eq!(requirements.explicit_context_window, Some(4096));
}

#[test]
fn every_missing_requirement_produces_a_stable_exclusion_reason() {
    let requirements = ModelRouteRequirements::from_request(
        ModelEndpointKind::ChatCompletions,
        &json!({
            "tools": [{"type": "function"}],
            "response_format": {"type": "json_object"},
            "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:image/png;base64,AA=="}}]}],
            "max_completion_tokens": 2048
        }),
        true,
        false,
    );
    let reasons = route_exclusion_reasons(&route(&[], None), &requirements, &HashSet::new());
    let codes = reasons
        .iter()
        .map(ModelRouteExclusionReason::code)
        .collect::<Vec<_>>();
    assert_eq!(
        codes,
        [
            "missing_capability",
            "missing_capability",
            "missing_capability",
            "missing_capability",
            "missing_capability",
            "context_window_undeclared",
        ]
    );
    let missing = reasons
        .iter()
        .filter_map(|reason| match reason {
            ModelRouteExclusionReason::MissingCapability(capability) => Some(*capability),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        missing,
        [
            ModelCapability::Chat,
            ModelCapability::Streaming,
            ModelCapability::Vision,
            ModelCapability::Tools,
            ModelCapability::StructuredOutput,
        ]
    );
}

#[test]
fn endpoint_capabilities_and_context_limit_filter_fail_closed() {
    let embeddings = ModelRouteRequirements::from_request(
        ModelEndpointKind::Embeddings,
        &json!({"input": "hello"}),
        false,
        false,
    );
    assert_eq!(
        route_exclusion_reasons(&route(&[], None), &embeddings, &HashSet::new())[0].code(),
        "missing_capability"
    );

    let images = ModelRouteRequirements::from_request(
        ModelEndpointKind::Images,
        &json!({"prompt": "hello"}),
        false,
        false,
    );
    assert!(route_exclusion_reasons(
        &route(&[ModelCapability::Images], None),
        &images,
        &HashSet::new()
    )
    .is_empty());

    let mut bounded = ModelRouteRequirements::default();
    bounded.explicit_context_window = Some(4096);
    assert_eq!(
        route_exclusion_reasons(&route(&[], Some(2048)), &bounded, &HashSet::new())[0].code(),
        "context_window_too_small"
    );
    assert!(route_exclusion_reasons(&route(&[], Some(4096)), &bounded, &HashSet::new()).is_empty());
}

#[test]
fn region_exclusions_share_the_same_bounded_decision() {
    let mut decision =
        ModelRoutingDecision::new(ModelRouteRequirements::default(), RoutingStrategy::Priority);
    let route = route(&[], None);
    assert!(!decision.consider(route, &HashSet::from(["eu-west-1".to_string()])));
    assert_eq!(decision.exclusions.len(), 1);
    assert_eq!(decision.exclusions[0].reason.code(), "region_undeclared");
    assert!(decision.eligible_routes.is_empty());
}

#[test]
fn exclusion_evidence_is_bounded_and_marks_truncation() {
    let mut requirements = ModelRouteRequirements::default();
    requirements.require(ModelCapability::Tools);
    let mut decision = ModelRoutingDecision::new(requirements, RoutingStrategy::Priority);

    for index in 0..40 {
        decision.consider(
            ModelRoute::new(format!("provider-{index}"), "physical-model"),
            &HashSet::new(),
        );
    }

    assert_eq!(decision.exclusions.len(), MAX_ROUTE_EXCLUSIONS);
    assert!(decision.exclusions_truncated);
    assert_eq!(decision.exclusions[0].candidate.provider, "provider-0");
    assert_eq!(decision.exclusions[31].candidate.provider, "provider-31");
    assert!(decision.eligible_routes.is_empty());
}
