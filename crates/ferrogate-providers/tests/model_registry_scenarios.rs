// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Scenario coverage for model resolution and provider compatibility (#106).

use ferrogate_providers::{
    is_openai_compatible_provider_kind, provider_compatibility_kind, ModelRegistry,
    ModelRegistryEntry, ModelRegistryError, ModelRoute,
};

fn entry(name: &str, provider: &str) -> ModelRegistryEntry {
    ModelRegistryEntry::new(name, provider, format!("{provider}-model"))
}

#[test]
fn resolve_returns_primary_route_for_enabled_model() {
    let registry = ModelRegistry::new([entry("fast-chat", "openai")]).unwrap();
    let resolved = registry.resolve("fast-chat").unwrap();
    assert_eq!(resolved.logical_model, "fast-chat");
    assert_eq!(resolved.primary.provider, "openai");
}

#[test]
fn resolve_unknown_and_disabled_models_fail_closed() {
    let mut disabled = entry("legacy", "openai");
    disabled.enabled = false;
    let registry = ModelRegistry::new([entry("fast-chat", "openai"), disabled]).unwrap();

    assert!(matches!(
        registry.resolve("ghost"),
        Err(ModelRegistryError::ModelNotFound { .. })
    ));
    assert!(matches!(
        registry.resolve("legacy"),
        Err(ModelRegistryError::ModelDisabled { .. })
    ));
}

#[test]
fn registry_rejects_empty_and_duplicate_model_names() {
    assert!(matches!(
        ModelRegistry::new([entry("   ", "openai")]),
        Err(ModelRegistryError::EmptyModelName)
    ));
    assert!(matches!(
        ModelRegistry::new([entry("dup", "openai"), entry("dup", "anthropic")]),
        Err(ModelRegistryError::DuplicateModel { .. })
    ));
}

#[test]
fn resolve_orders_fallbacks_by_priority_then_weight_then_name() {
    let mut e = entry("fast-chat", "openai");
    e.fallbacks = vec![
        ModelRoute::with_routing("b", "m", None, None, 1, 1),
        ModelRoute::with_routing("a", "m", None, None, 0, 5),
        ModelRoute::with_routing("a", "m", None, None, 0, 9),
    ];
    let registry = ModelRegistry::new([e]).unwrap();
    let resolved = registry.resolve("fast-chat").unwrap();

    // priority 0 before 1; within priority 0, higher weight first (9 before 5).
    assert_eq!(resolved.fallbacks[0].priority, 0);
    assert_eq!(resolved.fallbacks[0].weight, 9);
    assert_eq!(resolved.fallbacks[1].weight, 5);
    assert_eq!(resolved.fallbacks[2].priority, 1);
}

#[test]
fn enabled_models_are_filtered_and_sorted() {
    let mut disabled = entry("z-disabled", "openai");
    disabled.enabled = false;
    let registry = ModelRegistry::new([
        entry("b-model", "openai"),
        entry("a-model", "openai"),
        disabled,
    ])
    .unwrap();

    let enabled = registry.enabled_models();
    assert_eq!(enabled.len(), 2);
    assert_eq!(enabled[0].name, "a-model");
    assert_eq!(enabled[1].name, "b-model");
    assert_eq!(registry.len(), 3);
    assert!(!registry.is_empty());
}

#[test]
fn provider_compatibility_classification() {
    for openai_like in [
        "openai",
        "OpenAI",
        " ollama ",
        "vllm",
        "deepseek",
        "llama.cpp",
    ] {
        assert!(
            is_openai_compatible_provider_kind(openai_like),
            "{openai_like} should be openai-compatible"
        );
        assert_eq!(
            provider_compatibility_kind(openai_like),
            "openai-compatible"
        );
    }
    for dedicated in ["anthropic", "gemini", "azure", "unknown"] {
        assert!(!is_openai_compatible_provider_kind(dedicated));
        assert_eq!(provider_compatibility_kind(dedicated), "dedicated");
    }
}
