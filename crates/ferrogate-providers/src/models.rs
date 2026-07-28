// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{collections::HashMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    #[default]
    Priority,
    LowestCost,
    LowestLatency,
    Balanced,
}

/// Closed vocabulary for capabilities declared by one physical model route.
///
/// These names describe request features FerroGate dispatches today. They are
/// deliberately provider-neutral: adapters remain responsible for translating
/// the request into each provider's wire shape.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    Chat,
    Streaming,
    Vision,
    Images,
    Embeddings,
    Tools,
    StructuredOutput,
}

impl ModelCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Streaming => "streaming",
            Self::Vision => "vision",
            Self::Images => "images",
            Self::Embeddings => "embeddings",
            Self::Tools => "tools",
            Self::StructuredOutput => "structured_output",
        }
    }
}

impl fmt::Display for ModelCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ModelCapability {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "chat" => Ok(Self::Chat),
            "streaming" => Ok(Self::Streaming),
            "vision" => Ok(Self::Vision),
            "images" => Ok(Self::Images),
            "embeddings" => Ok(Self::Embeddings),
            "tools" => Ok(Self::Tools),
            "structured_output" => Ok(Self::StructuredOutput),
            _ => Err(format!(
                "unknown model capability {value:?}; expected one of chat, streaming, vision, images, embeddings, tools, structured_output"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelRoute {
    pub provider: String,
    pub provider_model: String,
    pub input_price_per_1m: Option<f64>,
    pub output_price_per_1m: Option<f64>,
    pub priority: u32,
    pub weight: u32,
    /// Request features this physical provider/model pair can accept. Empty is
    /// retained for legacy capability-neutral requests, but never satisfies an
    /// explicit request requirement.
    pub capabilities: Vec<ModelCapability>,
    /// Declared maximum context tokens for this physical route. `None` is
    /// retained for legacy requests without an explicit output-token bound,
    /// but never satisfies an explicit context requirement.
    pub context_window: Option<u32>,
    /// The provider's declared physical region (issue #173), e.g.
    /// "eu-west-1" -- `None` when the provider config doesn't declare one.
    /// A tenant with a non-empty region allowlist can only route to
    /// routes where this is `Some` and contained in that allowlist; see
    /// `ferrogate-cli`'s `AuthContext::can_use_region`.
    pub region: Option<String>,
}

impl ModelRoute {
    pub fn new(provider: impl Into<String>, provider_model: impl Into<String>) -> Self {
        Self::with_routing(provider, provider_model, None, None, 0, 1)
    }

    pub fn with_routing(
        provider: impl Into<String>,
        provider_model: impl Into<String>,
        input_price_per_1m: Option<f64>,
        output_price_per_1m: Option<f64>,
        priority: u32,
        weight: u32,
    ) -> Self {
        Self {
            provider: provider.into(),
            provider_model: provider_model.into(),
            input_price_per_1m,
            output_price_per_1m,
            priority,
            weight,
            capabilities: Vec::new(),
            context_window: None,
            region: None,
        }
    }

    pub fn with_capabilities_and_context(
        mut self,
        capabilities: Vec<ModelCapability>,
        context_window: Option<u32>,
    ) -> Self {
        self.capabilities = capabilities;
        self.context_window = context_window;
        self
    }

    pub fn with_region(mut self, region: Option<String>) -> Self {
        self.region = region;
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelRegistryEntry {
    pub name: String,
    pub primary: ModelRoute,
    pub fallbacks: Vec<ModelRoute>,
    pub capabilities: Vec<ModelCapability>,
    pub context_window: Option<u32>,
    pub input_price_per_1m: Option<f64>,
    pub output_price_per_1m: Option<f64>,
    pub routing_strategy: RoutingStrategy,
    pub enabled: bool,
}

impl ModelRegistryEntry {
    pub fn new(
        name: impl Into<String>,
        provider: impl Into<String>,
        provider_model: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            primary: ModelRoute::new(provider, provider_model),
            fallbacks: Vec::new(),
            capabilities: Vec::new(),
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            routing_strategy: RoutingStrategy::Priority,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedModelRoute {
    pub logical_model: String,
    pub routing_strategy: RoutingStrategy,
    pub primary: ModelRoute,
    pub fallbacks: Vec<ModelRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelRegistryError {
    EmptyModelName,
    DuplicateModel { name: String },
    ModelNotFound { name: String },
    ModelDisabled { name: String },
}

#[derive(Debug, Clone, Default)]
pub struct ModelRegistry {
    entries: HashMap<String, ModelRegistryEntry>,
}

impl ModelRegistry {
    pub fn new(
        entries: impl IntoIterator<Item = ModelRegistryEntry>,
    ) -> Result<Self, ModelRegistryError> {
        let mut registry = HashMap::new();
        for entry in entries {
            if entry.name.trim().is_empty() {
                return Err(ModelRegistryError::EmptyModelName);
            }
            let previous = registry.insert(entry.name.clone(), entry);
            if let Some(previous) = previous {
                return Err(ModelRegistryError::DuplicateModel {
                    name: previous.name,
                });
            }
        }
        Ok(Self { entries: registry })
    }

    pub fn resolve(&self, logical_model: &str) -> Result<ResolvedModelRoute, ModelRegistryError> {
        let Some(entry) = self.entries.get(logical_model) else {
            return Err(ModelRegistryError::ModelNotFound {
                name: logical_model.to_string(),
            });
        };
        if !entry.enabled {
            return Err(ModelRegistryError::ModelDisabled {
                name: logical_model.to_string(),
            });
        }

        let mut fallbacks = entry.fallbacks.clone();
        fallbacks.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| right.weight.cmp(&left.weight))
                .then_with(|| left.provider.cmp(&right.provider))
                .then_with(|| left.provider_model.cmp(&right.provider_model))
        });

        Ok(ResolvedModelRoute {
            logical_model: entry.name.clone(),
            routing_strategy: entry.routing_strategy,
            primary: entry.primary.clone(),
            fallbacks,
        })
    }

    pub fn enabled_models(&self) -> Vec<&ModelRegistryEntry> {
        let mut entries = self
            .entries
            .values()
            .filter(|entry| entry.enabled)
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_enabled_model_to_primary_route() {
        let registry = ModelRegistry::new([ModelRegistryEntry::new(
            "fast-chat",
            "openai",
            "gpt-4o-mini",
        )])
        .unwrap();

        let resolved = registry.resolve("fast-chat").unwrap();
        assert_eq!(resolved.logical_model, "fast-chat");
        assert_eq!(resolved.primary.provider, "openai");
        assert_eq!(resolved.primary.provider_model, "gpt-4o-mini");
    }

    #[test]
    fn rejects_duplicate_model_names() {
        let error = ModelRegistry::new([
            ModelRegistryEntry::new("fast-chat", "openai", "gpt-4o-mini"),
            ModelRegistryEntry::new("fast-chat", "anthropic", "claude-3-5-sonnet-latest"),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            ModelRegistryError::DuplicateModel {
                name: "fast-chat".into()
            }
        );
    }

    #[test]
    fn rejects_disabled_models_at_resolution_time() {
        let mut entry = ModelRegistryEntry::new("fast-chat", "openai", "gpt-4o-mini");
        entry.enabled = false;
        let registry = ModelRegistry::new([entry]).unwrap();

        assert_eq!(
            registry.resolve("fast-chat").unwrap_err(),
            ModelRegistryError::ModelDisabled {
                name: "fast-chat".into()
            }
        );
    }

    #[test]
    fn sorts_enabled_models_for_stable_listing() {
        let mut disabled = ModelRegistryEntry::new("z-disabled", "openai", "gpt-4o-mini");
        disabled.enabled = false;
        let registry = ModelRegistry::new([
            ModelRegistryEntry::new("b-model", "openai", "gpt-4o-mini"),
            ModelRegistryEntry::new("a-model", "openai", "gpt-4o-mini"),
            disabled,
        ])
        .unwrap();

        let names = registry
            .enabled_models()
            .into_iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["a-model", "b-model"]);
    }

    #[test]
    fn resolves_fallback_routes_by_priority_then_weight() {
        let mut entry = ModelRegistryEntry::new("fast-chat", "openai", "gpt-4o-mini");
        entry.fallbacks = vec![
            ModelRoute::with_routing("gemini", "gemini-2.5-flash", None, None, 20, 10),
            ModelRoute::with_routing("anthropic", "claude-3-5-sonnet-latest", None, None, 10, 1),
            ModelRoute::with_routing("grok", "grok-4.20-fast", None, None, 20, 20),
        ];
        let registry = ModelRegistry::new([entry]).unwrap();

        let resolved = registry.resolve("fast-chat").unwrap();
        let providers = resolved
            .fallbacks
            .into_iter()
            .map(|route| route.provider)
            .collect::<Vec<_>>();
        assert_eq!(providers, ["anthropic", "grok", "gemini"]);
    }
}
