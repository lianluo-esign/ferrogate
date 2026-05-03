use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRoute {
    pub provider: String,
    pub provider_model: String,
}

impl ModelRoute {
    pub fn new(provider: impl Into<String>, provider_model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            provider_model: provider_model.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelRegistryEntry {
    pub name: String,
    pub primary: ModelRoute,
    pub fallbacks: Vec<ModelRoute>,
    pub capabilities: Vec<String>,
    pub context_window: Option<u32>,
    pub input_price_per_1m: Option<f64>,
    pub output_price_per_1m: Option<f64>,
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
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModelRoute {
    pub logical_model: String,
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

        Ok(ResolvedModelRoute {
            logical_model: entry.name.clone(),
            primary: entry.primary.clone(),
            fallbacks: entry.fallbacks.clone(),
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
}
