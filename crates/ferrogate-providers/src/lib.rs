//! AI provider adapter boundaries.

mod anthropic;
mod gemini;
mod models;
mod openai;
mod registry;
mod types;

pub use anthropic::AnthropicAdapter;
pub use gemini::GeminiAdapter;
pub use models::{
    ModelRegistry, ModelRegistryEntry, ModelRegistryError, ModelRoute, ResolvedModelRoute,
};
pub use openai::OpenAiCompatibleAdapter;
pub use registry::ProviderAdapterRegistry;
pub use types::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderErrorResponse,
    ProviderHeader, ProviderHttpRequest, ProviderUsage, SecretValue,
};
