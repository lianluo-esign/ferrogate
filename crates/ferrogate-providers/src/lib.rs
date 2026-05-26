//! AI provider adapter boundaries.

mod anthropic;
mod azure;
mod canonical;
mod gemini;
mod grok;
mod models;
mod openai;
mod openrouter;
mod registry;
mod types;

pub use anthropic::AnthropicAdapter;
pub use azure::AzureOpenAiAdapter;
pub use gemini::GeminiAdapter;
pub use grok::GrokAdapter;
pub use models::{
    ModelRegistry, ModelRegistryEntry, ModelRegistryError, ModelRoute, ResolvedModelRoute,
    RoutingStrategy,
};
pub use openai::OpenAiCompatibleAdapter;
pub use openrouter::OpenRouterAdapter;
pub use registry::ProviderAdapterRegistry;
pub use types::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderErrorResponse,
    ProviderHeader, ProviderHttpRequest, ProviderUsage, ResponsesPlan, SecretValue,
};
