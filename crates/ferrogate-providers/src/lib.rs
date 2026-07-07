// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! AI provider adapter boundaries.

mod anthropic;
mod azure;
mod bedrock;
mod canonical;
mod gemini;
mod grok;
mod models;
mod openai;
mod openrouter;
mod registry;
mod sigv4;
mod types;

pub use anthropic::AnthropicAdapter;
pub use azure::AzureOpenAiAdapter;
pub use bedrock::BedrockAdapter;
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
    is_openai_compatible_provider_kind, provider_compatibility_kind, AdapterError,
    AwsProviderCredentials, ChatCompletionPlan, ProviderAdapter, ProviderCatalogModel,
    ProviderCatalogRequest, ProviderConfig, ProviderErrorResponse, ProviderHeader,
    ProviderHttpRequest, ProviderUsage, ResponsesPlan, SecretValue,
};
