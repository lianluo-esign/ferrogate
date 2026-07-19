// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! AI provider adapter boundaries.

mod anthropic;
pub mod anthropic_messages;
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
mod vertex;

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
pub use sigv4::{
    presign_query as presign_sigv4_query, sign as sign_sigv4,
    sign_with_content_hash_header as sign_sigv4_with_content_hash_header, AwsCredentials,
    PresignRequest, SignedHeaders, SigningRequest,
};
pub use types::{
    canonical_provider_adapter_family, is_openai_compatible_provider_kind,
    provider_compatibility_kind, AdapterError, AwsProviderCredentials, ChatCompletionPlan,
    EmbeddingsPlan, GcpProviderCredentials, ProviderAdapter, ProviderAdapterFamily,
    ProviderAdapterFamilyDescriptor, ProviderCatalogModel, ProviderCatalogRequest, ProviderConfig,
    ProviderErrorResponse, ProviderHeader, ProviderHttpRequest, ProviderUsage, ResponsesPlan,
    SecretValue, SUPPORTED_PROVIDER_ADAPTER_FAMILIES,
};
pub use vertex::VertexAiAdapter;
