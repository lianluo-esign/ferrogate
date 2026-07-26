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
mod cloudflare;
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
pub use cloudflare::{
    apply_cloudflare_ai_gateway_routing, CloudflareAiGatewayMode, CloudflareAiGatewayRouting,
    CloudflareAiGatewaySurface,
};
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
    canonical_query_string as sigv4_canonical_query_string, presign_query as presign_sigv4_query,
    presign_query_bound as presign_sigv4_query_bound, sign as sign_sigv4,
    sign_streamed_with_content_hash_header as sign_sigv4_streamed_with_content_hash_header,
    sign_with_content_hash_header as sign_sigv4_with_content_hash_header,
    sign_with_content_hash_header_and_query as sign_sigv4_with_content_hash_header_and_query,
    AwsCredentials, BoundPresignedUpload, PresignBoundPayload, PresignRequest, SignedHeaders,
    SigningRequest, StreamedSigningRequest,
};
pub use types::{
    canonical_provider_adapter_family, is_openai_compatible_provider_kind,
    provider_compatibility_kind, AdapterError, AwsProviderCredentials, ChatCompletionPlan,
    EmbeddingsPlan, GcpProviderCredentials, ImagesPlan, ProviderAdapter, ProviderAdapterFamily,
    ProviderAdapterFamilyDescriptor, ProviderCatalogModel, ProviderCatalogRequest, ProviderConfig,
    ProviderErrorResponse, ProviderHeader, ProviderHttpRequest, ProviderUsage, ResponsesPlan,
    SecretValue, SUPPORTED_PROVIDER_ADAPTER_FAMILIES,
};
pub use vertex::VertexAiAdapter;
