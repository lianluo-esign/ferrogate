//! AI provider adapter boundaries.

mod anthropic;
mod openai;
mod registry;
mod types;

pub use anthropic::AnthropicAdapter;
pub use openai::OpenAiCompatibleAdapter;
pub use registry::ProviderAdapterRegistry;
pub use types::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderErrorResponse,
    ProviderHeader, ProviderHttpRequest, ProviderUsage, SecretValue,
};
