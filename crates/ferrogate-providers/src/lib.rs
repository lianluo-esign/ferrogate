//! AI provider adapter boundaries.

mod openai;
mod registry;
mod types;

pub use openai::OpenAiCompatibleAdapter;
pub use registry::ProviderAdapterRegistry;
pub use types::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderErrorResponse,
    ProviderHeader, ProviderHttpRequest, ProviderUsage, SecretValue,
};
