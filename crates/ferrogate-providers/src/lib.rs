//! AI provider adapter boundaries.

mod openai;
mod types;

pub use openai::OpenAiCompatibleAdapter;
pub use types::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderHeader,
    ProviderHttpRequest, SecretValue,
};
