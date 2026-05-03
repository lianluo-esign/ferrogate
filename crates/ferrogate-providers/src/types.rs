use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChatCompletionPlan {
    pub logical_model: String,
    pub provider_model: String,
    pub stream: bool,
    pub body: Value,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHeader {
    pub name: String,
    pub value: SecretValue,
}

#[derive(Clone, PartialEq)]
pub struct ProviderHttpRequest {
    pub provider: String,
    pub endpoint: String,
    pub body: Value,
    pub stream: bool,
    pub headers: Vec<ProviderHeader>,
}

impl fmt::Debug for ProviderHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpRequest")
            .field("provider", &self.provider)
            .field("endpoint", &self.endpoint)
            .field("body", &self.body)
            .field("stream", &self.stream)
            .field("headers", &self.headers)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    UnsupportedProviderKind { kind: String },
    InvalidRequest { message: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderErrorResponse {
    pub status: u16,
    pub body: Value,
}

pub trait ProviderAdapter: Send + Sync {
    fn kind(&self) -> &'static str;

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError>;

    fn normalize_error_response(
        &self,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> ProviderErrorResponse;

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage>;
}
