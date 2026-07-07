// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use ferrogate_core::{ToolCall, ToolDef, ToolResult};
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub openrouter_http_referer: Option<String>,
    pub openrouter_x_title: Option<String>,
    /// AWS SigV4 credentials for the `bedrock` adapter (issue #172) --
    /// unused by every other adapter, which authenticate via `api_key`
    /// instead. `None` for a Bedrock provider means the adapter fails
    /// closed at request-preparation time rather than silently sending an
    /// unsigned (and therefore rejected) request.
    pub aws_credentials: Option<AwsProviderCredentials>,
}

/// AWS access-key credentials plus the region a Bedrock provider targets
/// (issue #172). `session_token` is present only for temporary/STS
/// credentials; long-lived IAM user access keys omit it. The secret
/// fields use [`SecretValue`] so an accidental `{:?}` of a
/// [`ProviderConfig`] (or anything embedding it) can never leak them,
/// mirroring how [`ProviderHeader`] already protects header values.
#[derive(Clone, PartialEq, Eq)]
pub struct AwsProviderCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretValue,
    pub session_token: Option<SecretValue>,
    pub region: String,
}

impl fmt::Debug for AwsProviderCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsProviderCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &self.secret_access_key)
            .field("session_token", &self.session_token)
            .field("region", &self.region)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChatCompletionPlan {
    pub logical_model: String,
    pub provider_model: String,
    pub stream: bool,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponsesPlan {
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

#[derive(Clone, PartialEq)]
pub struct ProviderCatalogRequest {
    pub provider: String,
    pub endpoint: String,
    pub headers: Vec<ProviderHeader>,
}

impl fmt::Debug for ProviderCatalogRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCatalogRequest")
            .field("provider", &self.provider)
            .field("endpoint", &self.endpoint)
            .field("headers", &self.headers)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    UnsupportedProviderKind { kind: String },
    InvalidRequest { message: String },
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProviderKind { kind } => {
                write!(formatter, "unsupported provider kind {kind}")
            }
            Self::InvalidRequest { message } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for AdapterError {}

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderCatalogModel {
    pub id: String,
    pub owned_by: Option<String>,
    pub created: Option<u64>,
    pub context_window: Option<u64>,
    pub capabilities: Vec<String>,
}

pub fn is_openai_compatible_provider_kind(kind: &str) -> bool {
    matches!(
        normalize_kind(kind).as_str(),
        "openai"
            | "openai-compatible"
            | "deepseek"
            | "newapi"
            | "sub2api"
            | "cliproxyapi"
            | "cli-proxy-api"
            | "vllm"
            | "llama.cpp"
            | "llama-cpp"
            | "llamacpp"
            | "tgi"
            | "ollama"
            | "ollama-compatible"
    )
}

pub fn provider_compatibility_kind(kind: &str) -> &'static str {
    if is_openai_compatible_provider_kind(kind) {
        "openai-compatible"
    } else {
        "dedicated"
    }
}

fn normalize_kind(kind: &str) -> String {
    kind.trim().to_ascii_lowercase()
}

pub trait ProviderAdapter: Send + Sync {
    fn kind(&self) -> &'static str;

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError>;

    fn prepare_responses(
        &self,
        _provider: ProviderConfig,
        _request: ResponsesPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        Err(AdapterError::UnsupportedProviderKind {
            kind: self.kind().to_string(),
        })
    }

    fn prepare_model_catalog(
        &self,
        _provider: ProviderConfig,
    ) -> Result<ProviderCatalogRequest, AdapterError> {
        Err(AdapterError::UnsupportedProviderKind {
            kind: self.kind().to_string(),
        })
    }

    fn parse_model_catalog(&self, _body: &[u8]) -> Result<Vec<ProviderCatalogModel>, AdapterError> {
        Err(AdapterError::UnsupportedProviderKind {
            kind: self.kind().to_string(),
        })
    }

    fn normalize_error_response(
        &self,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> ProviderErrorResponse;

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage>;

    fn inject_tools(&self, body: Value, _tools: &[ToolDef]) -> Result<Value, AdapterError> {
        Ok(body)
    }

    fn extract_tool_calls(&self, _body: &[u8]) -> Result<Vec<ToolCall>, AdapterError> {
        Ok(Vec::new())
    }

    fn append_tool_results(
        &self,
        body: Value,
        _results: &[ToolResult],
    ) -> Result<Value, AdapterError> {
        Ok(body)
    }

    fn is_retryable_status(&self, status: u16) -> bool {
        status == 429 || (500..=599).contains(&status)
    }
}
